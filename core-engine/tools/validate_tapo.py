import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from sentri import config, db, enforce, engine, extract

DEV_MAC = "aa:00:00:00:00:11"
PI_MAC = "dc:a6:32:00:00:01"
DEV_IP = "192.168.50.42"
CLOUD_IP = "93.184.216.34"
MGMT_IP = "192.168.50.1"
BASE_TS = 1700000000.0

CONF = config.merge(config.DEFAULTS, {
    "exclude": {"macs": [PI_MAC], "tcp_ports": [8080, 22]},
    "network": {"gateway_ip": MGMT_IP},
    "run_label": "validate",
})
NO_DNS = extract.DnsLog(None)


def write_pcap(path, records):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1))
        for ts, data, wirelen in records:
            capped = data[:96]
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(capped), wirelen))
            f.write(capped)


def frame(ts, dport=443, outbound=True, sport=44000, size=None):
    if outbound:
        pkt = Ether(src=DEV_MAC, dst=PI_MAC) / IP(src=DEV_IP, dst=CLOUD_IP) / TCP(sport=sport, dport=dport)
    else:
        pkt = Ether(src=PI_MAC, dst=DEV_MAC) / IP(src=CLOUD_IP, dst=DEV_IP) / TCP(sport=dport, dport=sport)
    raw = bytes(pkt)
    return (ts, raw, size or len(raw))


def features_of(path, duration=300.0):
    packets, _ = extract.parse_chunk(path, CONF)
    return extract.window_features(packets, duration, DEV_IP, NO_DNS, MGMT_IP)


def check_wirelen(tmp):
    path = os.path.join(tmp, "wire.pcap")
    write_pcap(path, [frame(BASE_TS, size=1500)])
    packets, _ = extract.parse_chunk(path, CONF)
    assert len(packets) == 1, packets
    assert packets[0][3] == 1500, "captured length leaked into the feature: %d" % packets[0][3]
    feats, _ = features_of(path)
    assert abs(feats["bytes_out_rate"] - 5.0) < 1e-9, feats["bytes_out_rate"]
    print("1 wire length ok")


def check_control_isolation(tmp):
    clean = os.path.join(tmp, "clean.pcap")
    dirty = os.path.join(tmp, "dirty.pcap")
    normal = [frame(BASE_TS + i * 40.0) for i in range(5)]
    control = [(BASE_TS + i * 40.0 + 1.0,
                bytes(Ether(src=DEV_MAC, dst=PI_MAC) / IP(src=DEV_IP, dst=MGMT_IP) /
                      TCP(sport=51000, dport=8080)), 800) for i in range(5)]
    write_pcap(clean, normal)
    write_pcap(dirty, sorted(normal + control, key=lambda r: r[0]))
    assert features_of(clean)[0] == features_of(dirty)[0], "control channel reached the features"
    print("3 control channel isolation ok")


def check_carry_buffer(tmp):
    boundary = (int(BASE_TS) // 300 + 1) * 300
    records = [frame(boundary - 1.0), frame(float(boundary)), frame(boundary + 1.0)]
    one = os.path.join(tmp, "single.pcap")
    write_pcap(one, records)
    split_a = os.path.join(tmp, "a.pcap")
    split_b = os.path.join(tmp, "b.pcap")
    write_pcap(split_a, records[:1])
    write_pcap(split_b, records[1:])
    windower = extract.Windower([])
    windower.start_segment(boundary - 300)
    for path in (one,):
        windower.add(extract.parse_chunk(path, CONF)[0])
    windower.advance(boundary + 600)
    whole = {w[1]: w[3] for w in windower.ready()}
    other = extract.Windower([])
    other.start_segment(boundary - 300)
    for path in (split_a, split_b):
        other.add(extract.parse_chunk(path, CONF)[0])
    other.advance(boundary + 600)
    parts = {w[1]: w[3] for w in other.ready()}
    assert len(whole[boundary - 300]) == 1, whole
    assert len(whole[boundary]) == 2, whole
    assert {k: len(v) for k, v in whole.items()} == {k: len(v) for k, v in parts.items()}
    print("5 carry buffer ok")


def check_idempotency(tmp):
    path = os.path.join(tmp, "idem.pcap")
    write_pcap(path, [frame(BASE_TS + i * 40.0) for i in range(10)])
    conn = db.connect(os.path.join(tmp, "idem.db"))
    for _ in range(2):
        windower = extract.Windower([])
        windower.start_segment(BASE_TS)
        engine.process_chunk(conn, CONF, NO_DNS, windower, path, BASE_TS)
    rows = db.rows(conn, "SELECT * FROM windows ORDER BY window_start")
    starts = [r["window_start"] for r in rows]
    assert len(starts) == len(set(starts)), "reprocessing added duplicate windows"
    print("4 idempotency ok, %d windows" % len(rows))


def check_enforcement(tmp):
    conf = config.merge(CONF, {"enforcement": {"mode": "enforce", "never_enforce": []}})
    enforce.load_ruleset(os.path.join(os.path.dirname(__file__), "..", "nftables", "sentri.nft"))
    enforce.apply_tier(DEV_MAC, DEV_IP, "block", conf)
    active = enforce.list_active()
    assert DEV_MAC in active["blocked_mac"], active
    assert DEV_IP in active["blocked_ip"], active
    enforce.clear(DEV_MAC, DEV_IP)
    assert DEV_MAC not in enforce.list_active()["blocked_mac"]
    conn = db.connect(os.path.join(tmp, "enforce.db"))
    db.add_device(conn, DEV_MAC, DEV_IP, BASE_TS)
    db.update_device(conn, DEV_MAC, tier="block")
    enforce.sync_from_db(conn, conf)
    assert DEV_MAC in enforce.list_active()["blocked_mac"], "restart did not restore the block"
    enforce.clear(DEV_MAC, DEV_IP)
    print("6 enforcement round trip ok")


def check_tapo(path):
    packets, _ = extract.parse_chunk(path, CONF)
    assert packets, "no packets survived the exclusions"
    windower = extract.Windower([])
    windower.start_segment(packets[0][0])
    windower.add(packets)
    windower.advance(packets[-1][0] + 600)
    seen = set()
    for mac, start, duration, pkts in windower.ready():
        if not pkts or duration < extract.COMPLETE_MIN:
            continue
        feats, counters = extract.window_features(pkts, duration, DEV_IP, NO_DNS, MGMT_IP)
        assert abs(feats["mean_iat_out"] - 55.0) < 1.0, feats["mean_iat_out"]
        assert abs(feats["mean_pkt_size_out"] - 85.0) < 15.0, feats["mean_pkt_size_out"]
        assert feats["distinct_peers"] == 1.0, counters["dests"]
        assert not seen or set(counters["dests"]) <= seen, "new destination after the first window"
        seen.update(counters["dests"])
    print("2 tapo ground truth ok")


pcaps = [a for a in sys.argv[1:] if not a.startswith("--")]

with tempfile.TemporaryDirectory() as tmpdir:
    check_wirelen(tmpdir)
    check_control_isolation(tmpdir)
    check_carry_buffer(tmpdir)
    check_idempotency(tmpdir)
    if pcaps:
        check_tapo(pcaps[0])
    else:
        print("2 tapo ground truth skipped, pass a tapo pcap as the first argument")
    if "--nft" in sys.argv:
        check_enforcement(tmpdir)
    else:
        print("6 enforcement round trip skipped, run as root on the Pi with --nft")
