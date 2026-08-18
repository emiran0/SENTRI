import os

import numpy as np
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapReader

WINDOW_SECONDS = 300
EMIT_LAG = 5
COMPLETE_MIN = 285
MIN_DURATION = 1.0
SMALL_BYTES = 150
LARGE_BYTES = 700
DNS_TTL = 86400

FEATURES = (
    "pkts_out_rate", "pkts_in_rate", "bytes_out_rate", "bytes_in_rate",
    "mean_pkt_size_out", "std_pkt_size_out", "mean_iat_out", "std_iat_out",
    "frac_small_out", "frac_large_out", "distinct_peers", "tcp_syn_rate",
)

LOG_FEATURES = frozenset((
    "pkts_out_rate", "pkts_in_rate", "bytes_out_rate", "bytes_in_rate",
    "mean_iat_out", "std_iat_out", "distinct_peers", "tcp_syn_rate",
))

INFRA_PORTS = {53: "dns_count", 67: "dhcp_count", 68: "dhcp_count", 123: "ntp_count"}

MULTI_SUFFIXES = frozenset((
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz",
    "co.jp", "com.br", "co.za", "com.tr", "com.cn",
))


def registrable(name):
    labels = name.lower().strip(".").split(".")
    if len(labels) < 3:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class DnsLog:
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.names = {}
        self.pending = {}
        self.chain = None

    def refresh(self, now):
        if not self.path or not os.path.exists(self.path):
            return
        size = os.path.getsize(self.path)
        if size < self.offset:
            self.offset = 0
        with open(self.path, errors="ignore") as f:
            f.seek(self.offset)
            for line in f:
                self.feed(line, now)
            self.offset = f.tell()
        self.names = {k: v for k, v in self.names.items() if v[1] > now - DNS_TTL}
        self.pending = {k: v for k, v in self.pending.items() if v[1] > now - DNS_TTL}

    # lines are read incrementally so the read time is close enough for a 24 h expiry
    def feed(self, line, now):
        parts = line.split()
        if len(parts) < 8:
            return
        if parts[4].startswith("query[") and parts[6] == "from":
            self.pending[parts[5]] = (parts[7], now)
            self.chain = (parts[7], parts[5])
        elif parts[4] == "reply" and parts[6] == "is":
            asked = self.pending.get(parts[5])
            if asked:
                self.chain = (asked[0], parts[5])
            # each cname hop gets its own reply line, so the address line carries the alias
            if self.chain and parts[7][0].isdigit():
                self.names[(self.chain[0], parts[7])] = (self.chain[1], now)

    def lookup(self, client_ip, peer_ip):
        hit = self.names.get((client_ip, peer_ip))
        return hit[0] if hit else None


def dest_key(device_ip, peer_ip, dnslog):
    name = dnslog.lookup(device_ip, peer_ip) if dnslog else None
    if name:
        return "d:" + registrable(name)
    return "p:" + peer_ip.rsplit(".", 1)[0] + ".0/24"


def parse_chunk(path, conf):
    infra = set(conf["exclude"]["macs"])
    dropped_ports = set(conf["exclude"]["tcp_ports"])
    gateway = conf["network"]["gateway_ip"]
    packets = []
    device_ips = {}
    with PcapReader(path) as reader:
        for pkt in reader:
            if Ether not in pkt or ARP in pkt:
                continue
            src, dst = pkt.src.lower(), pkt.dst.lower()
            # low bit of the first octet marks broadcast and multicast destinations
            if int(dst[:2], 16) & 1:
                continue
            if src not in infra:
                mac, direction = src, 0
            elif dst not in infra:
                mac, direction = dst, 1
            else:
                continue
            if IP not in pkt:
                continue
            ip = pkt[IP]
            # the peer is identified by IP, the far side MAC is always the Pi for routed traffic
            peer_ip = ip.dst if direction == 0 else ip.src
            device_ips[mac] = ip.src if direction == 0 else ip.dst
            proto, peer_port, is_syn = "other", 0, 0
            if TCP in pkt:
                tcp = pkt[TCP]
                proto = "tcp"
                peer_port = int(tcp.dport if direction == 0 else tcp.sport)
                local_port = int(tcp.sport if direction == 0 else tcp.dport)
                if peer_port in dropped_ports or local_port in dropped_ports:
                    continue
                is_syn = 1 if direction == 0 and "S" in tcp.flags and "A" not in tcp.flags else 0
            elif UDP in pkt:
                udp = pkt[UDP]
                proto = "udp"
                peer_port = int(udp.dport if direction == 0 else udp.sport)
            elif ICMP in pkt:
                proto = "icmp"
                if peer_ip == gateway:
                    continue
            # wirelen, not len(pkt): the 96 byte snaplen truncates every capture
            packets.append((float(pkt.time), mac, direction, int(pkt.wirelen),
                            peer_ip, proto, peer_port, is_syn))
    return packets, device_ips


def window_features(pkts, duration, device_ip, dnslog, gateway):
    counters = {"dns_count": 0, "dhcp_count": 0, "ntp_count": 0, "benign_ip_rotation": 0}
    external = []
    for p in pkts:
        name = INFRA_PORTS.get(p[6]) if p[4] == gateway else None
        if name:
            counters[name] += 1
        else:
            external.append(p)
    out = [p for p in external if p[2] == 0]
    inbound = [p for p in external if p[2] == 1]
    dests = {}
    services = set()
    for p in external:
        dests.setdefault(dest_key(device_ip, p[4], dnslog), set()).add(p[4])
        if p[2] == 0:
            services.add(p[5] + "/" + str(p[6]))
    sizes = np.array([p[3] for p in out], dtype=float)
    gaps = np.diff(sorted(p[0] for p in out)) if len(out) > 1 else np.array([])
    feats = {
        "pkts_out_rate": len(out) / duration,
        "pkts_in_rate": len(inbound) / duration,
        "bytes_out_rate": float(sizes.sum()) / duration,
        "bytes_in_rate": sum(p[3] for p in inbound) / duration,
        "mean_pkt_size_out": float(sizes.mean()) if len(sizes) else 0.0,
        "std_pkt_size_out": float(sizes.std()) if len(sizes) else 0.0,
        "mean_iat_out": float(gaps.mean()) if len(gaps) else float(duration),
        "std_iat_out": float(gaps.std()) if len(gaps) else 0.0,
        "frac_small_out": float((sizes < SMALL_BYTES).mean()) if len(sizes) else 0.0,
        "frac_large_out": float((sizes > LARGE_BYTES).mean()) if len(sizes) else 0.0,
        "distinct_peers": float(len(dests)),
        "tcp_syn_rate": sum(p[7] for p in out) / duration,
    }
    counters["dests"] = {k: sorted(v) for k, v in dests.items()}
    counters["services"] = sorted(services)
    return feats, counters


def to_vector(feats, names=FEATURES):
    return np.array([np.log1p(feats[f]) if f in LOG_FEATURES else feats[f] for f in names])


class Windower:
    def __init__(self, macs):
        self.buf = {}
        self.last = {m: None for m in macs}
        self.obs_start = 0.0
        self.stream_ts = 0.0

    def start_segment(self, ts):
        base = int(ts) // WINDOW_SECONDS * WINDOW_SECONDS - WINDOW_SECONDS
        self.obs_start = ts
        self.stream_ts = ts
        for mac in self.last:
            self.last[mac] = base

    def add(self, packets):
        for p in packets:
            start = int(p[0]) // WINDOW_SECONDS * WINDOW_SECONDS
            if self.last.get(p[1]) is None:
                self.last[p[1]] = start - WINDOW_SECONDS
            self.buf.setdefault((p[1], start), []).append(p)
        if packets:
            self.stream_ts = max(self.stream_ts, packets[-1][0])
            # a chunk can hold packets slightly older than its rotation timestamp
            self.obs_start = min(self.obs_start, packets[0][0])

    def advance(self, ts):
        self.stream_ts = max(self.stream_ts, ts)

    def ready(self):
        cutoff = self.stream_ts - EMIT_LAG
        out = []
        for mac in sorted(self.last):
            start = self.last[mac] + WINDOW_SECONDS
            while start + WINDOW_SECONDS <= cutoff:
                observed = max(start, self.obs_start)
                duration = max(MIN_DURATION, (start + WINDOW_SECONDS) - observed)
                out.append((mac, start, duration, self.buf.pop((mac, start), [])))
                self.last[mac] = start
                start += WINDOW_SECONDS
        return out
