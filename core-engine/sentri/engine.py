import json
import logging
import os
import time
import urllib.request

from . import baseline, capture, db, enforce, extract, score

log = logging.getLogger("sentri")


def setup_logging(conf):
    directory = os.path.join(os.path.dirname(conf["paths"]["db"]), "logs")
    os.makedirs(directory, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(os.path.join(directory, "engine.log")),
                  logging.StreamHandler()],
    )


def run(conf):
    conn = db.connect(conf["paths"]["db"])
    enforce.sync_from_db(conn, conf)
    dnslog = extract.DnsLog(conf["paths"]["pihole_log"])
    windower = extract.Windower([d["mac"] for d in db.all_devices(conn)])
    chunk_end = 0.0
    last_poll = 0.0
    log.info("engine started, mode %s, label %s", conf["enforcement"]["mode"], conf["run_label"])
    while True:
        for path, name, start in capture.pending(conf):
            # a gap between chunks means capture stopped, so observation restarts here
            if start - chunk_end > extract.WINDOW_SECONDS:
                windower.start_segment(start)
            process_chunk(conn, conf, dnslog, windower, path, start)
            chunk_end = start + extract.WINDOW_SECONDS
            capture.write_watermark(conf, name)
        now = time.time()
        if now - last_poll >= conf["ground_truth"]["poll_seconds"]:
            poll_ground_truth(conn, conf)
            last_poll = now
        auto_clear(conn, conf)
        time.sleep(conf["capture"]["poll_seconds"])


def process_chunk(conn, conf, dnslog, windower, path, start):
    dnslog.refresh(start)
    packets, device_ips = extract.parse_chunk(path, conf)
    windower.add(packets)
    windower.advance(start + extract.WINDOW_SECONDS)
    for mac, window_start, duration, pkts in windower.ready():
        process_window(conn, conf, dnslog, mac, window_start, duration, pkts,
                       device_ips.get(mac))
    log.info("chunk %s: %d packets, %d devices", os.path.basename(path), len(packets),
             len(device_ips))


def process_window(conn, conf, dnslog, mac, window_start, duration, pkts, ip):
    dev = db.get_device(conn, mac)
    if dev is None:
        db.add_device(conn, mac, ip, window_start)
        db.add_event(conn, mac, window_start, "normal", "device_new", "first seen " + mac,
                     {"ip": ip})
        dev = db.get_device(conn, mac)
    if ip and ip != dev["ip"]:
        db.update_device(conn, mac, ip=ip)
        dev["ip"] = ip
    feats, counters = extract.window_features(pkts, duration, dev["ip"], dnslog,
                                              conf["network"]["gateway_ip"])
    base = baseline.load(conn, mac) if dev["state"] == "monitoring" else None
    novel, hits = [], []
    if base:
        dests = {k: set(v) for k, v in counters["dests"].items()}
        new_dests, new_services, counters["benign_ip_rotation"] = score.novelty(
            dests, counters["services"], base)
        novel = new_dests + new_services
        hits = score.discrete_hits(new_dests, new_services)
    previous = db.prev_window(conn, mac, window_start)
    complete = 1 if duration >= extract.COMPLETE_MIN else 0
    window_id = db.add_window(conn, mac, window_start, duration, complete, len(pkts), feats,
                              counters, novel, conf["run_label"])
    if window_id is None:
        return
    db.update_device(conn, mac, last_seen=window_start + extract.WINDOW_SECONDS)
    if dev["state"] == "learning":
        check_learning(conn, conf, mac, dev, window_start)
    elif base:
        monitor(conn, conf, mac, dev, window_id, window_start, feats, base, hits, previous)


def check_learning(conn, conf, mac, dev, now):
    windows = baseline.usable(conn, mac, dev, conf)
    status = baseline.gates(windows, dev, conf)
    forced = baseline.expired(dev, now, conf)
    passed = status["windows"] and status["duration"] and status["stability"]
    if not passed and not forced:
        if len(windows) % 20 == 0:
            log.info("%s learning blocked: %s", mac, status["detail"])
        return
    baseline_id = baseline.fit(conn, mac, dev, conf, forced)
    if baseline_id is None:
        return
    db.update_device(conn, mac, state="monitoring", baseline_id=baseline_id, tier="normal",
                     consecutive_count=0)
    db.add_event(conn, mac, now, "normal", "learning_done",
                 "baseline %d fitted%s" % (baseline_id, ", hard stop" if forced else ""), status)


def monitor(conn, conf, mac, dev, window_id, window_start, feats, base, hits, previous):
    d2, contributions, zscores = score.distance(extract.to_vector(feats, base["names"]), base)
    before = score.hard_novelty(json.loads(previous["new_dests_json"])) if previous else False
    tier, count = score.decide_tier(dev["tier"], dev["consecutive_count"], d2,
                                    base["thresholds"], hits, before, conf)
    db.add_score(conn, window_id, base["id"], mac, d2, tier, contributions, zscores)
    db.update_device(conn, mac, tier=tier, consecutive_count=count)
    if tier == dev["tier"]:
        return
    summary = score.reason(d2, base["thresholds"], hits)
    db.add_event(conn, mac, window_start, tier, "tier_change", summary,
                 {"from": dev["tier"], "top": contributions})
    db.add_enforcement(conn, mac, tier, summary)
    enforce.apply_tier(mac, dev["ip"], tier, conf)
    log.warning("%s %s to %s: %s", mac, dev["tier"], tier, summary)


def auto_clear(conn, conf):
    limit = conf["enforcement"]["auto_clear_hours"] * 3600
    now = time.time()
    for row in db.open_enforcement(conn):
        if now - row["applied_at"] < limit:
            continue
        dev = db.get_device(conn, row["mac"])
        enforce.clear(row["mac"], dev["ip"] if dev else None)
        db.add_enforcement(conn, row["mac"], "normal", "auto clear")
        db.update_device(conn, row["mac"], tier="normal", consecutive_count=0)
        db.add_event(conn, row["mac"], now, "normal", "auto_clear",
                     "enforcement expired after %.1f h" % (conf["enforcement"]["auto_clear_hours"],), {})


def poll_ground_truth(conn, conf):
    for mac, host in conf["ground_truth"]["nodes"].items():
        mac = mac.lower()
        since = db.last_ground_truth_ms(conn, mac)
        url = "http://%s:8080/log?since=%d" % (host, since)
        # nodes reboot and drop connections during experiments, so this one really can fail
        try:
            body = urllib.request.urlopen(url, timeout=5).read().decode()
            entries = [json.loads(line) for line in body.splitlines() if line.strip()]
        except (OSError, ValueError) as exc:
            log.warning("ground truth poll failed for %s: %s", mac, exc)
            continue
        for entry in entries:
            if entry.get("t", 0) > since:
                db.add_ground_truth(conn, mac, entry)
        if entries:
            log.info("%s ground truth: %d entries", mac, len(entries))
