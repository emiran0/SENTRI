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
    chunk_end = 0.0  # where the last chunk should have ended, for gap detection
    last_poll = 0.0
    log.info("engine started, mode %s, label %s", conf["enforcement"]["mode"], conf["run_label"])
    while True:
        for path, name, start in capture.pending(conf):
            # gap means capture stopped, restart observation here
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


def replay(conf, directory, limit=None):
    # same pipeline over an archived capture. capture.pending cannot be reused, it filters
    # on mtime against wall clock and writes the live db. nothing below here may special
    # case a replay, the benchmark claim rests on it being the same path
    conn = db.connect(conf["paths"]["db"])
    # no resolver log in an archive, so everything keys by prefix. that is the benchmark
    # condition, not a defect, the prefix keyed arm is its own control
    dnslog = extract.DnsLog(conf["paths"].get("pihole_log") if conf["paths"] else None)
    windower = extract.Windower([d["mac"] for d in db.all_devices(conn)])
    chunks = []
    for name in sorted(os.listdir(directory)):
        if name.startswith(capture.CHUNK_PREFIX) and name.endswith(capture.CHUNK_SUFFIX):
            chunks.append((os.path.join(directory, name), name, capture.chunk_time(name)))
    chunks.sort(key=lambda c: c[2])
    if limit:
        chunks = chunks[:limit]
    log.info("replay starting, %d chunks, label %s, db %s",
             len(chunks), conf["run_label"], conf["paths"]["db"])
    chunk_end = 0.0
    ips = {}
    for i, (path, name, start) in enumerate(chunks, 1):
        # live, window N flushes when chunk N+1 lands. an archive can be sparse, so a window
        # whose successor never comes just sits there. flush before every gap and at the end
        if start - chunk_end > extract.WINDOW_SECONDS:
            # only once a segment has run, before the first chunk ready() hits a None position
            if chunk_end:
                windower.advance(chunk_end + extract.WINDOW_SECONDS)
                drain_windows(conn, conf, dnslog, windower, ips)
            windower.start_segment(start)
        ips = process_chunk(conn, conf, dnslog, windower, path, start) or ips
        chunk_end = start + extract.WINDOW_SECONDS
        if i % 50 == 0 or i == len(chunks):
            log.info("replay %d/%d chunks", i, len(chunks))
    windower.advance(chunk_end + extract.WINDOW_SECONDS)
    drain_windows(conn, conf, dnslog, windower, ips)
    for dev in db.all_devices(conn):
        log.info("replay done: %s state=%s tier=%s baseline=%s",
                 dev["mac"], dev["state"], dev["tier"], dev["baseline_id"])
    return len(chunks)


def drain_windows(conn, conf, dnslog, windower, device_ips):
    for mac, window_start, duration, pkts in windower.ready():
        process_window(conn, conf, dnslog, mac, window_start, duration, pkts,
                       device_ips.get(mac))


def process_chunk(conn, conf, dnslog, windower, path, start):
    t0 = time.monotonic()
    dnslog.refresh(start)
    packets, device_ips = extract.parse_chunk(path, conf)
    t_parse = time.monotonic()
    windower.add(packets)
    windower.advance(start + extract.WINDOW_SECONDS)
    drain_windows(conn, conf, dnslog, windower, device_ips)
    # this against the 300 s rotation is the duty cycle. if it gets close the Pi is
    # not keeping up, so log it per chunk
    elapsed = time.monotonic() - t0
    log.info("chunk %s: %d packets, %d devices, parse %.2fs, in %.2fs",
             os.path.basename(path), len(packets), len(device_ips), t_parse - t0, elapsed)
    # returned so a replay can carry the address map across a gap
    return device_ips


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
    previous = db.prev_window(conn, mac, window_start)  # novelty needs the one before
    complete = 1 if duration >= extract.COMPLETE_MIN else 0
    window_id = db.add_window(conn, mac, window_start, duration, complete, len(pkts), feats,
                              counters, novel, conf["run_label"])
    if window_id is None:
        return  # already stored, do not score it twice
    db.update_device(conn, mac, last_seen=window_start + extract.WINDOW_SECONDS)
    if dev["state"] == "learning":
        check_learning(conn, conf, mac, dev, window_start)
    elif base:
        trusted = score.trusted_distance(len(pkts), complete, conf)
        monitor(conn, conf, mac, dev, window_id, window_start, feats, base, hits, previous,
                trusted)


def check_learning(conn, conf, mac, dev, now):
    windows = baseline.usable(conn, mac, dev, conf)
    status = baseline.gates(windows, dev, conf)
    forced = baseline.expired(dev, now, conf)  # hard stop, fit whatever we have
    passed = status["windows"] and status["duration"] and status["stability"]
    if not passed and not forced:
        if len(windows) % 20 == 0:  # every window would be noise in the log
            log.info("%s learning blocked: %s", mac, status["detail"])
        return
    baseline_id = baseline.fit(conn, mac, dev, conf, forced)
    if baseline_id is None:
        return
    db.update_device(conn, mac, state="monitoring", baseline_id=baseline_id, tier="normal",
                     consecutive_count=0, recent_flags=0)
    db.add_event(conn, mac, now, "normal", "learning_done",
                 "baseline %d fitted%s" % (baseline_id, ", hard stop" if forced else ""), status)


def monitor(conn, conf, mac, dev, window_id, window_start, feats, base, hits, previous,
            trusted):
    d2, contributions, zscores = score.distance(extract.to_vector(feats, base["names"]), base)
    before = score.hard_novelty(json.loads(previous["new_dests_json"])) if previous else False
    # still recorded for the evaluation record, it just must not move the tier or the streak
    if score.superseded_by_clear(window_start, dev["cleared_at"]):
        db.add_score(conn, window_id, base["id"], mac, d2, dev["tier"], contributions, zscores)
        log.info("%s window %d predates the operator clear, tier decision skipped (d2 %.1f)",
                 mac, window_start, d2)
        return
    tier, count, recent = score.decide_tier(dev["tier"], dev["consecutive_count"], d2,
                                            base["thresholds"], hits, before, trusted, conf,
                                            dev["recent_flags"] or 0)
    db.add_score(conn, window_id, base["id"], mac, d2, tier, contributions, zscores)
    db.update_device(conn, mac, tier=tier, consecutive_count=count, recent_flags=recent)
    if tier == dev["tier"]:
        return
    summary = score.reason(d2, base["thresholds"], hits, trusted)
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
        # authoritative too, so queued windows must not undo it
        db.update_device(conn, row["mac"], tier="normal", consecutive_count=0, recent_flags=0,
                         cleared_at=now)
        db.add_event(conn, row["mac"], now, "normal", "auto_clear",
                     "enforcement expired after %.1f h" % (conf["enforcement"]["auto_clear_hours"],), {})


def poll_ground_truth(conn, conf):
    for mac, host in conf["ground_truth"]["nodes"].items():
        mac = mac.lower()
        since = db.last_ground_truth_ms(conn, mac)
        url = "http://%s:8080/log?since=%d" % (host, since)
        # nodes reboot mid experiment, this really does fail
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
