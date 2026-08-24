import json
import os
import sqlite3
import time

WINDOW_SECONDS = 300
SEVERITIES = ("normal", "alert", "throttle", "block", "unusable")
# the enforcement ladder, which "unusable" is not part of
TIER_ORDER = ("normal", "alert", "throttle", "block")


# the engine holds the database open in WAL mode, so a reader needs mode=ro rather than
# immutable: immutable would pin a stale snapshot and miss every window written since
def connect(path):
    conn = sqlite3.connect("file:" + path + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def rows(conn, sql, args=()):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def one(conn, sql, args=()):
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r else None


def loads(value, fallback=None):
    if not value:
        return fallback
    try:
        return json.loads(value)
    except ValueError:
        return fallback


def newest_file(directory, suffix):
    try:
        names = [n for n in os.listdir(directory) if n.endswith(suffix)]
    except OSError:
        return None, 0
    if not names:
        return None, len(names)
    latest = max(names, key=lambda n: os.path.getmtime(os.path.join(directory, n)))
    return os.path.join(directory, latest), len(names)


# mirrors capture.chunk_time. tcpdump writes the rotation time into the name in local
# time, which is the only timestamp that says when a chunk was *opened*
def chunk_time(name):
    try:
        return time.mktime(time.strptime(name[len("iot-"):-len(".pcap")], "%Y%m%d-%H%M%S"))
    except ValueError:
        return None


def system(conn, conf):
    now = time.time()
    db_path = conf["paths"]["db"]
    captures = conf["paths"]["captures"]
    latest, chunk_count = newest_file(captures, ".pcap")
    watermark = os.path.join(os.path.dirname(db_path), "watermark")
    mark, mark_age = None, None
    if os.path.exists(watermark):
        with open(watermark) as f:
            mark = f.read().strip()
        mark_age = now - os.path.getmtime(watermark)
    # chunks written but not yet consumed. capture.pending also drops anything still
    # inside the grace window, so one or two here is the steady state, not a backlog
    backlog = 0
    if mark is not None:
        try:
            backlog = len([n for n in os.listdir(captures)
                           if n.startswith("iot-") and n.endswith(".pcap") and n > mark])
        except OSError:
            backlog = 0
    last_window = one(conn, "SELECT max(window_start) AS m FROM windows")["m"] or 0
    counts = {}
    for table in ("devices", "windows", "baselines", "scores", "events", "ground_truth"):
        counts[table] = one(conn, "SELECT count(*) AS n FROM " + table)["n"]
    log_path = os.path.join(os.path.dirname(db_path), "logs", "engine.log")
    return {
        "now": now,
        "run_label": conf["run_label"],
        "enforcement_mode": conf["enforcement"]["mode"],
        "window_seconds": WINDOW_SECONDS,
        "db_path": db_path,
        "db_bytes": os.path.getsize(db_path) if os.path.exists(db_path) else 0,
        "log_path": log_path if os.path.exists(log_path) else None,
        # two different questions, and the mtime alone answers neither. tcpdump appends to
        # the open chunk continuously, so its mtime is always a second or two old whether
        # or not rotation is still happening. rotation_age is measured from the name, which
        # is when the chunk was opened, and grows past 300 s only if tcpdump has stopped.
        # write_age is how long since a packet last landed, which is a traffic question
        "capture": {
            "dir": captures,
            "chunks": chunk_count,
            "latest": os.path.basename(latest) if latest else None,
            "rotation_age_s": ((now - chunk_time(os.path.basename(latest)))
                               if latest and chunk_time(os.path.basename(latest)) else None),
            "write_age_s": (now - os.path.getmtime(latest)) if latest else None,
            "current_bytes": os.path.getsize(latest) if latest else 0,
        },
        "watermark": {"chunk": mark, "age_s": mark_age, "backlog": backlog},
        "pipeline": {
            "last_window_start": last_window,
            # a window is only emitted once the stream has passed its end, so the floor
            # on this lag is one window plus the capture poll interval, never zero
            "lag_s": now - (last_window + WINDOW_SECONDS) if last_window else None,
        },
        "counts": counts,
    }


def baseline_summary(conn, baseline_id):
    row = one(conn, "SELECT * FROM baselines WHERE id = ?", (baseline_id,))
    if not row:
        return None
    thresholds = loads(row["thresholds_json"], {}) or {}
    quality = loads(row["quality_json"], {}) or {}
    dest_set = loads(row["dest_set_json"], {"keys": [], "ips": []}) or {"keys": [], "ips": []}
    services = loads(row["service_set_json"], []) or []
    names = loads(row["feature_names_json"], []) or []
    keys = dest_set.get("keys", [])
    return {
        "id": row["id"],
        "active": bool(row["active"]),
        "created_at": row["created_at"],
        "n_windows": row["n_windows"],
        "names": names,
        "t_alert": thresholds.get("t_alert"),
        "t_critical": thresholds.get("t_critical"),
        "rule": thresholds.get("rule"),
        "candidates": thresholds.get("candidates", {}),
        "calib": thresholds.get("calib", {}),
        "chi2": thresholds.get("chi2", {}),
        "n_fit": quality.get("n_fit"),
        "n_calib": quality.get("n_calib"),
        "forced": bool(quality.get("forced")),
        # a well conditioned fit lands near the feature count, far below means collinearity
        "median_fit_d2": quality.get("median_fit_d2"),
        "gates": quality.get("gates", {}),
        "dest_keys": sorted(keys),
        "dest_domains": sorted(k for k in keys if k.startswith("d:")),
        "dest_prefixes": sorted(k for k in keys if k.startswith("p:")),
        "n_ips": len(dest_set.get("ips", [])),
        "services": services,
    }


# the tier stored on a score row is not one thing. engine.monitor writes the tier the
# state machine reached, with all of its hysteresis; cli refit writes a stateless per
# window severity. reading the column as either alone is wrong, so severity is recomputed
# here from the distance against the thresholds of the baseline that actually scored it.
# mirrors score.trusted_distance and the tier ladder in cli.cmd_refit
def stateless_severity(d2, packets, complete, thresholds, conf):
    if not complete or (not packets and not conf["learning"]["learn_include_empty"]):
        return "unusable"
    if d2 is None or not thresholds:
        return "unscored"
    if d2 >= thresholds["t_critical"]:
        return "block"
    if d2 >= thresholds["t_alert"]:
        return "alert"
    return "normal"


def threshold_cache(conn):
    cache = {}

    def get(baseline_id):
        if baseline_id not in cache:
            row = one(conn, "SELECT thresholds_json FROM baselines WHERE id = ?",
                      (baseline_id,))
            cache[baseline_id] = loads(row["thresholds_json"], {}) if row else {}
        return cache[baseline_id]
    return get


# a refit rescores every window back to time zero, so counting the whole table mixes
# regimes and badly overstates the alert rate. everything here is scoped to windows at or
# after the active baseline was fitted, which is the only out of sample set there is
def severity_counts(conn, conf, mac, since):
    counts = {name: 0 for name in SEVERITIES}
    counts.update({"unscored": 0, "novel": 0, "hard_novel": 0})
    thresholds = threshold_cache(conn)
    sql = ("SELECT s.d2 AS d2, s.baseline_id AS baseline_id, w.packets AS packets,"
           " w.complete AS complete, w.new_dests_json AS new_dests_json FROM windows w"
           " LEFT JOIN scores s ON s.window_id = w.id"
           " WHERE w.mac = ? AND w.window_start >= ?")
    total = 0
    for row in rows(conn, sql, (mac, since)):
        total += 1
        name = stateless_severity(row["d2"], row["packets"], row["complete"],
                                  thresholds(row["baseline_id"]), conf)
        counts[name] = counts.get(name, 0) + 1
        novel = loads(row["new_dests_json"], []) or []
        if novel:
            counts["novel"] += 1
            # a new prefix is address rotation under a known domain and can never block
            if any(not k.startswith("p:") for k in novel):
                counts["hard_novel"] += 1
    counts["total"] = total
    return counts


# what the state machine actually did, which is a different question from how many
# windows were far from the baseline
def episodes(conn, mac, since):
    out = {"tier_changes": 0, "enforced": 0, "worst": "normal"}
    for row in rows(conn, "SELECT tier FROM events WHERE mac = ? AND ts >= ?"
                          " AND kind = 'tier_change'", (mac, since)):
        out["tier_changes"] += 1
        if row["tier"] in TIER_ORDER and TIER_ORDER.index(row["tier"]) > \
                TIER_ORDER.index(out["worst"]):
            out["worst"] = row["tier"]
    out["enforced"] = one(conn, "SELECT count(*) AS n FROM enforcement WHERE mac = ?"
                                " AND applied_at >= ?", (mac, since))["n"]
    return out


def device_view(conn, conf, dev, learning_probe=None):
    mac = dev["mac"]
    base = baseline_summary(conn, dev["baseline_id"]) if dev["baseline_id"] else None
    latest = one(conn, "SELECT s.*, w.window_start AS window_start, w.packets AS packets,"
                       " w.complete AS complete, w.duration_s AS duration_s"
                       " FROM scores s JOIN windows w ON w.id = s.window_id"
                       " WHERE s.mac = ? ORDER BY s.id DESC LIMIT 1", (mac,))
    if latest:
        latest["contributions"] = loads(latest.pop("contributions_json"), []) or []
        latest["zscores"] = loads(latest.pop("zscores_json"), {}) or {}
        t_alert = (base or {}).get("t_alert")
        latest["ratio"] = (latest["d2"] / t_alert) if t_alert else None
        # "recorded" is whatever the engine stored, which for a refit row is a stateless
        # severity and for a live row is the tier the state machine reached
        latest["recorded"] = latest.pop("tier")
        latest["severity"] = stateless_severity(
            latest["d2"], latest["packets"], latest["complete"],
            (base or {}).get("t_alert") and {"t_alert": base["t_alert"],
                                             "t_critical": base["t_critical"]}, conf)
    since = base["created_at"] if base else 0
    open_row = one(conn, "SELECT * FROM enforcement WHERE mac = ? AND removed_at IS NULL"
                         " ORDER BY id DESC LIMIT 1", (mac,))
    last_window = one(conn, "SELECT max(window_start) AS m FROM windows WHERE mac = ?", (mac,))
    return {
        "mac": mac,
        "ip": dev["ip"],
        "name": dev["name"],
        "state": dev["state"],
        "tier": dev["tier"],
        "consecutive_count": dev["consecutive_count"],
        "first_seen": dev["first_seen"],
        "last_seen": dev["last_seen"],
        "last_window_start": last_window["m"] if last_window else None,
        "learning_started": dev["learning_started"],
        "baseline": base,
        "latest": latest,
        "since_fit": severity_counts(conn, conf, mac, since),
        "episodes": episodes(conn, mac, since),
        "enforcement": open_row,
        "learning": learning_probe(conn, conf, dev) if learning_probe else None,
        "keying": keying_drift(conn, mac, base),
        "node": conf["ground_truth"]["nodes"].get(mac),
        "excluded": mac in conf["exclude"]["macs"],
        "never_enforce": mac in conf["enforcement"]["never_enforce"],
    }


# the failure this looks for is silent by design: DnsLog holds the address to domain map
# in memory only, so after an engine restart past a pihole log rotation a device that
# rarely re-resolves keys as p:<prefix> instead of d:<domain>. the prefix is then novel
# against a baseline frozen on domains, and drives a tier change on a destination the
# device has contacted all along. a new prefix over addresses the baseline already knew
# is that case and nothing else
def keying_drift(conn, mac, base, lookback=24):
    if not base:
        return None
    known_ips = set()
    row = one(conn, "SELECT dest_set_json FROM baselines WHERE id = ?", (base["id"],))
    if row:
        known_ips = set((loads(row["dest_set_json"], {}) or {}).get("ips", []))
    recent = rows(conn, "SELECT window_start, counters_json, new_dests_json FROM windows"
                        " WHERE mac = ? ORDER BY window_start DESC LIMIT ?", (mac, lookback))
    domains, prefixes, suspect = set(), set(), {}
    for w in recent:
        counters = loads(w["counters_json"], {}) or {}
        dests = counters.get("dests", {}) or {}
        for key in dests:
            (domains if key.startswith("d:") else prefixes).add(key)
        for key in loads(w["new_dests_json"], []) or []:
            if not key.startswith("p:"):
                continue
            addrs = dests.get(key) or []
            if addrs and all(a in known_ips for a in addrs):
                suspect.setdefault(key, {"key": key, "addrs": addrs, "windows": 0,
                                         "last": w["window_start"]})
                suspect[key]["windows"] += 1
    return {
        "lookback_windows": len(recent),
        "recent_domains": sorted(domains),
        "recent_prefixes": sorted(prefixes),
        "baseline_domains": len(base["dest_domains"]),
        "baseline_prefixes": len(base["dest_prefixes"]),
        "drifted": sorted(suspect.values(), key=lambda s: -s["windows"]),
    }


def devices(conn, conf, learning_probe=None):
    return [device_view(conn, conf, dev, learning_probe)
            for dev in rows(conn, "SELECT * FROM devices ORDER BY mac")]


def series(conn, conf, mac, hours):
    since = time.time() - hours * 3600
    scored = rows(conn, "SELECT w.window_start AS t, w.packets AS packets,"
                        " w.complete AS complete, w.duration_s AS duration_s,"
                        " w.features_json AS features_json, w.new_dests_json AS new_dests_json,"
                        " s.d2 AS d2, s.tier AS recorded, s.baseline_id AS baseline_id"
                        " FROM windows w LEFT JOIN scores s ON s.window_id = w.id"
                        " WHERE w.mac = ? AND w.window_start >= ?"
                        " ORDER BY w.window_start", (mac, since))
    thresholds = threshold_cache(conn)
    out = []
    for row in scored:
        row["features"] = loads(row.pop("features_json"), {}) or {}
        row["new_dests"] = loads(row.pop("new_dests_json"), []) or []
        row["severity"] = stateless_severity(row["d2"], row["packets"], row["complete"],
                                             thresholds(row["baseline_id"]), conf)
        out.append(row)
    # a refit rescores history, so the thresholds a point should be read against are the
    # ones of the baseline that scored it, not whichever baseline is active now
    bands = {}
    for baseline_id in sorted({r["baseline_id"] for r in out if r["baseline_id"]}):
        base = baseline_summary(conn, baseline_id)
        if base:
            bands[baseline_id] = {"t_alert": base["t_alert"], "t_critical": base["t_critical"],
                                  "created_at": base["created_at"]}
    return {"mac": mac, "hours": hours, "points": out, "baselines": bands}


def events(conn, limit=60, mac=None):
    sql = "SELECT * FROM events"
    args = []
    if mac:
        sql += " WHERE mac = ?"
        args.append(mac)
    sql += " ORDER BY ts DESC, id DESC LIMIT ?"
    args.append(limit)
    out = rows(conn, sql, args)
    for row in out:
        row["detail"] = loads(row.pop("detail_json"), {}) or {}
    return out


def enforcement(conn, limit=40):
    return rows(conn, "SELECT * FROM enforcement ORDER BY id DESC LIMIT ?", (limit,))


def ground_truth(conn, mac=None, limit=40):
    sql = "SELECT * FROM ground_truth"
    args = []
    if mac:
        sql += " WHERE mac = ?"
        args.append(mac)
    sql += " ORDER BY device_ts_ms DESC LIMIT ?"
    args.append(limit)
    out = rows(conn, sql, args)
    for row in out:
        row["detail"] = loads(row.pop("detail_json"), {}) or {}
    return out


def injections(conn, mac, hours):
    since_ms = int((time.time() - hours * 3600) * 1000)
    entries = rows(conn, "SELECT device_ts_ms, action, type, magnitude FROM ground_truth"
                         " WHERE mac = ? AND class = 'anomaly' AND device_ts_ms >= ?"
                         " ORDER BY device_ts_ms", (mac, since_ms))
    spans, open_span = [], None
    for e in entries:
        if e["action"] == "start":
            open_span = {"start": e["device_ts_ms"] / 1000.0, "type": e["type"],
                         "magnitude": e["magnitude"], "end": None}
        elif open_span is not None:
            open_span["end"] = e["device_ts_ms"] / 1000.0
            spans.append(open_span)
            open_span = None
    if open_span is not None:
        spans.append(open_span)
    return spans


def windows_table(conn, conf, mac, limit=40):
    out = rows(conn, "SELECT w.window_start, w.duration_s, w.complete, w.packets,"
                     " w.features_json, w.counters_json, w.new_dests_json, w.label,"
                     " s.d2 AS d2, s.tier AS recorded, s.baseline_id AS baseline_id"
                     " FROM windows w LEFT JOIN scores s ON s.window_id = w.id"
                     " WHERE w.mac = ? ORDER BY w.window_start DESC LIMIT ?", (mac, limit))
    thresholds = threshold_cache(conn)
    for row in out:
        row["severity"] = stateless_severity(row["d2"], row["packets"], row["complete"],
                                             thresholds(row["baseline_id"]), conf)
        counters = loads(row.pop("counters_json"), {}) or {}
        row["features"] = loads(row.pop("features_json"), {}) or {}
        row["new_dests"] = loads(row.pop("new_dests_json"), []) or []
        row["dests"] = counters.get("dests", {})
        row["services"] = counters.get("services", [])
        row["infra"] = {k: counters.get(k, 0) for k in
                        ("dns_count", "dhcp_count", "ntp_count", "benign_ip_rotation")}
    return out


def baselines_for(conn, mac):
    ids = rows(conn, "SELECT id FROM baselines WHERE mac = ? ORDER BY id DESC", (mac,))
    return [baseline_summary(conn, r["id"]) for r in ids]


def log_tail(path, lines=80):
    if not path or not os.path.exists(path):
        return []
    # the engine log grows all day, so read the tail rather than the file
    with open(path, "rb") as f:
        size = os.path.getsize(path)
        block = min(size, max(4096, lines * 200))
        f.seek(size - block)
        text = f.read().decode("utf-8", "replace")
    return text.splitlines()[-lines:]
