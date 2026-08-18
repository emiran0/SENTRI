import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY, ip TEXT, name TEXT, state TEXT, first_seen REAL,
    last_seen REAL, tier TEXT, consecutive_count INTEGER, learning_started REAL,
    baseline_id INTEGER);

CREATE TABLE IF NOT EXISTS windows (
    id INTEGER PRIMARY KEY, mac TEXT, window_start INTEGER, duration_s REAL,
    complete INTEGER, packets INTEGER, features_json TEXT, counters_json TEXT,
    new_dests_json TEXT, label TEXT, UNIQUE(mac, window_start));

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY, mac TEXT, created_at REAL, n_windows INTEGER,
    active INTEGER, mean_json TEXT, precision_json TEXT, thresholds_json TEXT,
    dest_set_json TEXT, service_set_json TEXT, quality_json TEXT);

CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY, window_id INTEGER, baseline_id INTEGER, mac TEXT,
    d2 REAL, tier TEXT, contributions_json TEXT, zscores_json TEXT, scored_at REAL);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, mac TEXT, ts REAL, tier TEXT, kind TEXT,
    summary TEXT, detail_json TEXT);

CREATE TABLE IF NOT EXISTS enforcement (
    id INTEGER PRIMARY KEY, mac TEXT, tier TEXT, applied_at REAL,
    removed_at REAL, reason TEXT);

CREATE TABLE IF NOT EXISTS ground_truth (
    id INTEGER PRIMARY KEY, mac TEXT, device_ts_ms INTEGER, received_ts REAL,
    class TEXT, action TEXT, type TEXT, magnitude REAL, detail_json TEXT);

CREATE INDEX IF NOT EXISTS idx_windows_mac ON windows(mac, window_start);
CREATE INDEX IF NOT EXISTS idx_scores_mac ON scores(mac, scored_at);
CREATE INDEX IF NOT EXISTS idx_gt_mac ON ground_truth(mac, device_ts_ms);
"""


def connect(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.executescript(SCHEMA)
    ensure_column(conn, "baselines", "feature_names_json", "TEXT")
    return conn


# CREATE TABLE IF NOT EXISTS cannot add a column to a table that already exists
def ensure_column(conn, table, column, decl):
    present = [r["name"] for r in rows(conn, "PRAGMA table_info(" + table + ")")]
    if column not in present:
        conn.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + decl)
        conn.commit()


def rows(conn, sql, args=()):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def one(conn, sql, args=()):
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r else None


def get_device(conn, mac):
    return one(conn, "SELECT * FROM devices WHERE mac = ?", (mac,))


def all_devices(conn):
    return rows(conn, "SELECT * FROM devices ORDER BY mac")


def add_device(conn, mac, ip, ts):
    conn.execute(
        "INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?)",
        (mac, ip, mac, "learning", ts, ts, "normal", 0, ts, None),
    )
    conn.commit()


def update_device(conn, mac, **fields):
    sets = ", ".join(k + " = ?" for k in fields)
    conn.execute("UPDATE devices SET " + sets + " WHERE mac = ?", list(fields.values()) + [mac])
    conn.commit()


def add_window(conn, mac, window_start, duration, complete, packets, features, counters, new_dests, label):
    cur = conn.execute(
        "INSERT OR IGNORE INTO windows (mac, window_start, duration_s, complete, packets,"
        " features_json, counters_json, new_dests_json, label) VALUES (?,?,?,?,?,?,?,?,?)",
        (mac, window_start, duration, complete, packets, json.dumps(features),
         json.dumps(counters), json.dumps(new_dests), label),
    )
    conn.commit()
    # None means this window was already stored, which is how reprocessing stays a no-op
    return cur.lastrowid if cur.rowcount else None


def learning_windows(conn, mac, since):
    return rows(
        conn,
        "SELECT * FROM windows WHERE mac = ? AND window_start >= ? ORDER BY window_start",
        (mac, since),
    )


def prev_window(conn, mac, window_start):
    return one(
        conn,
        "SELECT * FROM windows WHERE mac = ? AND window_start < ? ORDER BY window_start DESC LIMIT 1",
        (mac, window_start),
    )


def add_baseline(conn, mac, n_windows, mean, precision, thresholds, dest_set, service_set,
                 quality, names):
    conn.execute("UPDATE baselines SET active = 0 WHERE mac = ?", (mac,))
    cur = conn.execute(
        "INSERT INTO baselines (mac, created_at, n_windows, active, mean_json, precision_json,"
        " thresholds_json, dest_set_json, service_set_json, quality_json, feature_names_json)"
        " VALUES (?,?,?,1,?,?,?,?,?,?,?)",
        (mac, time.time(), n_windows, json.dumps(mean), json.dumps(precision),
         json.dumps(thresholds), json.dumps(dest_set), json.dumps(service_set),
         json.dumps(quality), json.dumps(names)),
    )
    conn.commit()
    return cur.lastrowid


def active_baseline(conn, mac):
    return one(conn, "SELECT * FROM baselines WHERE mac = ? AND active = 1", (mac,))


def deactivate_baselines(conn, mac):
    conn.execute("UPDATE baselines SET active = 0 WHERE mac = ?", (mac,))
    conn.commit()


def add_score(conn, window_id, baseline_id, mac, d2, tier, contributions, zscores):
    conn.execute(
        "INSERT INTO scores (window_id, baseline_id, mac, d2, tier, contributions_json,"
        " zscores_json, scored_at) VALUES (?,?,?,?,?,?,?,?)",
        (window_id, baseline_id, mac, d2, tier, json.dumps(contributions),
         json.dumps(zscores), time.time()),
    )
    conn.commit()


def latest_score(conn, mac):
    return one(conn, "SELECT * FROM scores WHERE mac = ? ORDER BY id DESC LIMIT 1", (mac,))


def add_event(conn, mac, ts, tier, kind, summary, detail):
    conn.execute(
        "INSERT INTO events (mac, ts, tier, kind, summary, detail_json) VALUES (?,?,?,?,?,?)",
        (mac, ts, tier, kind, summary, json.dumps(detail)),
    )
    conn.commit()


def add_enforcement(conn, mac, tier, reason):
    conn.execute("UPDATE enforcement SET removed_at = ? WHERE mac = ? AND removed_at IS NULL",
                 (time.time(), mac))
    if tier in ("throttle", "block"):
        conn.execute("INSERT INTO enforcement (mac, tier, applied_at, reason) VALUES (?,?,?,?)",
                     (mac, tier, time.time(), reason))
    conn.commit()


def open_enforcement(conn):
    return rows(conn, "SELECT * FROM enforcement WHERE removed_at IS NULL")


def add_ground_truth(conn, mac, entry):
    conn.execute(
        "INSERT INTO ground_truth (mac, device_ts_ms, received_ts, class, action, type,"
        " magnitude, detail_json) VALUES (?,?,?,?,?,?,?,?)",
        (mac, entry.get("t", 0), time.time(), entry.get("class"), entry.get("action"),
         entry.get("type"), entry.get("mag"), json.dumps(entry)),
    )
    conn.commit()


def last_ground_truth_ms(conn, mac):
    r = one(conn, "SELECT max(device_ts_ms) AS m FROM ground_truth WHERE mac = ?", (mac,))
    return (r["m"] or 0) if r else 0


def injection_spans(conn, mac):
    entries = rows(
        conn,
        "SELECT device_ts_ms, action FROM ground_truth WHERE mac = ? AND class = 'anomaly'"
        " ORDER BY device_ts_ms",
        (mac,),
    )
    spans, start = [], None
    for e in entries:
        if e["action"] == "start":
            start = e["device_ts_ms"] / 1000.0
        elif start is not None:
            spans.append((start, e["device_ts_ms"] / 1000.0))
            start = None
    if start is not None:
        spans.append((start, start + 86400))
    return spans
