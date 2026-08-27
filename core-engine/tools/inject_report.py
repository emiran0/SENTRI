"""Measure detection latency and live detection rate from injected anomalies.

Reads the database read only, so it is safe against the live one: it fits nothing and
writes nothing. The authoritative record of what was injected is the `ground_truth`
table, not the campaign runner's log, because the node stamps a start row before the
first anomalous packet leaves.

    python tools/inject_report.py /srv/sentri/sentri.db
    python tools/inject_report.py /srv/sentri/sentri.db --since 2026-08-24

Latency is reported from the anomaly start to the close of the first window that flags,
because a window based detector cannot decide before its window ends. The ingest delay
that follows (capture rotation plus the engine's poll) is reported separately rather
than folded in, so the method's floor and the implementation's overhead stay separable.
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import score as S
from sentri.extract import WINDOW_SECONDS, to_vector

from sentri import config as _config

# replay under the rule config.yaml actually declares, so the report describes what the
# engine will do rather than a rule nobody deployed. the engine keeps running the code it
# was started with, so after an escalation change this differs from history until a restart
_CONF_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "config.yaml")
try:
    _rules = _config.load(_CONF_PATH)["thresholds"]
except (OSError, ValueError, KeyError):
    _rules = {}
CONF = {"thresholds": {"deescalate_windows": _rules.get("deescalate_windows", 3),
                       "escalate_window": _rules.get("escalate_window", 2),
                       "escalate_hits": _rules.get("escalate_hits", 2)},
        "learning": {"learn_include_empty": False}}
# how many quiet windows to replay before the injection so the ladder starts from a real
# state rather than an assumed one
PRE_WINDOWS = 6


def connect(path):
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    c.row_factory = sqlite3.Row
    return c


def load_baseline(c, mac):
    r = c.execute("select * from baselines where mac=? and active=1", (mac,)).fetchone()
    if not r:
        return None
    q = json.loads(r["quality_json"])
    d = json.loads(r["dest_set_json"])
    return {"id": r["id"], "created_at": r["created_at"],
            "names": json.loads(r["feature_names_json"]),
            "mean": np.array(json.loads(r["mean_json"])),
            "precision": np.array(json.loads(r["precision_json"])),
            "scale": np.array(q["scale"]),
            "thresholds": json.loads(r["thresholds_json"]),
            "dests": set(d["keys"]), "ips": set(d["ips"]),
            "services": set(json.loads(r["service_set_json"]))}


def d2_of(vec, b):
    z = (vec - b["mean"]) / b["scale"]
    return float(z @ b["precision"] @ z)


def spans(c, mac, since_ms=0):
    """(start_s, end_s, type, magnitude) per injection, from the node's own log"""
    rows = c.execute(
        "select device_ts_ms, action, type, magnitude from ground_truth"
        " where mac=? and class='anomaly' and device_ts_ms>? order by device_ts_ms",
        (mac, since_ms)).fetchall()
    out, open_row = [], None
    for r in rows:
        if r["action"] == "start":
            open_row = r
        elif open_row is not None:
            out.append((open_row["device_ts_ms"] / 1000.0, r["device_ts_ms"] / 1000.0,
                        open_row["type"], open_row["magnitude"]))
            open_row = None
    if open_row is not None:
        out.append((open_row["device_ts_ms"] / 1000.0, None, open_row["type"],
                    open_row["magnitude"]))
    return out


def window_rows(c, mac, lo, hi):
    return c.execute(
        "select * from windows where mac=? and window_start>=? and window_start<=?"
        " order by window_start", (mac, lo, hi)).fetchall()


def replay(c, b, mac, start, end):
    """drive the real state machine across an injection and report when it reacted"""
    lo = int(start) // WINDOW_SECONDS * WINDOW_SECONDS - PRE_WINDOWS * WINDOW_SECONDS
    hi = int((end or start + 3 * WINDOW_SECONDS)) // WINDOW_SECONDS * WINDOW_SECONDS + \
        6 * WINDOW_SECONDS
    tier, count, prev, recent = "normal", 0, [], 0
    first_alert = first_esc = None
    peak, peak_feat, during = 0.0, None, []
    steps = []
    for w in window_rows(c, mac, lo, hi):
        f = json.loads(w["features_json"])
        ct = json.loads(w["counters_json"])
        v = to_vector(f, b["names"])
        z = (v - b["mean"]) / b["scale"]
        wt = b["precision"] @ z
        d = float(z @ wt)
        tr = S.trusted_distance(w["packets"], w["complete"], CONF)
        nd, ns, _ = S.novelty(ct.get("dests", {}), set(ct.get("services", [])), b)
        hits = S.discrete_hits(nd, ns)
        tier, count, recent = S.decide_tier(tier, count, d, b["thresholds"], hits,
                                            S.hard_novelty(prev), tr, CONF, recent)
        # the engine stores new_dests + new_services together in new_dests_json and reads
        # hard_novelty off the pair, so a repeated service novelty reaches block. carrying
        # only the destinations here understates the ladder by one tier on a port swap
        prev = nd + ns
        w_end = w["window_start"] + WINDOW_SECONDS
        # an injection that expires 0.1 s into a window did not happen in that window.
        # require a real share of it before calling the window injected
        overlap = min(w_end, end or 9e18) - max(w["window_start"], start)
        inside = overlap >= WINDOW_SECONDS / 2
        if inside:
            during.append(d)
            if d > peak:
                peak = d
                peak_feat = b["names"][int(np.argmax(np.abs(z * wt)))]
        if inside and tier != "normal" and first_alert is None:
            first_alert = w_end
        if inside and tier in ("throttle", "block") and first_esc is None:
            first_esc = w_end
        steps.append((w["window_start"], round(d, 1), tier, w["packets"], inside))
    return {"first_alert": first_alert, "first_esc": first_esc, "peak": peak,
            "peak_feature": peak_feat, "during": during, "steps": steps}


def fmt(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%m-%d %H:%M:%S")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--since", default=None, help="YYYY-MM-DD, ignore anomalies before this")
    ap.add_argument("--steps", action="store_true", help="print every window of every trial")
    args = ap.parse_args(argv)
    since_ms = 0
    if args.since:
        since_ms = int(datetime.datetime.strptime(args.since, "%Y-%m-%d")
                       .replace(tzinfo=datetime.UTC).timestamp() * 1000)
    c = connect(args.db)
    macs = [r["mac"] for r in c.execute(
        "select distinct mac from ground_truth where class='anomaly'")]
    if not macs:
        print("no anomaly rows in ground_truth: no injection has run yet")
        return 1
    print("escalation rule in config.yaml: %d of the last %d windows" % (
        CONF["thresholds"]["escalate_hits"], CONF["thresholds"]["escalate_window"]))
    total = 0
    for mac in macs:
        b = load_baseline(c, mac)
        if not b:
            print("%s has no active baseline, skipped" % mac)
            continue
        found = spans(c, mac, since_ms)
        if not found:
            continue
        print("\n%s   baseline %d, t_alert %.2f, t_critical %.2f" % (
            mac, b["id"], b["thresholds"]["t_alert"], b["thresholds"]["t_critical"]))
        print("%-19s %-12s %7s %8s %9s %10s %9s  %s" % (
            "injected at", "type", "mag", "windows", "peak d2", "to alert", "to throt",
            "driver"))
        for start, end, kind, mag in found:
            total += 1
            r = replay(c, b, mac, start, end)
            if not r["during"]:
                print("%-19s %-12s %7.2f   no windows scored yet" % (fmt(start), kind, mag or 0))
                continue
            lat_a = "%.0fs" % (r["first_alert"] - start) if r["first_alert"] else "missed"
            lat_e = "%.0fs" % (r["first_esc"] - start) if r["first_esc"] else "none"
            print("%-19s %-12s %7.2f %8d %9.1f %10s %9s  %s" % (
                fmt(start), kind, mag or 0, len(r["during"]), r["peak"], lat_a, lat_e,
                r["peak_feature"] or "-"))
            if args.steps:
                for ws, d, tier, pk, inside in r["steps"]:
                    print("      %s  d2 %9.1f  %-8s pkts %5d %s" % (
                        fmt(ws), d, tier, pk, "<-- injected" if inside else ""))
    print("\n%d injection spans reported" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
