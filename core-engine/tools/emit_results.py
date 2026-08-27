"""Emit every measured figure into docs/results/results.jsonl.

    python tools/emit_results.py /path/to/db-copy

Recomputes each figure from the database rather than copying it out of a note, so the
machine-readable results file cannot drift from the data. Rerunning replaces the rows for
the experiments it knows about and leaves any others alone.

Proportions carry a Wilson score interval, which section 22 of the methodology notes
requires: a bare proportion from a handful of trials is not reportable.
"""

import argparse
import json
import math
import os
import sqlite3
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import score as S
from sentri.extract import WINDOW_SECONDS, to_vector

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "docs", "results", "results.jsonl")
CONF = {"thresholds": {"deescalate_windows": 3, "escalate_window": 2, "escalate_hits": 2},
        "learning": {"learn_include_empty": False}}
WINDOWS_PER_DAY = 86400 // WINDOW_SECONDS
COMMERCIAL = {"0c:ef:15:25:af:1a": "tapo-plug", "e0:d3:62:fb:cb:97": "tapo-bulb"}
NODES = {"ac:a7:04:f4:7e:dc": "plug-01", "1c:db:d4:75:b7:44": "sensor-01"}
NAME = dict(COMMERCIAL, **NODES)
TODAY = time.strftime("%Y-%m-%d")


def wilson(k, n, z=1.96):
    """score interval, correct at small n where the normal approximation is not"""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def connect(path):
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    c.row_factory = sqlite3.Row
    return c


def baseline(c, mac):
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


def d2_of(v, b):
    z = (v - b["mean"]) / b["scale"]
    return float(z @ b["precision"] @ z)


def spans(c, mac):
    rows = c.execute("select device_ts_ms, action, type, magnitude from ground_truth"
                     " where mac=? and class='anomaly' order by device_ts_ms", (mac,)).fetchall()
    out, op = [], None
    for r in rows:
        if r["action"] == "start":
            op = r
        elif op is not None:
            out.append((op["device_ts_ms"] / 1000.0, r["device_ts_ms"] / 1000.0,
                        op["type"], op["magnitude"]))
            op = None
    return out


def rows_for(c):
    emitted = []

    def add(**kw):
        kw.setdefault("measured_at", TODAY)
        emitted.append(kw)

    # ---------------- RQ2, false positives, observe-mode exposure
    for group, macs, label in (("commercial", COMMERCIAL, "commercial-false-positives"),
                               ("instrumented", NODES, "node-false-positives")):
        tot_days = tot_ep = tot_win = 0
        for mac in macs:
            b = baseline(c, mac)
            if not b:
                continue
            n = c.execute("select count(*) n from scores where mac=? and baseline_id=?",
                          (mac, b["id"])).fetchone()["n"]
            sp = spans(c, mac)
            evs = c.execute("select ts, tier from events where mac=? and kind='tier_change'"
                            " and ts>=? order by ts", (mac, b["created_at"])).fetchall()
            eps, open_ = 0, False
            for e in evs:
                if e["tier"] != "normal" and not open_:
                    if not any(a < e["ts"] + WINDOW_SECONDS and bb > e["ts"]
                               for a, bb, _k, _m in sp):
                        eps += 1
                    open_ = True
                elif e["tier"] == "normal":
                    open_ = False
            tot_days += n / WINDOWS_PER_DAY
            tot_ep += eps
            tot_win += n
        if tot_days:
            add(rq="RQ2", experiment=label, metric="episodes_per_device_day",
                value=round(tot_ep / tot_days, 3), unit="episodes/device-day", n=tot_ep,
                exposure=round(tot_days, 2), exposure_unit="device-days",
                conditions="observe mode, active frozen baselines, injected episodes excluded",
                source="tools/fp_report.py")
            add(rq="RQ2", experiment=label, metric="scored_windows",
                value=tot_win, unit="windows", exposure=round(tot_days, 2),
                exposure_unit="device-days", conditions="denominator basis",
                source="tools/emit_results.py")

    # ---------------- RQ1, live injections
    cells = {}
    for mac in NODES:
        b = baseline(c, mac)
        if not b:
            continue
        for start, end, kind, mag in spans(c, mac):
            ws = c.execute(
                "select * from windows where mac=? and window_start>=? and window_start<?"
                " order by window_start",
                (mac, int(start) // WINDOW_SECONDS * WINDOW_SECONDS, end)).fetchall()
            flagged, n_win, peak = 0, 0, 0.0
            for w in ws:
                ov = min(w["window_start"] + WINDOW_SECONDS, end) - max(w["window_start"], start)
                if ov < WINDOW_SECONDS / 2:
                    continue
                n_win += 1
                f = json.loads(w["features_json"])
                ct = json.loads(w["counters_json"])
                d = d2_of(to_vector(f, b["names"]), b)
                peak = max(peak, d)
                nd, ns, _ = S.novelty(ct.get("dests", {}), set(ct.get("services", [])), b)
                tr = S.trusted_distance(w["packets"], w["complete"], CONF)
                if (tr and d >= b["thresholds"]["t_alert"]) or nd or ns:
                    flagged += 1
            if not n_win:
                continue
            key = (NAME[mac], kind, float(mag or 0))
            cell = cells.setdefault(key, {"trials": 0, "detected": 0, "peaks": []})
            cell["trials"] += 1
            cell["detected"] += 1 if flagged else 0
            cell["peaks"].append(peak)
    for (dev, kind, mag), v in sorted(cells.items()):
        lo, hi = wilson(v["detected"], v["trials"])
        add(rq="RQ1", experiment="live-injection", metric="detection_rate",
            device=dev, anomaly_type=kind, magnitude=mag,
            value=round(v["detected"] / v["trials"], 3), unit="proportion of trials",
            ci_low=round(lo, 3), ci_high=round(hi, 3),
            n=v["trials"], exposure=v["trials"], exposure_unit="trials",
            conditions="observe mode, 3 injected windows per trial, boundary aligned",
            source="tools/inject_report.py")
        add(rq="RQ1", experiment="live-injection", metric="peak_d2",
            device=dev, anomaly_type=kind, magnitude=mag,
            value=round(float(np.median(v["peaks"])), 1), unit="squared Mahalanobis distance",
            n=v["trials"], exposure=v["trials"], exposure_unit="trials",
            conditions="median across repetitions of the cell",
            source="tools/inject_report.py")

    # ---------------- RQ4 arm A, destination keying as deployed
    for mac in NAME:
        b = baseline(c, mac)
        if not b:
            continue
        dk = pk = 0
        ips = set()
        for w in c.execute("select counters_json from windows where mac=? and window_start>=?",
                           (mac, b["created_at"])):
            for k, addrs in json.loads(w["counters_json"]).get("dests", {}).items():
                if k.startswith("p:"):
                    pk += 1
                else:
                    dk += 1
                ips.update(addrs)
        add(rq="RQ4", experiment="destination-keying-live", metric="distinct_peer_addresses",
            device=NAME[mac], value=len(ips), unit="addresses",
            conditions="arm A, resolver available", source="tools/results.py keys")
        add(rq="RQ4", experiment="destination-keying-live", metric="prefix_keyed_windows",
            device=NAME[mac], value=pk, unit="window-key instances",
            conditions="arm A, resolver available", source="tools/results.py keys")
    return emitted


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args(argv)
    c = connect(args.db)
    fresh = rows_for(c)
    known = {(r["rq"], r["experiment"]) for r in fresh}
    kept = []
    if os.path.exists(args.out):
        for line in open(args.out):
            if not line.strip():
                continue
            r = json.loads(line)
            if (r.get("rq"), r.get("experiment")) not in known:
                kept.append(r)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        for r in kept + fresh:
            f.write(json.dumps(r) + "\n")
    print("wrote %d rows (%d refreshed, %d preserved) to %s"
          % (len(kept) + len(fresh), len(fresh), len(kept), args.out))
    for r in fresh:
        if r["metric"] in ("episodes_per_device_day", "detection_rate"):
            extra = ""
            if "ci_low" in r:
                extra = "  CI %.2f-%.2f" % (r["ci_low"], r["ci_high"])
            print("  %-4s %-26s %-18s %8s%s" % (
                r["rq"], r.get("device", r["experiment"])[:26], r["metric"],
                r["value"], extra))
    return 0


if __name__ == "__main__":
    sys.exit(main())
