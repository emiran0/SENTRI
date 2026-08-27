"""Section 22 reporting for RQ1: detection rate, windows to detection, and the curve.

    python tools/detection_curve.py /path/to/db-copy --since 1787689223

Three things section 22 fixes that a bare detection table does not give:

* the **Wilson score interval**, never a bare proportion, because at 3 to 5 repetitions the
  width of the interval is the correct message about what a small testbed supports;
* **windows to detection as median and full range**, never mean and standard deviation,
  because the quantity is a small skewed integer and a mean implies precision that is not
  there;
* the **curve plotted from the floor up**, including the magnitudes that are not separable,
  because the floor of the curve is itself a result about what behavioural baselining
  cannot do.

Seconds are reported as a secondary figure with the pipeline lag decomposed, so the
architectural floor stays visible as a floor rather than being folded into an average.
"""

import argparse
import json
import math
import os
import sqlite3
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import score as S
from sentri.extract import WINDOW_SECONDS, to_vector

CONF = {"thresholds": {"deescalate_windows": 3, "escalate_window": 3, "escalate_hits": 2},
        "learning": {"learn_include_empty": False}}
NAME = {"ac:a7:04:f4:7e:dc": "plug-01", "1c:db:d4:75:b7:44": "sensor-01"}
# section 14: the score for a window is written 65 to 395 s after the window ends, so an
# alert on a sustained anomaly appears 365 to 695 s after it starts
PIPELINE_LAG = (65, 395)


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def load_baseline(c, mac):
    r = c.execute("select * from baselines where mac=? and active=1", (mac,)).fetchone()
    q = json.loads(r["quality_json"])
    d = json.loads(r["dest_set_json"])
    return {"names": json.loads(r["feature_names_json"]),
            "mean": np.array(json.loads(r["mean_json"])),
            "precision": np.array(json.loads(r["precision_json"])),
            "scale": np.array(q["scale"]),
            "thresholds": json.loads(r["thresholds_json"]),
            "dests": set(d["keys"]), "ips": set(d["ips"]),
            "services": set(json.loads(r["service_set_json"]))}


def trials(c, mac, since):
    b = load_baseline(c, mac)
    rows = c.execute("select device_ts_ms, action, type, magnitude from ground_truth where"
                     " mac=? and class='anomaly' and device_ts_ms>=? order by device_ts_ms",
                     (mac, int(since * 1000))).fetchall()
    out, op = [], None
    for r in rows:
        if r["action"] == "start":
            op = r
            continue
        if op is None:
            continue
        start, end = op["device_ts_ms"] / 1000.0, r["device_ts_ms"] / 1000.0
        kind, mag = op["type"], float(op["magnitude"] or 0)
        op = None
        tier, count, prev, recent = "normal", 0, [], 0
        peak, index, detected_at, escalated = 0.0, 0, None, None
        for w in c.execute("select * from windows where mac=? and window_start>=? and"
                           " window_start<? order by window_start",
                           (mac, int(start) // WINDOW_SECONDS * WINDOW_SECONDS, end)):
            f = json.loads(w["features_json"])
            ct = json.loads(w["counters_json"])
            z = (to_vector(f, b["names"]) - b["mean"]) / b["scale"]
            d2 = float(z @ b["precision"] @ z)
            tr = S.trusted_distance(w["packets"], w["complete"], CONF)
            nd, ns, _ = S.novelty(ct.get("dests", {}), set(ct.get("services", [])), b)
            hits = S.discrete_hits(nd, ns)
            tier, count, recent = S.decide_tier(tier, count, d2, b["thresholds"], hits,
                                                S.hard_novelty(prev), tr, CONF, recent)
            prev = nd + ns
            overlap = min(w["window_start"] + WINDOW_SECONDS, end) - max(w["window_start"], start)
            if overlap < WINDOW_SECONDS / 2:
                continue
            index += 1
            peak = max(peak, d2)
            flagged = (tr and d2 >= b["thresholds"]["t_alert"]) or bool(hits)
            if flagged and detected_at is None:
                detected_at = index
            if tier in ("throttle", "block") and escalated is None:
                escalated = index
        out.append({"type": kind, "magnitude": mag, "windows": index, "peak": peak,
                    "detected_at": detected_at, "escalated_at": escalated})
    return out


def report(c, since, emit):
    cells = {}
    for mac in NAME:
        for t in trials(c, mac, since):
            key = (NAME[mac], t["type"], t["magnitude"])
            cells.setdefault(key, []).append(t)

    print("Section 22 reporting, RQ1\n")
    print("%-11s %-12s %12s %8s %20s %10s %14s" % (
        "device", "type", "magnitude", "detect", "Wilson 95% CI", "escalate",
        "windows to detect"))
    rows = []
    for (dev, kind, mag), ts in sorted(cells.items()):
        n = len(ts)
        det = sum(1 for t in ts if t["detected_at"])
        esc = sum(1 for t in ts if t["escalated_at"])
        lo, hi = wilson(det, n)
        wtd = [t["detected_at"] for t in ts if t["detected_at"]]
        label = "%g" % mag if kind != "destination" else "%.0fs" % (mag / 1000)
        # median and full range, never mean and standard deviation: the quantity is a small
        # skewed integer and n is 1 to 3
        span = ("%d (%d to %d)" % (int(np.median(wtd)), min(wtd), max(wtd))) if wtd else "-"
        print("%-11s %-12s %12s %4d/%-3d %8.2f to %-8.2f %5d/%-3d %14s" % (
            dev, kind, label, det, n, lo, hi, esc, n, span))
        rows.append({"device": dev, "type": kind, "magnitude": mag, "n": n, "det": det,
                     "esc": esc, "lo": lo, "hi": hi, "wtd": wtd,
                     "peak": float(np.median([t["peak"] for t in ts]))})

    all_wtd = [w for r in rows for w in r["wtd"]]
    if all_wtd:
        print("\nwindows to detection, all detected trials pooled: median %d, range %d to %d"
              % (int(np.median(all_wtd)), min(all_wtd), max(all_wtd)))
        lo_s = int(np.median(all_wtd)) * WINDOW_SECONDS + PIPELINE_LAG[0]
        hi_s = int(np.median(all_wtd)) * WINDOW_SECONDS + PIPELINE_LAG[1]
        print("in seconds, secondary: %d window(s) x %d s plus %d to %d s pipeline lag"
              % (int(np.median(all_wtd)), WINDOW_SECONDS, *PIPELINE_LAG))
        print("                       = %d to %d s from anomaly start to alert" % (lo_s, hi_s))
        print("the %d s window is the architectural floor; the lag is implementation cost"
              % WINDOW_SECONDS)
    if emit:
        write_rows(rows, emit)
    return rows


def write_rows(rows, path):
    keep = [json.loads(x) for x in open(path) if x.strip()] if os.path.exists(path) else []
    keep = [r for r in keep if r.get("experiment") != "windows-to-detection"]
    for r in rows:
        if not r["wtd"]:
            continue
        keep.append({
            "rq": "RQ1", "experiment": "windows-to-detection", "device": r["device"],
            "anomaly_type": r["type"], "magnitude": r["magnitude"],
            "metric": "windows_to_detection_median", "value": int(np.median(r["wtd"])),
            "unit": "windows", "n": len(r["wtd"]), "exposure": r["n"],
            "exposure_unit": "trials",
            "conditions": "median with range %d to %d; section 22 forbids mean and sd here"
                          % (min(r["wtd"]), max(r["wtd"])),
            "source": "tools/detection_curve.py", "measured_at": "2026-08-26"})
    with open(path, "w") as f:
        for r in keep:
            f.write(json.dumps(r) + "\n")
    print("\nwrote windows-to-detection rows to %s" % path)


def plot(rows, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    devices = sorted({r["device"] for r in rows})
    fig, axes = plt.subplots(1, len(devices), figsize=(5.2 * len(devices), 4.2), sharey=True)
    if len(devices) == 1:
        axes = [axes]
    for ax, dev in zip(axes, devices):
        notes = []
        for kind in sorted({r["type"] for r in rows if r["device"] == dev}):
            pts = sorted([r for r in rows if r["device"] == dev and r["type"] == kind],
                         key=lambda r: r["magnitude"])
            if kind in ("destination", "protocol"):
                # categorical, so it has no place on a magnitude axis at all. section 15
                # says to report it as a categorical result and say why, not as a curve
                for p in pts:
                    label = ("%.0f s beacon" % (p["magnitude"] / 1000)
                             if kind == "destination" else "port swap")
                    notes.append("%s %s: %d/%d" % (kind, label, p["det"], p["n"]))
                continue
            x = [p["magnitude"] for p in pts]
            y = [p["det"] / p["n"] for p in pts]
            err = [[y[i] - pts[i]["lo"] for i in range(len(pts))],
                   [pts[i]["hi"] - y[i] for i in range(len(pts))]]
            ax.errorbar(x, y, yerr=err, marker="o", capsize=3, label=kind)
        ax.set_title(dev)
        ax.set_xlabel("volume magnitude (x)")
        # the floor of the curve is a result, so the axis starts at zero detection
        ax.set_ylim(-0.05, 1.15)
        ax.axhline(0.5, color="grey", lw=0.6, ls=":")
        ax.grid(alpha=0.25)
        if notes:
            ax.text(0.03, 0.97, "categorical, not on this axis:\n" + "\n".join(notes),
                    transform=ax.transAxes, va="top", ha="left", fontsize=7.5,
                    bbox={"boxstyle": "round", "fc": "white", "ec": "grey", "alpha": 0.85})
    axes[0].set_ylabel("detection rate (Wilson 95% CI)")
    axes[-1].legend(fontsize=8, loc="lower right")
    fig.suptitle("RQ1 detection curve, 3 repetitions per volume cell", fontsize=11)
    fig.tight_layout()
    os.makedirs(os.path.dirname(out), exist_ok=True)
    fig.savefig(out, dpi=150)
    print("wrote %s" % out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--since", type=float, default=0.0,
                    help="epoch seconds; restrict to one campaign")
    ap.add_argument("--emit", default=None, help="append figures to this results.jsonl")
    ap.add_argument("--plot", default=None, help="write the detection curve here")
    args = ap.parse_args(argv)
    c = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
    c.row_factory = sqlite3.Row
    rows = report(c, args.since, args.emit)
    if args.plot:
        plot(rows, args.plot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
