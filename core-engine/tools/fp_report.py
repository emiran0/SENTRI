"""RQ2: false positives in the units section 16 of the methodology notes fixes.

    python tools/fp_report.py /srv/sentri/sentri.db
    python tools/fp_report.py /srv/sentri/sentri.db --run-label fp-commercial-7d

Numerator is alert **episodes**, a maximal run of windows with the tier above normal, read
from the events table as tier_change-away-from-normal to the next tier_change-back. Windows
overstate the count because deescalate_windows holds a tier for three windows after the
deviation ends. Episodes are the headline, windows the raw figure, enforcement actions the
operational one, and all three are printed.

Denominator is monitored device-days under the active frozen baseline, scored windows over
288. A window that was never scored is in neither numerator nor denominator, so capture
gaps do not bias it.

The two populations are never pooled. The commercial devices are the RQ2 result; the
instrumented nodes are reported separately because their cloud endpoints were chosen by
the experimenter, so an endpoint's own reliability is an experimental variable rather than
a property of the method.

Episodes overlapping a labelled injection span are excluded and counted separately: an
injection is a true positive and belongs nowhere near a false positive rate.
"""

import argparse
import datetime
import json
import os
import sqlite3
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri.extract import WINDOW_SECONDS, to_vector

WINDOWS_PER_DAY = 86400 // WINDOW_SECONDS          # 288


# section 22 requires a Poisson interval on the episode count, not a bare rate. episodes are
# counts of events in an exposure, so the uncertainty is Poisson rather than binomial, and
# at these counts the normal approximation is wrong. this is the exact interval.
def poisson_ci(k, alpha=0.05):
    from scipy.stats import chi2
    lo = chi2.ppf(alpha / 2, 2 * k) / 2 if k > 0 else 0.0
    hi = chi2.ppf(1 - alpha / 2, 2 * (k + 1)) / 2
    return float(lo), float(hi)
COMMERCIAL = {"0c:ef:15:25:af:1a": "Tapo P100 plug", "e0:d3:62:fb:cb:97": "Tapo L630 bulb"}
INSTRUMENTED = {"ac:a7:04:f4:7e:dc": "plug-01", "1c:db:d4:75:b7:44": "sensor-01"}
NAME = dict(COMMERCIAL, **INSTRUMENTED)


def connect(path):
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    c.row_factory = sqlite3.Row
    return c


def active_baseline(c, mac):
    return c.execute("select * from baselines where mac=? and active=1", (mac,)).fetchone()


def injection_spans(c, mac):
    rows = c.execute("select device_ts_ms, action from ground_truth where mac=?"
                     " and class='anomaly' order by device_ts_ms", (mac,)).fetchall()
    spans, start = [], None
    for r in rows:
        if r["action"] == "start":
            start = r["device_ts_ms"] / 1000.0
        elif start is not None:
            spans.append((start, r["device_ts_ms"] / 1000.0))
            start = None
    return spans


def episodes(c, mac, since, until, spans):
    """maximal runs above normal, from the engine's own tier_change events"""
    rows = c.execute("select ts, tier, summary from events where mac=? and kind='tier_change'"
                     " and ts>=? and ts<=? order by ts", (mac, since, until)).fetchall()
    out, open_ep = [], None
    for r in rows:
        if r["tier"] != "normal" and open_ep is None:
            open_ep = {"start": r["ts"], "peak": r["tier"], "summary": r["summary"]}
        elif r["tier"] != "normal" and open_ep is not None:
            order = ("normal", "alert", "throttle", "block")
            if order.index(r["tier"]) > order.index(open_ep["peak"]):
                open_ep["peak"] = r["tier"]
        elif r["tier"] == "normal" and open_ep is not None:
            open_ep["end"] = r["ts"]
            out.append(open_ep)
            open_ep = None
    if open_ep is not None:
        open_ep["end"] = None
        out.append(open_ep)
    for e in out:
        e["injected"] = any(a < (e["end"] or e["start"] + WINDOW_SECONDS) and b > e["start"]
                            for a, b in spans)
    return out


# the categories section 16 fixes. everything that matches none of them is unexplained,
# and the unexplained rate is the figure worth defending
def reconnects(c, mac, lo, hi):
    """upstream reconnects the node logged itself, the only evidence that separates an
    endpoint degradation from an attack at the feature level"""
    return c.execute("select count(*) n from ground_truth where mac=? and class='connection'"
                     " and action='open' and device_ts_ms>=? and device_ts_ms<?",
                     (mac, int(lo * 1000), int(hi * 1000))).fetchone()["n"]


def classify(c, mac, ep, others):
    if ep["injected"]:
        return "injected (true positive)"
    start = ep["start"]
    w = c.execute("select * from windows where mac=? and window_start<=? order by window_start"
                  " desc limit 1", (mac, start)).fetchone()
    if w is None:
        return "unexplained"
    if not w["complete"] or not w["packets"]:
        return "capture interruption"
    # an instrumented node says so itself: a burst of reconnects is the endpoint failing,
    # not the device deviating. two is well above the median of zero in a normal window
    if mac in INSTRUMENTED and reconnects(c, mac, start, start + WINDOW_SECONDS) >= 2:
        return "upstream endpoint degradation"
    novel = json.loads(w["new_dests_json"] or "[]")
    if any(str(k).startswith("d:") for k in novel):
        return "scheduled second destination"
    if any(str(k).startswith("p:") for k in novel):
        return "endpoint address rotation"
    if any(str(k).startswith("tcp/") or str(k).startswith("udp/") for k in novel):
        return "new service"
    # a deviation that every same-vendor device shows in the same window is upstream
    if others:
        return "periodic vendor check-in (simultaneous on a peer device)"
    return "unexplained"


def report(c, macs, label, run_label, args):
    print("\n=== %s ===" % label)
    print("%-16s %8s %10s %9s %9s %9s %9s" % (
        "device", "windows", "device-days", "episodes", "windows>0", "enforce", "per dev-day"))
    totals = {"win": 0, "days": 0.0, "ep": 0, "aw": 0, "enf": 0}
    detail = {}
    for mac in macs:
        b = active_baseline(c, mac)
        if b is None:
            print("%-16s no active baseline" % NAME[mac])
            continue
        args_ = [mac, b["created_at"]]
        q = ("select count(*) n from scores s join windows w on w.id=s.window_id"
             " where s.mac=? and s.baseline_id=? ")
        # a run_label has to restrict the numerator and the denominator together. filtering
        # only the scored-window count against episodes drawn from the whole history
        # inflates the rate by whatever fraction of the exposure the label covers
        if run_label:
            row = c.execute(
                "select count(*) n, min(w.window_start) lo, max(w.window_start) hi"
                " from scores s join windows w on w.id=s.window_id"
                " where s.mac=? and s.baseline_id=? and w.label=?",
                (mac, b["id"], run_label)).fetchone()
            n_scored = row["n"]
            span_lo = row["lo"] if row["lo"] is not None else b["created_at"]
            span_hi = (row["hi"] + WINDOW_SECONDS) if row["hi"] is not None else span_lo
        else:
            n_scored = c.execute(
                "select count(*) n from scores where mac=? and baseline_id=?",
                (mac, b["id"])).fetchone()["n"]
            span_lo = b["created_at"]
            span_hi = None
        last = c.execute("select max(window_start) m from windows where mac=?",
                         (mac,)).fetchone()["m"] or b["created_at"]
        spans = injection_spans(c, mac)
        eps = episodes(c, mac, span_lo, span_hi or (last + WINDOW_SECONDS), spans)
        clean = [e for e in eps if not e["injected"]]
        inj = [e for e in eps if e["injected"]]
        # raw anomalous windows, recomputed rather than grouped off scores.tier, which is a
        # stateless severity. one join rather than a query per window: the per-window form
        # took minutes on four thousand windows
        aw = 0
        th = json.loads(b["thresholds_json"])["t_alert"]
        for w in c.execute(
                "select w.window_start, w.complete, w.packets, s.d2 from windows w"
                " join scores s on s.window_id = w.id"
                " where w.mac = ? and s.baseline_id = ?", (mac, b["id"])):
            if not (w["complete"] and w["packets"] and w["d2"] >= th):
                continue
            if any(a < w["window_start"] + WINDOW_SECONDS and b_ > w["window_start"]
                   for a, b_ in spans):
                continue
            aw += 1
        enf = c.execute("select count(*) n from enforcement where mac=? and applied_at>=?"
                        " and tier!='normal'", (mac, b["created_at"])).fetchone()["n"]
        days = n_scored / WINDOWS_PER_DAY
        print("%-16s %8d %10.2f %9d %9d %9d %9.2f" % (
            NAME[mac], n_scored, days, len(clean), aw, enf,
            len(clean) / days if days else 0))
        if inj:
            print("%-16s   (+%d injected episodes excluded as true positives)" % ("", len(inj)))
        totals["win"] += n_scored
        totals["days"] += days
        totals["ep"] += len(clean)
        totals["aw"] += aw
        totals["enf"] += enf
        detail[mac] = clean
    if totals["days"]:
        print("%-16s %8d %10.2f %9d %9d %9d %9.2f" % (
            "POPULATION", totals["win"], totals["days"], totals["ep"], totals["aw"],
            totals["enf"], totals["ep"] / totals["days"]))
        lo, hi = poisson_ci(totals["ep"])
        print("%-16s episodes %d, Poisson 95%% CI %.1f to %.1f, so %.2f to %.2f per "
              "device-day" % ("", totals["ep"], lo, hi, lo / totals["days"],
                              hi / totals["days"]))
    # cause classification
    print("\n  episodes by cause:")
    counts = {}
    for mac, eps in detail.items():
        for e in eps:
            peers = [m for m in detail if m != mac and any(
                abs(o["start"] - e["start"]) < WINDOW_SECONDS for o in detail[m])]
            cause = classify(c, mac, e, peers)
            counts[cause] = counts.get(cause, 0) + 1
    if not counts:
        print("    none")
    for k, v in sorted(counts.items(), key=lambda x: -x[1]):
        print("    %-52s %3d" % (k, v))
    unexplained = counts.get("unexplained", 0)
    if totals["days"]:
        print("  unexplained rate: %.2f per device-day" % (unexplained / totals["days"]))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--run-label", default=None,
                    help="restrict to windows carrying this run_label")
    args = ap.parse_args(argv)
    c = connect(args.db)
    print("RQ2 false positives, per section 16 of the methodology notes")
    print("numerator: alert episodes  denominator: device-days = scored windows / %d"
          % WINDOWS_PER_DAY)
    if args.run_label:
        print("restricted to run_label %r" % args.run_label)
    report(c, list(COMMERCIAL), "COMMERCIAL DEVICES (the RQ2 result)", args.run_label, args)
    report(c, list(INSTRUMENTED), "INSTRUMENTED NODES (reported separately, never pooled)",
           args.run_label, args)
    print("\nNote: section 16 requires at least 7 continuous device-days per device with no"
          "\nrefit, restart or config edit inside the window. Check the exposure above"
          "\nbefore quoting any of this as the RQ2 answer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
