"""RQ4 detection half: score annotated dataset attacks against replayed baselines.

    python tools/bench_detection.py /srv/sentri/replay/unsw/unsw.db \
        --annotations /srv/sentri/replay/raw/annotations

Section 18.2 fixes how a dataset label maps onto a 300 s window: a window counts as
attacked when the annotated span covers at least half of it, the same overlap rule the
live injection analysis uses, so the two are comparable rather than merely adjacent.

Every UNSW attack span is 600 s, which is exactly two windows, and each attack type appears
at 1, 10 and 100 packets per second. That is a magnitude ladder by construction and it is
reported as one.

Windows that no annotation covers are the benchmark's benign windows, and their alert rate
is the false positive half of RQ4 on the same corpus.
"""

import argparse
import collections
import glob
import json
import math
import os
import sqlite3
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

from sentri import score as S
from sentri.extract import WINDOW_SECONDS, to_vector

CONF = {"thresholds": {"deescalate_windows": 3, "escalate_window": 3, "escalate_hits": 2},
        "learning": {"learn_include_empty": False}}


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def load_annotations(directory):
    out = collections.defaultdict(list)
    for f in sorted(glob.glob(os.path.join(directory, "*.csv"))):
        mac = os.path.basename(f).split(".")[0].split("-")[0]
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2)).lower()
        for line in open(f):
            p = line.strip().split(",")
            if len(p) < 4:
                continue
            try:
                out[mac].append((int(p[0]), int(p[1]), p[2], p[3]))
            except ValueError:
                continue
    return out


def family(name):
    """strip the rate and topology suffix: TcpSynReflection100W2D2W -> TcpSynReflection"""
    return name.rstrip("WD0123456789L").rstrip("0123456789") or name


def rate(name):
    for r in (100, 10, 1):
        if str(r) in name:
            return r
    return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--eval-from", default=None,
                    help="ISO UTC time the evaluation set starts; default is the largest\n                         gap in the windows, which separates the two captures")
    args = ap.parse_args(argv)
    c = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
    c.row_factory = sqlite3.Row
    ann = load_annotations(args.annotations)
    eval_from = None
    if args.eval_from:
        from datetime import datetime as _dt
        eval_from = _dt.fromisoformat(args.eval_from).replace(
            tzinfo=timezone.utc).timestamp()

    cells = collections.defaultdict(lambda: {"n": 0, "det": 0, "esc": 0, "peaks": []})
    benign_windows = benign_alerts = 0
    per_attack = []

    for b in c.execute("select * from baselines where active=1"):
        mac = b["mac"]
        q = json.loads(b["quality_json"])
        d = json.loads(b["dest_set_json"])
        base = {"names": json.loads(b["feature_names_json"]),
                "mean": np.array(json.loads(b["mean_json"])),
                "precision": np.array(json.loads(b["precision_json"])),
                "scale": np.array(q["scale"]),
                "thresholds": json.loads(b["thresholds_json"]),
                "dests": set(d["keys"]), "ips": set(d["ips"]),
                "services": set(json.loads(b["service_set_json"]))}
        spans = ann.get(mac, [])
        # NOT filtered on baselines.created_at. That column is wall clock, stamped when the
        # fit ran, while window_start is dataset time. In a replay they are years apart and
        # the obvious filter silently selects nothing. The evaluation set is instead every
        # window after the largest gap, which is the boundary between the benign capture
        # and the attack capture.
        rows = list(c.execute(
            "select * from windows where mac=? order by window_start", (mac,)))
        if not rows:
            continue
        cut = eval_from
        if cut is None:
            gaps = [(rows[i + 1]["window_start"] - rows[i]["window_start"], i + 1)
                    for i in range(len(rows) - 1)]
            if gaps:
                biggest, idx = max(gaps)
                cut = rows[idx]["window_start"] if biggest > 6 * 3600 else 0
        rows = [r for r in rows if r["window_start"] >= (cut or 0)]
        if not rows:
            continue

        scored = []
        tier, count, prev, recent = "normal", 0, [], 0
        for w in rows:
            f = json.loads(w["features_json"])
            ct = json.loads(w["counters_json"])
            z = (to_vector(f, base["names"]) - base["mean"]) / base["scale"]
            d2 = float(z @ base["precision"] @ z)
            tr = S.trusted_distance(w["packets"], w["complete"], CONF)
            nd, ns, _ = S.novelty(ct.get("dests", {}), set(ct.get("services", [])), base)
            hits = S.discrete_hits(nd, ns)
            tier, count, recent = S.decide_tier(tier, count, d2, base["thresholds"], hits,
                                                S.hard_novelty(prev), tr, CONF, recent)
            prev = nd + ns
            flagged = (tr and d2 >= base["thresholds"]["t_alert"]) or bool(hits)
            scored.append((w["window_start"], d2, flagged, tier))

        for lo, hi, tags, name in spans:
            # section 18.2: a window is attacked when the span covers at least half of it
            covered = [s for s in scored
                       if min(s[0] + WINDOW_SECONDS, hi) - max(s[0], lo) >= WINDOW_SECONDS / 2]
            if not covered:
                continue
            det = any(s[2] for s in covered)
            esc = any(s[3] in ("throttle", "block") for s in covered)
            peak = max(s[1] for s in covered)
            key = (family(name), rate(name))
            cell = cells[key]
            cell["n"] += 1
            cell["det"] += int(det)
            cell["esc"] += int(esc)
            cell["peaks"].append(peak)
            per_attack.append((mac, name, lo, len(covered), det, esc, peak))

        attacked = set()
        for lo, hi, _, _ in spans:
            for s in scored:
                if min(s[0] + WINDOW_SECONDS, hi) - max(s[0], lo) >= WINDOW_SECONDS / 2:
                    attacked.add(s[0])
        for ws, d2, flagged, _ in scored:
            if ws not in attacked:
                benign_windows += 1
                benign_alerts += int(flagged)

    print("=== RQ4 detection, UNSW attack corpus, unmodified pipeline ===\n")
    print("%-22s %6s %8s %20s %9s %11s" % (
        "attack family", "rate", "detected", "Wilson 95% CI", "escalated", "median d2"))
    for (fam, r), v in sorted(cells.items(), key=lambda kv: (kv[0][0], kv[0][1] or 0)):
        lo, hi = wilson(v["det"], v["n"])
        print("%-22s %5s %5d/%-2d %10.2f to %-8.2f %5d/%-2d %11.1f" % (
            fam, "%s/s" % r if r else "-", v["det"], v["n"], lo, hi, v["esc"], v["n"],
            float(np.median(v["peaks"]))))

    tot_n = sum(v["n"] for v in cells.values())
    tot_d = sum(v["det"] for v in cells.values())
    tot_e = sum(v["esc"] for v in cells.values())
    if tot_n:
        lo, hi = wilson(tot_d, tot_n)
        print("\noverall: %d/%d attacks detected (Wilson %.2f to %.2f), %d escalated"
              % (tot_d, tot_n, lo, hi, tot_e))
    if benign_windows:
        lo, hi = wilson(benign_alerts, benign_windows)
        print("benchmark false positives: %d of %d unattacked windows flagged, %.2f%% "
              "(Wilson %.2f to %.2f%%)" % (benign_alerts, benign_windows,
                                           100 * benign_alerts / benign_windows,
                                           100 * lo, 100 * hi))

    print("\n=== per attack ===")
    print("%-20s %-26s %-17s %5s %4s %4s %10s" % (
        "device", "attack", "start", "wins", "det", "esc", "peak d2"))
    for mac, name, lo_ts, nw, det, esc, peak in sorted(per_attack, key=lambda x: x[2]):
        print("%-20s %-26s %-17s %5d %4s %4s %10.1f" % (
            mac, name[:26],
            datetime.fromtimestamp(lo_ts, timezone.utc).strftime("%m-%d %H:%M"),
            nw, "yes" if det else "NO", "yes" if esc else "-", peak))
    return 0


if __name__ == "__main__":
    sys.exit(main())
