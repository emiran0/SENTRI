"""Section 19: DNS provenance ablation, arms A and B over the same stored windows.

    python tools/ablate_provenance.py /path/to/db-copy

Arm A is the system as deployed: destinations keyed by registrable domain where the
resolver log gave provenance, by /24 prefix otherwise.
Arm B ignores the resolver entirely and keys every destination by /24 prefix, which is the
condition a benchmark capture imposes because it ships no resolver log.

Both arms run over the *same* window range, so the only variable is the key space.

The critical constraint from section 19: a baseline fitted on prefix keys cannot be scored
against domain-keyed windows or the reverse, because every window would then emit a key
absent from the learned set and register as hard novelty. So each arm gets its own learning
run and its own fit here, and nothing is backfilled. `distinct_peers` also changes meaning
between the arms, since one domain fronted by several addresses becomes several keys, so
arm B is not arm A with more alerts: it is a different model.

Arm C, the benchmark replay, needs the replay path that section 18.1 records as missing.
A minus B is what this tool measures: how much of the deployment gap the one mechanism
explains. B minus C is the residual and is not available yet.
"""

import argparse
import json
import os
import sys

import numpy as np
from scipy.stats import chi2
from sklearn.covariance import LedoitWolf

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import config as _config
from sentri import score as S
from sentri.extract import WINDOW_SECONDS, to_vector

CALIB_CHUNKS, CALIB_HOLDOUT, RIDGE = 10, (4, 9), 1e-6
NAME = {"0c:ef:15:25:af:1a": "tapo-plug", "e0:d3:62:fb:cb:97": "tapo-bulb",
        "ac:a7:04:f4:7e:dc": "plug-01", "1c:db:d4:75:b7:44": "sensor-01"}


def prefix_of(addr):
    return "p:" + addr.rsplit(".", 1)[0] + ".0/24"


def rekey(dests, arm):
    """arm A keeps the stored keys, arm B collapses every address to its /24"""
    if arm == "A":
        return {k: list(v) for k, v in dests.items()}
    out = {}
    for addrs in dests.values():
        for a in addrs:
            out.setdefault(prefix_of(a), set()).add(a)
    return {k: sorted(v) for k, v in out.items()}


def window_view(w, arm, names):
    """feature vector and destination set for one window under one arm"""
    feats = dict(json.loads(w["features_json"]))
    ct = json.loads(w["counters_json"])
    dests = rekey(ct.get("dests", {}), arm)
    # distinct_peers counts destination keys, so it changes meaning with the key space
    feats["distinct_peers"] = float(len(dests))
    return to_vector(feats, names), dests, set(ct.get("services", []))


def fit(rows, arm, names, floors):
    mats, dests, ips, svcs = [], set(), set(), set()
    for w in rows:
        v, d, s = window_view(w, arm, names)
        mats.append(v)
        dests |= set(d)
        for addrs in d.values():
            ips |= set(addrs)
        svcs |= s
    m = np.array(mats)
    st = np.array([w["window_start"] for w in rows])
    span = max(1, int(st[-1] - st[0]) + 1)
    held = np.isin((st - st[0]) * CALIB_CHUNKS // span, CALIB_HOLDOUT)
    if len(m) - int(held.sum()) <= len(names) + 1 or held.sum() < 2:
        held = np.zeros(len(m), bool)
        held[-1] = True
    train, calib = m[~held], m[held]
    mean = train.mean(axis=0)
    scale = np.maximum(train.std(axis=0), np.array([floors[n] for n in names]))
    cov = LedoitWolf(assume_centered=True).fit((train - mean) / scale).covariance_
    precision = np.linalg.inv(cov + RIDGE * np.eye(len(names)))
    z = (calib - mean) / scale
    cd = np.einsum("ij,jk,ik->i", z, precision, z)
    t_alert = max(float(np.percentile(cd, 95)), float(chi2.ppf(0.999, len(names))))
    return {"names": names, "mean": mean, "scale": scale, "precision": precision,
            "dests": dests, "ips": ips, "services": svcs,
            "thresholds": {"t_alert": t_alert, "t_critical": t_alert * 10.0},
            "n_fit": len(train)}


def evaluate(rows, arm, base, conf):
    tier, count, prev, recent = "normal", 0, [], 0
    far = novel_windows = esc = 0
    rotations = 0
    d2s = []
    for w in rows:
        v, dests, svcs = window_view(w, arm, base["names"])
        z = (v - base["mean"]) / base["scale"]
        d = float(z @ base["precision"] @ z)
        trusted = S.trusted_distance(w["packets"], w["complete"], conf)
        nd, ns, rot = S.novelty(dests, svcs, base)
        rotations += rot
        hits = S.discrete_hits(nd, ns)
        before = tier
        tier, count, recent = S.decide_tier(tier, count, d, base["thresholds"], hits,
                                            S.hard_novelty(prev), trusted, conf, recent)
        prev = nd + ns
        if trusted:
            d2s.append(d)
            far += d >= base["thresholds"]["t_alert"]
        novel_windows += bool(hits)
        if S.TIERS.index(tier) > S.TIERS.index(before) and tier != "alert":
            esc += 1
    return {"n": len(rows), "far": far, "novel": novel_windows, "esc": esc,
            "rotations": rotations, "d2": np.array(d2s), "keys": len(base["dests"])}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    args = ap.parse_args(argv)
    if os.path.realpath(args.db) == "/srv/sentri/sentri.db":
        print("refusing to run against the live database, take a copy first")
        return 2
    import sqlite3
    c = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
    c.row_factory = sqlite3.Row
    conf = _config.load(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "config.yaml"))
    floors = conf["variance_floors"]
    names = conf["model_features"]
    ls = dict(c.execute("select mac, learning_started from devices"))

    print("Section 19 DNS provenance ablation, arms A and B on the same stored windows")
    print("arm A: domain where the resolver gave provenance, prefix otherwise (as deployed)")
    print("arm B: prefix only, resolver ignored (the benchmark condition)\n")

    for mac in NAME:
        b = c.execute("select created_at from baselines where mac=? and active=1",
                      (mac,)).fetchone()
        if not b:
            continue
        start = ls[mac]
        learn = [w for w in c.execute(
            "select * from windows where mac=? and window_start>=? and window_start<?"
            " and complete=1 and packets>0 order by window_start",
            (mac, start, b["created_at"]))]
        test = [w for w in c.execute(
            "select * from windows where mac=? and window_start>=? order by window_start",
            (mac, b["created_at"]))]
        if len(learn) < len(names) + 5 or not test:
            print("%-11s not enough windows" % NAME[mac])
            continue
        print("%s   learn %d windows, evaluate %d" % (NAME[mac], len(learn), len(test)))
        print("  %-4s %6s %9s %9s %9s %10s %9s %9s" % (
            "arm", "keys", "t_alert", "far", "novelty", "escalations", "med d2", "max d2"))
        got = {}
        for arm in ("A", "B"):
            base = fit(learn, arm, names, floors)
            r = evaluate(test, arm, base, conf)
            got[arm] = r
            print("  %-4s %6d %9.2f %9d %9d %10d %9.2f %9.1f" % (
                arm, r["keys"], base["thresholds"]["t_alert"], r["far"], r["novel"],
                r["esc"], np.median(r["d2"]), r["d2"].max()))
        a, bb = got["A"], got["B"]
        print("  A to B: destination keys %d -> %d, novelty windows %d -> %d,"
              " escalations %d -> %d" % (a["keys"], bb["keys"], a["novel"], bb["novel"],
                                         a["esc"], bb["esc"]))
        print()
    print("Arm C, the benchmark replay, requires the replay path recorded as missing in"
          " section 18.1.\nB minus C, the residual that is not the resolver, cannot be"
          " computed until it exists.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
