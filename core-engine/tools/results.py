"""Regenerate every table in docs/2026-08-24_results-available-now.md.

Reads a database copy, never the live one. Numbers are recomputed from the stored
feature vectors against the stored baselines rather than read out of the scores
table, because refit rescores history and the stored tier is a stateless severity
rather than the tier the state machine reached.

    python tools/results.py /path/to/copy-of-sentri.db [section ...]

Sections: fp attrib curve mode transfer duration keys thresholds gauss gt.
With no section named it runs all of them, after the self check.
"""

import contextlib
import json
import os
import sqlite3
import sys

import numpy as np
from scipy.stats import chi2, fisher_exact
from sklearn.covariance import LedoitWolf

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import score as S
from sentri.extract import to_vector

# pinned to the consecutive-window rule on purpose, not read from config.yaml: every
# escalation figure in docs/2026-08-24_results-available-now.md was measured under it, and
# the tables have to stay reproducible after config.yaml moves to 2 of 3
CONF = {"thresholds": {"deescalate_windows": 3, "escalate_window": 2, "escalate_hits": 2},
        "learning": {"learn_include_empty": False}}
NAME = {
    "0c:ef:15:25:af:1a": "tapo-plug (P100)",
    "e0:d3:62:fb:cb:97": "tapo-bulb (L630)",
    "ac:a7:04:f4:7e:dc": "node plug-01",
    "1c:db:d4:75:b7:44": "node sensor-01",
}
ORDER = ["0c:ef:15:25:af:1a", "e0:d3:62:fb:cb:97", "ac:a7:04:f4:7e:dc", "1c:db:d4:75:b7:44"]
MTU = 1514.0
# baseline.fit's own constants, repeated here so a refit sweep matches the engine
CALIB_CHUNKS, CALIB_HOLDOUT, RIDGE = 10, (4, 9), 1e-6


def connect(path):
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    c.row_factory = sqlite3.Row
    return c


def baselines(c):
    out = {}
    for r in c.execute("select * from baselines where active=1"):
        q = json.loads(r["quality_json"])
        d = json.loads(r["dest_set_json"])
        out[r["mac"]] = {
            "id": r["id"], "created_at": r["created_at"],
            "names": json.loads(r["feature_names_json"]),
            "mean": np.array(json.loads(r["mean_json"])),
            "precision": np.array(json.loads(r["precision_json"])),
            "scale": np.array(q["scale"]),
            "thresholds": json.loads(r["thresholds_json"]),
            "dests": set(d["keys"]), "ips": set(d["ips"]),
            "services": set(json.loads(r["service_set_json"])),
            "quality": q, "floors": q.get("floors"),
        }
    return out


def windows(c, mac, since=None):
    q = "select * from windows where mac=? %s order by window_start" % (
        "and window_start>=?" if since else "")
    return list(c.execute(q, (mac, since) if since else (mac,)))


def d2_of(vec, b):
    z = (vec - b["mean"]) / b["scale"]
    return float(z @ b["precision"] @ z)


def trusted(w):
    return S.trusted_distance(w["packets"], w["complete"], CONF)


def clean_feats(c, mac, b, drop_alerting=True):
    """out-of-sample windows whose distance the engine would trust"""
    ws = [w for w in windows(c, mac, b["created_at"]) if trusted(w)]
    fs = [json.loads(w["features_json"]) for w in ws]
    if drop_alerting:
        fs = [f for f in fs if d2_of(to_vector(f, b["names"]), b) < b["thresholds"]["t_alert"]]
    return ws, fs


# the firmware's own semantics: volume_mult scales the payload, cadence_mult divides the
# interval of the affected task class, extra_dest adds a destination, protocol_swap moves
# the port. see node-firmware/src/control.cpp
def inject(f, kind, mult):
    g = dict(f)
    if kind == "volume":
        # outbound only. the firmware scales the request through scaled(PRIMARY_OUT) while
        # cloud_exchange asks for /bytes/{PRIMARY_IN}, a constant, so the reply size does
        # not move. an injection model that also scaled the inbound side would credit the
        # detector with a signal the node cannot actually produce
        g["bytes_out_rate"] = f["bytes_out_rate"] * mult
        # payload grows into bigger packets until the MTU, then into more of them
        if f["mean_pkt_size_out"]:
            size = min(MTU, f["mean_pkt_size_out"] * mult)
            grow = f["mean_pkt_size_out"] * mult / size
            g["mean_pkt_size_out"] = size
            g["pkts_out_rate"] = f["pkts_out_rate"] * grow
            if grow > 1:
                g["mean_iat_out"] = f["mean_iat_out"] / grow
                g["std_iat_out"] = f["std_iat_out"] / grow
            if size > 700:
                g["frac_large_out"], g["frac_small_out"] = 1.0, 0.0
        else:
            g["pkts_out_rate"] = f["pkts_out_rate"] * mult
    elif kind == "cadence":
        for k in ("pkts_out_rate", "pkts_in_rate", "bytes_out_rate", "bytes_in_rate"):
            g[k] = f[k] * mult
        g["mean_iat_out"] = f["mean_iat_out"] / mult
        g["std_iat_out"] = f["std_iat_out"] / mult
    elif kind == "destination":
        g["distinct_peers"] = f["distinct_peers"] + 1
        g["pkts_out_rate"] = f["pkts_out_rate"] * 1.05
        g["bytes_out_rate"] = f["bytes_out_rate"] * 1.05
        g["tcp_syn_rate"] = f["tcp_syn_rate"] + 1 / 300.0
    elif kind == "protocol":
        g["tcp_syn_rate"] = f["tcp_syn_rate"] + 1 / 300.0
    else:
        raise ValueError("unknown injection " + kind)
    return g


def detect_rate(fs, b, kind, mult, bb=None):
    tgt = bb or b
    t = tgt["thresholds"]["t_alert"]
    return 100 * np.mean([d2_of(to_vector(inject(f, kind, mult), tgt["names"]), tgt) >= t
                          for f in fs])


# ---------------------------------------------------------------- self check

def selfcheck(c, B):
    """the harness must reproduce the engine's own scores before any table is believed"""
    worst, total = 0.0, 0
    for mac in ORDER:
        b = B[mac]
        rows = c.execute("""select s.d2 sd2, w.features_json fj from scores s
            join windows w on w.id = s.window_id
            where s.mac = ? and s.baseline_id = ?""", (mac, b["id"])).fetchall()
        for r in rows:
            mine = d2_of(to_vector(json.loads(r["fj"]), b["names"]), b)
            worst = max(worst, abs(mine - r["sd2"]) / max(1e-9, abs(r["sd2"])))
        total += len(rows)
    print("self check: %d engine score rows, worst relative error %.2e" % (total, worst))
    if worst > 1e-9:
        raise SystemExit("harness disagrees with the engine, tables not written")


# ---------------------------------------------------------------- sections

def sec_fp(c, B):
    print("\n== 1. out-of-sample false positives ==")
    print("%-18s %6s %7s %8s %7s %7s %8s %9s %10s" % (
        "device", "wins", "hours", "median", "p95", "p99", "max", "per-win", "escalation"))
    for mac in ORDER:
        b = B[mac]
        ws = windows(c, mac, b["created_at"])
        d2s, tier, count, prev, esc = [], "normal", 0, [], 0
        flagged, recent = 0, 0
        for w in ws:
            f = json.loads(w["features_json"])
            ct = json.loads(w["counters_json"])
            d = d2_of(to_vector(f, b["names"]), b)
            tr = trusted(w)
            nd, ns, _ = S.novelty(ct.get("dests", {}), set(ct.get("services", [])), b)
            hits = S.discrete_hits(nd, ns)
            before = tier
            tier, count, recent = S.decide_tier(tier, count, d, b["thresholds"], hits,
                                                S.hard_novelty(prev), tr, CONF, recent)
            # engine.py stores new_dests + new_services in new_dests_json and takes
            # hard_novelty off the pair, so the carry has to include services
            prev = nd + ns
            if tr:
                d2s.append(d)
                flagged += d >= b["thresholds"]["t_alert"] or bool(hits)
            if S.TIERS.index(tier) > S.TIERS.index(before) and tier != "alert":
                esc += 1
        a = np.array(d2s)
        print("%-18s %6d %7.1f %8.2f %7.1f %7.1f %8.1f %8.2f%% %9.2f%%" % (
            NAME[mac], len(ws), len(ws) * 300 / 3600, np.percentile(a, 50),
            np.percentile(a, 95), np.percentile(a, 99), a.max(),
            100 * flagged / len(ws), 100 * esc / len(ws)))


def alert_windows(c, mac, b):
    out = set()
    for w in windows(c, mac, b["created_at"]):
        if not trusted(w):
            continue
        f = json.loads(w["features_json"])
        if d2_of(to_vector(f, b["names"]), b) >= b["thresholds"]["t_alert"]:
            out.add(w["window_start"])
    return out


def sec_attrib(c, B):
    print("\n== 2. are false positives independent across devices? ==")
    tp, tb = "0c:ef:15:25:af:1a", "e0:d3:62:fb:cb:97"
    ap, ab = alert_windows(c, tp, B[tp]), alert_windows(c, tb, B[tb])
    n = len({w["window_start"] for w in windows(c, tp, B[tp]["created_at"])} &
            {w["window_start"] for w in windows(c, tb, B[tb]["created_at"])})
    k = len(ap & ab)
    odds, p = fisher_exact([[k, len(ap) - k], [len(ab) - k, n - len(ap) - len(ab) + k]])
    print("   shared windows %d, plug alerts %d, bulb alerts %d, simultaneous %d" % (
        n, len(ap), len(ab), k))
    print("   expected if independent %.2f, odds ratio %.0f, Fisher exact p = %.2e" % (
        len(ap) * len(ab) / n, odds, p))
    print("   attributable to a shared cloud event: plug %.0f%%, bulb %.0f%%" % (
        100 * k / len(ap), 100 * k / len(ab)))
    print("   residual device-local rate: plug %.2f%%, bulb %.2f%%" % (
        100 * (len(ap) - k) / n, 100 * (len(ab) - k) / n))
    mac = "ac:a7:04:f4:7e:dc"
    b = B[mac]
    per = {}
    for r in c.execute("select device_ts_ms from ground_truth where mac=? and class='connection'",
                       (mac,)):
        t = int(r["device_ts_ms"] / 1000) // 300 * 300
        per[t] = per.get(t, 0) + 1
    al = alert_windows(c, mac, b)
    nw = len(windows(c, mac, b["created_at"]))
    attr = sum(1 for t in al if per.get(t, 0) >= 2)
    print("   node plug-01: %d alerts, %d (%.0f%%) with >=2 upstream reconnects, "
          "residual %.2f%%" % (len(al), attr, 100 * attr / len(al), 100 * (len(al) - attr) / nw))


GRID = ([("volume", m) for m in (1.25, 1.5, 2, 3, 4, 8)] +
        [("cadence", m) for m in (1.5, 2, 3, 4, 8)] +
        [("destination", 1), ("protocol", 1)])


def sec_curve(c, B):
    print("\n== 3. detection curve, injections on out-of-sample windows ==")
    print("%-14s" % "injection" + "".join("%18s" % NAME[m] for m in ORDER))
    cache = {mac: clean_feats(c, mac, B[mac])[1] for mac in ORDER}
    for kind, mult in GRID:
        label = "%s x%g" % (kind, mult) if kind in ("volume", "cadence") else kind
        row = "%-14s" % label
        for mac in ORDER:
            row += "%17.1f%%" % detect_rate(cache[mac], B[mac], kind, mult)
        print(row)
    print("\n   minimum detectable magnitude, by bisection")
    print("%-18s %11s %11s %11s %11s" % (
        "device", "vol @50%", "vol @95%", "cad @50%", "cad @95%"))
    for mac in ORDER:
        got = []
        for kind in ("volume", "cadence"):
            for target in (50, 95):
                lo, hi = 1.0, 20.0
                for _ in range(40):
                    mid = (lo + hi) / 2
                    if detect_rate(cache[mac], B[mac], kind, mid) < target:
                        lo = mid
                    else:
                        hi = mid
                got.append(hi)
        print("%-18s %11.2f %11.2f %11.2f %11.2f" % (NAME[mac], *got))


def sec_mode(c, B):
    print("\n== 4. detection conditioned on behavioural mode ==")
    for mac in ("0c:ef:15:25:af:1a", "e0:d3:62:fb:cb:97"):
        b = B[mac]
        ws = [w for w in windows(c, mac, b["created_at"]) if trusted(w)]
        pairs = [(w["packets"], json.loads(w["features_json"])) for w in ws]
        pairs = [(p, f) for p, f in pairs
                 if d2_of(to_vector(f, b["names"]), b) < b["thresholds"]["t_alert"]]
        idle = [f for p, f in pairs if p < 8]
        live = [f for p, f in pairs if p >= 8]
        print("%s   idle n=%d, check-in n=%d" % (NAME[mac], len(idle), len(live)))
        for kind, mult in (("cadence", 2), ("cadence", 4), ("volume", 1.5), ("volume", 3)):
            print("   %-12s idle %6.1f%%   check-in %6.1f%%" % (
                "%s x%g" % (kind, mult), detect_rate(idle, b, kind, mult),
                detect_rate(live, b, kind, mult)))


def sec_transfer(c, B):
    print("\n== 5. does a baseline transfer? ==")
    print("   median d2 of each device's normal windows on every baseline, (%) would alert")
    print("%-20s" % "windows from" + "".join("%20s" % NAME[m] for m in ORDER))
    for src in ORDER:
        ws, _ = clean_feats(c, src, B[src], drop_alerting=False)
        fs = [json.loads(w["features_json"]) for w in ws]
        row = "%-20s" % NAME[src]
        for tgt in ORDER:
            b = B[tgt]
            d = np.array([d2_of(to_vector(f, b["names"]), b) for f in fs])
            row += "%20s" % ("%8.1f (%4.0f%%)" % (
                np.median(d), 100 * np.mean(d >= b["thresholds"]["t_alert"])))
        print(row)
    print("\n   a borrowed baseline is only useful if it still detects")
    for src, borrow in (("0c:ef:15:25:af:1a", "e0:d3:62:fb:cb:97"),
                        ("e0:d3:62:fb:cb:97", "0c:ef:15:25:af:1a"),
                        ("ac:a7:04:f4:7e:dc", "1c:db:d4:75:b7:44")):
        own, bor = B[src], B[borrow]
        ws, fs = clean_feats(c, src, own)
        allf = [json.loads(w["features_json"]) for w in ws]
        fp_o = 100 * np.mean([d2_of(to_vector(f, own["names"]), own) >=
                              own["thresholds"]["t_alert"] for f in allf])
        fp_b = 100 * np.mean([d2_of(to_vector(f, bor["names"]), bor) >=
                              bor["thresholds"]["t_alert"] for f in allf])
        print("   %s on %s baseline: FP %.1f%% own, %.1f%% borrowed" % (
            NAME[src], NAME[borrow], fp_o, fp_b))
        for kind, mult in (("volume", 2), ("volume", 3), ("cadence", 2), ("cadence", 8)):
            print("      %-12s own %6.1f%%   borrowed %6.1f%%" % (
                "%s x%g" % (kind, mult), detect_rate(fs, own, kind, mult),
                detect_rate(fs, own, kind, mult, bb=bor)))


def refit(rows, names, floors):
    """baseline.fit, in memory, so a learning-duration sweep needs no database write"""
    m = np.array([to_vector(json.loads(w["features_json"]), names) for w in rows])
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
    t = max(float(np.percentile(cd, 95)), float(chi2.ppf(0.999, len(names))))
    dests = set()
    for w in rows:
        dests |= set(json.loads(w["counters_json"]).get("dests", {}))
    return {"mean": mean, "scale": scale, "precision": precision, "names": names,
            "thresholds": {"t_alert": t}, "dests": dests}


def sec_duration(c, B, floors):
    print("\n== 6. how long must a device learn? ==")
    ls = dict(c.execute("select mac, learning_started from devices"))
    for mac in ORDER:
        start = ls[mac]
        names = B[mac]["names"]
        allw = [w for w in windows(c, mac, start) if w["complete"] and w["packets"]]
        cut = start + 72 * 3600
        ev = [w for w in allw if w["window_start"] >= cut]
        if len(ev) < 50:
            cut = start + 48 * 3600
            ev = [w for w in allw if w["window_start"] >= cut]
        fs = [json.loads(w["features_json"]) for w in ev]
        print("%s   evaluated on %d windows from +%.0fh" % (
            NAME[mac], len(ev), (cut - start) / 3600))
        print("   %-7s %7s %9s %8s %8s %8s %8s" % (
            "learn", "wins", "t_alert", "FP%", "vol 3x", "cad 4x", "cad 8x"))
        for hrs in (3, 6, 12, 24, 36, 48):
            tr = [w for w in allw if w["window_start"] < start + hrs * 3600]
            if len(tr) <= len(names) + 3:
                print("   %-7s %7d   too few windows" % ("%dh" % hrs, len(tr)))
                continue
            b = refit(tr, names, floors)
            neg = np.array([d2_of(to_vector(f, names), b) for f in fs])
            print("   %-7s %7d %9.1f %8.2f %8.1f %8.1f %8.1f" % (
                "%dh" % hrs, len(tr), b["thresholds"]["t_alert"],
                100 * np.mean(neg >= b["thresholds"]["t_alert"]),
                detect_rate(fs, b, "volume", 3), detect_rate(fs, b, "cadence", 4),
                detect_rate(fs, b, "cadence", 8)))


def sec_keys(c, B):
    print("\n== 7. destination identity ==")
    print("%-18s %9s %9s %12s %8s  %s" % (
        "device", "d: keys", "p: keys", "win w/ p: %", "peer IPs", "baseline dest set"))
    for mac in ORDER:
        b = B[mac]
        ws = windows(c, mac, b["created_at"])
        dk, pk, ips, wp = set(), set(), set(), 0
        for w in ws:
            has_prefix = False
            for k, addrs in json.loads(w["counters_json"]).get("dests", {}).items():
                (pk if k.startswith("p:") else dk).add(k)
                ips.update(addrs)
                has_prefix |= k.startswith("p:")
            wp += has_prefix
        print("%-18s %9d %9d %12.1f %8d  %s" % (
            NAME[mac], len(dk), len(pk), 100 * wp / len(ws), len(ips), ",".join(sorted(b["dests"]))))


def sec_thresholds(c, B):
    print("\n== 8. threshold sweep ==")
    keys = (("volume", 1.5), ("volume", 2), ("volume", 3), ("cadence", 2), ("cadence", 4))
    for mac in ORDER:
        b = B[mac]
        ws, fs = clean_feats(c, mac, b, drop_alerting=False)
        neg = np.array([d2_of(to_vector(f, b["names"]), b) for f in fs])
        pos = {k: np.array([d2_of(to_vector(inject(f, *k), b["names"]), b) for f in fs])
               for k in keys}
        print("%s   (t_alert in use %.2f)" % (NAME[mac], b["thresholds"]["t_alert"]))
        print("   %-24s %7s" % ("threshold", "FP%") +
              "".join("%9s" % ("%s%g" % (k[0][0], k[1])) for k in keys))
        for label, t in (("chi2 floor", b["thresholds"]["candidates"]["chi2"]),
                         ("empirical p95", float(np.percentile(neg, 95))),
                         ("empirical p99", float(np.percentile(neg, 99))),
                         ("observed max", float(neg.max())),
                         ("2x observed max", float(neg.max()) * 2)):
            print("   %-16s %7.1f %7.2f" % (label, t, 100 * np.mean(neg >= t)) +
                  "".join("%9.1f" % (100 * np.mean(pos[k] >= t)) for k in keys))
        print()


def sec_gauss(c, B):
    print("\n== 9. gaussianity gap ==")
    dims = len(B[ORDER[0]]["names"])
    print("   chi2(%d): p50 %.2f, p95 %.2f, p99 %.2f, p999 %.2f" % (
        dims, chi2.ppf(.5, dims), chi2.ppf(.95, dims), chi2.ppf(.99, dims),
        chi2.ppf(.999, dims)))
    print("%-18s %10s %10s %11s %14s" % ("device", "emp p95", "emp p99", "emp max", "max/chi2p999"))
    for mac in ORDER:
        b = B[mac]
        ws, fs = clean_feats(c, mac, b, drop_alerting=False)
        d = np.array([d2_of(to_vector(f, b["names"]), b) for f in fs])
        print("%-18s %10.2f %10.2f %11.2f %13.1fx" % (
            NAME[mac], np.percentile(d, 95), np.percentile(d, 99), d.max(),
            d.max() / chi2.ppf(.999, dims)))


def sec_gt(c, B):
    print("\n== 10. node characterisation from ground truth ==")
    for mac in ("ac:a7:04:f4:7e:dc", "1c:db:d4:75:b7:44"):
        rows = list(c.execute(
            "select class, action, device_ts_ms from ground_truth where mac=? "
            "order by device_ts_ms", (mac,)))
        print("%s   %d events, %d failures" % (
            NAME[mac], len(rows), sum(1 for r in rows if r["action"] == "failed")))
        for cls in ("keepalive", "report", "connection", "ntp", "dns"):
            t = [r["device_ts_ms"] for r in rows if r["class"] == cls]
            if len(t) < 3:
                continue
            g = np.diff(t) / 1000.0
            g = g[g > 0]
            print("   %-11s n=%5d  median %9.2fs  p95 %9.2fs  max %10.2fs" % (
                cls, len(t), np.median(g), np.percentile(g, 95), g.max()))


SECTIONS = {"fp": sec_fp, "attrib": sec_attrib, "curve": sec_curve, "mode": sec_mode,
            "transfer": sec_transfer, "keys": sec_keys, "thresholds": sec_thresholds,
            "gauss": sec_gauss, "gt": sec_gt}


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    if os.path.realpath(path) == "/srv/sentri/sentri.db":
        print("refusing to run against the live database, take a copy first")
        return 2
    want = argv[2:] or list(SECTIONS) + ["duration"]
    c = connect(path)
    B = baselines(c)
    missing = [m for m in ORDER if m not in B]
    if missing:
        print("no active baseline for: %s" % ", ".join(missing))
        return 1
    selfcheck(c, B)
    floors = None
    if "duration" in want:
        # the fit floors are a config value, not a database one, so read them from config
        from sentri import config
        conf = config.load(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "config.yaml"))
        floors = conf["variance_floors"]
    for name in want:
        if name == "duration":
            sec_duration(c, B, floors)
        elif name in SECTIONS:
            SECTIONS[name](c, B)
        else:
            print("unknown section: %s" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
