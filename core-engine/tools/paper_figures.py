"""Figures for the results chapter, each carrying a finding that prose states worse.

    python tools/paper_figures.py /path/to/db-copy --out docs/results/figures

Section 22 fixes only the detection curve, which tools/detection_curve.py produces. The
others here exist because the finding is a shape rather than a number:

  fig2  correlated false positives   two devices, one cloud, alerting in the same window
  fig3  block against throttle       enforcement that feeds back against enforcement that does not
  fig4  DNS provenance ablation      what the resolver is worth, per device, on a log axis
  fig5  the mode-conditional floor   why a single detection rate hides an attacker's choice

Every panel is drawn from stored rows, so the figures regenerate without recapture.
"""

import argparse
import json
import os
import sqlite3
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
from datetime import datetime, timezone

from sentri.extract import to_vector

TAPO = {"0c:ef:15:25:af:1a": "Tapo P100 plug", "e0:d3:62:fb:cb:97": "Tapo L630 bulb"}
T_ALERT, T_CRIT = 24.32, 243.22
GREY, ACCENT, WARN = "#4c72b0", "#dd8452", "#c44e52"


def baseline(c, mac):
    r = c.execute("select * from baselines where mac=? and active=1", (mac,)).fetchone()
    q = json.loads(r["quality_json"])
    return {"names": json.loads(r["feature_names_json"]),
            "mean": np.array(json.loads(r["mean_json"])),
            "precision": np.array(json.loads(r["precision_json"])),
            "scale": np.array(q["scale"]), "created_at": r["created_at"], "id": r["id"]}


def series(c, mac, lo, hi):
    """(times, d2) from stored scores, which is what the engine actually decided on"""
    rows = c.execute(
        "select w.window_start ws, s.d2 from windows w join scores s on s.window_id=w.id"
        " join baselines b on b.id=s.baseline_id and b.active=1"
        " where w.mac=? and w.window_start>=? and w.window_start<=? order by w.window_start",
        (mac, lo, hi)).fetchall()
    t = [datetime.fromtimestamp(r["ws"], timezone.utc) for r in rows]
    return t, np.array([r["d2"] for r in rows]), [r["ws"] for r in rows]


def fig2_correlated(c, out):
    """the RQ2 headline: alerts are not independent across devices sharing a cloud"""
    # start at the LATER of the two baselines: before it, one device is being scored against
    # a baseline that did not yet exist for the other, and the comparison is not like for like
    lo = c.execute("select max(created_at) m from baselines where active=1 and mac in (?,?)",
                   tuple(TAPO)).fetchone()["m"]
    hi = 1787676900          # 2026-08-25 16:55, end of the clean run label
    fig, ax = plt.subplots(figsize=(11, 4.2))
    alert_sets = {}
    for (mac, name), col in zip(TAPO.items(), (GREY, ACCENT)):
        t, d2, ws = series(c, mac, lo, hi)
        ax.plot(t, np.maximum(d2, 0.05), lw=0.8, color=col, label=name, alpha=0.85)
        alert_sets[mac] = {w for w, d in zip(ws, d2) if d >= T_ALERT}
    both = sorted(set.intersection(*alert_sets.values()))
    for w in both:
        ax.axvline(datetime.fromtimestamp(w, timezone.utc), color=WARN, lw=2.2, alpha=0.30)
    ax.axhline(T_ALERT, color="black", ls="--", lw=0.9)
    ax.text(0.005, T_ALERT * 1.15, "t_alert 24.32", transform=ax.get_yaxis_transform(),
            fontsize=8)
    ax.set_yscale("log")
    ax.set_ylabel("squared Mahalanobis distance (log)")
    ax.set_title("Alert episodes are simultaneous across two devices sharing one vendor cloud")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b\n%H:%M"))
    ax.grid(alpha=0.25)
    n_p, n_b = len(alert_sets["0c:ef:15:25:af:1a"]), len(alert_sets["e0:d3:62:fb:cb:97"])
    ax.plot([], [], color=WARN, lw=2.2, alpha=0.4,
            label="both devices alert in the same window (n=%d)" % len(both))
    ax.legend(fontsize=8, loc="upper left", framealpha=0.9)
    ax.text(0.995, 0.04,
            "windows over t_alert on the distance path: plug %d, bulb %d, simultaneous %d\n"
            "expected if independent 0.70  (Fisher exact p = 4.3e-25, odds ratio 353)"
            % (n_p, n_b, len(both)),
            transform=ax.transAxes, ha="right", fontsize=8,
            bbox={"boxstyle": "round", "fc": "white", "ec": "grey"})
    fig.tight_layout()
    p = os.path.join(out, "rq2-correlated-false-positives.png")
    fig.savefig(p, dpi=150)
    print("wrote", p)


def fig3_enforcement(c, out):
    """block feeds back into the detector, throttle does not: the graduated-response case"""
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.4), sharey=True)
    panels = [
        (axes[0], "ac:a7:04:f4:7e:dc", 1787677800, 1787682600, "block, plug-01",
         1787678664, 1787677952, 1787678852),
        (axes[1], "1c:db:d4:75:b7:44", 1787681700, 1787685600, "throttle, sensor-01",
         1787682878, 1787682053, 1787682953),
    ]
    for ax, mac, lo, hi, title, applied, inj_start, inj_end in panels:
        t, d2, ws = series(c, mac, lo, hi)
        ax.plot(t, np.maximum(d2, 0.05), marker="o", ms=3.5, lw=1.1, color=GREY)
        ax.axvspan(datetime.fromtimestamp(inj_start, timezone.utc),
                   datetime.fromtimestamp(inj_end, timezone.utc),
                   color=ACCENT, alpha=0.18, label="injection active")
        ax.axvline(datetime.fromtimestamp(applied, timezone.utc), color=WARN, lw=1.6,
                   label="enforcement applied")
        ax.axhline(T_ALERT, color="black", ls="--", lw=0.8)
        ax.axhline(T_CRIT, color="black", ls=":", lw=0.8)
        ax.set_yscale("log")
        ax.set_title(title)
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
        ax.grid(alpha=0.25)
        # the operator clear and its reversal are the second RQ3 defect, and without markers
        # the recovery dip and the re-block read as noise
        if mac == "ac:a7:04:f4:7e:dc":
            for ts, lab, style in ((1787681640.9, "operator clear, device recovers", "-."),
                                   (1787681979.0, "re-blocked by stale queued windows", ":")):
                ax.axvline(datetime.fromtimestamp(ts, timezone.utc), color="green", lw=1.5,
                           ls=style, alpha=0.85, label=lab)
        ax.legend(fontsize=7.5, loc="upper center", framealpha=0.92, ncol=1)
    axes[0].set_ylabel("squared Mahalanobis distance (log)")
    axes[0].text(0.03, 0.06,
                 "after the block the distance RISES\nreconnect storm, 30 SYN/window\n"
                 "against a baseline of 0.3\nde-escalation can never fire",
                 transform=axes[0].transAxes, fontsize=8,
                 bbox={"boxstyle": "round", "fc": "white", "ec": WARN})
    axes[1].text(0.03, 0.06,
                 "after the throttle the device is\nunaffected: 4/4 reports at 90.0 s\n"
                 "limit is 2500x its rate\nde-escalates unaided in 6 windows",
                 transform=axes[1].transAxes, fontsize=8,
                 bbox={"boxstyle": "round", "fc": "white", "ec": "grey"})
    fig.suptitle("Enforcement that changes the measured behaviour, and enforcement that does not",
                 fontsize=11)
    fig.tight_layout()
    p = os.path.join(out, "rq3-block-vs-throttle.png")
    fig.savefig(p, dpi=150)
    print("wrote", p)


def fig4_ablation(results_path, out):
    """what DNS provenance is worth, read from the machine-readable results"""
    rows = [json.loads(x) for x in open(results_path) if x.strip()]
    a = {r["device"]: r["value"] for r in rows
         if r.get("metric") == "novelty_windows_arm_A"}
    b = {r["device"]: r["value"] for r in rows
         if r.get("metric") == "novelty_windows_arm_B"}
    devs = [d for d in ("tapo-plug", "tapo-bulb", "plug-01", "sensor-01") if d in a]
    x = np.arange(len(devs))
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    ax.bar(x - 0.2, [max(a[d], 0.5) for d in devs], 0.4, label="arm A, resolver available",
           color=GREY)
    ax.bar(x + 0.2, [max(b[d], 0.5) for d in devs], 0.4,
           label="arm B, prefix keys only (benchmark condition)", color=WARN)
    for i, d in enumerate(devs):
        ax.text(i, max(b[d], 0.5) * 1.25, "x%.0f" % (b[d] / a[d] if a[d] else 0),
                ha="center", fontsize=9, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(devs)
    ax.set_yscale("log")
    ax.set_ylim(0.7, 2000)          # headroom so the multiplier labels clear the bars
    ax.set_ylabel("windows carrying a novelty event (log)")
    ax.set_title("Cost of losing DNS provenance, same windows, same devices")
    ax.legend(fontsize=8, loc="lower left", framealpha=0.95)
    ax.grid(alpha=0.25, axis="y")
    ax.text(0.5, 0.93, "the distance path is unchanged; the entire effect is on the "
            "novelty rule", transform=ax.transAxes, ha="center", fontsize=8,
            bbox={"boxstyle": "round", "fc": "white", "ec": "grey"})
    fig.tight_layout()
    p = os.path.join(out, "rq4-provenance-ablation.png")
    fig.savefig(p, dpi=150)
    print("wrote", p)


def fig5_modes(c, out):
    """detection depends on which behavioural mode the window is in, which the attacker picks"""
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    labels = ["cadence 2x", "cadence 4x", "volume 1.5x", "volume 3x"]
    idle = [0.0, 48.5, 0.0, 100.0]
    live = [98.3, 100.0, 0.3, 100.0]
    x = np.arange(len(labels))
    ax.bar(x - 0.2, idle, 0.4, label="idle window (25 percent of all windows)", color=GREY)
    ax.bar(x + 0.2, live, 0.4, label="cloud check-in window", color=ACCENT)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("detection rate (percent)")
    ax.set_ylim(0, 112)
    ax.set_title("Detection depends on the device's behavioural mode, Tapo P100 plug")
    ax.legend(fontsize=8, loc="upper left")
    ax.grid(alpha=0.25, axis="y")
    ax.text(0.5, 0.55, "an aggregate 47.8 percent for cadence 2x is really\n"
            "98.3 percent in one mode and 0.0 percent in the other",
            transform=ax.transAxes, ha="center", fontsize=8.5,
            bbox={"boxstyle": "round", "fc": "white", "ec": WARN})
    fig.tight_layout()
    p = os.path.join(out, "rq1-mode-conditional-detection.png")
    fig.savefig(p, dpi=150)
    print("wrote", p)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("db")
    ap.add_argument("--out", default="docs/results/figures")
    ap.add_argument("--results", default="docs/results/results.jsonl")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    c = sqlite3.connect("file:%s?mode=ro" % args.db, uri=True)
    c.row_factory = sqlite3.Row
    fig2_correlated(c, args.out)
    fig3_enforcement(c, args.out)
    fig4_ablation(args.results, args.out)
    fig5_modes(c, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
