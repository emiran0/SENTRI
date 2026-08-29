"""Rank per-device dataset captures by whether they can satisfy the learning gates.

    python tools/dataset_profile.py /srv/sentri/replay/raw --hours 24

For a per-device release such as the UNSW traces, the question is not "which devices are
interesting" but "which devices are dense enough to learn from at all". The gates need
`min_windows` non-empty 300 s windows inside a `learning_hours` span. A device that is
active twice a day has hundreds of days of capture and still cannot supply them.

So this reports, per file: the span, the fraction of 300 s windows that contain any
traffic, and the **densest continuous window of `--hours`**, which is the slice a replay
should actually take. It also reports the consistent peer MAC, which is the gateway and
belongs in `exclude.macs` so `extract.parse_chunk` can derive packet direction.

Reads raw records, so a large capture costs seconds rather than minutes.
"""

import argparse
import collections
import glob
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.utils import RawPcapReader

WINDOW = 300


def mac_at(d, o):
    return ":".join("%02x" % b for b in d[o:o + 6])


def meta_ts(meta):
    if hasattr(meta, "sec"):
        return int(meta.sec)
    raw = (int(meta.tshigh) << 32) | int(meta.tslow)
    res = int(getattr(meta, "tsresol", 1000000)) or 1000000
    return raw // res


def mac_from_name(name):
    part = os.path.basename(name).split("_")[-1].split(".")[0]
    if len(part) == 12:
        return ":".join(part[i:i + 2] for i in range(0, 12, 2)).lower()
    return None


def profile(path, hours):
    dev = mac_from_name(path)
    windows = collections.Counter()
    peers = collections.Counter()
    first = last = None
    n = 0
    r = RawPcapReader(path)
    try:
        for data, meta in r:
            n += 1
            ts = meta_ts(meta)
            first = ts if first is None else first
            last = ts
            if len(data) < 14:
                continue
            windows[ts // WINDOW] += 1
            s, d = mac_at(data, 6), mac_at(data, 0)
            other = d if s == dev else s
            if other and not other.startswith("ff:") and other != dev:
                peers[other] += 1
    finally:
        r.close()

    ws = sorted(windows)
    span_w = int(hours * 3600 // WINDOW)
    best, best_at = 0, None
    j = 0
    for i in range(len(ws)):
        while j < len(ws) and ws[j] < ws[i] + span_w:
            j += 1
        if j - i > best:
            best, best_at = j - i, ws[i]
    return {
        "device": dev, "packets": n, "first": first, "last": last,
        "windows": len(ws), "densest": best, "densest_at": best_at,
        "peer": peers.most_common(1)[0] if peers else (None, 0),
        "span_days": (last - first) / 86400 if first else 0,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--hours", type=float, default=24.0,
                    help="learning span the gate requires (learning_hours)")
    ap.add_argument("--min-windows", type=int, default=200,
                    help="non-empty windows the gate requires (min_windows)")
    args = ap.parse_args(argv)

    files = sorted(glob.glob(os.path.join(args.directory, "*.pcap"))
                   + glob.glob(os.path.join(args.directory, "*.pcapng")))
    if not files:
        print("no captures in %s" % args.directory)
        return 1
    rows = []
    for f in files:
        try:
            rows.append((os.path.basename(f), profile(f, args.hours)))
        except Exception as exc:                       # a corrupt file must not stop a sweep
            print("%-44s FAILED: %s" % (os.path.basename(f)[:44], exc))
    rows.sort(key=lambda r: -r[1]["densest"])

    print("\ngate: %d non-empty windows within %.0f h\n" % (args.min_windows, args.hours))
    print("%-40s %9s %8s %9s %10s  %s" % (
        "capture", "packets", "days", "occupancy", "densest", "verdict"))
    for name, p in rows:
        total_w = max(1, (p["last"] - p["first"]) / WINDOW)
        verdict = "USABLE" if p["densest"] >= args.min_windows else \
                  "too sparse (%d short)" % (args.min_windows - p["densest"])
        print("%-40s %9d %8.1f %8.2f%% %10d  %s" % (
            name[:40], p["packets"], p["span_days"], 100 * p["windows"] / total_w,
            p["densest"], verdict))

    print("\nbest slice per usable device:")
    any_usable = False
    for name, p in rows:
        if p["densest"] >= args.min_windows and p["densest_at"]:
            any_usable = True
            print("  %-38s --start %s --hours %.0f" % (
                name[:38],
                datetime.fromtimestamp(p["densest_at"] * WINDOW, timezone.utc)
                .strftime("%Y-%m-%dT%H:%M"), args.hours))
    if not any_usable:
        print("  none. Either pick denser devices, or relax the gates for the replay and"
              "\n  record the relaxation, as section 18.1 allows.")

    peers = collections.Counter()
    for _, p in rows:
        if p["peer"][0]:
            peers[p["peer"][0]] += p["peer"][1]
    if peers:
        print("\nconsistent peer MAC across devices, the gateway side:")
        for mac, k in peers.most_common(3):
            print("  %-20s %d packets  -> put this in exclude.macs" % (mac, k))
    return 0


if __name__ == "__main__":
    sys.exit(main())
