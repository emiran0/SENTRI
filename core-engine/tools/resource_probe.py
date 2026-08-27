"""Section 20: Pi 5 resource measurement, entirely external to the engine.

Nothing here imports the engine or touches the database, so sampling cannot perturb the
run it is measuring. The claim under test is that the whole pipeline fits inside the budget
of a Pi that is simultaneously the live gateway, so this must run while the box is really
routing, never on an idle one.

    python tools/resource_probe.py --seconds 3600 --out research/resource/probe.jsonl
    python tools/resource_probe.py --report research/resource/probe.jsonl

Reports the median and the 95th percentile rather than the mean: the load is bursty by
construction, idle between chunk rotations and spiking during parse.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
SERVICES = {"engine": "sentri.service", "capture": "sentri-capture.service"}
CAPTURE_DIR = "/srv/sentri/captures"
DB_PATH = "/srv/sentri/sentri.db"


def pid_of(unit):
    try:
        out = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        pid = int(out or 0)
        return pid or None
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def proc_sample(pid):
    """cumulative CPU jiffies and current RSS for one process"""
    try:
        with open("/proc/%d/stat" % pid) as f:
            parts = f.read().rsplit(") ", 1)[1].split()
        utime, stime = int(parts[11]), int(parts[12])
        with open("/proc/%d/statm" % pid) as f:
            rss_pages = int(f.read().split()[1])
        return (utime + stime) / CLK_TCK, rss_pages * PAGE / (1024 * 1024)
    except (OSError, IndexError, ValueError):
        return None, None


def disk_usage():
    total = 0
    n = 0
    try:
        for entry in os.scandir(CAPTURE_DIR):
            if entry.is_file():
                total += entry.stat().st_size
                n += 1
    except OSError:
        pass
    db = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            db += os.path.getsize(DB_PATH + suffix)
        except OSError:
            pass
    return total / (1024 ** 2), n, db / (1024 ** 2)


def loadavg():
    try:
        with open("/proc/loadavg") as f:
            return float(f.read().split()[0])
    except OSError:
        return None


def sample_once(prev, interval):
    row = {"ts": time.time(), "load1": loadavg()}
    for name, unit in SERVICES.items():
        pid = pid_of(unit)
        if pid is None:
            row[name] = None
            continue
        cpu, rss = proc_sample(pid)
        if cpu is None:
            row[name] = None
            continue
        pct = None
        if prev.get(name) is not None and interval > 0:
            pct = 100.0 * (cpu - prev[name]) / interval
        prev[name] = cpu
        row[name] = {"cpu_pct": pct, "rss_mb": rss, "pid": pid}
    cap_mb, cap_n, db_mb = disk_usage()
    row["captures_mb"] = cap_mb
    row["captures_files"] = cap_n
    row["db_mb"] = db_mb
    return row


def collect(seconds, interval, out):
    os.makedirs(os.path.dirname(out), exist_ok=True)
    prev = {}
    sample_once(prev, 0)          # prime the CPU deltas
    end = time.time() + seconds
    n = 0
    with open(out, "a") as f:
        while time.time() < end:
            time.sleep(interval)
            row = sample_once(prev, interval)
            f.write(json.dumps(row) + "\n")
            f.flush()
            n += 1
    print("wrote %d samples to %s" % (n, out))


def pct(values, p):
    if not values:
        return float("nan")
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round((p / 100.0) * (len(values) - 1)))))
    return values[k]


def chunk_durations():
    """per-chunk processing time, from the engine's own INFO log if it records it"""
    try:
        out = subprocess.run(
            ["journalctl", "-u", "sentri.service", "--since", "24 hours ago", "--no-pager", "-o",
             "cat"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    seen = []
    for line in out.splitlines():
        if "chunk " in line and " in " in line and line.rstrip().endswith("s"):
            try:
                seen.append(float(line.rsplit(" in ", 1)[1].rstrip("s")))
            except ValueError:
                pass
    return seen


def report(path):
    rows = [json.loads(x) for x in open(path) if x.strip()]
    if not rows:
        print("no samples in %s" % path)
        return 1
    span = rows[-1]["ts"] - rows[0]["ts"]
    print("samples %d over %.1f h" % (len(rows), span / 3600))
    print("\n%-10s %10s %10s %10s %10s" % ("process", "cpu med", "cpu p95", "rss med", "rss max"))
    for name in SERVICES:
        cpu = [r[name]["cpu_pct"] for r in rows
               if r.get(name) and r[name].get("cpu_pct") is not None]
        rss = [r[name]["rss_mb"] for r in rows if r.get(name)]
        if not cpu:
            print("%-10s %10s" % (name, "not running"))
            continue
        print("%-10s %9.2f%% %9.2f%% %8.1f MB %8.1f MB" % (
            name, pct(cpu, 50), pct(cpu, 95), pct(rss, 50), max(rss)))
    load = [r["load1"] for r in rows if r.get("load1") is not None]
    if load:
        print("\nload average 1 min: median %.2f, p95 %.2f" % (pct(load, 50), pct(load, 95)))
    # storage growth, the constraint is captures rather than the database
    if span > 600:
        d_cap = rows[-1]["captures_mb"] - rows[0]["captures_mb"]
        d_db = rows[-1]["db_mb"] - rows[0]["db_mb"]
        per_day = 86400 / span
        print("captures %.0f MB now, growing %.0f MB/day" % (rows[-1]["captures_mb"],
                                                             d_cap * per_day))
        print("database %.0f MB now, growing %.1f MB/day" % (rows[-1]["db_mb"], d_db * per_day))
    durations = chunk_durations()
    if durations:
        print("\nper-chunk processing time, n=%d" % len(durations))
        print("  median %.2f s, p95 %.2f s, max %.2f s" % (
            pct(durations, 50), pct(durations, 95), max(durations)))
        print("  duty cycle against the 300 s rotation: median %.1f%%, p95 %.1f%%" % (
            100 * pct(durations, 50) / 300, 100 * pct(durations, 95) / 300))
    else:
        print("\nper-chunk processing time: engine does not log it yet, see section 20")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=3600)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--out", default="research/resource/probe.jsonl")
    ap.add_argument("--report", default=None)
    args = ap.parse_args(argv)
    if args.report:
        return report(args.report)
    collect(args.seconds, args.interval, args.out)
    return report(args.out)


if __name__ == "__main__":
    sys.exit(main())
