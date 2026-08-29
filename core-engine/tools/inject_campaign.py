"""Drive labelled anomaly injections against the instrumented nodes.

The node control channel accepts commands only from the gateway, so this runs on the
Pi. Every injection carries its own expiry on the device (`anomaly.expires_at_ms`), so
a node returns to normal on its own even if this script is killed mid-trial.

    python tools/inject_campaign.py --plan pilot
    python tools/inject_campaign.py --plan full --node plug-01
    python tools/inject_campaign.py --status

Trials are aligned to the 300 s window grid so the first affected window is fully
anomalous, which is what makes a detection latency measurable in windows rather than
in fractions of one. Each trial is followed by a recovery gap long enough for the tier
ladder to de-escalate all the way back to normal (`deescalate_windows` 3, two rungs).

Records go to research/injections/<run>.jsonl and are the campaign's own account of
what was commanded. The engine's `ground_truth` table is the independent record; the
two are compared by tools/inject_report.py.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

WINDOW = 300
CONTROL_PORT = 8080
NODES = {
    "plug-01": {"mac": "ac:a7:04:f4:7e:dc", "host": "192.168.50.185"},
    "sensor-01": {"mac": "1c:db:d4:75:b7:44", "host": "192.168.50.189"},
}

# section 15: 5 windows of injection so at least four carry the full dose, then at least
# 4 normal windows of spacing. deescalate_windows is 3 and the ladder unwinds one rung at a
# time, so 6 is used here to cover a return from block rather than the section's minimum
INJECT_WINDOWS = 5
RECOVER_WINDOWS = 6
REPETITIONS = 5

# section 15 fixes the ladder in advance so the curves are comparable across types.
# 1.5x volume is included deliberately to define the floor of the curve, not because it is
# expected to detect. destination magnitude is the beacon interval in ms, not a multiplier:
# anomaly_apply feeds it to set_interval("beacon", ...), so what it varies is contacts per
# window, 60 / 10 / 2 / 0.5. The 600 s level is the important one, because below one contact
# per window detection becomes probabilistic and the escalation rule cannot complete.
LADDER = {
    "volume": [1.5, 2.0, 3.0, 5.0, 10.0],
    "cadence": [1.5, 2.0, 4.0, 8.0, 16.0],
    "destination": [5000.0, 30000.0, 150000.0, 600000.0],
    "protocol": [1.0],
}
FULL = [(kind, m) for kind in ("volume", "cadence", "destination", "protocol")
        for m in LADDER[kind]]
PILOT = [("volume", 3.0)]
PROTOCOL = [("protocol", 1.0)]
# the shortest ladder that still answers something. 3 repetitions per cell is the floor for
# a Wilson interval to exist at all, a stated deviation from the 5 section 22 requires.
#
# the three volume levels are the cells where the two transport models disagree: plug-01
# detected 1.5x, 2x and 3x, sensor-01 missed 1.5x and 2x and detected 3x. that contrast is
# the campaign's headline claim and at one repetition per cell it rests on single trials.
#
# destination at a 600 s interval is the one genuinely new cell: section 15 calls it the
# important level because below one contact per window detection becomes probabilistic and
# the escalation rule cannot complete. it has never been run at any repetition.
#
# cadence is deliberately excluded. 2x and 4x already scored d2 209 to 1050 against a
# threshold of 24.32, eight to forty times over, on both nodes. those are unambiguous
# existence results and repeating them buys precision on a question nobody is asking.
SHORT = [("volume", 1.5), ("volume", 2.0), ("volume", 3.0),
         ("destination", 600000.0)]

# the two rungs the ladder above defines but no campaign ever ran. volume stopped at 3x
# against a specified 10x and cadence at 4x against a specified 16x, so neither curve has
# an upper end and the figures stop where the campaign stopped rather than where the
# response does. these are the next rung of each, run so the curves carry a point beyond
# the knee. one repetition per cell matches how the existing cadence cells were run, so
# the cadence series stays internally consistent at n=1
TOP = [("volume", 5.0), ("cadence", 8.0)]


def control(host, path, body=None, timeout=5, tries=3):
    """the node serves its control channel from the same loop that does blocking TLS, so a
    reconnect or a beacon can stall it past a short timeout. one such stall cost the
    plug-01 protocol trial on 2026-08-25, so a command retries before it is called lost"""
    url = "http://%s:%d%s" % (host, CONTROL_PORT, path)
    data = body.encode() if body else None
    last = None
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data),
                                        timeout=timeout * (attempt + 1)) as r:
                return r.read().decode()
        except (OSError, ValueError) as exc:
            last = exc
            if attempt + 1 < tries:
                print("   %s attempt %d failed (%s), retrying" % (path, attempt + 1, exc),
                      flush=True)
                time.sleep(2)
    raise last


def status(host):
    out = {}
    for part in control(host, "/status").strip().split():
        k, _, v = part.partition("=")
        out[k] = v
    return out


def log_since(host, since_ms):
    body = control(host, "/log?since=%d" % since_ms, timeout=10)
    return [json.loads(x) for x in body.splitlines() if x.strip()]


def next_boundary(now=None):
    now = now or time.time()
    return (int(now) // WINDOW + 1) * WINDOW


def wait_until(ts, label, drain=None):
    """drain runs each minute so the node's 64 entry ring cannot wrap unobserved between
    gateway polls during a high rate anomaly"""
    while True:
        left = ts - time.time()
        if left <= 0:
            return
        print("   waiting %5.0fs for %s" % (left, label), flush=True)
        time.sleep(min(left, 60))
        if drain:
            drain()


def run_trial(node, name, kind, magnitude, out, offset=0, rep=1):
    host = NODES[name]["host"]
    duration_ms = INJECT_WINDOWS * WINDOW * 1000
    # section 15: injection is deliberately NOT aligned to the window grid, because real
    # attacks are not. an aligned start measures the easy case and removes the dilution
    # that section 14 identifies, where an anomaly covering part of a window moves the rate
    # features by only that fraction of its magnitude
    start = next_boundary() + offset
    if start - time.time() < 10:
        start += WINDOW
    wait_until(start - 1, "start offset %ds into a window" % offset)
    before = status(host)
    wait_until(start, "injection start")
    t_post = time.time()
    reply = control(host, "/anomaly", json.dumps(
        {"type": kind, "magnitude": magnitude, "duration_ms": duration_ms}))
    after = status(host)
    print("   %s %s x%g at %d, node says %s" % (
        name, kind, magnitude, start, reply.strip()), flush=True)
    rec = {
        "node": name, "mac": NODES[name]["mac"], "type": kind, "magnitude": magnitude,
        "duration_ms": duration_ms, "commanded_at": t_post, "repetition": rep,
        "start_offset_s": offset,
        "window_first": int(start), "window_last": int(start + (INJECT_WINDOWS - 1) * WINDOW),
        "node_epoch_ms_at_post": int(after.get("epoch_ms", 0)),
        "status_before": before, "status_after": after,
    }
    end = start + INJECT_WINDOWS * WINDOW
    # an independent copy of the node log, taken often enough that it survives a wrap and
    # a missed gateway poll. the engine's ground_truth stays the authoritative record
    seen, cursor = [], int(rec["node_epoch_ms_at_post"]) - 120000

    def drain():
        nonlocal cursor
        try:
            fresh = log_since(host, cursor)
        except (OSError, ValueError) as exc:
            print("   drain failed: %s" % exc, flush=True)
            return
        for e in fresh:
            if e.get("t", 0) > cursor:
                seen.append(e)
        if fresh:
            cursor = max(cursor, max(e.get("t", 0) for e in fresh))

    wait_until(end + 30, "injection expiry", drain=drain)
    rec["status_at_expiry"] = status(host)
    drain()
    rec["node_log"] = seen
    rec["recorded_at"] = time.time()
    with open(out, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("   trial recorded, %d node log entries" % len(rec.get("node_log", [])), flush=True)
    wait_until(end + RECOVER_WINDOWS * WINDOW, "recovery to finish")
    return rec


def main(argv=None):
    global INJECT_WINDOWS, RECOVER_WINDOWS
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", choices=("pilot", "full", "protocol", "short", "top"),
                    default="pilot")
    ap.add_argument("--node", default="plug-01", choices=sorted(NODES))
    ap.add_argument("--out", default=None)
    ap.add_argument("--status", action="store_true")
    # two nodes injected at the same instant would make every simultaneous alert during
    # the campaign ambiguous, and simultaneity is itself a result (section 2 of the
    # results notes). staggering keeps that reading available throughout
    ap.add_argument("--start-after", type=float, default=0.0,
                    help="seconds to idle before the first trial, to stagger two nodes")
    ap.add_argument("--repetitions", type=int, default=REPETITIONS,
                    help="trials per cell; section 22 needs 5 for a Wilson interval")
    # section 15 fixes 5 injected windows and at least 4 normal windows of spacing. the
    # spacing minimum is what makes trials independent: deescalate_windows is 3, so fewer
    # than 4 means the device has not returned to normal before the next trial starts
    ap.add_argument("--inject-windows", type=int, default=INJECT_WINDOWS,
                    help="windows per injection (section 15 fixes 5)")
    ap.add_argument("--recover-windows", type=int, default=RECOVER_WINDOWS,
                    help="quiet windows between trials (section 15 minimum is 4)")
    args = ap.parse_args(argv)
    if args.recover_windows < 4:
        print("refusing: fewer than 4 quiet windows makes consecutive trials dependent, "
              "because deescalate_windows is 3 (section 15)")
        return 2
    INJECT_WINDOWS, RECOVER_WINDOWS = args.inject_windows, args.recover_windows
    if args.status:
        for name, n in sorted(NODES.items()):
            try:
                print("%-10s %s" % (name, status(n["host"])))
            except (OSError, ValueError) as exc:
                print("%-10s unreachable: %s" % (name, exc))
        return 0
    trials = {"pilot": PILOT, "full": FULL, "protocol": PROTOCOL, "short": SHORT,
              "top": TOP}[args.plan]
    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "research", "injections",
        "%s-%s-%s.jsonl" % (args.plan, args.node, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    print("plan %s on %s, %d trials, writing %s" % (args.plan, args.node, len(trials), out))
    try:
        status(NODES[args.node]["host"])
    except (OSError, ValueError) as exc:
        print("node unreachable, nothing started: %s" % exc)
        return 1
    if args.start_after > 0:
        wait_until(time.time() + args.start_after, "staggered start")
    # section 22 requires a Wilson interval per cell, which needs a proportion out of the
    # repetition count, so a cell is only reportable once every repetition has run
    plan = [(k, m, rep) for (k, m) in trials for rep in range(1, args.repetitions + 1)]
    for i, (kind, magnitude, rep) in enumerate(plan, 1):
        print("trial %d/%d: %s x%g rep %d/%d" % (
            i, len(plan), kind, magnitude, rep, args.repetitions), flush=True)
        try:
            # vary the phase within the window across repetitions so a cell samples the
            # dilution effect rather than one fixed alignment
            offset = int(WINDOW * (rep - 1) / max(1, args.repetitions))
            run_trial(NODES[args.node], args.node, kind, magnitude, out, offset, rep)
        except (OSError, ValueError) as exc:
            print("   trial failed: %s" % exc, flush=True)
            # the device expiry still clears it, but say so explicitly rather than assume
            try:
                control(NODES[args.node]["host"], "/anomaly", json.dumps({"type": "", "duration_ms": 0}))
            except (OSError, ValueError):
                pass
    print("plan complete, %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
