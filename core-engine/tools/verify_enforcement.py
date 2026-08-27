"""Section 17: enforcement verification, RQ3.

    python tools/verify_enforcement.py --watch plug-01        # observe a tier in progress
    python tools/verify_enforcement.py --report /path/db-copy # after the phase

O3's criterion is three separate claims and each needs its own measurement: the tier is
applied and withdrawn, the tier has its intended effect, and other devices are unaffected.

The instrument section 17.2 specifies is iperf3, ping, dig and dhclient from a host on the
IoT subnet. That host does not exist in this testbed: the two targets are ESP32 nodes and
cannot run iperf3. What they can do is better for two of the three claims, because each
node already logs every cloud exchange with a millisecond timestamp. A block is therefore
verified against the device's own record of whether its traffic actually got through,
rather than against a synthetic transfer by a stand-in host.

What that substitution can and cannot show is stated in the report itself, because the
throughput ceiling of the throttle tier genuinely cannot be measured this way: the node
never sends anything near 20 kbytes/second. Section 17.3 predicts exactly that, and says
the invisibility of the limit to normal traffic is itself the finding.
"""

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NODES = {"plug-01": {"mac": "ac:a7:04:f4:7e:dc", "host": "192.168.50.185"},
         "sensor-01": {"mac": "1c:db:d4:75:b7:44", "host": "192.168.50.189"}}
SETS = ("blocked_mac", "throttled_mac", "blocked_ip")


def nft_members(name):
    r = subprocess.run(["nft", "list", "set", "inet", "sentri", name],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    body = r.stdout
    if "elements = {" not in body:
        return set()
    inner = body.split("elements = {", 1)[1].rsplit("}", 1)[0]
    return {x.strip() for x in inner.split(",") if x.strip()}


def nft_state():
    return {name: nft_members(name) for name in SETS}


def gt_counts(c, mac, lo, hi):
    """what the device itself says happened in a time range"""
    rows = c.execute(
        "select class, action, count(*) n from ground_truth where mac=?"
        " and device_ts_ms>=? and device_ts_ms<? group by class, action",
        (mac, int(lo * 1000), int(hi * 1000))).fetchall()
    return {(r["class"], r["action"]): r["n"] for r in rows}


def summarise(counts):
    sent = sum(v for (cls, act), v in counts.items() if act == "sent")
    failed = sum(v for (cls, act), v in counts.items() if act == "failed")
    opens = counts.get(("connection", "open"), 0)
    dns = counts.get(("dns", "resolved"), 0)
    return sent, failed, opens, dns


def watch(name, interval, seconds):
    """print set membership transitions as they happen, with the moment of each change"""
    node = NODES[name]
    print("watching nft sets for %s (%s), %ds" % (name, node["mac"], seconds))
    prev = None
    end = time.time() + seconds
    while time.time() < end:
        st = nft_state()
        if st != prev:
            now = time.time()
            where = [s for s in SETS if st.get(s) and node["mac"] in st[s]]
            print("%.3f  %s -> %s" % (now, name, ",".join(where) or "no set"))
            prev = st
        time.sleep(interval)
    return 0


def report(db, args):
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    c.row_factory = sqlite3.Row
    print("Section 17 enforcement verification, RQ3\n")

    live = nft_state()
    if live.get("blocked_mac") is None:
        print("nft table inet sentri is not loaded, or nft is not readable here.")
        print("Claim 1 (tier applied) cannot be checked without it.\n")
    else:
        print("live nft state: " + ", ".join(
            "%s=%d" % (k, len(v)) for k, v in live.items()) + "\n")

    rows = c.execute("select * from enforcement where tier!='normal' order by applied_at").fetchall()
    if not rows:
        print("No enforcement rows. Either the phase has not run or mode is still observe.")
        print("Section 21 phase 4 requires mode: enforce, plug-01 targeted, sensor-01 as")
        print("the untargeted control, and both commercial MACs in never_enforce.")
        return 1

    print("%-11s %-9s %-21s %-21s %9s" % ("device", "tier", "applied", "removed", "held"))
    for r in rows:
        name = next((n for n, v in NODES.items() if v["mac"] == r["mac"]), r["mac"])
        applied = time.strftime("%m-%d %H:%M:%S", time.gmtime(r["applied_at"]))
        removed = (time.strftime("%m-%d %H:%M:%S", time.gmtime(r["removed_at"]))
                   if r["removed_at"] else "still active")
        held = ("%.0f s" % (r["removed_at"] - r["applied_at"])) if r["removed_at"] else "-"
        print("%-11s %-9s %-21s %-21s %9s" % (name, r["tier"], applied, removed, held))

    print("\nclaim 2, the tier had its intended effect, from each node's own log")
    print("%-11s %-9s %28s %28s" % ("device", "tier", "during enforcement", "same span before"))
    for r in rows:
        name = next((n for n, v in NODES.items() if v["mac"] == r["mac"]), None)
        if name is None:
            continue
        lo, hi = r["applied_at"], r["removed_at"] or time.time()
        span = max(1.0, hi - lo)
        during = summarise(gt_counts(c, r["mac"], lo, hi))
        before = summarise(gt_counts(c, r["mac"], lo - span, lo))
        fmt = "sent %d fail %d opens %d dns %d"
        print("%-11s %-9s %28s %28s" % (name, r["tier"], fmt % during, fmt % before))
        if r["tier"] == "block":
            if during[0] == 0 and before[0] > 0:
                print("            block stopped the device's cloud traffic entirely")
            elif during[1] > before[1]:
                print("            block took effect, exchanges are failing")
            else:
                print("            WARNING: traffic continued, the block did not take effect")
            if during[3] > 0:
                print("            DNS still resolving under block, as the ruleset intends")
        if r["tier"] == "throttle" and during[0] >= before[0] * 0.9:
            print("            throttle left normal traffic untouched, as section 17.3"
                  " predicts: 20 kB/s is orders of magnitude above this device")

    print("\nclaim 3, other devices unaffected")
    for r in rows:
        target = next((n for n, v in NODES.items() if v["mac"] == r["mac"]), None)
        control = next((n for n in NODES if n != target), None)
        if not target or not control:
            continue
        lo, hi = r["applied_at"], r["removed_at"] or time.time()
        span = max(1.0, hi - lo)
        during = summarise(gt_counts(c, NODES[control]["mac"], lo, hi))
        before = summarise(gt_counts(c, NODES[control]["mac"], lo - span, lo))
        print("  while %s was %-9s  %s: sent %d (was %d), fail %d (was %d)" % (
            target, r["tier"], control, during[0], before[0], during[1], before[1]))

    print("\nnot measured by this tool, and why:")
    print("  throttle throughput ceiling: needs a host on the IoT subnet running iperf3.")
    print("    The nodes cannot. Section 17.3 predicts the ceiling is invisible to them,")
    print("    which the counts above test but do not quantify.")
    print("  enforcement latency: the gap between the tier decision and set membership")
    print("    needs --watch running across the transition, sampled faster than the")
    print("    300 s window. Run it during phase 4 rather than reconstructing it after.")
    print("  restart and reboot persistence: restart sentri.service with a device at block")
    print("    and re-run this report; sync_from_db should restore membership.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=None, help="path to a database copy")
    ap.add_argument("--watch", default=None, choices=sorted(NODES))
    ap.add_argument("--interval", type=float, default=0.05)
    ap.add_argument("--seconds", type=float, default=1800)
    args = ap.parse_args(argv)
    if args.watch:
        return watch(args.watch, args.interval, args.seconds)
    if args.report:
        return report(args.report, args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
