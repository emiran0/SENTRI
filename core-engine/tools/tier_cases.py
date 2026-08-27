import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import score

# the numbers only have to straddle the thresholds, the state machine never sees real units
TH = {"t_alert": 24.32, "t_critical": 243.22}
CONF = {"thresholds": {"deescalate_windows": 3, "escalate_window": 2, "escalate_hits": 2},
        "learning": {"learn_include_empty": False}}
# the rule the live injections argued for, exercised alongside the old one
GAPPY = {"thresholds": {"deescalate_windows": 3, "escalate_window": 3, "escalate_hits": 2},
         "learning": {"learn_include_empty": False}}
NORMAL = (1.0, [], True)
ALERT = (100.0, [], True)
CRITICAL = (400.0, [], True)
DOMAIN = (1.0, ["new_domain evil.com"], True)
PREFIX = (1.0, ["new_prefix 1.2.3.0/24"], True)


# each step is (d2, hits, trusted), the return is the tier after every step
def drive(steps, conf=CONF):
    tier, count, previous, recent = "normal", 0, [], 0
    tiers = []
    for d2, hits, trusted in steps:
        tier, count, recent = score.decide_tier(tier, count, d2, TH, hits,
                                                score.hard_novelty(previous), trusted, conf,
                                                recent)
        previous = [("d:" if h.startswith("new_domain") else "p:") + h.split()[-1] for h in hits]
        tiers.append(tier)
    return tiers


CASES = [
    # the critical path takes two windows, so one heavy reconnect can never enforce
    ("single critical spike stops at alert", [NORMAL, CRITICAL, NORMAL], 1, "alert"),
    ("two consecutive criticals block", [NORMAL, CRITICAL, CRITICAL], 2, "block"),
    ("critical then merely far is a throttle", [NORMAL, CRITICAL, ALERT], 2, "throttle"),
    # a window learning would have discarded contributes no distance and no streak
    ("untrusted distance cannot even alert", [NORMAL, (9e9, [], False)], 1, "normal"),
    ("untrusted window does not advance the streak",
     [NORMAL, (9e9, [], False), CRITICAL], 2, "alert"),
    ("untrusted window keeps its novelty", [(9e9, ["new_domain evil.com"], False)], 0, "alert"),
    ("novelty repeats through an untrusted window",
     [DOMAIN, (9e9, ["new_domain evil.com"], False)], 1, "block"),
    ("quiet device stays normal", [NORMAL] * 6, 5, "normal"),
    # the live injection shape: anomalous, a gap, anomalous. the consecutive rule cannot
    # see it, which is the whole reason escalate_window exists
    ("gapped anomaly never escalates under 2 of 2",
     [ALERT, NORMAL, ALERT], 2, "alert"),
]
GAPPY_CASES = [
    ("gapped anomaly escalates under 2 of 3", [ALERT, NORMAL, ALERT], 2, "throttle"),
    ("2 of 3 still needs a second hit", [ALERT, NORMAL, NORMAL], 2, "alert"),
    ("a lone spike two windows back has expired",
     [ALERT, NORMAL, NORMAL, ALERT], 3, "alert"),
    ("consecutive still escalates under 2 of 3", [ALERT, ALERT], 1, "throttle"),
    ("a gapped critical pair still blocks", [CRITICAL, NORMAL, CRITICAL], 2, "block"),
    ("prefix novelty with a gap stops at throttle",
     [PREFIX, NORMAL, PREFIX], 2, "throttle"),
]
SEQUENCES = [
    ("sustained critical blocks on window two",
     [CRITICAL] * 3, ["alert", "block", "block"]),
    ("prefix novelty never passes throttle",
     [PREFIX] * 4, ["alert", "throttle", "throttle", "throttle"]),
    ("de-escalation steps one tier at a time",
     [ALERT, ALERT] + [NORMAL] * 7,
     ["alert", "throttle", "throttle", "throttle", "alert", "alert", "alert",
      "normal", "normal"]),
]


# an operator clear outranks anything still queued in the capture path
CLEAR_CASES = [
    ("no clear recorded, every window counts", (1787680800, None), False),
    ("window fully before the clear is superseded", (1787680800, 1787681640.9), True),
    ("window starting before the clear is superseded even if it overlaps",
     (1787681400, 1787681640.9), True),
    ("window starting after the clear is evaluated", (1787681700, 1787681640.9), False),
    ("window starting exactly at the clear is evaluated", (1787681640, 1787681640.0), False),
    ("a zero timestamp is not a clear", (1787680800, 0), False),
]


def main():
    failures = 0
    for name, steps, index, want in CASES:
        got = drive(steps)[index]
        failures += got != want
        print("%-46s %s" % (name, "ok" if got == want else "FAIL %s, wanted %s" % (got, want)))
    for name, steps, want in SEQUENCES:
        got = drive(steps)
        failures += got != want
        print("%-46s %s" % (name, "ok" if got == want else "FAIL %s, wanted %s" % (got, want)))
    for name, steps, index, want in GAPPY_CASES:
        got = drive(steps, GAPPY)[index]
        failures += got != want
        print("%-46s %s" % (name, "ok" if got == want else "FAIL %s, wanted %s" % (got, want)))
    for name, (ws, cleared), want in CLEAR_CASES:
        got = score.superseded_by_clear(ws, cleared)
        failures += got != want
        print("%-46s %s" % (name, "ok" if got == want else "FAIL %s, wanted %s" % (got, want)))
    total = len(CASES) + len(SEQUENCES) + len(GAPPY_CASES) + len(CLEAR_CASES)
    print("%d of %d failed" % (failures, total))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
