import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import score

# the numbers only have to straddle the thresholds, the state machine never sees real units
TH = {"t_alert": 24.32, "t_critical": 243.22}
CONF = {"thresholds": {"deescalate_windows": 3}, "learning": {"learn_include_empty": False}}
NORMAL = (1.0, [], True)
ALERT = (100.0, [], True)
CRITICAL = (400.0, [], True)
DOMAIN = (1.0, ["new_domain evil.com"], True)
PREFIX = (1.0, ["new_prefix 1.2.3.0/24"], True)


# each step is (d2, hits, trusted), the return is the tier after every step
def drive(steps):
    tier, count, previous = "normal", 0, []
    tiers = []
    for d2, hits, trusted in steps:
        tier, count = score.decide_tier(tier, count, d2, TH, hits,
                                        score.hard_novelty(previous), trusted, CONF)
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
    print("%d of %d failed" % (failures, len(CASES) + len(SEQUENCES)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
