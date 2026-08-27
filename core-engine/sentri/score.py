import numpy as np

TIERS = ("normal", "alert", "throttle", "block")


def distance(vector, base):
    names = base["names"]
    # the precision is fitted in standardised space, so delta is already the z score
    delta = (vector - base["mean"]) / base["scale"]
    weighted = base["precision"] @ delta
    d2 = float(delta @ weighted)
    contrib = delta * weighted
    top = [{"feature": names[i], "value": float(contrib[i]),
            "share": float(contrib[i] / d2) if d2 else 0.0}
           for i in np.argsort(-np.abs(contrib))[:3]]
    zscores = dict(zip(names, delta.tolist()))
    return d2, top, zscores


def novelty(dests, services, base):
    new_dests, rotations = [], 0
    for key, addrs in dests.items():
        if key in base["dests"]:
            rotations += len([a for a in addrs if a not in base["ips"]])
        else:
            new_dests.append(key)
    new_services = [s for s in services if s not in base["services"]]
    return new_dests, new_services, rotations


def discrete_hits(new_dests, new_services):
    hits = []
    for key in new_dests:
        hits.append(("new_domain " if key.startswith("d:") else "new_prefix ") + key[2:])
    return hits + ["new_service " + s for s in new_services]


# a new prefix is address rotation under a known domain, it can alert and throttle, never block
def hard_novelty(keys):
    return any(not k.startswith("p:") for k in keys)


# learning fits only complete, non empty windows, so a truncated or silent window has no
# distribution behind its distance and the distance must be ignored. its novelty is still
# real: a domain is a domain whether the window ran 105 seconds or 300
def trusted_distance(packets, complete, conf):
    return bool(complete) and (bool(packets) or conf["learning"]["learn_include_empty"])


# an operator clear is authoritative. the capture to score path is several minutes deep, so
# when an operator clears a device there are still windows in the queue that were captured
# while enforcement was in force. those windows describe exactly the state the operator just
# overruled, and scoring them re-enforces a device that has already been cleared. measured
# 2026-08-25: a manual unblock at 18:14 was reversed at 18:19 by two windows captured before
# it. a window that merely overlaps the clear is also suspect, so the test is on its start.
def superseded_by_clear(window_start, cleared_at):
    return bool(cleared_at) and window_start < cleared_at


# count is a signed streak: positive counts anomalous windows, negative counts normal ones.
# recent is a bitmask of the last `escalate_window` decisions, newest in bit 0, which is
# what lets escalation tolerate a gap. a consecutive streak cannot: measured on the live
# injections of 2026-08-25, a sustained volume anomaly cleared the threshold in two windows
# out of three with the gap in the middle, so the streak reset every time and a real
# anomaly never escalated. see docs/2026-08-25_live-injection-campaign.md
def decide_tier(tier, count, d2, thresholds, hits, hits_before, trusted, conf, recent=0):
    rules = conf["thresholds"]
    span = max(1, int(rules.get("escalate_window", 2)))
    need = max(1, int(rules.get("escalate_hits", 2)))
    far = trusted and d2 >= thresholds["t_alert"]
    anomalous = far or bool(hits)
    if anomalous:
        count = count + 1 if count > 0 else 1
    else:
        count = count - 1 if count < 0 else -1
    recent = ((recent << 1) | int(anomalous)) & ((1 << span) - 1)
    agree = bin(recent).count("1")
    hard = [h for h in hits if not h.startswith("new_prefix")]
    # the distance was the only route to block that could act on a single window. it now
    # takes the same agreement the novelty route already required, so one heavy reconnect
    # alerts and only a sustained deviation enforces
    critical = trusted and d2 >= thresholds["t_critical"] and agree >= need
    if critical or (hard and hits_before):
        new = "block"
    elif agree >= need and anomalous:
        new = "throttle"
    elif anomalous:
        new = "alert"
    else:
        new = tier
        if -count >= conf["thresholds"]["deescalate_windows"]:
            new = TIERS[max(0, TIERS.index(tier) - 1)]
            count = 0
    # a device only ever steps down one tier at a time, never straight to normal
    if TIERS.index(new) < TIERS.index(tier) and anomalous:
        new = tier
    return new, count, recent


def reason(d2, thresholds, hits, trusted=True):
    head = "d2 %.1f (alert %.1f, critical %.1f)" % (d2, thresholds["t_alert"],
                                                    thresholds["t_critical"])
    if not trusted:
        head += " [distance ignored, window not usable]"
    return ", ".join([head] + hits)
