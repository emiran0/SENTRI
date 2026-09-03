import numpy as np

TIERS = ("normal", "alert", "throttle", "block")


def distance(vector, base):
    names = base["names"]
    # precision is fitted in standardised space, so delta is already the z score
    delta = (vector - base["mean"]) / base["scale"]
    weighted = base["precision"] @ delta
    d2 = float(delta @ weighted)
    contrib = delta * weighted
    # top 3, that is all the event detail has room for
    top = [{"feature": names[i], "value": float(contrib[i]),
            "share": float(contrib[i] / d2) if d2 else 0.0}
           for i in np.argsort(-np.abs(contrib))[:3]]
    zscores = dict(zip(names, delta.tolist()))
    return d2, top, zscores


def novelty(dests, services, base):
    new_dests, rotations = [], 0
    for key, addrs in dests.items():
        if key in base["dests"]:
            # known key, unseen address. cdn shuffling, not a new destination
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


# def repeat_hits(hits, hits_before):
#     # was meant to weight a key that keeps coming back, but hits_before is only a bool by
#     # the time it reaches here, so this ended up counting rotations twice
#     return len([h for h in hits if h in hits_before])


# a new prefix is just address rotation under a known domain, alerts and throttles, never blocks
def hard_novelty(keys):
    return any(not k.startswith("p:") for k in keys)


# learning only fits complete, non empty windows, so a truncated one has no distribution
# behind its distance. novelty still counts, a domain is a domain either way
def trusted_distance(packets, complete, conf):
    return bool(complete) and (bool(packets) or conf["learning"]["learn_include_empty"])


# an operator clear wins. capture to score is minutes deep, so windows captured before the
# clear are still queued and would re-enforce a device that was already cleared (2026-08-25,
# an 18:14 unblock reversed at 18:19). test the start, an overlapping window is suspect too
def superseded_by_clear(window_start, cleared_at):
    return bool(cleared_at) and window_start < cleared_at


# count is a signed streak, positive anomalous / negative normal. recent is a bitmask of the
# last escalate_window decisions, newest in bit 0, so escalation survives a gap. a plain
# consecutive streak did not
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
    agree = bin(recent).count("1")  # how many of the last span windows flagged
    hard = [h for h in hits if not h.startswith("new_prefix")]
    # distance used to block off one window, now it needs the agreement novelty already did
    critical = trusted and d2 >= thresholds["t_critical"] and agree >= need
    # critical = trusted and d2 >= thresholds["t_critical"]
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
    # one tier down at a time, never straight back to normal
    if TIERS.index(new) < TIERS.index(tier) and anomalous:
        new = tier
    return new, count, recent


def reason(d2, thresholds, hits, trusted=True):
    head = "d2 %.1f (alert %.1f, critical %.1f)" % (d2, thresholds["t_alert"],
                                                    thresholds["t_critical"])
    if not trusted:
        head += " [distance ignored, window not usable]"
    return ", ".join([head] + hits)
