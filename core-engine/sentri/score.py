import numpy as np

from .extract import FEATURES

TIERS = ("normal", "alert", "throttle", "block")


def distance(vector, base):
    delta = vector - base["mean"]
    weighted = base["precision"] @ delta
    d2 = float(delta @ weighted)
    contrib = delta * weighted
    top = [{"feature": FEATURES[i], "value": float(contrib[i]),
            "share": float(contrib[i] / d2) if d2 else 0.0}
           for i in np.argsort(-np.abs(contrib))[:3]]
    zscores = dict(zip(FEATURES, (delta / base["std"]).tolist()))
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


# count is a signed streak: positive counts anomalous windows, negative counts normal ones
def decide_tier(tier, count, d2, thresholds, hits, hits_before, conf):
    anomalous = d2 >= thresholds["t_alert"] or bool(hits)
    if anomalous:
        count = count + 1 if count > 0 else 1
    else:
        count = count - 1 if count < 0 else -1
    if d2 >= thresholds["t_critical"] or (hits and hits_before):
        new = "block"
    elif count >= 2 and d2 >= thresholds["t_alert"]:
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
    return new, count


def reason(d2, thresholds, hits):
    head = "d2 %.1f (alert %.1f, critical %.1f)" % (d2, thresholds["t_alert"],
                                                    thresholds["t_critical"])
    return ", ".join([head] + hits)
