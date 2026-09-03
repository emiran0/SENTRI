import json
import logging

import numpy as np
from scipy.stats import chi2
from sklearn.covariance import LedoitWolf

from . import db
from .extract import FEATURES, WINDOW_SECONDS, to_vector

log = logging.getLogger("sentri")
CALIB_CHUNKS = 10
CALIB_HOLDOUT = (4, 9)  # middle and tail, not two neighbours
RIDGE = 1e-6  # keeps the inverse from blowing up on a near singular cov


def usable(conn, mac, dev, conf):
    windows = db.learning_windows(conn, mac, dev["learning_started"])
    spans = db.injection_spans(conn, mac)
    keep = []
    for w in windows:
        if not w["complete"]:
            continue
        if not w["packets"] and not conf["learning"]["learn_include_empty"]:
            continue
        start = w["window_start"]
        # overlaps an injection, ground truth says it is dirty
        if any(a < start + WINDOW_SECONDS and b > start for a, b in spans):
            continue
        keep.append(w)
    return keep


def gates(windows, dev, conf):
    learn = conf["learning"]
    if not windows:
        return {"windows": False, "duration": False, "stability": False, "detail": "no windows"}
    hours = (windows[-1]["window_start"] - dev["learning_started"]) / 3600.0
    cut = int(len(windows) * (1 - learn["stability_fraction"]))
    # dests only ever seen in the tail means the device has not settled yet
    early, late = set(), set()
    for i, w in enumerate(windows):
        keys = json.loads(w["counters_json"]).get("dests", {}).keys()
        (late if i >= cut else early).update(keys)
    fresh = late - early
    return {
        "windows": len(windows) >= learn["min_windows"],
        "duration": hours >= learn["learning_hours"],
        "stability": not fresh,
        "detail": "windows %d/%d, hours %.1f/%.1f, new dests in tail %s" % (
            len(windows), learn["min_windows"], hours, learn["learning_hours"], sorted(fresh)),
    }


def expired(dev, now, conf):
    return (now - dev["learning_started"]) / 3600.0 >= conf["learning"]["hard_stop_hours"]


def valid_names(names, where):
    unknown = [n for n in names if n not in FEATURES]
    if unknown:
        raise ValueError(where + " has unknown features: " + ", ".join(unknown))
    return names


# row wise quadratic form, one squared distance per window
def distances(matrix, mean, scale, precision):
    z = (matrix - mean) / scale
    return np.einsum("ij,jk,ik->i", z, precision, z)
    # return np.array([r @ precision @ r for r in z])  # same thing, too slow on the Pi


def pick_thresholds(calib_d2, dims, conf):
    rules = conf["thresholds"]
    calib = {
        "p50": float(np.percentile(calib_d2, 50)),
        "p95": float(np.percentile(calib_d2, 95)),
        "p99": float(np.percentile(calib_d2, 99)),
        "max": float(calib_d2.max()),
    }
    # all three stored every fit, so comparing rules is just a re-score
    candidates = {
        "max_margin": calib["max"] * rules["alert_margin"],
        "p99_margin": calib["p99"] * rules["alert_margin"],
        "p95_margin": calib["p95"] * rules["alert_margin"],
        "chi2": float(chi2.ppf(0.999, dims)),
    }
    # chi2 floor, a quiet calib slice would otherwise put t_alert under the noise
    t_alert = max(candidates[rules["rule"]], candidates["chi2"])
    return {
        "rule": rules["rule"],
        "t_alert": t_alert,
        "t_critical": t_alert * rules["critical_multiplier"],
        "candidates": candidates,
        "calib": calib,
        "chi2": {"p50": float(chi2.ppf(0.50, dims)), "p95": float(chi2.ppf(0.95, dims)),
                 "p99": float(chi2.ppf(0.99, dims)), "p999": float(chi2.ppf(0.999, dims))},
    }


def fit(conn, mac, dev, conf, forced=False):
    windows = usable(conn, mac, dev, conf)
    status = gates(windows, dev, conf)
    names = valid_names(conf["model_features"], "model_features")
    if len(windows) <= len(names) + 1:
        log.warning("%s cannot fit, only %d usable windows", mac, len(windows))
        return None
    matrix = np.array([to_vector(json.loads(w["features_json"]), names) for w in windows])
    # two spread chunks, a plain tail slice can land between cloud check ins and see idle only
    starts = np.array([w["window_start"] for w in windows])
    span = max(1, int(starts[-1] - starts[0]) + 1)
    held = np.isin((starts - starts[0]) * CALIB_CHUNKS // span, CALIB_HOLDOUT)
    if len(matrix) - int(held.sum()) <= len(names) + 1 or held.sum() < 2:
        held = np.zeros(len(matrix), dtype=bool)
        held[-1] = True  # too few windows to spread, last one it is
    train, calib = matrix[~held], matrix[held]
    mean = train.mean(axis=0)
    floors = np.array([conf["variance_floors"].get(f, 0.0) for f in names])
    if not floors.all():
        raise ValueError("variance_floors missing for: " + ", ".join(
            n for n, f in zip(names, floors) if not f))
    # standardise first, LedoitWolf shrinks toward trace/p times identity so a bytes scale
    # feature would drown the log scale ones
    scale = np.maximum(train.std(axis=0), floors)
    cov = LedoitWolf(assume_centered=True).fit((train - mean) / scale).covariance_
    cov = cov + RIDGE * np.eye(len(names))
    precision = np.linalg.inv(cov)
    thresholds = pick_thresholds(distances(calib, mean, scale, precision), len(names), conf)
    dests, ips, services = set(), set(), set()
    for w in windows:
        counters = json.loads(w["counters_json"])
        for key, addrs in counters.get("dests", {}).items():
            dests.add(key)
            ips.update(addrs)
        services.update(counters.get("services", []))
    quality = {
        "gates": status,
        "forced": forced,
        "n_fit": len(train),
        "n_calib": len(calib),
        "scale": scale.tolist(),
        "correlation": cov.tolist(),
        # lands near the feature count when well conditioned, far below means collinearity
        "median_fit_d2": float(np.median(distances(train, mean, scale, precision))),
    }
    baseline_id = db.add_baseline(conn, mac, len(windows), mean.tolist(), precision.tolist(),
                                  thresholds, {"keys": sorted(dests), "ips": sorted(ips)},
                                  sorted(services), quality, names)
    log.info("%s baseline %d fitted on %d windows, %d features, t_alert %.2f", mac,
             baseline_id, len(windows), len(names), thresholds["t_alert"])
    return baseline_id


def load(conn, mac):
    row = db.active_baseline(conn, mac)
    if not row:
        return None
    dest_set = json.loads(row["dest_set_json"])
    quality = json.loads(row["quality_json"])
    stored = row["feature_names_json"]
    # pre config baselines used all twelve
    names = valid_names(json.loads(stored) if stored else list(FEATURES), "baseline")
    return {
        "id": row["id"],
        "names": names,
        "mean": np.array(json.loads(row["mean_json"])),
        "precision": np.array(json.loads(row["precision_json"])),
        "thresholds": json.loads(row["thresholds_json"]),
        "dests": set(dest_set["keys"]),
        "ips": set(dest_set["ips"]),
        "services": set(json.loads(row["service_set_json"])),
        # pre standardisation baselines have precision in raw feature space, so ones
        "scale": np.array(quality["scale"]) if "scale" in quality else np.ones(len(names)),
    }
