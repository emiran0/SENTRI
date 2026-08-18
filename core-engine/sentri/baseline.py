import json
import logging

import numpy as np
from scipy.stats import chi2
from sklearn.covariance import LedoitWolf

from . import db
from .extract import FEATURES, WINDOW_SECONDS, to_vector

log = logging.getLogger("sentri")
FIT_FRACTION = 0.8
RIDGE = 1e-6


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


def pick_thresholds(calib_d2, dims, conf):
    rules = conf["thresholds"]
    calib = {
        "p50": float(np.percentile(calib_d2, 50)),
        "p95": float(np.percentile(calib_d2, 95)),
        "p99": float(np.percentile(calib_d2, 99)),
        "max": float(calib_d2.max()),
    }
    # all three are stored every fit so a threshold rule comparison needs only a re-score
    candidates = {
        "max_margin": calib["max"] * rules["alert_margin"],
        "p99_margin": calib["p99"] * rules["alert_margin"],
        "chi2": float(chi2.ppf(0.999, dims)),
    }
    t_alert = candidates[rules["rule"]]
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
    split = max(len(names) + 1, int(len(matrix) * FIT_FRACTION))
    train, calib = matrix[:split], matrix[split:]
    if not len(calib):
        train, calib = matrix[:-1], matrix[-1:]
    mean = train.mean(axis=0)
    floors = np.array([conf["variance_floors"].get(f, 0.0) for f in names])
    if not floors.all():
        raise ValueError("variance_floors missing for: " + ", ".join(
            n for n, f in zip(names, floors) if not f))
    # standardise before shrinkage: LedoitWolf shrinks toward trace over p times the
    # identity, so one feature measured in bytes drowns every log scale feature
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
        # a well conditioned fit lands near the feature count, far below means collinearity
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
    # baselines fitted before the feature set was configurable used all twelve
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
        # a baseline fitted before standardisation has its precision in raw feature space
        "scale": np.array(quality["scale"]) if "scale" in quality else np.ones(len(names)),
    }
