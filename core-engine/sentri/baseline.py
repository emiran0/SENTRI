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


def fit(conn, mac, dev, conf, forced=False):
    windows = usable(conn, mac, dev, conf)
    status = gates(windows, dev, conf)
    if len(windows) <= len(FEATURES) + 1:
        log.warning("%s cannot fit, only %d usable windows", mac, len(windows))
        return None
    matrix = np.array([to_vector(json.loads(w["features_json"])) for w in windows])
    split = max(len(FEATURES) + 1, int(len(matrix) * FIT_FRACTION))
    train, calib = matrix[:split], matrix[split:]
    if not len(calib):
        train, calib = matrix[:-1], matrix[-1:]
    mean = train.mean(axis=0)
    cov = LedoitWolf(assume_centered=False).fit(train).covariance_
    floors = np.array([conf["variance_floors"].get(f, 0.0) for f in FEATURES])
    np.fill_diagonal(cov, np.maximum(np.diag(cov), floors ** 2))
    cov = cov + RIDGE * np.eye(len(FEATURES))
    precision = np.linalg.inv(cov)
    deltas = calib - mean
    # row wise quadratic form, one squared distance per calibration window
    calib_d2 = np.einsum("ij,jk,ik->i", deltas, precision, deltas)
    theory = float(chi2.ppf(0.999, len(FEATURES)))
    t_alert = max(float(calib_d2.max()) * conf["thresholds"]["alert_multiplier"], theory)
    thresholds = {
        "t_alert": t_alert,
        "t_critical": t_alert * conf["thresholds"]["critical_multiplier"],
    }
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
        "std": np.sqrt(np.diag(cov)).tolist(),
        "empirical": {
            "p95": float(np.percentile(calib_d2, 95)),
            "p99": float(np.percentile(calib_d2, 99)),
            "max": float(calib_d2.max()),
        },
        # kept alongside the empirical values to show how far real IoT traffic
        # is from the multivariate Gaussian assumption
        "chi2": {
            "p95": float(chi2.ppf(0.95, len(FEATURES))),
            "p99": float(chi2.ppf(0.99, len(FEATURES))),
            "p999": theory,
        },
    }
    baseline_id = db.add_baseline(conn, mac, len(windows), mean.tolist(), precision.tolist(),
                                  thresholds, {"keys": sorted(dests), "ips": sorted(ips)},
                                  sorted(services), quality)
    log.info("%s baseline %d fitted on %d windows, t_alert %.1f", mac, baseline_id,
             len(windows), t_alert)
    return baseline_id


def load(conn, mac):
    row = db.active_baseline(conn, mac)
    if not row:
        return None
    dest_set = json.loads(row["dest_set_json"])
    return {
        "id": row["id"],
        "mean": np.array(json.loads(row["mean_json"])),
        "precision": np.array(json.loads(row["precision_json"])),
        "thresholds": json.loads(row["thresholds_json"]),
        "dests": set(dest_set["keys"]),
        "ips": set(dest_set["ips"]),
        "services": set(json.loads(row["service_set_json"])),
        "std": np.array(json.loads(row["quality_json"])["std"]),
    }
