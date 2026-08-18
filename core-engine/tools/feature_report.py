import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from sklearn.covariance import LedoitWolf

from sentri import config, db
from sentri.extract import FEATURES, LOG_FEATURES, WINDOW_SECONDS, to_vector

parser = argparse.ArgumentParser(prog="feature_report")
parser.add_argument("mac")
parser.add_argument("--baseline", type=int)
parser.add_argument("--config", default=os.path.join(os.path.dirname(__file__), "..", "config.yaml"))
args = parser.parse_args()

conf = config.load(args.config)
conn = db.connect(conf["paths"]["db"])
windows = db.learning_windows(conn, args.mac, 0)
if not windows:
    sys.exit("no windows stored for " + args.mac)

spans = db.injection_spans(conn, args.mac)
empty = [w for w in windows if not w["packets"]]
short = [w for w in windows if not w["complete"]]
kept = []
for w in windows:
    if not w["complete"] or (not w["packets"] and not conf["learning"]["learn_include_empty"]):
        continue
    if any(a < w["window_start"] + WINDOW_SECONDS and b > w["window_start"] for a, b in spans):
        continue
    kept.append(w)

matrix = np.array([to_vector(json.loads(w["features_json"])) for w in kept])
print("%s: %d windows stored, %d empty, %d incomplete, %d used for the fit" % (
    args.mac, len(windows), len(empty), len(short), len(kept)))
print("empty windows included in learning: %s\n" % conf["learning"]["learn_include_empty"])

print("%-20s %10s %10s %10s %10s %10s %s" % (
    "FEATURE", "MEAN", "STD", "MIN", "MAX", "FLOOR", "TRANSFORM"))
constant = []
for i, name in enumerate(FEATURES):
    column = matrix[:, i]
    floor = conf["variance_floors"].get(name, 0.0)
    flag = ""
    if column.std() == 0.0:
        flag = "  CONSTANT"
        constant.append(name)
    elif floor > 0 and column.std() <= floor * 1.01:
        flag = "  AT FLOOR"
    print("%-20s %10.4f %10.4f %10.4f %10.4f %10.4f %-6s%s" % (
        name, column.mean(), column.std(), column.min(), column.max(), floor,
        "log1p" if name in LOG_FEATURES else "none", flag))

print("\npairwise pearson correlation, a dash means one side is constant")
# a constant column has zero standard deviation, so its correlation is undefined
with np.errstate(invalid="ignore", divide="ignore"):
    corr = np.corrcoef(matrix, rowvar=False)
# np.cov can leave float residue where std is exactly zero, which reads as a spurious 1.00
for i in [FEATURES.index(n) for n in constant]:
    corr[i, :] = np.nan
    corr[:, i] = np.nan
print("%-20s%s" % ("", "".join("%8d" % i for i in range(len(FEATURES)))))
for i, name in enumerate(FEATURES):
    cells = ["%8s" % "-" if np.isnan(v) else "%8.2f" % v for v in corr[i]]
    print("%-2d %-17s%s" % (i, name[:17], "".join(cells)))

pairs = [(abs(corr[i][j]), FEATURES[i], FEATURES[j])
         for i in range(len(FEATURES)) for j in range(i + 1, len(FEATURES))
         if not np.isnan(corr[i][j])]
print("\nmost correlated pairs")
for value, a, b in sorted(pairs, reverse=True)[:8]:
    print("  %.4f  %s / %s" % (value, a, b))
if constant:
    print("constant features, they carry no information at this traffic level: %s"
          % ", ".join(constant))

raw = np.cov(matrix, rowvar=False)
shrunk = LedoitWolf(assume_centered=False).fit(matrix).covariance_
eigenvalues = np.sort(np.linalg.eigvalsh(raw))[::-1]
rank = int((eigenvalues > eigenvalues[0] * 0.01).sum())
print("\ncondition number raw      %.4g" % np.linalg.cond(raw))
print("condition number shrunk  %.4g" % np.linalg.cond(shrunk))
print("effective rank           %d of %d (eigenvalues above 1 percent of the largest)"
      % (rank, len(FEATURES)))
print("eigenvalues              %s" % " ".join("%.4g" % v for v in eigenvalues))

row = (db.one(conn, "SELECT * FROM baselines WHERE id = ?", (args.baseline,)) if args.baseline
       else db.active_baseline(conn, args.mac))
if row:
    stored = row["feature_names_json"]
    names = json.loads(stored) if stored else list(FEATURES)
    quality = json.loads(row["quality_json"])
    print("\nbaseline %d, %d windows, %d features: %s" % (
        row["id"], row["n_windows"], len(names), ", ".join(names)))
    print("thresholds %s" % row["thresholds_json"])
    print("std        %s" % " ".join("%.4f" % v for v in quality["std"]))
    if "median_fit_d2" in quality:
        print("median fit d2 %.3f against %d features" % (quality["median_fit_d2"], len(names)))
