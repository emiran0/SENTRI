import argparse
import csv
import json
import time

from . import baseline, config, db, engine, enforce, extract, score

TABLES = ("windows", "scores", "events")


def cmd_init(conn, conf, args):
    if conf["enforcement"]["mode"] == "enforce":
        enforce.load_ruleset(conf["paths"]["nft_file"])
    print("database at %s, mode %s" % (conf["paths"]["db"], conf["enforcement"]["mode"]))


def cmd_run(conn, conf, args):
    engine.setup_logging(conf)
    engine.run(conf)


def cmd_status(conn, conf, args):
    active = enforce.list_active()
    print("%-18s %-11s %-9s %-9s %10s %s" % ("MAC", "STATE", "TIER", "COUNT", "D2", "ENFORCED"))
    for dev in db.all_devices(conn):
        latest = db.latest_score(conn, dev["mac"])
        sets = [name for name, members in active.items()
                if dev["mac"] in members or (dev["ip"] and dev["ip"] in members)]
        print("%-18s %-11s %-9s %-9d %10s %s" % (
            dev["mac"], dev["state"], dev["tier"], dev["consecutive_count"],
            "%.1f" % latest["d2"] if latest else "-", ",".join(sets) or "-"))
    for dev in db.all_devices(conn):
        if dev["state"] == "learning":
            windows = baseline.usable(conn, dev["mac"], dev, conf)
            print("%s learning: %s" % (dev["mac"], baseline.gates(windows, dev, conf)["detail"]))


def cmd_rebaseline(conn, conf, args):
    db.drop_baselines(conn, args.mac)
    db.update_device(conn, args.mac, state="learning", baseline_id=None, tier="normal",
                     consecutive_count=0, learning_started=time.time())
    db.add_event(conn, args.mac, time.time(), "normal", "rebaseline", "baseline wiped", {})
    print("%s back to learning" % args.mac)


def cmd_refit(conn, conf, args):
    dev = db.get_device(conn, args.mac)
    baseline_id = baseline.fit(conn, args.mac, dev, conf, forced=True)
    if baseline_id is None:
        return
    db.update_device(conn, args.mac, baseline_id=baseline_id)
    base = baseline.load(conn, args.mac)
    thresholds = base["thresholds"]
    for window in db.learning_windows(conn, args.mac, 0):
        feats = json.loads(window["features_json"])
        d2, contributions, zscores = score.distance(
            extract.to_vector(feats, base["names"]), base)
        # a stateless per window severity, so a false positive count is one GROUP BY,
        # and the stored novelty reflects the old destination set so it is not replayed
        tier = "normal"
        if d2 >= thresholds["t_critical"]:
            tier = "block"
        elif d2 >= thresholds["t_alert"]:
            tier = "alert"
        db.add_score(conn, window["id"], baseline_id, args.mac, d2, tier, contributions, zscores)
    db.add_event(conn, args.mac, time.time(), "normal", "refit",
                 "baseline %d over %d features" % (baseline_id, len(base["names"])), thresholds)
    print("%s baseline %d, t_alert %.2f, t_critical %.2f, rescored %d windows" % (
        args.mac, baseline_id, thresholds["t_alert"], thresholds["t_critical"],
        len(db.learning_windows(conn, args.mac, 0))))


def cmd_unblock(conn, conf, args):
    targets = db.all_devices(conn) if args.mac == "all" else [db.get_device(conn, args.mac)]
    for dev in targets:
        enforce.clear(dev["mac"], dev["ip"])
        db.add_enforcement(conn, dev["mac"], "normal", "manual unblock")
        db.update_device(conn, dev["mac"], tier="normal", consecutive_count=0)
        db.add_event(conn, dev["mac"], time.time(), "normal", "unblock", "manual unblock", {})
        print("cleared %s" % dev["mac"])


def cmd_export(conn, conf, args):
    count = write_csv(conn, args.table, args.out)
    print("wrote %d rows to %s" % (count, args.out))


def write_csv(conn, table, path):
    rows = db.rows(conn, "SELECT * FROM " + table + " ORDER BY rowid")
    flat = [flatten(r) for r in rows]
    columns = []
    for row in flat:
        for key in row:
            if key not in columns:
                columns.append(key)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(flat)
    return len(flat)


def flatten(row):
    out = {}
    for key, value in row.items():
        if not key.endswith("_json") or value is None:
            out[key] = value
            continue
        parsed = json.loads(value)
        if isinstance(parsed, dict) and all(not isinstance(v, (dict, list)) for v in parsed.values()):
            for name, item in parsed.items():
                out[key[:-5] + "_" + name] = item
        else:
            out[key] = value
    return out


def main():
    parser = argparse.ArgumentParser(prog="sentri")
    parser.add_argument("--config", default="config.yaml")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("init").set_defaults(func=cmd_init)
    subs.add_parser("run").set_defaults(func=cmd_run)
    subs.add_parser("status").set_defaults(func=cmd_status)
    rebase = subs.add_parser("rebaseline")
    rebase.add_argument("mac")
    rebase.set_defaults(func=cmd_rebaseline)
    refit = subs.add_parser("refit")
    refit.add_argument("mac")
    refit.set_defaults(func=cmd_refit)
    unblock = subs.add_parser("unblock")
    unblock.add_argument("mac")
    unblock.set_defaults(func=cmd_unblock)
    export = subs.add_parser("export")
    export.add_argument("table", choices=TABLES)
    export.add_argument("--out", required=True)
    export.set_defaults(func=cmd_export)
    args = parser.parse_args()
    conf = config.load(args.config)
    conn = db.connect(conf["paths"]["db"])
    args.func(conn, conf, args)


if __name__ == "__main__":
    main()
