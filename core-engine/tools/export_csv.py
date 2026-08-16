import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentri import cli, config, db

out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
default_conf = os.path.join(os.path.dirname(__file__), "..", "config.yaml")
conf = config.load(sys.argv[2] if len(sys.argv) > 2 else default_conf)
conn = db.connect(conf["paths"]["db"])

for table in cli.TABLES + ("devices", "baselines", "enforcement", "ground_truth"):
    path = os.path.join(out_dir, table + ".csv")
    print("%s: %d rows" % (path, cli.write_csv(conn, table, path)))
