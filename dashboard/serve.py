"""Read only web view over the SENTRI database.

Local only by design. It opens the database read only, never writes, and never shells
out to nft, so it can run unprivileged alongside the engine.
"""

import argparse
import json
import mimetypes
import os
import posixpath
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import queries

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
REPO = os.path.dirname(HERE)
ENGINE = os.path.join(REPO, "core-engine")

sys.path.insert(0, ENGINE)
from sentri import config  # noqa: E402  needs ENGINE on the path

# the learning gates are numpy free but live in baseline.py next to the fit, which is
# not. importing them keeps the dashboard reporting the gate the engine actually applies
# rather than a copy that can drift, and the view degrades to no progress if it fails
try:
    from sentri import baseline as engine_baseline
except ImportError:
    engine_baseline = None


def learning_probe(conn, conf, dev):
    if dev["state"] != "learning":
        return None
    if engine_baseline is None:
        return {"unavailable": "engine baseline module not importable"}
    windows = engine_baseline.usable(conn, dev["mac"], dev, conf)
    status = engine_baseline.gates(windows, dev, conf)
    status["usable_windows"] = len(windows)
    status["min_windows"] = conf["learning"]["min_windows"]
    status["learning_hours"] = conf["learning"]["learning_hours"]
    status["hard_stop_hours"] = conf["learning"]["hard_stop_hours"]
    status["hours_elapsed"] = (time.time() - dev["learning_started"]) / 3600.0
    return status


class Handler(BaseHTTPRequestHandler):
    server_version = "sentri-dashboard"
    protocol_version = "HTTP/1.1"

    @property
    def conf(self):
        return self.server.conf

    def log_message(self, fmt, *args):
        if self.server.verbose:
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        query = parse_qs(parsed.query)
        try:
            if route.startswith("/api/"):
                payload = self.api(route[5:], query)
                if payload is None:
                    self.send_json({"error": "unknown endpoint: " + route}, status=404)
                else:
                    self.send_json(payload)
            else:
                self.send_static(route)
        except BrokenPipeError:
            pass
        except Exception:
            traceback.print_exc()
            self.send_json({"error": traceback.format_exc(limit=2)}, status=500)

    def arg(self, query, name, default=None, cast=str):
        values = query.get(name)
        if not values:
            return default
        try:
            return cast(values[0])
        except (TypeError, ValueError):
            return default

    def api(self, name, query):
        conf = self.conf
        conn = queries.connect(conf["paths"]["db"])
        try:
            if name == "state":
                return {
                    "system": queries.system(conn, conf),
                    "devices": queries.devices(conn, conf, learning_probe),
                    "events": queries.events(conn, self.arg(query, "events", 40, int)),
                    "enforcement": queries.enforcement(conn),
                }
            mac = unquote(self.arg(query, "mac", "") or "").lower()
            if name == "series":
                hours = max(1, min(720, self.arg(query, "hours", 12, int)))
                out = queries.series(conn, conf, mac, hours)
                out["injections"] = queries.injections(conn, mac, hours)
                return out
            if name == "device":
                return {
                    "windows": queries.windows_table(conn, conf, mac,
                                                     self.arg(query, "limit", 40, int)),
                    "baselines": queries.baselines_for(conn, mac),
                    "events": queries.events(conn, 40, mac),
                    "ground_truth": queries.ground_truth(conn, mac, 40),
                }
            if name == "log":
                path = queries.system(conn, conf)["log_path"]
                return {"path": path,
                        "lines": queries.log_tail(path, self.arg(query, "lines", 120, int))}
        finally:
            conn.close()
        # the caller turns this into a 404 rather than an exception page
        return None

    def send_json(self, payload, status=200):
        body = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, route):
        name = "index.html" if route in ("/", "") else posixpath.normpath(unquote(route))
        path = os.path.join(STATIC, name.lstrip("/"))
        if not os.path.abspath(path).startswith(STATIC) or not os.path.isfile(path):
            self.send_json({"error": "not found"}, status=404)
            return
        with open(path, "rb") as f:
            body = f.read()
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(prog="sentri-dashboard")
    parser.add_argument("--config", default=os.path.join(ENGINE, "config.yaml"))
    parser.add_argument("--db", help="override paths.db from the config")
    # loopback by default: this exposes the whole capture history and has no authentication
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8842)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    conf = config.load(args.config)
    if args.db:
        conf["paths"]["db"] = args.db
    if not os.path.exists(conf["paths"]["db"]):
        sys.exit("database not found: " + conf["paths"]["db"])
    queries.connect(conf["paths"]["db"]).close()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.conf = conf
    server.verbose = args.verbose
    server.daemon_threads = True
    print("sentri dashboard on http://%s:%d, database %s"
          % (args.host, args.port, conf["paths"]["db"]))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("")


if __name__ == "__main__":
    main()
