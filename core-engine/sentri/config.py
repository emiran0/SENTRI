import yaml

DEFAULTS = {
    "run_label": "dev",
    "paths": {
        "db": "/srv/sentri/sentri.db",
        "captures": "/srv/sentri/captures",
        "pihole_log": "/var/log/pihole/pihole.log",
        "nft_file": "nftables/sentri.nft",
    },
    "capture": {"grace_seconds": 60, "poll_seconds": 30},
    "network": {"gateway_ip": "192.168.50.1", "iface": "eth1"},
    "exclude": {"macs": [], "tcp_ports": [8080, 22]},
    "learning": {
        "min_windows": 200,
        "learning_hours": 24,
        "hard_stop_hours": 72,
        "stability_fraction": 0.25,
        "learn_include_empty": False,
    },
    "thresholds": {
        "rule": "p99_margin",
        "alert_margin": 3.0,
        "critical_multiplier": 4.0,
        "deescalate_windows": 3,
    },
    "model_features": ["bytes_out_rate", "bytes_in_rate", "mean_pkt_size_out",
                       "std_pkt_size_out", "mean_iat_out", "distinct_peers"],
    "variance_floors": {},
    "enforcement": {"mode": "observe", "never_enforce": [], "auto_clear_hours": 2},
    "ground_truth": {"poll_seconds": 300, "nodes": {}},
}


def load(path="config.yaml"):
    with open(path) as f:
        user = yaml.safe_load(f) or {}
    conf = merge(DEFAULTS, user)
    conf["exclude"]["macs"] = [m.lower() for m in conf["exclude"]["macs"]]
    conf["enforcement"]["never_enforce"] = [m.lower() for m in conf["enforcement"]["never_enforce"]]
    return conf


def merge(base, over):
    out = dict(base)
    for key, value in over.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = value
    return out
