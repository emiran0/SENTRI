import logging
import subprocess

from . import db

log = logging.getLogger("sentri")
SETS = ("blocked_mac", "throttled_mac", "blocked_ip")


def nft(args, check=True):
    r = subprocess.run(["nft"] + args, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("nft " + " ".join(args) + " failed: " + r.stderr.strip())
    return r


def add(name, element):
    nft(["add", "element", "inet", "sentri", name, "{ " + element + " }"])


def remove(name, element):
    # deleting an absent element is an error in nftables, and it is not interesting here
    nft(["delete", "element", "inet", "sentri", name, "{ " + element + " }"], check=False)


def load_ruleset(path):
    nft(["-f", path])


def apply_tier(mac, ip, tier, conf):
    if conf["enforcement"]["mode"] != "enforce" or mac in conf["enforcement"]["never_enforce"]:
        return False
    if tier == "block":
        add("blocked_mac", mac)
        if ip:
            add("blocked_ip", ip)
        remove("throttled_mac", mac)
    elif tier == "throttle":
        add("throttled_mac", mac)
        remove("blocked_mac", mac)
        if ip:
            remove("blocked_ip", ip)
    else:
        clear(mac, ip)
    log.info("enforced %s on %s", tier, mac)
    return True


def clear(mac, ip):
    remove("blocked_mac", mac)
    remove("throttled_mac", mac)
    if ip:
        remove("blocked_ip", ip)


def sync_from_db(conn, conf):
    for dev in db.all_devices(conn):
        if dev["tier"] in ("throttle", "block"):
            apply_tier(dev["mac"], dev["ip"], dev["tier"], conf)


def list_active():
    active = {}
    for name in SETS:
        result = nft(["list", "set", "inet", "sentri", name], check=False)
        parts = result.stdout.split("elements = {")
        body = parts[1].split("}")[0] if len(parts) > 1 else ""
        active[name] = [e.strip() for e in body.split(",") if e.strip()]
    return active
