"""Recover destination provenance for a replay by reading the capture's own DNS answers.

    python tools/dns_from_pcap.py 18-10-19.pcap --out /srv/sentri/replay/unsw/dns.log

A gateway capture contains the DNS traffic it carried, so the address-to-domain mapping a
live deployment gets from its resolver log is recoverable from the archive itself. This
writes it in the dnsmasq line format `extract.DnsLog` already parses, so the engine reads
it with **no code change**: point `paths.pihole_log` at the output.

Why it matters. Without provenance every destination keys as `p:<prefix>`, cloud addresses
rotate, and the novelty rule fires constantly. Measured on the UNSW attack capture, 63
percent of unattacked windows were flagged. That is the benchmark condition, and it is a
real result, but it conflates two different things: the absence of a resolver, and every
other way a benchmark differs from a live deployment. Recovering provenance separates them.

This produces a fourth arm for the section 19 ablation:

    A  live, resolver available
    B  live, resolver ignored          (isolates the resolver on live traffic)
    C  benchmark, no resolver          (the benchmark as it ships)
    D  benchmark, resolver recovered   (this tool)

B against D is then everything about a benchmark that is *not* the missing resolver.

Only responses are read, and only A records. Reading is raw and packets are dissected only
when the byte offsets already say UDP source port 53, so the cost is a small fraction of a
full dissection pass.
"""

import argparse
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.dns import DNS
from scapy.utils import RawPcapReader

ETH_IP = b"\x08\x00"
PROTO_UDP = 17


def meta_ts(meta):
    if hasattr(meta, "sec"):
        return int(meta.sec)
    raw = (int(meta.tshigh) << 32) | int(meta.tslow)
    res = int(getattr(meta, "tsresol", 1000000)) or 1000000
    return raw // res


def ipv4(b):
    return ".".join(str(x) for x in b)


def dns_payload(data):
    """cheap byte-offset test first, so only real DNS responses are dissected"""
    if len(data) < 42 or data[12:14] != ETH_IP:
        return None
    ihl = (data[14] & 0x0F) * 4
    if ihl < 20 or data[23] != PROTO_UDP:
        return None
    udp = 14 + ihl
    if len(data) < udp + 8:
        return None
    sport = (data[udp] << 8) | data[udp + 1]
    if sport != 53:                       # responses only
        return None
    src = ipv4(data[14 + 12:14 + 16])
    dst = ipv4(data[14 + 16:14 + 20])
    return src, dst, data[udp + 8:]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    seen = dns_pkts = records = 0
    pairs = set()
    truncated = None
    t0 = time.monotonic()
    r = RawPcapReader(args.pcap)
    out = open(args.out, "w")
    try:
        it = iter(r)
        while True:
            try:
                data, meta = next(it)
            except StopIteration:
                break
            except Exception as exc:
                truncated = "%s after %d packets" % (exc, seen)
                break
            seen += 1
            hit = dns_payload(data)
            if not hit:
                continue
            server, client, payload = hit
            try:
                d = DNS(payload)
            except Exception:
                continue
            if not getattr(d, "ancount", 0):
                continue
            dns_pkts += 1
            qname = None
            if getattr(d, "qd", None):
                try:
                    qname = d.qd.qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = None
            if not qname:
                continue
            stamp = datetime.fromtimestamp(meta_ts(meta), timezone.utc).strftime(
                "%b %d %H:%M:%S")
            for i in range(d.ancount):
                try:
                    rr = d.an[i]
                except Exception:
                    break
                if getattr(rr, "type", None) != 1:      # A records only
                    continue
                addr = rr.rdata
                addr = addr if isinstance(addr, str) else str(addr)
                if (client, addr) in pairs:
                    continue
                pairs.add((client, addr))
                # the two line shape DnsLog.feed expects: a query that names the client,
                # then a reply that binds the queried name to the address
                out.write("%s dnsmasq[1]: query[A] %s from %s\n" % (stamp, qname, client))
                out.write("%s dnsmasq[1]: reply %s is %s\n" % (stamp, qname, addr))
                records += 1
    finally:
        out.close()
        r.close()

    dt = time.monotonic() - t0
    if truncated:
        print("NOTE: capture ended early: %s" % truncated)
    print("read      %d packets in %.1f s (%.0f pkt/s)" % (seen, dt, seen / max(dt, 1e-9)))
    print("DNS responses with answers: %d" % dns_pkts)
    print("distinct client/address mappings written: %d" % records)
    print("wrote %s" % args.out)
    if not records:
        print("\nNo A records recovered. Either the capture carries no DNS, or the devices"
              "\nuse DoT or DoH, in which case provenance cannot be recovered this way and"
              "\nthe prefix-only arm is the only one available.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
