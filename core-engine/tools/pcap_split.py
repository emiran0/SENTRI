"""Split an archived capture into 300 s chunks the unmodified pipeline can read.

    python tools/pcap_split.py unsw/16-09-23.pcap --out /srv/sentri/replay/unsw \
        --macs macs.txt --start 2016-09-23T00:00 --hours 36

Why split rather than replay the file directly: `extract.parse_chunk` reads a whole pcap
into a list of per-packet tuples. A live chunk is 300 s and a few hundred packets; a
dataset capture is a whole day across dozens of devices, which does not fit in memory on
this box. Splitting first also keeps `parse_chunk`, `baseline`, `score` and `decide_tier`
**completely unmodified**, which is the claim RQ4 rests on.

Filtering happens here, at split time, for the same reason. `extract.parse_chunk` treats
every MAC not in `exclude.macs` as a monitored device, so a gateway capture containing
laptops and phones would silently enrol them. Selecting devices here means the engine sees
only the intended ones and needs no allowlist of its own.

Reading is streamed, so the input size does not matter. Output filenames use the live
`iot-YYYYmmdd-HHMMSS.pcap` convention so `capture.chunk_time` parses them unchanged.
"""

import argparse
import os
import struct
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.utils import PcapReader, PcapWriter, RawPcapReader

WINDOW = 300
# measured on this Pi: scapy's dissecting reader manages 434 packets/s, because it builds
# the full layer stack for every frame. splitting needs only the timestamp and the two MAC
# addresses, which sit at fixed offsets in the Ethernet header, so the raw reader and a
# hand-written pcap record are used instead. a dataset day is millions of packets and the
# difference is hours against minutes.
PCAP_MAGIC = 0xA1B2C3D4


def mac_at(data, offset):
    return ":".join("%02x" % b for b in data[offset:offset + 6])


def meta_ts(meta):
    """classic pcap carries sec/usec; pcapng carries a 64 bit count at its own resolution.
    The UNSW release is pcapng, so both forms have to be handled here."""
    if hasattr(meta, "sec"):
        return int(meta.sec), int(meta.usec)
    raw = (int(meta.tshigh) << 32) | int(meta.tslow)
    res = int(getattr(meta, "tsresol", 1000000)) or 1000000
    sec = raw // res
    return sec, int((raw - sec * res) * 1000000 // res)


class ChunkWriter:
    """writes raw pcap records, one file per 300 s bucket, live naming convention"""

    def __init__(self, out_dir, linktype, snaplen):
        self.out_dir = out_dir
        self.linktype = linktype
        self.snaplen = max(snaplen, 65535)
        self.fh = None
        self.bucket = None
        self.count = 0

    def _open(self, bucket):
        if self.fh:
            self.fh.close()
        name = "iot-%s.pcap" % datetime.fromtimestamp(bucket, timezone.utc).strftime(
            "%Y%m%d-%H%M%S")
        self.fh = open(os.path.join(self.out_dir, name), "wb")
        self.fh.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, self.snaplen,
                                  self.linktype))
        self.bucket = bucket
        self.count += 1

    def write(self, data, sec, usec, wirelen):
        bucket = sec // WINDOW * WINDOW
        if bucket != self.bucket:
            self._open(bucket)
        self.fh.write(struct.pack("<IIII", sec, usec, len(data), wirelen))
        self.fh.write(data)

    def close(self):
        if self.fh:
            self.fh.close()


def load_macs(path):
    out = set()
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip().lower()
            if line:
                out.add(line)
    return out


def chunk_name(start):
    return "iot-%s.pcap" % datetime.fromtimestamp(start, timezone.utc).strftime(
        "%Y%m%d-%H%M%S")


def split(src, out_dir, keep, lo, hi):
    os.makedirs(out_dir, exist_ok=True)
    kept = seen = 0
    first_ts = last_ts = None
    reader = RawPcapReader(src)
    # pcapng reports link type per packet rather than per file, so it is checked on the
    # first frame instead of up front
    writer = ChunkWriter(out_dir, 1, getattr(reader, "snaplen", 65535))
    checked = False
    truncated = None
    try:
        it = iter(reader)
        while True:
            # a large archived capture can carry a malformed or truncated block. stopping
            # cleanly and saying how far we got beats aborting a multi-hour replay, and the
            # UNSW attack capture does exactly this partway through
            try:
                data, meta = next(it)
            except StopIteration:
                break
            except Exception as exc:
                truncated = "%s after %d packets" % (exc, seen)
                break
            seen += 1
            if not checked:
                lt = int(getattr(meta, "linktype", getattr(reader, "linktype", 1)))
                if lt != 1:
                    raise SystemExit("link type %d is not Ethernet; the pipeline keys on "
                                     "MAC addresses and cannot use this capture" % lt)
                checked = True
            sec, usec = meta_ts(meta)
            if lo and sec < lo:
                continue
            if hi and sec >= hi:
                break
            if len(data) < 14:
                continue
            if keep:
                # relevant if either end is a selected device. the gateway side comes along
                # implicitly, because it is the other end of exactly those frames
                if mac_at(data, 6) not in keep and mac_at(data, 0) not in keep:
                    continue
            writer.write(data, sec, usec, int(meta.wirelen))
            kept += 1
            if first_ts is None:
                first_ts = sec
            last_ts = sec
    finally:
        writer.close()
        reader.close()
    if truncated:
        print("NOTE: capture ended early: %s" % truncated)
    return seen, kept, writer.count, first_ts, last_ts


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--out", required=True, help="directory for the 300 s chunks")
    # DEVICE MACs only. do not list the gateway here: almost every frame in a gateway
    # capture has the gateway at one end, so including it matches everything and the filter
    # silently does nothing. the gateway belongs in exclude.macs in the config, where the
    # engine uses it to derive packet direction
    ap.add_argument("--macs", default=None,
                    help="file of DEVICE MACs to keep, one per line, comments with #. "
                         "Do not include the gateway MAC, that matches every packet")
    ap.add_argument("--start", default=None, help="ISO time, inclusive, UTC")
    ap.add_argument("--hours", type=float, default=None,
                    help="how many hours after --start to keep")
    args = ap.parse_args(argv)

    keep = load_macs(args.macs) if args.macs else None
    lo = hi = None
    if args.start:
        lo = datetime.fromisoformat(args.start).replace(tzinfo=timezone.utc).timestamp()
        if args.hours:
            hi = lo + args.hours * 3600
    t0 = time.monotonic()
    seen, kept, written, first_ts, last_ts = split(args.pcap, args.out, keep, lo, hi)
    dt = time.monotonic() - t0

    print("read     %d packets in %.1f s (%.0f pkt/s)" % (seen, dt, seen / max(dt, 1e-9)))
    print("kept     %d packets" % kept)
    print("wrote    %d chunks to %s" % (written, args.out))
    if first_ts:
        print("span     %s to %s (%.1f h)" % (
            datetime.fromtimestamp(first_ts, timezone.utc),
            datetime.fromtimestamp(last_ts, timezone.utc),
            (last_ts - first_ts) / 3600))
        print("coverage %d chunks against %.0f possible, %.0f percent" % (
            written, (last_ts - first_ts) / WINDOW + 1,
            100 * written / max(1, (last_ts - first_ts) / WINDOW + 1)))
    if keep:
        print("filtered to %d device MACs" % len(keep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
