import os
import time

CHUNK_PREFIX = "iot-"
CHUNK_SUFFIX = ".pcap"


# the filename is the clock here, mtime keeps moving while the chunk is written
def chunk_time(name):
    stamp = name[len(CHUNK_PREFIX):-len(CHUNK_SUFFIX)]
    return time.mktime(time.strptime(stamp, "%Y%m%d-%H%M%S"))


def watermark_path(conf):
    return os.path.join(os.path.dirname(conf["paths"]["db"]), "watermark")


def read_watermark(conf):
    path = watermark_path(conf)
    if not os.path.exists(path):
        return ""
    with open(path) as f:
        return f.read().strip()


def write_watermark(conf, name):
    with open(watermark_path(conf), "w") as f:
        f.write(name)


def pending(conf):
    directory = conf["paths"]["captures"]
    if not os.path.isdir(directory):
        return []
    mark = read_watermark(conf)  # last chunk we finished, names sort in time order
    cutoff = time.time() - conf["capture"]["grace_seconds"]
    out = []
    for name in sorted(os.listdir(directory)):
        if not name.startswith(CHUNK_PREFIX) or not name.endswith(CHUNK_SUFFIX):
            continue
        if name <= mark:
            continue
        path = os.path.join(directory, name)
        # a chunk still being written keeps touching its mtime, so grace is enough
        if os.path.getmtime(path) > cutoff:
            continue
        out.append((path, name, chunk_time(name)))
    return out
