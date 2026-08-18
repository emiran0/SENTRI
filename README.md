# SENTRI

SENTRI learns what each IoT device on a network normally does, scores every five minute
window of its traffic against that baseline, and restricts the device when it deviates.
It runs on a Raspberry Pi 5 acting as the gateway for an isolated IoT subnet.

This is an MSc research instrument, not a product. It exists to measure whether
per-device behavioural baselining is a workable defence for consumer IoT, and how well
it actually performs.

## How it works

Passive capture only. No payload inspection, no TLS interception. Everything is keyed on
MAC address, so an IP change is an attribute and never an identity.

1. Rotating pcap chunks are parsed and bucketed into 300 second windows per device.
2. Each window yields twelve continuous features (packet and byte rates, packet sizes,
   inter-arrival times, destination breadth, connection rate) plus the set of
   destinations and services contacted.
3. After a learning period, each device gets a baseline: a mean vector and a shrunk
   covariance over a chosen subset of those features, with the destination and service
   sets frozen.
4. Later windows are scored as a squared Mahalanobis distance, combined with discrete
   rules for previously unseen destinations and services.
5. The score maps to a tier, normal through alert, throttle and block, applied as
   nftables set membership.

Destinations are identified by registrable domain where the resolver log allows it, and
by /24 prefix otherwise. This stops ordinary cloud endpoint rotation from reading as a
new destination.

Baselines are frozen once fitted, never updated during monitoring, so they stay
deterministic and cannot be poisoned gradually. Old baselines are retained so thresholds
can be retuned by re-scoring stored windows instead of recapturing traffic.

## What is in this repository

| Path | Contents |
| --- | --- |
| `core-engine/` | The Python engine: capture, feature extraction, learning and fit, scoring, tier decisions, nftables enforcement, and the CLI. |
| `node-firmware/` | Firmware for the instrumented nodes used as ground truth, in three profiles: plug and camera on ESP32, sensor on Pico 2W. Each emulates a device behaviour and can inject labelled anomalies on command. |
| `dashboard/` | Read only view over the database. Planned. |

## Ground truth

The nodes expose a control channel that the gateway polls. Keepalives and injected
anomalies are logged with millisecond timestamps, written before the first anomalous
packet leaves the device. Four anomaly types are supported, volume, cadence, destination
and protocol, each with a scalable magnitude so results can be reported as a detection
curve rather than a single pass or fail.

This is what makes detection latency and false positive rates measurable rather than
estimated.

## Status

Core engine complete and running. Node firmware written across all three profiles.
Evaluation against live nodes not yet run.
