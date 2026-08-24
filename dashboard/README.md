# SENTRI dashboard

A local, read only web view over the SENTRI database. It exists so the current state of
the system is legible at a glance: what capture and the engine are doing, where each
device sits against its own baseline, and why.

It is an operator's instrument, not part of the research method. Nothing here feeds the
evaluation, and nothing here can change the running system.

## Running it

```sh
cd core-engine && .venv/bin/python ../dashboard/serve.py
```

Then open <http://127.0.0.1:8842>.

Plain `python3` works too, as long as `pyyaml` is importable. It reads
`core-engine/config.yaml` for the database path and the enforcement mode.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--config` | `core-engine/config.yaml` | where to read paths and mode from |
| `--db` | from the config | override the database path, for looking at a copy |
| `--host` | `127.0.0.1` | loopback only, see below |
| `--port` | `8842` | |
| `--verbose` | off | log each request |

To read a snapshot instead of the live database:

```sh
python3 dashboard/serve.py --db /srv/sentri/sentri-before-peerfloor.db --port 8843
```

### Where it runs, and reaching it

It runs on the Pi itself, next to the engine, because that is where the database is. It
reads `/srv/sentri/sentri.db` directly from disk and there is no remote mode.

The default binds loopback, because the page exposes the entire capture history and has
no authentication whatsoever. `127.0.0.1` is the Pi talking to itself, so it is never
reachable from a laptop as it stands. Options, best first.

**Forward the port over the SSH session you already have.** If you are working on the Pi
through VS Code Remote SSH, this needs no binding change and exposes nothing: VS Code
tunnels the port down the existing connection. Open the **PORTS** panel next to the
terminal, *Forward a Port*, enter `8842`, then browse `http://localhost:8842` on the
laptop. VS Code often detects the listening port and offers this by itself.

The plain SSH equivalent, run from the laptop:

```sh
ssh -N -L 8842:127.0.0.1:8842 emiran@192.168.50.1
```

**Bind to the IoT subnet.** The laptop sits on `192.168.50.0/24` alongside the monitored
devices, so this works directly:

```sh
core-engine/.venv/bin/python dashboard/serve.py --host 192.168.50.1
```

Then `http://192.168.50.1:8842`. Two things to know before choosing it. The monitored
devices are on that subnet too, so the plug, the bulb and the nodes can all reach the
page. And it only stays out of the captures because the laptop's MAC is in
`exclude.macs`; that address is locally administered, so if the laptop ever rotates its
MAC the exclusion silently stops matching and dashboard traffic starts landing in the
windows. Check `ip neigh show dev eth1` against the exclude list if in doubt.

**Bind to the tailnet**, but only once the laptop has actually joined it:

```sh
core-engine/.venv/bin/python dashboard/serve.py --host 100.114.140.57
```

Then `http://lilapi.gannet-mooneye.ts.net:8842`, or `https://lilapi.gannet-mooneye.ts.net/`
if you prefer `tailscale serve --bg 8842`, which keeps the server on loopback and adds a
real certificate. `tailscale serve` persists across reboots; undo it with
`tailscale serve --https=443 off`.

Each `--host` **replaces** the loopback binding rather than adding to it, so whichever
address you pick becomes the only one that answers, on the Pi as well.

**Do not use `--host 0.0.0.0` on this box.** It works, but the Pi holds every one of
these addresses at once, so binding to all interfaces serves the entire capture history,
unauthenticated, to the LAN and to the IoT subnet together. Bind to one address
deliberately, never to all of them.

### As a service

Started by hand it lives only as long as the shell that started it. To have it come back
on boot alongside the engine:

```sh
sudo install -m 644 dashboard/sentri-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentri-dashboard
```

Edit `--host` in the unit first if you want it on the tailnet rather than loopback.

### Update frequency

The page polls `/api/state` every 15 seconds. That cadence is for the health signals,
which move between windows; the data itself cannot change faster than one window every
300 seconds.

The device panels and their charts are therefore redrawn only when
`max(window_start)` actually advances, or when the range changes. Otherwise fourteen
polls out of fifteen would rebuild every chart for identical data and throw away the
hover and any open table while doing it. Health, events and enforcement update on every
poll.

The header shows the last update to the second and counts down to the next one, so a
stalled poll loop is visible rather than inferred.

## What it will not do

- **It never writes.** The database is opened with `mode=ro`, so a bug here cannot
  corrupt a run. There are no POST routes and no buttons that act on the engine.
  Rebaseline, refit and unblock stay in `sentri.cli`, where they are deliberate.
- **It never touches nftables.** `enforce.list_active()` needs root; the enforcement
  panel is built from the `enforcement` table instead, so the dashboard runs
  unprivileged. That means it shows what the engine *recorded*, which is not the same
  as reading the live ruleset. `sentri.cli status` is still the authority on what
  nftables actually holds.
- **It adds no dependencies.** Standard library `http.server` and `sqlite3`, no
  framework, no CDN. The page works on a Pi with no internet.

## Reading the page

### Health

Seven tiles across the top. The three that matter most:

- **capture** is the age of the newest chunk measured *from its filename*, which is when
  tcpdump opened it. It climbs to 300 s and resets on each rotation; past about two
  rotations, capture has stopped, which is the failure that silently ends a run. The
  file's mtime is deliberately not used for this: tcpdump appends to the open chunk
  continuously, so the mtime always reads a second or two old whether or not rotation is
  still happening. It appears in the tile's second line instead, where a stalled write
  time means tcpdump is up but no packets are arriving.
- **engine** is how far the watermark is behind the chunks on disk. One behind is the
  steady state, because `capture.pending` holds a chunk back until its grace window
  expires.
- **keying** is described below, and is the one worth trusting least at face value.

### Distance charts

One chart per device, never a shared axis. Each device is scored against its own frozen
baseline with its own thresholds, so overlaying them on one scale would invite a
comparison that is not meaningful.

The y axis is `log1p`. Ordinary windows sit near zero while a reconnect or an injection
lands two orders of magnitude higher, and `t_critical` is ten times `t_alert`; a linear
axis puts every normal window on the floor.

The line breaks across missing windows rather than interpolating, because a gap means
capture stopped and the engine restarted observation on the far side of it.

Marks carry tier by **shape**, not colour: a ring is an alert, a diamond a throttle, a
triangle a block, a hollow square a window whose distance was not trusted. The four
status colours do not separate from one another under simulated colour vision
deficiency, so shape and the word are what actually carry the meaning.

Shaded bands are injected anomalies, taken from the node's own ground truth log.

### Severity is recomputed, and that is deliberate

The `tier` column on a score row is not one thing. `engine.monitor` writes the tier the
state machine reached, hysteresis and all. `cli refit` writes a stateless per window
severity, and it rewrites every row back to time zero.

Grouping that column therefore mixes two definitions and, because a refit rescores
history against a baseline that history predates, badly overstates the alert rate. On the
Tapo plug the naive count read 53 alert and 3 throttle windows where the honest count is
19 alert and none.

So this page does two separate things instead:

- **Severity** is recomputed per window from the distance against the thresholds of the
  baseline that actually scored it, and every count is scoped to windows at or after the
  active baseline was fitted. Throttle never appears here, because throttle is a state
  machine outcome and not a property of a single window.
- **Tier changes** and **enforcement episodes** are counted separately, from the `events`
  and `enforcement` tables. That is the question of what the system actually did.

These two numbers are supposed to differ. The gap between them is the hysteresis doing
its job.

### Destination keying

`extract.DnsLog` holds the address to domain map in memory and seeds it from the current
`pihole.log` plus one rotation. A device that resolves less often than the log rotates
can therefore lose its attribution across an engine restart, and its destinations
silently key as `p:<prefix>` instead of `d:<domain>`. Nothing in the engine warns about
this, and a prefix that is novel against a domain keyed baseline can drive a tier change
on a destination the device has contacted all along.

The keying panel flags exactly that case: a new `p:` key whose addresses were *already*
in the baseline's address set. A genuinely new destination does not match that pattern.

If it fires, power cycling the device makes it re-resolve, which puts the answer back in
the current log.

## Checking it

No JavaScript engine or browser is installed on the Pi, so the front end is verified
statically:

```sh
python3 dashboard/tools/check_static.py
```

That checks HTML nesting, ids the script reaches for, classes used against classes
styled, and bracket balance. It cannot tell you the page looks right.

`tools/validate_palette.py` is a Python port of the palette validator used to choose the
marks. It reproduces the reference figures exactly, and it is what established that the
status colours need shape as well as hue:

```sh
python3 dashboard/tools/validate_palette.py "#2a78d6,#0ca30c,#fab219,#ec835a,#d03b3b" light
```

## Endpoints

| Route | Returns |
| --- | --- |
| `/api/state` | health, every device with its baseline and counts, events, enforcement |
| `/api/series?mac=&hours=` | per window distance, features and novelty, plus injection spans |
| `/api/device?mac=&limit=` | recent windows, every baseline ever fitted, events, ground truth |
| `/api/log?lines=` | tail of `engine.log` |
