"use strict";

/* SENTRI local dashboard. Read only: every number here comes from the database the
   engine writes, and nothing on this page can change the running system. */

// a window closes every 300 s, so nothing in the data can change faster than that. this
// cadence is for the health signals, which move between windows
const POLL_MS = 15000;
const SVG_NS = "http://www.w3.org/2000/svg";

/* A status is never colour alone. Each tier carries a glyph and a word here, and a
   distinct mark shape on the charts, because the four status hues do not clear the
   colour separation gates against one another. */
const TIER = {
  normal:    { cls: "st-good",     glyph: "●", word: "normal" },
  alert:     { cls: "st-warning",  glyph: "▲", word: "alert" },
  throttle:  { cls: "st-serious",  glyph: "◆", word: "throttle" },
  block:     { cls: "st-critical", glyph: "■", word: "block" },
  unusable:  { cls: "st-idle",     glyph: "○", word: "unusable" },
  unscored:  { cls: "st-idle",     glyph: "○", word: "unscored" },
  learning:  { cls: "st-idle",     glyph: "◐", word: "learning" },
  monitoring:{ cls: "st-good",     glyph: "●", word: "monitoring" },
};

/* localStorage is a convenience here and never load bearing. It throws outright in a
   few configurations (blocked site data, private windows, a full quota), and an
   uncaught throw out of a click handler would leave the button dead with nothing on
   screen to say why. Every read and write goes through here. */
const store = {
  get(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw === null ? fallback : raw;
    } catch (err) {
      return fallback;
    }
  },
  set(key, value) {
    try { localStorage.setItem(key, value); } catch (err) { /* preference not kept */ }
  },
};

const state = {
  hours: Number(store.get("sentri.hours", "")) || 12,
  paused: false,
  series: new Map(),
  open: new Set((() => {
    try { return JSON.parse(store.get("sentri.open", "[]")); } catch (err) { return []; }
  })()),
  timer: null,
  countdown: null,
  nextAt: 0,
  lastWindow: null,
  seriesHours: null,
};

/* ---------- small helpers ---------- */

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of [].concat(children || [])) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

function svg(tag, attrs, children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of [].concat(children || [])) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

const pad = (n) => String(n).padStart(2, "0");

function clock(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return pad(d.getHours()) + ":" + pad(d.getMinutes());
}

/* the header needs seconds. with a 15 s poll and minute resolution the timestamp sits
   unchanged for four polls in a row, which reads exactly like a page that has stopped */
function clockSec(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return clock(ts) + ":" + pad(d.getSeconds());
}

function stamp(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return pad(d.getDate()) + "/" + pad(d.getMonth() + 1) + " " + clock(ts);
}

/* durations read as an operator would say them, and never as "0 seconds ago" */
function ago(seconds) {
  if (seconds === null || seconds === undefined) return "-";
  const s = Math.max(0, Math.round(seconds));
  if (s < 90) return s + "s";
  const m = Math.round(s / 60);
  if (m < 90) return m + "m";
  const h = s / 3600;
  if (h < 48) return h.toFixed(h < 10 ? 1 : 0) + "h";
  return (h / 24).toFixed(1) + "d";
}

function num(v, digits) {
  if (v === null || v === undefined || Number.isNaN(v)) return "-";
  const d = digits === undefined ? (Math.abs(v) >= 100 ? 0 : Math.abs(v) >= 10 ? 1 : 2) : digits;
  return Number(v).toFixed(d);
}

function bytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return n.toFixed(i ? 1 : 0) + " " + units[i];
}

const macTail = (mac) => (mac || "").slice(-8);

function status(kind, word) {
  const t = TIER[kind] || TIER.unscored;
  return el("span", { class: "status " + t.cls }, [
    el("span", { class: "glyph", "aria-hidden": "true", text: t.glyph }),
    el("span", { text: word === undefined ? t.word : word }),
  ]);
}

/* ---------- tooltip ---------- */

const tip = {
  node: null,
  show(x, y, nodes) {
    if (!this.node) this.node = $("#tooltip");
    this.node.replaceChildren(...nodes);
    this.node.hidden = false;
    const box = this.node.getBoundingClientRect();
    const left = Math.min(Math.max(8, x + 14), window.innerWidth - box.width - 8);
    const top = Math.min(Math.max(8, y - box.height - 14), window.innerHeight - box.height - 8);
    this.node.style.left = left + "px";
    this.node.style.top = top + "px";
  },
  hide() { if (this.node) this.node.hidden = true; },
};

const tipRow = (k, v) => el("div", { class: "r" }, [el("span", { text: k }), el("b", { text: v })]);

/* ---------- the distance chart ---------- */

/* d2 spans two regimes: ordinary windows sit near zero while an injection or a cloud
   reconnect lands two orders of magnitude higher, and the critical threshold is ten
   times the alert one. A linear axis would flatten every normal window onto the floor,
   so the axis is log1p and the thresholds are drawn as labelled rules. */
const scaleOf = (max) => {
  const top = Math.log1p(Math.max(max, 1));
  return (v) => (top ? Math.log1p(Math.max(0, v || 0)) / top : 0);
};

/* shape carries the tier, not colour: the four status hues do not separate from one
   another under simulated colour vision deficiency, so an alert ring must still be
   distinguishable from a block triangle with the hue removed. every shape is set by
   class, never by presentation attribute, because a CSS rule outranks the attribute */
function markShape(severity, x, y) {
  if (severity === "alert") return svg("circle", { class: "mark ring", cx: x, cy: y, r: 3.6 });
  if (severity === "throttle") {
    return svg("path", { class: "mark diamond",
      d: `M${x} ${y - 4.6}L${x + 4.6} ${y}L${x} ${y + 4.6}L${x - 4.6} ${y}Z` });
  }
  if (severity === "block") {
    return svg("path", { class: "mark tri",
      d: `M${x} ${y - 5}L${x + 4.7} ${y + 4}L${x - 4.7} ${y + 4}Z` });
  }
  if (severity === "unusable") {
    return svg("rect", { class: "mark miss", x: x - 3, y: y - 3, width: 6, height: 6 });
  }
  return null;
}

function distanceChart(points, bands, injections, hours) {
  const W = 1000, H = 190, L = 40, R = 12, T = 12, B = 22;
  const iw = W - L - R, ih = H - T - B;
  const now = Date.now() / 1000;
  const t0 = now - hours * 3600, t1 = now;
  const scored = points.filter((p) => p.d2 !== null && p.d2 !== undefined);
  /* a refit rescores history, so a range can hold points from more than one baseline.
     the rules drawn are the current one's, taken from the most recent scored window */
  const last = scored.length ? scored[scored.length - 1] : null;
  const band = (last && bands[last.baseline_id]) || Object.values(bands)[0] || {};
  const tAlert = band.t_alert || 0, tCrit = band.t_critical || 0;
  const maxD2 = Math.max(1, tAlert * 1.25, ...scored.map((p) => p.d2));
  const y = scaleOf(maxD2);
  const px = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * iw;
  const py = (v) => T + ih - y(v) * ih;

  const root = svg("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": `distance per window over the last ${hours} hours` });

  /* injected anomalies first, so they read as background rather than data */
  for (const span of injections || []) {
    const a = px(Math.max(t0, span.start));
    const b = px(Math.min(t1, span.end || t1));
    if (b > a) root.append(svg("rect", { class: "inj", x: a, y: T, width: Math.max(2, b - a), height: ih }));
  }

  /* y grid at decades that actually fall inside the range */
  for (const v of [0, 1, 10, 100, 1000]) {
    if (v > maxD2 * 1.05) continue;
    const yy = py(v);
    root.append(svg("line", { class: "grid", x1: L, x2: W - R, y1: yy, y2: yy }));
    root.append(svg("text", { x: L - 6, y: yy + 3, "text-anchor": "end", text: String(v) }));
  }

  /* x ticks, roughly one per sixth of the range */
  const step = (t1 - t0) / 6;
  for (let i = 0; i <= 6; i += 1) {
    const t = t0 + i * step;
    root.append(svg("text", { x: px(t), y: H - 6, "text-anchor": i === 0 ? "start" : i === 6 ? "end" : "middle",
      text: hours > 48 ? stamp(t) : clock(t) }));
  }

  /* the line breaks wherever windows are missing: capture stops, and the engine
     restarts observation on the far side of the gap. a continuous line would invent
     data across it */
  const segs = [];
  let cur = [];
  let prevT = null;
  for (const p of scored) {
    if (prevT !== null && p.t - prevT > 450) { if (cur.length) segs.push(cur); cur = []; }
    cur.push(p);
    prevT = p.t;
  }
  if (cur.length) segs.push(cur);

  for (const seg of segs) {
    const d = seg.map((p, i) => (i ? "L" : "M") + px(p.t) + " " + py(p.d2)).join("");
    if (seg.length === 1) {
      root.append(svg("circle", { cx: px(seg[0].t), cy: py(seg[0].d2), r: 2, fill: "var(--series)" }));
    } else {
      const base = T + ih;
      root.append(svg("path", { class: "area",
        d: d + `L${px(seg[seg.length - 1].t)} ${base}L${px(seg[0].t)} ${base}Z` }));
      root.append(svg("path", { class: "line", d }));
    }
  }

  /* thresholds on top of the series, so a spike never hides the rule it crossed */
  for (const [v, cls, label] of [[tAlert, "thr", "alert " + num(tAlert, 1)],
                                 [tCrit, "thr crit", "block " + num(tCrit, 0)]]) {
    if (!v || v > maxD2 * 1.05) continue;
    root.append(svg("line", { class: cls, x1: L, x2: W - R, y1: py(v), y2: py(v) }));
    root.append(svg("text", { x: W - R, y: py(v) - 4, "text-anchor": "end", text: label }));
  }

  for (const p of scored) {
    const shape = markShape(p.severity, px(p.t), py(p.d2));
    if (shape) root.append(shape);
  }

  /* hover layer: one crosshair, nearest point by x */
  const cross = svg("line", { class: "cross", y1: T, y2: T + ih, x1: -10, x2: -10, opacity: 0 });
  root.append(cross);
  const hit = svg("rect", { class: "hit", x: L, y: T, width: iw, height: ih });
  root.append(hit);
  const move = (ev) => {
    if (!scored.length) return;
    const box = root.getBoundingClientRect();
    const t = t0 + ((ev.clientX - box.left) / box.width * W - L) / iw * (t1 - t0);
    let best = scored[0];
    for (const p of scored) if (Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
    cross.setAttribute("x1", px(best.t));
    cross.setAttribute("x2", px(best.t));
    cross.setAttribute("opacity", 1);
    const rows = [
      el("div", { class: "h", text: stamp(best.t) + " → " + clock(best.t + 300) }),
      tipRow("distance", num(best.d2)),
      tipRow("severity", (TIER[best.severity] || TIER.unscored).word),
      tipRow("recorded tier", best.recorded || "-"),
      tipRow("packets", best.packets),
    ];
    if (!best.complete) rows.push(tipRow("window", num(best.duration_s, 0) + "s, truncated"));
    if (best.new_dests && best.new_dests.length) {
      rows.push(tipRow("new", best.new_dests.map((k) => k.slice(2)).join(", ")));
    }
    const f = best.features || {};
    if (f.bytes_out_rate !== undefined) {
      rows.push(tipRow("out / in", num(f.bytes_out_rate, 1) + " / " + num(f.bytes_in_rate, 1) + " B/s"));
      rows.push(tipRow("peers", num(f.distinct_peers, 0)));
    }
    tip.show(ev.clientX, ev.clientY, rows);
  };
  hit.addEventListener("mousemove", move);
  hit.addEventListener("mouseleave", () => { cross.setAttribute("opacity", 0); tip.hide(); });
  return root;
}

/* a compact linear sparkline, used for the raw features behind the distance */
function sparkline(points, key, label) {
  const W = 320, H = 54, T = 6, B = 12, L = 2, R = 2;
  const ih = H - T - B, iw = W - L - R;
  const vals = points.map((p) => (p.features || {})[key]).filter((v) => v !== undefined);
  if (!vals.length) return el("div", { class: "muted", text: label + ": no data" });
  const lo = Math.min(...vals), hi = Math.max(...vals);
  const span = hi - lo || 1;
  const t0 = points[0].t, t1 = points[points.length - 1].t;
  const px = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * iw;
  const py = (v) => T + ih - ((v - lo) / span) * ih;
  const usable = points.filter((p) => (p.features || {})[key] !== undefined);
  const d = usable.map((p, i) => (i ? "L" : "M") + px(p.t) + " " + py(p.features[key])).join("");
  const root = svg("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": `${label}, ${num(lo)} to ${num(hi)}` }, [
    svg("path", { class: "line", d, "stroke-width": 1.5 }),
    svg("text", { x: L, y: H - 2, text: label + "  " + num(lo) + " to " + num(hi) }),
  ]);
  return root;
}

/* ---------- health tiles ---------- */

function tile(k, value, sub, statusNode) {
  return el("div", { class: "tile" }, [
    el("div", { class: "k", text: k }),
    el("div", { class: "v num", text: value }),
    sub ? el("div", { class: "s", text: sub }) : null,
    statusNode || null,
  ]);
}

function renderHealth(sys, devices) {
  const host = $("#health");
  const cap = sys.capture, wm = sys.watermark, pipe = sys.pipeline;

  /* measured from the chunk's name, which is when tcpdump opened it. the file's mtime is
     useless as a liveness signal because tcpdump appends to the open chunk continuously,
     so it always reads one or two seconds old whether or not rotation is still running.
     rotation every 300 s means this climbs to 300 and resets; past about two rotations
     capture has stopped, which is the failure that silently ends a run */
  const capAge = cap.rotation_age_s;
  const capState = capAge === null ? "unscored" : capAge > 660 ? "block" : capAge > 380 ? "alert" : "normal";
  const capWord = capAge === null ? "no chunks" : capState === "normal" ? "rotating" :
    capState === "alert" ? "rotation late" : "stopped";
  /* a live rotation with nothing being written is a different fault: tcpdump is up but
     no packets are reaching the interface */
  const quiet = cap.write_age_s !== null && cap.write_age_s > 120;

  /* the engine consumes a chunk only after the grace window, so one behind is normal */
  const backlog = wm.backlog || 0;
  const engState = wm.age_s === null ? "unscored" : backlog > 4 ? "block" : backlog > 2 ? "alert" : "normal";
  const engWord = wm.age_s === null ? "no watermark" : backlog > 2 ? backlog + " chunks behind" : "keeping up";

  const lag = pipe.lag_s;
  const lagState = lag === null ? "unscored" : lag > 1500 ? "block" : lag > 900 ? "alert" : "normal";

  const learning = devices.filter((d) => d.state === "learning").length;
  const monitoring = devices.filter((d) => d.state === "monitoring").length;
  const worst = devices.reduce((acc, d) => {
    const order = ["normal", "alert", "throttle", "block"];
    return order.indexOf(d.tier) > order.indexOf(acc) ? d.tier : acc;
  }, "normal");
  const enforced = devices.filter((d) => d.enforcement).length;
  const drift = devices.filter((d) => d.keying && d.keying.drifted.length).length;

  host.replaceChildren(
    tile("capture", ago(capAge),
         cap.latest ? `${bytes(cap.current_bytes)} written, last ${ago(cap.write_age_s)} ago`
                    : cap.dir,
         status(quiet && capState === "normal" ? "alert" : capState,
                quiet && capState === "normal" ? "rotating, no packets" : capWord)),
    tile("engine", wm.chunk ? ago(wm.age_s) : "-", wm.chunk || "watermark missing",
         status(engState, engWord)),
    tile("newest window", stamp(pipe.last_window_start),
         "lag " + ago(lag), status(lagState, lagState === "normal" ? "current" : "behind")),
    tile("devices", String(devices.length),
         monitoring + " monitoring, " + learning + " learning",
         status(learning ? "learning" : "normal", learning ? "baselines pending" : "all baselined")),
    tile("worst tier now", (TIER[worst] || TIER.normal).word,
         enforced ? enforced + " under enforcement" : "nothing enforced",
         status(worst)),
    tile("keying", drift ? String(drift) : "clean",
         drift ? "devices keying to prefixes" : "domains attributed",
         status(drift ? "alert" : "normal", drift ? "check DNS" : "as baselined")),
    tile("database", bytes(sys.db_bytes),
         sys.counts.windows.toLocaleString() + " windows, " +
         sys.counts.scores.toLocaleString() + " scores"),
  );

  $("#run-label").textContent = sys.run_label;
  const chip = $("#mode-chip");
  chip.textContent = sys.enforcement_mode;
  chip.classList.toggle("enforce", sys.enforcement_mode === "enforce");
  chip.title = sys.enforcement_mode === "enforce"
    ? "tier changes are applied to nftables"
    : "observe only, no nftables changes are made";
}

/* ---------- device card ---------- */

function meter(latest, base) {
  const ratio = latest && latest.ratio !== null && latest.ratio !== undefined ? latest.ratio : null;
  const pct = ratio === null ? 0 : Math.min(100, ratio * 100);
  const cls = ratio === null ? "" : ratio >= 10 ? "crit" : ratio >= 1 ? "over" : "";
  return el("div", {}, [
    el("div", { class: "meter-row" }, [
      el("span", { class: "muted", text: "distance vs alert threshold" }),
      el("span", { class: "num", text: latest ? num(latest.d2) + " / " + num(base.t_alert, 1) : "-" }),
    ]),
    el("div", { class: "meter" }, [el("i", { class: cls, style: `width:${pct}%` })]),
    el("div", { class: "muted", style: "margin-top:4px",
      text: ratio === null ? "not scored yet" : num(ratio * 100, 0) + "% of the alert threshold" }),
  ]);
}

function contributions(latest) {
  if (!latest || !latest.contributions.length) return null;
  const top = Math.max(...latest.contributions.map((c) => Math.abs(c.value))) || 1;
  return el("div", {}, [
    el("div", { class: "muted", style: "margin-bottom:6px",
      text: "what the distance is made of" }),
    el("div", { class: "bars" }, latest.contributions.map((c) => el("div", { class: "bar-row" }, [
      el("span", { class: "t", text: c.feature, title: c.feature }),
      el("span", { class: "track" }, [
        el("span", { class: "fill", style: `width:${Math.abs(c.value) / top * 100}%` }),
      ]),
      el("span", { class: "n num", text: num(c.share * 100, 0) + "%" }),
    ]))),
  ]);
}

function zscoreRow(latest) {
  if (!latest || !latest.zscores) return null;
  const entries = Object.entries(latest.zscores);
  if (!entries.length) return null;
  return el("div", {}, [
    el("div", { class: "muted", style: "margin-bottom:6px", text: "z scores, latest window" }),
    el("div", {}, entries.map(([k, v]) => el("span", {
      class: "tag", title: k + " " + num(v, 2),
      text: k.replace(/_rate$/, "").replace(/_/g, " ") + " " + (v >= 0 ? "+" : "") + num(v, 1),
    }))),
  ]);
}

function keyingPanel(keying) {
  if (!keying) return null;
  const kids = [];
  if (keying.drifted.length) {
    kids.push(el("div", { class: "warn-box" }, [
      el("b", { text: "destination keying has slipped to prefixes" }),
      el("div", { text: "These prefixes are novel against the baseline, but every address "
        + "inside them was already known. That is the DNS attribution dropping out, not a "
        + "new destination, and it can drive a tier change on its own." }),
      el("div", { style: "margin-top:6px" }, keying.drifted.map((d) => el("span", {
        class: "tag new", title: d.addrs.join(", ") + " in " + d.windows + " windows",
        text: d.key.slice(2) + " ×" + d.windows,
      }))),
    ]));
  }
  kids.push(el("div", {}, [
    el("div", { class: "muted", style: "margin-bottom:4px",
      text: `destinations seen in the last ${keying.lookback_windows} windows` }),
    el("div", {}, [
      ...keying.recent_domains.map((k) => el("span", { class: "tag dom", text: k.slice(2) })),
      ...keying.recent_prefixes.map((k) => el("span", { class: "tag pre", text: k.slice(2) })),
      !keying.recent_domains.length && !keying.recent_prefixes.length
        ? el("span", { class: "muted", text: "no external traffic" }) : null,
    ]),
  ]));
  return el("div", {}, kids);
}

function learningPanel(dev) {
  const l = dev.learning;
  if (!l) return null;
  if (l.unavailable) return el("div", { class: "muted", text: l.unavailable });
  const gate = (ok, label) => el("div", { class: "gate-row" }, [
    el("span", { text: label }),
    status(ok ? "normal" : "learning", ok ? "met" : "pending"),
  ]);
  return el("div", {}, [
    el("div", { class: "muted", style: "margin-bottom:6px", text: "learning gates" }),
    el("div", { class: "bars" }, [
      gate(l.windows, `windows ${l.usable_windows}/${l.min_windows}`),
      gate(l.duration, `hours ${num(l.hours_elapsed, 1)}/${l.learning_hours}`),
      gate(l.stability, "destination set settled"),
    ]),
    el("div", { class: "muted", style: "margin-top:6px", text: l.detail }),
    el("div", { class: "muted", text: `hard stop at ${l.hard_stop_hours} h forces a fit` }),
  ]);
}

function severityPanel(dev) {
  const c = dev.since_fit, e = dev.episodes;
  const total = c.total || 1;
  const rows = [
    ["normal", c.normal], ["alert", c.alert], ["block", c.block],
    ["unusable", c.unusable],
  ].filter(([, n]) => n);
  return el("div", {}, [
    el("div", { class: "muted", style: "margin-bottom:6px",
      text: `${c.total} windows since this baseline was fitted` }),
    el("div", { class: "bars" }, rows.map(([k, n]) => el("div", { class: "bar-row" }, [
      status(k),
      el("span", { class: "track" }, [
        el("span", { class: "fill", style: `width:${n / total * 100}%` }),
      ]),
      el("span", { class: "n num", text: String(n) }),
    ]))),
    el("dl", { class: "kv", style: "margin-top:8px" }, [
      el("dt", { text: "windows with novelty" }),
      el("dd", { class: "num", text: `${c.novel} (${c.hard_novel} hard)` }),
      el("dt", { text: "tier changes" }),
      el("dd", { class: "num", text: String(e.tier_changes) }),
      el("dt", { text: "enforcement episodes" }),
      el("dd", { class: "num", text: String(e.enforced) }),
    ]),
    el("div", { class: "muted", style: "margin-top:6px",
      text: "Severity is recomputed per window from the distance and that baseline's "
        + "thresholds. It is not the stored tier, which mixes the state machine's "
        + "hysteresis with the stateless severity a refit writes." }),
  ]);
}

function baselinePanel(base) {
  if (!base) return el("div", { class: "muted", text: "no baseline fitted" });
  const age = (Date.now() / 1000 - base.created_at) / 3600;
  return el("dl", { class: "kv" }, [
    el("dt", { text: "baseline" }), el("dd", { class: "num", text: "#" + base.id }),
    el("dt", { text: "fitted" }), el("dd", { text: stamp(base.created_at) + " (" + ago(age * 3600) + " ago)" }),
    el("dt", { text: "windows" }), el("dd", { class: "num", text: `${base.n_fit} fit + ${base.n_calib} calib` }),
    el("dt", { text: "features" }), el("dd", { class: "num", text: String(base.names.length) }),
    el("dt", { text: "rule" }), el("dd", { text: base.rule + (base.forced ? ", hard stop" : "") }),
    el("dt", { text: "alert / block" }),
    el("dd", { class: "num", text: num(base.t_alert, 1) + " / " + num(base.t_critical, 0) }),
    el("dt", { text: "median fit d2", title: "a well conditioned fit lands near the feature count" }),
    el("dd", { class: "num", text: num(base.median_fit_d2) }),
    el("dt", { text: "known destinations" }),
    el("dd", { class: "num", text: `${base.dest_domains.length} domains, ${base.dest_prefixes.length} prefixes` }),
    el("dt", { text: "known services" }), el("dd", { class: "num", text: String(base.services.length) }),
  ]);
}

function windowsTable(windows) {
  const head = ["window", "d2", "severity", "pkts", "out B/s", "in B/s", "peers", "new"];
  return el("div", { class: "scroll-x" }, [
    el("table", { class: "tbl" }, [
      el("thead", {}, [el("tr", {}, head.map((h) => el("th", { text: h })))]),
      el("tbody", {}, windows.map((w) => el("tr", {}, [
        el("td", { class: "num", text: stamp(w.window_start) + (w.complete ? "" : " ⚠") }),
        el("td", { class: "num", text: num(w.d2) }),
        el("td", {}, [status(w.severity)]),
        el("td", { class: "num", text: String(w.packets) }),
        el("td", { class: "num", text: num((w.features || {}).bytes_out_rate, 1) }),
        el("td", { class: "num", text: num((w.features || {}).bytes_in_rate, 1) }),
        el("td", { class: "num", text: num((w.features || {}).distinct_peers, 0) }),
        el("td", { text: (w.new_dests || []).map((k) => k.slice(2)).join(", ") || "-" }),
      ]))),
    ]),
  ]);
}

function feedRows(items, kind) {
  if (!items.length) return [el("div", { class: "empty", text: "nothing recorded" })];
  return items.map((it) => {
    if (kind === "event") {
      return el("div", { class: "row" }, [
        el("span", { class: "when num", text: stamp(it.ts) }),
        el("span", { class: "what" }, [
          el("div", {}, [
            status(it.tier, it.kind.replace(/_/g, " ")),
            el("span", { class: "muted", text: "  " + macTail(it.mac) }),
          ]),
          el("div", { class: "sum", text: it.summary || "" }),
        ]),
      ]);
    }
    const live = !it.removed_at;
    return el("div", { class: "row" }, [
      el("span", { class: "when num", text: stamp(it.applied_at) }),
      el("span", { class: "what" }, [
        el("div", {}, [
          status(it.tier),
          el("span", { class: "muted", text: "  " + macTail(it.mac) + "  " +
            (live ? "active" : "cleared after " + ago(it.removed_at - it.applied_at)) }),
        ]),
        el("div", { class: "sum", text: it.reason || "" }),
      ]),
    ]);
  });
}

function deviceCard(dev, series) {
  const base = dev.baseline;
  const attn = dev.tier === "alert" || dev.tier === "throttle";
  const crit = dev.tier === "block" || Boolean(dev.enforcement);
  const t = TIER[dev.tier] || TIER.normal;

  const head = el("div", { class: "card-head" }, [
    el("div", {}, [
      el("div", { class: "name mono", text: dev.mac }),
      el("div", { class: "sub", text: [dev.ip, dev.node ? "node " + dev.node : null,
        dev.excluded ? "excluded" : null, dev.never_enforce ? "never enforced" : null]
        .filter(Boolean).join("  ·  ") }),
    ]),
    el("span", { class: "spacer" }),
    dev.enforcement ? el("span", { class: "chip enforce", text: "enforced " + dev.enforcement.tier }) : null,
    el("span", { class: "chip", text: dev.state }),
    el("span", { class: "tier-badge " + t.cls }, [
      el("span", { class: "glyph", "aria-hidden": "true", text: t.glyph }),
      el("span", { text: t.word }),
    ]),
    el("span", { class: "muted num", title: "signed streak: positive counts anomalous windows, negative counts normal ones",
      text: (dev.consecutive_count > 0 ? "+" : "") + dev.consecutive_count }),
  ]);

  const chartCell = el("div", { class: "chart-cell" });
  if (!series) {
    chartCell.append(el("div", { class: "muted", text: "loading windows" }));
  } else if (!series.points.length) {
    chartCell.append(el("div", { class: "muted", text: "no windows in this range" }));
  } else {
    chartCell.append(distanceChart(series.points, series.baselines, series.injections, series.hours));
    const scored = series.points.filter((p) => p.d2 !== null && p.d2 !== undefined);
    const worst = scored.reduce((a, p) => (p.d2 > (a ? a.d2 : -1) ? p : a), null);
    chartCell.append(el("div", { class: "muted", style: "margin-top:6px",
      text: `last ${series.hours}h: ${series.points.length} windows, ${scored.length} scored`
        + (worst ? `, peak ${num(worst.d2)} at ${stamp(worst.t)}` : "")
        + (series.injections.length ? `, ${series.injections.length} injection spans shaded` : "") }));
  }

  const side = el("div", { class: "side-cell" }, [
    base ? meter(dev.latest, base) : null,
    dev.state === "learning" ? learningPanel(dev) : null,
    contributions(dev.latest),
    dev.latest ? el("div", { class: "muted",
      text: "latest window " + stamp(dev.latest.window_start) + ", " + dev.latest.packets + " packets"
        + (dev.latest.complete ? "" : ", truncated") }) : null,
  ].filter(Boolean));

  const detail = el("details", { open: state.open.has(dev.mac), ontoggle: (ev) => {
    if (ev.target.open) state.open.add(dev.mac); else state.open.delete(dev.mac);
    store.set("sentri.open", JSON.stringify([...state.open]));
  } }, [
    el("summary", { text: "baseline, destinations and recent windows" }),
    el("div", { class: "inner" }, [
      el("div", { class: "split" }, [
        el("div", {}, [baselinePanel(base), zscoreRow(dev.latest)]),
        el("div", {}, [severityPanel(dev)]),
      ]),
      keyingPanel(dev.keying),
      base ? el("div", {}, [
        el("div", { class: "muted", style: "margin-bottom:4px", text: "baseline destination and service sets" }),
        el("div", {}, [
          ...base.dest_domains.map((k) => el("span", { class: "tag dom", text: k.slice(2) })),
          ...base.dest_prefixes.map((k) => el("span", { class: "tag pre", text: k.slice(2) })),
          ...base.services.map((s) => el("span", { class: "tag", text: s })),
        ]),
      ]) : null,
      series && series.points.length && base ? el("div", {}, [
        el("div", { class: "muted", style: "margin-bottom:4px", text: "model features over the range" }),
        el("div", { class: "tiles" }, base.names.map((n) => el("div", { class: "tile" },
          [sparkline(series.points, n, n.replace(/_/g, " "))]))),
      ]) : null,
      el("div", { class: "device-windows", "data-mac": dev.mac }, [
        el("div", { class: "muted", text: "recent windows load when this section is opened" }),
      ]),
    ].filter(Boolean)),
  ]);

  return el("div", { class: "card" + (crit ? " crit" : attn ? " attn" : ""), "data-mac": dev.mac }, [
    head,
    el("div", { class: "card-body" }, [chartCell, side]),
    detail,
  ]);
}

/* ---------- data flow ---------- */

async function get(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(path + " returned " + res.status);
  return res.json();
}

function banner(message) {
  const node = $("#banner");
  node.hidden = !message;
  node.textContent = message || "";
}

async function loadSeries(devices) {
  await Promise.all(devices.map(async (d) => {
    try {
      state.series.set(d.mac, await get(
        `/api/series?mac=${encodeURIComponent(d.mac)}&hours=${state.hours}`));
    } catch (err) {
      state.series.delete(d.mac);
    }
  }));
}

async function loadWindows(mac, host) {
  try {
    const data = await get(`/api/device?mac=${encodeURIComponent(mac)}&limit=30`);
    host.replaceChildren(
      el("div", { class: "muted", style: "margin-bottom:4px", text: "last 30 windows" }),
      windowsTable(data.windows));
  } catch (err) {
    host.replaceChildren(el("div", { class: "muted", text: "could not load windows" }));
  }
}

function renderMarkLegend() {
  const items = [
    ["line", "distance per window"],
    ["alert", "over the alert threshold"],
    ["block", "over the block threshold"],
    ["unusable", "empty or truncated window, distance ignored"],
    ["inj", "injected anomaly, from the node's own log"],
  ];
  const swatch = (kind) => {
    const s = svg("svg", { width: 16, height: 16, viewBox: "0 0 16 16", "aria-hidden": "true" });
    if (kind === "line") s.append(svg("path", { class: "line", d: "M1 11L6 6L10 9L15 4" }));
    else if (kind === "inj") s.append(svg("rect", { class: "inj", x: 1, y: 2, width: 14, height: 12 }));
    else s.append(markShape(kind, 8, 8));
    return s;
  };
  $("#mark-legend").replaceChildren(...items.map(([kind, label]) =>
    el("span", { class: "item" }, [swatch(kind), el("span", { text: label })])));
}

function renderDevices(devices) {
  const host = $("#devices");
  host.replaceChildren(...devices.map((d) => deviceCard(d, state.series.get(d.mac))));
  for (const box of host.querySelectorAll(".device-windows")) {
    const detail = box.closest("details");
    const mac = box.dataset.mac;
    if (detail.open) loadWindows(mac, box);
    else detail.addEventListener("toggle", function once() {
      if (detail.open) { loadWindows(mac, box); detail.removeEventListener("toggle", once); }
    });
  }
}

async function refresh() {
  try {
    const data = await get("/api/state?events=60");
    banner("");
    renderHealth(data.system, data.devices);
    /* the device panels are redrawn only when there is something new to draw. a window
       closes every 300 s, so at a 15 s poll fourteen refreshes out of fifteen would
       otherwise rebuild every chart for identical data, throwing away the hover and any
       open table in the process. health, events and enforcement still update every poll */
    const latest = data.system.pipeline.last_window_start;
    const fresh = latest !== state.lastWindow || state.seriesHours !== state.hours;
    if (fresh) {
      await loadSeries(data.devices);
      renderDevices(data.devices);
      state.lastWindow = latest;
      state.seriesHours = state.hours;
    }
    $("#events").replaceChildren(...feedRows(data.events, "event"));
    $("#enforcement").replaceChildren(...feedRows(data.enforcement, "enf"));
    $("#updated").textContent = "updated " + clockSec(data.system.now);
    state.nextAt = Date.now() + POLL_MS;
    const pulse = $("#pulse");
    pulse.classList.remove("beat", "stale", "dead");
    void pulse.offsetWidth;
    pulse.classList.add("beat");
  } catch (err) {
    banner("Cannot reach the dashboard API: " + err.message
      + ". The engine writes the database independently, so this is a dashboard problem, "
      + "not necessarily an engine one.");
    $("#pulse").classList.add("dead");
  }
}

async function refreshLog() {
  try {
    const data = await get("/api/log?lines=160");
    const node = $("#log");
    node.replaceChildren(...data.lines.map((line) => el("div", {
      class: /ERROR|Traceback/.test(line) ? "l-err" : /WARNING/.test(line) ? "l-warn" : "",
      text: line,
    })));
    node.scrollTop = node.scrollHeight;
  } catch (err) {
    $("#log").textContent = "log unavailable";
  }
}

function setRange(hours) {
  state.hours = hours;
  store.set("sentri.hours", String(hours));
  for (const b of document.querySelectorAll(".range")) {
    b.setAttribute("aria-pressed", String(Number(b.dataset.hours) === hours));
  }
  refresh();
}

function schedule() {
  clearInterval(state.timer);
  if (!state.paused) {
    state.nextAt = Date.now() + POLL_MS;
    state.timer = setInterval(refresh, POLL_MS);
  }
  tickCountdown();
}

/* a visible countdown, on its own one second timer. without it there is no way to tell a
   page whose numbers happen to be steady from a page whose poll loop has died */
function tickCountdown() {
  clearInterval(state.countdown);
  const node = $("#countdown");
  const paint = () => {
    if (state.paused) { node.textContent = "auto refresh off"; return; }
    const left = Math.max(0, Math.ceil((state.nextAt - Date.now()) / 1000));
    node.textContent = `every ${POLL_MS / 1000}s · next in ${left}s`;
  };
  paint();
  state.countdown = setInterval(paint, 1000);
}

/* nothing on this page is worth a silent failure. an uncaught throw anywhere, including
   out of a click handler, surfaces in the banner rather than only in the console */
function reportCrash(what, err) {
  const message = (err && (err.stack || err.message)) || String(err);
  banner(what + ": " + message
    + ". The engine is unaffected, this is the dashboard only. Reload after fixing, "
    + "or report this text.");
}

function init() {
  window.addEventListener("error", (ev) => reportCrash("Dashboard script error", ev.error || ev.message));
  window.addEventListener("unhandledrejection", (ev) => reportCrash("Dashboard request failed", ev.reason));
  const saved = store.get("sentri.theme", null);
  if (saved) document.documentElement.dataset.theme = saved;
  $("#theme").addEventListener("click", () => {
    const dark = matchMedia("(prefers-color-scheme: dark)").matches;
    const now = document.documentElement.dataset.theme || (dark ? "dark" : "light");
    const next = now === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    store.set("sentri.theme", next);
  });
  $("#pause").addEventListener("click", (ev) => {
    state.paused = !state.paused;
    ev.target.setAttribute("aria-pressed", String(state.paused));
    ev.target.textContent = state.paused ? "paused" : "pause";
    schedule();
    if (!state.paused) refresh();
  });
  for (const b of document.querySelectorAll(".range")) {
    b.addEventListener("click", () => setRange(Number(b.dataset.hours)));
  }
  $("#log-details").addEventListener("toggle", (ev) => { if (ev.target.open) refreshLog(); });
  renderMarkLegend();
  setRange(state.hours);
  schedule();
}

init();
