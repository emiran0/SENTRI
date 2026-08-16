#include <WiFi.h>

#include "net.h"

struct LogEntry {
  uint64_t t;
  char cls[14];
  char action[12];
  char type[12];
  float mag;
  int bytes;
};

static WiFiServer server(CONTROL_PORT);
static LogEntry entries[LOG_ENTRIES];
static int head = 0;
static int stored = 0;

static LogEntry *push() {
  LogEntry *e = &entries[head];
  head = (head + 1) % LOG_ENTRIES;
  if (stored < LOG_ENTRIES) stored++;
  memset(e, 0, sizeof(LogEntry));
  e->t = epoch_ms();
  e->bytes = -1;
  return e;
}

void gt_log(const char *cls, const char *action, int bytes) {
  LogEntry *e = push();
  strncpy(e->cls, cls, sizeof(e->cls) - 1);
  strncpy(e->action, action, sizeof(e->action) - 1);
  e->bytes = bytes;
}

void gt_log_anomaly(const char *action, const char *type, float mag) {
  LogEntry *e = push();
  strncpy(e->cls, "anomaly", sizeof(e->cls) - 1);
  strncpy(e->action, action, sizeof(e->action) - 1);
  strncpy(e->type, type, sizeof(e->type) - 1);
  e->mag = mag;
}

void control_begin() {
  server.begin();
  Serial.printf("control server on %u\n", CONTROL_PORT);
}

static void anomaly_reset(const char *why) {
  if (anomaly.expires_at_ms == 0) return;
  anomaly.volume_mult = 1.0f;
  anomaly.cadence_mult = 1.0f;
  anomaly.extra_dest = false;
  anomaly.protocol_swap = false;
  anomaly.expires_at_ms = 0;
  set_enabled("beacon", false);
  net_close();
  gt_log_anomaly("end", why, 1.0f);
}

void anomaly_apply(const char *type, float magnitude, uint32_t duration_ms) {
  if (!type[0] || duration_ms == 0) {
    anomaly_reset("manual");
    return;
  }
  // logged before the first anomalous packet leaves, latency is measured from here
  gt_log_anomaly("start", type, magnitude);
  if (!strcmp(type, "volume")) {
    anomaly.volume_mult = magnitude;
  } else if (!strcmp(type, "cadence")) {
    anomaly.cadence_mult = magnitude;
  } else if (!strcmp(type, "destination")) {
    anomaly.extra_dest = true;
    set_interval("beacon", magnitude > 0 ? (uint32_t)magnitude : BEACON_MS);
    set_enabled("beacon", true);
    reschedule("beacon", 0);
  } else if (!strcmp(type, "protocol")) {
    anomaly.protocol_swap = true;
    net_close();
  }
  anomaly.expires_at_ms = now64() + duration_ms;
}

void anomaly_check() {
  if (anomaly.expires_at_ms && now64() >= anomaly.expires_at_ms) anomaly_reset("expired");
}

static void parse_anomaly(const char *body) {
  char type[16] = {0};
  float mag = 1.0f;
  unsigned long duration = 0;
  const char *p = strstr(body, "\"type\"");
  if (p) sscanf(p, "\"type\"%*[^\"]\"%15[^\"]", type);
  p = strstr(body, "\"magnitude\"");
  if (p) sscanf(p, "\"magnitude\"%*[^0-9.-]%f", &mag);
  p = strstr(body, "\"duration_ms\"");
  if (p) sscanf(p, "\"duration_ms\"%*[^0-9-]%lu", &duration);
  anomaly_apply(type, mag, (uint32_t)duration);
}

static void send_head(WiFiClient &c) {
  c.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n");
}

static void send_log(WiFiClient &c, uint64_t since) {
  char line[220];
  int start = stored < LOG_ENTRIES ? 0 : head;
  for (int i = 0; i < stored; i++) {
    LogEntry *e = &entries[(start + i) % LOG_ENTRIES];
    if (e->t <= since) continue;
    int n = snprintf(line, sizeof(line), "{\"t\":%llu,\"dev\":\"%s\",\"class\":\"%s\",\"action\":\"%s\"",
                     (unsigned long long)e->t, DEVICE_NAME, e->cls, e->action);
    if (e->type[0])
      n += snprintf(line + n, sizeof(line) - n, ",\"type\":\"%s\",\"mag\":%.2f", e->type, e->mag);
    if (e->bytes >= 0) n += snprintf(line + n, sizeof(line) - n, ",\"bytes\":%d", e->bytes);
    snprintf(line + n, sizeof(line) - n, "}\n");
    c.print(line);
  }
}

void control_poll() {
  WiFiClient c = server.available();
  if (!c) return;
  // the control channel is for the gateway only, never for anything on the subnet
  if (c.remoteIP().toString() != String(MGMT_IP)) {
    c.stop();
    return;
  }
  c.setTimeout(2000);
  char line[192];
  char method[8] = {0};
  char path[120] = {0};
  int n = c.readBytesUntil('\n', line, sizeof(line) - 1);
  line[n] = 0;
  if (sscanf(line, "%7s %119s", method, path) != 2) {
    c.stop();
    return;
  }
  int content = 0;
  while (true) {
    n = c.readBytesUntil('\n', line, sizeof(line) - 1);
    if (n <= 1) break;
    line[n] = 0;
    if (!strncasecmp(line, "Content-Length:", 15)) content = atoi(line + 15);
  }
  char body[192] = {0};
  if (content > 0) {
    if (content > (int)sizeof(body) - 1) content = sizeof(body) - 1;
    c.readBytes(body, content);
  }
  send_head(c);
  if (!strcmp(path, "/status")) {
    snprintf(line, sizeof(line),
             "dev=%s uptime_ms=%llu epoch_ms=%llu volume=%.2f cadence=%.2f dest=%d swap=%d expires=%llu\n",
             DEVICE_NAME, (unsigned long long)now64(), (unsigned long long)epoch_ms(),
             anomaly.volume_mult, anomaly.cadence_mult, anomaly.extra_dest ? 1 : 0,
             anomaly.protocol_swap ? 1 : 0, (unsigned long long)anomaly.expires_at_ms);
    c.print(line);
  } else if (!strcmp(path, "/event")) {
    task_event();
    c.print("fired\n");
  } else if (!strcmp(path, "/anomaly")) {
    parse_anomaly(body);
    c.print("applied\n");
  } else if (!strncmp(path, "/log", 4)) {
    const char *q = strstr(path, "since=");
    send_log(c, q ? strtoull(q + 6, nullptr, 10) : 0);
  } else {
    c.print("unknown\n");
  }
  c.flush();
  c.stop();
}
