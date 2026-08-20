#include "net.h"

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <WiFiUdp.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>

#include "secrets.h"

static WiFiClientSecure client;
static WiFiUDP udp;
static IPAddress cloud_ip;
static uint64_t epoch_base_ms = 0;
static uint64_t epoch_ref = 0;
static uint32_t backoff_ms = RECONNECT_BASE_MS;
static int attempts = 0;
static uint64_t next_try = 0;
static char pad_block[128];

#if SENTRI_PROFILE == CAMERA
static WiFiClientSecure media;
#endif

uint64_t now64() {
  static uint32_t last = 0;
  static uint64_t high = 0;
  uint32_t ms = millis();
  if (ms < last) high += 0x100000000ULL;
  last = ms;
  return high + ms;
}

uint64_t epoch_ms() { return epoch_base_ms + (now64() - epoch_ref); }

uint16_t cloud_port() { return anomaly.protocol_swap ? SWAP_PORT : CLOUD_PORT; }

static void gratuitous_arp() {
  if (netif_default) etharp_gratuitous(netif_default);
}

static bool wifi_join() {
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(DEVICE_NAME);
  // modem sleep lets the AP buffer replies for a DTIM interval, which lands in std_iat_out
  WiFi.setSleep(false);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 20000) delay(200);
  return WiFi.status() == WL_CONNECTED;
}

bool net_open(const char *host, uint16_t port) {
  client.stop();
  // no CA bundle: the handshake and therefore the traffic shape is unchanged
  client.setInsecure();
  client.setTimeout(8000);
  return client.connect(host, port);
}

void net_close() { client.stop(); }

int net_send(const char *data, int len) { return client.write((const uint8_t *)data, len); }

int net_recv(uint32_t timeout_ms) {
  client.setTimeout(timeout_ms);
  char line[160];
  int total = 0;
  int content = 0;
  while (true) {
    int n = client.readBytesUntil('\n', line, sizeof(line) - 1);
    if (n <= 0) return total;
    line[n] = 0;
    total += n + 1;
    if (n == 1) break;
    if (!strncasecmp(line, "Content-Length:", 15)) content = atoi(line + 15);
  }
  // the body must be drained fully or the next keep-alive request reads a stale reply
  uint8_t sink[256];
  while (content > 0) {
    int n = client.readBytes(sink, content > (int)sizeof(sink) ? (int)sizeof(sink) : content);
    if (n <= 0) break;
    content -= n;
    total += n;
  }
  return total;
}

int build_request(char *buf, const char *method, const char *path, const char *host,
                  int body_len, int target, int *pad) {
  const char *conn = PERSISTENT ? "keep-alive" : "close";
  int n = snprintf(buf, REQ_MAX, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: %s\r\n",
                   method, path, host, conn);
  if (body_len > 0)
    n += snprintf(buf + n, REQ_MAX - n,
                  "Content-Type: application/octet-stream\r\nContent-Length: %d\r\n", body_len);
  // the padding header is what makes the outbound size land on the configured value
  int want = target - n - 7 - 4 - body_len;
  if (want < 1) {
    *pad = 0;
    n += snprintf(buf + n, REQ_MAX - n, "\r\n");
    return n;
  }
  *pad = want;
  n += snprintf(buf + n, REQ_MAX - n, "X-Pad: ");
  return n;
}

int send_request(const char *method, const char *path, const char *host,
                 const char *body, int body_len, int target) {
  char head[REQ_MAX];
  int pad = 0;
  int n = build_request(head, method, path, host, body_len, target, &pad);
  int sent = net_send(head, n);
  int left = pad;
  while (left > 0) {
    int chunk = left > (int)sizeof(pad_block) ? (int)sizeof(pad_block) : left;
    sent += net_send(pad_block, chunk);
    left -= chunk;
  }
  if (pad > 0) sent += net_send("\r\n\r\n", 4);
  if (body_len > 0) sent += net_send(body, body_len);
  return sent;
}

bool net_ensure() {
  if (!PERSISTENT) return true;
  if (client.connected()) return true;
  if (now64() < next_try) return false;
  attempts++;
  // re-resolve from the third attempt in case the endpoint moved
  if (attempts >= 3) net_dns_refresh();
  Serial.printf("reconnect attempt %d, backoff %u ms\n", attempts, backoff_ms);
  if (net_open(CLOUD_HOST, cloud_port())) {
    gt_log("connection", "open", 0);
    attempts = 0;
    backoff_ms = RECONNECT_BASE_MS;
    return true;
  }
  gt_log("connection", "failed", 0);
  int32_t jitter = (int32_t)backoff_ms / 5;
  next_try = now64() + backoff_ms + random(-jitter, jitter + 1);
  backoff_ms = backoff_ms * 2 > RECONNECT_CAP_MS ? RECONNECT_CAP_MS : backoff_ms * 2;
  return false;
}

bool cloud_exchange(const char *cls, int out_bytes, int in_bytes) {
  if (!net_ensure()) return false;
  char path[32];
  snprintf(path, sizeof(path), "/bytes/%d", in_bytes);
  int sent = send_request("GET", path, CLOUD_HOST, nullptr, 0, out_bytes);
  int got = net_recv(3000);
  if (got <= 0) {
    net_close();
    return false;
  }
  gt_log(cls, "sent", sent);
  return true;
}

void net_dns_refresh() {
  IPAddress found;
  if (WiFi.hostByName(CLOUD_HOST, found)) {
    cloud_ip = found;
    Serial.printf("dns %s is %s\n", CLOUD_HOST, cloud_ip.toString().c_str());
    gt_log("dns", "resolved", 0);
  }
}

void net_ntp_sync() {
  uint8_t pkt[48];
  memset(pkt, 0, sizeof(pkt));
  pkt[0] = 0xE3;
  udp.begin(2390);
  udp.beginPacket(NTP_HOST, NTP_PORT);
  udp.write(pkt, sizeof(pkt));
  udp.endPacket();
  uint32_t start = millis();
  while (udp.parsePacket() < 48) {
    if (millis() - start > 3000) {
      udp.stop();
      return;
    }
    delay(10);
  }
  udp.read(pkt, sizeof(pkt));
  udp.stop();
  uint32_t seconds = ((uint32_t)pkt[40] << 24) | ((uint32_t)pkt[41] << 16) |
                     ((uint32_t)pkt[42] << 8) | pkt[43];
  uint32_t frac = ((uint32_t)pkt[44] << 24) | ((uint32_t)pkt[45] << 16) |
                  ((uint32_t)pkt[46] << 8) | pkt[47];
  uint64_t unix_ms = (uint64_t)(seconds - 2208988800UL) * 1000ULL + (frac / 4294967ULL);
  // before the first sync there is no local clock to compare against
  int64_t offset = epoch_base_ms ? (int64_t)unix_ms - (int64_t)epoch_ms() : 0;
  epoch_base_ms = unix_ms;
  epoch_ref = now64();
  Serial.printf("ntp offset %lld ms\n", (long long)offset);
  gt_log("ntp", "sync", (int)offset);
}

void net_beacon() {
  WiFiClientSecure beacon;
  beacon.setInsecure();
  beacon.setTimeout(3000);
  if (!beacon.connect(BEACON_HOST, BEACON_PORT)) {
    gt_log("beacon", "failed", 0);
    return;
  }
  char req[128];
  int n = snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                   BEACON_HOST);
  beacon.write((const uint8_t *)req, n);
  beacon.stop();
  gt_log("beacon", "sent", n);
}

bool net_boot() {
  memset(pad_block, 'x', sizeof(pad_block));
  Serial.printf("boot %s\n", DEVICE_NAME);
  if (!wifi_join()) {
    Serial.println("wifi association failed");
    return false;
  }
  Serial.printf("wifi associated, mac %s\n", WiFi.macAddress().c_str());
  Serial.printf("dhcp bound %s\n", WiFi.localIP().toString().c_str());
  gt_log("boot", "dhcp", 0);
  delay(200);
  gratuitous_arp();
  delay(200);
  net_dns_refresh();
  delay(300);
  net_ntp_sync();
  delay(300);
  if (!net_open(CLOUD_HOST, cloud_port())) {
    Serial.println("tls handshake failed");
    return false;
  }
  gt_log("boot", "tls", 0);
  delay(200);
  int sent = send_request("GET", "/bytes/512", CLOUD_HOST, nullptr, 0, REGISTER_OUT);
  net_recv(5000);
  gt_log("boot", "registered", sent);
  if (!PERSISTENT) net_close();
  Serial.println("steady state");
  return true;
}

#if SENTRI_PROFILE == CAMERA
bool media_start() {
  media.setInsecure();
  media.setTimeout(8000);
  if (!media.connect(MEDIA_HOST, MEDIA_PORT)) return false;
  char head[REQ_MAX];
  int n = snprintf(head, sizeof(head),
                   "POST /__up HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n",
                   MEDIA_HOST, (int)(MEDIA_BYTES * anomaly.volume_mult));
  media.write((const uint8_t *)head, n);
  return true;
}

int media_slice(int bytes) {
  int left = bytes;
  while (left > 0) {
    int chunk = left > (int)sizeof(pad_block) ? (int)sizeof(pad_block) : left;
    int n = media.write((const uint8_t *)pad_block, chunk);
    if (n <= 0) break;
    left -= n;
  }
  return bytes - left;
}

void media_stop() { media.stop(); }
#endif
