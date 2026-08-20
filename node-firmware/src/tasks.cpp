#include <math.h>

#include "net.h"

uint32_t poisson_delay(uint32_t mean_ms) {
  float u = random(1, 10000) / 10000.0f;
  return (uint32_t)(-logf(u) * mean_ms);
}

static int scaled(int bytes) { return (int)(bytes * anomaly.volume_mult); }

#if SENTRI_PROFILE == SENSOR
static uint32_t seq = 0;
static float temperature = 21.0f;
static float humidity = 50.0f;
static constexpr int BODY_LEN = 48;

static void walk() {
  temperature += random(-8, 9) / 100.0f;
  humidity += random(-8, 9) / 100.0f;
  if (temperature < 18.0f) temperature = 18.0f;
  if (temperature > 24.0f) temperature = 24.0f;
  if (humidity < 40.0f) humidity = 40.0f;
  if (humidity > 60.0f) humidity = 60.0f;
}

static bool one_shot(const char *cls, const char *method, const char *path, const char *body,
                     int body_len, int out_bytes) {
  // this profile opens a socket per report, so the report starts at the SYN, not the POST
  uint64_t t_sent = epoch_ms();
  if (!net_open(CLOUD_HOST, cloud_port())) {
    gt_log(cls, "failed", 0);
    return false;
  }
  int sent = send_request(method, path, CLOUD_HOST, body, body_len, out_bytes);
  net_recv(5000);
  net_close();
  gt_log_at(cls, "sent", sent, t_sent);
  return true;
}

void task_primary() {
  walk();
  char body[BODY_LEN + 1];
  int n = snprintf(body, sizeof(body), "{\"t\":%.2f,\"h\":%.2f,\"seq\":%lu}", temperature,
                   humidity, (unsigned long)seq++);
  // the reading text varies but the payload length must not, size is a feature
  while (n < BODY_LEN) body[n++] = ' ';
  body[BODY_LEN] = 0;
  one_shot("report", "POST", "/post", body, BODY_LEN, scaled(PRIMARY_OUT));
}

void task_second() { one_shot("firmware", "GET", "/get", nullptr, 0, SECOND_OUT); }

void task_event() {}

void media_pump() {}
#endif

#if SENTRI_PROFILE == PLUG
static bool relay_on = false;

void task_primary() { cloud_exchange("keepalive", scaled(PRIMARY_OUT), PRIMARY_IN); }

void task_second() { cloud_exchange("telemetry", SECOND_OUT, SECOND_IN); }

void task_event() {
  relay_on = !relay_on;
  int out = relay_on ? EVENT_ON_OUT : EVENT_OFF_OUT;
  int in = relay_on ? EVENT_ON_IN : EVENT_OFF_IN;
  cloud_exchange(relay_on ? "event_on" : "event_off", out, in);
  if (!EVENT_SCRIPTED) reschedule("event", poisson_delay(EVENT_MS));
}

void media_pump() {}
#endif

#if SENTRI_PROFILE == CAMERA
static bool bursting = false;
static uint64_t burst_start = 0;
static long burst_sent = 0;

void task_primary() { cloud_exchange("keepalive", scaled(PRIMARY_OUT), PRIMARY_IN); }

void task_second() { cloud_exchange("status", SECOND_OUT, SECOND_IN); }

void task_event() {
  if (bursting) return;
  if (!media_start()) {
    gt_log("media", "failed", 0);
    return;
  }
  bursting = true;
  burst_start = now64();
  burst_sent = 0;
  cloud_exchange("motion", MEDIA_NOTICE_OUT, MEDIA_NOTICE_IN);
  gt_log("media", "start", 0);
  if (!EVENT_SCRIPTED) reschedule("event", poisson_delay(EVENT_MS));
}

void media_pump() {
  if (!bursting) return;
  uint32_t elapsed = (uint32_t)(now64() - burst_start);
  long total = (long)(MEDIA_BYTES * anomaly.volume_mult);
  // pace the upload so the burst really lasts its configured duration
  long due = (long)((double)MEDIA_RATE_BYTES * anomaly.volume_mult * elapsed / 1000.0);
  if (due > total) due = total;
  if (due > burst_sent) burst_sent += media_slice((int)(due - burst_sent));
  if (elapsed < MEDIA_BURST_MS && burst_sent < total) return;
  media_stop();
  bursting = false;
  cloud_exchange("motion_end", MEDIA_NOTICE_OUT, MEDIA_NOTICE_IN);
  gt_log("media", "end", (int)burst_sent);
}
#endif
