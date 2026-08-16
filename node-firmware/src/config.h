#pragma once

#include <Arduino.h>

#define PLUG 1
#define SENSOR 2
#define CAMERA 3

#ifndef SENTRI_PROFILE
#define SENTRI_PROFILE PLUG
#endif

constexpr uint16_t CONTROL_PORT = 8080;
constexpr char MGMT_IP[] = "192.168.50.1";
constexpr char NTP_HOST[] = "pool.ntp.org";
constexpr uint16_t NTP_PORT = 123;
constexpr char BEACON_HOST[] = "1.1.1.1";
constexpr uint16_t BEACON_PORT = 443;
constexpr uint32_t BEACON_MS = 5000;
constexpr uint16_t SWAP_PORT = 8443;
constexpr uint32_t RECONNECT_BASE_MS = 1000;
constexpr uint32_t RECONNECT_CAP_MS = 60000;
constexpr int LOG_ENTRIES = 64;
constexpr int REQ_MAX = 1400;

#if SENTRI_PROFILE == PLUG
constexpr char DEVICE_NAME[] = "sentri-plug-01";
constexpr char CLOUD_HOST[] = "testserver.host";
constexpr uint16_t CLOUD_PORT = 443;
constexpr bool PERSISTENT = true;
constexpr uint32_t PRIMARY_MS = 40000;
constexpr int32_t PRIMARY_JITTER_MS = 0;
constexpr int PRIMARY_OUT = 112;
constexpr int PRIMARY_IN = 112;
constexpr uint32_t SECOND_MS = 900000;
constexpr int SECOND_OUT = 180;
constexpr int SECOND_IN = 64;
constexpr uint32_t EVENT_MS = 600000;
constexpr bool EVENT_SCRIPTED = true;
constexpr int EVENT_ON_OUT = 604;
constexpr int EVENT_ON_IN = 1188;
constexpr int EVENT_OFF_OUT = 605;
constexpr int EVENT_OFF_IN = 1189;
constexpr uint32_t NTP_MS = 21600000;
constexpr uint32_t DNS_MS = 1800000;

#elif SENTRI_PROFILE == SENSOR
constexpr char DEVICE_NAME[] = "sentri-sensor-01";
constexpr char CLOUD_HOST[] = "httpbin.org";
constexpr uint16_t CLOUD_PORT = 443;
constexpr bool PERSISTENT = false;
constexpr uint32_t PRIMARY_MS = 90000;
constexpr int32_t PRIMARY_JITTER_MS = 250;
constexpr int PRIMARY_OUT = 240;
constexpr uint32_t SECOND_MS = 86400000;
constexpr int SECOND_OUT = 200;
constexpr uint32_t NTP_MS = 43200000;
constexpr uint32_t DNS_MS = 1800000;

#elif SENTRI_PROFILE == CAMERA
constexpr char DEVICE_NAME[] = "sentri-cam-01";
constexpr char CLOUD_HOST[] = "testserver.host";
constexpr uint16_t CLOUD_PORT = 443;
constexpr bool PERSISTENT = true;
constexpr uint32_t PRIMARY_MS = 30000;
constexpr int32_t PRIMARY_JITTER_MS = 0;
constexpr int PRIMARY_OUT = 96;
constexpr int PRIMARY_IN = 96;
constexpr uint32_t SECOND_MS = 300000;
constexpr int SECOND_OUT = 220;
constexpr int SECOND_IN = 64;
constexpr uint32_t EVENT_MS = 1200000;
constexpr bool EVENT_SCRIPTED = false;
constexpr char MEDIA_HOST[] = "speed.cloudflare.com";
constexpr uint16_t MEDIA_PORT = 443;
constexpr uint32_t MEDIA_BURST_MS = 20000;
constexpr int MEDIA_RATE_BYTES = 62500;
constexpr int MEDIA_BYTES = 1250000;
constexpr int MEDIA_NOTICE_OUT = 140;
constexpr int MEDIA_NOTICE_IN = 64;
constexpr uint32_t NTP_MS = 21600000;
constexpr uint32_t DNS_MS = 1800000;
#endif

constexpr int REGISTER_OUT = 420;

struct Anomaly {
  float volume_mult;
  float cadence_mult;
  bool extra_dest;
  bool protocol_swap;
  uint64_t expires_at_ms;
};

struct Task {
  const char *name;
  uint64_t next_due_ms;
  uint32_t interval_ms;
  int32_t jitter_ms;
  bool enabled;
  void (*fire)();
};

extern Anomaly anomaly;
extern Task tasks[];
extern int task_count;

void reschedule(const char *name, uint32_t delay_ms);
void set_enabled(const char *name, bool on);
void set_interval(const char *name, uint32_t ms);
uint32_t poisson_delay(uint32_t mean_ms);

void task_primary();
void task_second();
void task_event();
void media_pump();

void control_begin();
void control_poll();
void gt_log(const char *cls, const char *action, int bytes);
void gt_log_anomaly(const char *action, const char *type, float mag);
void anomaly_apply(const char *type, float magnitude, uint32_t duration_ms);
void anomaly_check();
