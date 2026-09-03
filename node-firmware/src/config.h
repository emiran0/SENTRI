#pragma once

#include <Arduino.h>

#define PLUG 1
#define SENSOR 2
#define CAMERA 3

#ifndef SENTRI_PROFILE
#define SENTRI_PROFILE PLUG
#endif

// sentri filters 8080 out entirely, so nothing that models device behaviour may use it
constexpr uint16_t CONTROL_PORT = 8080;
// the only address the control server answers, everything else on the subnet gets dropped
constexpr char MGMT_IP[] = "192.168.50.1";
constexpr char NTP_HOST[] = "pool.ntp.org";
constexpr uint16_t NTP_PORT = 123;
// ip literal on purpose, no dns lookup first, that is what mirai style beaconing looks like
constexpr char BEACON_HOST[] = "1.1.1.1";
constexpr uint16_t BEACON_PORT = 443;
constexpr uint32_t BEACON_MS = 5000;  // default spacing, /anomaly overrides it per injection
constexpr uint16_t SWAP_PORT = 8443;  // where the protocol anomaly moves the cloud class
constexpr uint32_t RECONNECT_BASE_MS = 1000;
constexpr uint32_t RECONNECT_CAP_MS = 60000;
constexpr int LOG_ENTRIES = 64;  // ring, the pi polls well before this many pile up
constexpr int REQ_MAX = 1400;  // one segment, a request that splits changes the packet shape

#if SENTRI_PROFILE == PLUG
#if PLUG_ID == 2
constexpr char DEVICE_NAME[] = "sentri-plug-02";
// same traffic shape as plug-01 on a different operator, so the endpoint is the only variable
constexpr char CLOUD_HOST[] = "httpbin.dev";
#else
constexpr char DEVICE_NAME[] = "sentri-plug-01";
// testserver.host closes idle sockets at 5 s, httpbin holds them and serves the same /bytes/{n}
constexpr char CLOUD_HOST[] = "httpbin.org";
#endif
constexpr uint16_t CLOUD_PORT = 443;
constexpr bool PERSISTENT = true;  // one socket for the whole run, keepalives ride on it
constexpr uint32_t PRIMARY_MS = 40000;  // keepalive. the real tapo held 55 s at 2 ms sd
constexpr int32_t PRIMARY_JITTER_MS = 0;  // none, a heartbeat this regular is the signature
constexpr int PRIMARY_OUT = 112;  // payload, tls and ip overhead land on top of it
constexpr int PRIMARY_IN = 112;
constexpr uint32_t SECOND_MS = 900000;  // telemetry, 15 min
constexpr int SECOND_OUT = 180;
constexpr int SECOND_IN = 64;
constexpr uint32_t EVENT_MS = 600000;  // relay toggle
constexpr bool EVENT_SCRIPTED = true;  // fixed offsets, reproducible. false goes poisson
// on and off differ by a byte, same as the pingpong signature off the real plug
constexpr int EVENT_ON_OUT = 604;
constexpr int EVENT_ON_IN = 1188;
constexpr int EVENT_OFF_OUT = 605;
constexpr int EVENT_OFF_IN = 1189;
constexpr uint32_t NTP_MS = 21600000;  // 6 h
constexpr uint32_t DNS_MS = 1800000;  // 30 min, refreshes the name even on a held socket

#elif SENTRI_PROFILE == SENSOR
constexpr char DEVICE_NAME[] = "sentri-sensor-01";
// this profile opens a socket per report, so the 5 s keep-alive timeout here does not apply
constexpr char CLOUD_HOST[] = "testserver.host";
constexpr uint16_t CLOUD_PORT = 443;
// no held socket, which is what drives tcp_syn_rate and the size features off the plug
constexpr bool PERSISTENT = false;
constexpr uint32_t PRIMARY_MS = 90000;  // report
constexpr int32_t PRIMARY_JITTER_MS = 250;  // a little, unlike the plug
constexpr int PRIMARY_OUT = 240;
constexpr uint32_t SECOND_MS = 86400000;  // firmware check, daily
constexpr int SECOND_OUT = 200;
constexpr uint32_t NTP_MS = 43200000;  // 12 h
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
constexpr uint32_t EVENT_MS = 1200000;  // motion, poisson mean not a period
constexpr bool EVENT_SCRIPTED = false;
// only reached in active mode, so the first burst after a baseline freeze is a new domain
constexpr char MEDIA_HOST[] = "speed.cloudflare.com";
constexpr uint16_t MEDIA_PORT = 443;
constexpr uint32_t MEDIA_BURST_MS = 20000;
constexpr int MEDIA_RATE_BYTES = 62500;  // 500 kbps
constexpr int MEDIA_BYTES = 1250000;  // 20 s at that rate, keep the two in step
constexpr int MEDIA_NOTICE_OUT = 140;  // start and end notice, these stay on the control host
constexpr int MEDIA_NOTICE_IN = 64;
constexpr uint32_t NTP_MS = 21600000;
constexpr uint32_t DNS_MS = 1800000;
#endif

constexpr int REGISTER_OUT = 420;  // one on boot, has to be visibly bigger than a keepalive

// the only runtime mutable state on the node, everything else above is constexpr
struct Anomaly {
  float volume_mult;      // multiplies payload sizes, 1.0 is normal
  float cadence_mult;     // divides the class interval, 4.0 is four times faster
  bool extra_dest;        // beacon to the hardcoded address is running
  bool protocol_swap;     // cloud class moved to SWAP_PORT
  uint64_t expires_at_ms; // 0 means nothing active, otherwise revert at this point
};

struct Task {
  const char *name;
  uint64_t next_due_ms;  // absolute grid, advanced by interval, never from now
  uint32_t interval_ms;
  int32_t jitter_ms;     // shifts the firing moment only, never accumulates
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
void gt_log_at(const char *cls, const char *action, int bytes, uint64_t t);
void gt_log_anomaly(const char *action, const char *type, float mag);
void anomaly_apply(const char *type, float magnitude, uint32_t duration_ms);
void anomaly_check();
