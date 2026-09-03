#include "net.h"

Anomaly anomaly = {1.0f, 1.0f, false, false, 0};  // neutral until the pi injects something

// order matters, primary is index 0 and advance() keys the cadence anomaly off that
Task tasks[] = {
    {"primary", 0, PRIMARY_MS, PRIMARY_JITTER_MS, true, task_primary},
    {"second", 0, SECOND_MS, 0, true, task_second},
#if SENTRI_PROFILE != SENSOR
    {"event", 0, EVENT_MS, 0, true, task_event},
#endif
    {"ntp", 0, NTP_MS, 0, true, net_ntp_sync},
    {"dns", 0, DNS_MS, 0, true, net_dns_refresh},
    {"beacon", 0, BEACON_MS, 0, false, net_beacon},  // off until a destination anomaly
};

int task_count = sizeof(tasks) / sizeof(tasks[0]);
// drawn once per firing and held, so the same jitter is not re-rolled every loop pass
static int32_t jitter_now[sizeof(tasks) / sizeof(tasks[0])];

// a handful of entries, a name scan is cheaper than anything cleverer at this size
static int find(const char *name) {
  for (int i = 0; i < task_count; i++)
    if (!strcmp(tasks[i].name, name)) return i;
  return -1;
}

void reschedule(const char *name, uint32_t delay_ms) {
  int i = find(name);
  if (i >= 0) tasks[i].next_due_ms = now64() + delay_ms;
}

void set_enabled(const char *name, bool on) {
  int i = find(name);
  if (i >= 0) tasks[i].enabled = on;
}

void set_interval(const char *name, uint32_t ms) {
  int i = find(name);
  if (i >= 0) tasks[i].interval_ms = ms;
}

static void advance(int i, uint64_t now) {
  Task &t = tasks[i];
  // the cadence anomaly divides the interval of the affected class, which is task 0
  uint32_t step = i == 0 ? (uint32_t)(t.interval_ms / anomaly.cadence_mult) : t.interval_ms;
  if (step < 100) step = 100;  // floor, a 60x cadence on a fast class would spin the loop
  t.next_due_ms += step;
  // more than one step behind means a long reconnect, resync rather than fire a backlog
  if (t.next_due_ms + step < now) t.next_due_ms = now + step;
  jitter_now[i] = t.jitter_ms ? random(-t.jitter_ms, t.jitter_ms + 1) : 0;
}

// static void advance(int i) { tasks[i].next_due_ms = now64() + tasks[i].interval_ms; }
// drifted, every slow loop pass widened the interval and the sd went with it

void setup() {
  Serial.begin(115200);
  delay(500);
  randomSeed(micros());
  while (!net_boot()) delay(5000);  // nothing downstream works without it, so keep trying
  control_begin();
  // one epoch for every task, so due times stay on an absolute grid instead of drifting
  uint64_t epoch_start = now64();
  for (int i = 0; i < task_count; i++) tasks[i].next_due_ms = epoch_start + tasks[i].interval_ms;
#if SENTRI_PROFILE == CAMERA
  if (!EVENT_SCRIPTED) reschedule("event", poisson_delay(EVENT_MS));
#endif
}

void loop() {
  uint64_t now = now64();
  for (int i = 0; i < task_count; i++) {
    // jitter moves the firing moment only, next_due stays on the absolute grid
    if (!tasks[i].enabled || (int64_t)now < (int64_t)tasks[i].next_due_ms + jitter_now[i]) continue;
    tasks[i].fire();
    advance(i, now);
  }
  net_ensure();    // reconnect if the persistent socket dropped
  media_pump();    // camera only, no-op elsewhere
  control_poll();
  anomaly_check(); // expiry, so an injection always reverts on its own
  delay(5);  // well under any jitter that matters, just keeps the loop off the cpu
}
