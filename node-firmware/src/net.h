#pragma once

#include "config.h"

bool net_boot();
bool net_ensure();
void net_close();
bool net_open(const char *host, uint16_t port);
int net_send(const char *data, int len);
int net_recv(uint32_t timeout_ms);

int build_request(char *buf, const char *method, const char *path, const char *host,
                  int body_len, int target, int *pad);
int send_request(const char *method, const char *path, const char *host,
                 const char *body, int body_len, int target);
bool cloud_exchange(const char *cls, int out_bytes, int in_bytes);
void net_ntp_sync();
void net_dns_refresh();
void net_beacon();

uint64_t now64();
uint64_t epoch_ms();
uint16_t cloud_port();

#if SENTRI_PROFILE == CAMERA
bool media_start();
int media_slice(int bytes);
void media_stop();
#endif
