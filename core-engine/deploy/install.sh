#!/bin/bash
set -e
cd "$(dirname "$0")"
install -d /srv/sentri/captures /srv/sentri/logs
install -m 644 sentri.service sentri-capture.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentri-capture.service
systemctl enable --now sentri.service
systemctl status --no-pager sentri-capture.service sentri.service
