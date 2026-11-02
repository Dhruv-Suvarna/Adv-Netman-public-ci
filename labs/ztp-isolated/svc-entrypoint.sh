#!/usr/bin/env bash
# Supervise dhcpd on the isolated fixture: (re)start it whenever /srv/dhcp/dhcpd.conf exists and dhcpd is not running.
# NMAS applies configuration by writing /srv/dhcp (bind mount) and asking for a restart (/srv/dhcp/restart marker).
set -euo pipefail
mkdir -p /srv/dhcp
touch /srv/dhcp/dhcpd.leases
while true; do
  if [ -f /srv/dhcp/restart ]; then
    rm -f /srv/dhcp/restart
    pkill -x dhcpd 2>/dev/null || true
    sleep 1
  fi
  if [ -f /srv/dhcp/dhcpd.conf ] && ! pgrep -x dhcpd >/dev/null 2>&1; then
    dhcpd -4 -q -cf /srv/dhcp/dhcpd.conf -lf /srv/dhcp/dhcpd.leases -pf /run/dhcpd.pid >>/srv/dhcp/dhcpd.log 2>&1 &
  fi
  sleep 2
done
