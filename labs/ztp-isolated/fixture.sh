#!/usr/bin/env bash
# NMAS V2 Phase 3 -- disposable, isolated native-ZTP fixture.
#
#   [ZTPNEW1 cEOS, factory default]  Ethernet1 --- Ethernet1  [ZTPUP1 cEOS, trusted relay]  Ethernet2 --- eth1 [nmas-ztp-svc]
#            DHCP client, native ZTP          10.254.30.1/24, ip helper + option 82   10.254.31.1/30      10.254.31.2/30
#                                                                                                         ISC dhcpd + NMAS
#                                                                                                         artifact server
#
# Every container is started with Docker's "none" network: no Containerlab management bridge, no docker0, no route to the
# production lab, VLAN 200 or the host.  Links are point-to-point veth pairs created here.  The new device's network
# namespace is held by a separate holder container so a native EOS reload (which restarts the container) keeps its links.
#
# The fixture's "hardware identity" (serial number, system MAC) is written to the new device's flash as cEOS documents
# (/mnt/flash/ceos-config) -- the container equivalent of a burned-in chassis identity.  Nothing else is pre-configured on
# ZTPNEW1: no startup-config, ZTP is left enabled, no user, no SSH key.
#
# Usage: fixture.sh up | down | status | reset-new      (needs docker and sudo for ip/nsenter)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="${NMAS_ZTP_RUNTIME:-$HERE/runtime}"
CEOS_IMAGE="${NMAS_ZTP_CEOS_IMAGE:-ceos:4.36.2F}"
SVC_IMAGE="${NMAS_ZTP_SVC_IMAGE:-nmas-ztp-svc:p3}"
P="nmas-ztp-p3"
NEW_SERIAL="${NMAS_ZTP_NEW_SERIAL:-ZTPP3NEW0001}"
NEW_MAC="${NMAS_ZTP_NEW_MAC:-02:5a:70:00:00:01}"
UP_MAC="02:5a:70:00:01:01"
CEOS_ENV=(-e CEOS=1 -e EOS_PLATFORM=ceoslab -e container=docker -e INTFTYPE=eth -e ETBA=1
          -e SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 -e MAPETH0=0)

pid_of() { docker inspect -f '{{.State.Pid}}' "$1"; }

veth() {  # veth <containerA> <ifA> <containerB> <ifB>
  local a b; a=$(pid_of "$1"); b=$(pid_of "$3")
  local ta="z${RANDOM}a" tb="z${RANDOM}b"
  sudo ip link add "$ta" type veth peer name "$tb"
  sudo ip link set "$ta" netns "$a"; sudo ip link set "$tb" netns "$b"
  sudo nsenter -t "$a" -n ip link set "$ta" name "$2"; sudo nsenter -t "$b" -n ip link set "$tb" name "$4"
  sudo nsenter -t "$a" -n ip link set "$2" up; sudo nsenter -t "$b" -n ip link set "$4" up
  # cEOS (ETBA) forwards in software and does not complete partial checksums: with TX checksum offload left on, TCP
  # segments (e.g. the SYN-ACK of the artifact fetch) cross the relay with a bad checksum and are dropped.
  sudo nsenter -t "$a" -n ethtool -K "$2" tx off >/dev/null; sudo nsenter -t "$b" -n ethtool -K "$4" tx off >/dev/null
}

holder() { docker run -d --name "$1" --network none --restart unless-stopped alpine:latest sleep infinity >/dev/null; }

start_new() {
  sudo rm -rf "$RUNTIME/new-flash"; mkdir -p "$RUNTIME/new-flash"
  printf 'SERIALNUMBER=%s\nSYSTEMMACADDR=%s\n' "$NEW_SERIAL" "$NEW_MAC" > "$RUNTIME/new-flash/ceos-config"
  docker run -d --name "$P-new" --privileged --network "container:$P-new-ns" --restart unless-stopped "${CEOS_ENV[@]}" \
    -v "$RUNTIME/new-flash:/mnt/flash" "$CEOS_IMAGE" /sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 \
    systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab \
    systemd.setenv=container=docker systemd.setenv=MAPETH0=0 >/dev/null
}

up() {
  mkdir -p "$RUNTIME/up-flash" "$RUNTIME/dhcp"
  holder "$P-new-ns"; holder "$P-up-ns"
  docker run -d --name "$P-svc" --network none --restart unless-stopped -v "$RUNTIME/dhcp:/srv/dhcp" "$SVC_IMAGE" >/dev/null
  veth "$P-new-ns" eth1 "$P-up-ns" eth1
  veth "$P-up-ns" eth2 "$P-svc" eth1
  local s; s=$(pid_of "$P-svc")
  sudo nsenter -t "$s" -n ip addr add 10.254.31.2/30 dev eth1
  sudo nsenter -t "$s" -n ip route add 10.254.30.0/24 via 10.254.31.1
  # the trusted upstream: pre-configured fixture infrastructure (it is not the device under test)
  cp "$HERE/upstream-startup-config" "$RUNTIME/up-flash/startup-config"
  printf 'DISABLE=True\n' > "$RUNTIME/up-flash/zerotouch-config"
  printf 'SERIALNUMBER=ZTPP3UP0001\nSYSTEMMACADDR=%s\n' "$UP_MAC" > "$RUNTIME/up-flash/ceos-config"
  docker run -d --name "$P-up" --privileged --network "container:$P-up-ns" --restart unless-stopped "${CEOS_ENV[@]}" \
    -v "$RUNTIME/up-flash:/mnt/flash" "$CEOS_IMAGE" /sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 \
    systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSTEMDCHECK=1 systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab \
    systemd.setenv=container=docker systemd.setenv=MAPETH0=0 >/dev/null
  start_new
  echo "fixture up: $P-new (factory default, serial $NEW_SERIAL mac $NEW_MAC), $P-up (relay), $P-svc (10.254.31.2)"
}

down() {
  docker rm -f "$P-new" "$P-up" "$P-svc" "$P-new-ns" "$P-up-ns" >/dev/null 2>&1 || true
  sudo rm -rf "$RUNTIME"
  echo "fixture removed"
}

reset_new() {  # a disposable-fixture action only: return the device under test to factory default (NOT an NMAS recovery path)
  docker rm -f "$P-new" >/dev/null 2>&1 || true
  start_new
  echo "$P-new restarted from factory default"
}

status() { docker ps -a --filter "name=$P" --format '{{.Names}} {{.Status}} {{.Networks}}'; }

case "${1:-}" in
  up) up ;; down) down ;; status) status ;; reset-new) reset_new ;;
  *) echo "usage: $0 up|down|status|reset-new" >&2; exit 2 ;;
esac
