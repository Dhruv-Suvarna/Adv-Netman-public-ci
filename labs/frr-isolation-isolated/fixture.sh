#!/usr/bin/env bash
# Disposable, isolated R4-equivalent fixture for Ubuntu/FRR trusted-upstream isolation (nftables).  Never touches the
# production lab: every container uses Docker's "none" network (no Containerlab management bridge, no docker0, no route to
# VLAN 200 or the host) and is linked only to the others by point-to-point veth pairs created here.  Container names start
# with "nmasfrrfx-" (never "clab-": no production collector or topology builder enumerates them).
#
#   [prod]                       [core: FRR, OSPF area 0]           [up: R4-EQUIVALENT trusted upstream]          [dev: hostile probe /
#   eth1 10.254.94.10/24 ------- eth2 10.254.94.1/24                 FRR 8.4.4 (R4's build) + nftables 1.0.9         stand-in for R6]
#        2001:db8:fe94::10/64         2001:db8:fe94::1/64            (R4's build) + ISC dhcrelay
#                                eth1 10.254.91.2/30 =============== eth1 -> bridge Vlan102 10.254.91.1/30         eth1 10.254.90.2/29
#                                     2001:db8:fe91::2/64                     2001:db8:fe91::1/64 (OSPF area 0,         2001:db8:fe90::2/64
#                                lo 10.254.255.2/32                           interface-scoped, as on R4)           lo 10.254.255.6/32
#                                                                     eth4 10.254.90.1/29 (BOOTSTRAP PORT) ========= (FRR ospfd, area 10:
#                                                                          2001:db8:fe90::1/64                        "premature OSPF")
#                                                                          ip ospf area 0.0.0.10 (pre-staged)
#                                                                          dhcrelay -id eth4 -iu eth2 10.254.92.2
#                                                                     eth2 10.254.92.1/30 ================ eth1 [svc] 10.254.92.2/30
#                                                                     lo 10.254.255.4/32                    ISC dhcpd, HTTP :8080, ssh client
#                                                                     eth5 10.254.95.1/29 (BOOTSTRAP PORT B) ======== [dev2] 10.254.95.2/29 (probe)
#
# Usage: fixture.sh up | down | status | svc-pid | x <node> <argv...> | sh <node> '<shell>' | dev-ospf <start|stop> | addr-dev <static|dhcp>
set -euo pipefail

IMAGE="${NMAS_FRR_FX_IMAGE:-nmas-frr-iso-fx:2}"          # Dockerfile.upstream + Dockerfile.ssh (sudo)
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME="$HERE/runtime"
P="nmasfrrfx"
NODES=(up core svc prod dev dev2)

pid_of() { docker inspect -f '{{.State.Pid}}' "$P-$1"; }
x() { local n=$1; shift; docker exec "$P-$n" "$@"; }
xsh() { docker exec "$P-$1" sh -c "$2"; }

veth() {  # veth <nodeA> <ifA> <nodeB> <ifB>
  local a b ta="f${RANDOM}a" tb="f${RANDOM}b"; a=$(pid_of "$1"); b=$(pid_of "$3")
  sudo -n ip link add "$ta" type veth peer name "$tb"
  sudo -n ip link set "$ta" netns "$a"; sudo -n ip link set "$tb" netns "$b"
  sudo -n nsenter -t "$a" -n ip link set "$ta" name "$2"; sudo -n nsenter -t "$b" -n ip link set "$tb" name "$4"
  sudo -n nsenter -t "$a" -n ip link set "$2" up; sudo -n nsenter -t "$b" -n ip link set "$4" up
  # software forwarding + packet-socket DHCP: never leave partial checksums on the wire
  sudo -n nsenter -t "$a" -n ethtool -K "$2" tx off rx off >/dev/null; sudo -n nsenter -t "$b" -n ethtool -K "$4" tx off rx off >/dev/null
}

frr_start() {  # frr_start <node> <daemons...>  (the production R4 daemon options; zebra without -r)
  local n=$1; shift
  xsh "$n" 'mkdir -p /var/run/frr && chown frr:frr /var/run/frr && /usr/lib/frr/zebra -d -F traditional -A 127.0.0.1 -s 90000000'
  for d in "$@"; do
    case $d in ospf6d) xsh "$n" "/usr/lib/frr/ospf6d -d -F traditional -A ::1";; *) xsh "$n" "/usr/lib/frr/$d -d -F traditional -A 127.0.0.1";; esac
  done
  sleep 2; x "$n" vtysh -b >/dev/null
}

frr_conf() { docker exec -i "$P-$1" sh -c 'cat > /etc/frr/frr.conf; chown frr:frr /etc/frr/frr.conf'; }

up() {
  for n in "${NODES[@]}"; do
    docker inspect "$P-$n" >/dev/null 2>&1 && { echo "$P-$n exists (run down first)"; exit 1; }
    docker run -d --name "$P-$n" --hostname "fx-$n" --label nmas-fixture=$P --network none --privileged --init \
      --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.all.forwarding=1 \
      --sysctl net.ipv6.conf.all.accept_ra=0 --sysctl net.ipv6.conf.default.accept_ra=0 \
      --entrypoint sleep "$IMAGE" infinity >/dev/null
  done
  veth up eth1 core eth1; veth up eth2 svc eth1; veth up eth4 dev eth1; veth up eth5 dev2 eth1; veth core eth2 prod eth1
  # up: production-shaped (bridge VLAN SVI for the OSPF core link, as R4's Vlan102/Vlan104)
  xsh up 'ip link add Vlan102 type bridge && ip link set eth1 master Vlan102 && ip link set Vlan102 up &&
          ip addr add 10.254.91.1/30 dev Vlan102 && ip -6 addr add 2001:db8:fe91::1/64 dev Vlan102 nodad &&
          ip addr add 10.254.92.1/30 dev eth2 && ip addr add 10.254.90.1/29 dev eth4 && ip -6 addr add 2001:db8:fe90::1/64 dev eth4 nodad &&
          ip addr add 10.254.95.1/29 dev eth5 && ip -6 addr add 2001:db8:fe95::1/64 dev eth5 nodad &&
          ip addr add 10.254.255.4/32 dev lo'
  xsh core 'ip addr add 10.254.91.2/30 dev eth1 && ip -6 addr add 2001:db8:fe91::2/64 dev eth1 nodad &&
            ip addr add 10.254.94.1/24 dev eth2 && ip -6 addr add 2001:db8:fe94::1/64 dev eth2 nodad && ip addr add 10.254.255.2/32 dev lo'
  xsh prod 'ip addr add 10.254.94.10/24 dev eth1 && ip -6 addr add 2001:db8:fe94::10/64 dev eth1 nodad &&
            ip route add default via 10.254.94.1 && ip -6 route add default via 2001:db8:fe94::1'
  xsh svc 'ip addr add 10.254.92.2/30 dev eth1 && ip route add default via 10.254.92.1'
  addr_dev static
  frr_conf up <<'CFG'
frr version 8.4.4
frr defaults traditional
hostname fx-up
service integrated-vtysh-config
interface Vlan102
 ip ospf area 0.0.0.0
 ipv6 ospf6 area 0.0.0.0
exit
interface eth2
 ip ospf area 0.0.0.0
 ip ospf passive
exit
interface eth4
 ip ospf area 0.0.0.10
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ipv6 ospf6 area 0.0.0.10
exit
interface eth5
 ip ospf area 0.0.0.10
 ipv6 ospf6 area 0.0.0.10
exit
interface lo
 ip ospf area 0.0.0.0
exit
router ospf
 ospf router-id 10.254.255.4
exit
router ospf6
 ospf6 router-id 10.254.255.4
exit
CFG
  frr_conf core <<'CFG'
frr version 8.4.4
frr defaults traditional
hostname fx-core
service integrated-vtysh-config
interface eth1
 ip ospf area 0.0.0.0
 ipv6 ospf6 area 0.0.0.0
exit
interface eth2
 ip ospf area 0.0.0.0
 ip ospf passive
 ipv6 ospf6 area 0.0.0.0
 ipv6 ospf6 passive
exit
interface lo
 ip ospf area 0.0.0.0
exit
router ospf
 ospf router-id 10.254.255.2
exit
router ospf6
 ospf6 router-id 10.254.255.2
exit
CFG
  frr_conf dev <<'CFG'
frr version 8.4.4
frr defaults traditional
hostname fx-dev
service integrated-vtysh-config
interface eth1
 ip ospf area 0.0.0.10
 ip ospf hello-interval 1
 ip ospf dead-interval 4
exit
interface lo
 ip ospf area 0.0.0.10
exit
router ospf
 ospf router-id 10.254.255.6
exit
CFG
  xsh dev 'ip addr add 10.254.255.6/32 dev lo'
  frr_start up ospfd ospf6d staticd; frr_start core ospfd ospf6d
  frr_start dev                                  # zebra only: the probe's ospfd is started / stopped by `dev-ospf`
  # svc: ISC dhcpd for the bootstrap prefix (via the relay), the bootstrap HTTP artifact, an SSH client for NMAS's session
  xsh svc 'mkdir -p /srv/boot /var/lib/dhcp && touch /var/lib/dhcp/dhcpd.leases && echo "fixture bootstrap artifact" > /srv/boot/bootstrap &&
           printf "%s\n" "authoritative;" "default-lease-time 600;" "max-lease-time 600;" \
             "subnet 10.254.92.0 netmask 255.255.255.252 { }" \
             "subnet 10.254.90.0 netmask 255.255.255.248 { range 10.254.90.4 10.254.90.6; option routers 10.254.90.1; }" \
             "subnet 10.254.95.0 netmask 255.255.255.248 { range 10.254.95.4 10.254.95.6; option routers 10.254.95.1; }" > /etc/dhcp/dhcpd.conf &&
           dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf eth1 && (cd /srv/boot && nohup python3 -m http.server 8080 --bind 10.254.92.2 >/tmp/http.log 2>&1 &)'
  # dev: an SSH service (NMAS's commissioning session target)
  xsh dev 'mkdir -p /run/sshd && ssh-keygen -A >/dev/null && /usr/sbin/sshd'
  # up: its own SSH service for NMAS (V2 Phase 9: the ONLY way NMAS reaches the upstream).  NMAS's machine identity is the
  # dedicated key-only account nmas-svc, which may run exactly nft and vtysh as root; no password, no root login, no other
  # user.  The host key is generated here and pinned in the harness inventory (ssh_host_key).  NMAS runs inside svc's network
  # namespace (run-harness.sh) and reaches the upstream's loopback through eth2 -- a link the isolation never filters.
  mkdir -p "$RUNTIME/keys" && chmod 700 "$RUNTIME/keys"
  [ -f "$RUNTIME/keys/nmas-svc" ] || ssh-keygen -q -t ed25519 -N '' -C "nmas-svc@nmasfrrfx" -f "$RUNTIME/keys/nmas-svc"
  docker exec -i "$P-up" sh -c 'useradd -m -s /bin/bash nmas-svc && passwd -l nmas-svc >/dev/null && mkdir -p /home/nmas-svc/.ssh &&
    cat > /home/nmas-svc/.ssh/authorized_keys && chmod 700 /home/nmas-svc/.ssh && chmod 600 /home/nmas-svc/.ssh/authorized_keys &&
    chown -R nmas-svc:nmas-svc /home/nmas-svc/.ssh' < "$RUNTIME/keys/nmas-svc.pub"
  xsh up 'printf "%s\n" "nmas-svc ALL=(root) NOPASSWD: /usr/sbin/nft, /usr/bin/vtysh" > /etc/sudoers.d/nmas-svc && chmod 440 /etc/sudoers.d/nmas-svc &&
          visudo -cq -f /etc/sudoers.d/nmas-svc &&
          printf "%s\n" "PasswordAuthentication no" "KbdInteractiveAuthentication no" "PermitRootLogin no" "AllowUsers nmas-svc" \
            > /etc/ssh/sshd_config.d/nmas.conf && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && /usr/sbin/sshd'
  x up cat /etc/ssh/ssh_host_ed25519_key.pub > "$RUNTIME/keys/up_host_ed25519.pub"
  # the DHCP relay for the bootstrap port (client side eth4, server side eth2)
  xsh up 'nohup dhcrelay -4 -d -id eth4 -iu eth2 10.254.92.2 >/tmp/dhcrelay.log 2>&1 &'
  xsh up 'nohup dhcrelay -4 -d -id eth5 -iu eth2 10.254.92.2 >/tmp/dhcrelay-b.log 2>&1 &'
  # dev2: a second hostile probe on bootstrap port B (no routing daemon)
  xsh dev2 'ip addr add 10.254.95.2/29 dev eth1 && ip -6 addr add 2001:db8:fe95::2/64 dev eth1 nodad &&
            ip route add default via 10.254.95.1 && ip -6 route add default via 2001:db8:fe95::1 && mkdir -p /run/sshd && ssh-keygen -A >/dev/null && /usr/sbin/sshd'
  echo "fixture up; waiting for OSPF on the core link"
  for _ in $(seq 1 60); do x up vtysh -c "show ip ospf neighbor" | grep -q "Full" && break; sleep 2; done
  status
}

addr_dev() {
  case ${1:-static} in
    static) xsh dev 'pkill -x dhclient; sleep 1; ip addr flush dev eth1 scope global; ip addr add 10.254.90.2/29 dev eth1; ip -6 addr add 2001:db8:fe90::2/64 dev eth1 nodad;
                     ip route replace default via 10.254.90.1; ip -6 route replace default via 2001:db8:fe90::1';;
    dhcp) xsh dev 'ip addr flush dev eth1 scope global; rm -f /var/lib/dhcp/dhclient.leases; timeout 40 dhclient -4 -1 -v eth1 2>&1 | tail -4; ip -4 -o addr show dev eth1; pkill -x dhclient || true';;
  esac
}

dev_ospf() {
  case $1 in
    start) xsh dev 'pgrep -x ospfd >/dev/null || /usr/lib/frr/ospfd -d -F traditional -A 127.0.0.1; sleep 1; vtysh -b >/dev/null; pgrep -x ospfd >/dev/null';;
    stop) xsh dev 'pkill -x ospfd || true; sleep 1; ! pgrep -x ospfd >/dev/null';;
  esac
}

down() {
  for n in "${NODES[@]}"; do
    if docker inspect "$P-$n" >/dev/null 2>&1; then
      [ "$(docker inspect -f '{{index .Config.Labels "nmas-fixture"}}' "$P-$n")" = "$P" ] || { echo "$P-$n is not a fixture container"; exit 1; }
      docker rm -f "$P-$n" >/dev/null && echo "removed $P-$n"
    fi
  done
}

status() {
  for n in "${NODES[@]}"; do printf '%-16s %s\n' "$P-$n" "$(docker inspect -f '{{.State.Status}} net={{.HostConfig.NetworkMode}}' "$P-$n" 2>/dev/null || echo absent)"; done
  docker inspect "$P-up" >/dev/null 2>&1 && x up vtysh -c "show ip ospf neighbor" | sed 's/^/  up: /' || true
}

case "${1:-}" in
  up) up;; down) down;; status) status;;
  svc-pid) docker inspect -f '{{.State.Pid}}' "$P-svc";;
  x) shift; x "$@";; sh) xsh "$2" "$3";;
  dev-ospf) dev_ospf "$2";; addr-dev) addr_dev "$2";;
  *) sed -n '2,25p' "$0"; exit 2;;
esac
