#!/bin/bash
# Two-core disposable sandbox (plain docker; never part of srlceos01).  Every object carries the label nmas-sandbox=isisbx.
set -e
P=isisbx; D=$(dirname "$0")
i=20
for net in a-r1c3 b-r1c4 c-r2c3 d-r2c4 e-c3pe f-c4pe g-r1s1 h-r2s2 i-s1s2 j-s1h1 k-s1h2 l-s2h3 m-s2h4 n-peweb; do
  i=$((i+1)); docker network create --internal --label nmas-sandbox=$P --subnet 10.251.$i.0/24 $P-$net >/dev/null
  br=br-$(docker network inspect -f '{{.Id}}' $P-$net | cut -c1-12); sudo -n sh -c "echo 0 > /sys/class/net/$br/bridge/multicast_snooping"
done
mk(){ name=$1; shift
  docker create --name $P-$name --hostname $name --label nmas-sandbox=$P --privileged \
    -e INTFTYPE=eth -e ETBA=1 -e SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT=1 -e CEOS=1 -e EOS_PLATFORM=ceoslab -e container=docker -e MGMT_INTF=eth0 \
    -t ceos:4.36.2F /sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT=1 \
    systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab systemd.setenv=container=docker systemd.setenv=MGMT_INTF=eth0 >/dev/null
  for net in "$@"; do docker network connect $P-$net $P-$name; done; docker start $P-$name >/dev/null; }
mk pe e-c3pe f-c4pe n-peweb
mk c3 a-r1c3 c-r2c3 e-c3pe
mk c4 b-r1c4 d-r2c4 f-c4pe
mk r1 a-r1c3 b-r1c4 g-r1s1
mk r2 c-r2c3 d-r2c4 h-r2s2
mk s1 g-r1s1 i-s1s2 j-s1h1 k-s1h2
mk s2 h-r2s2 i-s1s2 l-s2h3 m-s2h4
for h in "h1 j-s1h1" "h2 k-s1h2" "h3 l-s2h3" "h4 m-s2h4" "web n-peweb"; do set -- $h
  docker run -d --name $P-$1 --hostname $1 --label nmas-sandbox=$P --network $P-$2 --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.all.accept_ra=0 --sysctl net.ipv6.conf.default.accept_ra=0 -v $D/tools:/tools:ro --entrypoint sleep nmas-traffic-tools:1 infinity >/dev/null; done
docker ps --filter label=nmas-sandbox=$P --format '{{.Names}}' | tr '\n' ' '
