#!/bin/bash
# Wait for every sandbox cEOS to accept the CLI, load its baseline, address the hosts.  Sandbox containers only.
set -u
D=$(dirname "$0")
for n in pe c3 c4 r1 r2 s1 s2; do
  [ "$(docker inspect -f '{{index .Config.Labels "nmas-sandbox"}}' isisbx-$n)" = isisbx ] || { echo "not a sandbox"; exit 1; }
  for t in $(seq 90); do docker exec isisbx-$n Cli -p 15 -c "show version" 2>/dev/null | grep -q "Software image" && break; sleep 4; done
  # interfaces must exist before the config refers to them
  for t in $(seq 60); do docker exec isisbx-$n Cli -p 15 -c "show interfaces status" 2>/dev/null | grep -q "Et2" && break; sleep 3; done
  (echo configure; cat $D/$n.cfg; echo end; echo "write memory") | docker exec -i isisbx-$n Cli -p 15 2>&1 | grep -E '^%' | sed "s/^/$n: /"
  echo "$n configured"
done
h(){ c=isisbx-$1; shift; docker exec -u 0 $c sh -c "$*"; }
h h1 'ip addr add 192.168.10.102/24 dev eth0; ip -6 addr add 2001:db8:10::102/64 dev eth0 nodad; ip route replace default via 192.168.10.1; ip -6 route replace default via 2001:db8:10::1'
h h2 'ip addr add 192.168.20.101/24 dev eth0; ip -6 addr add 2001:db8:20::101/64 dev eth0 nodad; ip route replace default via 192.168.20.1; ip -6 route replace default via 2001:db8:20::1'
h h3 'ip addr add 192.168.10.103/24 dev eth0; ip -6 addr add 2001:db8:10::103/64 dev eth0 nodad; ip route replace default via 192.168.10.1; ip -6 route replace default via 2001:db8:10::1'
h h4 'ip -6 addr add 2001:db8:30::104/64 dev eth0 nodad; ip -6 route replace default via 2001:db8:30::1'
h web 'ip addr add 172.31.50.1/31 dev eth0; ip -6 addr add 2001:db8:3150::2/64 dev eth0 nodad; ip addr add 172.30.50.10/32 dev lo; ip -6 addr add 2001:db8:3050::10/128 dev lo; ip route replace default via 172.31.50.0; ip -6 route replace default via 2001:db8:3150::1'
# the software forwarding plane does not complete offloaded checksums: TCP needs them computed by the sender
for n in h1 h2 h3 h4 web; do sudo -n nsenter -t $(docker inspect -f '{{.State.Pid}}' isisbx-$n) -n ethtool -K eth0 tx off rx off >/dev/null; done
docker exec -u 0 -d isisbx-web python3 /tools/srv.py
echo hosts-done
