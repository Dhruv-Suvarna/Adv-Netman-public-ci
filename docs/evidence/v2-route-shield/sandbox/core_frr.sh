#!/bin/bash
# Replace the sandbox core (c3, c4) by FRR 8.4.4 routers IN the forwarding path, as in production (R3/R4): OSPFv2/v3 toward
# r1/r2, eBGP toward pe with `network` statements, the kernel as the forwarding plane.  Sandbox containers only, by exact name.
set -eu
P=isisbx; IMG=clab-raw-verifier-frr:8.4.4-1.1ubuntu6.7
for n in c3 c4 f3; do
  if docker inspect $P-$n >/dev/null 2>&1; then
    [ "$(docker inspect -f '{{index .Config.Labels "nmas-sandbox"}}' $P-$n)" = $P ] || { echo "$P-$n is not a sandbox container"; exit 1; }
    docker rm -f $P-$n >/dev/null
  fi
done
# name  as  rid  peer-as-nbr4 peer-nbr6   then  net:docker-subnet:v4:v6 ...
mk(){ name=$1 as=$2 rid=$3 pe4=$4 pe6=$5; shift 5
  docker create --name $P-$name --hostname $name --label nmas-sandbox=$P --privileged --sysctl net.ipv6.conf.all.disable_ipv6=0 \
    --sysctl net.ipv6.conf.all.forwarding=1 --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.accept_ra=0 --sysctl net.ipv6.conf.default.accept_ra=0 \
    --entrypoint sleep $IMG infinity >/dev/null
  for spec in "$@"; do docker network connect $P-${spec%%,*} $P-$name; done
  docker network disconnect bridge $P-$name 2>/dev/null || true
  docker start $P-$name >/dev/null
  pid=$(docker inspect -f '{{.State.Pid}}' $P-$name); ospf=""
  for spec in "$@"; do IFS=, read net sub v4 v6 role <<<"$spec"
    dev=$(docker exec $P-$name sh -c "ip -o -4 addr | grep ' $sub\.' | cut -d' ' -f2")
    docker exec $P-$name sh -c "ip addr flush dev $dev scope global; ip addr add $v4 dev $dev; ip -6 addr add $v6 dev $dev nodad"
    sudo -n nsenter -t $pid -n ethtool -K $dev tx off rx off >/dev/null
    [ "$role" = ospf ] && ospf="$ospf
interface $dev
 ip ospf area 0.0.0.0
 ipv6 ospf6 area 0.0.0.0
exit"
  done
  docker exec -i $P-$name sh -c 'cat > /etc/frr/frr.conf; chown frr:frr /etc/frr/frr.conf' <<CFG
frr version 8.4.4
frr defaults traditional
hostname $name
service integrated-vtysh-config
$ospf
router bgp $as
 bgp router-id $rid
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor $pe4 remote-as 65005
 neighbor $pe6 remote-as 65005
 address-family ipv4 unicast
  network 192.168.10.0/24
  network 192.168.20.0/24
  neighbor $pe4 activate
 exit-address-family
 address-family ipv6 unicast
  network 2001:db8:10::/64
  network 2001:db8:20::/64
  network 2001:db8:30::/64
  neighbor $pe6 activate
 exit-address-family
exit
router ospf
 ospf router-id $rid
 redistribute bgp route-map BGP4-TO-OSPF
exit
router ospf6
 ospf6 router-id $rid
 redistribute bgp route-map BGP6-TO-OSPF
exit
ip prefix-list WEB-V4 seq 10 permit 172.30.50.10/32
ipv6 prefix-list WEB-V6 seq 10 permit 2001:db8:3050::10/128
route-map BGP4-TO-OSPF permit 10
 match ip address prefix-list WEB-V4
exit
route-map BGP6-TO-OSPF permit 10
 match ipv6 address prefix-list WEB-V6
exit
CFG
  # the production daemons and options (zebra WITHOUT -r)
  docker exec $P-$name sh -c 'mkdir -p /var/run/frr && chown frr:frr /var/run/frr; /usr/lib/frr/zebra -d -F traditional -A 127.0.0.1 -s 90000000; /usr/lib/frr/bgpd -d -F traditional -A 127.0.0.1; /usr/lib/frr/ospfd -d -F traditional -A 127.0.0.1; /usr/lib/frr/ospf6d -d -F traditional -A ::1; sleep 2; vtysh -b' 2>&1 | grep -v '^$' | sed "s/^/$name: /" || true
}
mk c3 65003 192.168.255.3 10.3.0.1 2001:db8:205:1::2 a-r1c3,10.251.21,192.168.100.1/31,2001:db8:100:101::2/64,ospf c-r2c3,10.251.23,192.168.100.5/31,2001:db8:100:103::2/64,ospf e-c3pe,10.251.25,10.3.0.0/31,2001:db8:205:1::1/64,bgp
mk c4 65004 192.168.255.4 10.4.0.1 2001:db8:205:2::2 b-r1c4,10.251.22,192.168.100.3/31,2001:db8:100:102::2/64,ospf d-r2c4,10.251.24,192.168.100.7/31,2001:db8:100:104::2/64,ospf f-c4pe,10.251.26,10.4.0.0/31,2001:db8:205:2::1/64,bgp
# pe: the production R5 shape -- eBGP to both cores, the service prefixes by `network`, no IGP
docker exec -i $P-pe Cli -p 15 <<'CFG' | grep -E '^%' || true
configure
no router ospf 10
no ipv6 router ospf 10
interface Ethernet1
   no ip ospf area 0.0.0.0
   no ipv6 ospf 10 area 0.0.0.0
interface Ethernet2
   no ip ospf area 0.0.0.0
   no ipv6 ospf 10 area 0.0.0.0
ip prefix-list WEB-V4 seq 10 permit 172.30.50.10/32
ipv6 prefix-list WEB-V6
   seq 10 permit 2001:db8:3050::10/128
route-map WEB-V4-OUT permit 10
   match ip address prefix-list WEB-V4
route-map WEB-V6-OUT permit 10
   match ipv6 address prefix-list WEB-V6
router bgp 65005
   router-id 192.168.255.5
   neighbor 10.3.0.0 remote-as 65003
   neighbor 10.3.0.0 route-map WEB-V4-OUT out
   neighbor 10.4.0.0 remote-as 65004
   neighbor 10.4.0.0 route-map WEB-V4-OUT out
   neighbor 2001:db8:205:1::1 remote-as 65003
   neighbor 2001:db8:205:2::1 remote-as 65004
   address-family ipv4
      neighbor 10.3.0.0 activate
      neighbor 10.4.0.0 activate
      network 172.30.50.10/32
   address-family ipv6
      neighbor 2001:db8:205:1::1 activate
      neighbor 2001:db8:205:1::1 route-map WEB-V6-OUT out
      neighbor 2001:db8:205:2::1 activate
      neighbor 2001:db8:205:2::1 route-map WEB-V6-OUT out
      network 2001:db8:3050::10/128
end
write memory
CFG
echo core-rebuilt
