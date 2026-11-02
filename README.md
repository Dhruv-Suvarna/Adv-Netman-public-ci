# CSCI 5840 dual-stack Containerlab automation

This package splits the lab into a small master Python script plus per-device EOS templates.

## Final routing model

- S1/S2 remain multilayer switches and VM default gateways.
- S3/S4 and `mgmt_swt` are Layer-2 only.
- Lower IPv4 routing domain: RIPv2 across S1/S2/R1/R2.
- Lower IPv6 transport: IPv6-in-IPv4 IP-in-IP (6in4 behavior) using EOS nexthop-groups/decap-groups.
- There is **no OSPF on S1-R1 or S2-R2**.
- R1/R2 redistribute RIPv2 into OSPFv2.
- R1/R2 have selected static IPv6 client routes through IP-in-IP and redistribute only those client routes into OSPFv3.
- Upper domain: native OSPFv2 + OSPFv3 area 0.
- R3/R4/R5: native eBGP IPv4 + IPv6.
- R5 and WebServer are enabled for this initial iteration and can later be disabled independently.
- NMAS is the primary ISC DHCPv4/DHCPv6 server.
- R2 is the secondary EOS DHCP server with non-overlapping pools.
- VLAN 30 remains IPv6-only.

## Files

- `master.py` — orchestration.
- `inventory.yml` — toggles and global values.
- `templates/*.cfg.j2` — one config template per EOS device.
- `dhcp/dhcpd.conf.j2` — NMAS DHCPv4.
- `dhcp/dhcpd6.conf.j2` — NMAS stateful DHCPv6.
- `srlceos01.clab.yml` — topology.
- `requirements.txt` — Python dependencies.

## Important initial-iteration toggles

In `inventory.yml`:

```yaml
toggles:
  include_r5: true
  include_webserver: true
```

For later runs:

```yaml
toggles:
  include_r5: false
  include_webserver: false
```

These are independent toggles.

## Deploy

```bash
cd ~/clab-quickstart
sudo containerlab destroy -t srlceos01.clab.yml --cleanup
sudo containerlab deploy -t srlceos01.clab.yml
```

Copy this package to the NMAS VM, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python master.py
```

The script uses the built-in Containerlab management addresses for bootstrap/configuration, while DHCP relay and later operational management use the dedicated `192.168.200.0/24` / `2001:db8:200::/64` management LAN.

## DHCP pools

Primary NMAS:

- VLAN10 v4: `192.168.10.100-179`
- VLAN20 v4: `192.168.20.100-179`
- VLAN10 v6: `2001:db8:10::1000-1fff`
- VLAN20 v6: `2001:db8:20::1000-1fff`
- VLAN30 v6: `2001:db8:30::1000-1fff`

Secondary R2:

- VLAN10 v4: `192.168.10.200-220`
- VLAN20 v4: `192.168.20.200-220`
- VLAN10 v6: `2001:db8:10::2000-20ff`
- VLAN20 v6: `2001:db8:20::2000-20ff`
- VLAN30 v6: `2001:db8:30::2000-20ff`

Because relays point at both servers, this is secondary-server redundancy with non-overlapping pools, not coordinated active/passive DHCP failover.

## WebServer

The WebServer is bootstrapped with SSH, but its networking, Apache installation/configuration, service IPs, routes, and page are all configured over SSH by `master.py`.

Service addresses:

- IPv4: `172.30.50.10/32`
- IPv6: `2001:db8:3050::10/128`

Page:

```text
Hello world
```

Client verification:

```bash
curl http://172.30.50.10/
curl -g 'http://[2001:db8:3050::10]/'
```

## 6in4/IP-in-IP note

EOS implements this with a static nexthop-group of type `ip-in-ip` plus a matching decap-group. The master script deliberately verifies `show nexthop-group` and `show ip decap-group`.

The design uses RIPv2 only to make the IPv4 outer tunnel endpoints reachable. IPv6 client routes are static through the IP-in-IP nexthop-groups and are selectively redistributed into OSPFv3 at R1/R2.

If cEOS rejects IP-in-IP/decap programming, that is a virtual-platform dataplane limitation and the script stops instead of silently continuing with a broken IPv6 path.
