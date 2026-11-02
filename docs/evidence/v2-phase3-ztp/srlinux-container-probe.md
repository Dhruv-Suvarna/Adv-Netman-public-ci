# V2 Phase 3 — SR Linux 24.10 container: first-boot ZTP feasibility probe

Date: 2026-10-24 (UTC). Result: **native ZTP does not run in the container image**, so the SR Linux adapter stays
`PARTIALLY_IMPLEMENTED`: it renders and unit-tests the artifact, but there is no live proof. This is a limitation of the
container runtime. It is **not** vendor evidence that SR Linux lacks ZTP: hardware SR Linux documents DHCP-on-mgmt0 ZTP.

## Method (isolated, observe-only)

* `ghcr.io/nokia/srlinux:24.10` was started on Docker network `none`, with no Containerlab and no startup configuration.
* One veth was created as the container's `eth0` (mgmt0). Its peer sat in a holder namespace that only ran `tcpdump`.
  Nothing answered, and nothing was configured on the device.
* We listened 240 s for DHCP from mgmt0, then inspected processes, files and the app-manager definitions, and removed the
  containers.

## Observations

| Check | Result |
|-------|--------|
| DHCP from mgmt0 in 240 s | 0 packets |
| ZTP processes after boot (`ps`, matching "ztp") | none |
| ZTP components in the image | `/opt/srlinux/bin/ztp`, `ztpd`, `ztp_dhcp_client_mgr`; `/opt/srlinux/ztp/` (client, templates) |
| App-manager definitions (`/opt/srlinux/appmgr/*.yml`) | DHCP client / relay / server managers only; **no ZTP application** |
| `sr_cli` as the container's default exec user | refused ("not authorized to use CLI"); the state could not be read that way |

## Consequence

On this image, a factory-default container never starts the native ZTP client, so NMAS cannot exercise SR Linux native
ZTP without injecting its own boot-time agent. Phase 3 forbids that. To test SR Linux live, the options are: hardware, a VM
form of SR Linux that runs its boot-time ZTP, or a vendor-documented way to enable the ZTP client in the container. None of
those was available. Live verification of IOS XE (`vrnetlab/cisco_c8000v:17.06.01a`) was not attempted for a similar
reason: vrnetlab boots the VM with its own console-applied configuration and a QEMU user-mode management network whose
built-in DHCP would answer instead of NMAS. Exercising native IOS XE ZTP there would need a modified launcher, which would
no longer be the normal native path.
