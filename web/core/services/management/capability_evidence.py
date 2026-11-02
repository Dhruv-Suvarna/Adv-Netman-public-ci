"""Recorded LIVE evidence for management-VRF capability rows.  An entry exists only for a feature proven on a real device
in the isolated Phase 4 fixture (``labs/mgmt-multihoming-isolated``); the value names the evidence file (repository
relative).  A renderer or a unit test never adds an entry here.

What the files prove (see docs/evidence/v2-phase4-management/README.md):
  vrf-execution.json           cEOS 4.36.2F: the six-Configlet management-VRF plan (VRF, Ethernet3 binding, static route,
                               SSH / eAPI / gNMI in the VRF) applied by the cEOS executor, SSH answered inside the VRF,
                               every Configlet compensated in reverse to the exact prior running-config digest, then re-applied
                               to the same applied digest.  SYSLOG / NTP / SNMP in the VRF were NOT exercised: no entry.
  failover.json                three registered paths to one cEOS device, L1-L6 probes from the NMAS namespace, failover on
                               two link failures, the management switch frozen with the device still managed over the
                               independent routed-VRF attachment, hold-down failback, and the live negatives.
  bootstrap-retirement.json    a key-only replacement account installed, verified over an independent pinned session, the
                               enrollment account removed under ``commit timer`` and confirmed only after the device rejected
                               the bootstrap key, then the provider secret retired.
"""

_DIR = "docs/evidence/v2-phase4-management/live"
_VRF = f"{_DIR}/vrf-execution.json"

LIVE: dict = {
    # execution.capability.management_gate: live apply + compensation per object type; services per service
    "arista_ceos:execute:mgmt_vrf": _VRF,
    "arista_ceos:execute:mgmt_vrf_binding": _VRF,
    "arista_ceos:execute:mgmt_vrf_route": _VRF,
    "arista_ceos:execute:mgmt_vrf_service:SSH": _VRF,
    "arista_ceos:execute:mgmt_vrf_service:EAPI": _VRF,
    "arista_ceos:execute:mgmt_vrf_service:GNMI": _VRF,
    # management.vrf.capability_matrix live_verified
    "arista_ceos:live:VRF_DEFINE": _VRF,
    "arista_ceos:live:INTERFACE_BINDING": _VRF,
    "arista_ceos:live:STATIC_ROUTE": _VRF,
    "arista_ceos:live:SSH": _VRF,
    "arista_ceos:live:EAPI": _VRF,
    "arista_ceos:live:GNMI": _VRF,
    # capabilities.lifecycle_features rows
    "arista_ceos:live:MGMT_VRF": _VRF,
    "arista_ceos:live:MGMT_FAILOVER": f"{_DIR}/failover.json",
    "arista_ceos:live:BCRED": f"{_DIR}/bootstrap-retirement.json",
}
