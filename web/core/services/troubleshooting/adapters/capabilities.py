"""Capability probe: (canonical platform, source type) -> verdict + the evidence behind it.

Precedence for CLI on cEOS / Linux: the EXISTING health engine capability (``core.services.health.live.get_capability``) -- passed in
as a callable so this module stays importable without Django.  Everything else is a table of what the repository or the gateway
actually evidences; any pair not listed is ``UNKNOWN`` (fail closed).  No platform support is inferred from another platform.
"""

from __future__ import annotations

from ..collectors import SourceType

S, U, N = "SUPPORTED", "UNSUPPORTED", "NOT_VERIFIED"

# (platform, source) -> (status, evidence)
STATIC_CAPABILITIES: dict[tuple[str, str], tuple[str, str]] = {
    ("ceos", SourceType.GNMI_STREAM): (S, "monitoring/config/gnmi_paths.yml verified live against cEOS 4.36.2F (docs/TELEMETRY_STREAMS.md)"),
    ("ceos", SourceType.GNMI_GET): (S, "modules/gnmi.py verify_capabilities_and_get on cEOS"),
    ("linux", SourceType.GNMI_STREAM): (S, "repository-owned Linux/FRR lab adapter (modules/linux_telemetry_adapter.py) exposes the limited schema for R3/R4"),
    ("linux", SourceType.GNMI_GET): (S, "same Linux/FRR lab adapter; limited schema only"),
    ("iosxe", SourceType.GNMI_STREAM): (N, "no repository evidence of gNMI on Catalyst 8000V; not attempted"),
    ("iosxe", SourceType.GNMI_GET): (N, "no repository evidence of gNMI on Catalyst 8000V"),
    ("ceos", SourceType.SNMP_POLL): (S, "modules/snmp.py + monitoring/config/snmp_oids.yml (IF-MIB, ifOperStatus) verified on cEOS"),
    ("linux", SourceType.SNMP_POLL): (S, "modules/snmp.py platform 'linux' (net-snmp) verified"),
    ("iosxe", SourceType.SNMP_POLL): (N, "no repository SNMP onboarding for IOS XE"),
    ("ceos", SourceType.SYSLOG): (S, "modules/syslog.py configure_ceos + rsyslog -> InfluxDB pipeline"),
    ("linux", SourceType.SYSLOG): (S, "modules/syslog.py configure_linux"),
    ("iosxe", SourceType.SYSLOG): (N, "no repository syslog onboarding for IOS XE"),
    ("ceos", SourceType.NETCONF): (S, "modules/netconf.py verify_device (OpenConfig interfaces/system) on cEOS"),
    ("linux", SourceType.NETCONF): (U, "FRR/Linux has no NETCONF server in the lab"),
    ("iosxe", SourceType.NETCONF): (N, "IOS XE NETCONF not onboarded or verified in the repository"),
    ("ceos", SourceType.NETFLOW): (U, "no NetFlow/IPFIX exporter configuration or collector exists in the repository; replay of recorded records only"),
    ("linux", SourceType.NETFLOW): (U, "no flow export configured in the repository"),
    ("iosxe", SourceType.NETFLOW): (U, "no flow export configured in the repository"),
}
PLATFORM_INDEPENDENT = (SourceType.PCAP_METADATA, SourceType.CONFIG_SNAPSHOT, SourceType.STATE_SNAPSHOT, SourceType.NETBOX_INTENT, SourceType.GOLDEN_CONFIG,
                        SourceType.TOPOLOGY_TELEMETRY)
KNOWN_PLATFORMS = ("ceos", "iosxe", "linux")


def make_capability_probe(*, health_capability=None, gateway_platforms=()):
    """``health_capability(platform_key) -> {"status": ..., "evidence": ..., "transport": ...}`` is ``health.live.get_capability``.

    CLI: SUPPORTED for ceos/linux iff the health engine says SUPPORTED; for any platform listed in ``gateway_platforms`` CLI is SUPPORTED
    *via the gateway only* (fixture evidence), which is reported in ``transport``.  IOS XE has no production health session
    (health reports NOT_IMPLEMENTED), so outside the gateway it is not attempted."""
    gateway_platforms = set(gateway_platforms)

    def probe(platform: str, source_type: str) -> dict:
        if source_type in PLATFORM_INDEPENDENT:
            return {"status": S, "evidence": "platform-independent (metadata/provider source)", "transport": "provider"}
        if source_type == SourceType.CLI:
            if platform in gateway_platforms:
                return {"status": S, "evidence": f"read-only CLI attested through the execution gateway fixture for {platform}", "transport": "gateway"}
            if health_capability is not None and platform in ("ceos", "linux"):
                cap = health_capability(platform)
                return {"status": str(cap.get("status", "UNKNOWN")), "evidence": cap.get("evidence", ""), "transport": cap.get("transport", "")}
            return {"status": "UNKNOWN", "evidence": "no health capability source supplied and not a gateway platform", "transport": ""}
        status, evidence = STATIC_CAPABILITIES.get((platform, source_type), ("UNKNOWN", "no capability evidence recorded"))
        return {"status": status, "evidence": evidence, "transport": ""}
    return probe


def capability_matrix(probe) -> dict:
    """Serializable platform x source matrix (documentation + UI limitation display)."""
    return {p: {s: probe(p, s) for s in SourceType.ALL} for p in KNOWN_PLATFORMS}
