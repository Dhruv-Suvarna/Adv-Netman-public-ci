"""Adapters binding the s2 collectors to the REAL NMAS modules and to the trusted execution gateway.

Nothing here duplicates a collector or a database: each adapter reuses an existing, already-validated module (health live
allowlists, monitoring YAML catalogs, the topology/health telemetry snapshot, the gateway client) or states precisely that none exists.

    transports.py    CLI transports: health.live sessions, Netmiko-shaped objects, argv runners, the gateway (fixtures)
    capabilities.py  capability probe (platform x source) with the evidence behind every verdict; unsupported sources are named
    monitoring.py    gNMI/SNMP catalogs from monitoring/config/*.yml, Flux syslog query/parse, topology-telemetry snapshot adapter
    contracts_bridge.py  mapping of s2 bundles/observations onto the s1 ``collection_bundle/1`` / ``observation/1`` contracts
"""

ADAPTER_VERSION = "1.0.0"
