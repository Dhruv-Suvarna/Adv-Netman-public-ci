"""
Service boundary for NSOT (Network Source of Truth).

This is a read-only AGGREGATION layer across several real, independent
sources -- it is not a declaration that NetBox owns everything. Every
function below returns data tagged with which source actually produced it
(NETBOX / GIT / LIVE / TOPOLOGY / INVENTORY / MONITORING), plus a
fetched/observed timestamp, and degrades one source at a time: a NetBox
failure never hides Git/topology data, and vice versa (see
docs/DJANGO_NSOT_INTEGRATION.md "Failure / degraded behavior").

NetBox remains passive storage: everything here reads through
core/services/nsot_netbox.py (itself a thin adapter over the existing
modules/netbox_ipam.py + modules/ipam_context.py), never a second client.
Git access is confined to core/services/nsot_git.py. Live-device access is
confined to core/services/nsot_live.py and is never triggered automatically
by this module -- only by an explicit running-config route.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from django.core.cache import cache

from . import nsot_git, nsot_live, nsot_netbox, topology_service
from .base import not_integrated

_DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_seconds(value: dict) -> float | None:
    fetched_at = value.get("fetched_at")
    if not fetched_at:
        return None
    try:
        fetched = datetime.fromisoformat(fetched_at)
    except (TypeError, ValueError):
        return None
    return max(0.0, (datetime.now(timezone.utc) - fetched).total_seconds())


_LAST_GOOD_SUFFIX = ":last_good"


def _last_good_snapshot(key: str, *, refresh_error: str) -> dict | None:
    """The durable (never-expiring) fallback snapshot for `key`, tagged
    STALE with the failure that produced this fallback -- or None if no
    successful load has ever populated it."""
    last_good = cache.get(f"{key}{_LAST_GOOD_SUFFIX}")
    if last_good is None:
        return None
    value = dict(last_good)
    value["cache"] = "stale"
    value["refresh_error"] = refresh_error
    value["freshness"] = {"state": "STALE", "age_seconds": _age_seconds(value)}
    return value


def _cached(key: str, ttl: float, loader, *, force_refresh: bool = False) -> dict:
    """Small process-local (Django default LocMemCache) TTL cache. Cache
    failure/misses never fabricate data -- the loader always runs to
    completion on a miss, and its own status/message is what callers see.

    A failed load (the loader raises, or returns ``status: "unavailable"``)
    NEVER overwrites the last known good snapshot. That snapshot -- kept
    separately with no expiry -- is returned instead, tagged STALE with the
    failure recorded alongside it. See docs/DJANGO_NSOT_INTEGRATION.md
    "Cache failure / staleness".
    """
    if not force_refresh:
        cached_value = cache.get(key)
        if cached_value is not None:
            value = dict(cached_value)
            value["cache"] = "hit"
            value["freshness"] = {"state": "CURRENT", "age_seconds": _age_seconds(value)}
            return value

    try:
        value = dict(loader())
    except Exception as exc:  # noqa: BLE001 - a loader failure must not crash the page
        fallback = _last_good_snapshot(key, refresh_error=str(exc) or exc.__class__.__name__)
        if fallback is not None:
            return fallback
        return {
            "status": "unavailable", "message": str(exc) or exc.__class__.__name__,
            "fetched_at": None, "data": None, "cache": "miss",
            "freshness": {"state": "STALE", "age_seconds": None},
        }

    if value.get("status") == "unavailable":
        fallback = _last_good_snapshot(key, refresh_error=value.get("message") or "NSOT source unavailable")
        if fallback is not None:
            return fallback
        value["cache"] = "miss"
        value["freshness"] = {"state": "STALE", "age_seconds": None}
        return value

    value["cache"] = "miss"
    value["freshness"] = {"state": "CURRENT", "age_seconds": _age_seconds(value)}
    try:
        cache.set(key, value, timeout=ttl)
        cache.set(f"{key}{_LAST_GOOD_SUFFIX}", value, timeout=None)
    except Exception:  # noqa: BLE001 - a cache backend problem must not break the page
        pass
    return value


def get_nsot_summary() -> dict:
    """Legacy Phase-3 name, retained for the existing home-page description
    text and for anything still calling the pre-Phase-7 placeholder shape."""
    overview = get_overview()
    return overview


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------


def get_overview(force_refresh: bool = False) -> dict:
    from django.conf import settings

    def _load():
        netbox_health = nsot_netbox.health()
        devices = nsot_netbox.list_devices()
        interfaces = nsot_netbox.list_interfaces()
        prefixes = nsot_netbox.list_prefixes()
        addresses = nsot_netbox.list_ip_addresses()
        vlans = nsot_netbox.list_vlans()
        git_state = nsot_git.get_repo_state()
        topology = topology_service.get_topology_summary()

        return {
            "status": "available",
            "fetched_at": _now_iso(),
            "netbox": {
                "status": netbox_health["status"],
                "device_count": len(devices["data"]) if devices["data"] is not None else None,
                "interface_count": len(interfaces["data"]) if interfaces["data"] is not None else None,
                "prefix_count": len(prefixes["data"]) if prefixes["data"] is not None else None,
                "address_count": len(addresses["data"]) if addresses["data"] is not None else None,
                "vlan_count": len(vlans["data"]) if vlans["data"] is not None else None,
                "source": nsot_netbox.SOURCE,
            },
            "git": git_state,
            "topology": {
                "status": topology["status"],
                "node_count": topology.get("node_count"),
                "edge_count": topology.get("edge_count"),
                "source": "TOPOLOGY",
            },
            "page_title": "NSOT",
        }

    result = _cached("nsot:overview", settings.NSOT_CACHE_TTL_SECONDS, _load, force_refresh=force_refresh)
    result["page_title"] = "NSOT"
    return result


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def get_devices(force_refresh: bool = False) -> dict:
    from django.conf import settings

    return _cached(
        "nsot:devices", settings.NSOT_CACHE_TTL_SECONDS, nsot_netbox.list_devices, force_refresh=force_refresh
    )


def _valid_device_name(name: str) -> bool:
    return bool(_DEVICE_NAME_RE.match(name or ""))


def get_device_detail(name: str, force_refresh: bool = False) -> dict:
    from django.conf import settings

    if not _valid_device_name(name):
        return {"status": "not_found", "message": "Unknown device.", "data": None}

    def _load():
        detail = nsot_netbox.get_device_detail(name)
        if detail["status"] == "not_found":
            # NetBox is the authority for device names: an unknown device gets no drift, inventory, git or topology
            # lookups (the view answers 404).  With NetBox UNAVAILABLE the page still degrades to the other read-only sources.
            return {"status": "not_found", "message": detail.get("message"), "fetched_at": _now_iso(), "device": None}
        drift = nsot_netbox.compare_device_facts(name)
        git_template = nsot_git.read_catalogued_file(f"templates/{name}.cfg.j2")
        # Metadata only: rendering the page must never read secret material.
        live_target = nsot_live.get_live_target_metadata(name)
        monitoring_links = _monitoring_links_for(name)
        topology_neighbors = _topology_neighbors_for(name)
        return {
            "status": detail["status"],
            "message": detail.get("message"),
            "fetched_at": _now_iso(),
            "device": detail.get("data"),
            "drift": drift,
            "git_template": {
                "status": git_template["status"],
                "path": git_template.get("path"),
                "available": git_template["status"] == "available",
            },
            "live": {
                "supported": bool(live_target and live_target.get("platform") == "ceos"),
                "address": live_target.get("address") if live_target else None,
            },
            "monitoring_links": monitoring_links,
            "topology_neighbors": topology_neighbors,
        }

    return _cached(
        f"nsot:device:{name}", settings.NSOT_CACHE_TTL_SECONDS, _load, force_refresh=force_refresh
    )


def _monitoring_links_for(device_name: str) -> dict:
    from django.urls import reverse

    return {
        "resources": f"{reverse('core:monitoring_resources')}?device={device_name}",
        "link_events": f"{reverse('core:monitoring_link_events')}?device={device_name}",
        "link_state_traffic": f"{reverse('core:monitoring_link_state_traffic')}?device={device_name}",
    }


def _topology_neighbors_for(device_name: str) -> dict:
    topology = topology_service.get_topology_summary()
    if topology["status"] != "available":
        return {"status": "unavailable", "message": topology["message"], "data": []}
    edges = topology["data"]["graph"]["edges"]
    neighbors = []
    for edge in edges:
        if edge.get("source") == device_name:
            neighbors.append({"neighbor": edge.get("target"), "status": edge.get("status"), "edge_id": edge.get("id")})
        elif edge.get("target") == device_name:
            neighbors.append({"neighbor": edge.get("source"), "status": edge.get("status"), "edge_id": edge.get("id")})
    return {"status": "available", "data": neighbors, "source": "TOPOLOGY"}


def fetch_device_running_config(name: str) -> dict:
    """Explicit, never-cached, bounded live fetch -- see nsot_live.py."""
    if not _valid_device_name(name):
        return {"status": "not_found", "message": "Unknown device.", "data": None}
    return nsot_live.fetch_running_config(name)


# ---------------------------------------------------------------------------
# Interfaces / IPAM / VLANs / Routing / Platforms
# ---------------------------------------------------------------------------


def get_interfaces(device: str | None = None, force_refresh: bool = False) -> dict:
    from django.conf import settings

    device = device if device and _valid_device_name(device) else None
    key = f"nsot:interfaces:{device or 'all'}"
    return _cached(
        key, settings.NSOT_CACHE_TTL_SECONDS, lambda: nsot_netbox.list_interfaces(device), force_refresh=force_refresh
    )


def get_ipam(force_refresh: bool = False) -> dict:
    from django.conf import settings

    def _load():
        prefixes = nsot_netbox.list_prefixes()
        addresses = nsot_netbox.list_ip_addresses()
        dhcp_ranges = nsot_netbox.list_dhcp_ranges()
        reservations = nsot_netbox.reservation_report()
        return {
            "status": "available",
            "fetched_at": _now_iso(),
            "prefixes": prefixes,
            "addresses": addresses,
            "dhcp_ranges": dhcp_ranges,
            "reservations": reservations,
        }

    return _cached("nsot:ipam", settings.NSOT_CACHE_TTL_SECONDS, _load, force_refresh=force_refresh)


def get_vlans(force_refresh: bool = False) -> dict:
    from django.conf import settings

    return _cached(
        "nsot:vlans", settings.NSOT_CACHE_TTL_SECONDS, nsot_netbox.list_vlans, force_refresh=force_refresh
    )


def get_routing(force_refresh: bool = False) -> dict:
    """Honest current state: NetBox models no BGP/OSPF/RIP intent today.
    ASN objects (if any) are reported as-is; static routing protocol
    assignments are Git-sourced (AGENTS.md's frozen Lab 1 baseline), shown
    for context and clearly tagged GIT, never presented as NetBox-owned."""
    from django.conf import settings

    def _load():
        asns = nsot_netbox.list_asns()
        return {
            "status": "available",
            "fetched_at": _now_iso(),
            "asns": asns,
            "git_routing_summary": {
                "source": "GIT",
                "note": (
                    "No structured BGP/OSPF/RIP intent is modeled in NetBox yet "
                    "(Phase 8+ Device Builder scope). The frozen Lab 1 baseline "
                    "documented in AGENTS.md/README.md is: RIPv2 across "
                    "S1/S2/R1/R2, OSPFv2+OSPFv3 area 0 in the upper domain, "
                    "native eBGP IPv4/IPv6 on R3/R4/R5. This text is Git-sourced "
                    "documentation, not a NetBox record."
                ),
            },
        }

    return _cached("nsot:routing", settings.NSOT_CACHE_TTL_SECONDS, _load, force_refresh=force_refresh)


def get_platforms(force_refresh: bool = False) -> dict:
    from django.conf import settings

    def _load():
        device_types = nsot_netbox.get_device_types()
        return {
            "status": "available",
            "fetched_at": _now_iso(),
            "device_types": device_types,
            "known_images": {
                "source": "GIT",
                "note": "Image versions are AGENTS.md-documented, not modeled as a NetBox field.",
                "rows": [
                    {"platform": "Arista cEOS", "image": "4.36.2F", "devices": "R1, R2, R5, S1-S4, mgmt_swt"},
                    {"platform": "Ubuntu + FRRouting", "image": "24.04 / FRR 8.4.4", "devices": "R3, R4"},
                ],
            },
        }

    return _cached("nsot:platforms", settings.NSOT_CACHE_TTL_SECONDS, _load, force_refresh=force_refresh)


# ---------------------------------------------------------------------------
# Templates / Code (Git)
# ---------------------------------------------------------------------------


def get_templates_catalogue(force_refresh: bool = False) -> dict:
    from django.conf import settings

    return _cached(
        "nsot:templates", settings.NSOT_CACHE_TTL_SECONDS, nsot_git.list_catalogued_files, force_refresh=force_refresh
    )


def get_template_file(path: str) -> dict:
    """Never cached -- allowlist membership is re-checked on every call, and
    file reads are cheap and local."""
    return nsot_git.read_catalogued_file(path)


def get_git_state(force_refresh: bool = False) -> dict:
    from django.conf import settings

    return _cached(
        "nsot:git", settings.NSOT_CACHE_TTL_SECONDS, nsot_git.get_repo_state, force_refresh=force_refresh
    )


# ---------------------------------------------------------------------------
# Drift / consistency
# ---------------------------------------------------------------------------

DRIFT_IN_SYNC = "IN_SYNC"
DRIFT_DRIFT = "DRIFT"
DRIFT_UNMANAGED = "UNMANAGED"
DRIFT_UNAVAILABLE = "UNAVAILABLE"
DRIFT_NOT_COMPARABLE = "NOT_COMPARABLE"


def get_drift(force_refresh: bool = False) -> dict:
    from django.conf import settings

    def _load():
        checks = []

        # 1. NetBox vs Git (per managed device, reusing Phase 3A's exact
        # field-by-field comparator -- never a generic text diff).  Managed
        # devices are fetched concurrently through a bounded read-only helper;
        # the former serial N-device loop dominated cold Drift-page latency.
        devices = nsot_netbox.list_devices()
        if devices["status"] == "available":
            managed_names = [row["name"] for row in devices["data"] if row["managed"]]
            comparisons = nsot_netbox.compare_device_facts_many(managed_names)
            for row in devices["data"]:
                if not row["managed"]:
                    checks.append(
                        {
                            "domain": f"netbox_vs_git:{row['name']}",
                            "label": f"NetBox vs Git addressing -- {row['name']}",
                            "status": DRIFT_UNMANAGED,
                            "detail": "Unmanaged device (R5/WebServer); not compared.",
                        }
                    )
                    continue
                result = comparisons[row["name"]]
                if result["status"] != "available":
                    checks.append(
                        {
                            "domain": f"netbox_vs_git:{row['name']}",
                            "label": f"NetBox vs Git addressing -- {row['name']}",
                            "status": DRIFT_UNAVAILABLE,
                            "detail": result.get("message", "Comparison unavailable."),
                        }
                    )
                else:
                    checks.append(
                        {
                            "domain": f"netbox_vs_git:{row['name']}",
                            "label": f"NetBox vs Git addressing -- {row['name']}",
                            "status": DRIFT_IN_SYNC if result["data"]["equivalent"] else DRIFT_DRIFT,
                            "detail": (
                                "No field differences."
                                if result["data"]["equivalent"]
                                else f"{len(result['data']['differences'])} field difference(s)."
                            ),
                        }
                    )
        else:
            checks.append(
                {
                    "domain": "netbox_vs_git",
                    "label": "NetBox vs Git addressing",
                    "status": DRIFT_UNAVAILABLE,
                    "detail": devices.get("message", "NetBox unavailable."),
                }
            )

        # 1b. Accepted baselines.  A reconciliation record pins ONE accepted digest per device; the device is in sync only
        # while it still holds exactly that configuration.  Bounded: only devices that HAVE a record are read.
        from core import models as core_models

        from . import reconciliation_service

        for name in sorted(set(core_models.StateReconciliation.objects.values_list("device_name", flat=True))):
            row = reconciliation_service.baseline_status(name)
            status = {"IN_SYNC": DRIFT_IN_SYNC, "DRIFT": DRIFT_DRIFT}.get(row["status"], DRIFT_UNAVAILABLE)
            if row["status"] == "IN_SYNC":
                detail = f"Running configuration equals the baseline accepted by {row['record_id']} ({row['accepted'][:12]})."
            elif row["status"] == "DRIFT":
                detail = (f"Running configuration differs from the baseline accepted by {row['record_id']} "
                          f"({row['accepted'][:12]} -> {row['current'][:12]}; sections: {', '.join(row['changed_sections']) or 'unknown'}).")
            else:
                detail = f"The device could not be read; the baseline accepted by {row['record_id']} was not compared."
            if row["later_runs"]:
                detail += f" {len(row['later_runs'])} execution run(s) applied to this device after the acceptance; the baseline needs a new decision."
            checks.append({"domain": f"accepted_baseline:{name}", "label": f"Accepted baseline vs running configuration -- {name}",
                           "status": status, "detail": detail})

        # 2. NetBox reservation readiness (VLAN200 static-management check).
        reservations = nsot_netbox.reservation_report()
        if reservations["status"] == "available":
            checks.append(
                {
                    "domain": "reservation_readiness",
                    "label": "NetBox DHCP reservation readiness",
                    "status": DRIFT_IN_SYNC if reservations["data"]["ok"] else DRIFT_DRIFT,
                    "detail": f"{reservations['data']['rows_checked']} rows checked, overall {reservations['data']['overall_status']}.",
                }
            )
        else:
            checks.append(
                {
                    "domain": "reservation_readiness",
                    "label": "NetBox DHCP reservation readiness",
                    "status": DRIFT_UNAVAILABLE,
                    "detail": reservations.get("message", "NetBox unavailable."),
                }
            )

        # 3. Topology vs NetBox managed-device set.
        topology = topology_service.get_topology_summary()
        if topology["status"] == "available" and devices["status"] == "available":
            topology_names = {n["canonical_name"] for n in topology["data"]["graph"]["nodes"]}
            netbox_names = {row["name"] for row in devices["data"]}
            missing_from_topology = sorted(netbox_names - topology_names)
            missing_from_netbox = sorted(topology_names - netbox_names)
            in_sync = not missing_from_topology and not missing_from_netbox
            checks.append(
                {
                    "domain": "topology_vs_netbox",
                    "label": "Topology device set vs NetBox device set",
                    "status": DRIFT_IN_SYNC if in_sync else DRIFT_DRIFT,
                    "detail": (
                        "Device sets match."
                        if in_sync
                        else f"Only in NetBox: {missing_from_topology or 'none'}; only in topology: {missing_from_netbox or 'none'}."
                    ),
                }
            )
        else:
            checks.append(
                {
                    "domain": "topology_vs_netbox",
                    "label": "Topology device set vs NetBox device set",
                    "status": DRIFT_UNAVAILABLE,
                    "detail": "Topology or NetBox source unavailable.",
                }
            )

        # 4. Live running-config vs stored/rendered state -- not compared by
        # default (requires an explicit, bounded per-device fetch; see
        # docs/DJANGO_NSOT_INTEGRATION.md "Drift / consistency").
        checks.append(
            {
                "domain": "netbox_vs_live",
                "label": "NetBox vs live running-config",
                "status": DRIFT_NOT_COMPARABLE,
                "detail": (
                    "No automatic full-fleet live comparison is performed on "
                    "page load (bounded, explicit per-device fetch only -- "
                    "see the device detail page's running-config action)."
                ),
            }
        )

        return {"status": "available", "fetched_at": _now_iso(), "checks": checks}

    return _cached("nsot:drift", settings.NSOT_CACHE_TTL_SECONDS, _load, force_refresh=force_refresh)
