"""The six baseline template families, generated from the lab's CURRENT source devices -- never hand-written configs.

    Access Layer Switch       S1 + S2   extraction, generalized over both
    Default Gateway Router    R1 + R2   extraction, generalized over both
    Spine Device              S3 + S4   extraction, generalized over both
    Internet Uplink Device    R3 + R4   extraction (Ubuntu/FRR), generalized over both
    Multilayer Switch         semantic combination of the Access and Gateway baselines (``combine``)
    End Device                H1-H4     OUTSIDE NMAS management: derived from the repository's own lab definition
                                        (inventory.yml ``hosts`` + the topology file), never from a device login

Source devices are only ever READ (the existing sanitized, read-only capture), or not contacted at all when the newest
stored snapshot is used.  Baseline template ids are fixed, so every NMAS instance names the same family the same way.
Regenerating is idempotent: unchanged content publishes nothing; changed content publishes the next immutable version.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from django.conf import settings
from django.db import transaction

from ... import models
from ..config_workbench import snapshots
from . import combine, package, service
from .service import TemplateError

F = models.TemplateFamily
EXTRACTED = (
    {"key": "access-layer-switch", "template_id": "TPL-BASELINE-ACCESS-SWITCH", "family": F.ACCESS_SWITCH, "name": "Access Layer Switch",
     "sources": ("S1", "S2"), "description": "Access-layer switching role: edge access ports, inter-switch trunk, client VLAN SVIs with "
     "first-hop redundancy and DHCP relay, routed uplink to the gateway router, static management on VLAN 200."},
    {"key": "default-gateway-router", "template_id": "TPL-BASELINE-GATEWAY-ROUTER", "family": F.GATEWAY_ROUTER, "name": "Default Gateway Router",
     "sources": ("R1", "R2"), "description": "Default-gateway routing role: routed link to the access layer, trunk into the layer-2 fabric, "
     "transit SVIs in OSPF, RIP/OSPF redistribution point, static management on VLAN 200."},
    {"key": "spine-device", "template_id": "TPL-BASELINE-SPINE", "family": F.SPINE, "name": "Spine Device",
     "sources": ("S3", "S4"), "description": "Spine role: layer-2 fabric trunks between the gateway routers and the internet uplinks, "
     "static management on VLAN 200."},
    {"key": "internet-uplink-device", "template_id": "TPL-BASELINE-INTERNET-UPLINK", "family": F.INTERNET_UPLINK, "name": "Internet Uplink Device",
     "sources": ("R3", "R4"), "description": "Internet-uplink role on Ubuntu/FRR: fabric transit SVIs in OSPF, eBGP to the provider edge, "
     "source NAT (PAT) for the client networks, static management on VLAN 200."},
)
MLS = {"key": "multilayer-switch", "template_id": "TPL-BASELINE-MULTILAYER-SWITCH", "family": F.MULTILAYER_SWITCH, "name": "Multilayer Switch",
       "description": "A device that both switches and routes: the semantic combination of the Access Layer Switch and Default Gateway "
       "Router baselines (not a merge of their configurations)."}
END_DEVICE = {"key": "end-device", "template_id": "TPL-BASELINE-END-DEVICE", "family": F.END_DEVICE, "name": "End Device",
              "sources": ("H1", "H2", "H3", "H4"),
              "description": "Workload host attached to an access port.  OUTSIDE NMAS management: this template exists for lab generation, "
              "testing, topology/workload reuse and exchange -- it never onboards a host as managed infrastructure."}
ALL_KEYS = tuple(spec["key"] for spec in (*EXTRACTED, MLS, END_DEVICE))
PACKAGE_DIR = Path(settings.REPO_ROOT) / "templates" / "baselines"


def _captures(sources, *, live: bool, actor: str, session_factory) -> list[tuple]:
    captures = []
    for device in sources:
        if live:
            outcome, sections = snapshots.capture_with_sections(device, actor=actor, session_factory=session_factory)
            if outcome.snapshot is None:
                raise TemplateError(outcome.code or "RETRIEVAL_FAILED", outcome.message)
            captures.append((outcome.snapshot, sections))
        else:
            snapshot = models.RunningConfigSnapshot.objects.filter(device_name=device).order_by("-captured_at", "-id").first()
            if snapshot is None:
                raise TemplateError("NO_SNAPSHOT", f"No stored running-configuration snapshot exists for {device}; capture it or use a live read.")
            captures.append((snapshot, None))
    return captures


_VOLATILE = frozenset({"snapshot_id", "captured_at", "extracted_at", "repository_head"})


def _stable(value):
    """Content without capture bookkeeping: re-reading an UNCHANGED device (same running-config digest) is not a new version."""
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in value.items() if k not in _VOLATILE}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


def _publish(spec: dict, content: dict, *, actor: str, source_version=None) -> tuple[object, bool]:
    """Idempotent: an unchanged baseline publishes nothing."""
    template = service.get_template(spec["template_id"])
    latest = template.latest_published() if template else None
    if latest is not None and _stable(package.version_content(latest)) == _stable(content):
        return latest, False
    with transaction.atomic():
        if template is None:
            template = service.create_template(name=spec["name"], family=spec["family"], origin=models.TemplateOrigin.BASELINE,
                                               description=spec["description"], actor=actor, template_id=spec["template_id"])
        version = service.create_version(template, content, actor=actor, source_version=source_version)
        service.publish(version, actor=actor)
    return version, True


def end_device_content() -> dict:
    """From the repository's lab definition only -- H1-H4 are never contacted and never become managed devices."""
    inventory = yaml.safe_load((Path(settings.REPO_ROOT) / "inventory.yml").read_text(encoding="utf-8")) or {}
    hosts = inventory.get("hosts") or {}
    topology = next(iter(sorted(Path(settings.REPO_ROOT).glob("*.clab.yml"))), None)
    nodes = ((yaml.safe_load(topology.read_text(encoding="utf-8")) or {}).get("topology") or {}) if topology else {}
    attachments = {}
    for link in nodes.get("links") or []:
        ends = [str(e).split(":") for e in link.get("endpoints", [])]
        for (node, port), (peer, peer_port) in ((ends[0], ends[1]), (ends[1], ends[0])) if len(ends) == 2 else ():
            if node in hosts:
                attachments[node] = {"interface": port, "access_switch": peer, "access_port": peer_port}
    images = {name: (nodes.get("nodes") or {}).get(name, {}).get("image", "") for name in hosts}
    intent = {
        "device": {"hostname": "{{ hostname }}"},
        "interfaces": [{"name": "eth1", "kind": "ROUTED_PHYSICAL", "description": "{{ uplink_description }}", "mtu": 1500, "admin_state": "ENABLED"}],
        "host": {"access_interface": "eth1", "ipv4_dhcp_client": "{{ ipv4_enabled }}", "ipv6_dhcp_client": "{{ ipv6_enabled }}",
                 "default_route_source": "dhcp", "image": sorted(set(images.values()))[0] if images else ""},
    }
    parameters = {
        "hostname": {"type": "hostname", "description": "Host name", "required": True},
        "uplink_description": {"type": "string", "description": "Where eth1 attaches (access switch and port)", "required": False, "default": ""},
        "ipv4_enabled": {"type": "boolean", "description": "Run a DHCPv4 client on eth1", "required": False, "default": True},
        "ipv6_enabled": {"type": "boolean", "description": "Run a DHCPv6 client on eth1", "required": False, "default": True},
    }
    sets = {name: {"hostname": name, "ipv4_enabled": bool(meta.get("ipv4", True)), "ipv6_enabled": bool(meta.get("ipv6", True)),
                   "uplink_description": f"{attachments[name]['access_switch']}:{attachments[name]['access_port']}" if name in attachments else ""}
            for name, meta in sorted(hosts.items())}
    families = sorted({(s["ipv4_enabled"], s["ipv6_enabled"]) for s in sets.values()})
    provenance = {"method": "repository-lab-definition", "source_devices": sorted(hosts), "platforms": ["linux-host"],
                  "sources": [{"device": name, "source": "inventory.yml#hosts", "attachment": attachments.get(name, {}), "image": images.get(name, "")}
                              for name in sorted(hosts)],
                  "source_files": ["inventory.yml", topology.name if topology else "", "hostserv.py#configure_host"],
                  "extracted_at": "", "repository_head": service.repository_head(),
                  "differences": [{"path": "host/ipv4_dhcp_client", "kind": "VALUE_DIFFERS", "values": {n: s["ipv4_enabled"] for n, s in sets.items()}}]
                  if len(families) > 1 else []}
    notes = ("H1-H4 are outside NMAS management scope and stay unmanaged; they were not logged into for this template.  Addresses are "
             "DHCP-assigned and therefore not template values.  MAC addresses / DUIDs / leases are device identity and are excluded.")
    return service.build_content(family=F.END_DEVICE, intent=intent, parameters=parameters, parameter_sets=sets, provenance=provenance,
                                 notes=notes, constraints={"deployable": False, "managed_scope": False,
                                                           "purpose": ["lab-generation", "testing", "workload-reuse", "exchange"]})


def mls_content(access_version, gateway_version) -> dict:
    combined = combine.combine({"intent": access_version.intent, "parameters": access_version.parameters},
                               {"intent": gateway_version.intent, "parameters": gateway_version.parameters})
    provenance = {"method": "semantic-combination", "source_devices": sorted(set((access_version.provenance or {}).get("source_devices", []))
                                                                           | set((gateway_version.provenance or {}).get("source_devices", []))),
                  "platforms": sorted(set((access_version.provenance or {}).get("platforms", [])) | set((gateway_version.provenance or {}).get("platforms", []))),
                  "derived_from": [{"template_id": v.template.template_id, "version": v.version, "digest": v.digest, "role": role}
                                   for role, v in (("access", access_version), ("gateway", gateway_version))],
                  "extracted_at": max((access_version.provenance or {}).get("extracted_at", ""), (gateway_version.provenance or {}).get("extracted_at", "")),
                  "repository_head": service.repository_head(), "conflicts": combined["conflicts"]}
    notes = ("Semantic combination, not a configuration merge.  Port numbers of the routing role were re-homed where both roles used the same "
             "port; every decision is listed under provenance.conflicts.  No parameter set is provided: no source device is a multilayer switch.")
    return service.build_content(family=F.MULTILAYER_SWITCH, intent=combined["intent"], parameters=combined["parameters"], provenance=provenance,
                                 notes=notes, constraints={"requires": ["layer-2 switching (access / trunk ports, SVIs)", "layer-3 routing"]})


def generate(*, actor: str = "", live: bool = False, session_factory=None, only=None) -> list[dict]:
    """Generate / refresh the baselines.  -> [{"key", "ref", "created", "digest"}].  Read-only toward every device."""
    results, versions = [], {}
    wanted = set(only or ALL_KEYS)
    for spec in EXTRACTED:
        if spec["key"] not in wanted and not (MLS["key"] in wanted and spec["family"] in (F.ACCESS_SWITCH, F.GATEWAY_ROUTER)):
            continue
        captures = _captures(spec["sources"], live=live, actor=actor, session_factory=session_factory)
        content = service.extraction_content(
            captures, family=spec["family"], method="live-read-only-capture" if live else "stored-running-config-snapshot",
            notes=f"Common {spec['name'].lower()} behaviour of {' and '.join(spec['sources'])}.  Values the sources share are baseline defaults; "
                  "values that differ are parameters (see parameter_sets for each source); objects only one source has are optional "
                  "(_when) and listed under provenance.differences.")
        version, created = _publish(spec, content, actor=actor)
        if created:
            service._record_extraction_evidence(version, actor=actor, live=live)  # noqa: SLF001
        versions[spec["family"]] = version
        results.append({"key": spec["key"], "ref": version.ref, "created": created, "digest": version.digest})
    if MLS["key"] in wanted:
        version, created = _publish(MLS, mls_content(versions[F.ACCESS_SWITCH], versions[F.GATEWAY_ROUTER]), actor=actor,
                                    source_version=versions[F.ACCESS_SWITCH])
        results.append({"key": MLS["key"], "ref": version.ref, "created": created, "digest": version.digest})
    if END_DEVICE["key"] in wanted:
        version, created = _publish(END_DEVICE, end_device_content(), actor=actor)
        results.append({"key": END_DEVICE["key"], "ref": version.ref, "created": created, "digest": version.digest})
    return results


def write_packages(directory: Path | None = None, *, actor: str = "") -> list[Path]:
    """Export the newest published version of every baseline as a tracked, deterministic package file."""
    directory = Path(directory or PACKAGE_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for spec in (*EXTRACTED, MLS, END_DEVICE):
        template = service.get_template(spec["template_id"])
        version = template.latest_published() if template else None
        if version is None:
            continue
        _name, data = service.export_package(version, actor=actor)
        path = directory / f"{spec['key']}{package.FILE_SUFFIX}"
        path.write_bytes(data)
        written.append(path)
    return written


def load_packages(directory: Path | None = None, *, actor: str = "") -> list[dict]:
    """Register the tracked baseline packages on this instance (idempotent; validated like any import)."""
    results = []
    for path in sorted(Path(directory or PACKAGE_DIR).glob(f"*{package.FILE_SUFFIX}")):
        version, created = service.import_package(path.read_bytes(), actor=actor, trusted_baseline=True)
        results.append({"file": path.name, "ref": version.ref, "created": created, "digest": version.digest})
    return results
