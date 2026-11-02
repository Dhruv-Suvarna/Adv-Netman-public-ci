"""Execute actual application paths for each matrix cell, without external I/O.

Temporary Changes are rolled back. Only the explicit assessment/evidence is
persisted by the caller. Synthetic source bundles are labelled fixture-only;
they do not claim live IPAM, device state, or platform behavior.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from copy import deepcopy

from django.db import transaction

from ... import models
from .. import candidate_renderer, change_service, field_commit_service, field_registry, intent_service
from .. import service_policy_intent_service as policy
from .. import network_config_validation, platform_drivers, srlinux_model
from ..config_import import parser_ceos, parser_frr, service as import_service
from ..execution import capability as execution_capability
from ..execution.codes import Capability
from ..execution.executors import ceos, iosxe, linux, registry as executors, srlinux
from ..execution.executors.base import ConfigletSpec, ExecutorError
from ..health.evidence import DeviceEvidence, FactGroup
from ..health.routing_config import normalized_area
from ..validation import sources
from ..validation.findings import sha256_of
from .assessment import CellAssessment, LIVE_PROBES, PROBES, probe
from .probe_cases import author, sample


def fixture_sources(platform, head):
    data = {
        "NETBOX": {"ip_addresses": [], "prefixes": [
            {"prefix": "198.18.0.0/15", "family": 4, "relay_targets": []},
            {"prefix": "2001:db8::/32", "family": 6, "relay_targets": []}],
            "vlans": [44, 45], "dhcp_ranges": [], "interface_modes": [], "devices": [],
            "managed_devices": ["CAPDUT"]},
        "TOPOLOGY": {"lab_name": "nmas-cap-offline-fixture", "nodes": {
            "CAPDUT": {"kind": platform, "image": "offline-fixture"}}, "links": []},
        "INVENTORY": {"management": {}, "network_devices": {"CAPDUT": {"platform": platform,
            "monitoring_address": "192.0.2.44", "monitoring_address_v6": "", "edge": False}}, "hosts": []},
    }
    results = {name: sources.SourceResult(name, "available", value, fingerprint=sha256_of(value)) for name, value in data.items()}
    return sources.SourceBundle(results["NETBOX"], results["TOPOLOGY"], results["INVENTORY"],
                                sources.collect_capability(), repository_head=head,
                                extra={"assessment_source": "OFFLINE_FIXTURE"})


def _descriptors(platform, sections):
    rows = platform_drivers.get_driver(platform).render_candidate(
        field_values={"device.hostname": "CAPDUT", "device.description": ""},
        interfaces=list(sections.get("interfaces", {}).values()), routing=sections.get("routing", {}),
        phase12={k: sections.get(k, {}) for k in ("fhrp", "nat", "services", "security", "policy")},
    )
    return [text for row in rows if (text := candidate_renderer.descriptor_text(row)) is not None]


def _parsed_contains(parsed, feature, case):
    code = feature.code
    if feature.family == "interface":
        return any(i.name == case.expected["interface"] and i.kind == code for i in parsed.interfaces)
    if feature.family == "routing":
        if code.startswith("STATIC_"):
            return any(r.destination == case.expected["prefix"] and r.next_hop_address == case.expected["next_hop"]
                       for r in parsed.static_routes)
        family = next(f for f in ("rip", "ospf", "isis", "eigrp", "bgp") if code.lower().startswith(f))
        af = "IPV6" if code in {"RIPNG", "OSPFV3", "BGP_IPV6", "EIGRP_IPV6"} else "IPV4"
        for instance in parsed.routing_instances:
            if instance.family != family:
                continue
            if family == "bgp":
                wanted = next(iter(next(iter(case.sections["routing"]["bgp"].values()))["neighbors"].values()))
                prefix = next(iter(next(iter(case.sections["routing"]["bgp"].values()))["networks"].values()))["cidr"]
                return instance.fields.get("local_asn") == 65044 and any(
                    n.get("peer_address") == wanted["peer_address"] and n.get("remote_asn") == wanted["remote_asn"] and
                    (n.get("family", af) == af or n.get(f"activate_{af.lower()}") is True)
                    for n in instance.neighbors) and any(n.get("cidr") == prefix and n.get("family") == af
                                                        for n in instance.networks)
            if family == "ospf":
                binding_ok = any(b.get("interface_name") == case.expected["interface"] and
                                 normalized_area(b.get("area")) == "0" and b.get("version") == code for b in instance.bindings)
                network_ok = af == "IPV6" or (parsed.parser_version.startswith(("ubuntu-frr", "srlinux")) and binding_ok) or any(
                    n.get("prefix") == "198.18.0.0/30" and n.get("area") == "0" for n in instance.networks)
                return instance.fields.get("version") == code and instance.fields.get("router_id") == "198.18.44.1" \
                    and network_ok and binding_ok
            if family == "rip":
                return instance.fields.get("address_family") == af and instance.fields.get("enabled") is True and \
                    any(b.get("interface_name") == case.expected["interface"] for b in instance.bindings)
            return instance.fields.get("version", code) == code and instance.fields.get("address_family", af) == af
        return False
    if code.startswith("FHRP_"):
        protocol, af = code[len("FHRP_"):].rsplit("_", 1)
        return any(f.get("protocol") == protocol and f.get("address_family") == af
                   for i in parsed.interfaces for f in i.fhrp)
    if code.startswith("ACL_ATTACH_"):
        af = code.rsplit("_", 1)[1]
        return any(a.get("family") == af and a.get("name") == "CAP_ACL" and a.get("direction") == "IN"
                   for i in parsed.interfaces for a in i.acl_attachments)
    if code.startswith("ACL_"):
        _, af, acl_type = code.split("_")
        return any(a.name == "CAP_ACL" and a.family == af and a.acl_type == acl_type and a.entries for a in parsed.acls)
    if code.startswith("DHCP_RELAY_"):
        return any(r.get("family") == code.rsplit("_", 1)[1] for i in parsed.interfaces for r in i.dhcp_relays)
    if code.startswith("NAT_") and not code.startswith("NAT_POOL_"):
        payload = code[len("NAT_"):]
        family = next(f for f in policy.NAT_FAMILIES if payload.startswith(f + "_"))
        mode = payload[len(family) + 1:]
        return any(r.family == family and r.mode == mode for r in parsed.nat_rules)
    # Explicitly tested: the ParsedConfig dataclass has no collection for these
    # semantics. Unmanaged text is preservation, NOT a successful semantic import.
    return False


def _parse(platform, lines, case):
    text = "\n".join(lines)
    if platform == "arista_ceos":
        return parser_ceos.parse(text)
    if platform == "ubuntu_frr":
        addr_rows = []
        for interface in case.sections.get("interfaces", {}).values():
            addr_info = [{"family": "inet6" if a.get("family") == "IPV6" else "inet",
                          "local": a["cidr"].split("/")[0], "prefixlen": int(a["cidr"].split("/")[1])}
                         for a in (interface.get("addresses") or {}).values() if a.get("cidr")]
            addr_rows.append({"ifname": interface["name"], "flags": ["UP"], "mtu": interface.get("mtu") or 1500,
                              "addr_info": addr_info})
        # the fixture device is managed through the addresses of the interface its intent declares as management
        managed = [a["cidr"] for i in case.sections.get("interfaces", {}).values() if i.get("kind") == "MANAGEMENT"
                   for a in (i.get("addresses") or {}).values() if a.get("cidr")]
        return parser_frr.parse(text, addr_json=json.dumps(addr_rows), nft_text=text, management_addresses=managed)
    parser, _ = import_service.FIXTURE_PARSERS[platform]
    if platform == "sonic":
        text = text[text.index("{"):]
    return parser(text)


class _FixtureConfigSession:
    def __init__(self, text):
        self._text = text

    def send_command(self, command, **_kwargs):
        if command == "show tcp brief":
            return ""                                   # the fixture has no management session to protect
        if command != "show running-config":
            raise ValueError("Offline fixture session only serves the running configuration.")
        return self._text


class _FixtureGnmi:
    """Serves one configuration tree as a gNMI GetResponse; refuses everything else (no Set, no state)."""

    def __init__(self, tree):
        self._tree = tree

    def get(self, path, datatype="config"):
        if (path, datatype) != ("/", "config"):
            raise ValueError("Offline fixture session only serves the running configuration.")
        return {"notification": [{"update": [{"path": None, "val": self._tree}]}]}


def _failure(exc, *, reason):
    # Deliberately don't persist exception strings: transport/library errors may
    # carry credentials. Class and fixed reason are sufficient for offline failures.
    return probe("FAIL", f"Probe raised {type(exc).__name__}; see regression reproducer.", reason=reason)


def verify_cell(platform, feature, *, head) -> CellAssessment:
    case = sample(platform, feature)
    cell = CellAssessment(platform, feature.key, head)
    results = cell.probes
    with transaction.atomic():
        change = change_service.create_change(title=f"Offline capability probe {platform} {feature.key}")
        intent, _ = intent_service.create_or_get_device_intent(change=change, device_name="CAPDUT", platform=platform)
        revision = intent_service.create_candidate_revision(device_intent=intent)
        field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
        revision.sections = deepcopy(case.baseline)
        revision.save(update_fields=["sections"])
        try:
            authored = author(revision, platform, feature)
            results["device_builder_ui"] = probe(
                "PASS" if authored is not None else "FAIL",
                "Real Device Builder mutation API accepted the feature." if authored is not None else
                "No public collection authoring API exists for local DHCP server configuration.",
                reason="" if authored is not None else "UI_ABSENT")
        except ValueError as exc:
            results["device_builder_ui"] = probe("FAIL", f"Real authoring API refused the feature ({type(exc).__name__}).",
                                                  reason="UI_ABSENT")
        # Probe the modeled/historical raw intent too, even when normal UI refuses
        # it. All of this is inside a rollback-only transaction and never planned.
        revision.field_states.exclude(path__startswith="device.").delete()
        revision.sections = deepcopy(case.sections)
        revision.save(update_fields=["sections"])
        try:
            spec = field_registry.resolve_field_spec(case.field_path, revision=revision)
            results["semantic_model"] = probe("PASS" if spec else "FAIL",
                f"Canonical fixture resolves the feature-specific path {case.field_path}." if spec else
                f"Feature-specific field {case.field_path} is absent from the canonical field registry.",
                reason="" if spec else "NMAS_MODEL_ABSENT")
            if spec:
                positive = field_commit_service.commit_field(change=change, intent=intent, revision=revision,
                    path=case.field_path, raw_value=case.good_value)
                negative = field_commit_service.commit_field(change=change, intent=intent, revision=revision,
                    path=case.field_path, raw_value=case.bad_value)
                ok = positive.validation_state == "VALID" and negative.validation_state == "INVALID"
                results["field_validation"] = probe("PASS" if ok else "FAIL",
                    f"Feature field commit: valid sample={positive.validation_state}; invalid sample={negative.validation_state}.",
                    reason="" if ok else "FIELD_VALIDATION_FAILED")
            else:
                results["field_validation"] = probe("FAIL", "Field registry refused the feature-specific path.", reason="VALIDATOR_ABSENT")
        except ValueError as exc:
            results["semantic_model"] = results.get("semantic_model", _failure(exc, reason="NMAS_MODEL_ABSENT"))
            results["field_validation"] = _failure(exc, reason="FIELD_VALIDATION_FAILED")
        # Restore the raw accepted fixture after negative field tests. Invalid
        # field-state markers must not create a false positive candidate result.
        revision.field_states.exclude(path__startswith="device.").delete()
        revision.sections = deepcopy(case.sections)
        revision.save(update_fields=["sections"])
        lines, added = [], []
        try:
            lines = _descriptors(platform, case.sections)
            base = _descriptors(platform, case.baseline)
            added = list((Counter(lines) - Counter(base)).elements())
            target = [s for s in added if s.strip() and not s.lstrip().startswith(("!", "#"))]
            markers = [s for s in added if s.startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER)]
            ok = bool(target) and not markers
            digest = hashlib.sha256("\n".join(added).encode()).hexdigest()
            results["renderer"] = probe("PASS" if ok else "FAIL",
                f"Authoritative renderer differential: {len(target)} target line(s), {len(markers)} refusal marker(s); sha256={digest}.",
                reason="" if ok else "RENDERER_ABSENT")
            candidate = candidate_renderer.render(intent, revision)
            ok = bool(candidate["text"].strip()) and results["renderer"]["outcome"] == "PASS" and not candidate.get("composition_conflicts")
            results["candidate_generation"] = probe("PASS" if ok else "FAIL",
                f"Real candidate_renderer.render ran; {len(candidate['text'])} chars; target-rendered={results['renderer']['outcome']}.",
                reason="" if ok else "RENDERER_ABSENT")
        except Exception as exc:
            results["renderer"] = _failure(exc, reason="RENDERER_FAILED")
            results["candidate_generation"] = _failure(exc, reason="RENDERER_FAILED")
        try:
            parsed = _parse(platform, lines, case)
            ok = _parsed_contains(parsed, feature, case)
            results["parser_import"] = probe("PASS" if ok else "FAIL",
                f"Real {parsed.parser_version} parser executed; target semantic match={ok}; unmanaged blocks={len(parsed.unmanaged_blocks)}.",
                reason="" if ok else "PARSER_ABSENT")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            results["parser_import"] = _failure(exc, reason="PARSER_FAILED")
        try:
            run = network_config_validation.validate_candidate(change, actor="offline-fixture-probe",
                sources=fixture_sources(platform, head))
            codes = sorted({r.get("check", "") for r in run.errors})
            ok = run.status in {"PASS", "WARNING"} and results["renderer"]["outcome"] == "PASS"
            results["config_validation"] = probe("PASS" if ok else "FAIL",
                f"Actual network-config validation={run.status}; failing checks={codes}; external inputs are OFFLINE_FIXTURE only.",
                reason="" if ok else "CONFIG_VALIDATION_FAILED")
        except Exception as exc:
            results["config_validation"] = _failure(exc, reason="CONFIG_VALIDATION_FAILED")
        try:
            executor = executors.executor_for({"name": "CAPDUT", "platform": platform, "container": "offline-fixture"})
            cap = execution_capability.capability_for(platform, case.object_type)
            spec = ConfigletSpec("CAP-OFFLINE", 1, "CAPDUT", platform, case.object_type, "CREATE_DEFINE",
                                tuple(line for line in added if line.strip() and not line.lstrip().startswith(("!", "#"))), case.expected)
            facts = DeviceEvidence("CAPDUT", platform, {name: FactGroup(value, "SYNTHETIC")
                for name, value in (("interfaces", {}), ("addresses", {}), ("routes", []))}, live_attempted=True)
            # No connect/apply calls: this tests real preflight on synthetic input.
            executor._reader = lambda device: facts
            if platform == "arista_ceos":
                # Config-snapshot preflight reads the running configuration: serve the rendered baseline, no session.
                executor._conn = _FixtureConfigSession("\n".join(base))
            if platform == "ubuntu_frr":
                # Incremental FRR preflight reads the running configuration; the fixture never contacts Docker.
                executor._config_reader = lambda _container, _timeout: "\n".join(base)
                executor._daemon_reader = lambda _container, _timeout: {"zebra", *linux.frr_routing.DAEMONS.values()}
                executor._nft_reader = lambda _container, _timeout: ""
            if platform == "cisco_c8000v_iosxe":
                # Captured-config preflight reads the running configuration: the rendered baseline, no session.
                executor._conn = _FixtureConfigSession("\n".join(["interface GigabitEthernet9", " no ip address", " shutdown", *base]))
            if platform == "nokia_srlinux":
                # Captured-tree preflight reads the running configuration over gNMI: serve the rendered baseline.
                executor._conn = _FixtureGnmi(srlinux_model.tree_from_set_lines(base))
            preflight = executor.assess(spec)
            inverse = ceos.inverse_lines(spec) if platform == "arista_ceos" else linux.inverse_operations(spec)
            if platform == "nokia_srlinux":
                inverse = srlinux.config_inverse(spec.lines, srlinux_model.tree_from_set_lines(base))
            if platform == "cisco_c8000v_iosxe":
                inverse = iosxe.config_inverse(list(spec.lines), iosxe.stable_config("\n".join(base)))
            if platform == "ubuntu_frr" and spec.object_type in linux.FRR_ROUTING_TYPES:
                inverse = linux.frr_routing_inverse(spec.lines, "\n".join(base))
            ok = cap.apply == Capability.SUPPORTED and preflight.action != "REFUSE" and bool(spec.lines)
            results["executor"] = probe("PASS" if ok else "FAIL",
                f"Real executor.assess on fixture: action={preflight.action}; exact inverse present={inverse is not None}; "
                f"restorable={preflight.restorable}; no connection/apply invoked.", reason="" if ok else "EXECUTOR_REFUSED")
        except ExecutorError as exc:
            results["executor"] = probe("FAIL", f"executor_for rejected this platform with fixed code {exc.code}.",
                                           reason="EXECUTOR_ABSENT", test_type="STATIC")
        except Exception as exc:
            results["executor"] = _failure(exc, reason="EXECUTOR_REFUSED")
        try:
            repeated = _descriptors(platform, case.sections)
            ok = lines == repeated and results["field_validation"]["outcome"] == "PASS"
            results["automated_tests"] = probe("PASS" if ok else "FAIL",
                f"Repeated renderer determinism={lines == repeated}; feature-specific valid/invalid field regression={results['field_validation']['outcome']}.",
                reason="" if ok else "FUNCTIONAL_TEST_FAILED")
        except Exception as exc:
            results["automated_tests"] = _failure(exc, reason="FUNCTIONAL_TEST_FAILED")
        transaction.set_rollback(True)
    for name in LIVE_PROBES:
        results[name] = probe("PENDING", "Isolated runtime investigation/probe is required; this offline run did not contact any device.",
                              test_type="STATIC")
    if set(results) != set(PROBES):
        raise AssertionError("Offline harness omitted a named probe.")
    return cell
