#!/usr/bin/env python3
"""Bounded gateway acceptance for versioned route intent on a disposable ``ceos_peer`` fixture.

The caller supplies a gateway source pin for this worktree.  Every live command is gateway-allowlisted and recorded.  The only
fault is removal of one IPv4 static route on the disposable r1; it is restored in ``finally`` and the fixture is always stopped.
No production inventory, credential, lifecycle record, network, policy, grant, or service is touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "web"
INTENT = Path(__file__).resolve().parent / "fixtures" / "troubleshooting_routing" / "ceos-peer-intent-v1.json"
TOPOLOGY_REVISION = "88a735d06dca5e64f0e2efb15f7bbefba36c82b8"
sys.path.insert(0, str(WEB))
sys.path.insert(0, "/opt/ai-orchestrator/gateway/client")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")


class RecordedGateway:
    def __init__(self, gateway, pin):
        self.gateway, self.pin, self.stage, self.sequences = gateway, pin, "setup", {}

    def call(self, op, **fields):
        result = self.gateway.call(op, **fields)
        if isinstance(result, dict) and isinstance(result.get("evidence_seq"), int):
            self.sequences.setdefault(self.stage, []).append(result["evidence_seq"])
        return result

    def execute(self, fixture, node, kind, *, commands=None, argv=None):
        fields = {"fixture_id": fixture, "node": node, "kind": kind,
                  "pin_id": self.pin, "label": f"nmas-route-intent-{self.stage}"}
        fields["commands" if commands is not None else "argv"] = commands if commands is not None else argv
        result = self.call("fixture_exec", **fields)
        if not result.get("ok"):
            raise RuntimeError(f"{self.stage}: {node} {kind} failed: {result.get('outputs')}")
        return result["outputs"]

    def config(self, fixture, *commands):
        return self.execute(fixture, "r1", "config", commands=list(commands))

    def show(self, fixture, command):
        return self.execute(fixture, "r1", "show", commands=[command])[0]

    def peer(self, fixture, *argv):
        return self.execute(fixture, "peer", "argv", argv=list(argv))[0].split("\n[stderr]\n", 1)[0]


def _json(text):
    value = json.loads(text)
    if not isinstance(value, (dict, list)):
        raise RuntimeError("gateway command did not return a JSON object/list")
    return value


def _ping_ok(text):
    return bool(re.search(r"(?:^|[\s,])0(?:\.0+)?% packet loss\b", text))


def _entry(ribs, af, device, prefix):
    value = ribs[af][device].get(prefix)
    return value.as_dict() if value else None


def configure(gw, fixture):
    gw.config(fixture, "ipv6 unicast-routing", "interface Ethernet1", "no switchport")
    switchport = gw.show(fixture, "show interfaces Ethernet1 switchport")
    if "Switchport: Disabled" not in switchport:
        raise RuntimeError("cEOS Ethernet1 did not confirm routed mode before address assignment")
    gw.config(fixture,
              "interface Ethernet1", "ip address 10.77.0.1/30",
              "ipv6 address 2001:db8:77::1/64", "no shutdown",
              "interface Loopback0", "ip address 192.0.2.1/32",
              "ipv6 address 2001:db8:100::1/128", "no shutdown",
              "ip route 198.51.100.2/32 10.77.0.2",
              "ipv6 route 2001:db8:200::2/128 2001:db8:77::2")
    for argv in (
        ("ip", "link", "set", "eth1", "up"),
        ("ip", "addr", "add", "10.77.0.2/30", "dev", "eth1"),
        ("ip", "-6", "addr", "add", "2001:db8:77::2/64", "dev", "eth1"),
        ("ip", "addr", "add", "198.51.100.2/32", "dev", "lo"),
        ("ip", "-6", "addr", "add", "2001:db8:200::2/128", "dev", "lo"),
        ("ip", "route", "add", "192.0.2.1/32", "via", "10.77.0.1"),
        ("ip", "-6", "route", "add", "2001:db8:100::1/128", "via", "2001:db8:77::1"),
    ):
        gw.peer(fixture, *argv)
    for _attempt in range(20):
        rows = _json(gw.peer(fixture, "ip", "-j", "-6", "addr", "show"))
        address = next((info for link in rows for info in link.get("addr_info", [])
                        if info.get("local") == "2001:db8:77::2"), None)
        if address is not None and not address.get("tentative") and not address.get("dadfailed") \
                and "tentative" not in address.get("flags", []) and "dadfailed" not in address.get("flags", []):
            return
        time.sleep(0.5)
    raise RuntimeError("peer IPv6 link address did not leave tentative state before the baseline probes")


def collect_ribs(gw, fixture):
    from django.utils import timezone
    from core.services.troubleshooting import routing

    before = sum((values for values in gw.sequences.values()), [])
    r4 = routing.ceos_rib(_json(gw.show(fixture, "show ip route | json")), af="ipv4")
    r6 = routing.ceos_rib(_json(gw.show(fixture, "show ipv6 route | json")), af="ipv6")
    p4 = routing.linux_rib(_json(gw.peer(fixture, "ip", "-j", "-4", "route", "show")), "ipv4")
    p6 = routing.linux_rib(_json(gw.peer(fixture, "ip", "-j", "-6", "route", "show")), "ipv6")
    if any(value is None for value in (r4, r6, p4, p6)):
        raise RuntimeError("one or more fixture RIBs were unreadable")
    at = timezone.now()
    after = sum((values for values in gw.sequences.values()), [])
    return {"ribs": {"ipv4": {"r1": r4, "peer": p4}, "ipv6": {"r1": r6, "peer": p6}},
            "observed_at": at.isoformat(), "device_observed_at": {"r1": at.isoformat(), "peer": at.isoformat()},
            "collector": "authorized ceos_peer gateway fixture read-only RIB campaign",
            "gateway_evidence": after[len(before):]}


def traffic(gw, fixture):
    probes = {
        "r1_peer_v4": gw.show(fixture, "ping 198.51.100.2 source 10.77.0.1 repeat 3"),
        "r1_peer_v6": gw.show(fixture, "ping ipv6 2001:db8:200::2 source 2001:db8:77::1 repeat 3"),
        "return_v4": gw.show(fixture, "ping 198.51.100.2 source 192.0.2.1 repeat 3"),
        "return_v6": gw.show(fixture, "ping ipv6 2001:db8:200::2 source 2001:db8:100::1 repeat 3"),
    }
    return {name: _ping_ok(text) for name, text in probes.items()}


def campaign(gw, fixture, result, diagnosis_summary, hypothesis_title):
    from datetime import timedelta
    from django.test import Client
    from django.urls import reverse
    from django.utils import timezone
    from core import models, troubleshooting_views
    from core.services.troubleshooting import ai, faults, governance, intake, repository as repo, route_intent
    from core.tests.helpers.troubleshooting import ts_sign_in, ts_user

    snapshots = []
    service_telemetry = {}

    def reader(_intent, _cfg):
        snap = collect_ribs(gw, fixture)
        if service_telemetry:
            snap.update(service_telemetry=dict(service_telemetry), service_devices=["r1", "peer"])
        snapshots.append(snap)
        return snap

    dispatch_result = {}

    def governed_dispatch(handoff_id):
        handoff = models.TsAIHandoff.objects.get(record_id=handoff_id)
        diagnosis = {
            "conclude": {"outcome": "ROOT_CAUSE_SUPPORTED", "summary": diagnosis_summary,
                         "hypotheses": [{"title": hypothesis_title, "domain": "routing", "confidence": "high",
                                          "supporting": list(models.TsEvidenceRef.objects.filter(
                                              case=handoff.case, source_type="route_intent").values_list(
                                                  "evidence_id", flat=True)),
                                          "contradicting": []}]},
            "nonce": "fixture-conclusion-0001",
        }
        done = ai.investigate(repo.Actor("fixture-dispatcher", "system", tenant="default"), handoff_id,
                              lambda context: diagnosis,
                              ai.Runtime(runner=None, ports=governance.Ports(), clock=timezone.now), now=timezone.now())
        dispatch_result["handoff"] = done
        return done.status == "COMPLETED"

    def codex_handoff(actor, case, **fields):
        return ai.open_handoff(actor, case, **{**fields, "agent_identity": "codex"})

    deps = intake.IntakeDeps(run_case=lambda actor, case_id, runtime: None, open_handoff=codex_handoff,
                             dispatch=governed_dispatch,
                             notify=lambda subject, body: None, maintenance=lambda devices: "")
    engine = intake.Intake(
        cfg=intake.IntakeConfig(devices=(), routing_devices=(), routing_every=1, confirm_seconds=1,
                                route_intent_path=str(INTENT), topology_revision=TOPOLOGY_REVISION,
                                route_intent_max_age_seconds=60, verify_clear=False),
        reader=lambda device, cfg: [], deps=deps, _peers={}, route_reader=None,
        adjacency_reader=lambda device, cfg: [], route_intent_reader=reader,
    )

    gw.stage = "baseline"
    baseline_traffic = traffic(gw, fixture)
    healthy = engine.poll(timezone.now())
    baseline = snapshots[-1]["ribs"]
    if not all(baseline_traffic.values()) or healthy[0].get("route_intent") != "HEALTHY":
        raise RuntimeError(f"fixture baseline failed: traffic={baseline_traffic} intent={healthy}")

    gw.stage = "fault"
    gw.config(fixture, "no ip route 198.51.100.2/32 10.77.0.2")
    faulted = True
    try:
        first = engine.poll(timezone.now())
        fault_traffic = traffic(gw, fixture)
        service_telemetry.update(fault_traffic)
        time.sleep(1.2)
        opened = engine.poll(timezone.now() + timedelta(seconds=2))
        cases = [row for row in opened if row.get("case")]
        if len(cases) != 1:
            raise RuntimeError(f"expected one persisted route-intent case, got {opened}")
        row = cases[0]
        case = models.TsCase.objects.get(case_id=row["case"])
        actor = repo.Actor("fixture-campaign", "system", tenant=case.tenant, devices=frozenset({"r1"}))
        evidence = list(models.TsEvidenceRef.objects.filter(case=case).values_list("evidence_id", flat=True))
        route_ev = models.TsEvidenceRef.objects.get(case=case, source_type="route_intent")
        correlation = models.TsCorrelationRecord.objects.get(case=case)
        handoff = models.TsAIHandoff.objects.get(case=case)
        done = dispatch_result.get("handoff")
        if done is None:
            raise RuntimeError("normal intake dispatch did not execute the governed Codex handoff")
        case.refresh_from_db()
        principal = troubleshooting_views.Principal(actor, frozenset({"admin"}))
        detail = troubleshooting_views._detail(principal, case, governance.Ports(), timezone.now())
        viewer = ts_user("fixture-authenticated-admin", "ts-admin", "ts-tenant:default")
        client = Client()
        ts_sign_in(client, viewer, mfa_verified=True)
        response = client.get(reverse("core:troubleshooting_detail", kwargs={"case_id": case.case_id}))
        if response.status_code != 200:
            raise RuntimeError(f"authenticated case detail returned HTTP {response.status_code}")
        page = bytes(response.content)
        observation = models.TsObservation.objects.get(case=case, key="intake.route_intent@r1-peer-v4")
        decision = models.TsAuditEvent.objects.filter(case=case, action="REMEDIATION_DECISION").latest("seq")
        if observation.value["classification"]["evidence"].get("subtype") != "MISSING_ROUTE":
            raise RuntimeError("persisted route classification was not MISSING_ROUTE")
        if decision.result != faults.DIAGNOSE_AND_ESCALATE or done.status != "COMPLETED":
            raise RuntimeError("governed diagnosis/decision did not complete as expected")
        if models.TsRemediationPlan.objects.filter(case=case).exists():
            raise RuntimeError("route fault unexpectedly created a remediation plan")
        rendered = page.decode("utf-8", "replace")
        if case.case_id not in rendered or hypothesis_title not in rendered:
            raise RuntimeError("case detail did not render persisted diagnosis")
        result.update({"healthy": healthy, "fault_debounce": first, "case": case.case_id,
                       "handoff": handoff.record_id, "handoff_status": done.status,
                       "classification": "MISSING_ROUTE", "decision": decision.result,
                       "correlation": correlation.record_id, "evidence_ids": evidence,
                       "gateway_evidence_in_observation": observation.value.get("gateway_evidence"),
                       "fault_traffic": fault_traffic, "page_sha256": hashlib.sha256(page).hexdigest(),
                       "authenticated_case_page_status": response.status_code,
                       "page_evidence_count": detail["evidence_count"],
                       "remediation_plans": models.TsRemediationPlan.objects.filter(case=case).count()})
    finally:
        if faulted:
            gw.stage = "restore"
            gw.config(fixture, "ip route 198.51.100.2/32 10.77.0.2")

    gw.stage = "postcheck"
    restored = collect_ribs(gw, fixture)["ribs"]
    restored_traffic = traffic(gw, fixture)
    evaluated = route_intent.evaluate(route_intent.load(INTENT), restored, now=timezone.now())
    prefixes = (("ipv4", "r1", "198.51.100.2/32"), ("ipv6", "r1", "2001:db8:200::2/128"),
                ("ipv4", "peer", "192.0.2.1/32"), ("ipv6", "peer", "2001:db8:100::1/128"))
    exact = all(_entry(baseline, *item) == _entry(restored, *item) for item in prefixes)
    result.update({"baseline_traffic": baseline_traffic, "restored_traffic": restored_traffic,
                   "route_baseline_restored_exactly": exact,
                   "postcheck_all_intent_healthy": all(item.category == faults.NO_FAULT for item in evaluated),
                   "audit_chain": repo.verify_audit_chain(models.TsCase.objects.get(case_id=result["case"]))})


def passed(result):
    return bool(result.get("classification") == "MISSING_ROUTE"
                and result.get("decision") == "DIAGNOSE_AND_ESCALATE"
                and result.get("handoff_status") == "COMPLETED"
                and result.get("remediation_plans") == 0
                and result.get("route_baseline_restored_exactly")
                and result.get("postcheck_all_intent_healthy")
                and all((result.get("baseline_traffic") or {}).values())
                and all((result.get("restored_traffic") or {}).values())
                and not result.get("audit_chain") and not result.get("error"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", required=True, help="gateway source pin for this exact candidate tree")
    parser.add_argument("--fixture", help="ready caller-owned ceos_peer fixture; otherwise start and stop one")
    parser.add_argument("--out")
    parser.add_argument("--diagnosis-summary", required=True,
                        help="bounded Codex inference to submit through the governed handoff")
    parser.add_argument("--hypothesis-title", required=True,
                        help="bounded Codex root-cause hypothesis to cite to the stored route evidence")
    args = parser.parse_args()
    import django
    django.setup()
    from django.test.runner import DiscoverRunner
    from django.test.utils import setup_test_environment, teardown_test_environment
    from aiorch_gw import Gateway

    gateway = RecordedGateway(Gateway(), args.pin)
    result = {"schema": "nmas.route-intent-fixture-acceptance/1", "pin_id": args.pin,
              "topology_revision": TOPOLOGY_REVISION, "fixture_owned": not bool(args.fixture),
              "production_changes": False}
    fixture, runner, old = args.fixture, None, None
    try:
        if not fixture:
            fixture = gateway.call("fixture_start", template="ceos_peer", ttl_seconds=1200)["fixture_id"]
            gateway.gateway.wait("fixture_status", "fixture_id", fixture, ("starting",), interval=10, timeout=900)
        result["fixture_id"] = fixture
        setup_test_environment()
        runner = DiscoverRunner(verbosity=0, interactive=False)
        old = runner.setup_databases()
        configure(gateway, fixture)
        campaign(gateway, fixture, result, args.diagnosis_summary, args.hypothesis_title)
        result["source_manifest"] = gateway.call("evidence_manifest", fixture_id=fixture, pin_id=args.pin)
    except Exception as exc:  # noqa: BLE001 -- acceptance artifact must retain the exact failed stage
        result["error"] = f"{type(exc).__name__}: {str(exc)[:500]}"
        result["error_trace"] = traceback.format_exc()[-2000:]
    finally:
        if runner is not None and old is not None:
            runner.teardown_databases(old)
            teardown_test_environment()
        if result["fixture_owned"] and fixture:
            try:
                result["fixture_stop"] = gateway.call("fixture_stop", fixture_id=fixture)
            except Exception as exc:  # noqa: BLE001
                result["fixture_stop_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
        result["gateway_evidence"] = gateway.sequences
        gateway.gateway.close()
    text = json.dumps(result, sort_keys=True, default=str)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if passed(result) else 1


if __name__ == "__main__":
    raise SystemExit(main())
