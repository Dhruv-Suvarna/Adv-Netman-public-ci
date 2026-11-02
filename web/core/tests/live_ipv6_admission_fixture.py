"""V2 Phase 9 (D) LIVE harness -- IPv6 admission: OSPFv3 on the bootstrap port suppressed by isolation, a natively onboarded cEOS
commissioned with IPv6 addressing and OSPFv3 from Device Builder intent, and a dual-stack admission verified by OSPFv3 adjacency,
IPv6 routes learned through the released port and IPv6 reachability.

The Phases 5 + 6 harness (``live_isolation_commissioning_fixture``) on the same disposable fixture, started with
``NMAS_ISO_FX_OSPF6=on`` (UP1 runs OSPFv3 on bootstrap port A, its core link and loopback; CORE on the UP1 link and the
production LAN).  NOT part of any automated suite.  Run through ``labs/isolation-commissioning-isolated/run-harness.sh`` with
``NMAS_LIVE_MODULE=core.tests.live_ipv6_admission_fixture``:

    prepare isolate ztp onboard     as in Phases 5 + 6; the isolation plan now carries ``ipv6 router ospf 1 / passive-interface
                                    Ethernet1`` (UP1 runs OSPFv3 on the port) and its verification reads the OSPFv3 neighbour table
    commission                      NEW1's intent adds 2001:db8:254:60::10/64 (uplink), 2001:db8:254:255::11/128 (loopback) and
                                    OSPFv3 process 1 (uplink; loopback passive); the planner puts ``ipv6 unicast-routing`` before it
    v6-isolated                     NEW1 runs OSPFv3 on its uplink, UP1 forms no OSPFv3 adjacency and learns no IPv6 route from it;
                                    isolation re-verified (routing finding includes the OSPFv3 table)
    admit-fail                      a dual-stack admission expecting an IPv6 route NEW1 never advertises: released, verification
                                    fails on routes_v6, every removed statement (OSPFv3 passive included) restored, isolation re-verified
    admit                           the dual-stack admission: OSPF and OSPFv3 FULL with NEW1 on Ethernet1, IPv4 and IPv6 routes
                                    learned through it, IPv4 and IPv6 reachability from UP1; ADMITTED / IN_SERVICE
    v6-admitted                     production (PROD, behind CORE) reaches NEW1's IPv6 loopback; CORE learned it over OSPFv3
    report                          the evidence index

Evidence goes to ``NMAS_ISO_LIVE_EVIDENCE`` (runtime/ by default); the committed copy is docs/evidence/v2-phase9-closure/ipv6-admission.
"""

from __future__ import annotations

import json
import os

from core import models
from core.tests import live_isolation_commissioning_fixture as P56
from core.tests.live_isolation_commissioning_fixture import APPROVER, FX, NEW1_LOOPBACK, NEW1_ROUTER_ID, cli, evidence, running, wait_for

NEW1_UPLINK_V6, NEW1_LOOPBACK_V6 = "2001:db8:254:60::10/64", "2001:db8:254:255::11/128"
NEW1_V6 = NEW1_LOOPBACK_V6.split("/", 1)[0]
NEVER_ADVERTISED_V6 = "2001:db8:254:250::/64"


def ospf6_table(node: str) -> dict:
    """The node's ``show ipv6 ospf neighbor | json`` (empty dict when unreadable)."""
    try:
        return json.loads(cli(node, "show ipv6 ospf neighbor | json") or "{}")
    except ValueError:
        return {}


def ospf6_rows(node: str, interface: str = "Ethernet1") -> list[dict]:
    from core.services.isolation import eos

    return eos.ospf6_neighbors_on(json.dumps(ospf6_table(node)), interface) or []


class Run(P56.Harness):
    def new1_intent(self, dev) -> dict:
        declared = super().new1_intent(dev)
        uplink, loopback = dev.current_iface(declared["uplink"]["id"]), dev.current_iface(declared["loopback"]["id"])
        dev.address(uplink, NEW1_UPLINK_V6)
        dev.address(dev.current_iface(loopback["id"]), NEW1_LOOPBACK_V6)
        ospf6 = dev.ospf(version="OSPFV3", router_id=NEW1_ROUTER_ID, process_id=1)
        dev.bind("ospf", ospf6, dev.current_iface(uplink["id"]), area="0.0.0.0")
        dev.bind("ospf", ospf6, dev.current_iface(loopback["id"]), area="0.0.0.0", passive=True)
        return declared

    def admit_fail_expectations(self) -> dict:
        return {"routing": "OSPF", "ospf_neighbors": [NEW1_ROUTER_ID], "ospfv3_neighbors": [NEW1_ROUTER_ID],
                "routes_v4": [NEW1_LOOPBACK], "routes_v6": [NEW1_LOOPBACK_V6, NEVER_ADVERTISED_V6], "reachable": [NEW1_ROUTER_ID, NEW1_V6]}

    def admit_expectations(self) -> dict:
        return {"routing": "OSPF", "ospf_neighbors": [NEW1_ROUTER_ID], "ospfv3_neighbors": [NEW1_ROUTER_ID],
                "routes_v4": [NEW1_LOOPBACK, "10.254.64.0/24"], "routes_v6": [NEW1_LOOPBACK_V6], "reachable": [NEW1_ROUTER_ID, NEW1_V6]}

    def stage_commission(self):
        super().stage_commission()
        new1 = self.device("NEW1")
        run = models.ProvisioningRun.objects.filter(device_name="NEW1").order_by("-id").first()
        configlets = [{"cfg_id": c.cfg_id, "object_type": (c.desired_state_ref or {}).get("source", {}).get("object_type"),
                       "lines": c.rendered_config.splitlines()} for c in run.plan.configlets.order_by("sequence")]
        ipv6 = [c for c in configlets if any("ipv6" in line for line in c["lines"])]
        assert any(c["lines"][:1] == ["ipv6 unicast-routing"] and any(l.startswith("ipv6 router ospf 1") for l in c["lines"]) for c in ipv6), ipv6
        evidence("v6-40-commission-ipv6-configlets.json", {"device": new1.device_id, "provisioning_run": run.prov_id,
                                                            "ipv6_configlets": ipv6})

    def stage_v6_isolated(self):
        from core.services.isolation import service as isolation

        new1 = self.device("NEW1")
        policy = self.policy(new1)
        record = {"policy": isolation.status(policy)}
        record["up1_ospf6_process"] = cli("up", "show running-config section ipv6 router ospf")
        assert "passive-interface Ethernet1" in record["up1_ospf6_process"], record["up1_ospf6_process"]
        record["new1_ospf6_interface"] = cli("new1", "show ipv6 ospf interface Ethernet1")
        record["new1_runs_ospf6_on_uplink"] = "Ethernet1" in record["new1_ospf6_interface"]
        record["new1_ipv6_routing"] = cli("new1", "show running-config | include ipv6 unicast-routing")
        record["up1_ospf6_neighbors_json"] = ospf6_table("up")
        record["up1_ospf6_neighbors_on_port"] = ospf6_rows("up")
        record["up1_route_to_new1_v6"] = cli("up", f"show ipv6 route {NEW1_V6}")
        assert record["new1_runs_ospf6_on_uplink"] and "ipv6 unicast-routing" in record["new1_ipv6_routing"], record
        assert record["up1_ospf6_neighbors_on_port"] == [], record["up1_ospf6_neighbors_on_port"]
        self.serve()
        verified = isolation.verify(policy, actor=APPROVER, traffic=self.traffic("new1"), with_device=True)
        record["reverified"] = {"ok": verified.ok, "codes": verified.codes, "flows": self.last_flows}
        assert verified.ok, verified.codes
        evidence("v6-45-isolated-ospfv3-suppressed.json", record)

    def stage_admit_fail(self):
        super().stage_admit_fail()
        record = {"up1_ospf6_process_after_restore": cli("up", "show running-config section ipv6 router ospf"),
                  "up1_ospf6_adjacency_gone": bool(wait_for(lambda: ospf6_rows("up") == [], timeout=60)),
                  "up1_ospf6_neighbors_on_port": ospf6_rows("up"), "up1_route_to_new1_v6": cli("up", f"show ipv6 route {NEW1_V6}")}
        assert "passive-interface Ethernet1" in record["up1_ospf6_process_after_restore"] and record["up1_ospf6_adjacency_gone"], record
        evidence("v6-50-restored-ospfv3-passive.json", record)

    def stage_v6_admitted(self):
        new1 = self.device("NEW1")
        new1.refresh_from_db()
        record = {"device": {"lifecycle": new1.lifecycle_state, "admission": new1.admission_state}}
        record["up1_ospf6_neighbors_on_port"] = ospf6_rows("up")
        record["up1_ospf6_process"] = cli("up", "show running-config section ipv6 router ospf")
        record["up1_route_to_new1_v6"] = cli("up", f"show ipv6 route {NEW1_V6}")
        record["core_route_to_new1_v6"] = wait_for(lambda: (lambda out: out if NEW1_V6 in out and "O3" in out else "")(
            cli("core", f"show ipv6 route {NEW1_V6}")), timeout=90) or cli("core", f"show ipv6 route {NEW1_V6}")
        record["production_to_new1_v6_loopback"] = self.ping([str(FX / "fixture.sh"), "prod"], NEW1_V6)
        record["production_to_new1_v6_uplink"] = self.ping([str(FX / "fixture.sh"), "prod"], NEW1_UPLINK_V6.split("/")[0])
        record["new1_ospf6_neighbors"] = ospf6_rows("new1")
        record["new1_running"] = running("new1")
        assert record["device"]["admission"] == models.ProductionAdmissionState.ADMITTED, record["device"]
        assert any(r["neighbor"] == NEW1_ROUTER_ID and r["state"].lower() == "full" for r in record["up1_ospf6_neighbors_on_port"]), record
        assert "passive-interface Ethernet1" not in record["up1_ospf6_process"], record["up1_ospf6_process"]
        assert "O3" in record["core_route_to_new1_v6"] and record["production_to_new1_v6_loopback"], record
        evidence("v6-60-admitted-ipv6-reachability.json", record)

    def stage_report(self):
        super().stage_report()
        evidence("v6-99-index.json", {"files": sorted(p.name for p in P56.EVIDENCE.glob("*") if p.is_file()),
                                      "fixture": "labs/isolation-commissioning-isolated with NMAS_ISO_FX_OSPF6=on (cEOS 4.36.2F)",
                                      "transport": "CeosExecutor over SSH as nmas-svc (key only, pinned host key) from the bootstrap-service "
                                                   "namespace; the fixture console (docker exec Cli) only observes"})


STAGES = ("prepare", "isolate", "ztp", "onboard", "commission", "v6-isolated", "admit-fail", "admit", "v6-admitted", "report")


def main():
    stages = os.environ.get("NMAS_ISO_LIVE_STAGES", "").split()
    unknown = [s for s in stages if s not in STAGES]
    if not stages or unknown:
        raise SystemExit(f"stages: {' '.join(STAGES)} (unknown: {unknown})")
    harness = Run()
    try:
        for stage in stages:
            print(f"[stage] {stage}", flush=True)
            getattr(harness, "stage_" + stage.replace("-", "_"))()
    finally:
        if harness.http is not None:
            harness.http.shutdown()
