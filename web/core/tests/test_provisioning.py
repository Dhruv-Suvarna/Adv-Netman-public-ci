"""V2 Phase 5A -- new-device provisioning.  Everything runs on fakes: no device, no NetBox, no Docker.

The workflow under test drives the REAL Change pipeline (intent, both validations, the plan builder, the precheck, the execution engine and
its postcheck, the bundle chain and the soak start); only device / NetBox I/O is simulated.
"""

from __future__ import annotations

from datetime import timedelta

from core.services.test_governance.cases import NEGATIVE, case
from django.test import TestCase, override_settings

from core import models
from core.services import bundle_service, execution_service as es, provisioning_service as ps
from core.services.health import inventory
from core.services.provisioning import bootstrap, capability_gate, ipam, registry
from core.tests.helpers import execution as ex, provisioning as p
from core.tests.helpers.validation import Dev, make_sources, new_change

S = models.ProvisioningStatus


class RequestConflictTests(TestCase):
    def test_inventory_endpoint_and_unmanaged_names_are_refused(self):
        for name in ("R1", "R5", "H1", "H4", "WebServer", "mgmt_swt"):
            result = ps.create_request(device_name=name, platform=p.FRR, role="router", requested_by="op")
            self.assertEqual(result.codes, ["NAME_CONFLICT"], name)
        self.assertEqual(models.ProvisioningRun.objects.count(), 0)

    def test_invalid_identity_is_refused_without_a_row(self):
        self.assertEqual(ps.create_request(device_name="bad name!", platform=p.FRR, role="router", requested_by="op").codes, ["NAME_INVALID"])
        self.assertEqual(ps.create_request(device_name="X1", platform="junos", role="router", requested_by="op").codes, ["PLATFORM_UNKNOWN"])
        self.assertEqual(ps.create_request(device_name="X1", platform=p.FRR, role="firewall", requested_by="op").codes, ["ROLE_INVALID"])
        self.assertEqual(models.ProvisioningRun.objects.count(), 0)

    def test_one_live_request_per_device_name(self):
        first = ps.create_request(device_name="EDGE1", platform=p.FRR, role="router", requested_by="op")
        again = ps.create_request(device_name="EDGE1", platform=p.FRR, role="router", requested_by="op")
        self.assertTrue(first.ok)
        self.assertEqual(again.codes, ["NAME_CONFLICT"])
        ps.cancel(first.run, actor="op")
        self.assertTrue(ps.create_request(device_name="EDGE1", platform=p.FRR, role="router", requested_by="op").ok)

    def test_netbox_and_registry_name_conflicts_block_ipam(self):
        lab = p.Lab(gateway=p.FakeGateway(devices={"EDGE1"}))
        self.assertEqual(lab.through("ipam").codes, ["NAME_CONFLICT"])
        self.assertEqual(lab.gateway.objects, {})
        self.assertEqual(lab.run.status, S.CAPABILITY_RESOLVED)


class IdentityAndVlanPolicyTests(TestCase):
    def test_vlan200_is_never_dhcp_or_dhcpv6(self):
        for assignment in ("dhcp", "dhcpv6"):
            lab = p.Lab(name=f"SW{assignment}", disposable=False)
            result = lab.identity(management={"interface": "Vlan200", "vlan": 200, "ipv4": "192.168.200.50/24",
                                              "ipv6": "2001:db8:200::50/64", "assignment": assignment})
            self.assertEqual(result.codes, ["VLAN200_DHCP_FORBIDDEN"])
            self.assertEqual(lab.run.status, S.DRAFT)

    def test_vlan200_address_is_detected_without_a_vlan_number(self):
        lab = p.Lab(disposable=False)
        result = lab.identity(management={"interface": "eth9", "ipv4": "192.168.200.50/24", "assignment": "dhcp"})
        self.assertEqual(result.codes, ["VLAN200_DHCP_FORBIDDEN"])

    def test_vlan200_needs_static_ipv4_and_ipv6(self):
        lab = p.Lab(disposable=False)
        self.assertEqual(lab.identity(management={"interface": "Vlan200", "vlan": 200, "ipv4": "192.168.200.50/24"}).codes,
                         ["VLAN200_DUAL_STACK_REQUIRED"])
        ok = lab.identity(management={"interface": "Vlan200", "vlan": 200, "ipv4": "192.168.200.50/24", "ipv6": "2001:db8:200::50/64"})
        self.assertTrue(ok.ok)

    def test_a_disposable_device_never_takes_a_production_management_address(self):
        lab = p.Lab()
        result = lab.identity(management={"interface": "eth0", "ipv4": "192.168.200.50/24", "ipv6": "2001:db8:200::50/64"})
        self.assertEqual(result.codes, ["DISPOSABLE_IN_PRODUCTION_MANAGEMENT"])

    def test_malformed_management_and_secret_shaped_input_are_refused(self):
        lab = p.Lab()
        self.assertEqual(lab.identity(management={"interface": "eth0", "ipv4": "172.31.250.11"}).codes, ["MANAGEMENT_ADDRESS_INVALID"])
        self.assertEqual(lab.identity(management={"interface": "eth0", "ipv4": "fd00::1/64"}).codes, ["MANAGEMENT_ADDRESS_INVALID"])
        self.assertEqual(lab.identity(target={**p.TARGET, "password": "hunter2"}).codes, ["SECRET_SHAPED_INPUT"])
        self.assertEqual(lab.run.bootstrap_target, {})

    def test_production_lab_targets_are_refused(self):
        lab = p.Lab()
        for target in ({"container": "clab-srlceos01-R5", "lab": "other"}, {"container": "anything", "lab": "srlceos01"}):
            self.assertEqual(lab.identity(target=target).codes, ["BOOTSTRAP_TARGET_IS_PRODUCTION"])
        self.assertEqual(lab.identity(target={"container": "bad name", "lab": "x"}).codes, ["BOOTSTRAP_TARGET_INVALID"])

    def test_stages_cannot_be_skipped(self):
        lab = p.Lab()
        self.assertEqual(lab.capability().codes, ["WRONG_STAGE"])
        self.assertEqual(lab.ipam().codes, ["WRONG_STAGE"])
        self.assertEqual(lab.run.status, S.DRAFT)
        self.assertEqual([e.outcome for e in lab.run.events.all()], ["BLOCKED", "BLOCKED"])


class BootstrapStateTests(TestCase):
    def test_reachable_bootstrap_device(self):
        lab = p.Lab()
        self.assertTrue(lab.through("bootstrap").ok)
        self.assertEqual(lab.run.bootstrap_state, models.BootstrapState.REACHABLE_BOOTSTRAP)

    def test_already_configured_device_is_onboarding_not_provisioning(self):
        lab = p.Lab()
        result = lab.through("bootstrap", configured=True)
        self.assertEqual(result.codes, ["DEVICE_ALREADY_CONFIGURED"])
        self.assertEqual(lab.run.bootstrap_state, models.BootstrapState.ALREADY_CONFIGURED)
        self.assertEqual(lab.run.status, S.IDENTIFIED)

    def test_unreachable_device_is_staged_but_never_executed(self):
        lab = p.Lab()
        lab.through("bootstrap", exists=False, running=False, answers=False, lab="")
        self.assertEqual(lab.run.bootstrap_state, models.BootstrapState.UNREACHABLE)
        for step in ("capability", "ipam", "candidate"):
            self.assertTrue(getattr(lab, step)().ok, step)
        lab.intent()
        self.assertTrue(lab.validate().ok)
        self.assertTrue(lab.plan().ok)
        self.assertEqual(lab.precheck().codes, ["DEVICE_UNREACHABLE"])     # honest staging: planned and reserved, not executable
        self.assertEqual(lab.run.status, S.PLANNED)
        self.assertEqual(lab.world.mutating_calls(), [])
        self.assertTrue(lab.bootstrap().ok)                                 # the device came up: re-probe without re-walking the stages
        self.assertEqual(lab.run.status, S.PLANNED)
        self.assertTrue(lab.precheck().ok)

    def test_probe_in_another_or_the_production_lab_is_refused(self):
        lab = p.Lab()
        self.assertEqual(lab.through("bootstrap", lab="srlceos01").codes, ["BOOTSTRAP_TARGET_IS_PRODUCTION"])
        self.assertEqual(lab.bootstrap(lab="some-other-lab").codes, ["BOOTSTRAP_TARGET_INVALID"])
        self.assertEqual(lab.run.status, S.IDENTIFIED)

    def test_kernel_configuration_counts_as_already_configured(self):
        # Found by the live proof: NMAS configures Linux loopbacks / addresses with iproute2, which the FRR running-config never shows.
        pristine = [{"ifname": "lo", "addr_info": [{"scope": "host"}]},
                    {"ifname": "eth0", "addr_info": [{"scope": "global"}, {"scope": "link"}]},
                    {"ifname": "eth1", "addr_info": [{"scope": "link"}]}]
        self.assertEqual(bootstrap.configured_interfaces(pristine, "eth0"), [])
        dummy = [*pristine, {"ifname": "loopback10", "linkinfo": {"info_kind": "dummy"}, "addr_info": []}]
        self.assertEqual(bootstrap.configured_interfaces(dummy, "eth0"), ["loopback10"])
        addressed = [*pristine[:2], {"ifname": "eth1", "addr_info": [{"scope": "global"}]}]
        self.assertEqual(bootstrap.configured_interfaces(addressed, "eth0"), ["eth1"])
        self.assertEqual(bootstrap.configured_interfaces(pristine, "eth9"), ["eth0"])     # an address on an undeclared interface counts

    def test_prober_is_told_the_declared_management_interface(self):
        seen = {}
        lab = p.Lab()
        lab.identity()
        ps.classify_bootstrap(lab.run, actor="t", prober=lambda target: seen.update(target) or bootstrap.Probe(
            exists=True, running=True, lab=p.TARGET["lab"], answers=True))
        self.assertEqual(seen["management_interface"], "eth0")

    def test_one_container_is_one_device(self):
        first = p.Lab()
        first.through("candidate")                       # EDGE1 now owns the container in the registry
        second = p.Lab(name="EDGE2", supported=(), management={"interface": "eth0", "ipv4": "172.31.250.12/24"})
        self.assertEqual(second.identity().codes, ["BOOTSTRAP_TARGET_IN_USE"])
        self.assertEqual(second.run.status, S.DRAFT)
        third = p.Lab(name="EDGE3", supported=(), management={"interface": "eth0", "ipv4": "172.31.250.13/24"})
        self.assertTrue(third.identity(target={"container": "clab-nmas-prov-proof-other", "lab": "nmas-prov-proof"}).ok)

    def test_default_prober_refuses_a_malformed_container_without_spawning(self):
        self.assertEqual(bootstrap.docker_prober({"container": "a b; rm -rf /"}).error, "TARGET_INVALID")


class CapabilityGateTests(TestCase):
    def test_platform_without_a_proven_bootstrap_transport_fails_closed(self):
        # cEOS has a renderer AND an executor; neither is bootstrap support for a device with no inventory credentials.
        lab = p.Lab(platform=models.Platform.ARISTA_CEOS, supported=())
        p.support(models.Platform.ARISTA_CEOS, "interface.LOOPBACK")
        result = lab.identity(transport="SSH")
        self.assertEqual(result.codes, ["BOOTSTRAP_TRANSPORT_UNSUPPORTED"])
        self.assertIn("credential", result.blockers[0]["details"]["reason"])

    def test_platform_with_no_supported_cell_fails_closed(self):
        lab = p.Lab(supported=())
        result = lab.through("capability")
        self.assertEqual(result.codes, ["CAPABILITY_UNSUPPORTED"])
        self.assertEqual(lab.run.status, S.BOOTSTRAP_CLASSIFIED)

    def test_renderer_only_feature_blocks_the_plan_and_names_the_cell(self):
        lab = p.Lab()                                   # only interface.LOOPBACK is SUPPORTED
        lab.through("candidate")
        dev = p.ProvDev(lab.run.change, lab.name)
        dev.address(dev.iface("eth1", kind="ROUTED_PHYSICAL"), "192.0.2.1/31")
        self.assertTrue(lab.validate().ok)              # it renders and validates ...
        result = lab.plan()                             # ... and is still refused: a renderer is not support
        self.assertEqual(set(result.codes), {"CAPABILITY_UNSUPPORTED"})
        details = result.blockers[0]["details"]
        self.assertEqual((details["feature"], details["platform"]), ("interface.ROUTED_PHYSICAL", p.FRR))
        self.assertTrue(details["reason"])
        self.assertEqual(lab.run.status, S.VALIDATED)
        self.assertEqual(lab.run.candidate_hash, "")

    def test_supported_plan_records_the_resolved_cells(self):
        lab = p.Lab()
        self.assertTrue(lab.through("plan").ok)
        cells = lab.run.capability_resolution["plan"]["cells"]
        self.assertEqual([(c["feature"], c["status"]) for c in cells], [("interface.LOOPBACK", "SUPPORTED")])
        self.assertEqual(len(lab.run.candidate_hash), 64)
        self.assertIn("loopback10", lab.run.candidate_config)

    def test_unclassified_configlet_is_refused(self):
        lab = p.Lab()
        lab.through("plan")
        plan = lab.run.plan
        configlet = plan.configlets.first()
        ref = dict(configlet.desired_state_ref)
        ref["source"] = {**ref["source"], "capability_feature": ""}
        models.Configlet.objects.filter(pk=configlet.pk).update(desired_state_ref=ref)
        _resolution, blockers = capability_gate.resolve_plan(p.FRR, plan)
        self.assertEqual([b["code"] for b in blockers], ["CAPABILITY_UNCLASSIFIED"])


class IpamTests(TestCase):
    def test_duplicate_management_address_in_netbox(self):
        lab = p.Lab(gateway=p.FakeGateway(addresses={"172.31.250.11": "OTHER"}))
        result = lab.through("ipam")
        self.assertEqual(result.codes, ["MGMT_IP_DUPLICATE"])
        self.assertEqual(lab.gateway.objects, {})

    def test_duplicate_of_an_inventory_management_address(self):
        lab = p.Lab(disposable=False, management={"interface": "Vlan200", "vlan": 200, "ipv4": "192.168.200.3/24", "ipv6": "2001:db8:200::77/64"},
                    gateway=p.FakeGateway(prefixes=["192.168.200.0/24", "2001:db8:200::/64"]))
        self.assertEqual(lab.through("ipam").codes, ["MGMT_IP_DUPLICATE"])

    def test_prefix_rules(self):
        management = {"interface": "eth0", "ipv4": "10.99.0.5/24"}
        unknown = p.Lab(name="A1", disposable=False, management=management, target={**p.TARGET, "container": "clab-nmas-prov-proof-a1"})
        self.assertEqual(unknown.through("ipam").codes, ["PREFIX_NOT_IN_IPAM"])
        mismatch = p.Lab(name="A2", disposable=False, management=management, supported=(), target={**p.TARGET, "container": "clab-nmas-prov-proof-a2"}, gateway=p.FakeGateway(prefixes=["10.99.0.0/23"]))
        self.assertEqual(mismatch.through("ipam").codes, ["PREFIX_LENGTH_MISMATCH"])
        pool = p.Lab(name="A3", disposable=False, management=management, supported=(), target={**p.TARGET, "container": "clab-nmas-prov-proof-a3"},
                     gateway=p.FakeGateway(prefixes=["10.99.0.0/24"], dhcp_ranges=[("10.99.0.2", "10.99.0.50")]))
        self.assertEqual(pool.through("ipam").codes, ["DHCP_POOL_CONFLICT"])

    def test_reservation_records_exactly_what_it_created(self):
        lab = p.Lab()
        self.assertTrue(lab.through("ipam").ok)
        created = lab.run.netbox["created"]
        self.assertEqual([c["kind"] for c in created], ["prefix", "prefix", "device", "interface", "ip_address", "ip_address"])
        self.assertEqual(lab.gateway.objects[lab.run.netbox["device_id"]]["status"], "planned")
        self.assertEqual(lab.run.planned_addresses[0]["address"], "172.31.250.11/24")
        self.assertEqual(lab.gateway.objects[lab.run.netbox["device_id"]]["provenance"]["prov_id"], lab.run.prov_id)

    def test_failed_reservation_is_rolled_back_transactionally(self):
        lab = p.Lab()
        lab.gateway.fail_on = "ip_address"
        result = lab.through("ipam")
        self.assertEqual(result.codes, ["IPAM_RESERVATION_FAILED"])
        self.assertEqual(lab.gateway.objects, {})                       # nothing half-reserved is left behind
        self.assertTrue(result.event.evidence["clean"])
        self.assertEqual(lab.run.status, S.CAPABILITY_RESOLVED)
        self.assertEqual(lab.run.netbox, {})

    def test_a_leftover_after_a_failed_rollback_is_reported_not_hidden(self):
        lab = p.Lab()
        lab.gateway.fail_on, lab.gateway.fail_delete = "ip_address", {"device"}
        result = lab.through("ipam")
        self.assertFalse(result.event.evidence["clean"])
        self.assertEqual(lab.gateway.kinds(), ["device"])
        self.assertEqual([r["kind"] for r in result.event.evidence["released"] if not r["released"]], ["device"])

    def test_netbox_unavailable_reserves_nothing(self):
        lab = p.Lab(gateway=p.FakeGateway(available=False))
        self.assertEqual(lab.through("ipam").codes, ["IPAM_UNAVAILABLE"])

    def test_existing_allocations_are_never_modified(self):
        gateway = p.FakeGateway(devices={"R1"}, addresses={"192.168.200.1": "R1"}, prefixes=["192.168.200.0/24"])
        before = (set(gateway.devices), dict(gateway.addresses), list(gateway.prefixes))
        lab = p.Lab(gateway=gateway)
        lab.through("sync")
        ps.decommission(lab.run, actor="op", gateway=gateway)
        self.assertEqual((set(gateway.devices), dict(gateway.addresses), list(gateway.prefixes)), before)
        self.assertEqual(gateway.objects, {})


class PlanApprovalTests(TestCase):
    def test_empty_intent_cannot_be_validated(self):
        lab = p.Lab()
        lab.through("candidate")
        self.assertEqual(lab.validate().codes, ["INTENT_EMPTY"])

    def test_candidate_is_an_ordinary_new_device_change(self):
        lab = p.Lab()
        lab.through("candidate")
        change = lab.run.change
        self.assertEqual(change.category, models.ChangeCategory.NEW_DEVICE_PROVISIONING)
        intent = change.device_intents.get()
        self.assertEqual((intent.device_name, intent.target_type), ("EDGE1", models.DeviceIntentTargetType.NEW_DEVICE))
        self.assertEqual(change.metadata["provisioning"]["prov_id"], lab.run.prov_id)

    def test_approval_binds_the_exact_candidate(self):
        lab = p.Lab()
        lab.through("precheck")
        self.assertEqual(lab.approve(confirm="0" * 64).codes, ["APPROVAL_CONFIRMATION_MISMATCH"])
        self.assertEqual(lab.run.status, S.PRECHECKED)
        self.assertTrue(lab.approve().ok)
        approval = lab.run.approval
        self.assertEqual((approval["approved_by"], approval["candidate_hash"]), ("approver", lab.run.candidate_hash))
        self.assertEqual(approval["plan_id"], str(lab.run.plan.plan_id))

    @override_settings(PROVISIONING_REQUIRE_SEPARATE_APPROVER=True)
    def test_separate_approver_policy(self):
        lab = p.Lab()
        lab.through("precheck")
        self.assertEqual(lab.approve(actor="requester").codes, ["APPROVAL_SELF"])
        self.assertTrue(lab.approve(actor="someone-else").ok)

    def test_approval_goes_stale_when_the_candidate_changes(self):
        lab = p.Lab()
        lab.through("approve")
        dev = p.ProvDev(lab.run.change, lab.name)
        dev.address(dev.iface("loopback11", kind="LOOPBACK"), "198.51.100.11/32")
        from core.services import change_plan_service as cps, change_validation_service as cvs, network_config_validation as ncv
        ncv.validate_candidate(lab.run.change, actor="t", sources=lab.sources)
        cvs.validate_change(lab.run.change, actor="t", sources=lab.sources, network_validated=True)
        cps.build_change_plan(lab.run.change, actor="t", sources=lab.sources)
        result = lab.provision()
        self.assertIn("PROVISIONING_APPROVAL_STALE", result.codes)      # refused by the ENGINE's own gate
        self.assertEqual(lab.world.mutating_calls(), [])
        self.assertEqual(lab.run.status, S.APPROVED)


class PlanBuilderRefusalTests(TestCase):
    """Lab 7 (found by the Pylint gate, redundant-keyword-arg): a plan-builder refusal that carries a stable ``code`` must be
    reported as the PLAN_NOT_CURRENT blocker.  Before the fix the blocker call passed ``code`` twice and raised TypeError,
    turning a clean refusal into a crash."""

    @case("PROVISIONING_PLAN_BUILDER_REFUSAL_IS_A_BLOCKER", target="web/core/services/provisioning/lifecycle.py::build_plan",
          polarity=NEGATIVE, condition="the Change plan builder refuses with a stable error code during the provisioning plan stage",
          expected="StageResult refused with PLAN_NOT_CURRENT (reason + plan_code recorded); no plan, no crash",
          requirement="fail closed with evidence instead of an unhandled TypeError")
    def test_a_plan_builder_refusal_is_recorded_not_raised(self):
        from unittest import mock

        from core.services import change_plan_service as cps
        from core.services.provisioning import lifecycle

        class PlanError(Exception):
            code = "PLAN_PRECONDITION"

        lab = p.Lab()
        lab.through("validate")
        with mock.patch.object(cps, "build_change_plan", side_effect=PlanError("refused")):
            result = lifecycle.build_plan(lab.run, actor="tester", sources=lab.sources)
        self.assertFalse(result.ok)
        self.assertEqual(result.codes, ["PLAN_NOT_CURRENT"])
        self.assertEqual(result.blockers[0]["details"], {"reason": "PlanError", "plan_code": "PLAN_PRECONDITION"})
        lab.run.refresh_from_db()
        self.assertIsNone(lab.run.plan)


class ProvisionTests(TestCase):
    def test_successful_provisioning_end_to_end(self):
        lab = p.Lab()
        result = lab.through("sync")
        self.assertTrue(result.ok)
        run = lab.run
        self.assertEqual(run.status, S.NSOT_SYNCED)
        self.assertEqual(len(lab.world.applied()), run.plan.configlets.count())
        self.assertEqual(lab.world.state["EDGE1"]["addresses"]["loopback10"], ["198.51.100.10/32"])
        # evidence is REFERENCED, not copied
        self.assertEqual(run.execution_run.change_id, run.change_id)
        self.assertEqual(run.validation_run.change_id, run.change_id)
        self.assertEqual(run.precheck_run.mode, models.OperationalRunMode.CHANGE_PRECHECK)
        self.assertIsNotNone(run.postcheck_run)
        self.assertEqual(run.result["postcheck"]["result"], "PASS")
        self.assertEqual(len(run.pre_config_digest), 64)
        self.assertNotEqual(run.pre_config_digest, run.post_config_digest)
        self.assertEqual(run.result["config_digest"], run.post_config_digest)
        self.assertEqual(run.result["netbox_identity"]["status"], "active")
        self.assertFalse(run.result["netbox_identity"]["managed_scope"])        # disposable: never joins the IaC managed scope
        self.assertEqual([e.stage for e in run.events.all()],
                         ["IDENTITY", "BOOTSTRAP", "CAPABILITY", "IPAM", "CANDIDATE", "VALIDATION", "PLAN", "PRECHECK", "APPROVAL", "PROVISION", "NSOT_SYNC"])

    def test_device_becomes_resolvable_only_through_the_registry(self):
        lab = p.Lab()
        self.assertNotIn("EDGE1", inventory.managed_devices())
        lab.through("candidate")
        entry = inventory.managed_devices()["EDGE1"]
        self.assertEqual((entry["platform"], entry["container"], entry["provisioning_state"]), ("linux", p.TARGET["container"], "ADMITTED"))
        lab.intent()
        for step in ("validate", "plan", "precheck", "approve", "provision", "sync"):
            getattr(lab, step)()
        self.assertEqual(inventory.managed_devices()["EDGE1"]["provisioning_state"], "ACTIVE")
        self.assertNotIn("EDGE1", inventory.inventory_devices())                # the tracked inventory is untouched

    def test_registry_can_never_redefine_a_production_device(self):
        lab = p.Lab()
        lab.through("candidate")
        models.ProvisionedDevice.objects.filter(run=lab.run).update(name="R1")
        self.assertEqual(inventory.managed_devices()["R1"]["container"], "clab-srlceos01-R1")
        self.assertNotIn("provisioned", inventory.managed_devices()["R1"])

    def test_new_device_is_unresolvable_without_admission(self):
        change = new_change("not a provisioning run")
        dev = Dev(change, "GHOST1", platform=p.FRR, target_type=models.DeviceIntentTargetType.NEW_DEVICE)
        dev.address(dev.iface("loopback10", kind="LOOPBACK"), "198.51.100.20/32")
        prepared = ex.prepared(type("F", (), {"change": change, "sources": make_sources()})(), require_permit=False)
        report = es.check_execution_eligibility(change, confirm_mode=change.execution_mode, sources=prepared.sources)
        self.assertIn("TARGET_DEVICE_UNRESOLVABLE", report.codes)

    def _foreign(self, target_type):
        """Another Change that targets EDGE1 -> the execution gate's blocker codes."""
        change = new_change("someone else's change")
        dev = Dev(change, "EDGE1", platform=p.FRR, target_type=target_type)
        dev.address(dev.iface("loopback20", kind="LOOPBACK"), "198.51.100.20/32")
        prepared = ex.prepared(type("F", (), {"change": change, "sources": make_sources()})(), require_permit=False)
        return es.check_execution_eligibility(change, confirm_mode=change.execution_mode, sources=prepared.sources).codes

    def test_an_admitted_device_serves_only_its_own_provisioning_change(self):
        lab = p.Lab()
        lab.through("candidate")
        self.assertTrue(registry.admitted_for("EDGE1", lab.run.change))
        self.assertFalse(registry.admitted_for("R1", lab.run.change))
        for target_type in models.DeviceIntentTargetType.values:      # neither a NEW_DEVICE nor an EXISTING_DEVICE intent of another Change
            self.assertIn("TARGET_DEVICE_UNRESOLVABLE", self._foreign(target_type), target_type)

    def test_an_active_provisioned_device_is_an_ordinary_managed_device(self):
        lab = p.Lab()
        lab.through("sync")
        self.assertNotIn("TARGET_DEVICE_UNRESOLVABLE", self._foreign(models.DeviceIntentTargetType.EXISTING_DEVICE))
        self.assertIn("TARGET_DEVICE_UNRESOLVABLE", self._foreign(models.DeviceIntentTargetType.NEW_DEVICE))

    def test_apply_failure_in_complete_mode_rolls_back_and_reconciles(self):
        lab = p.Lab()
        lab.through("candidate", execution_mode=models.ExecutionMode.COMPLETE)
        lab.intent()
        for step in ("validate", "plan", "precheck", "approve"):
            self.assertTrue(getattr(lab, step)().ok, step)
        last = lab.run.plan.configlets.order_by("-sequence").first().cfg_id
        lab.world.fail_apply[last] = ("COMMAND_REJECTED", False)
        result = lab.provision()
        run = lab.run
        self.assertFalse(result.ok)
        self.assertEqual(run.status, S.ROLLED_BACK)
        self.assertEqual(run.failure["code"], "EXECUTION_FAILED")
        self.assertTrue(run.failure["device_restored"])
        self.assertEqual(lab.world.state["EDGE1"]["interfaces"], {})           # the device holds none of this run's configuration
        self.assertEqual(lab.gateway.objects, {})                              # NetBox reservation released
        self.assertTrue(run.failure["reconciliation"]["clean"])
        self.assertEqual(run.failure["reconciliation"]["registry"], "RETIRED")
        self.assertNotIn("EDGE1", inventory.managed_devices())
        self.assertIsNotNone(run.execution_run)                                # the failed execution stays referenced
        self.assertEqual(run.events.last().outcome, "FAILED")

    def test_partial_failure_is_failed_not_rolled_back_and_says_so(self):
        lab = p.Lab()
        lab.through("candidate", execution_mode=models.ExecutionMode.PARTIAL_UAT)
        lab.intent()
        for step in ("validate", "plan", "precheck", "approve"):
            self.assertTrue(getattr(lab, step)().ok, step)
        last = lab.run.plan.configlets.order_by("-sequence").first().cfg_id
        lab.world.fail_apply[last] = ("COMMAND_REJECTED", False)
        lab.provision()
        run = lab.run
        self.assertEqual(run.status, S.FAILED)
        self.assertFalse(run.failure["device_restored"])                       # Partial (UAT) preserves the applied prefix
        self.assertTrue(lab.world.state["EDGE1"]["interfaces"])
        self.assertEqual(len(run.failure["device_digest_after"]), 64)          # the leftover state is read back and recorded
        self.assertNotEqual(run.failure["device_digest_after"], run.pre_config_digest)
        self.assertEqual(lab.gateway.objects, {})

    def test_postcheck_failure_fails_the_provision(self):
        lab = p.Lab()
        lab.through("approve")
        lab.provision(evidence_provider=lambda plan, cfg_ids: ex.h.evidence_set(ex.h.device_evidence("EDGE1")))
        self.assertIn(lab.run.status, (S.FAILED, S.ROLLED_BACK))
        self.assertEqual(lab.run.failure["code"], "POSTCHECK_NOT_PASSING")
        self.assertEqual(lab.gateway.objects, {})

    def test_unreadable_configuration_never_yields_a_digest(self):
        lab = p.Lab()
        lab.through("approve")

        def broken(device):
            raise OSError("no session")
        result = lab.provision(config_reader=broken)
        self.assertIn("PROVISIONING_BASELINE_UNREADABLE", result.codes)
        self.assertIn("DIGEST_UNAVAILABLE", [b["code"] for e in lab.run.events.filter(stage="PROVISION") for b in e.blockers])
        self.assertEqual(lab.run.status, S.APPROVED)
        self.assertEqual((lab.run.pre_config_digest, lab.world.mutating_calls()), ("", []))

    def test_nsot_sync_failure_keeps_the_device_admitted_and_is_retryable(self):
        lab = p.Lab()
        lab.through("provision")
        lab.gateway.available = False
        self.assertEqual(lab.sync().codes, ["NSOT_SYNC_FAILED"])
        self.assertEqual(lab.run.status, S.POSTCHECKED)
        self.assertEqual(registry.live_entry("EDGE1").state, "ADMITTED")
        lab.gateway.available = True
        self.assertTrue(lab.sync().ok)

    def test_non_disposable_device_joins_the_managed_scope(self):
        gateway = p.FakeGateway(prefixes=["10.99.0.0/24"])
        lab = p.Lab(name="CORE9", disposable=False, management={"interface": "eth0", "ipv4": "10.99.0.5/24"}, gateway=gateway)
        lab.through("sync")
        self.assertTrue(lab.run.result["netbox_identity"]["managed_scope"])
        self.assertTrue(gateway.objects[lab.run.netbox["device_id"]]["managed"])


class CancelAndImmutabilityTests(TestCase):
    def test_cancel_releases_the_reservation_and_retires_the_entry(self):
        lab = p.Lab()
        lab.through("candidate")
        self.assertTrue(lab.gateway.objects)
        result = ps.cancel(lab.run, actor="op", gateway=lab.gateway, reason="no longer needed")
        self.assertTrue(result.ok)
        self.assertEqual(lab.run.status, S.CANCELLED)
        self.assertEqual(lab.gateway.objects, {})
        self.assertNotIn("EDGE1", inventory.managed_devices())
        self.assertEqual(result.event.outcome, "RECONCILED")

    def test_a_provisioned_device_cannot_be_cancelled(self):
        lab = p.Lab()
        lab.through("provision")
        self.assertEqual(ps.cancel(lab.run, actor="op", gateway=lab.gateway).codes, ["WRONG_STAGE"])

    def test_finished_run_and_its_evidence_are_immutable(self):
        lab = p.Lab()
        lab.through("identity")
        ps.cancel(lab.run, actor="op")
        run = models.ProvisioningRun.objects.get(pk=lab.run.pk)
        run.site = "edited"
        with self.assertRaises(ValueError):
            run.save()
        with self.assertRaises(ValueError):
            run.delete()
        self.assertEqual(ps.define_identity(run, actor="op", bootstrap_transport="DOCKER_EXEC", bootstrap_target=p.TARGET,
                                            management=p.MANAGEMENT).codes, ["RUN_FINISHED"])
        event = run.events.first()
        event.stage = "EDITED"
        with self.assertRaises(ValueError):
            event.save()
        with self.assertRaises(ValueError):
            event.delete()
        with self.assertRaises(ValueError):
            models.ProvisioningEvent.objects.filter(run=run).update(stage="X")

    def test_identity_fields_are_immutable(self):
        lab = p.Lab()
        lab.run.device_name = "OTHER"
        with self.assertRaises(ValueError):
            lab.run.save()

    def test_evidence_never_stores_a_credential(self):
        lab = p.Lab()
        lab.through("sync")
        blob = repr([(e.evidence, e.blockers) for e in lab.run.events.all()]) + repr(
            [lab.run.bootstrap_target, lab.run.netbox, lab.run.result, lab.run.approval]).lower()
        for needle in ("password", "secret", "token", "private_key"):
            self.assertNotIn(needle, blob)

    def test_stage_rows_describe_the_workflow(self):
        lab = p.Lab()
        lab.through("bootstrap")
        rows = ps.stage_rows(lab.run)
        self.assertEqual([r["state"] for r in rows[:4]], ["DONE", "DONE", "NEXT", "PENDING"])
        self.assertEqual(ps.next_stage(lab.run), "CAPABILITY")
        self.assertEqual(ps.get_run(lab.run.prov_id), lab.run)
        self.assertIsNone(ps.get_run("PROV-xyz"))


class ManagedScopeTests(TestCase):
    """Found by the live proof: the network-configuration validation's managed-scope check must admit the device being provisioned."""

    def test_provisioning_device_is_in_scope_for_its_own_change_only(self):
        from core.services import network_config_validation as ncv
        lab = p.Lab()
        lab.through("validate")
        check = next(c for c in lab.run.network_config_validation_run.checks if c["check"] == "MANAGED_SCOPE")
        self.assertEqual((check["status"], check["evidence"]["provisioning"]), ("PASS", ["EDGE1"]))
        other = new_change("someone else's change")
        dev = Dev(other, "EDGE1", platform=p.FRR)
        dev.address(dev.iface("loopback20", kind="LOOPBACK"), "198.51.100.20/32")
        foreign = ncv.validate_candidate(other, actor="t", sources=lab.sources)
        check = next(c for c in foreign.checks if c["check"] == "MANAGED_SCOPE")
        self.assertEqual((check["status"], check["evidence"]["outside_scope"]), ("BLOCKED", ["EDGE1"]))


class ExecutionBoundaryTests(TestCase):
    """There is ONE execution entry point.  A provisioning Change goes through it, and cannot use it to skip the provisioning approval."""

    def _execute_directly(self, lab, **kw):
        return lab.provision(**kw)

    def test_provisioning_change_cannot_be_executed_before_approval(self):
        lab = p.Lab()
        lab.through("precheck")                         # validated, planned, prechecked, device admitted -- but NOT approved
        result = self._execute_directly(lab)
        self.assertIn("PROVISIONING_NOT_APPROVED", result.codes)
        self.assertTrue(result.execution.refused)
        self.assertEqual(lab.world.mutating_calls(), [])
        self.assertEqual(lab.run.status, S.PRECHECKED)

    def test_the_ordinary_execute_route_enforces_the_provisioning_approval(self):
        from django.urls import reverse
        lab = p.Lab()
        lab.through("precheck")
        change = lab.run.change
        self.client.post(reverse("core:change_execute_run", args=[change.change_id]), {"confirm_mode": change.execution_mode})
        blocked = models.ChangeExecutionRun.objects.filter(change=change).first()
        self.assertEqual(blocked.outcome, models.ExecutionOutcome.BLOCKED)
        self.assertIn("PROVISIONING_NOT_APPROVED", [b["code"] for b in blocked.report["blockers"]])
        lab.run.refresh_from_db()
        self.assertEqual(lab.run.status, S.PRECHECKED)

    def test_unreachable_or_onboarding_device_is_refused_by_the_engine_gate(self):
        lab = p.Lab()
        lab.through("approve")
        models.ProvisioningRun.objects.filter(pk=lab.run.pk).update(bootstrap_state=models.BootstrapState.UNREACHABLE)
        result = self._execute_directly(lab)
        self.assertIn("PROVISIONING_DEVICE_UNREACHABLE", result.codes)
        self.assertEqual(lab.world.mutating_calls(), [])

    def test_a_provisioned_change_cannot_be_executed_twice(self):
        lab = p.Lab()
        lab.through("provision")
        again = self._execute_directly(lab)
        self.assertIn("PROVISIONING_NOT_APPROVED", again.codes)
        self.assertEqual(len(lab.world.applied()), lab.run.plan.configlets.count())      # applied exactly once
        self.assertEqual(lab.run.status, S.POSTCHECKED)

    def test_an_ordinary_change_is_untouched_by_the_provisioning_hooks(self):
        prepared = ex.prepared()
        world = ex.FakeWorld()
        result = ex.run(prepared, world)
        self.assertEqual(result.outcome, models.ExecutionOutcome.SUCCEEDED)
        self.assertEqual(models.ProvisioningEvent.objects.count(), 0)

    def test_same_engine_evidence_as_any_change(self):
        lab = p.Lab()
        lab.through("provision")
        execution = lab.run.execution_run
        self.assertEqual((execution.mode, execution.outcome), (models.ExecutionMode.COMPLETE, models.ExecutionOutcome.SUCCEEDED))
        self.assertEqual(execution.precheck_run_id, lab.run.precheck_run_id)              # the same precheck the gate required
        self.assertEqual(execution.results.filter(phase=models.ExecutionResultPhase.APPLY).count(), lab.run.plan.configlets.count())
        self.assertFalse(models.ExecutionDeviceLock.objects.filter(run=execution).exists())  # locks released by the engine
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.DEPLOYMENT_RECORDED, change=lab.run.change).exists())

    def test_expired_precheck_can_be_refreshed_while_approved(self):
        lab = p.Lab()
        lab.through("approve")
        first = lab.run.precheck_run_id
        self.assertTrue(lab.precheck().ok)
        self.assertEqual(lab.run.status, S.APPROVED)
        self.assertNotEqual(lab.run.precheck_run_id, first)
        self.assertTrue(lab.provision().ok)


class ProbationLineageTests(TestCase):
    def test_successful_complete_provisioning_starts_the_normal_seven_day_probation(self):
        lab = p.Lab()
        lab.through("sync")
        self.assertEqual(lab.run.change.execution_mode, models.ExecutionMode.COMPLETE)     # the default; nothing pretends to be a UAT
        result = ps.start_probation(lab.run, actor="approver")
        self.assertTrue(result.ok, result.blockers)
        run = lab.run
        self.assertEqual(run.status, S.PROBATION)
        soak = run.soak_run
        self.assertEqual(soak.state, models.SoakState.RUNNING)
        self.assertEqual(soak.required_end_at - soak.started_at, timedelta(days=7))
        self.assertEqual(soak.duration_seconds, 604800)
        probation = run.probation_bundle
        root = probation.parent
        self.assertEqual((probation.kind, root.kind), (models.BundleKind.PROBATION, models.BundleKind.DEPLOYED))
        self.assertTrue(root.bundle_id.startswith("BND-DEP-"))
        self.assertEqual(models.ConfigurationBundle.objects.filter(kind=models.BundleKind.UAT).count(), 0)

    def test_lineage_references_immutable_evidence_instead_of_copying_it(self):
        lab = p.Lab()
        lab.through("sync")
        ps.start_probation(lab.run, actor="approver")
        run, probation = lab.run, lab.run.probation_bundle
        root = probation.parent
        for bundle in (root, probation):
            self.assertEqual((bundle.change_id, bundle.plan_id, bundle.validation_run_id, bundle.execution_run_id, bundle.postcheck_run_id),
                             (run.change_id, run.plan_id, run.validation_run_id, run.execution_run_id, run.postcheck_run_id))
            self.assertTrue(bundle_service.verify_bundle_integrity(bundle).ok, bundle_service.verify_bundle_integrity(bundle).codes)
        self.assertEqual(root.payload_digest, probation.payload_digest)
        self.assertEqual(root.payload["source"]["execution"]["mode"], "COMPLETE")
        self.assertEqual([i.configlet_id for i in root.items.order_by("sequence")],
                         list(run.plan.configlets.order_by("sequence").values_list("pk", flat=True)))
        with self.assertRaises(ValueError):
            root.save()

    def test_failed_and_rolled_back_complete_provisioning_cannot_enter_probation(self):
        lab = p.Lab()
        lab.through("approve")
        last = lab.run.plan.configlets.order_by("-sequence").first().cfg_id
        lab.world.fail_apply[last] = ("COMMAND_REJECTED", False)
        lab.provision()
        self.assertEqual(lab.run.status, S.ROLLED_BACK)
        self.assertEqual(ps.start_probation(lab.run, actor="approver").codes, ["RUN_FINISHED"])
        refused = bundle_service.create_deployed_bundle(lab.run.execution_run, actor="approver")
        self.assertEqual([b["code"] for b in refused.blockers], ["OUTCOME_NOT_DEPLOYED"])
        self.assertEqual((models.ConfigurationBundle.objects.count(), models.ProbationSoakRun.objects.count()), (0, 0))

    def test_postcheck_failed_complete_provisioning_cannot_enter_probation(self):
        lab = p.Lab()
        lab.through("approve")
        lab.provision(evidence_provider=lambda plan, cfg_ids: ex.h.evidence_set(ex.h.device_evidence("EDGE1")))
        self.assertTrue(lab.run.is_terminal)
        refused = bundle_service.create_deployed_bundle(lab.run.execution_run, actor="approver")
        self.assertEqual([b["code"] for b in refused.blockers], ["OUTCOME_NOT_DEPLOYED"])

    def test_partial_uat_keeps_its_own_meaning_and_lineage(self):
        lab = p.Lab()
        lab.through("candidate", execution_mode=models.ExecutionMode.PARTIAL_UAT)
        lab.intent()
        for step in ("validate", "plan", "precheck", "approve", "provision", "sync"):
            self.assertTrue(getattr(lab, step)().ok, step)
        self.assertEqual(lab.run.execution_run.outcome, models.ExecutionOutcome.UAT_SCOPE_APPLIED)
        self.assertEqual([b["code"] for b in bundle_service.create_deployed_bundle(lab.run.execution_run, actor="a").blockers],
                         ["MODE_NOT_COMPLETE", "OUTCOME_NOT_DEPLOYED"])
        self.assertTrue(ps.start_probation(lab.run, actor="approver").ok)
        self.assertEqual(lab.run.probation_bundle.parent.kind, models.BundleKind.UAT)

    def test_an_ordinary_complete_change_seals_through_the_same_service_and_is_never_a_uat_bundle(self):
        """Provisioning does not own the Complete -> Deployed lineage: an ordinary Change uses the SAME service (test_deployed_lineage)."""
        prepared = ex.prepared()
        result = ex.run(prepared, ex.FakeWorld())
        self.assertEqual(result.outcome, models.ExecutionOutcome.SUCCEEDED)
        sealed = bundle_service.create_deployed_bundle(result.run, actor="a")
        self.assertEqual((sealed.created, sealed.bundle.kind), (True, models.BundleKind.DEPLOYED))
        self.assertIn("MODE_NOT_PARTIAL_UAT", [b["code"] for b in bundle_service.create_uat_bundle(result.run, actor="a").blockers])

    def test_deployed_bundle_is_idempotent_per_execution(self):
        lab = p.Lab()
        lab.through("sync")
        first = bundle_service.create_deployed_bundle(lab.run.execution_run, actor="a")
        second = bundle_service.create_deployed_bundle(lab.run.execution_run, actor="a")
        self.assertTrue(first.created)
        self.assertEqual((second.bundle.pk, second.created), (first.bundle.pk, False))

    def test_decommission_retires_the_device_and_releases_netbox(self):
        lab = p.Lab()
        lab.through("sync")
        report = ps.decommission(lab.run, actor="op", gateway=lab.gateway)
        self.assertTrue(report["clean"])
        self.assertEqual(report["registry"], "RETIRED")
        self.assertEqual(lab.gateway.objects, {})
        self.assertNotIn("EDGE1", inventory.managed_devices())
        self.assertTrue(models.AuditEvent.objects.filter(event_type=models.AuditEventType.DEVICE_DECOMMISSIONED).exists())
        self.assertEqual(models.ProvisionedDevice.objects.get(run=lab.run).state, "RETIRED")   # history is kept
        # Found by the live proof: the retired device's request must END, or it keeps claiming the name and the container.
        self.assertEqual((lab.run.status, lab.run.is_terminal), (S.DECOMMISSIONED, True))
        again = p.Lab(supported=())                       # same name, same container: a fresh request is possible again
        self.assertTrue(again.identity().ok)

    def test_decommission_of_a_device_in_probation_never_edits_the_finished_request(self):
        lab = p.Lab()
        lab.through("sync")
        ps.start_probation(lab.run, actor="approver")
        report = ps.decommission(lab.run, actor="op", gateway=lab.gateway)
        self.assertEqual((report["registry"], lab.run.status), ("RETIRED", S.PROBATION))
