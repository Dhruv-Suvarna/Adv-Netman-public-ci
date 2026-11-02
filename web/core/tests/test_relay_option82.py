"""V2 Phase 9: DHCP relay option 82 as a governed change (``ztp.relay_option82``), the relay read-back ZTP trusts, and the
refusal of a client-forged option 82 in discovery.

The device side is the in-memory EOS model of the isolation tests (``helpers.isolation.EosText``) driven by the REAL
``CeosExecutor`` and the REAL single-device transaction: assess / apply / read-back / compensation are the engine's own.  The relay
is S1 (arista_ceos in inventory.yml) relaying the ZTP test network from Ethernet7 (10.254.30.1/24, helper 10.254.31.2).
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from django.test import TestCase, override_settings
from django.utils import timezone

from core import models
from core.services import dhcp_relay_option82 as o82
from core.services import service_policy_intent_service as service
from core.services.execution.codes import Outcome
from core.services.execution.executors.base import ExecutorError
from core.services.execution.executors.ceos import CeosExecutor
from core.services.isolation import transaction
from core.services.ztp import dependencies, discovery, relay_option82 as R
from core.tests.helpers import isolation as I
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from core.tests.helpers.candidates import add_interface, make_candidate

REQUESTER, APPROVER, EXECUTOR = "olivia", "arthur", "erin"
DEFAULT = o82.Option82Intent("Ethernet7")


def factory(session):
    return lambda device: CeosExecutor(device, connection_factory=lambda d: session, reader=I._facts)   # pylint: disable=protected-access


class Broken:
    """A session whose every read fails (an unreachable relay)."""

    def send_command(self, *_a, **_k):
        raise OSError("unreachable")

    def disconnect(self):
        return None


def broken_factory(device):
    return CeosExecutor(device, connection_factory=lambda d: Broken(), reader=I._facts)


def prior(text, interface="Ethernet7"):
    return R.port_state(o82.parse_eos(text), interface)


class OperationsTests(TestCase):
    def test_operations_enable_option82_with_the_exact_inverse(self):
        ops = R.operations(DEFAULT, prior(I.upstream_config()))
        self.assertEqual([(op["key"], op["kind"], op["lines"], op["inverse"], op["paths"]) for op in ops],
                         [("global", "ADD", [o82.GLOBAL_LINE], [f"no {o82.GLOBAL_LINE}"], [o82.GLOBAL_LINE])])
        self.assertEqual(ops[0]["object_type"], R.OBJECT_TYPE)

    def test_operations_returns_the_captured_value_as_inverse_of_a_replaced_circuit_id(self):
        text = I.upstream_config(extra_port="ip dhcp relay information option circuit-id OLD-ID", extra=o82.GLOBAL_LINE)
        ops = R.operations(o82.Option82Intent("Ethernet7", "NEW-ID", "RID-1"), prior(text))
        self.assertEqual([(op["key"], op["lines"][1].strip(), op["inverse"][1].strip()) for op in ops],
                         [("circuit-id", "ip dhcp relay information option circuit-id NEW-ID", "ip dhcp relay information option circuit-id OLD-ID"),
                          ("remote-id", "ip dhcp relay information option remote-id RID-1", "no ip dhcp relay information option remote-id")])

    def test_operations_of_a_disabled_intent_remove_the_port_ids_and_keep_the_global_switch(self):
        text = I.upstream_config(extra_port="ip dhcp relay information option remote-id RID-1", extra=o82.GLOBAL_LINE)
        ops = R.operations(o82.Option82Intent("Ethernet7", enabled=False), prior(text))
        self.assertEqual([(op["key"], op["kind"], op["inverse"][1].strip()) for op in ops],
                         [("remote-id", "REMOVE", "ip dhcp relay information option remote-id RID-1")])

    def test_operations_return_empty_when_the_relay_already_holds_the_intent(self):
        self.assertEqual(R.operations(DEFAULT, prior(I.upstream_config(extra=o82.GLOBAL_LINE))), [])

    def test_operations_refuse_a_missing_port_and_an_invalid_intent(self):
        with self.assertRaises(o82.Option82Error) as missing:
            R.operations(o82.Option82Intent("Ethernet9"), prior(I.upstream_config(), "Ethernet9"))
        self.assertEqual(missing.exception.code, "OPTION82_PORT_MISSING")
        with self.assertRaises(o82.Option82Error) as invalid:
            R.operations(o82.Option82Intent("Ethernet7", "bad id"), prior(I.upstream_config()))
        self.assertEqual(invalid.exception.code, "OPTION82_VALUE_INVALID")

    def test_ops_of_refuses_a_change_whose_stored_port_is_missing(self):
        change = SimpleNamespace(metadata={"transition": {"intent": {"interface": "Ethernet9", "enabled": True},
                                                          "prior": {"present": False}}})
        with self.assertRaises(o82.Option82Error) as missing:
            R.ops_of(change)
        self.assertEqual(missing.exception.code, "OPTION82_PORT_MISSING")

    def test_port_state_returns_the_port_facts_a_change_depends_on(self):
        self.assertEqual(prior(I.upstream_config()), {"enabled": False, "interface": "Ethernet7", "present": True, "circuit_id": "",
                                                       "remote_id": "", "helpers": [I.SERVICE], "addresses": [I.GATEWAY]})

    def test_port_state_of_an_unconfigured_port_is_absent(self):
        self.assertEqual(prior(I.upstream_config(), "Ethernet9"), {"enabled": False, "interface": "Ethernet9", "present": False})


class IntentTests(TestCase):
    def _relay(self, name="Ethernet7"):
        _change, _intent, revision = make_candidate(platform="arista_ceos")
        interface = add_interface(revision, name=name)
        relay = service.add_dhcp_relay(revision=revision, family="IPV4", interface_id=interface["id"], destination=I.SERVICE)
        return revision, relay

    def test_intent_from_revision_returns_the_device_builder_option82_intent(self):
        revision, relay = self._relay()
        service.set_dhcp_relay_option82(revision=revision, relay_id=relay["id"], circuit_id="PORT-7")
        revision.refresh_from_db()
        self.assertEqual(R.intent_from_revision(revision, relay["id"]), o82.Option82Intent("Ethernet7", "PORT-7", "", True))

    def test_intent_from_revision_refuses_an_unknown_relay_and_a_relay_without_option82(self):
        revision, relay = self._relay()
        with self.assertRaises(o82.Option82Error) as unknown:
            R.intent_from_revision(revision, "dhcp_missing")
        self.assertEqual(unknown.exception.code, "OPTION82_RELAY_NOT_FOUND")
        with self.assertRaises(o82.Option82Error) as bare:
            R.intent_from_revision(revision, relay["id"])
        self.assertEqual(bare.exception.code, "OPTION82_INTENT_MISSING")


class PortFindingsTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        L.adopt()                                       # a bootstrap network lists only an adopted, in-service relay
    def test_port_findings_accept_a_routed_addressed_relay_port_of_the_network(self):
        self.assertEqual(R.port_findings("S1", DEFAULT, prior(I.upstream_config()), network=self.network()), [])

    def test_port_findings_refuse_a_switched_port_a_missing_helper_and_a_foreign_relay_address(self):
        network = self.network(relays=[{"relay_address": "10.254.30.5", "upstream_device": "S1"}])
        codes = [f["code"] for f in R.port_findings("S1", DEFAULT, prior(I.upstream_config(helper="")), network=network)]
        self.assertEqual(codes, ["BOOTSTRAP_PATH_UNAVAILABLE", "RELAY_UNTRUSTED"])
        switched = [f["code"] for f in R.port_findings("S1", o82.Option82Intent("Vlan30"), {"present": True, "addresses": [], "helpers": []})]
        self.assertEqual(switched, ["OPTION82_PORT_NOT_ROUTED", "OPTION82_PORT_UNADDRESSED"])
        self.assertEqual([f["code"] for f in R.port_findings("R3", DEFAULT, {"present": False})],
                         ["OPTION82_PLATFORM_NOT_IMPLEMENTED", "OPTION82_PORT_MISSING"])


class GovernedChangeTests(Z.ZtpTestMixin, TestCase):
    relay_readback_present = False

    def setUp(self):
        super().setUp()
        L.adopt()
        self.session = I.FakeEosSession(I.upstream_config())
        self.before = self.session.config.text()

    def planned(self, intent=DEFAULT, **kwargs):
        result = R.plan(device="S1", intent=intent, actor=REQUESTER, network=self.network(), executor_factory=factory(self.session),
                        source={"revision": "test"}, **kwargs)
        self.assertTrue(result.ok, result.codes)
        return result

    def approved(self, intent=DEFAULT):
        result = self.planned(intent)
        self.assertTrue(R.approve(result.change, actor=APPROVER, confirmation=result.detail["plan_hash"]).ok)
        return result

    def test_plan_builds_an_immutable_validated_plan_with_a_passing_precheck_and_sends_nothing(self):
        result = self.planned(o82.Option82Intent("Ethernet7", "PORT-7"))
        change = result.change
        self.assertEqual(transaction.kind_of(change), R.KIND)
        self.assertEqual(transaction.latest_validation(change).status, models.ValidationRunStatus.PASS)
        built = transaction.latest_plan(change)
        self.assertEqual([(c.desired_state_ref["source"]["object_type"], c.feature_namespace) for c in built.configlets.order_by("sequence")],
                         [(R.OBJECT_TYPE, "services"), (R.OBJECT_TYPE, "services")])
        self.assertEqual(transaction.latest_precheck(change, built).status, "PASS")
        self.assertEqual(self.session.sent, [])
        self.assertEqual(R.ops_of(change), result.detail["operations"])

    def test_plan_returns_satisfied_without_a_change_when_the_relay_holds_the_intent(self):
        self.session.config.apply([o82.GLOBAL_LINE])
        result = R.plan(device="S1", intent=DEFAULT, actor=REQUESTER, executor_factory=factory(self.session))
        self.assertEqual((result.ok, result.change, result.detail.get("satisfied")), (True, None, True))

    def test_plan_refuses_an_unreadable_relay_a_missing_port_and_an_unresolved_transition(self):
        unreadable = R.plan(device="S1", intent=DEFAULT, actor=REQUESTER, executor_factory=broken_factory)
        self.assertEqual(unreadable.codes, ["RELAY_UNREADABLE"])
        missing = R.plan(device="S1", intent=o82.Option82Intent("Ethernet9"), actor=REQUESTER, executor_factory=factory(self.session))
        self.assertEqual((missing.ok, missing.codes), (False, ["OPTION82_PORT_MISSING"]))
        self.assertEqual(transaction.latest_validation(missing.change).status, models.ValidationRunStatus.BLOCKED)
        with self.subTest("unresolved"):
            from unittest import mock

            with mock.patch.object(transaction, "unresolved_runs", return_value=["CHG-1"]):
                blocked = R.plan(device="S1", intent=DEFAULT, actor=REQUESTER, executor_factory=factory(self.session))
            self.assertEqual(blocked.codes, ["PRIOR_TRANSITION_UNRESOLVED"])

    def test_approve_refuses_the_requester_and_a_wrong_plan_hash(self):
        result = self.planned()
        self.assertIn("SELF_APPROVAL", R.approve(result.change, actor=REQUESTER, confirmation=result.detail["plan_hash"]).codes)
        self.assertIn("CONFIRMATION_MISMATCH", R.approve(result.change, actor=APPROVER, confirmation="0" * 64).codes)

    def test_approve_accepts_another_operator_confirming_the_plan_hash(self):
        result = self.planned()
        approved = R.approve(result.change, actor=APPROVER, confirmation=result.detail["plan_hash"])
        self.assertTrue(approved.ok, approved.codes)
        self.assertEqual(transaction.approval(result.change)["approved_by"], APPROVER)

    def test_precheck_passes_while_the_relay_port_is_unchanged(self):
        result = self.planned()
        self.assertTrue(R.precheck(result.change, actor=REQUESTER, executor_factory=factory(self.session)).ok)

    def test_precheck_blocks_when_the_relay_port_changed_since_planning(self):
        result = self.planned()
        self.session.config.apply(["interface Ethernet7", "ip dhcp relay information option circuit-id ELSEWHERE"])
        changed = R.precheck(result.change, actor=REQUESTER, executor_factory=factory(self.session))
        self.assertEqual(changed.codes, ["BASIS_CHANGED"])
        self.assertEqual(R.precheck(result.change, actor=REQUESTER, executor_factory=broken_factory).codes, ["RELAY_UNREADABLE"])

    def test_execute_applies_reads_back_and_records_the_trusted_readback(self):
        result = self.approved(o82.Option82Intent("Ethernet7", "", "RID-7"))
        done = R.execute(result.change, actor=EXECUTOR, confirmation=result.detail["plan_hash"], executor_factory=factory(self.session))
        self.assertTrue(done.ok, (done.codes, done.detail.get("outcome")))
        running = self.session.config.text()
        self.assertIn(f"{o82.GLOBAL_LINE}\n", running)
        self.assertIn("   ip dhcp relay information option remote-id RID-7", running)
        row = models.DhcpRelayReadback.objects.get(pk=done.detail["readback"])
        self.assertEqual((row.device, row.source, row.change_id), ("S1", models.DhcpRelayReadbackSource.POSTCHECK, result.change.pk))
        self.assertEqual(o82.effective_circuit_id(R.trusted_readback("S1"), "Ethernet7"), "Ethernet7")
        result.change.refresh_from_db()
        self.assertEqual(result.change.lifecycle_state, models.ChangeLifecycleState.DEPLOYED)

    def test_execute_blocks_before_any_write_when_the_basis_changed_after_approval(self):
        result = self.approved()
        self.session.config.apply(["interface Ethernet7", "ip dhcp relay information option circuit-id ELSEWHERE"])
        done = R.execute(result.change, actor=EXECUTOR, confirmation=result.detail["plan_hash"], executor_factory=factory(self.session))
        self.assertEqual((done.ok, done.detail["outcome"], done.codes), (False, Outcome.BLOCKED, ["BASIS_CHANGED"]))
        self.assertEqual(self.session.sent, [])
        self.assertFalse(models.DhcpRelayReadback.objects.exists())

    def test_execute_refuses_an_unapproved_change_and_sends_nothing(self):
        result = self.planned()
        done = R.execute(result.change, actor=EXECUTOR, confirmation=result.detail["plan_hash"], executor_factory=factory(self.session))
        self.assertEqual((done.ok, done.detail["outcome"]), (False, Outcome.BLOCKED))
        self.assertIn("NOT_APPROVED", done.codes)
        self.assertEqual(self.session.sent, [])

    def test_execute_compensates_exactly_when_the_relay_rejects_a_statement(self):
        result = self.approved(o82.Option82Intent("Ethernet7", "PORT-7"))
        self.session.reject = lambda commands: any("circuit-id" in c and not c.strip().startswith("no ") for c in commands)
        done = R.execute(result.change, actor=EXECUTOR, confirmation=result.detail["plan_hash"], executor_factory=factory(self.session))
        self.assertEqual((done.ok, done.detail["outcome"]), (False, Outcome.FAILED_ROLLED_BACK))
        self.assertEqual(self.session.config.text(), self.before)
        self.assertFalse(models.DhcpRelayReadback.objects.exists())

    def test_execute_rolls_back_a_failed_postcheck_to_the_exact_prior_configuration(self):
        result = self.approved(o82.Option82Intent("Ethernet7", "PORT-7"))
        real = o82.postcheck
        from unittest import mock

        with mock.patch.object(o82, "postcheck", side_effect=lambda intent, rb: [*real(intent, rb), "OPTION82_REMOTE_ID_MISMATCH"]):
            done = R.execute(result.change, actor=EXECUTOR, confirmation=result.detail["plan_hash"], executor_factory=factory(self.session))
        self.assertEqual((done.ok, done.detail["outcome"]), (False, Outcome.POSTCHECK_FAILED_ROLLED_BACK))
        self.assertEqual(self.session.config.text(), self.before)

    def test_execute_of_a_disabled_intent_removes_the_ids_and_restores_them_on_failure(self):
        self.session.config.apply([o82.GLOBAL_LINE, "interface Ethernet7", "ip dhcp relay information option remote-id RID-1"])
        before = self.session.config.text()
        result = self.approved(o82.Option82Intent("Ethernet7", enabled=False))
        from unittest import mock

        with mock.patch.object(o82, "postcheck", return_value=["OPTION82_PORT_MISSING"]):
            failed = R.execute(result.change, actor=EXECUTOR, confirmation=result.detail["plan_hash"], executor_factory=factory(self.session))
        self.assertEqual((failed.detail["outcome"], self.session.config.text()), (Outcome.POSTCHECK_FAILED_ROLLED_BACK, before))


class ReadbackTests(Z.ZtpTestMixin, TestCase):
    relay_readback_present = False

    def test_refresh_records_a_read_only_readback_and_sends_nothing(self):
        session = I.FakeEosSession(I.upstream_config(extra=o82.GLOBAL_LINE))
        result = R.refresh("S1", actor=REQUESTER, executor_factory=factory(session))
        self.assertTrue(result.ok)
        row = models.DhcpRelayReadback.objects.get(pk=result.detail["readback"])
        self.assertEqual((row.source, row.readback["enabled"], len(row.config_digest)), (models.DhcpRelayReadbackSource.READ, True, 64))
        self.assertEqual(session.sent, [])

    def test_refresh_refuses_an_unverified_platform_and_an_unreadable_relay(self):
        self.assertEqual(R.refresh("R3", actor=REQUESTER).codes, ["OPTION82_PLATFORM_NOT_IMPLEMENTED"])
        self.assertEqual(R.refresh("S1", actor=REQUESTER, executor_factory=broken_factory).codes, ["RELAY_UNREADABLE"])

    def test_trusted_readback_returns_the_latest_fresh_readback(self):
        Z.record_relay_readback(now=timezone.now() - timedelta(hours=2), enabled=False)
        Z.record_relay_readback()
        self.assertTrue(R.trusted_readback("S1")["enabled"])

    @override_settings(NMAS_OPTION82_READBACK_MAX_AGE_SECONDS=60)
    def test_trusted_readback_refuses_a_stale_or_missing_readback(self):
        self.assertIsNone(R.trusted_readback("S1"))
        Z.record_relay_readback(now=timezone.now() - timedelta(minutes=5))
        self.assertIsNone(R.trusted_readback("S1"))
        self.assertEqual(R.readback_max_age_seconds(), 60.0)

    def test_readback_max_age_seconds_returns_one_day_by_default(self):
        self.assertEqual(R.readback_max_age_seconds(), 86400.0)

    def test_readback_row_save_creates_one_stored_row(self):
        row = models.DhcpRelayReadback(device="S1", source=models.DhcpRelayReadbackSource.READ, readback={"enabled": True},
                                       config_digest="a" * 64, captured_by=REQUESTER, captured_at=timezone.now())
        row.save()
        self.assertIsNotNone(row.pk)
        self.assertEqual(models.DhcpRelayReadback.objects.get(pk=row.pk).readback, {"enabled": True})

    def test_record_readback_refuses_an_edit_a_delete_and_a_bad_digest(self):
        row = Z.record_relay_readback()
        with self.assertRaises(ValueError):
            row.save()
        with self.assertRaises(ValueError):
            row.delete()
        with self.assertRaises(ValueError):
            models.DhcpRelayReadback.objects.filter(pk=row.pk).update(device="S2")
        with self.assertRaises(ValueError):
            R.record_readback("S1", {}, source=models.DhcpRelayReadbackSource.READ, digest="short", actor=REQUESTER)
        with self.assertRaises(ValueError):
            R.record_readback("S1", {}, source="GUESS", digest="0" * 64, actor=REQUESTER)

    def test_giaddr_port_returns_the_one_routed_port_owning_the_relay_address(self):
        self.assertEqual(R.giaddr_port(Z.relay_readback(), Z.RELAY), "Ethernet7")

    def test_giaddr_port_refuses_an_unknown_shared_or_switched_address(self):
        shared = Z.relay_readback()
        shared["interfaces"]["Ethernet8"] = dict(shared["interfaces"]["Ethernet7"])
        self.assertEqual([R.giaddr_port(Z.relay_readback(), "10.254.30.99"), R.giaddr_port(shared, Z.RELAY),
                          R.giaddr_port(Z.relay_readback(port="Vlan30"), Z.RELAY), R.giaddr_port(Z.relay_readback(), "bad")], ["", "", "", ""])

    def test_required_for_and_platform_of_accept_a_verified_option82_platform(self):
        self.assertEqual((R.platform_of("S1"), R.required_for("S1")), ("arista_ceos", True))

    def test_required_for_refuses_an_unverified_or_unknown_upstream(self):
        self.assertEqual([R.required_for("R3"), R.required_for("NOPE"), R.platform_of("NOPE")], [False, False, ""])


class TrustTests(Z.ZtpTestMixin, TestCase):
    relay_readback_present = False

    def test_lease_problem_accepts_the_circuit_the_giaddr_port_inserts(self):
        Z.record_relay_readback()
        self.assertEqual(R.lease_problem("S1", Z.RELAY, "Ethernet7"), "")
        self.assertEqual(R.lease_problem("R3", Z.RELAY, "anything"), "")          # unverified platform: the existing rules stand alone

    def test_lease_problem_refuses_a_forged_circuit_an_unread_relay_and_an_unknown_giaddr(self):
        self.assertEqual(R.lease_problem("S1", Z.RELAY, "Ethernet7"), "RELAY_READBACK_MISSING")
        Z.record_relay_readback()
        self.assertEqual(R.lease_problem("S1", Z.RELAY, "Ethernet3"), "OPTION82_CIRCUIT_FORGED")
        self.assertEqual(R.lease_problem("S1", "10.254.30.77", "Ethernet7"), "RELAY_UNTRUSTED")
        Z.record_relay_readback(enabled=False)                                     # the relay inserts nothing: any circuit is the client's
        self.assertEqual(R.lease_problem("S1", Z.RELAY, "Ethernet7"), "OPTION82_CIRCUIT_FORGED")

    def test_ztp_open_is_blocked_without_a_fresh_relay_readback(self):
        device, attachment, _auth = L.ready_device()
        checks = {c["check"]: c for c in dependencies.evaluate(device, attachment, self.network())}
        self.assertEqual((checks["bootstrap_path_option82"]["ok"], checks["bootstrap_path_option82"]["code"]), (False, "RELAY_READBACK_MISSING"))
        Z.record_relay_readback(enabled=False)
        checks = {c["check"]: c for c in dependencies.evaluate(device, attachment, self.network(name="ztp-test-2"))}
        self.assertEqual(checks["bootstrap_path_option82"]["code"], "RELAY_UNTRUSTED")

    def test_ztp_open_passes_with_the_stored_readback_of_the_relay(self):
        Z.record_relay_readback()
        device, attachment, _auth = L.ready_device()
        checks = {c["check"]: c for c in dependencies.evaluate(device, attachment, self.network())}
        self.assertTrue(checks["bootstrap_path_option82"]["ok"], checks["bootstrap_path_option82"])

    def test_discovery_refuses_a_lease_carrying_a_forged_circuit_id(self):
        Z.record_relay_readback()
        session = Z.ZtpTestMixin.open_session(self)
        Z.record_relay_readback()                                                 # still fresh at discovery
        summary = discovery.ingest(session.network, text=Z.lease(circuit="Ethernet3"))
        observation = models.DhcpLeaseObservation.objects.get()
        self.assertEqual((observation.outcome, observation.code, observation.relay_trusted, observation.upstream_device),
                         (models.DhcpLeaseOutcome.UNTRUSTED_RELAY, "OPTION82_CIRCUIT_FORGED", False, ""))
        self.assertEqual(summary["outcomes"], {"UNTRUSTED_RELAY": 1})
        session.refresh_from_db()
        self.assertEqual(session.stage, models.ZtpSessionStage.AWAITING_DISCOVERY)

    def test_discovery_accepts_the_circuit_the_relay_inserts(self):
        Z.record_relay_readback()
        session = Z.ZtpTestMixin.open_session(self)
        discovery.ingest(session.network, text=Z.lease())
        self.assertEqual(models.DhcpLeaseObservation.objects.get().outcome, models.DhcpLeaseOutcome.CORRELATED)


class ResultTests(TestCase):
    def test_option82_result_codes_returns_the_blocker_codes(self):
        self.assertEqual(R.Option82Result(False, "X", None, [transaction.blocker("A"), transaction.blocker("B")]).codes, ["A", "B"])

    def test_option82_result_codes_of_a_success_are_empty(self):
        self.assertEqual(R.Option82Result(True, "X").codes, [])


class ExecutorTypeTests(TestCase):
    def test_ceos_executor_refuses_an_option82_statement_without_its_declared_inverse(self):
        from core.services.execution.executors.base import ConfigletSpec

        session = I.FakeEosSession(I.upstream_config())
        executor = CeosExecutor({"name": "S1", "platform": "ceos"}, connection_factory=lambda d: session, reader=I._facts)  # pylint: disable=protected-access
        executor.connect()
        spec = ConfigletSpec("CFG-001", 1, "S1", "arista_ceos", R.OBJECT_TYPE, "CREATE_DEFINE", (o82.GLOBAL_LINE,),
                             {"present_paths": [o82.GLOBAL_LINE], "inverse_lines": []})
        self.assertFalse(executor.assess(spec).restorable)
        self.assertIsInstance(ExecutorError("X"), Exception)


def _governed_files():
    """The shape the governed live run records (core.tests.live_option82_ztp_fixture); every stage satisfied."""
    return {
        "o82-10-gate.json": {"gate_with_option82_off": {"ok": False, "code": "RELAY_UNTRUSTED"}},
        "o82-20-fault-compensated.json": {"execute": {"ok": False, "compensation": {"status": "COMPENSATED", "not_compensated": []}},
                                          "up1_digest_restored": True},
        "o82-30-governed-apply.json": {"plan": {"ok": True, "codes": [], "change": "CHG-1", "source": {"relay": "dhcp_x", "revision": 2}},
                                       "configlets": [{"object_type": "dhcp_relay_option82", "lines": ["ip dhcp relay information option"]}],
                                       "execute": {"ok": True, "outcome": "SUCCEEDED"}, "change_state": "DEPLOYED",
                                       "readback": {"enabled": True, "change": "CHG-1"}, "gate_after": {"ok": True}},
        "o82-40-forged-option82.json": {"relayed_requests": [{"circuit_id": "Ethernet1", "nmas_discovery_gate": "TRUSTED"},
                                                             {"circuit_id": "Ethernet9", "nmas_discovery_gate": "OPTION82_CIRCUIT_FORGED"}]},
        "o82-50-native-ztp.json": {"lease_observations": [{"outcome": "CORRELATED", "relay_trusted": True, "circuit_id": "Ethernet1"}],
                                   "new1_relayed_requests": [{"circuit_id": "Ethernet1", "giaddr": "10.254.60.1"}]},
    }


class GovernedLedgerRowTests(TestCase):
    def test_governed_row_with_every_stage_recorded_is_supported(self):
        from core.services.capabilities import phase9_ledger as P

        row = P.governed_option82_row(_governed_files(), evidence_path="docs/x")
        self.assertEqual((row["closure_class"], row["missing_stages"], row["evidence"]), ("SUPPORTED", [], "docs/x"))

    def test_governed_row_missing_or_failed_evidence_is_never_supported(self):
        from core.services.capabilities import phase9_ledger as P

        def broken(mutate):
            files = _governed_files()
            mutate(files)
            return P.governed_option82_row(files)

        cases = {
            "execution": lambda f: f["o82-30-governed-apply.json"]["execute"].update(outcome="FAILED_ROLLED_BACK"),
            "readback": lambda f: f["o82-30-governed-apply.json"]["readback"].update(change="CHG-OTHER"),
            "compensation": lambda f: f["o82-20-fault-compensated.json"]["execute"]["compensation"].update(status="UNCERTAIN"),
            "restoration": lambda f: f["o82-20-fault-compensated.json"].update(up1_digest_restored=False),
            "live": lambda f: f["o82-40-forged-option82.json"]["relayed_requests"][1].update(nmas_discovery_gate="TRUSTED"),
        }
        for stage, mutate in cases.items():
            with self.subTest(stage):
                row = broken(mutate)
                self.assertNotEqual(row["closure_class"], "SUPPORTED")
                self.assertIn(stage, row["missing_stages"])
        for name in P.GOVERNED_OPTION82_FILES:
            with self.subTest(missing=name):
                self.assertNotEqual(broken(lambda f, n=name: f.pop(n))["closure_class"], "SUPPORTED")
        self.assertEqual(P.governed_option82_row(None)["closure_class"], "NOT_IMPLEMENTED")

    def test_governed_row_from_the_committed_live_evidence_is_supported(self):
        import json
        from pathlib import Path

        from django.conf import settings

        from core.services.capabilities import phase9_ledger as P

        folder = Path(settings.REPO_ROOT) / "docs/evidence/v2-phase9-closure/option82"
        files = {name: json.loads((folder / name).read_text()) for name in P.GOVERNED_OPTION82_FILES}
        row = P.governed_option82_row(files, evidence_path="docs/evidence/v2-phase9-closure/option82")
        self.assertEqual((row["closure_class"], row["missing_stages"]), ("SUPPORTED", []))
