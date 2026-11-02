"""Lab 7 closure -- V2 Phase 3 bootstrap policy, dependency checks, discovery folding and artifact bookkeeping, called directly.

``test_ztp_dhcp`` / ``test_ztp_discovery`` / ``test_ztp_artifacts`` prove these through the workflow and ``discovery.ingest`` /
``artifacts.authorize``; this module calls the helpers those flows are built from.  POSITIVE -- relay lookups, pool allocation,
URLs, eligible sessions, stored-network validation, dependency blockers, idempotency keys, folded bindings, artifact identity,
supersession and closure.  NEGATIVE -- an exhausted pool, an unknown upstream, a closed session, a missing network, an untrusted
relay, a release with no binding and an adapter-less request all yield nothing (or a refusal), never an invented value.

NMAS test database plus a temporary isolated provider root only (``ZtpTestMixin``).
"""
from __future__ import annotations

import hashlib
from datetime import timedelta
from types import SimpleNamespace

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.ztp import artifacts, dependencies, discovery, policy, workflow
from core.services.ztp.adapters.base import RenderedBootstrap
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z
from core.tests.test_ztp_dhcp import SupervisorRunner

State = models.BootstrapArtifactState


class PurePolicyTests(SimpleTestCase):
    NET = SimpleNamespace(trusted_relays=[{"relay_address": "10.254.30.1", "upstream_device": "S1"},
                                          {"relay_address": "10.254.30.2", "upstream_device": "S2"}],
                          service_address="10.254.31.2", http_port=8080)

    def test_reserved_prefix_list_includes_vlan_200_and_configured_extras(self):
        with override_settings(NMAS_ZTP_PROTECTED_PREFIXES=["10.99.0.0/16"]):
            found = [str(p) for p in policy.protected_prefixes()]
        self.assertIn("192.168.200.0/24", found)
        self.assertIn("172.20.20.0/24", found)
        self.assertEqual(found[-1], "10.99.0.0/16")

    def test_relay_for_returns_the_upstream_relay_address(self):
        self.assertEqual(policy.relay_for(self.NET, "S2"), "10.254.30.2")

    def test_relay_for_an_upstream_that_relays_nothing_is_empty(self):
        self.assertEqual(policy.relay_for(self.NET, "S9"), "")
        self.assertEqual(policy.relay_for(SimpleNamespace(trusted_relays=None), "S1"), "")

    def test_relay_map_maps_each_relay_to_its_upstream(self):
        self.assertEqual(policy.relay_map(self.NET), {"10.254.30.1": "S1", "10.254.30.2": "S2"})

    def test_relay_map_of_a_network_without_relays_is_empty(self):
        self.assertEqual(policy.relay_map(SimpleNamespace(trusted_relays=None)), {})

    def test_artifact_url_is_the_http_path_on_the_service_address(self):
        art = SimpleNamespace(artifact_id="ART-" + "a" * 24, filename="startup-config", transport="HTTP")
        self.assertEqual(policy.artifact_url(self.NET, art), f"http://10.254.31.2:8080/ztp/v1/ART-{'a' * 24}/startup-config")

    def test_artifact_url_for_tftp_or_port_80_never_carries_a_port(self):
        tftp = SimpleNamespace(artifact_id="ART-" + "b" * 24, filename="ztp.py", transport="TFTP")
        self.assertEqual(policy.artifact_url(self.NET, tftp), f"tftp://10.254.31.2/ztp/v1/ART-{'b' * 24}/ztp.py")
        http80 = SimpleNamespace(trusted_relays=[], service_address="10.254.31.2", http_port=80)
        self.assertEqual(policy.artifact_url(http80, SimpleNamespace(artifact_id="ART-c", filename="f", transport="HTTP")),
                         "http://10.254.31.2/ztp/v1/ART-c/f")

    def test_blockers_collect_the_code_of_each_unsatisfied_check(self):
        checks = [{"check": "a", "ok": True, "code": ""}, {"check": "b", "ok": False, "code": "UPSTREAM_NOT_READY"}]
        self.assertEqual(dependencies.blockers(checks), ["UPSTREAM_NOT_READY"])

    def test_blockers_of_passing_checks_are_empty(self):
        self.assertEqual(dependencies.blockers([{"check": "a", "ok": True, "code": ""}]), [])
        self.assertEqual(dependencies.blockers([]), [])

    def test_idempotency_key_is_a_stable_digest_of_the_binding(self):
        row = {"address": "10.254.30.10", "client_mac": "a2:27:1c:9a:b6:7b", "client_id": "x", "relay_address": "10.254.30.1",
               "circuit_id": "Ethernet7", "vendor_class": "Arista;"}
        key = discovery.idempotency_key(SimpleNamespace(pk=7), row)
        self.assertEqual(key, hashlib.sha256("7|10.254.30.10|a2:27:1c:9a:b6:7b|x|10.254.30.1|Ethernet7|Arista;".encode()).hexdigest())
        self.assertEqual(key, discovery.idempotency_key(SimpleNamespace(pk=7), dict(row)))

    def test_idempotency_key_never_merges_a_different_port_or_a_partial_row(self):
        row = {"address": "10.254.30.10", "circuit_id": "Ethernet7"}
        self.assertNotEqual(discovery.idempotency_key(SimpleNamespace(pk=7), row),
                            discovery.idempotency_key(SimpleNamespace(pk=7), {**row, "circuit_id": "Ethernet8"}))
        self.assertNotEqual(discovery.idempotency_key(SimpleNamespace(pk=7), row), discovery.idempotency_key(SimpleNamespace(pk=8), row))

    def test_make_artifact_id_derives_the_id_from_session_and_digest(self):
        expected = "ART-" + hashlib.sha256(b"3|abc").hexdigest()[:24]
        self.assertEqual(artifacts.make_artifact_id(SimpleNamespace(pk=3), "abc"), expected)

    def test_make_artifact_id_never_collides_across_sessions_or_content(self):
        ids = {artifacts.make_artifact_id(SimpleNamespace(pk=pk), digest) for pk in (1, 2) for digest in ("a", "b")}
        self.assertEqual(len(ids), 4)

    def test_request_for_lease_without_an_adapter_carries_no_identity_claim(self):
        lease = SimpleNamespace(vendor_class="Arista;cEOSLab;SN-NEW1", client_id=Z.CLIENT_ID, hostname="", upstream_device="S1",
                                upstream_interface="Ethernet7")
        request = artifacts.request_for_lease(SimpleNamespace(adapter="no-such-adapter"), lease)
        self.assertEqual((request["serial"], request["base_mac"], request["upstream_device"]), ("", "", "S1"))


class NetworkPolicyClosureTests(Z.ZtpTestMixin, TestCase):
    def test_stored_network_check_of_a_valid_active_network_passes(self):
        L.adopt()
        self.assertEqual(policy.stored_network_problems(self.network()), [])

    def test_stored_network_problems_of_a_missing_or_retired_network_are_refused(self):
        self.assertEqual([p["code"] for p in policy.stored_network_problems(None)], ["BOOTSTRAP_NETWORK_NOT_FOUND"])
        retired = SimpleNamespace(state="RETIRED")
        self.assertEqual([p["code"] for p in policy.stored_network_problems(retired)], ["BOOTSTRAP_NETWORK_NOT_FOUND"])

    def test_allocate_address_returns_the_first_free_pool_address(self):
        session = self.open_session()
        self.assertEqual(session.reserved_address, "10.254.30.10")
        self.assertEqual(policy.allocate_address(session.network), "10.254.30.11")

    def test_allocate_address_of_an_exhausted_pool_is_empty(self):
        device, _attachment, auth = L.ready_device()
        network = self.network(pool_end="10.254.30.10")
        self.assertTrue(workflow.open_session(device, authorization=auth, network=network, actor=L.OPERATOR).ok)
        self.assertEqual(policy.allocate_address(network), "")

    def test_eligible_sessions_lists_the_open_approved_session(self):
        session = self.open_session()
        self.assertEqual(list(policy.eligible_sessions(session.network)), [session])

    def test_eligible_sessions_never_include_a_cancelled_or_expired_session(self):
        session = self.open_session()
        later = timezone.now() + timedelta(hours=2)
        self.assertEqual(list(policy.eligible_sessions(session.network, now=later)), [])      # outside the authorization window
        workflow.cancel_session(session, actor=L.APPROVER, reason="test")
        self.assertEqual(list(policy.eligible_sessions(session.network)), [])

    def test_policy_is_not_current_before_any_application(self):
        session = self.open_session()
        self.assertFalse(policy.policy_current(session.network))

    def test_validate_policy_with_a_failing_validator_or_missing_network_is_refused(self):
        session = self.open_session()
        row, problems = policy.validate_policy(session.network, actor=L.OPERATOR, runner=SupervisorRunner(self.root / "dhcp", rc=1))
        self.assertEqual((row.state, [p["code"] for p in problems]), ("FAILED", ["DHCP_PROVIDER_ERROR"]))
        row, problems = policy.validate_policy(None, actor=L.OPERATOR)
        self.assertEqual((row, [p["code"] for p in problems]), (None, ["BOOTSTRAP_NETWORK_NOT_FOUND"]))


class DependencyClosureTests(Z.ZtpTestMixin, TestCase):
    def test_evaluate_without_an_attachment_or_network_is_refused(self):
        device, attachment, _auth = L.ready_device()
        self.assertEqual(dependencies.blockers(dependencies.evaluate(device, None, None)), ["ATTACHMENT_NOT_FOUND"])
        self.assertEqual(dependencies.blockers(dependencies.evaluate(device, attachment, None))[-1], "BOOTSTRAP_NETWORK_NOT_FOUND")

    def test_downstream_waiting_of_a_device_with_no_downstream_is_empty(self):
        device, _attachment, _auth = L.ready_device()
        self.assertEqual(dependencies.downstream_waiting(device), [])


class DiscoveryClosureTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.session = self.open_session()
        self.network = self.session.network

    def row(self, text):
        return discovery.dhcp.for_network(self.network).parse_leases(text)[0]

    def test_fold_correlates_a_trusted_lease_and_repeats_only_count(self):
        observation, created = discovery.fold(self.network, self.row(Z.lease()))
        self.assertEqual((created, observation.outcome, observation.upstream_device), (True, models.DhcpLeaseOutcome.CORRELATED, "S1"))
        again, created = discovery.fold(self.network, self.row(Z.lease()))
        self.assertEqual((created, again.pk, again.seen_count), (False, observation.pk, 2))

    def test_fold_of_an_untrusted_relay_or_an_unseen_release_is_refused(self):
        observation, created = discovery.fold(self.network, self.row(Z.lease(relay="10.254.30.99")))
        self.assertEqual((created, observation.outcome, observation.relay_trusted), (True, models.DhcpLeaseOutcome.UNTRUSTED_RELAY, False))
        self.assertEqual(discovery.fold(self.network, self.row(Z.released(address="10.254.30.15"))), (None, None))

    def test_read_lease_file_returns_the_provider_lease_database(self):
        (self.root / "dhcp" / "dhcpd.leases").write_text(Z.lease(), encoding="utf-8")
        text = discovery.read_lease_file(self.network)
        self.assertEqual(text, (self.root / "dhcp" / "dhcpd.leases").read_text(encoding="utf-8"))
        self.assertIn("lease 10.254.30.10 {", text)


class ArtifactClosureTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.session = self.open_session()
        self.artifact = self.session.artifacts.get(state=State.ACTIVE)

    def test_create_stores_a_new_artifact_and_supersedes_the_active_one(self):
        rendered = RenderedBootstrap("startup-config", "hostname NEW1\n", "text/plain", "startup-config")
        created = artifacts.create(self.session, rendered, expires_at=timezone.now() + timedelta(minutes=30))
        self.assertEqual((created.state, created.sha256), (State.ACTIVE, hashlib.sha256(b"hostname NEW1\n").hexdigest()))
        self.assertEqual(created.artifact_id, artifacts.make_artifact_id(self.session, created.sha256))
        self.artifact.refresh_from_db()
        self.assertEqual(self.artifact.state, State.SUPERSEDED)

    def test_close_for_session_revokes_the_active_artifact(self):
        self.assertEqual(artifacts.close_for_session(self.session), 1)
        self.artifact.refresh_from_db()
        self.assertEqual(self.artifact.state, State.REVOKED)

    def test_close_for_session_with_no_active_artifact_changes_nothing(self):
        artifacts.close_for_session(self.session, State.EXPIRED)
        self.assertEqual(artifacts.close_for_session(self.session), 0)
        self.artifact.refresh_from_db()
        self.assertEqual(self.artifact.state, State.EXPIRED)

    def test_expire_due_with_nothing_due_expires_none(self):
        self.assertEqual(artifacts.expire_due(), 0)
        self.artifact.refresh_from_db()
        self.assertEqual(self.artifact.state, State.ACTIVE)

    def test_request_for_lease_takes_claims_from_the_lease_and_the_port_from_the_relay(self):
        discovery.ingest(self.session.network, text=Z.lease())
        lease = self.session.lease_observations.get()
        request = artifacts.request_for_lease(self.session, lease)
        self.assertEqual(request, {"scope": "BOOTSTRAP_FETCH", "serial": L.SERIAL, "base_mac": L.MAC, "upstream_device": "S1",
                                   "upstream_interface": "Ethernet7", "attachment_source": models.ObservationSource.DHCP_RELAY_ATTACHMENT})
