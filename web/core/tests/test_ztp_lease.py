"""DHCP lease lifetime of an open ZTP session: lapse, genuine renewal, post-delivery release and the controlled re-discovery window."""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from core import models
from core.services.devices import events, stage_report
from core.services.ztp import adapters, artifacts, discovery, lease
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

Stage = models.ZtpSessionStage
OK_PATH = [{"check": c, "ok": True, "code": "", "detail": ""} for c in
           ("upstream_ready", "attachment_approved", "trusted_isolation", "bootstrap_network", "bootstrap_path_relay", "native_ztp_adapter")]


class LeaseLapseTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.start = timezone.now().replace(microsecond=0) - timedelta(minutes=1)
        self.session = self.open_session()
        self.network = self.session.network
        discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10))
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, Stage.DISCOVERED)

    def actions(self):
        return list(self.session.device.lifecycle_events.order_by("sequence").values_list("action", "outcome"))

    def test_active_binding_is_reported_and_changes_nothing(self):
        summary = discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10))
        self.assertEqual(summary["lapsed"], [])
        self.assertEqual(lease.status(self.session)["state"], lease.ACTIVE)

    def test_expiry_before_delivery_returns_the_session_to_discovery(self):
        later = self.start + timedelta(minutes=11)
        summary = discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10), now=later)
        self.assertEqual(summary["lapsed"], [self.session.session_id])
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, Stage.AWAITING_DISCOVERY)
        self.assertEqual(self.session.discovery["lapsed"]["state"], lease.EXPIRED)
        self.assertIn("address", self.session.discovery["previous"])            # stale facts kept, not erased
        device = models.ManagedDevice.objects.get(pk=self.session.device_id)
        self.assertEqual(device.lifecycle_state, models.DeviceLifecycleState.DISCOVERED)   # history is never rewritten
        self.assertIn(("ZTP_LEASE_LAPSED", "RECORDED"), self.actions())
        self.assertTrue(events.verify_chain(device))

    def test_release_before_delivery_lapses_as_ended(self):
        discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10) + Z.released())
        self.session.refresh_from_db()
        self.assertEqual((self.session.stage, self.session.discovery["lapsed"]["state"]), (Stage.AWAITING_DISCOVERY, lease.ENDED))

    def test_a_reread_of_the_lapsed_lease_file_is_not_a_renewal(self):
        text = Z.lease(start=self.start, minutes=10) + Z.released()
        discovery.ingest(self.network, text=text)
        for _ in range(3):
            discovery.ingest(self.network, text=text)
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, Stage.AWAITING_DISCOVERY)
        self.assertEqual([a for a in self.actions() if a[0].startswith("ZTP_LEASE")], [("ZTP_LEASE_LAPSED", "RECORDED")])

    def test_genuine_renewal_readvances_after_the_authorization_is_decided_again(self):
        later = self.start + timedelta(minutes=11)
        discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10), now=later)
        discovery.ingest(self.network, text=Z.lease(start=later, minutes=10), now=later + timedelta(seconds=5))
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, Stage.DISCOVERED)
        self.assertEqual(self.session.discovery["renewed_after"]["state"], lease.EXPIRED)
        renewed = self.session.device.lifecycle_events.get(action="ZTP_LEASE_RENEWED")
        self.assertEqual(renewed.outcome, "RECORDED")
        self.assertFalse(renewed.evidence["bootstrap_decision"]["production_admission"])
        self.assertEqual(lease.status(self.session, now=later + timedelta(seconds=5))["state"], lease.ACTIVE)

    def test_renewal_after_the_bootstrap_authorization_expired_is_refused(self):
        auth = self.session.authorization
        after = auth.valid_until + timedelta(minutes=1)
        discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10), now=after)          # lapses
        discovery.ingest(self.network, text=Z.lease(start=after, minutes=10), now=after + timedelta(seconds=5))
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, Stage.AWAITING_DISCOVERY)
        self.assertEqual(self.session.device.lifecycle_events.get(action="ZTP_LEASE_RENEWED").outcome, "REFUSED")

    def test_release_after_delivery_is_expected_and_never_regresses(self):
        models.ZtpSession.objects.filter(pk=self.session.pk).update(stage=Stage.DELIVERED)
        summary = discovery.ingest(self.network, text=Z.lease(start=self.start, minutes=10) + Z.released())
        self.session.refresh_from_db()
        self.assertEqual((summary["lapsed"], self.session.stage), ([], Stage.DELIVERED))
        report = lease.status(self.session)
        self.assertEqual(report["state"], lease.ENDED)
        self.assertIn("expected", report["meaning"])

    def test_delivery_refuses_an_ended_binding_even_with_a_future_end_time(self):
        observation = lease.binding(self.session)
        self.assertIsNotNone(artifacts._bound_lease(self.session, observation.address, timezone.now()))
        models.DhcpLeaseObservation.objects.filter(pk=observation.pk).update(binding_state="released",
                                                                             lease_ends=timezone.now() + timedelta(hours=1))
        self.assertIsNone(artifacts._bound_lease(self.session, observation.address, timezone.now()))


class LapseInStageReportTests(Z.ZtpTestMixin, TestCase):
    def test_a_lapsed_lease_is_visible_as_pending_discovery_with_its_evidence(self):
        session = self.discovered()
        discovery.ingest(session.network, text=Z.lease(), now=timezone.now() + timedelta(hours=1))
        session.refresh_from_db()
        device = models.ManagedDevice.objects.get(pk=session.device_id)
        report = stage_report.device_report(device)
        self.assertEqual({s['stage']: s['status'] for s in report['stages']}["DISCOVERED"], stage_report.COMPLETE)       # history kept: it WAS discovered
        self.assertEqual(session.stage, models.ZtpSessionStage.AWAITING_DISCOVERY)
        self.assertIn("ZTP_LEASE_LAPSED", [e.action for e in device.lifecycle_events.all()])
        self.assertTrue(report["evidence"]["chain_intact"])



class RenewalWindowTests(Z.ZtpTestMixin, TestCase):
    """The downstream device (R7 analogue) waits behind its upstream; once the path qualifies NMAS expects its native retry."""

    def setUp(self):
        super().setUp()
        self.session = self.open_session()
        self.network = self.session.network
        self.now = timezone.now().replace(microsecond=0)

    def test_window_is_refused_while_the_upstream_is_not_admitted(self):
        waiting = [*OK_PATH[1:], {"check": "upstream_ready", "ok": False, "code": "UPSTREAM_NOT_TRUSTED", "detail": "R6"}]
        ok, problems, record = lease.expect_renewal(self.session, actor=L.OPERATOR, checks=waiting, now=self.now)
        self.assertFalse(ok)
        self.assertEqual([p["code"] for p in problems], ["ZTP_BOOTSTRAP_PATH_NOT_READY"])
        self.assertEqual(problems[0]["details"]["failing"][0]["code"], "UPSTREAM_NOT_TRUSTED")
        self.assertEqual(record, {})
        self.assertEqual(self.session.device.lifecycle_events.get(action="ZTP_RENEWAL_EXPECTED").outcome, "REFUSED")
        self.session.refresh_from_db()
        self.assertEqual(lease.renewal_status(self.session)["state"], lease.NOT_EXPECTED)

    def test_dhcpv6_solicit_is_not_claimed(self):
        ok, problems, _ = lease.expect_renewal(self.session, actor=L.OPERATOR, family=6, checks=OK_PATH, now=self.now)
        self.assertFalse(ok)
        self.assertIn("DHCPV6_DISCOVERY_NOT_IMPLEMENTED", [p["code"] for p in problems])

    def test_window_from_the_adapter_retry_then_observed(self):
        ok, problems, record = lease.expect_renewal(self.session, actor=L.OPERATOR, checks=OK_PATH, now=self.now)
        self.assertTrue(ok, problems)
        self.assertEqual(record["window_seconds"], 120)           # cEOS: documented 30 s DISCOVER retry x 4
        self.session.refresh_from_db()
        self.assertEqual(lease.renewal_status(self.session, now=self.now + timedelta(seconds=10))["state"], lease.PENDING)
        discovery.ingest(self.network, text=Z.lease(start=self.now + timedelta(seconds=30)), now=self.now + timedelta(seconds=31))
        self.session.refresh_from_db()
        report = lease.renewal_status(self.session, now=self.now + timedelta(seconds=40))
        self.assertEqual(report["state"], lease.OBSERVED)
        self.assertTrue(report["within_window"])
        self.assertEqual(self.session.stage, Stage.DISCOVERED)
        self.assertIn("renewal", self.session.discovery)
        self.assertTrue(events.verify_chain(self.session.device))

    def test_no_request_in_the_window_is_overdue_with_native_recovery_only(self):
        lease.expect_renewal(self.session, actor=L.OPERATOR, checks=OK_PATH, now=self.now)
        self.session.refresh_from_db()
        report = lease.renewal_status(self.session, now=self.now + timedelta(seconds=121))
        self.assertEqual(report["state"], lease.OVERDUE)
        self.assertEqual(report["recovery"][0]["key"], "WAIT_NATIVE_RETRY")
        self.assertTrue(all(action["native"] for action in report["recovery"]))
        self.assertNotIn("link", " ".join(a["command"] + a["label"] for a in report["recovery"]).lower())

    def test_a_session_already_discovered_needs_no_window(self):
        discovery.ingest(self.network, text=Z.lease())
        self.session.refresh_from_db()
        ok, problems, _ = lease.expect_renewal(self.session, actor=L.OPERATOR, checks=OK_PATH)
        self.assertFalse(ok)
        self.assertEqual(problems[0]["code"], "ZTP_SESSION_STATE_INVALID")


class RenewalWindowUnitTests(SimpleTestCase):
    def test_adapters_without_a_documented_interval_open_no_window(self):
        windows = {name: lease.renewal_window_seconds(adapters.get(name)) for name in adapters.ADAPTERS}
        self.assertEqual(windows["arista_eos"], 120)
        self.assertIn(None, windows.values())                     # e.g. IOS XE documents no interval: no window is invented
