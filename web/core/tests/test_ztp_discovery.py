"""V2 Phase 3: discovery ingestion -- DHCP claims vs trusted relay evidence, idempotency, refusals and the lifecycle effect."""

from __future__ import annotations

from django.test import TestCase

from core import models
from core.services.ztp import discovery, policy
from core.tests.helpers import lifecycle as L
from core.tests.helpers import ztp as Z

O = models.DhcpLeaseOutcome


class DiscoveryTests(Z.ZtpTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.session = self.open_session()
        self.network = self.session.network

    def outcome(self, text):
        summary = discovery.ingest(self.network, text=text)
        return summary, models.DhcpLeaseObservation.objects.order_by("-id").first()

    def test_trusted_relay_correlates_and_records_claims_separately_from_attachment(self):
        summary, row = self.outcome(Z.lease())
        self.assertEqual((summary["new"], row.outcome, row.relay_trusted, row.upstream_device, row.upstream_interface),
                         (1, O.CORRELATED, True, "S1", "Ethernet7"))
        self.session.refresh_from_db()
        device = self.session.device
        device.refresh_from_db()
        self.assertEqual(self.session.stage, models.ZtpSessionStage.DISCOVERED)
        self.assertEqual(device.lifecycle_state, models.DeviceLifecycleState.DISCOVERED)
        self.assertEqual(device.ztp_state, models.ZtpState.ENABLED)
        self.assertEqual(device.identity_state, models.IdentityVerificationState.PENDING_VERIFICATION)   # DHCP is never identity proof
        identity = row.identity_observation
        attachment = row.attachment_observation
        self.assertEqual((identity.source, identity.trust), (models.ObservationSource.DHCP_CLIENT_CLAIM, models.ObservationTrust.CLAIMED))
        self.assertEqual((attachment.source, attachment.trust), (models.ObservationSource.DHCP_RELAY_ATTACHMENT, models.ObservationTrust.OBSERVED))
        self.assertEqual((identity.claims["serial"], identity.claims["base_mac"]), (L.SERIAL, L.MAC))
        event = device.lifecycle_events.get(action="ZTP_DISCOVERY")
        self.assertEqual(event.outcome, models.DeviceLifecycleEventOutcome.RECORDED)
        self.assertFalse(event.authorization["production_admission"])

    def test_retransmissions_and_rereads_are_idempotent(self):
        text = Z.lease()
        self.outcome(text)
        events_before = self.session.device.lifecycle_events.count()
        observations_before = models.DeviceObservation.objects.count()
        for _ in range(3):
            summary, _row = self.outcome(text)
            self.assertEqual((summary["new"], summary["repeat"]), (0, 1))
        row = models.DhcpLeaseObservation.objects.get()
        self.assertEqual(row.seen_count, 4)
        self.assertEqual(self.session.device.lifecycle_events.count(), events_before)
        self.assertEqual(models.DeviceObservation.objects.count(), observations_before)

    def test_release_block_ends_the_binding_and_is_never_untrusted(self):
        """Live regression: cEOS releases its lease after applying the bootstrap; ISC appends a relay-less ``free`` block."""
        self.outcome(Z.lease())
        summary = discovery.ingest(self.network, text=Z.lease() + Z.released())
        self.assertEqual((summary["new"], summary["inactive"]), (0, 1))
        self.assertFalse(models.DhcpLeaseObservation.objects.filter(outcome=O.UNTRUSTED_RELAY).exists())
        self.assertEqual(models.DhcpLeaseObservation.objects.get().binding_state, "free")

    def test_release_of_an_unseen_binding_is_ignored(self):
        summary = discovery.ingest(self.network, text=Z.released("10.254.30.15"))
        self.assertEqual((summary["new"], summary["inactive"]), (0, 1))
        self.assertFalse(models.DhcpLeaseObservation.objects.exists())

    def test_untrusted_or_missing_relay_changes_nothing(self):
        for label, text in (("unknown relay", Z.lease(relay="10.254.30.99")), ("no relay", Z.lease(relay="")),
                            ("no circuit id", Z.lease(circuit="", mac="a2:00:00:00:00:02"))):
            with self.subTest(label):
                _summary, row = self.outcome(text)
                self.assertEqual((row.outcome, row.code, row.relay_trusted, row.device), (O.UNTRUSTED_RELAY, "RELAY_UNTRUSTED", False, None))
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, models.ZtpSessionStage.AWAITING_DISCOVERY)
        self.assertEqual(self.session.device.lifecycle_state, models.DeviceLifecycleState.REGISTERED)
        refusals = models.AuditEvent.objects.filter(event_type=models.AuditEventType.DEVICE_LIFECYCLE_REFUSED, metadata__action="ZTP_DISCOVERY")
        self.assertEqual(refusals.count(), 3)

    def test_unauthorized_port_is_recorded_as_unauthorized(self):
        # the relay's read-back puts the trusted giaddr on Ethernet9 (where nobody is authorized): the circuit id is the relay's own,
        # not a forged one (that case: test_relay_option82.TrustTests), and no session expects that port
        Z.record_relay_readback(port="Ethernet9")
        _summary, row = self.outcome(Z.lease(circuit="Ethernet9", mac="a2:00:00:00:00:09"))
        self.assertEqual((row.outcome, row.code, row.session), (O.UNAUTHORIZED, "UNAUTHORIZED_DEVICE", None))

    def test_address_other_than_the_reservation_is_refused(self):
        _summary, row = self.outcome(Z.lease("10.254.30.15"))
        self.assertEqual((row.outcome, row.code), (O.REFUSED, "BOOTSTRAP_NETWORK_INVALID"))

    def test_identity_conflict_on_the_authorized_port(self):
        _summary, row = self.outcome(Z.lease(vendor="Arista;cEOSLab;OTHER-SERIAL"))
        self.assertEqual(row.outcome, O.IDENTITY_MISMATCH)
        self.session.refresh_from_db()
        self.assertEqual(self.session.failure["code"], "IDENTITY_MISMATCH")
        self.assertFalse(self.session.failure["retryable"])
        self.assertNotEqual(self.session.stage, models.ZtpSessionStage.DISCOVERED)

    def test_identity_conflict_closes_the_session_and_stops_delivery(self):
        """Review regression: a non-retryable identity mismatch closes the session FAILED (the documented contract), so its
        artifact is revoked and a later lease on the same port cannot resume the onboarding."""
        self.outcome(Z.lease(vendor="Arista;cEOSLab;OTHER-SERIAL"))
        self.session.refresh_from_db()
        self.assertEqual(self.session.stage, models.ZtpSessionStage.FAILED)
        self.assertFalse(self.session.is_open)
        self.assertFalse(self.session.artifacts.filter(state=models.BootstrapArtifactState.ACTIVE).exists())
        self.assertTrue(self.session.device.lifecycle_events.filter(action="ZTP_FAILURE").exists())
        _summary, row = self.outcome(Z.lease(mac="a2:00:00:00:00:77"))
        self.assertEqual(row.outcome, O.UNAUTHORIZED)                     # no open session holds the port any more
        self.assertEqual(policy.build_policy(self.network).reservations, ())

    def test_no_api_route_accepts_posted_leases(self):
        from django.urls import get_resolver
        names = [name for name in get_resolver("core.urls").reverse_dict if isinstance(name, str) and name.startswith("ztp_")]
        self.assertTrue(names)
        self.assertFalse([n for n in names if "lease" in n or "discover" in n])
        self.assertIn("ztp_network_ingest", names)     # the one ingest action reads the provider's own lease database

    def test_lease_file_read_is_bounded_to_the_isolated_root(self):
        (self.root / "dhcp" / "dhcpd.leases").write_text(Z.lease())
        summary = discovery.ingest(self.network)
        self.assertEqual(summary["new"], 1)
        self.network.lease_file = "/etc/dhcp/dhcpd.leases"
        with self.assertRaises(Exception):
            discovery.read_lease_file(self.network)
