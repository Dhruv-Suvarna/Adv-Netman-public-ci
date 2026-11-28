"""Adversarial tests for the common Troubleshooter target boundary."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from core.services.troubleshooting.target_policy import (
    AuthorizationRefused, Capability, Principal, PrincipalKind, TargetPolicy,
    TargetRequest, TargetSnapshot,
)


NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


class TargetPolicyTests(SimpleTestCase):
    def setUp(self):
        self.target = TargetSnapshot(
            topology_id="nmas-lab", tenant="default", device="R6", platform="arista_ceos",
            scope="WRITABLE", identity_state="VERIFIED", lifecycle_state="IN_SERVICE",
            admission_state="ADMITTED", endpoints=frozenset({"192.168.200.6", "2001:db8:200::6"}),
            approved_path_endpoints=frozenset({"192.168.200.6", "2001:db8:200::6"}),
            identity_pin="sha256:device-pin", revision="inventory-42",
        )
        self.targets = {"R6": self.target, "R5": replace(self.target, device="R5", excluded=True)}
        self.policy = TargetPolicy(topology_id="nmas-lab", snapshot=self.targets.get,
                                   protected_addresses=("10.224.77.10", "192.168.200.100"), now=lambda: NOW,
                                   authorization_validator=lambda _request, _target, _now: True)
        self.principal = Principal("agent-1", PrincipalKind.TROUBLESHOOTER_AGENT,
                                   frozenset({Capability.READ_DIAGNOSTIC}), tenant="default")

    def request(self, **kw):
        values = dict(principal=self.principal, capability=Capability.READ_DIAGNOSTIC,
                      topology_id="nmas-lab", device="R6", endpoint="192.168.200.6", port=22,
                      transport="SSH", operation_id="cli:version", authorization_ref="authz:case-1234",
                      authorization_expires_at=NOW + timedelta(minutes=2))
        values.update(kw)
        return TargetRequest(**values)

    def refused(self, fragment, **kw):
        with self.assertRaises(AuthorizationRefused) as caught:
            self.policy.authorize(self.request(**kw))
        self.assertIn(fragment, str(caught.exception))

    def test_approved_exact_device_is_allowed_and_grant_revalidates(self):
        grant = self.policy.authorize(self.request())
        self.assertEqual(grant.endpoint, "192.168.200.6")
        self.assertEqual(self.policy.revalidate(grant), grant)

    def test_unknown_and_explicitly_excluded_r5_are_denied(self):
        self.refused("absent from authoritative inventory", device="R9")
        self.refused("excluded", device="R5", endpoint="192.168.200.5")

    def test_unverified_withdrawn_and_revoked_targets_are_denied(self):
        for update, reason in (({"identity_state": "UNVERIFIED"}, "not verified"),
                               ({"lifecycle_state": "WITHDRAWN"}, "not in service"),
                               ({"revoked": True}, "revoked")):
            self.targets["R6"] = replace(self.target, **update)
            self.refused(reason)

    def test_expired_authorization_is_denied(self):
        self.refused("expired", authorization_expires_at=NOW)

    def test_missing_or_revoked_authorization_provider_fails_closed(self):
        policy = TargetPolicy(topology_id="nmas-lab", snapshot=self.targets.get, now=lambda: NOW)
        with self.assertRaises(AuthorizationRefused) as caught:
            policy.authorize(self.request())
        self.assertIn("validator is unavailable", str(caught.exception))
        denied = TargetPolicy(topology_id="nmas-lab", snapshot=self.targets.get, now=lambda: NOW,
                              authorization_validator=lambda _request, _target, _now: False)
        with self.assertRaises(AuthorizationRefused) as caught:
            denied.authorize(self.request())
        self.assertIn("not active", str(caught.exception))

    def test_cross_topology_and_cross_tenant_are_denied(self):
        self.refused("cross-topology", topology_id="another-lab")
        self.targets["R6"] = replace(self.target, tenant="another-student")
        self.refused("cross-tenant")

    def test_management_path_and_address_substitution_are_denied(self):
        self.targets["R6"] = replace(self.target, approved_path_endpoints=frozenset({"2001:db8:200::6"}))
        self.refused("no current approved management path")
        self.targets["R6"] = self.target
        self.refused("address substitution", endpoint="10.224.78.55")

    def test_vm1_management_addresses_are_never_device_targets(self):
        self.targets["R6"] = replace(self.target, endpoints=frozenset({"10.224.77.10"}),
                                     approved_path_endpoints=frozenset({"10.224.77.10"}))
        self.refused("protected", endpoint="10.224.77.10")

    def test_ipv4_mapped_ipv6_cannot_bypass_exact_or_protected_address(self):
        self.targets["R6"] = replace(self.target, endpoints=frozenset({"192.168.200.100"}),
                                     approved_path_endpoints=frozenset({"192.168.200.100"}))
        self.refused("protected", endpoint="::ffff:192.168.200.100")

    def test_unknown_operation_and_raw_command_are_denied(self):
        self.refused("fixed diagnostic registry", operation_id="cli:configure")
        self.refused("fixed diagnostic registry", operation_id="show version; docker ps")

    def test_agent_cannot_apply_change_and_proposal_opens_no_connection(self):
        changer = replace(self.principal, permissions=frozenset({Capability.APPLY_CHANGE}))
        self.refused("only the governed Change Engine", principal=changer, capability=Capability.APPLY_CHANGE)
        proposer = replace(self.principal, permissions=frozenset({Capability.PROPOSE_CHANGE}))
        decision, target = self.policy.decide(self.request(principal=proposer, capability=Capability.PROPOSE_CHANGE,
                                                           endpoint="", port=0, transport="", operation_id=""))
        self.assertTrue(decision.allowed)
        self.assertIsNone(target)

    def test_grant_is_short_lived_tamper_evident_and_bound_to_revision(self):
        grant = self.policy.authorize(self.request())
        with self.assertRaises(AuthorizationRefused):
            self.policy.revalidate(replace(grant, endpoint="192.168.200.7"))
        with self.assertRaises(AuthorizationRefused):
            self.policy.revalidate(grant, at=NOW + timedelta(seconds=61))
        self.targets["R6"] = replace(self.target, revision="inventory-43")
        with self.assertRaises(AuthorizationRefused):
            self.policy.revalidate(grant)

    def test_live_authorization_is_rechecked_immediately_before_use(self):
        active = {"value": True}
        policy = TargetPolicy(topology_id="nmas-lab", snapshot=self.targets.get, now=lambda: NOW,
                              authorization_validator=lambda _request, _target, _now: active["value"])
        grant = policy.authorize(self.request())
        active["value"] = False
        with self.assertRaises(AuthorizationRefused) as caught:
            policy.revalidate(grant)
        self.assertEqual(caught.exception.code, "AUTHORIZATION_REVOKED")

    def test_discovery_does_not_expand_scope(self):
        # A discovered/routable address absent from the authoritative snapshot is still refused.
        self.refused("address substitution", endpoint="192.168.200.250")
