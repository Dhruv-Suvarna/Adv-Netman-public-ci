"""Observation authorizations: enforceable device scope, command scope, expiry, budget and separation of duties (OA01-OA16)."""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from core import models
from core.services.devices import observation_authorizations as authz, resolver
from core.tests.test_observation_collector import DOC

REAL_RESOLVE = resolver.resolve
EOS = "show version | json"
FRR = "vtysh -c 'show version'"


def account(username, *roles, active=True):
    user = get_user_model().objects.create_user(username=username, password="unused-test-password", is_active=active)
    for role in roles:
        user.groups.add(Group.objects.get(name=role))
    return user


class AuthorizationTests(TestCase):
    def setUp(self):
        account("alice", "NMAS Approver")
        account("bob", "NMAS Executor")
        account("carol", "NMAS Approver", "NMAS Executor")
        account("dave", "NMAS Operator")
        account("eve", "NMAS Approver", active=False)
        p = mock.patch.object(authz.resolver, "resolve", lambda name, **kw: REAL_RESOLVE(name, document=DOC))
        p.start()
        self.addCleanup(p.stop)

    def grant(self, **over):
        args = {"devices": ["S1", "R3"], "commands": ["nos-version"], "ttl_seconds": 3600, "approver": "alice",
                "requested_by": "bob", "ticket": "CHG-2001", "reason": "version evidence for admission"}
        args.update(over)
        return authz.grant(**args)

    # OA01
    def test_grant_records_exact_scope_digest_and_reference(self):
        res = self.grant()
        self.assertTrue(res.ok, res.codes)
        auth = res.authorization
        self.assertEqual((auth.devices, auth.commands, auth.max_observations), (["R3", "S1"], ["nos-version"], 2))
        self.assertEqual(auth.expires_at - auth.not_before, timedelta(hours=1))
        self.assertRegex(authz.reference(auth), r"^OBSAUTH-\d{6}#sha256=[0-9a-f]{64}$")
        self.assertEqual(authz.still_valid(auth), "")

    # OA02
    def test_r5_unknown_and_malformed_devices_are_refused_at_grant(self):
        self.assertIn("DEVICE_EXCLUDED", self.grant(devices=["S1", "R5"]).codes)
        self.assertIn("DEVICE_UNKNOWN", self.grant(devices=["S9"]).codes)
        self.assertIn("SCOPE_INVALID", self.grant(devices=["S1;rm"]).codes)
        self.assertIn("SCOPE_INVALID", self.grant(devices=[]).codes)
        self.assertEqual(models.ObservationAuthorization.objects.count(), 0)

    # OA03
    def test_only_the_version_command_can_be_authorized(self):
        self.assertIn("COMMAND_UNKNOWN", self.grant(commands=["show running-config"]).codes)
        self.assertIn("SCOPE_INVALID", self.grant(commands=[]).codes)

    # OA04
    def test_approver_must_hold_approve_and_be_independent_of_requester(self):
        self.assertIn("APPROVER_NOT_AUTHORIZED", self.grant(approver="dave").codes)        # operator role only
        self.assertIn("APPROVER_NOT_AUTHORIZED", self.grant(approver="eve").codes)         # inactive account
        self.assertIn("APPROVER_NOT_AUTHORIZED", self.grant(approver="mallory").codes)     # no account
        self.assertIn("APPROVER_NOT_INDEPENDENT", self.grant(requested_by="ALICE").codes)
        self.assertIn("REQUESTER_MISSING", self.grant(requested_by=" ").codes)

    # OA05
    def test_window_and_ticket_bounds(self):
        self.assertIn("WINDOW_INVALID", self.grant(ttl_seconds=authz.MAX_TTL_SECONDS + 1).codes)
        self.assertIn("WINDOW_INVALID", self.grant(ttl_seconds=30).codes)
        self.assertIn("WINDOW_INVALID", self.grant(not_before=timezone.now() - timedelta(hours=1)).codes)
        self.assertIn("TICKET_INVALID", self.grant(ticket="").codes)
        self.assertIn("TICKET_INVALID", self.grant(ticket="a b").codes)
        self.assertIn("SCOPE_INVALID", self.grant(max_observations=0).codes)
        self.assertIn("SCOPE_INVALID", self.grant(max_observations=authz.MAX_USES_PER_DEVICE * 2 + 1).codes)

    # OA06
    def test_admit_reserves_a_use_inside_scope(self):
        auth = self.grant().authorization
        res = authz.admit(authz.reference(auth), device="S1", platform="arista_ceos", command=EOS, operator="bob")
        self.assertTrue(res.ok, res.codes)
        self.assertEqual((res.use.state, res.use.device, res.use.command, res.use.operator), ("RESERVED", "S1", "nos-version", "bob"))
        self.assertEqual(authz.admit(auth.auth_id, device="R3", platform="ubuntu_frr", command=FRR, operator="bob").codes,
                         ["AUTHORIZATION_REF_MISMATCH"])
        res = authz.admit(authz.reference(auth), device="R3", platform="ubuntu_frr", command=FRR, operator="bob")
        self.assertTrue(res.ok, res.codes)

    # OA07
    def test_device_and_command_outside_scope_are_refused(self):
        auth = self.grant(devices=["S1"]).authorization
        ref = authz.reference(auth)
        self.assertEqual(authz.admit(ref, device="R3", platform="ubuntu_frr", command=FRR, operator="bob").codes, ["DEVICE_NOT_AUTHORIZED"])
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command="show running-config", operator="bob").codes,
                         ["COMMAND_NOT_AUTHORIZED"])
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command=FRR, operator="bob").codes,
                         ["COMMAND_NOT_AUTHORIZED"])
        self.assertEqual(models.ObservationAuthorizationUse.objects.count(), 0)

    # OA08
    def test_operator_must_hold_execute_and_not_be_the_approver(self):
        auth = self.grant(approver="carol", requested_by="bob").authorization
        ref = authz.reference(auth)
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="carol").codes,
                         ["OPERATOR_NOT_INDEPENDENT"])
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="dave").codes,
                         ["OPERATOR_NOT_AUTHORIZED"])
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="").codes,
                         ["OPERATOR_NOT_AUTHORIZED"])

    # OA09
    def test_expiry_and_not_yet_valid_are_enforced(self):
        auth = self.grant(ttl_seconds=600).authorization
        ref = authz.reference(auth)
        later = timezone.now() + timedelta(seconds=601)
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="bob", now=later).codes,
                         ["AUTHORIZATION_EXPIRED"])
        self.assertEqual(authz.still_valid(auth, now=later), "AUTHORIZATION_EXPIRED")
        future = self.grant(not_before=timezone.now() + timedelta(hours=2)).authorization
        self.assertEqual(authz.admit(authz.reference(future), device="S1", platform="arista_ceos", command=EOS, operator="bob").codes,
                         ["AUTHORIZATION_NOT_YET_VALID"])

    # OA10
    def test_budget_counts_every_reservation(self):
        auth = self.grant(devices=["S1"], max_observations=2).authorization
        ref = authz.reference(auth)
        first = authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="bob")
        authz.finish(first.use, ok=False, codes=["PIN_MISSING"])
        self.assertTrue(authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="bob").ok)
        self.assertEqual(authz.admit(ref, device="S1", platform="arista_ceos", command=EOS, operator="bob").codes,
                         ["AUTHORIZATION_EXHAUSTED"])

    # OA11
    def test_revocation_is_final_and_needs_approve(self):
        auth = self.grant().authorization
        self.assertEqual(authz.revoke(auth, actor="bob").codes, ["REVOKER_NOT_AUTHORIZED"])
        self.assertTrue(authz.revoke(auth, actor="alice", reason="window closed").ok)
        self.assertEqual(authz.revoke(auth, actor="alice").codes, ["ALREADY_REVOKED"])
        self.assertEqual(authz.admit(authz.reference(auth), device="S1", platform="arista_ceos", command=EOS, operator="bob").codes,
                         ["AUTHORIZATION_REVOKED"])

    # OA12
    def test_tampered_scope_and_wrong_digest_are_refused(self):
        auth = self.grant(devices=["S1"]).authorization
        ref = authz.reference(auth)
        self.assertEqual(authz.lookup(f"{auth.auth_id}#sha256={'f' * 64}").codes, ["AUTHORIZATION_REF_MISMATCH"])
        models.ObservationAuthorization.objects.filter(pk=auth.pk).update(devices=["S1", "R3"])    # out-of-band DB edit
        self.assertEqual(authz.admit(ref, device="R3", platform="ubuntu_frr", command=FRR, operator="bob").codes,
                         ["AUTHORIZATION_TAMPERED"])
        models.ObservationAuthorization.objects.filter(pk=auth.pk).update(devices=["S1"],
                                                                          expires_at=auth.expires_at + timedelta(days=30))
        self.assertEqual(authz.still_valid(auth), "AUTHORIZATION_TAMPERED")

    # OA13
    def test_unknown_and_free_form_references_are_refused(self):
        for ref in ("", "auth-1", "CHG-1|devices=S1", "OBSAUTH-999999", "OBSAUTH-1"):
            self.assertEqual(authz.lookup(ref).codes, ["AUTHORIZATION_UNKNOWN"], ref)

    # OA14
    def test_rows_are_immutable_except_one_revocation_and_one_finish(self):
        auth = self.grant().authorization
        auth.devices = ["S1", "R3", "R5"]
        with self.assertRaises(ValueError):
            auth.save()
        with self.assertRaises(ValueError):
            auth.delete()
        use = authz.admit(authz.reference(auth), device="S1", platform="arista_ceos", command=EOS, operator="bob").use
        authz.finish(use, ok=False, codes=["HOST_KEY_MISMATCH"])
        with self.assertRaises(ValueError):
            authz.finish(use, ok=True)
        with self.assertRaises(ValueError):
            use.delete()

    # OA15
    def test_scope_is_rechecked_against_the_resolver_at_use(self):
        auth = self.grant(devices=["S1"]).authorization
        excluded = {**DOC, "network_devices": {**DOC["network_devices"], "S1": {"edge": True, "monitoring": {"platform": "ceos",
                                                                                                             "address": "auto"}}}}
        with mock.patch.object(authz.resolver, "resolve", lambda name, **kw: REAL_RESOLVE(name, document=excluded)):
            self.assertEqual(authz.admit(authz.reference(auth), device="S1", platform="arista_ceos", command=EOS, operator="bob").codes,
                             ["DEVICE_EXCLUDED"])

    # OA16
    def test_management_command_grant_show_revoke(self):
        out = StringIO()
        call_command("observation_authorize", "grant", "--approver", "alice", "--requested-by", "bob", "--ticket", "CHG-3001",
                     "--devices", "S1", "--ttl-minutes", "30", stdout=out)
        self.assertIn("granted OBSAUTH-", out.getvalue())
        auth = models.ObservationAuthorization.objects.get()
        out = StringIO()
        call_command("observation_authorize", "show", auth.auth_id, "--json", stdout=out)
        self.assertIn('"status": "VALID"', out.getvalue())
        with self.assertRaises(CommandError):
            call_command("observation_authorize", "grant", "--approver", "alice", "--requested-by", "bob", "--ticket", "CHG-3002",
                         "--devices", "R5", "--ttl-minutes", "30")
        call_command("observation_authorize", "revoke", auth.auth_id, "--actor", "alice", stdout=StringIO())
        self.assertIsNotNone(models.ObservationAuthorization.objects.get().revoked_at)
