"""Lab 7 closure -- the pure Health primitives: check results, bounded serialization, fact-group evidence and
precedence, the code catalogue, requirement descriptors and the plan-derived affected scope.

No I/O beyond the test database (the scope reads a validated, planned Change built by ``helpers.execution``).
POSITIVE: exact category / remediation, deterministic ordering and counts, freshness classes, live-over-telemetry
precedence, descriptor expansion and TARGET / PEER roles.  NEGATIVE: secret-shaped keys are dropped, oversized values
and result lists are truncated with the worst first, unknown codes and statuses are refused, unavailable groups yield
no facts and UNKNOWN freshness, and a descriptor without facts never claims a check.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core.services.health import codes, evidence, requirements, results, scope
from core.services.health.codes import CheckStatus, Freshness, Role
from core.tests.helpers import execution as x

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
THRESHOLDS = {"freshness": {"healthy": 60.0, "stale": 120.0}}


def result(code="DEVICE_REACHABLE", status=CheckStatus.PASS, device="R1", **kw):
    return results.CheckResult(check_code=code, status=status, device=device, message="m", source="LIVE", **kw)


class CheckResultTests(SimpleTestCase):
    def test_check_result_category_and_remediation_come_from_the_catalogue(self):
        found = result("DEVICE_UNREACHABLE", CheckStatus.FAIL, role=Role.TARGET)
        self.assertEqual((found.category, found.remediation, found.blocking),
                         ("REACHABILITY", "Verify the management path, credentials and that the device is running.", True))
        self.assertEqual(codes.spec("DEVICE_REACHABLE").core, True)

    def test_unknown_codes_and_statuses_are_refused(self):
        with self.assertRaisesRegex(ValueError, "Unknown health check code 'NOPE'"):
            result("NOPE")
        with self.assertRaisesRegex(ValueError, "Unknown check status 'MAYBE'"):
            result(status="MAYBE")
        with self.assertRaises(KeyError):
            codes.spec("NOPE")

    def test_bound_preserves_scalars_and_sorts_sets(self):
        self.assertEqual(results.bound({"b": 1.23456, "a": {"x", "y"}, "n": None, "t": True}), {"a": ["x", "y"], "b": 1.2346, "n": None, "t": True})
        self.assertEqual(results.bound({"credential_ref": "runtime://x"}), {"credential_ref": "runtime://x"})

    def test_bound_never_keeps_secret_keys_or_oversized_values(self):
        found = results.bound({"password": "fake-Secret-1", "x" * 300: "y" * 300, "deep": [[[[["z"]]]]], "list": list(range(40))})
        self.assertNotIn("password", str(found))
        self.assertNotIn("fake-Secret-1", str(found))
        self.assertEqual(found["redacted_field_1"], "[REDACTED]")
        self.assertEqual(len(found["x" * 240]), 240)
        self.assertTrue(found["x" * 240].endswith("..."))
        self.assertEqual(found["deep"], [[[["[TRUNCATED]"]]]])
        self.assertEqual(len(found["list"]), results.MAX_LIST)

    def test_ordered_and_count_by_status_return_deterministic_rows(self):
        rows = [result(device="S1"), result("DEVICE_UNREACHABLE", CheckStatus.FAIL, device="R1"), result(device="R1")]
        self.assertEqual([(r.device, r.check_code) for r in results.ordered(rows)],
                         [("R1", "DEVICE_REACHABLE"), ("R1", "DEVICE_UNREACHABLE"), ("S1", "DEVICE_REACHABLE")])
        self.assertEqual(results.count_by_status(rows), {**{s: 0 for s in CheckStatus.ALL}, "PASS": 2, "FAIL": 1})

    def test_ordered_and_count_of_no_results_are_empty_zero(self):
        self.assertEqual((results.ordered([]), set(results.count_by_status([]).values())), ([], {0}))

    def test_bounded_results_returns_every_row_when_under_the_cap(self):
        rows, truncated = results.bounded_results([result(), result("DEVICE_UNREACHABLE", CheckStatus.FAIL)])
        self.assertEqual(([r["status"] for r in rows], truncated), (["FAIL", "PASS"], False))

    def test_bounded_results_never_exceed_the_cap_and_keep_the_worst(self):
        many = [result(device=f"D{i:03}") for i in range(results.MAX_RESULTS)] + [result("DEVICE_UNREACHABLE", CheckStatus.FAIL, device="Z")]
        rows, truncated = results.bounded_results(many)
        self.assertEqual((len(rows), truncated, rows[0]["device"], rows[0]["status"]), (results.MAX_RESULTS, True, "Z", "FAIL"))


class EvidenceTests(SimpleTestCase):
    def group(self, age=30, data=None, source="LIVE"):
        return evidence.FactGroup(data=data if data is not None else {}, source=source, observed_at=NOW - timedelta(seconds=age))

    def test_fact_group_age_and_freshness_classes(self):
        self.assertEqual([self.group(age).freshness(NOW, THRESHOLDS) for age in (0, 60, 61, 120, 121)],
                         [Freshness.FRESH, Freshness.FRESH, Freshness.STALE, Freshness.STALE, Freshness.EXPIRED])
        self.assertEqual((self.group(30).age_seconds(NOW), self.group(-5).age_seconds(NOW), self.group().available), (30.0, 0.0, True))

    def test_unavailable_group_has_no_age_facts_or_freshness(self):
        missing = evidence.unavailable("LIVE", error="TIMEOUT")
        device = evidence.DeviceEvidence("R1", groups={"interfaces": missing})
        evset = evidence.EvidenceSet(devices={"R1": device}, now=NOW, thresholds=THRESHOLDS)
        self.assertEqual((missing.available, missing.age_seconds(NOW), missing.freshness(NOW, THRESHOLDS), missing.complete),
                         (False, None, Freshness.UNKNOWN, False))
        self.assertEqual((device.facts("interfaces"), device.facts("routes"), device.group("routes"), evset.device("R9")), (None, None, None, None))
        self.assertEqual((evidence.group_freshness(None, evset), evidence.group_freshness(missing, evset)), (Freshness.UNKNOWN, Freshness.UNKNOWN))

    def test_group_freshness_and_device_lookup_return_the_group_state(self):
        device = evidence.DeviceEvidence("R1", groups={"routes": self.group(90, {"r": 1})})
        evset = evidence.EvidenceSet(devices={"R1": device}, now=NOW, thresholds=THRESHOLDS)
        self.assertEqual((evset.device("R1").facts("routes"), evidence.group_freshness(device.group("routes"), evset)), ({"r": 1}, Freshness.STALE))

    def test_merge_precedence_uses_live_and_records_interface_conflicts(self):
        live = evidence.DeviceEvidence("R1", platform="ceos", live_attempted=True,
                                       groups={"interfaces": self.group(data={"Ethernet1": {"oper": "down"}}), "routes": evidence.unavailable("LIVE")})
        tele = evidence.DeviceEvidence("R1", groups={"interfaces": self.group(data={"Ethernet1": {"oper": "up"}}, source="TELEMETRY"),
                                                     "routes": self.group(data={"x": 1}, source="TELEMETRY")})
        merged = evidence.merge_precedence(live, tele)
        self.assertEqual((merged.platform, merged.live_reachable, merged.group("interfaces").source, merged.group("routes").source),
                         ("ceos", True, "LIVE", "TELEMETRY"))
        self.assertEqual(merged.conflicts, [{"group": "interfaces", "key": "Ethernet1", "live": "down", "telemetry": "up", "used": "LIVE"}])

    def test_merge_precedence_without_any_available_group_keeps_it_unavailable(self):
        merged = evidence.merge_precedence(None, evidence.DeviceEvidence("R1", groups={"bgp": evidence.unavailable("TELEMETRY")}))
        self.assertEqual((merged.device, merged.live_reachable, merged.group("bgp").available, merged.conflicts), ("R1", False, False, []))
        self.assertEqual(evidence.merge_precedence(None, None).device, "")


class RequirementTests(SimpleTestCase):
    def test_from_descriptor_expands_the_executable_checks(self):
        req = requirements.from_descriptor("CFG-1", {"requirement": "INTERFACE_PRESENT", "expected": {"interface": "Loopback9"},
                                                      "subject": {"label": "R1 Loopback9", "object_type": "interface", "object_id": "Loopback9"}}, device="R1")
        self.assertEqual((req.device, req.subject, req.check_types), ("R1", "R1 Loopback9", ("INTERFACE_PRESENT", "INTERFACE_ADMIN_STATE", "INTERFACE_OPER_STATE")))
        self.assertEqual(requirements.plan_interfaces([req]), {"R1": {"Loopback9"}})
        unlabeled = requirements.from_descriptor("CFG-2", {"requirement": "ADDRESS_PRESENT", "device": "R2", "subject": {"object_type": "address", "object_id": "a1"}})
        self.assertEqual(unlabeled.subject, "R2/address/a1")

    def test_from_descriptor_of_unknown_or_factless_requirements_is_not_executable(self):
        unknown = requirements.from_descriptor("CFG-3", {"requirement": "TELEPORT"})
        raw = requirements.from_descriptor("CFG-4", {"requirement": "RAW_CONFIG_APPLIED", "expected": "not-a-dict"})
        self.assertEqual((unknown.check_types, unknown.expected), ((requirements.UNKNOWN_TYPE,), None))
        self.assertEqual((raw.check_types, raw.expected), ((requirements.NOT_IMPLEMENTED,), None))
        self.assertEqual(requirements.plan_interfaces([unknown, raw, requirements.from_descriptor("C", {"requirement": "INTERFACE_PRESENT"})]), {})


class AffectedScopeTests(TestCase):
    def test_build_affected_scope_returns_targets_with_roles_and_reasons(self):
        plan = x.prepared().plan
        found = scope.build_affected_scope(plan)
        targets = sorted({c.target_device for c in plan.configlets.all()})
        self.assertEqual(found.names(Role.TARGET), targets)
        self.assertEqual({found.roles[name] for name in targets}, {Role.TARGET})
        self.assertEqual(found.names(), sorted(found.devices))
        self.assertIn("DEPLOY_TARGET", found.to_dict()["devices"][0]["reasons"])

    def test_scope_names_of_an_absent_role_are_empty(self):
        empty = scope.AffectedScope()
        self.assertEqual((empty.names(), empty.names(Role.PEER), empty.roles, empty.to_dict()), ([], [], {}, {"devices": []}))
