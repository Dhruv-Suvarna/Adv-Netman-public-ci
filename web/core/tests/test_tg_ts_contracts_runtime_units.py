"""Direct tests for the Troubleshooter contract helpers (troubleshooting/contracts.py) and the runtime's admission,
budget and observation helpers (troubleshooting/runtime.py).

Secrets are redacted before anything is stored or exported; only FRESH evidence yields a verdict; a device absent from
the authoritative inventory (or an unreadable inventory) admits nobody; and an attached ACL without collected rules is an
explicit gap, never a counter.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, TestCase

from core.services.troubleshooting import contracts as c
from core.services.troubleshooting import runtime as rt
from core.tests import test_troubleshooting_runtime as RT

NOW = datetime(2026, 11, 27, 6, 0, tzinfo=timezone.utc)
SECRET_LINE = "username admin secret 0 hunter2topsecret"


class ContractHelperTests(SimpleTestCase):
    def test_schema_name_returns_the_declared_schema(self):
        self.assertEqual(c.schema_name({"schema": "ai_handoff/1"}), "ai_handoff/1")

    def test_schema_name_of_a_non_object_is_empty(self):
        self.assertEqual((c.schema_name(["schema"]), c.schema_name({})), ("", ""))

    def test_assert_valid_rejects_a_contract_violation(self):
        with self.assertRaisesRegex(ValueError, "contract violation"):
            c.assert_valid({"schema": "ai_handoff/1"}, "ai_handoff/1")

    def test_canonical_json_of_unordered_or_non_json_values_is_never_ambiguous(self):
        self.assertEqual(c.canonical_json({"b": 1, "a": [NOW]}), '{"a":["2026-11-27 06:00:00+00:00"],"b":1}')
        self.assertEqual(c.canonical_json({"é": "x"}), '{"\\u00e9":"x"}')

    def test_parse_time_returns_an_aware_datetime(self):
        self.assertEqual(c.parse_time("2026-11-27T06:00:00Z"), NOW)
        self.assertEqual(c.parse_time(datetime(2026, 11, 27, 6, 0)), NOW)

    def test_parse_time_of_malformed_or_empty_input_is_none(self):
        for value in ("", "yesterday", 1764223200, None):
            with self.subTest(f"{value!r} is not a time"):
                self.assertIsNone(c.parse_time(value))

    def test_redact_value_preserves_clean_structured_data(self):
        doc = {"device": "R1", "counters": [1, 2], "note": "interface up"}
        self.assertEqual(c.redact_value(doc), doc)
        self.assertFalse(c.contains_secret(doc))

    def test_redact_value_and_text_never_keep_secret_keys_or_inline_secrets(self):
        out = c.redact_value({"password": "x", "lines": [SECRET_LINE]})
        self.assertEqual(out["password_redacted_ref"], c.REDACTED)
        self.assertNotIn("hunter2topsecret", str(out))
        text, count = c.redact_text(SECRET_LINE)
        self.assertEqual((count, c.redact_text(text)[1]), (1, 0))      # idempotent: a redacted marker is not counted again

    def test_contains_secret_returns_true_for_secret_shaped_input(self):
        self.assertTrue(c.contains_secret({"api_token": "abc"}))
        with self.subTest("an inline secret is not missed"):
            self.assertTrue(c.contains_secret([SECRET_LINE]))

    def test_freshness_and_tri_state_never_judge_stale_future_or_missing_evidence(self):
        cases = ((NOW - timedelta(seconds=10), "GOOD", False, c.FRESH), (NOW - timedelta(hours=2), "GOOD", False, c.STALE),
                 (NOW + timedelta(hours=1), "GOOD", False, c.UNTRUSTED), (None, "GOOD", False, c.NO_DATA),
                 (NOW, "UNTRUSTED", False, c.UNTRUSTED), (NOW, "GOOD", True, c.NO_DATA))
        for observed, quality, missing, expected in cases:
            with self.subTest(expected=expected, quality=quality):
                self.assertEqual(c.freshness(observed, 300, NOW, quality=quality, is_missing=missing), expected)
        self.assertEqual([c.tri_state(c.STALE, True), c.tri_state(c.FRESH, None), c.tri_state(c.FRESH, False)], [c.UNKNOWN, c.UNKNOWN, "FAULT"])


class RuntimeHelperTests(SimpleTestCase):
    def test_collector_budget_returns_the_clamped_run_bounds(self):
        budget = rt.RuntimeBudget.clamp({"max_commands": 99, "max_seconds": 500}).collector_budget()
        self.assertEqual((budget.max_commands, budget.max_seconds), (rt.SERVER_CAPS.max_commands, 60.0))

    def test_device_admission_as_dict_returns_every_field(self):
        out = rt.DeviceAdmission("R1", "VERIFIED", platform="ceos").as_dict()
        self.assertEqual((out["device"], out["state"], out["platform"], out["reason"]), ("R1", "VERIFIED", "ceos", ""))

    def test_inventory_admission_resolve_admits_an_inventoried_device(self):
        adm = rt.InventoryAdmission(inventory=lambda: {"R1": {"platform": "ceos", "os_version": "4.36.2F"}},
                                    lifecycle=lambda name: {"maintenance": True}).resolve(["R1"])["R1"]
        self.assertEqual((adm.admitted, adm.platform, adm.maintenance, adm.source), (True, "ceos", True, "inventory+lifecycle"))

    def test_inventory_admission_resolve_refuses_unknown_withdrawn_or_unreadable(self):
        def broken():
            raise OSError("inventory unreadable")

        admission = rt.InventoryAdmission(inventory=lambda: {"R1": {"platform": "ceos"}}, lifecycle=lambda name: {"withdrawn": True})
        out = admission.resolve(["R1", "R9"])
        self.assertEqual((out["R1"].state, out["R9"].state), ("WITHDRAWN", "UNKNOWN"))
        self.assertFalse(rt.InventoryAdmission(inventory=broken).resolve(["R1"])["R1"].admitted)

    def test_wanted_cli_returns_the_platform_catalogue_keys(self):
        self.assertEqual(rt.CollectorProvider.wanted_cli("ceos", ["interface.oper_state", "routing.neighbor"]),
                         ["interfaces", "ospf_neighbors", "bgp_summary"])

    def test_wanted_cli_of_an_unknown_platform_is_empty(self):
        self.assertEqual(rt.CollectorProvider.wanted_cli("junos", ["interface"]), [])

    def test_missing_obs_returns_a_redacted_missing_record(self):
        out = rt.missing_obs("interface.oper_state@Ethernet1", "R1", f"TIMEOUT {SECRET_LINE}", "2026-11-27T06:00:00Z", "run-1", "u1")
        self.assertEqual((out["quality"], out["is_missing_data"], out["stage_decision"]), ("MISSING", True, "UNKNOWN"))
        self.assertNotIn("hunter2topsecret", out["missing_reason"])

    def test_missing_obs_without_a_timestamp_is_never_undated(self):
        self.assertTrue(c.parse_time(rt.missing_obs("k", "R1", "EMPTY", "", "run-1", "u1")["observed_at"]))

    def test_join_acl_observations_of_an_attached_acl_without_rules_is_a_gap(self):
        attachment = {"key": "acl.attachment", "observed_at": "2026-11-27T06:00:00Z", "quality": "OK",
                      "value": {"acl": "EDGE", "af": "ipv4", "interface": "Ethernet1", "direction": "in"},
                      "source": {"evidence_id": "EV-1", "source_type": "CLI", "transport": "unit"}}
        out = rt.join_acl_observations([attachment], device="R1", run_key="run-1")
        rows = out["EV-1"]
        self.assertEqual((len(rows), rows[0]["is_missing_data"], rows[0]["key"]), (1, True, "acl.counters@Ethernet1-in"))


class ReceivedKeysTests(TestCase):
    def test_received_keys_returns_each_device_with_usable_observations(self):
        case = RT.make_case(key="tg-received")
        rt.run_case(RT.ACTOR, case.case_id, RT.deps(RT.Transport(RT.OUT)), run_key="r1", now=RT.T0)
        keys = rt.received_keys(RT.ACTOR, case)
        self.assertIn("R1", keys)
        self.assertIn("interface.oper_state", keys["R1"])
        self.assertEqual(keys["R1"], sorted(keys["R1"]))

