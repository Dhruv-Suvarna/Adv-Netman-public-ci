"""Lab 7 -- website template filters (core.templatetags.core_extras), one positive and one negative case each.

The filters only present data, but they are the last step before an operator reads a status: a known value must map to
its exact badge / label (POSITIVE), and an unknown, missing, wrong-type or hostile value must fall back to the documented
neutral / "not available" form -- never a green "success", never an exception that breaks the page (NEGATIVE).
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.templatetags import core_extras as f

TARGET = "web/core/templatetags/core_extras.py"
HOSTILE = (None, "", "<script>", 12, ["PASS"], {"PASS": 1})

# name -> ([(args, expected)] valid, [(args, expected)] invalid / unknown)
TABLE = {
    "notification_badge_display": ([((3,), "3"), (("12",), "9+")], [((0,), ""), ((-4,), ""), (("many",), ""), ((None,), ""), (([1],), "")]),
    "severity_icon": ([(("ERROR",), "✖"), (("INFO",), "ℹ")], [((v,), "•") for v in HOSTILE if not isinstance(v, (list, dict))]),
    "severity_badge_class": ([(("CRITICAL",), "critical"), (("SUCCESS",), "success")], [((v,), "neutral") for v in HOSTILE if not isinstance(v, (list, dict))]),
    "slack_status_badge_class": ([(("SENT",), "success"), (("FAILED",), "danger")], [((v,), "neutral") for v in HOSTILE if not isinstance(v, (list, dict))]),
    "get_item": ([(({"a": 1}, "a"), 1)], [(({"a": 1}, "b"), None), ((None, "a"), None), ((["a"], 0), None), (("text", "a"), None)]),
    "health_badge_class": ([(("PASS",), "success"), (("FAIL",), "danger")], [((v,), "neutral") for v in HOSTILE]),
    "metric": ([((12.6, " ms"), "13 ms"), ((3,), "3")], [((None,), "not available"), ((None, "%"), "not available")]),
    "execution_badge_class": ([(("SUCCEEDED",), "success"), (("COMPENSATED",), "success")], [((v,), "danger") for v in ("", "<script>", None, "BOGUS")]),
    "provisioning_badge_class": ([(("DONE",), "success"), (("RUNNING",), "info")], [(("",), "neutral"), (("UNKNOWN",), "neutral"), (("DRAFT",), "neutral"), (("<script>",), "info")]),
    "bundle_badge_class": ([(("GOLDEN",), "success"), (("FAILED",), "danger")], [((v,), "neutral") for v in HOSTILE]),
    "soak_duration": ([((604800,), "7d 0h 0m (168 h)"), ((90,), "1m 30s"), ((3720,), "1h 2m (1 h)")], [((None,), "—"), (("soon",), "—"), ((-50,), "0m 0s"), (([1],), "—")]),
    "support_label": ([(("PARSER_VALIDATED",), "validated"), (("FIXTURE_ONLY",), "preview only")], [(("SOME_NEW_CLASS",), "some new class"), ((None,), "none")]),
    "execution_mode_label": ([(("PARTIAL_UAT_ONLY",), "Partial (UAT) only")], [(("BOGUS",), "BOGUS"), ((None,), "None")]),
}
NEVER_GREEN = {"severity_badge_class", "slack_status_badge_class", "health_badge_class", "execution_badge_class", "provisioning_badge_class", "bundle_badge_class"}


class TemplateFilterCaseTests(SimpleTestCase):
    def _check(self, name, rows, label):
        for args, expected in rows:
            with self.subTest(case=f"{label} {args!r:.40}"):
                result = getattr(f, name)(*args)
                self.assertEqual(result, expected)
                if label == "invalid" and name in NEVER_GREEN:
                    self.assertNotEqual(result, "success")


def _add() -> None:
    for name, (valid, invalid) in TABLE.items():
        def positive(self, name=name, rows=valid):
            self._check(name, rows, "valid")

        def negative(self, name=name, rows=invalid):
            self._check(name, rows, "invalid")

        positive = case(f"FILTER_{name.upper()}_RENDERS_KNOWN_VALUES", target=f"{TARGET}::{name}", polarity=POSITIVE,
                        condition="a known status / value", expected="its exact badge class / label")(positive)
        negative = case(f"FILTER_{name.upper()}_UNKNOWN_VALUES_FALL_BACK", target=f"{TARGET}::{name}", polarity=NEGATIVE,
                        condition="an unknown, missing, wrong-type or hostile value",
                        expected="the documented neutral fallback (never success, never an exception)")(negative)
        setattr(TemplateFilterCaseTests, f"test_{name}_renders_known_values", positive)
        setattr(TemplateFilterCaseTests, f"test_{name}_unknown_values_fall_back", negative)


_add()


class FilterInventoryTests(SimpleTestCase):
    def test_every_registered_filter_has_a_table_row(self):
        self.assertEqual(sorted(TABLE), sorted(f.register.filters))
