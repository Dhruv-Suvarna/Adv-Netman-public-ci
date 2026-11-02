"""Lab 7 governance pages: rendering, filters, expansion, drill-down, CURRENT / STALE, and the read-only access boundary."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import Group
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from core.services.test_governance import evidence as evidence_module
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.tests.runner import make_test_operator, sign_in
from core.tests.test_test_governance import SERVICE, SOURCE, SYM, _report, ledger, trace

VIEWS = "web/core/test_governance_views.py"


def _evidence():
    rows = ledger(("arista_ceos", "routing.OSPFV2", "SUPPORTED"), ("sonic", "routing.OSPFV2", "UNSUPPORTED"))
    return _report({SERVICE: SOURCE, "web/core/services/health/live.py": "def norm_ip(text):\n    return text\n"},
                   trace(**{"django:core.tests.t.T.test_accepts_valid_port": ("PASS", {SYM: [1, 0, 0, 0]}, ()),
                            "django:core.tests.t.T.test_rejects_port_zero": ("PASS", {SYM: [0, 0, 1, 1]}, ())}), cell_rows=rows)


class GovernancePageTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.data = _evidence()
        evidence_module.accept(json.dumps(self.data).encode(), source="unit test", directory=Path(self.tmp.name))
        self.settings_override = override_settings(NMAS_TEST_GOVERNANCE_DIR=self.tmp.name)
        self.settings_override.enable()
        self.deployed = mock.patch.object(evidence_module, "deployed_state", return_value={"sha": "a" * 40, "fingerprint": "f" * 64})
        self.deployed.start()
        self.bundled = mock.patch.object(evidence_module, "BUNDLED_EVIDENCE", Path(self.tmp.name) / "none.json")
        self.bundled.start()

    def tearDown(self):
        self.bundled.stop()
        self.deployed.stop()
        self.settings_override.disable()
        self.tmp.cleanup()

    @case("QUALITY_UNIT_MATRIX_RENDERS", target=VIEWS + "::quality_unit_tests", polarity=POSITIVE,
          condition="accepted evidence for the deployed commit", expected="summary cards, artifact rows with Negative | Positive columns, CURRENT")
    def test_unit_matrix_shows_cards_rows_and_expandable_cases(self):
        response = self.client.get(reverse("core:quality_unit_tests"))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn('data-testid="freshness">CURRENT', html)
        self.assertIn(f'data-artifact="PY:{SERVICE}"', html)
        self.assertIn("Deployed file / artifact", html)
        self.assertIn("validate_port() refuses invalid, boundary or unexpected input", html)    # expansion lists each case
        self.assertIn("django:core.tests.t.T.test_rejects_port_zero", html)                     # with its exact test id
        self.assertIn("MISSING", html)                                                          # missing cases are shown
        self.assertIn("Lab 7 assignment examples", html)
        row = next(r for r in response.context["rows"] if r["artifact"]["path"] == SERVICE)
        self.assertEqual((row["neg"]["pass"], row["neg"]["required"], row["pos"]["pass"], row["pos"]["required"]), (1, 2, 1, 3))

    def test_filters_narrow_the_rows(self):
        for query, expected in ((f"?q=health", {"web/core/services/health/live.py"}), ("?group=configuration", {SERVICE}),
                                ("?polarity_missing=negative", {SERVICE, "web/core/services/health/live.py"}), ("?type=JINJA", set()),
                                ("?status=CLOSED_CURRENT_SCOPE", set()), ("?scope=nonsense&q=field", {SERVICE})):
            with self.subTest(case=query):
                response = self.client.get(reverse("core:quality_unit_tests") + query)
                self.assertEqual({r["artifact"]["path"] for r in response.context["rows"]}, expected)

    def test_artifact_detail_lists_symbols_cases_coverage_and_pylint(self):
        response = self.client.get(reverse("core:quality_artifact", args=["PY", SERVICE]))
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        for expected in ("PY:" + SERVICE, "validate_port", "Thing.__str__", "presentation / protocol dunder", "Negative cases", "Positive cases",
                         "Functions / methods", "Pylint", "Runtime coverage"):
            with self.subTest(expected=expected):
                self.assertIn(expected, html)
        self.assertEqual(self.client.get(reverse("core:quality_artifact", args=["PY", "nope.py"])).status_code, 404)

    @case("QUALITY_COVERAGE_MATRIX_RENDERS", target=VIEWS + "::quality_coverage", polarity=POSITIVE,
          condition="accepted evidence with one SUPPORTED and one UNSUPPORTED cell",
          expected="the supported cell shows its lifecycle closure POS / NEG; the unsupported one shows NOT_IMPLEMENTED; generic groups listed")
    def test_coverage_matrix_and_cell_detail(self):
        response = self.client.get(reverse("core:quality_coverage"))
        html = response.content.decode()
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-cell="arista_ceos|routing.OSPFV2" data-status="MISSING"', html)
        self.assertIn("POS 0/6", html)
        self.assertIn('data-status="NOT_IMPLEMENTED"', html)
        self.assertIn("Generic / control-plane coverage", html)
        detail = self.client.get(reverse("core:quality_cell", args=["arista_ceos", "routing.OSPFV2"]))
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Executor preflight", detail.content.decode())
        self.assertEqual(self.client.get(reverse("core:quality_cell", args=["arista_ceos", "routing.NOPE"])).status_code, 404)

    def test_feature_cells_show_lifecycle_closure_and_platform_headers_show_aggregate_coverage(self):
        from core.services.test_governance import presentation

        aggregate = {"arista_ceos": {"artifacts": 3, "functions": {"tested": 63, "required": 63}, "line_pct": 94.26, "branch_pct": 88.9}}
        with mock.patch.object(presentation, "platform_coverage", return_value=aggregate):
            response = self.client.get(reverse("core:quality_coverage"))
        html = response.content.decode()
        self.assertIn('data-testid="freshness">CURRENT', html)                              # evidence banner unchanged
        matrix = html[html.index('id="coverage-matrix"'):html.index('id="platform-scope-note"')]
        body = matrix[matrix.index("<tbody>"):]
        cell = body[body.index('data-cell="arista_ceos|routing.OSPFV2"'):body.index("</td>")]
        self.assertIn("LIFECYCLE CLOSURE", cell)
        self.assertIn("POS 0/6", cell)
        self.assertIn("NEG 0/6", cell)
        for platform_figure in ("FUNC", "LINES", "Functions", "Statements", "Branches"):  # never inside a feature cell
            self.assertNotIn(platform_figure, body)
        header = matrix[matrix.index('data-platform="arista_ceos"'):matrix.index("</th>", matrix.index('data-platform="arista_ceos"'))]
        for expected in ("Platform code coverage", "Functions 63 / 63", "Statements 94.26%", "Branches 88.9%"):
            self.assertIn(expected, header)
        sonic = matrix[matrix.index('data-platform="sonic"'):matrix.index("</th>", matrix.index('data-platform="sonic"'))]
        self.assertNotIn("Platform code coverage", sonic)                                # no supported cell, no figures
        self.assertIn('data-status="NOT_IMPLEMENTED"', html)                               # unsupported cell unchanged
        self.assertIn("Lifecycle closure", html)
        self.assertIn("Platform runtime coverage", html)
        self.assertIn("They are not isolated coverage for any individual feature.", html)

    def test_cell_detail_separates_feature_closure_from_platform_aggregate(self):
        from core.services.test_governance import presentation

        aggregate = {"arista_ceos": {"artifacts": 3, "functions": {"tested": 63, "required": 63}, "line_pct": 94.26, "branch_pct": 88.9}}
        with mock.patch.object(presentation, "platform_coverage", return_value=aggregate):
            html = self.client.get(reverse("core:quality_cell", args=["arista_ceos", "routing.OSPFV2"])).content.decode()
        lifecycle = html[html.index('id="feature-lifecycle"'):html.index('id="platform-runtime-coverage"')]
        platform = html[html.index('id="platform-runtime-coverage"'):]
        self.assertIn("Feature lifecycle test closure", lifecycle)
        self.assertIn("Lifecycle closure <strong>0%</strong>", lifecycle)
        for stage in ("Executor preflight", "POS <strong>0 / 6</strong>", "NEG <strong>0 / 6</strong>"):
            self.assertIn(stage, lifecycle)
        self.assertNotIn("functions", lifecycle.lower().replace("functions / methods", ""))
        self.assertIn("Platform aggregate runtime coverage", platform)
        self.assertIn("Python production artifacts recorded for its supported cells", platform)
        self.assertIn("They are not isolated coverage for any individual feature.", platform)
        self.assertIn("functions <strong>63 / 63</strong> · statements <strong>94.26%</strong> · branches <strong>88.9%</strong>", platform)

    def test_platform_coverage_is_computed_from_report_artifacts(self):
        from core.services.test_governance import presentation
        from core.services.test_governance.constants import ArtifactType

        def art(path, tested, required, statements, covered, branches, covered_b):
            return {"id": f"PY:{path}", "path": path, "type": ArtifactType.PYTHON, "functions": {"tested": tested, "required": required},
                    "coverage": {"statements": statements, "covered": covered, "branches": branches, "covered_branches": covered_b}}
        report = {
            "artifacts": [art("ceos.py", 10, 10, 100, 90, 20, 18), art("driver.py", 5, 6, 50, 50, 10, 5), art("srl.py", 3, 4, 40, 10, 8, 2),
                          art("unused.py", 1, 9, 9, 0, 9, 0), {**art("tmpl.j2", 0, 0, 1, 1, 1, 1), "type": ArtifactType.JINJA}],
            "cells": [
                {"platform": "arista_ceos", "feature": "a", "final_status": "SUPPORTED", "artifacts": ["PY:ceos.py", "PY:driver.py", "PY:tmpl.j2"]},
                {"platform": "arista_ceos", "feature": "b", "final_status": "SUPPORTED", "artifacts": ["PY:ceos.py", "PY:driver.py"]},
                {"platform": "arista_ceos", "feature": "c", "final_status": "NOT_IMPLEMENTED", "artifacts": ["PY:unused.py"]},
                {"platform": "nokia_srlinux", "feature": "a", "final_status": "SUPPORTED", "artifacts": ["PY:srl.py", "PY:driver.py"]},
            ]}
        totals = presentation.platform_coverage(report)
        self.assertEqual(totals["arista_ceos"], {"artifacts": 2, "functions": {"tested": 15, "required": 16}, "line_pct": 93.33, "branch_pct": 76.67})
        self.assertEqual(totals["nokia_srlinux"], {"artifacts": 2, "functions": {"tested": 8, "required": 10}, "line_pct": 66.67, "branch_pct": 38.89})
        self.assertEqual(presentation.platform_coverage({}), {})

    @case("QUALITY_PLATFORM_COVERAGE_NEVER_INVENTS_FIGURES", target="web/core/services/test_governance/presentation.py::platform_coverage",
          polarity=NEGATIVE, condition="only unsupported cells, unmeasured / non-Python / unknown artifacts, or no report data",
          expected="no platform aggregate (or empty figures) is produced; nothing is borrowed from another platform or cell")
    def test_platform_coverage_refuses_unsupported_and_unmeasured_inputs(self):
        from core.services.test_governance import presentation
        from core.services.test_governance.constants import ArtifactType

        report = {
            "artifacts": [{"id": "PY:a.py", "path": "a.py", "type": ArtifactType.PYTHON, "functions": {"tested": 9, "required": 9},
                           "coverage": {"statements": 10, "covered": 10, "branches": 2, "covered_branches": 2}},
                          {"id": "PY:b.py", "path": "b.py", "type": ArtifactType.PYTHON, "functions": {"tested": 1, "required": 1}, "coverage": None},
                          {"id": "JINJA:t.j2", "path": "t.j2", "type": ArtifactType.JINJA, "functions": {"tested": 0, "required": 0},
                           "coverage": {"statements": 1, "covered": 1, "branches": 0, "covered_branches": 0}}],
            "cells": [{"platform": "sonic", "feature": "x", "final_status": "UNSUPPORTED", "artifacts": ["PY:a.py"]},
                      {"platform": "junos", "feature": "x", "final_status": "NOT_IMPLEMENTED", "artifacts": ["PY:a.py"]},
                      {"platform": "nokia_srlinux", "feature": "x", "final_status": "SUPPORTED", "artifacts": ["PY:b.py", "JINJA:t.j2", "PY:gone.py"]}]}
        totals = presentation.platform_coverage(report)
        self.assertEqual(set(totals), {"nokia_srlinux"})                                    # unsupported platforms get nothing
        self.assertEqual(totals["nokia_srlinux"], {"artifacts": 0, "functions": {"tested": 0, "required": 0},
                                                    "line_pct": None, "branch_pct": None})   # unmeasured: no figure invented
        self.assertEqual(presentation.platform_coverage({"cells": None, "artifacts": None}), {})

    @case("QUALITY_STALE_EVIDENCE_SHOWN_STALE", target=VIEWS + "::quality_unit_tests", polarity=NEGATIVE,
          condition="the deployed checkout differs from the tested source", expected="the page says STALE (never presents old coverage as current)")
    def test_stale_evidence_is_marked_stale(self):
        with mock.patch.object(evidence_module, "deployed_state", return_value={"sha": "c" * 40, "fingerprint": "d" * 64}):
            html = self.client.get(reverse("core:quality_unit_tests")).content.decode()
        self.assertIn('data-testid="freshness">STALE', html)
        self.assertIn("re-run Tier-3", html)

    def test_no_evidence_is_explained(self):
        with override_settings(NMAS_TEST_GOVERNANCE_DIR=tempfile.mkdtemp()):
            html = self.client.get(reverse("core:quality_unit_tests")).content.decode()
        self.assertIn("No accepted evidence is available yet", html)
        self.assertIn("NO_EVIDENCE", html)

    def test_refresh_outcomes_are_reported_without_secrets(self):
        from core.services.test_governance import github_evidence

        with mock.patch.object(github_evidence, "refresh", side_effect=evidence_module.EvidenceError("TIER3_RUN_NOT_FOUND")):
            response = self.client.post(reverse("core:quality_refresh"), {"next": "coverage"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("core:quality_coverage") + "?refresh=TIER3_RUN_NOT_FOUND")
        html = self.client.get(response["Location"]).content.decode()
        self.assertIn("no completed Tier-3 run for the deployed commit", html)
        with mock.patch.object(github_evidence, "refresh", return_value={"run_id": 1, "payload_sha256": "x"}):
            response = self.client.post(reverse("core:quality_refresh"))
        self.assertTrue(response["Location"].endswith("?refresh=ACCEPTED"))
        html = self.client.get(reverse("core:quality_unit_tests") + "?refresh=<script>").content.decode()
        self.assertNotIn("<script>", html)

    def test_refresh_accepts_verified_tier3_evidence_and_returns_to_the_matrix(self):
        from core.services.test_governance import github_evidence

        with mock.patch.object(github_evidence, "refresh", return_value={"run_id": 1, "payload_sha256": "x"}) as refreshed, \
             mock.patch.object(evidence_module, "deployed_state", return_value={"sha": "a" * 40, "fingerprint": ""}):
            response = self.client.post(reverse("core:quality_refresh"))
        refreshed.assert_called_once_with("a" * 40)
        self.assertEqual(response["Location"], reverse("core:quality_unit_tests") + "?refresh=ACCEPTED")

    def test_the_automation_landing_links_both_read_only_pages(self):
        html = self.client.get(reverse("core:automation_landing")).content.decode()
        self.assertIn(reverse("core:quality_unit_tests"), html)
        self.assertIn(reverse("core:quality_coverage"), html)


class GovernanceAccessTests(TestCase):
    @case("QUALITY_PAGES_READ_ONLY_BOUNDARY", target=VIEWS + "::quality_refresh", polarity=NEGATIVE,
          condition="anonymous / MFA-pending / viewer requests and unsafe methods on the read routes",
          expected="anonymous redirected to login; MFA-pending refused; a viewer may read but not Refresh; POST on a read route is refused")
    def test_access_boundary(self):
        anonymous = Client()
        anonymous.nmas_auto_login = False
        response = anonymous.get(reverse("core:quality_unit_tests"))
        self.assertIn(response.status_code, (302, 403))
        from django.contrib.auth import get_user_model

        viewer_user = get_user_model().objects.create_user(username="tg-viewer")
        viewer_user.groups.add(Group.objects.get(name="NMAS Viewer"))     # VIEW only
        viewer = Client()
        sign_in(viewer, viewer_user)
        with mock.patch.object(evidence_module, "select", return_value={"report": None, "freshness": "NO_EVIDENCE", "reason": "", "deployed": {}}):
            self.assertEqual(viewer.get(reverse("core:quality_unit_tests")).status_code, 200)
            self.assertEqual(viewer.get(reverse("core:quality_coverage")).status_code, 200)
            self.assertEqual(viewer.post(reverse("core:quality_unit_tests")).status_code, 405)   # unsafe method: refused by the middleware
            self.assertEqual(viewer.post(reverse("core:quality_refresh")).status_code, 403)      # Refresh needs VALIDATE
        pending = Client()
        sign_in(pending, make_test_operator("tg-pending"), mfa_verified=False)
        self.assertNotEqual(pending.get(reverse("core:quality_unit_tests")).status_code, 200)
