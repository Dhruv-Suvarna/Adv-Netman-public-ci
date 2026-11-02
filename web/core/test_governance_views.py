"""Lab 7 read-only governance pages: Unit Test Matrix, artifact detail, Code Coverage matrix, capability-cell detail.

Every page reads persisted, verified evidence (core.services.test_governance.evidence); none runs a test, coverage.py,
Pylint or an AST scan.  The only POST (Refresh) fetches the Tier-3 artifact for the deployed commit from GitHub through
the read-only client; it never changes code, a device, NetBox or a Change.  Access: the ordinary NMAS boundary
(authenticated + website MFA + VIEW; Refresh needs VALIDATE) -- see services/identity/policy.py.
"""

from __future__ import annotations

from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST

from .services.test_governance import evidence, presentation


def _selected():
    return evidence.select()


@require_GET
def quality_unit_tests(request):
    context = presentation.unit_matrix(_selected(), request.GET)
    context.update(page_title="Automation · Unit Test Matrix", page_key="automation",
                   refresh_message=presentation.refresh_message(request.GET.get("refresh", "")))
    return render(request, "core/quality/unit_tests.html", context)


@require_GET
def quality_artifact(request, kind: str, path: str):
    context = presentation.artifact_detail(_selected(), f"{kind}:{path}")
    if context is None:
        raise Http404("Unknown artifact or no evidence")
    context.update(page_title=f"Automation · Unit Test Matrix · {path}", page_key="automation")
    return render(request, "core/quality/artifact.html", context)


@require_GET
def quality_coverage(request):
    context = presentation.coverage_matrix(_selected(), show_all=request.GET.get("all") == "1")
    context.update(page_title="Automation · Code Coverage", page_key="automation",
                   refresh_message=presentation.refresh_message(request.GET.get("refresh", "")))
    return render(request, "core/quality/coverage.html", context)


@require_GET
def quality_cell(request, platform: str, feature: str):
    context = presentation.cell_detail(_selected(), platform, feature)
    if context is None:
        raise Http404("Unknown capability cell or no evidence")
    context.update(page_title=f"Automation · Code Coverage · {platform} · {feature}", page_key="automation")
    return render(request, "core/quality/cell.html", context)


REFRESH_OUTCOMES = {"ACCEPTED", "TIER3_RUN_NOT_FOUND", "EVIDENCE_ARTIFACT_NOT_FOUND", "EVIDENCE_DOWNLOAD_FAILED", "EVIDENCE_RUN_MISMATCH",
                    "EVIDENCE_HASH_MISMATCH", "EVIDENCE_SCHEMA_INVALID", "EVIDENCE_SCHEMA_VERSION", "EVIDENCE_NOT_JSON", "EVIDENCE_TOO_LARGE",
                    "DEPLOYED_SHA_UNKNOWN", "GITHUB_NOT_CONFIGURED", "GITHUB_REFUSED", "GITHUB_UNREACHABLE", "GITHUB_RESPONSE_UNREADABLE"}


@require_POST
def quality_refresh(request):
    """Fetch the Tier-3 test-governance artifact for the deployed commit (read-only polling; no GitHub callback)."""
    from .services.configuration_validation.github import GitHubError
    from .services.test_governance import github_evidence

    try:
        github_evidence.refresh(evidence.deployed_state()["sha"])
        outcome = "ACCEPTED"
    except (evidence.EvidenceError, GitHubError) as exc:
        outcome = exc.code if exc.code in REFRESH_OUTCOMES else "GITHUB_RESPONSE_UNREADABLE"
    target = "core:quality_coverage" if request.POST.get("next") == "coverage" else "core:quality_unit_tests"
    return redirect(f"{reverse(target)}?refresh={outcome}")
