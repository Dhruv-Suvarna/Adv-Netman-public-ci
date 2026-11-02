"""Refresh: fetch the Tier-3 ``test-governance`` artifact for the DEPLOYED commit from GitHub Actions (read-only).

Polling, never a callback (the same approach as Configuration Validation).  The token is the protected runtime one
(``settings.NMAS_GITHUB_TOKEN_ENV``, Actions read); it is never logged, stored or shown.  The downloaded report is
accepted only if it verifies (schema + canonical hash) AND names the run's own head commit and run id -- an artifact
from another commit or a hand-edited file is refused.  Basic viewing never depends on GitHub being reachable.
"""

from __future__ import annotations

import io
import os
import zipfile
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from ..configuration_validation import github
from . import evidence

WORKFLOW_FILE = "tier3-validation.yml"
ARTIFACT_NAME = "test-governance"
REPORT_NAME = "test-governance-report.json"
MAX_ZIP_BYTES = 60 * 1024 * 1024
TIMEOUT_SECONDS = 20
NO_RUN, NO_ARTIFACT, DOWNLOAD_FAILED, MISMATCH = "TIER3_RUN_NOT_FOUND", "EVIDENCE_ARTIFACT_NOT_FOUND", "EVIDENCE_DOWNLOAD_FAILED", "EVIDENCE_RUN_MISMATCH"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib API
        return None


def _token() -> str:
    from django.conf import settings

    return os.environ.get(settings.NMAS_GITHUB_TOKEN_ENV, "").strip()


def runs_for(sha: str) -> list[dict]:
    data = github._call("GET", f"/actions/workflows/{WORKFLOW_FILE}/runs?head_sha={sha}&status=completed&per_page=10")  # pylint: disable=protected-access  # the one GitHub client
    return [r for r in data.get("workflow_runs") or [] if isinstance(r, dict) and r.get("head_sha") == sha]


def _download(url: str) -> bytes:
    """Artifact archives answer with a redirect to signed storage: follow it WITHOUT forwarding the token."""
    request = Request(url, headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {_token()}",
                                    "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "nmas-test-governance"})
    location = None
    try:
        with build_opener(_NoRedirect).open(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https API origin
            return response.read(MAX_ZIP_BYTES + 1)
    except HTTPError as exc:
        if exc.code in (301, 302, 303, 307, 308):
            location = exc.headers.get("Location")
        else:
            raise evidence.EvidenceError(DOWNLOAD_FAILED, f"HTTP {exc.code}") from None
    except (URLError, TimeoutError, OSError):
        raise evidence.EvidenceError(DOWNLOAD_FAILED, "unreachable") from None
    if not location or not location.startswith("https://"):
        raise evidence.EvidenceError(DOWNLOAD_FAILED, "no signed download location")
    try:
        with urlopen(Request(location, headers={"User-Agent": "nmas-test-governance"}), timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return response.read(MAX_ZIP_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError):
        raise evidence.EvidenceError(DOWNLOAD_FAILED, "signed download failed") from None


def extract_report(archive: bytes) -> bytes:
    if len(archive) > MAX_ZIP_BYTES:
        raise evidence.EvidenceError("EVIDENCE_TOO_LARGE")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            info = zf.getinfo(REPORT_NAME)
            if info.file_size > evidence.MAX_REPORT_BYTES:
                raise evidence.EvidenceError("EVIDENCE_TOO_LARGE")
            return zf.read(info)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise evidence.EvidenceError(NO_ARTIFACT, "the archive has no test-governance-report.json") from exc


def refresh(deployed_sha: str, *, directory=None, fetch=None) -> dict:
    """Find the newest completed Tier-3 run for ``deployed_sha`` with a governance artifact and accept its report."""
    if not deployed_sha or len(deployed_sha) != 40:
        raise evidence.EvidenceError("DEPLOYED_SHA_UNKNOWN")
    fetch = fetch or _download
    runs = runs_for(deployed_sha)
    if not runs:
        raise evidence.EvidenceError(NO_RUN, "no completed Tier-3 run for the deployed commit")
    for run in sorted(runs, key=lambda r: str(r.get("created_at") or ""), reverse=True):
        artifacts = github._call("GET", f"/actions/runs/{int(run['id'])}/artifacts?per_page=50")  # pylint: disable=protected-access
        wanted = next((a for a in artifacts.get("artifacts") or [] if a.get("name") == ARTIFACT_NAME and not a.get("expired")), None)
        if wanted is None:
            continue
        raw = extract_report(fetch(str(wanted["archive_download_url"])))
        data = evidence.verify_report(raw)
        provenance = data.get("provenance") or {}
        if data.get("repository_sha") != deployed_sha or str(provenance.get("run_id") or "") != str(run["id"]):
            raise evidence.EvidenceError(MISMATCH, "the artifact does not belong to this run / commit")
        meta = evidence.accept(raw, source=f"GitHub Tier-3 run {int(run['id'])}", directory=directory)
        return {**meta, "run_id": int(run["id"]), "run_url": str(run.get("html_url") or ""), "conclusion": str(run.get("conclusion") or "")}
    raise evidence.EvidenceError(NO_ARTIFACT, "no Tier-3 run for the deployed commit carries a test-governance artifact")

