#!/usr/bin/env python3
"""CI entry point of the GitHub Actions workflow "Configuration Validation".

    python scripts/ci/validate_configuration_change.py --event "$GITHUB_EVENT_PATH" [--summary-md FILE] [--json FILE] [--skip-tests]

Reads the ``repository_dispatch`` event NMAS sent, verifies and decodes its bundle, runs the candidate-specific checks
(``web/core/services/configuration_validation/checks.py``, categories A to E) and then the narrowest relevant Django
tests (category F).  Exit status 0 = PASS, 1 = FAIL.

VALIDATION ONLY.  It opens no device session, sends no configuration, executes no Configlet and writes no NetBox or
NMAS data: it has no credentials and no network target to do so, and the tests it runs use an in-memory database.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "web"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ.setdefault("DJANGO_DEBUG", "true")


def summary(report: dict) -> str:
    bundle = report.get("bundle") or {}
    lines = ["# NMAS Configuration Validation", "", f"**{report['overall']}**", "", "| | |", "|---|---|",
             f"| NMAS Change | `{bundle.get('change_id', 'unknown')}` |", f"| Correlation id | `{bundle.get('correlation_id', 'unknown')}` |",
             f"| Target device(s) | {', '.join(bundle.get('devices') or []) or 'none'} |", f"| Platform(s) | {', '.join(bundle.get('platforms') or []) or 'none'} |",
             f"| Requested features | {', '.join(bundle.get('features') or []) or 'none'} |", f"| Candidate hash | `{bundle.get('candidate_hash', '')}` |",
             f"| Change snapshot hash | `{bundle.get('snapshot_hash', '')}` |", f"| Tier-2 validation run | `{bundle.get('validation_run_id', '')}` |",
             f"| Repository tested | `{report.get('tested_sha', '')}` |", "", "| Category | Result |", "|---|---|"]
    lines += [f"| {c['category']}. {c['title']} | {c['status']} |" for c in report["categories"]]
    for category in report["categories"]:
        lines += ["", f"## {category['category']}. {category['title']}: {category['status']}", ""]
        lines += [f"- {'PASS' if c['status'] == 'PASS' else '**FAIL**'} {c['name']}" + (f" ({c['detail']})" if c["detail"] else "") for c in category["checks"]]
    lines += ["", "This workflow validates only: no device session, no configuration write, no NetBox or NMAS change."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True, help="The GitHub event file (repository_dispatch) or a client_payload JSON file.")
    parser.add_argument("--summary-md", default="")
    parser.add_argument("--json", default="")
    parser.add_argument("--skip-tests", action="store_true", help="Categories A to E only (used by the unit tests of this script).")
    args = parser.parse_args(argv)

    import django

    django.setup()
    from core.services.configuration_validation import bundle as bundle_module
    from core.services.configuration_validation import checks

    report = {"overall": "FAIL", "categories": [], "bundle": {}, "tested_sha": os.environ.get("GITHUB_SHA", "")}
    try:
        event = json.loads(Path(args.event).read_text(encoding="utf-8"))
        payload = event.get("client_payload", event)
        report["bundle"] = {"change_id": payload.get("change_id"), "correlation_id": payload.get("correlation_id")}
        bundle = bundle_module.decode(payload)
    except (OSError, ValueError, bundle_module.BundleError) as exc:
        failed = checks.Category("A", "Bundle integrity")
        failed.add("the dispatched bundle is readable and is the one NMAS hashed", False, str(exc))
        categories = [failed]
    else:
        report["bundle"] = {"change_id": bundle["change"].get("change_id"), "correlation_id": bundle.get("correlation_id"),
                            "devices": sorted({d["device"] for d in [*bundle["devices"], *bundle["removals"]]}),
                            "platforms": sorted({d["platform"] for d in [*bundle["devices"], *bundle["removals"]]}),
                            "features": sorted({f for d in bundle["devices"] for f in d.get("features") or []}),
                            "candidate_hash": bundle.get("candidate_hash"), "snapshot_hash": bundle.get("snapshot_hash"),
                            "validation_run_id": (bundle.get("validation") or {}).get("run_id"), "demonstration": bundle.get("demonstration", "")}
        categories = checks.run_static(bundle, repo_root=ROOT, payload=payload)
        if not args.skip_tests and all(c.status == checks.PASS for c in categories):
            tests = checks.Category("F", "Path-scoped automated tests")
            labels = checks.select_tests(bundle, repo_root=ROOT)
            done = subprocess.run([sys.executable, "manage.py", "test", *labels, "--noinput"], cwd=ROOT / "web", capture_output=True, text=True, check=False)  # noqa: S603
            tail = (done.stderr or done.stdout).strip().splitlines()[-1:] or [""]
            tests.add(f"{len(labels)} test module(s): {', '.join(label.rsplit('.', 1)[-1] for label in labels)}", done.returncode == 0, tail[0])
            if done.returncode:
                sys.stderr.write((done.stderr or done.stdout)[-6000:])
            categories.append(tests)
    report["categories"] = [c.as_dict() for c in categories]
    report["overall"] = "PASS" if all(c["status"] == "PASS" for c in report["categories"]) else "FAIL"
    text = summary(report)
    if args.summary_md:
        with open(args.summary_md, "a", encoding="utf-8") as handle:
            handle.write(text)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=1), encoding="utf-8")
    sys.stdout.write(text)
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
