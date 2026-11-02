"""Lab 7 test governance: inventory, catalog validation, evidence runs, Pylint, report, status, baseline, refresh.

    manage.py nmas_test_governance inventory [--json] [--scope current|all]
    manage.py nmas_test_governance validate-catalog [--ci] [--json]
    manage.py nmas_test_governance run --out DIR [--labels core ...] [--skip-pylint] [--ci]   traced tests + coverage + Pylint + report
    manage.py nmas_test_governance report --dir DIR [--ci] [--mode full]                      (Tier-3) combine, lint, assemble, gate
    manage.py nmas_test_governance pylint [--paths P ...] [--ci]
    manage.py nmas_test_governance status [--json]
    manage.py nmas_test_governance accept REPORT                                               store a verified local report
    manage.py nmas_test_governance baseline --from REPORT [--write]                            ratchet: debt can only shrink
    manage.py nmas_test_governance refresh                                                     fetch Tier-3 evidence for the deployed SHA

All logic lives in core.services.test_governance; this command only parses arguments and prints.  Nothing here
contacts a device, NetBox or the lab.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from core.services.test_governance import catalog_check, evidence, gate, inventory, runner, symbols
from core.services.test_governance.constants import REPO_ROOT, REPORT_FILENAME, ArtifactType, Scope
from core.services.test_governance.pylint_data import parse_pylint
from core.services.test_governance.policy import default_policy


class Command(BaseCommand):
    help = "Lab 7 unit-test catalog / function coverage / code coverage / Pylint governance (read-only; no device access)."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        inv = sub.add_parser("inventory", help="list deployed artifacts with classification and symbol dispositions")
        inv.add_argument("--json", action="store_true")
        inv.add_argument("--scope", choices=("current", "all"), default="all")
        val = sub.add_parser("validate-catalog", help="static catalog validation (no test run)")
        val.add_argument("--ci", action="store_true", help="exit 1 on any catalog error")
        val.add_argument("--json", action="store_true")
        run = sub.add_parser("run", help="full local evidence run")
        run.add_argument("--out", required=True)
        run.add_argument("--labels", nargs="*", default=["core"])
        run.add_argument("--skip-pylint", action="store_true")
        run.add_argument("--ci", action="store_true", help="exit 1 when the closure gate fails")
        rep = sub.add_parser("report", help="assemble + gate from the traced suites already in DIR (Tier-3)")
        rep.add_argument("--dir", required=True)
        rep.add_argument("--ci", action="store_true")
        rep.add_argument("--mode", default="full")
        rep.add_argument("--skip-pylint", action="store_true")
        lint = sub.add_parser("pylint", help="Pylint quality gate")
        lint.add_argument("--paths", nargs="*")
        lint.add_argument("--ci", action="store_true")
        lint.add_argument("--out", default="")
        st = sub.add_parser("status", help="the evidence NMAS would show, and its freshness")
        st.add_argument("--json", action="store_true")
        acc = sub.add_parser("accept", help="verify and store a report in the local evidence cache")
        acc.add_argument("report")
        base = sub.add_parser("baseline", help="derive the tracked baseline (ratchet) from a report")
        base.add_argument("--from", dest="source", required=True)
        base.add_argument("--write", action="store_true")
        sub.add_parser("refresh", help="fetch the Tier-3 evidence artifact for the deployed commit from GitHub")
        summ = sub.add_parser("summarize", help="render a verified report (and optionally the baseline) as Markdown")
        summ.add_argument("report")
        summ.add_argument("--baseline", default="")
        summ.add_argument("--out", default="")
        summ.add_argument("--gap", action="store_true", help="render REPORT as the baseline gap assessment (BASELINE.md)")

    def handle(self, *args, **options):
        handler = getattr(self, "do_" + options["action"].replace("-", "_"))
        return handler(**options)

    # -- inventory -----------------------------------------------------------------------------
    def do_inventory(self, *, json: bool = False, scope: str = "all", **_):  # noqa: A002 - argparse dest
        inv = inventory.build_inventory()
        rows = [a for a in inv.artifacts if scope == "all" or a.scope == Scope.CURRENT]
        modules = symbols.inventory_symbols([a.path for a in rows if a.type == ArtifactType.PYTHON])
        if json:
            payload = [{**a.to_dict(), "symbols": [s.to_dict() for s in (modules.get(a.path).symbols if a.path in modules else [])]} for a in rows]
            self.stdout.write(_json_dump({"artifacts": payload, "errors": inv.errors}))
            return
        dispositions = Counter(s.disposition for m in modules.values() for s in m.symbols)
        self.stdout.write(f"deployed artifacts: {len(inv.artifacts)} (shown: {len(rows)}); test files: {len(inv.test_files)}")
        self.stdout.write("by type: " + ", ".join(f"{k}={v}" for k, v in sorted(Counter(a.type for a in rows).items())))
        self.stdout.write("by scope: " + ", ".join(f"{k}={v}" for k, v in sorted(Counter(a.scope for a in rows).items())))
        self.stdout.write("python symbols: " + ", ".join(f"{k}={v}" for k, v in sorted(dispositions.items())))
        for error in inv.errors:
            self.stdout.write(f"ERROR {error}")

    # -- static catalog validation ---------------------------------------------------------------
    def do_validate_catalog(self, *, ci: bool = False, json: bool = False, **_):  # noqa: A002
        result = catalog_check.validate_catalog()
        if json:
            self.stdout.write(_json_dump(result))
        else:
            self.stdout.write(f"catalog: {result['artifacts']} artifacts, {result['symbols']} symbols, {result['declared']} declared case(s), "
                              f"{len(result['errors'])} error(s), {len(result['warnings'])} warning(s)")
            for error in result["errors"]:
                self.stdout.write(f"ERROR {error}")
            for warning in result["warnings"][:40]:
                self.stdout.write(f"WARN  {warning}")
        if ci and result["errors"]:
            raise SystemExit(1)

    # -- evidence --------------------------------------------------------------------------------
    def do_run(self, *, out: str, labels, skip_pylint: bool = False, ci: bool = False, **_):
        target = Path(out).resolve()
        run = runner.run_evidence(target, labels=tuple(labels), skip_pylint=skip_pylint, progress=lambda m: self.stderr.write(f"[governance] {m}"))
        for step in run.steps:
            self.stderr.write(f"[governance] {step.name}: exit {step.returncode}")
        data = runner.build_and_gate(target, baseline=gate.load_baseline(), mode="local")
        self._print_summary(data, target / REPORT_FILENAME)
        if ci and data["gate"]["result"] == gate.FAIL:
            raise SystemExit(1)

    def do_report(self, *, dir: str, ci: bool = False, mode: str = "full", skip_pylint: bool = False, **_):  # noqa: A002
        target = Path(dir).resolve()
        if not any((target / name).is_file() for name in ("django-trace.json", "monitoring-trace.json")):
            raise CommandError(f"no traced suite output in {target}: the traced django.tests / monitoring.unit checks did not run")
        for step in runner.combine_coverage(target, python=sys.executable):
            self.stderr.write(f"[governance] {step.name}: exit {step.returncode}")
            if step.returncode not in (0,) and step.name != "coverage.xml":
                self.stderr.write(step.tail)
                raise SystemExit(3)
        if not skip_pylint and not (target / "pylint.json").is_file():
            step = runner.run_pylint(target, python=sys.executable)
            self.stderr.write(f"[governance] pylint: exit {step.returncode}")
        data = runner.build_and_gate(target, baseline=gate.load_baseline(), mode=mode)
        self._print_summary(data, target / REPORT_FILENAME)
        if ci and data["gate"]["result"] == gate.FAIL:
            raise SystemExit(1)

    def do_pylint(self, *, paths=None, ci: bool = False, out: str = "", **_):
        known = {a.path for a in inventory.build_inventory().artifacts if a.type == ArtifactType.PYTHON and a.scope != Scope.EXEMPT}
        chosen = sorted(known if not paths else (set(paths) & known))
        if not chosen:
            self.stdout.write("pylint: no deployed Python artifact in scope")
            return
        target = Path(out or (REPO_ROOT / "tier3-governance")).resolve()
        target.mkdir(parents=True, exist_ok=True)
        step = runner.run_pylint(target, python=sys.executable, paths=chosen)
        if step.returncode is None:
            raise CommandError(f"pylint could not run: {step.tail}")
        lint = parse_pylint(json.loads((target / "pylint.json").read_text() or "{}"), policy=default_policy(), linted=chosen)
        allowed = gate.load_baseline().get("pylint") or {}
        critical = {p: e for p, e in lint.items() if e.critical}
        over = {p: e.over_baseline(allowed.get(p)) for p, e in lint.items() if e.over_baseline(allowed.get(p))}
        self.stdout.write(f"pylint: {len(chosen)} file(s); {sum(e.critical for e in lint.values())} critical; "
                          f"{sum(sum(e.counts.values()) for e in lint.values())} tracked non-critical; {len(over)} file(s) over baseline")
        for path, entry in sorted(critical.items()):
            for message in entry.messages:
                if message["critical"]:
                    self.stdout.write(f"CRITICAL {path}:{message['line']} {message['symbol']} {message['message']}")
        for path, extra in sorted(over.items()):
            self.stdout.write(f"NEW-DEBT {path}: {extra}")
        if ci and (critical or over):
            raise SystemExit(1)

    def do_status(self, *, json: bool = False, **_):  # noqa: A002
        chosen = evidence.select()
        data = chosen["report"]
        out = {"freshness": chosen["freshness"], "reason": chosen["reason"], "deployed": chosen["deployed"], "source": chosen["source"],
               "refused": chosen.get("refused", [])}
        if data:
            out.update({"repository_sha": data["repository_sha"], "generated_at": data["generated_at"], "payload_sha256": data["payload_sha256"],
                        "summary": data["summary"], "gate": (data.get("gate") or {}).get("result")})
        if json:
            self.stdout.write(_json_dump(out))
            return
        self.stdout.write(f"evidence: {out['freshness']} -- {out['reason']}")
        self.stdout.write(f"deployed SHA: {out['deployed'].get('sha')}  tested SHA: {out.get('repository_sha', '-')}  source: {out['source']}")
        if data:
            self._print_summary(data, None)

    def do_accept(self, *, report: str, **_):
        try:
            meta = evidence.accept(Path(report).read_bytes(), source=f"local evidence run ({Path(report).name})")
        except evidence.EvidenceError as exc:
            raise CommandError(f"refused: {exc.code} {exc.detail}") from None
        self.stdout.write(f"accepted {meta['payload_sha256']} (tested SHA {meta['repository_sha'] or '-'})")

    def do_baseline(self, *, source: str, write: bool = False, **_):
        data = evidence.verify_report(Path(source).read_bytes())
        baseline = gate.baseline_from_report(data)
        self.stdout.write(f"baseline from {data['repository_sha'] or 'working tree'}: {len(baseline['case_debt'])} debt case(s), "
                          f"{len(baseline['closed_artifacts'])} closed artifact(s), {len(baseline['closed_cells'])} closed cell(s), "
                          f"{len(baseline['declared_cases'])} locked declared case(s), {len(baseline['pylint'])} file(s) with tracked Pylint debt")
        if write:
            gate.write_baseline(baseline)
            self.stdout.write("written: web/core/services/test_governance/baseline.json")

    def do_refresh(self, **_):
        from core.services.configuration_validation.github import GitHubError
        from core.services.test_governance import github_evidence

        sha = evidence.deployed_state()["sha"]
        try:
            meta = github_evidence.refresh(sha)
        except (evidence.EvidenceError, GitHubError) as exc:
            raise CommandError(f"refresh refused: {exc.code} {getattr(exc, 'detail', '')}") from None
        self.stdout.write(f"accepted Tier-3 run {meta['run_id']} ({meta['conclusion']}) evidence {meta['payload_sha256'][:12]} for {sha[:12]}")

    def do_summarize(self, *, report: str, baseline: str = "", out: str = "", gap: bool = False, **_):
        from core.services.test_governance import summary

        final = evidence.verify_report(_read_evidence(report))
        before = evidence.verify_report(_read_evidence(baseline)) if baseline else None
        text = summary.gap_markdown(final) if gap else summary.results_markdown(final, before)
        if out:
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            Path(out).write_text(text, encoding="utf-8")
            self.stdout.write(f"written: {out}")
        else:
            self.stdout.write(text)

    # -- output ----------------------------------------------------------------------------------
    def _print_summary(self, data: dict, path: Path | None):
        s = data["summary"]
        pos, neg, cov, cells = s["positive"], s["negative"], s.get("coverage") or {}, s["cells"]
        self.stdout.write(f"tests: {s['tests']['total']} ({', '.join(f'{k}={v}' for k, v in s['tests'].items() if k != 'total')})")
        self.stdout.write(f"positive cases: {pos['pass']} / {pos['required']} PASS ({pos['missing']} missing, {pos['fail']} failing, {pos['exempt']} exempt)")
        self.stdout.write(f"negative cases: {neg['pass']} / {neg['required']} PASS ({neg['missing']} missing, {neg['fail']} failing)")
        self.stdout.write(f"artifacts closed: {s['artifacts']['closed']} / {s['artifacts']['counted']} (coverage-only {s['artifacts']['coverage_only']}, "
                          f"exempt {s['artifacts']['exempt']}, not current {s['artifacts']['not_current']})")
        self.stdout.write(f"functions explicitly tested: {s['functions']['tested']} / {s['functions']['required']}")
        if cov:
            self.stdout.write(f"statements: {cov['line_pct']}%  branches: {cov['branch_pct']}%")
        self.stdout.write(f"capability cells closed: {cells['closed']} / {cells['supported']}  (POS {cells['positive']['pass']}/{cells['positive']['required']}, "
                          f"NEG {cells['negative']['pass']}/{cells['negative']['required']})")
        self.stdout.write(f"pylint: {s['pylint']['status']} ({s['pylint']['critical']} critical)")
        if data.get("gate"):
            self.stdout.write(f"gate: {data['gate']['result']}")
            for finding in data["gate"]["findings"]:
                self.stdout.write(f"  {finding['severity']:4} {finding['code']}: {finding['message']}")
        if path:
            self.stdout.write(f"report: {path}  sha256(payload)={data['payload_sha256']}")


def _json_dump(value) -> str:
    return json.dumps(value, sort_keys=True, indent=1, default=str)



def _read_evidence(path: str) -> bytes:
    """Raw report bytes; a ``.gz`` file (the bundled baseline report) is decompressed first, then verified like any other."""
    import gzip

    raw = Path(path).read_bytes()
    return gzip.decompress(raw) if path.endswith(".gz") else raw
