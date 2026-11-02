"""The operator's ONE-TIME command for the legacy baseline bootstrap (see docs/LEGACY_BASELINE_BOOTSTRAP.md).

    python web/manage.py legacy_bootstrap probe    [--json]                    read-only readiness probe (persists nothing)
    python web/manage.py legacy_bootstrap capture  [--actor NAME]              read-only capture -> immutable LEGACY_BASELINE candidate
    python web/manage.py legacy_bootstrap start    [--candidate BND-LEGACY-..]  start the 30-minute observation (the server fixes start, end, duration)
    python web/manage.py legacy_bootstrap observe  [--run BOOT-..]              drive the observation: sample every 5 minutes and WAIT (never a busy loop)
                                                                                until it ends; Ctrl-C is safe (the run stays RUNNING; run it again to resume)
    python web/manage.py legacy_bootstrap status   [--run BOOT-..] [--json]    read-only report
    python web/manage.py legacy_bootstrap approve  --run BOOT-.. --confirm      the operator's approval of the initial Golden (the SAME service function the
                                                                                web page's Approve button calls; it re-reads every device first)
    python web/manage.py legacy_bootstrap verify   [--json]                    read-only: integrity of the candidate / initial Golden, the lockout, the policies

Everything READS the network through the existing allowlisted read-only sessions and writes only application rows (candidate, run, samples, audit,
notifications and -- for ``approve`` -- the one Golden bundle).  Nothing here configures a device, writes NetBox / Git, runs Containerlab or calls
``master.py`` (which could converge devices).  Nothing here can backdate, sleep-skip, shorten or edit a timestamp: time is the server's own clock.

Exit status: 0 = the action succeeded; 1 = refused / not passed (see the printed blockers); 130 = interrupted (the run is left RUNNING and resumable).
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core import models
from core.services import bootstrap_service as bs, bundle_service, soak_service

DEFAULT_ACTOR = "legacy-bootstrap-operator"


def _blockers(blockers) -> str:
    return "\n".join(f"  - {b['code']}: {b['message']} {b['remediation']}" + (f"  details={json.dumps(b['details'], sort_keys=True, default=str)}" if b.get("details") else "")
                     for b in blockers)


class Command(BaseCommand):
    help = "One-time legacy baseline bootstrap: probe, capture, start, observe (30 real minutes), status, approve, verify."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=["probe", "capture", "start", "observe", "status", "approve", "verify"])
        parser.add_argument("--actor", default=DEFAULT_ACTOR, help="Operator identity recorded in the audit trail.")
        parser.add_argument("--candidate", default="", help="Candidate bundle id (default: the newest LEGACY_BASELINE candidate).")
        parser.add_argument("--run", default="", help="Observation id (default: the running one, else the newest).")
        parser.add_argument("--confirm", action="store_true", help="Required by 'approve': you reviewed the evidence and approve THIS baseline.")
        parser.add_argument("--reason", default="", help="Optional approval comment (never enter a secret).")
        parser.add_argument("--json", action="store_true", help="Print JSON where supported.")

    # ------------------------------------------------------------------------------------------------------------------------------
    def handle(self, *args, **options):
        getattr(self, f"do_{options['action']}")(options)

    def _candidate(self, options):
        if options["candidate"]:
            found = bundle_service.get_bundle(options["candidate"])
            if found is None or found.kind != models.BundleKind.LEGACY_BASELINE:
                raise CommandError("No such legacy baseline candidate.")
            return found
        found = models.ConfigurationBundle.objects.filter(kind=models.BundleKind.LEGACY_BASELINE).order_by("-created_at", "-id").first()
        if found is None:
            raise CommandError("No legacy baseline candidate exists yet: run 'capture' first.")
        return found

    def _run(self, options):
        if options["run"]:
            run = bs.get_run(options["run"])
            if run is None:
                raise CommandError("No such bootstrap observation.")
            return run
        run = bs.active_run() or (bs.list_runs(limit=1) or [None])[0]
        if run is None:
            raise CommandError("No bootstrap observation exists yet: run 'start' first.")
        return run

    # ------------------------------------------------------------------------------------------------------------------------------
    def do_probe(self, options):
        report = bs.readiness_probe()
        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2, sort_keys=True, default=str))
        else:
            self.stdout.write(f"legacy bootstrap readiness probe at {report['generated_at']}: {'READY' if report['ready'] else 'BLOCKED'}")
            self.stdout.write(f"  managed devices ({len(report['managed_devices'])}): {', '.join(report['managed_devices'])}")
            self.stdout.write(f"  unreachable: {', '.join(report['unreachable']) or 'none'}")
            self.stdout.write(f"  monitoring: {json.dumps(report['monitoring'], sort_keys=True)}")
            for d in report["devices"]:
                self.stdout.write(f"    {d['device']:8s} {d['platform']:6s} capability={d['capability']} reachable={d['reachable']} freshness={d['telemetry_freshness']} "
                                  f"sections={[s['name'] for s in d['sections']]}{' problems=' + str(d['section_problems']) if d['section_problems'] else ''}")
            if report["assessment"]:
                self.stdout.write(f"  assessment: {report['assessment']['result']} counts={report['assessment']['counts']}")
                for f in report["assessment"]["findings"]:
                    self.stdout.write(f"    finding: {f}")
            if report["blockers"]:
                self.stdout.write("  blockers:\n" + _blockers(report["blockers"]))
        if not report["ready"]:
            raise SystemExit(1)

    def do_capture(self, options):
        result = bs.capture_candidate(actor=options["actor"])
        if result.bundle is None:
            self.stdout.write("BASELINE NOT CAPTURED (nothing was created):\n" + _blockers(result.blockers))
            raise SystemExit(1)
        b = result.bundle
        self.stdout.write(f"captured {b.bundle_id}: {len(b.payload['scope']['devices'])} devices, baseline digest {b.payload_digest}\n"
                          f"  captured_at {b.payload['baseline']['captured_at']}  redacted lines {b.payload['baseline']['sanitization']['redacted_lines']}  "
                          f"integrity {bundle_service.verify_bundle_integrity(b).state}")

    def do_start(self, options):
        result = bs.start_bootstrap(self._candidate(options), actor=options["actor"])
        if result.run is None:
            self.stdout.write("OBSERVATION NOT STARTED:\n" + _blockers(result.blockers))
            raise SystemExit(1)
        r = result.run
        self.stdout.write(f"{'started' if result.created else 'already running'} {r.run_id}: started_at {r.started_at.isoformat()}  required_end_at {r.required_end_at.isoformat()}  "
                          f"({r.duration_seconds // 60} minutes, {r.policy['sample_interval_seconds']} s samples, policy {r.policy_version})")

    def do_observe(self, options):
        run = self._run(options)
        if not run.is_running:
            self.stdout.write(f"{run.run_id} is not running ({run.state}/{run.result or '-'} {run.terminal_reason}).")
            return
        self.stdout.write(f"observing {run.run_id} until {run.required_end_at.isoformat()} (read-only; Ctrl-C is safe, run this command again to resume)")
        try:
            finished = bs.drive(run, emit=lambda text: (self.stdout.write(text), self.stdout.flush()))
        except KeyboardInterrupt:
            self.stdout.write(f"\ninterrupted: {run.run_id} stays RUNNING; no sample was fabricated. Run 'legacy_bootstrap observe' again to resume.")
            raise SystemExit(130)
        self.stdout.write(f"{finished.run_id} finished: {finished.state}/{finished.result or '-'} reason={finished.terminal_reason}")
        if not finished.is_technical_pass:
            raise SystemExit(1)

    def do_status(self, options):
        run = self._run(options)
        progress = bs.progress(run)
        decision = bs.decision_of(run)
        doc = {
            "run_id": run.run_id, "candidate": run.candidate.bundle_id, "state": run.state, "result": run.result, "terminal_reason": run.terminal_reason,
            "started_at": run.started_at.isoformat(), "required_end_at": run.required_end_at.isoformat(), "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "elapsed_seconds": progress["elapsed_seconds"], "remaining_seconds": progress["remaining_seconds"], "samples": progress["stats"]["samples"],
            "coverage_percent": progress["stats"]["coverage_percent"], "max_gap_seconds": progress["stats"]["max_gap_seconds"], "evidence_digest": run.evidence_digest,
            "approved": decision is not None, "golden": decision.golden_bundle.bundle_id if decision else None,
        }
        self.stdout.write(json.dumps(doc, indent=2, sort_keys=True) if options["json"] else " ".join(f"{k}={v}" for k, v in doc.items()))

    def do_approve(self, options):
        if not options["confirm"]:
            raise CommandError("Refusing to approve without --confirm: this seals the INITIAL Golden, once, from the exact observed baseline.")
        run = self._run(options)
        confirm = {"run_id": run.run_id, "candidate_id": run.candidate.bundle_id, "candidate_digest": run.candidate_digest, "baseline_digest": run.candidate.payload_digest}
        result = bs.approve(run, actor=options["actor"], reason=options["reason"], confirm=confirm)
        if result.refused or result.bundle is None:
            self.stdout.write("APPROVAL REFUSED (nothing was created):\n" + _blockers(result.blockers))
            raise SystemExit(1)
        g = result.bundle
        self.stdout.write(f"{'approved' if result.created else 'already approved'}: {g.bundle_id} provenance={g.provenance} created_at {g.created_at.isoformat()} "
                          f"digest {g.bundle_digest} baseline {g.payload_digest}")

    def do_verify(self, options):
        golden = bs.legacy_golden()
        entry = bundle_service.known_good_baseline()
        doc = {
            "gate": [b["code"] for b in bs.gate_blockers()], "initial_golden": golden.bundle_id if golden else None,
            "golden_integrity": bundle_service.verify_bundle_integrity(golden).state if golden else None,
            "candidates": {c.bundle_id: bundle_service.verify_bundle_integrity(c).state for c in models.ConfigurationBundle.objects.filter(kind=models.BundleKind.LEGACY_BASELINE)},
            "phase21_entry": {"valid": entry.valid, "source": entry.source, "golden": entry.golden.bundle_id if entry.golden else None},
            "normal_probation_seconds": soak_service.current_policy().duration_seconds, "bootstrap_seconds": bs.current_policy().duration_seconds,
        }
        self.stdout.write(json.dumps(doc, indent=2, sort_keys=True) if options["json"] else "\n".join(f"{k}: {v}" for k, v in doc.items()))
        if golden is not None and doc["golden_integrity"] != "INTACT":
            raise SystemExit(1)
