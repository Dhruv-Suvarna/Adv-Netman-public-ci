"""Operate the restart-safe bulk admission of the nine-device srlceos01 managed topology (see services.devices.bulk_admission).

    prepare            --dir D --ticket T   evidence, adoption, attachments (+ observation), diagnostic credentials, cEOS paths
    exception-document --dir D --window A|B  write the exact-target single-admin scope (root installs it; nothing is approved)
    approve-window     --dir D --window A|B  consume the INSTALLED + ACTIVATED exception for exactly its targets, then revoke it
    identity           --dir D --devices ... observe (signed observer source, under the grant) + verify_identity by dhruv
    register-frr-paths --dir D               FRR paths, after their legacy-route identity is verified
    activate           --dir D --devices ... probe + activate approved paths
    status             --dir D [--json]      the nine-device admission matrix

Every step is idempotent and checkpointed; nothing here edits approval state except through the existing services.
"""

from __future__ import annotations

import json
import os

import time

from django.core.management.base import BaseCommand, CommandError
from django.db import OperationalError

from core import models
from core.services.devices import attachments, bulk_admission as ba, observation_authorizations
from core.services.identity import single_admin_exception as exception
from core.services.management import paths


def _retry(call, attempts: int = 8, pause: float = 3.0):
    """SQLite writer contention (intake / web): every governed call is ONE atomic transaction (its exception-use audit rolls back
    with it), so retrying a 'database is locked' refusal is safe and can never double-consume (the replay guard also refuses)."""
    for attempt in range(attempts):
        try:
            return call()
        except OperationalError as exc:
            if "locked" not in str(exc) or attempt == attempts - 1:
                raise
            time.sleep(pause)
    return None


class Command(BaseCommand):
    help = "Bulk, restart-safe admission of the nine managed srlceos01 devices (owner-authorized single-admin windows)."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        for name in ("prepare", "exception-document", "approve-window", "identity", "register-frr-paths", "activate", "status"):
            cmd = sub.add_parser(name)
            cmd.add_argument("--dir", required=True)
            if name == "prepare":
                cmd.add_argument("--ticket", required=True)
                cmd.add_argument("--devices", nargs="*", default=[m.name for m in ba.MEMBERS])
            if name in ("exception-document", "approve-window"):
                cmd.add_argument("--window", choices=("A", "A2", "B", "B2", "C"), required=True)
            if name == "exception-document":
                cmd.add_argument("--out", required=True)
            if name in ("identity", "activate"):
                cmd.add_argument("--devices", nargs="+", required=True)
            if name == "status":
                cmd.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        batch = ba.Batch.open(opts["dir"])
        getattr(self, "_" + opts["action"].replace("-", "_"))(batch, opts)

    # ----------------------------------------------------------------------------------------------------------------
    def _prepare(self, batch, opts):
        batch.state["ticket"] = opts["ticket"]
        batch.save()
        for name in opts["devices"]:
            member = ba.BY_NAME[name]
            for phase, fn in (("EVIDENCE", ba.phase_evidence), ("ADOPT", ba.phase_adopt), ("ATTACH", ba.phase_attach),
                              ("CREDENTIAL", ba.phase_credential)):
                if batch.done(name, phase):
                    continue
                row = fn(batch, member)
                self.stdout.write(f"{name:9s} {phase:10s} {row['status']} {','.join(row.get('codes') or [])}")
                if row["status"] != "DONE":
                    break
            else:
                if not member.frr and not batch.done(name, "PATH"):
                    row = ba.phase_path(batch, member)
                    self.stdout.write(f"{name:9s} PATH       {row['status']} {','.join(row.get('codes') or [])} {row.get('path', '')}")

    def _exception_document(self, batch, opts):
        doc = ba.exception_document(batch, grant=opts["window"][0] in "AC")
        scope = {k: v for k, v in doc["scope"].items() if opts["window"][0] in "AC" or k == "MGMT_PATH_APPROVE"}
        uses = sum(len(v) for v in scope.values())
        if not uses:
            raise CommandError("nothing to approve in this window")
        document = {
            "schema": exception.SCHEMA, "marker": exception.MARKER, "mode": exception.MODE,
            "exception_id": f"OWNER-LAB-BULK-20261117-019-{opts['window']}", "actor": ba.ACTOR, "lab_id": ba.LAB,
            "issued_at": doc["issued_at"], "expires_at": doc["expires_at"], "max_uses": uses, "scope": scope,
            "evidence": {"authorization": "owner instruction 'NMAS V2 AUTHORITATIVE BULK COMMISSIONING' (dhruv, sole lab administrator)",
                         "batch_state": str(batch.root / "state.json"), "window": opts["window"],
                         "devices": [m.name for m in ba.MEMBERS],
                         **({"attachment_observations": doc["attachment_observations"],
                             "attachment_evidence_sha256s": doc["attachment_evidence_sha256s"]} if opts["window"].startswith("A") else {})},
        }
        if not exception.parse(document).ok:
            raise CommandError("refused: generated document does not validate")
        with open(opts["out"], "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=1, sort_keys=True)
        batch.state.setdefault("windows", {})[opts["window"]] = {"exception_id": document["exception_id"], "scope": scope,
                                                                 "document": opts["out"], "max_uses": uses}
        batch.save()
        self.stdout.write(json.dumps({"exception_id": document["exception_id"], "uses": uses, "scope": scope}, indent=1))

    def _approve_window(self, batch, opts):
        loaded = exception.load()
        if not loaded.ok:
            raise CommandError("refused: " + ";".join(loaded.codes))
        cap = loaded.capability
        expected = (batch.state.get("windows") or {}).get(opts["window"], {}).get("exception_id")
        if cap.exception_id != expected:
            raise CommandError("refused: installed exception is not this window's document")
        if not exception.state(cap).ok:
            activated = _retry(lambda: exception.activate(cap, actor=ba.ACTOR))
            if not activated.ok:
                raise CommandError("refused: " + ";".join(activated.codes))
        results = []
        try:
            for target in cap.scope.get("ATTACHMENT_APPROVE", ()):
                device_id, pk = target.split(":")
                device = next(d for d in models.ManagedDevice.objects.all() if d.device_id == device_id)
                r = _retry(lambda: attachments.approve_attachment(device, int(pk), actor=ba.ACTOR, exception=cap))
                results.append(("ATTACHMENT_APPROVE", target, r.ok, r.codes))
            for target in cap.scope.get("OBSERVATION_AUTHORIZATION_GRANT", ()):
                ticket, names, cmds = target.split("|")
                r = _retry(lambda: observation_authorizations.grant(
                    devices=names.split(","), commands=cmds.split(","), ttl_seconds=6 * 3600, approver=ba.ACTOR, requested_by=ba.ACTOR,
                    ticket=ticket, reason="bulk admission identity observations", exception=cap,
                    max_observations=2 * len(names.split(","))))      # one retry per device, still bounded
                if r.ok:
                    batch.state["observation_authorization"] = observation_authorizations.reference(r.authorization)
                    batch.save()
                results.append(("OBSERVATION_AUTHORIZATION_GRANT", target, r.ok, r.codes))
            for target in cap.scope.get("MGMT_PATH_APPROVE", ()):
                path = models.ManagementPath.objects.get(pk=int(target.removeprefix("MPATH-")))
                r = _retry(lambda: paths.approve_path(path, actor=ba.ACTOR, exception=cap))
                results.append(("MGMT_PATH_APPROVE", target, r.ok, r.codes))
        finally:
            revoked = _retry(lambda: exception.revoke(cap, actor=ba.ACTOR, reason=f"bulk admission window {opts['window']} complete"))
            batch.state["windows"][opts["window"]].update(
                revoked=revoked.ok, revoke_codes=revoked.codes,
                results=[{"action": a, "target": t, "ok": ok, "codes": c} for a, t, ok, c in results])
            batch.save()
        for row in results:
            self.stdout.write(f"{row[0]:32s} {row[1]:40s} {'OK' if row[2] else 'REFUSED ' + ','.join(row[3])}")
        self.stdout.write(f"exception {cap.exception_id} revoked={revoked.ok}")

    def _identity(self, batch, opts):
        source_id = os.environ.get("NMAS_OBSERVATION_SOURCE_ID", "")
        ref = batch.state.get("observation_authorization", "")
        if not source_id or not ref:
            raise CommandError("refused: observation source environment or authorization missing")
        evidence = ba.OBSERVATION_EVIDENCE_DIR      # observation_evidence.APPROVED_ROOTS (same directory as the R2/S2 evidence)
        for name in opts["devices"]:
            row = ba.observe_identity(batch, ba.BY_NAME[name], authorization_ref=ref, source_id=source_id, evidence_dir=str(evidence))
            self.stdout.write(f"{name:9s} IDENTITY   {row['status']} {','.join(row.get('codes') or [])}")

    def _register_frr_paths(self, batch, opts):
        for member in ba.MEMBERS:
            if member.frr:
                if not batch.done(member.name, "IDENTITY"):
                    self.stdout.write(f"{member.name:9s} PATH       SKIPPED identity not verified")
                    continue
                row = ba.phase_path(batch, member)
                self.stdout.write(f"{member.name:9s} PATH       {row['status']} {','.join(row.get('codes') or [])} {row.get('path', '')}")

    def _activate(self, batch, opts):
        for name in opts["devices"]:
            row = ba.activate(batch, ba.BY_NAME[name])
            self.stdout.write(f"{name:9s} ACTIVATE   {row['status']} {row.get('path')} {row.get('health')} {','.join(row.get('codes') or [])}")

    def _status(self, batch, opts):
        rows = ba.matrix(batch)
        if opts["json"]:
            self.stdout.write(json.dumps(rows, indent=1, sort_keys=True))
            return
        for r in rows:
            self.stdout.write(f"{r['device']:9s} {r['identity']:11s} {r['path']:13s} {r['path_state']:26s} {r['diag_credential']:30s} "
                              f"{'ADMITTED' if ba.admitted(r) else 'NOT-ADMITTED'}  {r['attachment']}")
        self.stdout.write(f"admitted {sum(ba.admitted(r) for r in rows)}/9")
