"""Grant, revoke or inspect a scoped, expiring read-only observation authorization (``observation_authorizations``).

    manage.py observation_authorize grant --approver <APPROVE account> --requested-by <requester> --ticket <CHG-ID>
        --devices R2,R4 [--commands nos-version] --ttl-minutes 240 [--max-observations N] [--reason TEXT]
    manage.py observation_authorize revoke OBSAUTH-000001 --actor <APPROVE account> [--reason TEXT]
    manage.py observation_authorize show OBSAUTH-000001 [--json]

Database only: no device, credential, key or network is touched.  The printed reference (OBSAUTH-NNNNNN#sha256=<scope digest>) is
what ``device_observe --authorization-ref`` takes; the observation is then run by a different account holding EXECUTE.
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from core.services.devices import observation_authorizations as authz


class Command(BaseCommand):
    help = "Grant / revoke / show a scoped, expiring read-only device observation authorization."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        g = sub.add_parser("grant")
        g.add_argument("--approver", required=True)
        g.add_argument("--requested-by", required=True, dest="requested_by")
        g.add_argument("--ticket", required=True)
        g.add_argument("--devices", required=True, help="comma-separated device names (WRITABLE scope only; R5 is refused)")
        g.add_argument("--commands", default="nos-version")
        g.add_argument("--ttl-minutes", type=int, required=True, dest="ttl_minutes")
        g.add_argument("--max-observations", type=int, default=None, dest="max_observations")
        g.add_argument("--reason", default="")
        r = sub.add_parser("revoke")
        r.add_argument("ref")
        r.add_argument("--actor", required=True)
        r.add_argument("--reason", default="")
        s = sub.add_parser("show")
        s.add_argument("ref")
        s.add_argument("--json", action="store_true")

    def handle(self, *args, **opts):
        action = opts["action"]
        if action == "grant":
            result = authz.grant(devices=opts["devices"].split(","), commands=opts["commands"].split(","),
                                 ttl_seconds=int(opts["ttl_minutes"]) * 60, approver=opts["approver"],
                                 requested_by=opts["requested_by"], ticket=opts["ticket"], reason=opts["reason"],
                                 max_observations=opts["max_observations"])
            if not result.ok:
                raise CommandError("refused: " + "; ".join(result.codes))
            self.stdout.write(f"granted {authz.reference(result.authorization)}")
            self._show(result.authorization, as_json=False)
            return
        found = authz.lookup(opts["ref"])
        if not found.ok:
            raise CommandError("refused: " + "; ".join(found.codes))
        if action == "revoke":
            result = authz.revoke(found.authorization, actor=opts["actor"], reason=opts["reason"])
            if not result.ok:
                raise CommandError("refused: " + "; ".join(result.codes))
            self.stdout.write(f"revoked {result.authorization.auth_id}")
            return
        self._show(found.authorization, as_json=opts["json"])

    def _show(self, auth, *, as_json: bool):
        uses = list(auth.uses.order_by("id").values("device", "command", "operator", "state", "outcome_codes", "evidence_ref"))
        doc = {"id": auth.auth_id, "reference": authz.reference(auth), "devices": auth.devices, "commands": auth.commands,
               "ticket": auth.ticket, "requested_by": auth.requested_by, "approved_by": auth.approved_by,
               "not_before": auth.not_before.isoformat(), "expires_at": auth.expires_at.isoformat(),
               "max_observations": auth.max_observations, "used": len(uses), "status": authz.still_valid(auth) or "VALID",
               "revoked_by": auth.revoked_by, "uses": uses}
        if as_json:
            self.stdout.write(json.dumps(doc, indent=2, sort_keys=True))
            return
        for key in ("id", "reference", "devices", "commands", "ticket", "requested_by", "approved_by", "not_before", "expires_at",
                    "max_observations", "used", "status"):
            self.stdout.write(f"  {key}: {doc[key]}")
