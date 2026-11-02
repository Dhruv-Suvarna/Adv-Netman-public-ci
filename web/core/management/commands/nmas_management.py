"""Management multihoming from the shell -- the automation side of V2 Phase 4 (the website carries the operator side).

    nmas_management status [--device NAME]          READ-ONLY: paths, health, active path and management state as JSON
    nmas_management spof                            READ-ONLY: the single-point-of-failure report (never claims redundancy)
    nmas_management telemetry                       READ-ONLY: what telemetry would follow (it does NOT follow failover yet)
    nmas_management capability                      READ-ONLY: the management-VRF matrix and the Phase-4 lifecycle rows
    nmas_management observe --attachment NMA-x --actor U   read-only host observation of one NMAS attachment, recorded
    nmas_management evaluate (--device NAME | --all) --actor U   probe approved paths (SSH, pinned host key) and select
    nmas_management recover --actor U               restart recovery: repair active flags from the database
    nmas_management bcred-execute --transition BCRED-x --actor U   run / resume an APPROVED bootstrap credential transition

Probes contact only registered, approved management targets.  Nothing here changes host routing, firewall rules,
namespaces or NIC configuration, and nothing touches DHCP, VLAN 200, NetBox or monitoring services.
"""

from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from ... import models
from ...services.capabilities import lifecycle_features
from ...services.identity.policy import Action, permission_name
from ...services.management import bootstrap_credentials, nmas_side, resolve, selector, vrf

PERMISSION = {"observe": Action.VALIDATE, "evaluate": Action.VALIDATE, "recover": Action.EXECUTE, "bcred-execute": Action.EXECUTE}


def _pk(identifier: str, prefix: str) -> int:
    text = str(identifier or "")
    if not text.startswith(prefix) or not text[len(prefix):].isdigit():
        raise CommandError(f"expected {prefix}NNNNNN")
    return int(text[len(prefix):])


class Command(BaseCommand):
    help = "Management multihoming: path status, SPOF report, probes / selection, restart recovery and bootstrap credential retirement."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("status").add_argument("--device", default="")
        for name in ("spof", "telemetry", "capability"):
            sub.add_parser(name)
        observe = sub.add_parser("observe")
        observe.add_argument("--attachment", required=True)
        evaluate = sub.add_parser("evaluate")
        target = evaluate.add_mutually_exclusive_group(required=True)
        target.add_argument("--device", default="")
        target.add_argument("--all", action="store_true")
        sub.add_parser("recover")
        sub.add_parser("bcred-execute").add_argument("--transition", required=True)
        for name, child in sub.choices.items():
            if name in PERMISSION:
                child.add_argument("--actor", required=True)

    def _actor(self, options) -> str:
        user = get_user_model().objects.filter(username=options["actor"], is_active=True).first()
        required = PERMISSION[options["action"]]
        if user is None or not user.has_perm(permission_name(required)):
            raise CommandError(f"--actor must be an active user holding core.{required.value}")
        return user.get_username()

    def _device(self, name):
        device = models.ManagedDevice.objects.filter(name=name).first()
        if device is None:
            raise CommandError("unknown managed device")
        return device

    def _out(self, payload):
        self.stdout.write(json.dumps(payload, indent=2, sort_keys=True, default=str))

    def handle(self, *args, **options):  # noqa: C901 - a flat dispatcher
        action = options["action"]
        actor = self._actor(options) if action in PERMISSION else ""
        if action == "status":
            devices = [self._device(options["device"])] if options["device"] else \
                models.ManagedDevice.objects.filter(management_paths__isnull=False).distinct().order_by("name")
            return self._out({"devices": [selector.device_status(d) for d in devices]})
        if action == "spof":
            return self._out(nmas_side.spof_report())
        if action == "telemetry":
            return self._out({"telemetry_follows_failover": False, "targets": resolve.telemetry_targets()})
        if action == "capability":
            return self._out({"management_vrf": vrf.capability_matrix(),
                              "lifecycle": [lifecycle_features.by_key()[k].as_dict() for k in
                                            ("lifecycle.CREDENTIAL_ONBOARDING", "lifecycle.MGMT_VRF", "lifecycle.MGMT_FAILOVER")]})
        if action == "observe":
            attachment = models.NmasManagementAttachment.objects.filter(pk=_pk(options["attachment"], "NMA-")).first()
            if attachment is None:
                raise CommandError("unknown NMAS attachment")
            result = nmas_side.observe_and_record(attachment, actor=actor)
            if not result.ok:
                raise CommandError(f"refused: {', '.join(result.codes)}")
            attachment.refresh_from_db()
            return self._out({"attachment": attachment.attachment_id, "verification": attachment.verification_state,
                              "observation": attachment.observation})
        if action == "evaluate":
            devices = [self._device(options["device"])] if options["device"] else \
                models.ManagedDevice.objects.filter(management_paths__approval_state=models.ManagementApproval.APPROVED).distinct().order_by("name")
            return self._out({"evaluations": [selector.evaluate(d, actor=f"nmas-selector (requested by {actor})"[:150]).as_dict()
                                              for d in devices]})
        if action == "recover":
            return self._out({"repairs": selector.recover(actor=f"nmas-selector (requested by {actor})"[:150])})
        if action == "bcred-execute":
            transition = models.BootstrapCredentialTransition.objects.filter(pk=_pk(options["transition"], "BCRED-")).first()
            if transition is None:
                raise CommandError("unknown bootstrap credential transition")
            result = bootstrap_credentials.execute(transition, actor=actor)
            payload = bootstrap_credentials.status(result.transition or transition)
            if not result.ok:
                self._out(payload)
                raise CommandError(f"stopped: {', '.join(result.codes)}")
            return self._out(payload)
        raise CommandError("unknown action")
