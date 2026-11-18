"""Operate one explicit, root-scoped single-administrator lab exception."""

from django.core.management.base import BaseCommand, CommandError

from core import models
from core.services.devices import attachments
from core.services.identity import single_admin_exception as exception
from core.services.management import paths


class Command(BaseCommand):
    help = "Activate, inspect, use or revoke the bounded owner-authorized single-admin lab exception."

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest="action", required=True)
        for name in ("activate", "status", "revoke", "expire", "approve-nma", "approve-attachment", "approve-path"):
            command = sub.add_parser(name)
            if name not in ("status", "expire"):
                command.add_argument("--actor", required=True)
            if name == "activate":
                command.add_argument("--confirm", required=True)
            elif name == "revoke":
                command.add_argument("--reason", required=True)
            elif name == "approve-nma":
                command.add_argument("--attachment", required=True)
            elif name == "approve-attachment":
                command.add_argument("--device", required=True)
                command.add_argument("--attachment-id", required=True, type=int)
            elif name == "approve-path":
                command.add_argument("--path", required=True)

    def handle(self, *args, **options):
        loaded = exception.load()
        if not loaded.ok:
            raise CommandError("refused: " + ";".join(loaded.codes))
        cap = loaded.capability
        action = options["action"]
        if action == "activate":
            if options["confirm"] != exception.MARKER:
                raise CommandError("refused: EXCEPTION_CONFIRMATION_MISMATCH")
            result = exception.activate(cap, actor=options["actor"])
        elif action == "status":
            result = exception.state(cap)
            self.stdout.write(f"id={cap.exception_id} mode={exception.MODE} actor={cap.actor} expires={cap.expires_at.isoformat()} "
                              f"status={'ACTIVE' if result.ok else ','.join(result.codes)}")
            return
        elif action == "revoke":
            result = exception.revoke(cap, actor=options["actor"], reason=options["reason"])
        elif action == "expire":
            result = exception.revoke(
                cap,
                actor="system:single-admin-exception-expiry",
                reason="automatic 30-minute expiration",
                operation="EXPIRE",
            )
        elif action == "approve-nma":
            row = models.NmasManagementAttachment.objects.filter(pk=str(options["attachment"]).removeprefix("NMA-")).first()
            if row is None:
                raise CommandError("refused: NMAS_ATTACHMENT_NOT_FOUND")
            result = paths.approve_nmas_attachment(row, actor=options["actor"], exception=cap)
        elif action == "approve-attachment":
            device = next(
                (item for item in models.ManagedDevice.objects.all() if item.device_id == options["device"]),
                None,
            )
            if device is None:
                raise CommandError("refused: DEVICE_UNKNOWN")
            result = attachments.approve_attachment(device, options["attachment_id"], actor=options["actor"], exception=cap)
        else:
            path = models.ManagementPath.objects.filter(pk=str(options["path"]).removeprefix("MPATH-")).first()
            if path is None:
                raise CommandError("refused: MGMT_PATH_NOT_FOUND")
            result = paths.approve_path(path, actor=options["actor"], exception=cap)
        if not result.ok:
            raise CommandError("refused: " + ";".join(result.codes))
        self.stdout.write(f"ok: {action} mode={exception.MODE} exception={cap.exception_id}")
