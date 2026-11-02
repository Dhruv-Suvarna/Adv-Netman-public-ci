"""
Safe cleanup for synthetic test notifications (Phase 4).

Deletes ONLY notifications explicitly marked is_test=True (created by
send_test_notification). Never touches a real notification, regardless of
its severity/title/content. Dry-run by default -- pass --apply to delete.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from core.models import Notification


class Command(BaseCommand):
    help = (
        "Delete synthetic TEST notifications (is_test=True) created by "
        "send_test_notification. Dry-run by default; pass --apply to delete."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply", action="store_true", help="Actually delete; without this flag, only reports the count."
        )

    def handle(self, *args, **options):
        queryset = Notification.objects.filter(is_test=True)
        count = queryset.count()
        if options["apply"]:
            queryset.delete()
            self.stdout.write(self.style.SUCCESS(f"Deleted {count} test notification(s)."))
        else:
            self.stdout.write(f"{count} test notification(s) would be deleted. Re-run with --apply to delete.")
