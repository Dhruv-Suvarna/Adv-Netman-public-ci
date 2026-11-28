"""Run the isolated NMAS Troubleshooter diagnostic worker."""

from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from core.services.troubleshooting.diagnostic_worker import server_from_environment


class _ReadOnlySql:
    """Defence in depth: the diagnostic process has no database write API."""

    _ALLOWED = ("SELECT", "PRAGMA", "EXPLAIN", "WITH")

    def __call__(self, execute, sql, params, many, context):
        statement = str(sql).lstrip().upper()
        if not statement.startswith(self._ALLOWED):
            raise RuntimeError("diagnostic worker database is read-only")
        return execute(sql, params, many, context)


class Command(BaseCommand):
    help = "Run authenticated, typed diagnostic IPC (no arbitrary shell/destination API)."

    def handle(self, *args, **options):
        try:
            # SQLite is the deployed NMAS database.  Enforce read-only mode in
            # the database engine as well as through the SQL wrapper and the
            # unit's read-only bind mount.
            with connection.cursor() as cursor:
                cursor.execute("PRAGMA query_only=ON")
            with connection.execute_wrapper(_ReadOnlySql()):
                server_from_environment().serve()
        except KeyboardInterrupt:
            return
        except Exception as exc:
            raise CommandError(f"diagnostic worker refused startup: {type(exc).__name__}") from exc
