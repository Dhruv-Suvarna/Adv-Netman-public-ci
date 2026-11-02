"""Django settings for the disposable FRR isolation fixture run (``run-harness.sh``).  Never used by a deployment.

The NMAS database is a fresh, migrated SQLite file and the DHCP provider root a directory, both under this fixture's
git-ignored ``runtime/``.  Nothing points at the production database, NetBox, DHCP or any production device.
"""

from pathlib import Path

from config.settings import *  # pylint: disable=wildcard-import,unused-wildcard-import  # noqa: F401,F403 - the ordinary settings, then the fixture overrides below

RUNTIME = Path(__file__).resolve().parent / "runtime"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": RUNTIME / "nmas-fixture.sqlite3"}}
NMAS_ZTP_PROVIDER_ROOTS = [RUNTIME]
NMAS_ZTP_ENROLLMENT_STORE = str(RUNTIME / "enrollment-store.json")
NMAS_CONFIGURATION_VALIDATION_ENABLED = False
