"""Django settings for the disposable V2 Phase 7 decommission fixture run (``run-harness.sh``).  Never used by a deployment.

The NMAS database is a fresh, migrated SQLite file in this fixture's git-ignored ``runtime/``; nothing reaches production state.
"""

from pathlib import Path

from config.settings import *  # pylint: disable=wildcard-import,unused-wildcard-import  # noqa: F401,F403 - the ordinary settings, then the fixture overrides below

RUNTIME = Path(__file__).resolve().parent / "runtime"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": RUNTIME / "nmas-fixture.sqlite3"}}
# SUBSTITUTION (recorded in the evidence README): the external GitHub Actions "Configuration Validation" gate is off for the fixture
# (no token; a fixture candidate is never dispatched to the project's CI).  Every in-NMAS gate still applies.
NMAS_CONFIGURATION_VALIDATION_ENABLED = False
# Phase 8: NetBox writes stay disabled (projection is computed and recorded only).
NMAS_NSOT_RECONCILE_WRITE = False
