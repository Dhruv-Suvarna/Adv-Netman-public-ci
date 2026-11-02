"""Django settings for the disposable V2 Phases 5 + 6 live fixture run (``run-harness.sh``).  Never used by a deployment.

Everything that would otherwise reach production state is redirected into this fixture's git-ignored ``runtime/``: the NMAS
database (a fresh, migrated SQLite file), the ZTP enrollment-key store and the DHCP provider root, whose validate / status
commands run inside the fixture's own bootstrap-service container.
"""

from pathlib import Path

from config.settings import *  # pylint: disable=wildcard-import,unused-wildcard-import  # noqa: F401,F403 - the ordinary settings, then the fixture overrides below

RUNTIME = Path(__file__).resolve().parent / "runtime"
SVC_CONTAINER = "nmas-iso-p56-svc"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": RUNTIME / "nmas-fixture.sqlite3"}}
NMAS_ZTP_PROVIDER_ROOTS = [RUNTIME]
NMAS_ZTP_ENROLLMENT_STORE = str(RUNTIME / "enrollment-store.json")
NMAS_ZTP_DHCP_COMMANDS = {"ISC_DHCP": {"validate": ["docker", "exec", SVC_CONTAINER, "dhcpd", "-t", "-cf", "/srv/dhcp/{name}"],
                                       "status": ["docker", "exec", SVC_CONTAINER, "pgrep", "-x", "dhcpd"]}}
# SUBSTITUTION (recorded in the evidence README): the external GitHub Actions "Configuration Validation" gate is off for the
# fixture.  The fixture has no GitHub token, and a fixture candidate must never be dispatched to the project's CI.  In-NMAS
# Tier-1/2 validation, the network-configuration validation and every other execution gate still apply; in production the
# commissioning Change additionally needs a Configuration Validation PASS for its exact candidate.
NMAS_CONFIGURATION_VALIDATION_ENABLED = False
