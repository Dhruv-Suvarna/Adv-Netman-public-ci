"""
Django settings for the Phase 3 UI foundation (clab_dualstack_lab).

This project is a HUMAN CONTROL PLANE only. It must never contain direct
Netmiko/pynetbox/subprocess/InfluxDB calls in views — see
core/services/ for the explicit service boundary, and
docs/DJANGO_UI_FOUNDATION.md for the full architecture writeup.

Security posture (documented per Phase 3 requirements):
- DEBUG is environment-aware (DJANGO_DEBUG), defaults to False (secure).
- SECRET_KEY must come from DJANGO_SECRET_KEY outside of DEBUG mode; an
  obviously-fake "django-insecure-" value is used only when DEBUG=true and
  no key is supplied, matching Django's own startproject convention.
- ALLOWED_HOSTS must be set explicitly outside of DEBUG mode.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

# Repository root (one level above web/), so future services can locate
# modules/, netbox/, monitoring/ without hardcoding relative ".." paths
# all over the codebase.
REPO_ROOT = BASE_DIR.parent


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# --- DEBUG -------------------------------------------------------------
DEBUG = _env_bool("DJANGO_DEBUG", default=False)

# --- SECRET_KEY ----------------------------------------------------------
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    if DEBUG:
        # Obviously-fake, Django's own "insecure" convention. Never used
        # when DEBUG=False.
        SECRET_KEY = "django-insecure-phase3-dev-only-do-not-use-in-production"
    else:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY environment variable must be set when "
            "DJANGO_DEBUG is not enabled."
        )

# --- ALLOWED_HOSTS -------------------------------------------------------
_allowed_hosts_env = os.environ.get("DJANGO_ALLOWED_HOSTS", "")
if _allowed_hosts_env.strip():
    ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_env.split(",") if h.strip()]
elif DEBUG:
    ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
else:
    ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # V2 Phase 1: authentication + website MFA + route permission enforcement + request audit (core/middleware.py).
    "core.middleware.NmasAccessMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.theme_context",
                "core.context_processors.maintenance_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# Database
# SQLite is sufficient for the Phase 3 UI shell: no NSOT/monitoring/network
# state is stored here. Django's own contrib apps (auth/sessions/admin) are
# the only tables that exist; theme selection deliberately uses a cookie,
# not a model (see docs/DJANGO_UI_FOUNDATION.md).
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, theme artwork)
STATIC_URL = "static/"
# V2 Phase 1: the Apache deployment collects into a path outside the home directory (DJANGO_STATIC_ROOT).
STATIC_ROOT = Path(os.environ.get("DJANGO_STATIC_ROOT", "").strip() or BASE_DIR / "staticfiles")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Theme framework -------------------------------------------------------
# Cookie used to persist the user's chosen top-level theme across requests.
# Deliberately a plain cookie (not a DB-backed user profile field): no
# authentication/account system exists yet in Phase 3, and the theme has no
# bearing on any security or data decision. See core/theme_registry.py and
# docs/DJANGO_UI_FOUNDATION.md.
THEME_COOKIE_NAME = "nmas_theme"
THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year

# --- Existing read-only topology service ---------------------------------
# The browser never receives or chooses this upstream URL.  Django's
# same-origin GET-only adapter in core.services.topology_service is the sole
# consumer.  The upstream service already maintains its own 10-second cache,
# so Django deliberately adds no second cache layer.
TOPOLOGY_SERVICE_URL = os.environ.get(
    "TOPOLOGY_SERVICE_URL", "http://127.0.0.1:8050/api/topology"
).strip()
try:
    TOPOLOGY_SERVICE_TIMEOUT_SECONDS = float(
        os.environ.get("TOPOLOGY_SERVICE_TIMEOUT_SECONDS", "2.5")
    )
except ValueError as exc:
    raise ImproperlyConfigured(
        "TOPOLOGY_SERVICE_TIMEOUT_SECONDS must be a number."
    ) from exc
if not 0.1 <= TOPOLOGY_SERVICE_TIMEOUT_SECONDS <= 10:
    raise ImproperlyConfigured(
        "TOPOLOGY_SERVICE_TIMEOUT_SECONDS must be between 0.1 and 10 seconds."
    )

# --- Existing read-only Grafana service ---------------------------------
# One credential-free base URL is used for both the server-side health check
# and browser-facing dashboard links in the current localhost deployment.
# Grafana remains authenticated and anonymous access remains disabled. The
# project Compose configuration allows framing, but Django also probes the
# running dashboard response and refuses to render an iframe when X-Frame-
# Options or CSP prohibits it. This flag is an operator kill switch, not a
# substitute for that runtime capability check. Credentials are never accepted
# here or sent to the browser.
GRAFANA_BASE_URL = os.environ.get(
    "GRAFANA_BASE_URL", "http://127.0.0.1:3000"
).strip()
GRAFANA_EMBED_ENABLED = _env_bool("GRAFANA_EMBED_ENABLED", default=True)
try:
    GRAFANA_HEALTH_TIMEOUT_SECONDS = float(
        os.environ.get("GRAFANA_HEALTH_TIMEOUT_SECONDS", "2.5")
    )
except ValueError as exc:
    raise ImproperlyConfigured(
        "GRAFANA_HEALTH_TIMEOUT_SECONDS must be a number."
    ) from exc
if not 0.1 <= GRAFANA_HEALTH_TIMEOUT_SECONDS <= 10:
    raise ImproperlyConfigured(
        "GRAFANA_HEALTH_TIMEOUT_SECONDS must be between 0.1 and 10 seconds."
    )

# --- Existing read-only NSOT aggregation (Phase 7) ------------------------
# NetBox connection details are resolved by modules.netbox_ipam.load_config()
# itself (real process env vars, falling back to the gitignored netbox/.env)
# -- Django adds no separate NETBOX_* setting and never receives a token.
# These three settings only bound how core.services.nsot_service behaves:
# a short process-local read cache TTL, a bounded read-only live-device SSH
# timeout (cEOS "show running-config" only, never a config-mode command),
# and a bounded `git` subprocess timeout for repository metadata reads.
def _bounded_seconds(env_name, default, low, high):
    try:
        value = float(os.environ.get(env_name, default))
    except ValueError as exc:
        raise ImproperlyConfigured(f"{env_name} must be a number.") from exc
    if not low <= value <= high:
        raise ImproperlyConfigured(f"{env_name} must be between {low} and {high} seconds.")
    return value


NSOT_CACHE_TTL_SECONDS = _bounded_seconds("NSOT_CACHE_TTL_SECONDS", "30", 1, 300)
NSOT_LIVE_READ_TIMEOUT_SECONDS = _bounded_seconds("NSOT_LIVE_READ_TIMEOUT_SECONDS", "8", 1, 30)
NSOT_GIT_TIMEOUT_SECONDS = _bounded_seconds("NSOT_GIT_TIMEOUT_SECONDS", "5", 1, 30)

# Phase 15 Deep Health: bounded per-connection / per-command timeout for the explicit, read-only live queries
# (fixed server-owned "show ..." / "ip -j ..." allowlists only; see core/services/health/live.py).
HEALTH_LIVE_TIMEOUT_SECONDS = _bounded_seconds("HEALTH_LIVE_TIMEOUT_SECONDS", "8", 1, 30)

# Phase 17 structured execution: bounded tunables (see core/services/execution/codes.py).  The precheck must be recent
# enough that its device evidence still describes the devices; the lease bounds how long a crashed run can hold locks;
# settling is the bounded poll applied to convergence-sensitive postchecks (never an unbounded sleep).
EXECUTION_PRECHECK_MAX_AGE_SECONDS = _bounded_seconds("EXECUTION_PRECHECK_MAX_AGE_SECONDS", "900", 60, 86400)
EXECUTION_LEASE_SECONDS = _bounded_seconds("EXECUTION_LEASE_SECONDS", "1800", 60, 7200)
EXECUTION_SETTLE_TIMEOUT_SECONDS = _bounded_seconds("EXECUTION_SETTLE_TIMEOUT_SECONDS", "30", 0, 300)
EXECUTION_SETTLE_INTERVAL_SECONDS = _bounded_seconds("EXECUTION_SETTLE_INTERVAL_SECONDS", "3", 0.5, 30)
EXECUTION_DEVICE_TIMEOUT_SECONDS = _bounded_seconds("EXECUTION_DEVICE_TIMEOUT_SECONDS", "20", 1, 120)

# Phase 18 Raw Configlet verification sandbox (see core/services/raw_configlets/sandbox.py).  EVERY value here is server-owned:
# the image names are fixed local images (never taken from a request), the privileged cEOS backend is OFF unless an operator with
# server access opts in, and the timeouts bound every sandbox call.  Resource limits (memory / CPU / PIDs) are code constants.
RAW_VERIFIER_FRR_IMAGE = os.environ.get("RAW_VERIFIER_FRR_IMAGE", "clab-raw-verifier-frr:8.4.4-1.1ubuntu6.7")
RAW_VERIFIER_CEOS_IMAGE = os.environ.get("RAW_VERIFIER_CEOS_IMAGE", "ceos:4.36.2F")

# V2 Phase 5B: the traffic runner's Unix socket (deploy/systemd/nmas-traffic-runner.socket).  The website only CONNECTS to it; it
# starts no process and needs no privilege for a traffic test.
NMAS_TRAFFIC_RUNNER_SOCKET = os.environ.get("NMAS_TRAFFIC_RUNNER_SOCKET", "").strip() or "/run/nmas-traffic-runner/runner.sock"
# cEOS runs systemd as PID 1 and can only start with --privileged (exactly as containerlab starts it).  Untrusted-ish operator
# config in a privileged container is reduced isolation, so this backend is disabled unless explicitly enabled.
RAW_VERIFIER_ALLOW_PRIVILEGED = _env_bool("RAW_VERIFIER_ALLOW_PRIVILEGED", False)
RAW_VERIFIER_TIMEOUT_SECONDS = _bounded_seconds("RAW_VERIFIER_TIMEOUT_SECONDS", "30", 5, 120)
RAW_VERIFIER_CEOS_BOOT_TIMEOUT_SECONDS = _bounded_seconds("RAW_VERIFIER_CEOS_BOOT_TIMEOUT_SECONDS", "150", 30, 300)
RAW_VERIFIER_CLEANUP_TIMEOUT_SECONDS = _bounded_seconds("RAW_VERIFIER_CLEANUP_TIMEOUT_SECONDS", "30", 5, 120)
RAW_VERIFIER_LEASE_SECONDS = _bounded_seconds("RAW_VERIFIER_LEASE_SECONDS", "600", 60, 3600)

# Phase 20 probation soak (see core/services/soak/policy.py and docs/PROBATION_SOAK_AND_PROMOTION.md).  EVERY value is server-owned: a
# request can never supply, shorten or override any of them, and a run PINS the values it started under (they are copied into the run row,
# so changing a setting later never shortens or extends a soak that already started).
#
# The production observation duration is 7 x 24 h of ELAPSED time (168 hours, timezone-aware UTC arithmetic -- never "seven calendar
# dates", and unaffected by daylight-saving).  The environment can only RAISE it: the lower bound below is exactly seven days, so an
# operator cannot shorten a real soak with an environment variable.  Automated tests use ``override_settings`` (which bypasses this
# loader) to run a short soak; the production code path is identical.
SOAK_PRODUCTION_DURATION_SECONDS = 7 * 24 * 60 * 60
PROBATION_SOAK_DURATION_SECONDS = _bounded_seconds(
    "PROBATION_SOAK_DURATION_SECONDS", str(SOAK_PRODUCTION_DURATION_SECONDS), SOAK_PRODUCTION_DURATION_SECONDS, 30 * 24 * 60 * 60
)
# One sample per interval.  Default 900 s == ``recent_event_window_seconds`` of monitoring/config/topology.yml: the topology service counts
# critical syslog / SNMP-trap events inside that window, so consecutive samples tile the timeline and no critical event can fall between two
# of them (a contract test keeps the two values equal).
PROBATION_SOAK_SAMPLE_INTERVAL_SECONDS = _bounded_seconds("PROBATION_SOAK_SAMPLE_INTERVAL_SECONDS", "900", 60, 3600)
# The longest stretch of the window that may go unobserved (no usable sample): 8 intervals.  A scheduler outage longer than this makes the
# soak INCOMPLETE; the collector never fabricates a sample for downtime.
PROBATION_SOAK_MAX_GAP_SECONDS = _bounded_seconds("PROBATION_SOAK_MAX_GAP_SECONDS", "7200", 120, 86400)
# The share of the window's sample intervals that must be covered by a usable sample.
PROBATION_SOAK_MIN_COVERAGE_PERCENT = _bounded_seconds("PROBATION_SOAK_MIN_COVERAGE_PERCENT", "90", 50, 100)
# How long a technically PASSED soak stays eligible for the operator's Golden decision (the collector no longer samples a completed run).
PROBATION_SOAK_DECISION_MAX_AGE_SECONDS = _bounded_seconds("PROBATION_SOAK_DECISION_MAX_AGE_SECONDS", str(3 * 24 * 60 * 60), 3600, 30 * 24 * 60 * 60)

# V2 Phase 5C: a soak pins the configuration digest of every device it observes when it starts, and refuses to start when one cannot be
# read (a soak without a baseline cannot prove what entered probation).  This is ON in every real environment; only the automated test
# environment turns it off (``core.tests.runner``), where no device exists to read.
PROBATION_SOAK_REQUIRE_BASELINE_DIGEST = True

# One-time LEGACY BASELINE BOOTSTRAP (see core/services/bootstrap/policy.py and docs/LEGACY_BASELINE_BOOTSTRAP.md).  This is a SEPARATE policy: it never
# touches the seven-day production soak above.  The operator approved ONE exception -- observe the pre-automation network for 30 REAL minutes before
# adopting it as the initial Golden -- so the duration is server-owned and the environment can only RAISE it (lower bound = 30 minutes, exactly like the
# production soak's lower bound); a request can supply none of it.  Automated tests use ``override_settings`` for a short window.  After the initial Golden
# exists the bootstrap start path refuses forever (persisted state), whatever these values are.
LEGACY_BOOTSTRAP_MIN_DURATION_SECONDS = 30 * 60
LEGACY_BOOTSTRAP_DURATION_SECONDS = _bounded_seconds("LEGACY_BOOTSTRAP_DURATION_SECONDS", "1800", LEGACY_BOOTSTRAP_MIN_DURATION_SECONDS, 2 * 60 * 60)
LEGACY_BOOTSTRAP_SAMPLE_INTERVAL_SECONDS = _bounded_seconds("LEGACY_BOOTSTRAP_SAMPLE_INTERVAL_SECONDS", "300", 60, 600)
LEGACY_BOOTSTRAP_MAX_GAP_SECONDS = _bounded_seconds("LEGACY_BOOTSTRAP_MAX_GAP_SECONDS", "600", 120, 1800)
LEGACY_BOOTSTRAP_MIN_COVERAGE_PERCENT = _bounded_seconds("LEGACY_BOOTSTRAP_MIN_COVERAGE_PERCENT", "80", 50, 100)
LEGACY_BOOTSTRAP_DECISION_MAX_AGE_SECONDS = _bounded_seconds("LEGACY_BOOTSTRAP_DECISION_MAX_AGE_SECONDS", "3600", 300, 24 * 60 * 60)
# How old a captured baseline may be when its observation starts (an older capture would leave an unobserved stretch between capture and start).
LEGACY_BOOTSTRAP_CANDIDATE_MAX_AGE_SECONDS = _bounded_seconds("LEGACY_BOOTSTRAP_CANDIDATE_MAX_AGE_SECONDS", "3600", 300, 24 * 60 * 60)

# CSRF stays enabled project-wide (default CsrfViewMiddleware above is not
# removed). No credentials of any kind (NetBox/Grafana/device) are ever
# placed in settings that reach templates/JS.

# --- V2 Phase 1: website authentication, sessions, MFA and reverse proxy ---------------------------------------
# Django's own auth (users, PBKDF2 password hashing, DB sessions) -- see docs/V2_PHASE1_IDENTITY_SECURITY_AUDIT.md.
# Every value that differs per deployment comes from the protected runtime environment file (outside Git); nothing
# secret has a default here.
LOGIN_URL = "core:login"
LOGIN_REDIRECT_URL = "core:home"
LOGOUT_REDIRECT_URL = "core:login"

SESSION_COOKIE_NAME = "nmas_sessionid"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = int(_bounded_seconds("NMAS_SESSION_AGE_SECONDS", "28800", 900, 7 * 24 * 60 * 60))
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_HTTPONLY = False  # the theme / form templates read no CSRF cookie from JS; kept default-compatible
CSRF_COOKIE_SAMESITE = "Lax"
# Secure-only cookies when every browser path is HTTPS (Cloudflare).  The local recovery path is plain HTTP on
# loopback, so this is an explicit deployment decision, not a default.
SESSION_COOKIE_SECURE = _env_bool("DJANGO_SESSION_COOKIE_SECURE", default=False)
CSRF_COOKIE_SECURE = _env_bool("DJANGO_CSRF_COOKIE_SECURE", default=SESSION_COOKIE_SECURE)
CSRF_TRUSTED_ORIGINS = [o.strip() for o in os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()]

# Reverse proxy (Apache -> Gunicorn).  Apache OVERWRITES X-Forwarded-Proto per virtual host (http on the local
# vhost, https on the tunnel-only vhost), so trusting it is safe only behind that proxy -- hence opt-in.
if _env_bool("DJANGO_BEHIND_TRUSTED_PROXY", default=False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
NMAS_TRUSTED_PROXY_IPS = tuple(
    ip.strip() for ip in os.environ.get("NMAS_TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if ip.strip()
)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"  # NMAS pages are never framed; NMAS framing Grafana is governed by Grafana's own headers.

# Website MFA (Microsoft Authenticator TOTP) -- separate from all network-device MFA.  Required by default; the
# only way to turn it off is an explicit environment decision (it is never disabled by a missing library).
NMAS_APP_MFA_REQUIRED = _env_bool("NMAS_APP_MFA_REQUIRED", default=True)
NMAS_APP_MFA_KEY = os.environ.get("NMAS_APP_MFA_KEY", "").strip()

# Login throttling, counted from the durable audit ledger (works across Gunicorn workers).
NMAS_LOGIN_FAILURE_LIMIT = int(_bounded_seconds("NMAS_LOGIN_FAILURE_LIMIT", "5", 3, 50))
NMAS_LOGIN_FAILURE_WINDOW_SECONDS = int(_bounded_seconds("NMAS_LOGIN_FAILURE_WINDOW_SECONDS", "900", 60, 86400))

# Test runner: legacy view tests run as an authenticated, fully authorised, MFA-verified operator; the access
# boundary itself is proven by tests that use an explicit anonymous / limited client (core/tests/runner.py).
TEST_RUNNER = "core.tests.runner.NmasTestRunner"


# --- Configuration Validation (GitHub Actions) ---------------------------------------------------------------------------
# A Change that passes Tier-2 validation is sent, as a sanitized hash-bound bundle, to the GitHub Actions workflow
# "Configuration Validation" (repository_dispatch), and may be executed only after that run passed for exactly that
# candidate.  The token comes from the protected runtime environment file only (never Git, never a model, never a log):
# a fine-grained token for this one repository with Contents read/write (repository_dispatch) and Actions read.
# ON in every real environment; only the automated test environment turns it off (``core.tests.runner``).
NMAS_CONFIGURATION_VALIDATION_ENABLED = True
NMAS_GITHUB_REPOSITORY = os.environ.get("NMAS_GITHUB_REPOSITORY", "").strip() or "Dhruv-Suvarna/Adv-Netman"
NMAS_GITHUB_API_URL = "https://api.github.com"
NMAS_GITHUB_TOKEN_ENV = "NMAS_GITHUB_TOKEN"
