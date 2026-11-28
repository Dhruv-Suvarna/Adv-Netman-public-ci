"""Deployment system checks for the troubleshooting bindings and the observation source (``manage.py check``).

Messages name settings and environment variables only -- never a value -- so the output is safe to paste into a change record.
"""

from __future__ import annotations

import os
import re

from django.conf import settings
from django.core import checks

KEY_ENV = re.compile(r"^NMAS_OBSERVATION_KEY(?:_[A-Z0-9]{1,32})?$")
SOURCE_FIELDS = {"key_env", "platforms"}
OBSERVABLE_PLATFORMS = {"arista_ceos", "ubuntu_frr"}
BINDINGS = {"", "nmas-v1"}


@checks.register(checks.Tags.security, deploy=False)
def troubleshooting_bindings(app_configs=None, **kwargs):
    from core.services.troubleshooting import deployment
    from core.services.troubleshooting.adapters import nmas_providers

    errors = []
    binding = str(getattr(settings, "NMAS_TS_BINDING", "") or "")
    if binding not in BINDINGS:
        errors.append(checks.Error("NMAS_TS_BINDING has an unknown value; no admission provider is bound.",
                                   hint="Use nmas-v1 or leave it unset.", id="nmas.E001"))
    configured = getattr(settings, "NMAS_TS_DEPLOYMENT", None) or {}
    if binding == "nmas-v1" and {k: configured.get(k) for k in nmas_providers.RECOMMENDED_BINDING} != nmas_providers.RECOMMENDED_BINDING:
        errors.append(checks.Error("NMAS_TS_DEPLOYMENT differs from nmas_providers.RECOMMENDED_BINDING.", id="nmas.E002"))
    if getattr(settings, "NMAS_TS_RUNTIME_FACTORY", "") or getattr(settings, "TROUBLESHOOTING_RUNTIME_DEPS", ""):
        if deployment.consistency_problems(settings):
            errors.append(checks.Error("The two troubleshooting factory settings do not point at the shared factory.", id="nmas.E003"))
    return errors


@checks.register(checks.Tags.security, deploy=False)
def observation_sources(app_configs=None, **kwargs):
    from core.services.devices import observations   # one key rule for the check and the runtime

    errors = []
    secret = str(getattr(settings, "SECRET_KEY", "") or "")
    for source_id, entry in (getattr(settings, "NMAS_OBSERVATION_SOURCES", None) or {}).items():
        entry = entry if isinstance(entry, dict) else {}
        if set(entry) - SOURCE_FIELDS:
            errors.append(checks.Error(f"Observation source {source_id!r} carries fields other than key_env/platforms; key material must "
                                       "never be configured in settings.", id="nmas.E010"))
        key_env = str(entry.get("key_env") or "")
        if not KEY_ENV.fullmatch(key_env):
            errors.append(checks.Error(f"Observation source {source_id!r}: key_env must name a dedicated NMAS_OBSERVATION_KEY* variable.",
                                       id="nmas.E011"))
        if not set(entry.get("platforms") or ()) <= OBSERVABLE_PLATFORMS:
            errors.append(checks.Error(f"Observation source {source_id!r}: platforms must be within {sorted(OBSERVABLE_PLATFORMS)}.",
                                       id="nmas.E012"))
        value = os.environ.get(key_env, "") if KEY_ENV.fullmatch(key_env) else ""
        if not observations.key_is_strong(value):
            errors.append(checks.Warning(f"Observation source {source_id!r}: {key_env} is absent or too weak in this process; the "
                                         "source is untrusted here (device_observe refuses SOURCE_UNCONFIGURED).", id="nmas.W013"))
        elif secret and value == secret:
            errors.append(checks.Error(f"Observation source {source_id!r}: {key_env} must not reuse the Django SECRET_KEY.", id="nmas.E014"))
    return errors
