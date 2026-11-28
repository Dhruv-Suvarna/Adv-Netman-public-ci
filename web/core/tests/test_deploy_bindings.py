"""Deployment bindings and observation-source key hygiene (DB01-DB10): fail closed, never print or store a key."""

from __future__ import annotations

import importlib
import os
import secrets
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from core import checks
from core.services.devices import observations
from core.services.troubleshooting import deployment
from core.services.troubleshooting.adapters import nmas_providers

GOOD = secrets.token_hex(32)
SRC = {"nmas-observer-v1": {"key_env": "NMAS_OBSERVATION_KEY", "platforms": ["arista_ceos", "ubuntu_frr"]}}


def ids(messages):
    return sorted(m.id for m in messages)


class SettingsBindingTests(SimpleTestCase):
    def reload_settings_module(self, **env):
        """Evaluate config/settings.py under a controlled environment (no Django reconfiguration)."""
        import config.settings as module
        with mock.patch.dict(os.environ, {k: v for k, v in env.items()}, clear=False):
            for name in ("NMAS_TS_BINDING", "NMAS_OBSERVATION_SOURCE_ID"):
                if name not in env:
                    os.environ.pop(name, None)
            return importlib.reload(module)

    def tearDown(self):
        import config.settings as module
        importlib.reload(module)

    # DB01
    def test_settings_default_is_fail_closed(self):
        module = self.reload_settings_module()
        self.assertEqual((module.NMAS_TS_DEPLOYMENT, module.NMAS_OBSERVATION_SOURCES), ({}, {}))
        self.assertEqual(module.NMAS_TS_RUNTIME_FACTORY, deployment.FACTORY_PATH)
        self.assertEqual(module.TROUBLESHOOTING_RUNTIME_DEPS, deployment.FACTORY_PATH)

    # DB02
    def test_explicit_binding_equals_the_recommended_binding(self):
        module = self.reload_settings_module(NMAS_TS_BINDING="nmas-v1")
        self.assertEqual(module.NMAS_TS_DEPLOYMENT, nmas_providers.RECOMMENDED_BINDING)
        self.assertEqual(self.reload_settings_module(NMAS_TS_BINDING="true").NMAS_TS_DEPLOYMENT, {})

    # DB03
    def test_source_registration_names_only_the_key_variable(self):
        module = self.reload_settings_module(NMAS_OBSERVATION_SOURCE_ID="nmas-observer-v1", NMAS_OBSERVATION_KEY=GOOD)
        self.assertEqual(module.NMAS_OBSERVATION_SOURCES, SRC)
        self.assertNotIn(GOOD, repr({k: getattr(module, k) for k in dir(module) if k.isupper()}))


class TrustedSourceTests(SimpleTestCase):
    def sources(self, entry=None, key=GOOD, secret="django-secret"):
        with override_settings(NMAS_OBSERVATION_SOURCES={"nmas-observer-v1": entry or SRC["nmas-observer-v1"]}, SECRET_KEY=secret), \
                mock.patch.dict(os.environ, {"NMAS_OBSERVATION_KEY": key, "NMAS_OBSERVATION_KEY_B": key, "NETBOX_TOKEN": key}):
            return observations.trusted_sources()

    # DB04
    def test_strong_dedicated_key_is_trusted(self):
        found = self.sources()
        self.assertEqual(found["nmas-observer-v1"]["key"], GOOD.encode())

    # DB05
    def test_weak_short_reused_or_misplaced_keys_are_untrusted(self):
        self.assertEqual(self.sources(key="k" * 40), {})                                  # too few distinct characters
        self.assertEqual(self.sources(key=GOOD[:31]), {})                                 # too short
        self.assertEqual(self.sources(key=GOOD, secret=GOOD), {})                          # reuses SECRET_KEY
        self.assertEqual(self.sources(entry={"key_env": "NETBOX_TOKEN", "platforms": []}), {})   # another service secret
        self.assertEqual(self.sources(entry={"key_env": "NMAS_OBSERVATION_KEY", "key": GOOD}), {})  # literal key in settings
        self.assertIn("nmas-observer-v1", self.sources(entry={"key_env": "NMAS_OBSERVATION_KEY_B", "platforms": []}))


    # DB10
    def test_every_generated_hex_key_is_accepted_and_degenerate_keys_are_not(self):
        fifteen = ("0123456789abcde" * 3)[:40]                     # a token_hex key that happens to miss one hex digit
        self.assertEqual(len(set(fifteen)), 15)
        self.assertIn("nmas-observer-v1", self.sources(key=fifteen))
        self.assertEqual(self.sources(key="ab" * 20), {})
        self.assertEqual(self.sources(key=("012345678" * 5)[:40]), {})   # 9 distinct characters
        self.assertTrue(all(observations.key_is_strong(secrets.token_hex(32)) for _ in range(2000)))
        self.assertFalse(observations.key_is_strong(""))


class CheckTests(SimpleTestCase):
    # DB06
    def test_current_settings_pass(self):
        self.assertEqual(ids(checks.troubleshooting_bindings()), [])
        self.assertEqual([m for m in checks.observation_sources() if m.id != "nmas.W013"], [])

    # DB07
    def test_binding_errors(self):
        with override_settings(NMAS_TS_BINDING="yes"):
            self.assertEqual(ids(checks.troubleshooting_bindings()), ["nmas.E001"])
        with override_settings(NMAS_TS_BINDING="nmas-v1", NMAS_TS_DEPLOYMENT={"inventory": "x.y"}):
            self.assertEqual(ids(checks.troubleshooting_bindings()), ["nmas.E002"])
        with override_settings(TROUBLESHOOTING_RUNTIME_DEPS="other.factory"):
            self.assertEqual(ids(checks.troubleshooting_bindings()), ["nmas.E003"])

    # DB08
    def test_source_errors_never_print_the_key(self):
        bad = {"s": {"key_env": "DJANGO_SECRET_KEY", "platforms": ["cisco_iosxr"], "key": GOOD}}
        with override_settings(NMAS_OBSERVATION_SOURCES=bad):
            messages = checks.observation_sources()
        self.assertEqual(ids(messages), ["nmas.E010", "nmas.E011", "nmas.E012", "nmas.W013"])
        self.assertFalse(any(GOOD in str(m) for m in messages))
        with override_settings(NMAS_OBSERVATION_SOURCES=SRC, SECRET_KEY=GOOD), mock.patch.dict(os.environ, {"NMAS_OBSERVATION_KEY": GOOD}):
            messages = checks.observation_sources()
        self.assertEqual(ids(messages), ["nmas.E014"])
        self.assertFalse(any(GOOD in str(m) for m in messages))

    # DB09
    def test_settings_source_never_contains_key_material(self):
        text = open(settings.BASE_DIR / "config" / "settings.py", encoding="utf-8").read()
        block = text[text.index("NMAS_OBSERVATION_KEY_ENV"):]
        self.assertNotRegex(block, r"[0-9a-f]{32,}")
        self.assertNotIn('"key":', block)
