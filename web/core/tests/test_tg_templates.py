"""Lab 7 -- every CURRENT network Jinja template, systematically, through its REAL producer.

One positive and (when the template references variables) one negative case per template, generated from the
deployed-artifact inventory, so a new template is tested -- or visibly failing -- the moment it is added:

    TPL:<path>:RENDER:POSITIVE           rendered by the code that renders it in production (Lab-1 device configs:
                                         modules.eos_render.render with the tracked inventory; monitoring templates:
                                         modules.snmp / syslog / gnmi render; DHCP: the NMAS / R2 DHCP renders; feature
                                         templates: the platform drivers rendering every SUPPORTED capability cell);
                                         the output equals its tracked golden digest and is identical on a re-render
    TPL:<path>:STRICT_UNDEFINED:NEGATIVE every referenced variable, removed in turn, makes the same producer fail
                                         closed with UndefinedError (a deliberately optional variable must instead fail
                                         when its structure is malformed); nothing renders silently empty

No device, NetBox or network access: contexts are the tracked inventory plus fixed fake values (never credentials).
Golden digests: web/core/tests/fixtures/test_governance/template_golden.json (regenerate deliberately with
NMAS_TG_UPDATE_GOLDEN=1 after reviewing a rendering change).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from functools import lru_cache
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase
from jinja2.exceptions import UndefinedError

from core.services import feature_template_renderer, platform_drivers
from core.services.capabilities import features as capability_features, probe_cases
from core.services.test_governance import cells as cells_module, inventory
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.services.test_governance.constants import REPO_ROOT, ArtifactType, Scope

if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from modules import eos_render, gnmi, snmp, syslog  # noqa: E402

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "test_governance" / "template_golden.json"
FAKE_SECRET = "fake-not-a-credential"
R2_DHCP = {
    "ipv4_subnets": [{"vlan": 10, "server": "secondary", "prefix": "192.168.10.0/24", "start": "192.168.10.200", "end": "192.168.10.220",
                      "gateway": "192.168.10.1"}],
    "ipv6_subnets": [{"vlan": 10, "server": "secondary", "prefix": "2001:db8:10::/64", "start": "2001:db8:10::2000", "end": "2001:db8:10::20ff",
                      "gateway": None}],
}
NMAS_DHCP = {
    "management": {"v4_network": "192.168.200.0", "v4_netmask": "255.255.255.0", "v6_prefix": "2001:db8:200::/64"},
    "ipv4_subnets": [{"vlan": 10, "network": "192.168.10.0", "netmask": "255.255.255.0", "start": "192.168.10.100",
                      "end": "192.168.10.179", "gateway": "192.168.10.1"}],
    "ipv6_subnets": [{"vlan": 10, "prefix": "2001:db8:10::/64", "start": "2001:db8:10::1000", "end": "2001:db8:10::1fff"}],
}


class Render:
    """One call of a real producer: enough to replay it with a modified context."""

    def __init__(self, path: str, kind: str, name: str, context: dict):
        self.path, self.kind, self.name, self.context = path, kind, name, context

    def replay(self, context: dict | None = None) -> str:
        ctx = self.context if context is None else context
        if self.kind == "eos":
            return eos_render.render(self.name, ctx)
        if self.kind in ("snmp", "syslog", "gnmi"):
            return {"snmp": snmp.render, "syslog": syslog.render, "gnmi": gnmi.render}[self.kind](self.name, ctx)
        rows = feature_template_renderer.render_descriptors(template_name=self.name, fields=ctx["fields"], flags=ctx["flags"])
        return json.dumps(rows, sort_keys=True)

    def without(self, variable: str) -> dict:
        ctx = json.loads(json.dumps(self.context, default=str))
        if self.kind == "feature":
            ctx["fields"].pop(variable, None)
            ctx["flags"].pop(variable, None)
        else:
            ctx.pop(variable, None)
        return ctx

    def malformed(self, variable: str) -> dict:
        ctx = json.loads(json.dumps(self.context, default=str))
        target = ctx["flags"] if self.kind == "feature" and variable in ctx["flags"] else ctx["fields"] if self.kind == "feature" else ctx
        target[variable] = {}
        return ctx


@lru_cache(maxsize=1)
def produced() -> dict[str, list[Render]]:
    """Run every real producer once (offline) and record each template render."""
    out: dict[str, list[Render]] = {}

    def keep(render: Render) -> None:
        out.setdefault(render.path, []).append(render)

    inv = yaml.safe_load((REPO_ROOT / "inventory.yml").read_text())
    for node, meta in sorted(inv["network_devices"].items()):        # master.py _build_eos_config / push_linux_router
        context = {"management": inv["management"], "node": node, **({"dhcp": R2_DHCP} if node == "R2" else {})}
        keep(Render(f"templates/{meta['template']}", "eos", f"templates/{meta['template']}", context))
    keep(Render("templates/R2_dhcp_server.cfg.j2", "eos", "templates/R2_dhcp_server.cfg.j2", {"dhcp": R2_DHCP}))   # render_r2_dhcp.py
    for name in ("dhcp/dhcpd.conf.j2", "dhcp/dhcpd6.conf.j2"):                                                     # master.py setup_nmas
        keep(Render(name, "eos", name, {"management": inv["management"], "dhcp": NMAS_DHCP}))
    snmp_ctx = {"username": "nmas-snmp", "auth_password": FAKE_SECRET, "privacy_password": FAKE_SECRET, "receiver": "192.168.200.100"}
    keep(Render("templates/monitoring/snmpd.conf.j2", "snmp", "snmpd.conf.j2", {**snmp_ctx, "device": "R3", "address": "192.168.200.3"}))
    keep(Render("templates/monitoring/ceos_snmp.j2", "snmp", "ceos_snmp.j2", {**snmp_ctx, "source_interface": "Vlan200"}))
    policy = syslog.policy()
    keep(Render("templates/monitoring/ceos_syslog.j2", "syslog", "ceos_syslog.j2", {"receiver": policy["receiver"], "source_interface": "Vlan200"}))
    keep(Render("templates/monitoring/linux_syslog.conf.j2", "syslog", "linux_syslog.conf.j2", dict(policy)))
    keep(Render("templates/monitoring/ceos_gnmi_security.j2", "gnmi", "ceos_gnmi_security.j2",
                {"ssl_profile": gnmi.SSL_PROFILE, "username": "nmas-telemetry", "password": FAKE_SECRET}))
    keep(Render("templates/monitoring/ceos_gnmi_enable.j2", "gnmi", "ceos_gnmi_enable.j2", {"ssl_profile": gnmi.SSL_PROFILE}))

    original = feature_template_renderer.render_descriptors

    def recording(*, template_name, fields, flags=None):
        keep(Render(f"templates/features/{template_name}", "feature", template_name,
                    {"fields": {k: dict(v) for k, v in fields.items()}, "flags": dict(flags or {})}))
        return original(template_name=template_name, fields=fields, flags=flags)

    catalogue = capability_features.by_key()
    with mock.patch.object(feature_template_renderer, "render_descriptors", side_effect=recording):
        for platform, feature_key in sorted(cells_module.supported_cells()):   # every SUPPORTED cell, as the Device Builder renders it
            sample = probe_cases.sample(platform, catalogue[feature_key])
            for sections in (sample.sections, sample.baseline):
                platform_drivers.get_driver(platform).render_candidate(
                    field_values={"device.hostname": "CAPDUT", "device.description": ""},
                    interfaces=list(sections.get("interfaces", {}).values()), routing=sections.get("routing", {}),
                    phase12={k: sections.get(k, {}) for k in ("fhrp", "nat", "services", "security", "policy")})
    return out


def current_templates():
    return [a for a in inventory.build_inventory().artifacts if a.type == ArtifactType.JINJA and a.scope == Scope.CURRENT]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class TemplateCaseTests(SimpleTestCase):
    maxDiff = None

    def _renders(self, path: str) -> list[Render]:
        renders = produced().get(path, [])
        self.assertTrue(renders, f"no real producer renders {path}: add it to the producer list or classify it as unused")
        return renders

    def _positive(self, path: str) -> None:
        renders = self._renders(path)
        golden = json.loads(GOLDEN.read_text()) if GOLDEN.is_file() else {}
        first = renders[0].replay()
        self.assertTrue(first.strip(), f"{path} rendered empty")
        self.assertNotRegex(first, r"\{\{|\{%", "unrendered Jinja syntax in the output")
        for render in renders:
            self.assertEqual(render.replay(), render.replay(), "rendering must be deterministic")
        if os.environ.get("NMAS_TG_UPDATE_GOLDEN") == "1":
            golden[path] = digest(first)
            GOLDEN.parent.mkdir(parents=True, exist_ok=True)
            GOLDEN.write_text(json.dumps(golden, sort_keys=True, indent=1) + "\n")
        self.assertEqual(golden.get(path), digest(first), f"{path}: rendered output differs from its reviewed golden digest")

    def _negative(self, path: str, variables: tuple[str, ...]) -> None:
        render = self._renders(path)[0]
        for variable in variables:
            with self.subTest(case=f"missing variable {variable}"):
                try:
                    render.replay(render.without(variable))
                except UndefinedError:
                    continue
                # a deliberately optional variable (``is defined``): malformed structure must still fail closed
                with self.assertRaises(UndefinedError, msg=f"{path}: neither a missing nor a malformed {variable!r} fails closed"):
                    render.replay(render.malformed(variable))


def _slug(path: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")


def _add_cases() -> None:
    for artifact in current_templates():
        path, variables = artifact.path, artifact.variables

        def positive(self, path=path):
            self._positive(path)

        positive = case(f"TPL:{path}:RENDER:POSITIVE", target=path, polarity=POSITIVE,
                        condition="valid intent rendered through the template's real producer",
                        expected="non-empty, fully rendered, deterministic output equal to the reviewed golden digest",
                        platform="", feature="")(positive)
        setattr(TemplateCaseTests, f"test_renders_{_slug(path)}", positive)
        if variables:
            def negative(self, path=path, variables=variables):
                self._negative(path, variables)

            negative = case(f"TPL:{path}:STRICT_UNDEFINED:NEGATIVE", target=path, polarity=NEGATIVE,
                            condition=f"each referenced variable ({', '.join(variables)}) missing in turn",
                            expected="UndefinedError from the real producer (StrictUndefined); no silently empty configuration")(negative)
            setattr(TemplateCaseTests, f"test_missing_variable_fails_{_slug(path)}", negative)


_add_cases()


class TemplateSuiteContractTests(SimpleTestCase):
    def test_every_current_template_has_generated_cases_and_a_golden_digest(self):
        golden = json.loads(GOLDEN.read_text())
        for artifact in current_templates():
            with self.subTest(template=artifact.path):
                self.assertTrue(hasattr(TemplateCaseTests, f"test_renders_{_slug(artifact.path)}"))
                self.assertIn(artifact.path, golden)

    def test_unused_and_unsupported_templates_are_not_rendered_as_current(self):
        rendered = set(produced())
        for artifact in inventory.build_inventory().artifacts:
            if artifact.type == ArtifactType.JINJA and artifact.scope == Scope.NOT_CURRENT_SCOPE:
                with self.subTest(template=artifact.path):
                    self.assertNotIn(artifact.path, rendered)

    def test_no_fake_value_resembles_a_real_credential(self):
        for renders in produced().values():
            for render in renders:
                text = json.dumps(render.context, default=str)
                self.assertNotRegex(text, r"(?i)runtime://|BEGIN [A-Z ]*PRIVATE KEY")
