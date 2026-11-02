"""Fixtures for the Phase-18 Raw Configlet tests.  A simulated sandbox and network only: no Docker, no device, NetBox, Slack or socket.

* ``ScriptedCeos`` / ``ScriptedFrr``  shared verifier fakes.  They SUBCLASS the real adapters and override only ``verify`` (the one
                                      method that starts a sandbox), so their identity (adapter id / version / backend) is the real
                                      one and Change-input currency is exercised faithfully.
* ``context``                         a ``VerificationContext`` wired to the fakes.
* ``raw_change`` / ``verified``       a Change with Raw Configlets, optionally already verified.
* ``RecordingWorld``                  a Phase-17 ``FakeWorld`` whose executors record exactly which statements were sent for a RAW Configlet.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

from core import models
from core.services import raw_configlet_service as rcs
from core.services.raw_configlets import adapters, codes, sandbox
from core.services.raw_configlets.codes import finding
from core.tests.helpers import execution as ex
from core.tests.helpers.validation import Dev, new_change, simple_pass_change

EOS_TEXT = "interface Loopback99\n   description synthetic raw configlet\n   ip address 192.0.2.99/32\n"
EOS_TEXT_2 = "interface Loopback98\n   ip address 192.0.2.98/32\n"
FRR_TEXT = "router ospf\n ospf router-id 192.0.2.1\n network 192.0.2.0/24 area 0\n"


class _Scripted:
    """Mixin: ``verify`` never starts anything; it returns the scripted findings and records the call."""

    def scripted(self, *codes_, started=True):
        self.script, self.started, self.calls = list(codes_), started, []
        return self

    def verify(self, normalized, *, config, runner, clock, sleep):
        self.calls.append(normalized)
        out = adapters.AdapterOutcome(started=self.started)
        out.sandbox = {"backend": self.backend(config), "container": "clab-rawverify-fake-000000000000", "cleanup": "OK", "network": "none"}
        out.evidence = {"output": ["scripted"]}
        for item in self.script:
            code, kwargs = (item, {}) if isinstance(item, str) else item
            out.findings.append(finding(code, **kwargs))
        return out


class ScriptedCeos(_Scripted, adapters.CeosConfigSession):
    pass


class ScriptedFrr(_Scripted, adapters.FrrVtyshDryRun):
    pass


ACCEPT = ("SYNTAX_ACCEPTED", "SEMANTICS_NOT_VERIFIED")
REJECT = ("SYNTAX_REJECTED",)


def fakes(*script, frr_script=ACCEPT):
    """-> (registry, ceos, frr) with the CEOS fake scripted with ``script`` (default: accept)."""
    ceos, frr = ScriptedCeos().scripted(*(script or ACCEPT)), ScriptedFrr().scripted(*frr_script)
    return {ceos.adapter_id: ceos, frr.adapter_id: frr}, ceos, frr


def context(registry=None, *, allow_privileged=True):
    """The REAL server-owned sandbox configuration (so a stored run's backend identity matches what currency computes); only the
    privilege opt-in and the timeouts are overridden.  Nothing is started: the adapters are the scripted fakes."""
    registry = registry if registry is not None else fakes()[0]
    config = dataclasses.replace(sandbox.load_config(), allow_privileged=allow_privileged, timeout=5.0, boot_timeout=5.0, cleanup_timeout=5.0)
    return rcs.VerificationContext(actor="tester", adapters=registry, config=config, runner=None)


def raw_change(*, text=EOS_TEXT, device="R1", priority=6, name="Loopback", dependencies=(), assertions=(), frr_device=False):
    """A simple PASS Change (R1/R2 cEOS) plus one Raw Configlet.  -> namespace(change, f, raw, revision, sources)"""
    f = simple_pass_change()
    if frr_device:
        Dev(f.change, "R3", platform=models.Platform.UBUNTU_FRR)
    raw, revision = rcs.create_raw_configlet(
        f.change, target_device=device, name=name, content=text, priority=priority, dependencies=list(dependencies),
        assertions=list(assertions), actor="tester",
    )
    return SimpleNamespace(change=f.change, f=f, raw=raw, revision=revision, sources=f.sources)


def verify(revision, *script, registry=None, reuse=True):
    """Explicitly verify ``revision`` with the scripted fakes.  -> the run."""
    ctx = context(registry if registry is not None else fakes(*script)[0])
    response = rcs.request_verification(revision, actor="tester", context=ctx, reuse=reuse)
    assert response.run is not None, response.refused
    return response.run


def verified(**kwargs):
    """A raw_change whose Raw Configlet already has a CURRENT PASS verification."""
    p = raw_change(**kwargs)
    p.run = verify(p.revision)
    return p


class RecordingExecutor(ex.FakeExecutor):
    """The Phase-17 fake executor, additionally recording the statements a RAW Configlet was sent with (and simulating its effect)."""

    def apply(self, spec, assessment):
        if spec.origin == "RAW":
            self.world.sent[spec.cfg_id] = tuple(spec.lines)
            self.world.raw_pins[spec.cfg_id] = dict(spec.raw or {})
            effect = self.world.raw_effect
            if effect is not None:
                effect(self.world, spec)
        return super().apply(spec, assessment)


class RecordingWorld(ex.FakeWorld):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sent: dict = {}
        self.raw_pins: dict = {}
        self.raw_effect = None   # callable(world, spec) simulating what the raw statements do on the device

    def factory(self, device):
        return RecordingExecutor(self, device["name"])


def raw_cfg(plan):
    return plan.configlets.get(origin=models.ConfigletOrigin.RAW)
