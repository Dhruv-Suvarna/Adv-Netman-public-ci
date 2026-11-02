"""Lab 7 -- the platform x feature capability matrix, cell by cell, stage by stage, positive AND negative.

Generated from the tracked capability ledger: every SUPPORTED cell gets one positive and one negative case for each
lifecycle stage its capability evidence says is implemented, so a cell that becomes SUPPORTED is tested -- or visibly
failing -- at once.  Every case drives the REAL code path the Phase-4 offline probe uses, inside a rolled-back
transaction, with fake devices only (no connection, no apply, no NetBox, no lab):

  stage         POSITIVE (valid intent)                          NEGATIVE (invalid / unsupported input fails closed)
  MODEL         Tier-1 field commit of the feature value: VALID  the invalid sample value: INVALID
  RENDER        the platform driver renders target lines, no     with the capability registry saying NOT_IMPLEMENTED the
                refusal marker, deterministic, golden digest     renderer emits a refusal marker and none of the lines
  IMPORT        the platform parser recovers the feature from    the same configuration WITHOUT the feature never imports
                the rendered configuration                       it (no phantom intent)
  VALIDATE      network-configuration validation PASS / WARNING  without IPAM / topology / inventory evidence it never passes
  EXECUTE       executor preflight on a fake device: APPLY       a Configlet with no statements is REFUSED
  COMPENSATION  preflight proves an exact compensation            the device's previous state cannot be read: preflight raises,
                (restorable) for the rendered Configlet          a restorable state is never assumed
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import unittest
from collections import Counter
from copy import deepcopy
from pathlib import Path
from unittest import mock

from django.db import transaction
from django.test import TestCase

from core.services import (
    candidate_renderer, change_service, field_commit_service, field_registry, intent_service, network_config_validation, platform_drivers,
    srlinux_model,
)
from core.services.capabilities import features as capability_features, offline_verify, probe_cases
from core.services.execution.executors import ceos, iosxe, linux, registry as executors, srlinux
from core.services.execution.executors.base import APPLY, REFUSE, ConfigletSpec, ExecutorError
from core.services.health.live import LiveError
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.services.test_governance import cells as cells_module
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.services.validation import sources

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "test_governance" / "cell_golden.json"
GARBAGE = "nmas-governance-unrecognised-statement 9"
HEAD = "0" * 40


def _feature(key: str):
    return capability_features.by_key()[key]


class CellContext:
    """One cell's offline fixture: the probe sample, its rendered lines and the differential the feature adds."""

    def __init__(self, platform: str, feature_key: str):
        self.platform, self.feature = platform, _feature(feature_key)
        self.case = probe_cases.sample(platform, self.feature)
        self.lines = offline_verify._descriptors(platform, self.case.sections)    # pylint: disable=protected-access
        self.base = offline_verify._descriptors(platform, self.case.baseline)     # pylint: disable=protected-access
        self.added = list((Counter(self.lines) - Counter(self.base)).elements())    # golden digest input (canonical order)
        # what an executor receives keeps the rendered order (as the planner's diff does): a block may repeat a line
        self.target = [s for s in offline_verify.ordered_added(self.lines, self.base)
                       if s.strip() and not s.lstrip().startswith(("!", "#"))]
        if platform == "arista_ceos":
            self.target = _with_parents(self.target, self.lines, self.base)

    def spec(self, lines) -> ConfigletSpec:
        return ConfigletSpec("CAP-GOV", 1, "CAPDUT", self.platform, self.case.object_type, "CREATE_DEFINE", tuple(lines), self.case.expected)

    def executor(self):
        executor = executors.executor_for({"name": "CAPDUT", "platform": self.platform, "container": "offline-fixture"})
        facts = DeviceEvidence("CAPDUT", self.platform, {name: FactGroup(value, "SYNTHETIC") for name, value in
                                                         (("interfaces", {}), ("addresses", {}), ("routes", []))}, live_attempted=True)
        executor._reader = lambda device: facts                                                     # no device read
        base_text = "\n".join(self.base)
        if self.platform == "arista_ceos":
            executor._conn = offline_verify._FixtureConfigSession(base_text)                        # pylint: disable=protected-access
        if self.platform == "ubuntu_frr":
            executor._config_reader = lambda _container, _timeout: base_text
            executor._daemon_reader = lambda _container, _timeout: {"zebra", *linux.frr_routing.DAEMONS.values()}
            executor._nft_reader = lambda _container, _timeout: ""
        if self.platform == "cisco_c8000v_iosxe":
            executor._conn = offline_verify._FixtureConfigSession("\n".join(["interface GigabitEthernet9", " no ip address", " shutdown", *self.base]))  # pylint: disable=protected-access
        if self.platform == "nokia_srlinux":
            executor._conn = offline_verify._FixtureGnmi(srlinux_model.tree_from_set_lines(self.base))  # pylint: disable=protected-access
        return executor

    def inverse(self, lines):
        spec, base_text = self.spec(lines), "\n".join(self.base)
        if self.platform == "arista_ceos":
            return ceos.inverse_lines(spec)
        if self.platform == "nokia_srlinux":
            return srlinux.config_inverse(spec.lines, srlinux_model.tree_from_set_lines(self.base))
        if self.platform == "cisco_c8000v_iosxe":
            return iosxe.config_inverse(list(spec.lines), iosxe.stable_config(base_text))
        if spec.object_type in linux.FRR_ROUTING_TYPES:
            return linux.frr_routing_inverse(spec.lines, base_text)
        return linux.inverse_operations(spec)


def _with_parents(target, lines, base):
    """cEOS: put every indented child statement back under the block header the renderer emitted it in.

    The differential drops a header that the baseline already holds (``interface Ethernet1`` with a new
    ``ip helper-address`` beneath it), leaving a parent-less child that no executor can apply or invert.  The header is
    recovered from the real rendering: the block whose child multiset grew relative to the baseline.
    """
    def blocks(text):
        found: dict[str, Counter] = {}
        for header, children in ceos._config_blocks(text):          # pylint: disable=protected-access
            found.setdefault(header, Counter()).update(children)
        return found
    rendered, before = blocks(lines), blocks(base)
    grown = {header: children - before.get(header, Counter()) for header, children in rendered.items()}
    out: dict[str, list[str]] = {}
    header = None
    for line in target:
        if not line.startswith(" "):
            header = line
            out.setdefault(header, [])
            continue
        owner = header if header is not None and grown.get(header, Counter())[line] > 0 else \
            next((h for h, children in grown.items() if children[line] > 0), header)
        grown.get(owner, Counter())[line] -= 1
        out.setdefault(owner, []).append(line)
    return [line for owner, children in out.items() for line in ([owner] if owner is not None else []) + children]


class CellCaseTests(TestCase):
    maxDiff = None

    def _intent(self, ctx: CellContext, sections: dict):
        change = change_service.create_change(title=f"Governance cell {ctx.platform} {ctx.feature.key}")
        intent, _ = intent_service.create_or_get_device_intent(change=change, device_name="CAPDUT", platform=ctx.platform)
        revision = intent_service.create_candidate_revision(device_intent=intent)
        field_commit_service.seed_device_identity_field_states(intent=intent, revision=revision)
        revision.sections = deepcopy(sections)
        revision.save(update_fields=["sections"])
        return change, intent, revision

    # MODEL ---------------------------------------------------------------------------------------
    def model(self, ctx: CellContext, polarity: str):
        change, intent, revision = self._intent(ctx, ctx.case.sections)
        self.assertIsNotNone(field_registry.resolve_field_spec(ctx.case.field_path, revision=revision))
        value = ctx.case.good_value if polarity == POSITIVE else ctx.case.bad_value
        state = field_commit_service.commit_field(change=change, intent=intent, revision=revision, path=ctx.case.field_path, raw_value=value)
        self.assertEqual(state.validation_state, "VALID" if polarity == POSITIVE else "INVALID")

    # RENDER --------------------------------------------------------------------------------------
    def render(self, ctx: CellContext, polarity: str):
        if polarity == POSITIVE:
            self.assertTrue(ctx.target, "the feature renders no configuration line")
            self.assertFalse([s for s in ctx.added if s.startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER)])
            self.assertEqual(offline_verify._descriptors(ctx.platform, ctx.case.sections), ctx.lines)  # pylint: disable=protected-access
            digest = hashlib.sha256("\n".join(ctx.added).encode()).hexdigest()
            golden = json.loads(GOLDEN.read_text()) if GOLDEN.is_file() else {}
            key = f"{ctx.platform}|{ctx.feature.key}"
            if os.environ.get("NMAS_TG_UPDATE_GOLDEN") == "1":
                golden[key] = digest
                GOLDEN.parent.mkdir(parents=True, exist_ok=True)
                GOLDEN.write_text(json.dumps(golden, sort_keys=True, indent=1) + "\n")
            self.assertEqual(golden.get(key), digest, "rendered configuration differs from its reviewed golden digest")
            return
        refused = platform_drivers.PlatformCapability(platform_drivers.CapabilityStatus.NOT_IMPLEMENTED, "governance negative probe")
        code = ctx.feature.code
        gated_names = ("capability_for", "capability_for_routing", "is_routing_protocol_selectable", "capability_for_service_policy",
                       "resolve_service_policy_capability", "_service_policy_capability_or_not_implemented")
        originals = {name: getattr(platform_drivers, name) for name in gated_names}

        def gate(name):
            def gated(platform, feature, *args, **kwargs):
                value = str(getattr(feature, "value", feature))
                hit = value == code or (name == "is_routing_protocol_selectable" and code.startswith("BGP_") and value.startswith("BGP_"))
                if hit:
                    return False if name.startswith("is_") else refused
                return originals[name](platform, feature, *args, **kwargs)
            return gated

        with mock.patch.multiple(platform_drivers, **{name: mock.DEFAULT for name in gated_names}) as patched:
            for name in gated_names:
                patched[name].side_effect = gate(name)
            lines = offline_verify._descriptors(ctx.platform, ctx.case.sections)  # pylint: disable=protected-access
        added = list((Counter(lines) - Counter(ctx.base)).elements())
        self.assertTrue(any(s.startswith(platform_drivers.UNSUPPORTED_OBJECT_MARKER) for s in added), "no refusal marker for an unsupported feature")
        leaked = [s for s in ctx.target if s in added]
        self.assertEqual(leaked, [], "an unsupported feature still rendered configuration")

    # IMPORT --------------------------------------------------------------------------------------
    def import_(self, ctx: CellContext, polarity: str):
        sample = ctx.case if polarity == POSITIVE else probe_cases.ProbeCase(ctx.case.baseline, ctx.case.baseline, ctx.case.field_path,
                                                                                    ctx.case.good_value, ctx.case.bad_value, ctx.case.object_type,
                                                                                    ctx.case.expected)
        lines = ctx.lines if polarity == POSITIVE else ctx.base
        parsed = offline_verify._parse(ctx.platform, lines, sample)                    # pylint: disable=protected-access
        self.assertIs(offline_verify._parsed_contains(parsed, ctx.feature, ctx.case), polarity == POSITIVE)  # pylint: disable=protected-access

    # VALIDATE ------------------------------------------------------------------------------------
    def validate(self, ctx: CellContext, polarity: str):
        change, _intent, _revision = self._intent(ctx, ctx.case.sections)
        bundle = offline_verify.fixture_sources(ctx.platform, HEAD)
        if polarity == NEGATIVE:   # no external evidence at all: IPAM, topology and the managed-device inventory unavailable
            bundle = sources.SourceBundle(*(sources.SourceResult(name, "unavailable", None, f"{name} unavailable")
                                            for name in ("NETBOX", "TOPOLOGY", "INVENTORY")),
                                          bundle.capability, repository_head=HEAD, extra=bundle.extra)
        run = network_config_validation.validate_candidate(change, actor="governance-cell-probe", sources=bundle)
        if polarity == POSITIVE:
            self.assertIn(run.status, {"PASS", "WARNING"}, sorted({e.get("check", "") for e in run.errors}))
        else:
            self.assertNotIn(run.status, {"PASS", "WARNING"}, "validation passed without its IPAM evidence")

    # EXECUTE -------------------------------------------------------------------------------------
    def execute(self, ctx: CellContext, polarity: str):
        executor = ctx.executor()
        found = executor.assess(ctx.spec(ctx.target if polarity == POSITIVE else ()))
        if polarity == POSITIVE:   # the complete object is absent from the baseline: exactly APPLY, never SKIP / REFUSE
            self.assertEqual(found.action, APPLY, found.reason)
        else:
            self.assertEqual(found.action, REFUSE)

    # COMPENSATION --------------------------------------------------------------------------------
    def compensation(self, ctx: CellContext, polarity: str):
        executor = ctx.executor()
        if polarity == POSITIVE:
            found = executor.assess(ctx.spec(ctx.target))
            self.assertEqual(found.action, APPLY, found.reason)
            self.assertTrue(found.restorable, f"no provable compensation: {found.reason}")
            return
        # the previous state cannot be read: preflight must raise, never assume a restorable state
        def unreadable(*_args, **_kwargs):
            raise LiveError("CONNECTION_FAILED")

        executor._reader = unreadable
        for attr in ("_config_reader", "_daemon_reader", "_nft_reader"):
            if hasattr(executor, attr):
                setattr(executor, attr, unreadable)
        if hasattr(executor, "_conn"):
            executor._conn = _Unreachable()
        with self.assertRaises((ExecutorError, LiveError)):
            executor.assess(ctx.spec(ctx.target))


class _Unreachable:
    def __getattr__(self, name):
        def call(*_args, **_kwargs):
            raise LiveError("CONNECTION_FAILED")
        return call


# Known defects these negative cases reproduce run as expected failures (the case stays MISSING, never PASS); the day the code
# is fixed the test passes unexpectedly, which fails the gate until the entry is removed here.  Empty: F2 (render contributions
# not capability-gated) and F3 (L2 validation WARNING without NetBox evidence) were fixed in the closure sprint -- see
# test_tg_defect_regressions.py and docs/UNIT_TEST_AND_CODE_COVERAGE.md "Findings".
KNOWN_DEFECTS: dict[tuple[str, str, str], str] = {}

STAGE_METHODS = {"MODEL": "model", "RENDER": "render", "IMPORT": "import_", "VALIDATE": "validate", "EXECUTE": "execute",
                 "COMPENSATION": "compensation"}
CONDITIONS = {
    "MODEL": ("the feature's valid sample value committed through Tier-1 field validation", "VALID",
              "the feature's invalid sample value", "INVALID; the value is never accepted"),
    "RENDER": ("valid intent rendered by the platform driver", "target lines, no refusal marker, deterministic, golden digest",
               "the capability registry reports the feature NOT_IMPLEMENTED for the platform", "refusal marker; none of the configuration"),
    "IMPORT": ("the rendered running configuration", "the platform parser recovers the feature",
               "the same configuration without the feature", "nothing is imported (no phantom intent)"),
    "VALIDATE": ("the candidate with the offline IPAM / topology / inventory fixture", "network-configuration validation PASS or WARNING",
                 "IPAM, topology and inventory sources unavailable", "validation never passes without its evidence"),
    "EXECUTE": ("the rendered Configlet against a fake device", "preflight decides exactly APPLY (not SKIP / REFUSE); nothing is sent",
                "a Configlet with no statements", "REFUSE before any device contact"),
    "COMPENSATION": ("the rendered Configlet against a fake device", "preflight proves an exact compensation (restorable)",
                     "the device's previous state cannot be read", "preflight raises; a restorable state is never assumed"),
}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _add_cases() -> None:
    contexts: dict[tuple[str, str], CellContext] = {}

    def context(platform: str, feature_key: str) -> CellContext:
        if (platform, feature_key) not in contexts:
            contexts[(platform, feature_key)] = CellContext(platform, feature_key)
        return contexts[(platform, feature_key)]

    for cell in cells_module.default_cells():
        if not cell.supported:
            continue
        for stage in cell.stages:
            for polarity in (POSITIVE, NEGATIVE):
                pos_condition, pos_expected, neg_condition, neg_expected = CONDITIONS[stage]

                def test(self, platform=cell.platform, feature_key=cell.feature, stage=stage, polarity=polarity):
                    with transaction.atomic():
                        getattr(self, STAGE_METHODS[stage])(context(platform, feature_key), polarity)
                        transaction.set_rollback(True)

                test = case(cells_module.cell_case_id(cell.platform, cell.feature, stage, polarity),
                            target="web/core/services/platform_drivers.py", polarity=polarity,
                            condition=pos_condition if polarity == POSITIVE else neg_condition,
                            expected=pos_expected if polarity == POSITIVE else neg_expected,
                            platform=cell.platform, feature=cell.feature, stage=stage)(test)
                if polarity == NEGATIVE and (cell.platform, cell.feature, stage) in KNOWN_DEFECTS:
                    test = unittest.expectedFailure(test)
                name = f"test_{_slug(cell.platform)}_{_slug(cell.feature)}_{stage.lower()}_{'valid' if polarity == POSITIVE else 'refuses_invalid'}"
                setattr(CellCaseTests, name, test)


_add_cases()
