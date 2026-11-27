"""CFG cases for the reviewed deploy-side JSON artifacts, following the convention of test_tg_artifacts.py.

    CFG:<path>:LOAD:POSITIVE        the tracked file goes through the loader NMAS really uses
    CFG:<path>:MALFORMED:NEGATIVE   a malformed / tampered COPY in a temporary directory is refused by that loader

The loaders are the deploy controllers themselves (loaded by file path).  Where a loader demands root ownership, the
copy's ownership is faked at ``lstat``; the bytes are the tracked bytes.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PosixPath
from unittest import mock

from django.test import SimpleTestCase

from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.services.test_governance.constants import REPO_ROOT
from core.services.troubleshooting import fault_injection as fi
from core.tests.test_tg_sandbox_research_release_units import Fixture as ReleaseFixture

SANDBOX = REPO_ROOT / "deploy" / "sandbox"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = _load("tg_cfg_compat_overlay", REPO_ROOT / "deploy" / "compat" / "nmas_compat_overlay.py")
dto = _load("tg_cfg_diagnostic_target_overlay", SANDBOX / "diagnostic_target_overlay.py")
rp = _load("tg_cfg_render_policy", SANDBOX / "render_policy.py")
na = _load("tg_cfg_namespace_activation", SANDBOX / "namespace_activation.py")
wr = _load("tg_cfg_worker_runtime", SANDBOX / "worker_runtime.py")
rr = _load("tg_cfg_research_release", SANDBOX / "research_release.py")

COMPAT = "deploy/compat/reviewed-manifest.json"
OVERLAY = "deploy/sandbox/diagnostic-target-overlay.managed.json"
CAMPAIGN = "deploy/sandbox/fault-campaign.fixture.json"
SIMULATED = "deploy/sandbox/fixtures/approved-simulated.json"
RECEIPT = "deploy/sandbox/fixtures/research-v2-rollback-receipt.json"
DISPATCH = "deploy/sandbox/stage-b/dispatch-source-manifest.json"
RELEASE = "deploy/sandbox/stage-b/research-activation-release.json"


def cfg(path: str, stage: str, polarity: str, condition: str, expected: str):
    return case(f"CFG:{path}:{stage}:{polarity}", target=path, polarity=polarity, condition=condition, expected=expected)


def tracked(path: str):
    return json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))


class Temp(SimpleTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def copy(self, path: str, value=None, mode=0o600) -> Path:
        target = self.tmp / Path(path).name
        if value is None:
            shutil.copyfile(REPO_ROOT / path, target)
        else:
            target.write_text(json.dumps(value), encoding="utf-8")
        target.chmod(mode)
        return target


class CompatManifestTests(Temp):
    @cfg(COMPAT, "LOAD", POSITIVE, "the tracked reviewed compatibility-overlay manifest",
         "its review identity verifies the way nmas_compat_overlay.load checks it: schema, no build problems, entries_sha256")
    def test_reviewed_manifest_identity_verifies(self):
        manifest = tracked(COMPAT)
        self.assertEqual((manifest["schema"], manifest["problems"]), (tool.SCHEMA, []))
        self.assertEqual(tool.sha256_bytes(json.dumps(manifest["entries"], sort_keys=True).encode()), manifest["entries_sha256"])
        self.assertEqual(manifest["overlay_migrations"], list(tool.OVERLAY_MIGRATIONS))
        self.assertTrue(all(e["action"] in {"ADD", "REPLACE", "MERGE"} for e in manifest["entries"]))

    @cfg(COMPAT, "MALFORMED", NEGATIVE, "a copy whose entries were edited after review",
         "nmas_compat_overlay.load refuses it (entries do not match entries_sha256) before any payload is read")
    def test_edited_manifest_copy_is_refused(self):
        manifest = tracked(COMPAT)
        manifest["entries"][0]["post_sha256"] = "0" * 64
        package = self.tmp / "pkg"
        package.mkdir()
        (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "entries_sha256"):
            tool.load(package)


class _WithinAuthorization(datetime):
    @classmethod
    def now(cls, tz=None):
        return datetime(2026, 11, 20, tzinfo=timezone.utc).astimezone(tz)


class DiagnosticOverlayPolicyTests(Temp):
    def root_owned(self, path):
        real = PosixPath.lstat

        def lstat(candidate):
            info = real(candidate)
            if candidate != path:
                return info
            fields = list(info)
            fields[4] = fields[5] = 0
            return os.stat_result(fields)
        return mock.patch.object(PosixPath, "lstat", lstat)

    @cfg(OVERLAY, "LOAD", POSITIVE, "the tracked managed diagnostic-target overlay, inside its authorization window",
         "diagnostic_target_overlay._policy accepts it: exact unicast IPv4 TCP/22 targets, bound to the base activation")
    def test_managed_overlay_policy_loads(self):
        path = self.copy(OVERLAY)
        with self.root_owned(path), mock.patch.object(dto, "datetime", _WithinAuthorization):
            policy, digest = dto._policy(path)   # pylint: disable=protected-access  # the controller's own policy loader
        self.assertEqual(digest, tool.sha256_bytes((REPO_ROOT / OVERLAY).read_bytes()))
        self.assertTrue(policy["targets"] and all(t["port"] == 22 for t in policy["targets"]))

    @cfg(OVERLAY, "MALFORMED", NEGATIVE, "a copy with a non-SSH port / a duplicated target / an expired authorization",
         "diagnostic_target_overlay._policy refuses each")
    def test_tampered_overlay_policy_copies_are_refused(self):
        base = tracked(OVERLAY)
        cases = (("a non-SSH port", {**base, "targets": [{**base["targets"][0], "port": 2222}]}),
                 ("a duplicated target", {**base, "targets": [base["targets"][0], base["targets"][0]]}),
                 ("an expired authorization", {**base, "expires_at": "2026-11-01T00:00:00Z"}))
        for label, value in cases:
            path = self.copy(OVERLAY, value)
            with self.subTest(f"{label} is refused"), self.root_owned(path), mock.patch.object(dto, "datetime", _WithinAuthorization), \
                    self.assertRaises(dto.Refused):
                dto._policy(path)                 # pylint: disable=protected-access  # the controller's own policy loader


class CampaignAndRendererFixtureTests(Temp):
    @cfg(CAMPAIGN, "LOAD", POSITIVE, "the tracked fault-campaign fixture policy", "fault_injection.load_policy accepts it as fixture-only")
    def test_campaign_fixture_loads(self):
        policy = fi.load_policy(str(REPO_ROOT / CAMPAIGN))
        self.assertTrue(policy["campaign"]["fixture_only"])
        self.assertEqual({f["family"] for f in policy["protected_flows"]}, {"IPv4", "IPv6"})

    @cfg(CAMPAIGN, "MALFORMED", NEGATIVE, "a copy targeting R5 / a wildcard device", "fault_injection.load_policy refuses each")
    def test_campaign_fixture_copies_are_refused(self):
        for label, device in (("R5", "R5"), ("a wildcard", "*")):
            policy = tracked(CAMPAIGN)
            policy["allowed_faults"][0]["device"] = device
            with self.subTest(f"{label} is refused"), self.assertRaises(fi.FaultRefused):
                fi.load_policy(str(self.copy(CAMPAIGN, policy)))

    @cfg(SIMULATED, "LOAD", POSITIVE, "the tracked approved simulated sandbox manifest",
         "render_policy.validate accepts it and render produces the activation files")
    def test_simulated_manifest_renders(self):
        manifest = tracked(SIMULATED)
        endpoints, dns, destinations = rp.validate(manifest)
        self.assertTrue(endpoints and dns and destinations)
        out = rp.render(manifest, (SANDBOX / "nmas-troubleshooter-device-worker.service.in").read_text(encoding="utf-8"),
                        (SANDBOX / "research-egress.nft.in").read_text(encoding="utf-8"))
        self.assertTrue(out["diagnostic-targets.env"].startswith("TARGETS=tcp:"))

    @cfg(SIMULATED, "MALFORMED", NEGATIVE, "a copy whose target resolves to a protected host address / is R5",
         "render_policy.validate refuses each")
    def test_simulated_manifest_copies_are_refused(self):
        for label, mutate in (("a protected address", lambda m: m["approved_targets"][0].update(
                                  approved_paths=[{"address": m["protected_addresses"][0], "port": 22, "transport": "SSH"}])),
                              ("R5", lambda m: m["approved_targets"][0].update(device="R5"))):
            manifest = tracked(SIMULATED)
            mutate(manifest)
            with self.subTest(f"{label} is refused"), self.assertRaises(rp.ManifestRefused):
                rp.validate(json.loads(self.copy(SIMULATED, manifest).read_text()))


class ReceiptAndManifestTests(Temp):
    @cfg(RECEIPT, "LOAD", POSITIVE, "the tracked historical research-v2 rollback receipt",
         "namespace_activation.read_state accepts it as a legacy-schema receipt that owns nothing")
    def test_rollback_receipt_loads_as_an_inert_legacy_receipt(self):
        state = na.read_state(self.copy(RECEIPT))
        self.assertIn(state["schema"], na.LEGACY_SCHEMAS)
        self.assertEqual(state["status"], "rollback")
        self.assertFalse(any(state.get(flag) for flag in ("namespace_owned", "marker_owned", "host_link_owned", "host_table_owned",
                                                          "resolver_file_owned", "resolver_directory_owned")))

    @cfg(RECEIPT, "MALFORMED", NEGATIVE, "a copy with a foreign schema / that is group-readable",
         "namespace_activation.read_state refuses each")
    def test_rollback_receipt_copies_are_refused(self):
        with self.subTest("a foreign schema is refused"), self.assertRaises(na.Refused):
            na.read_state(self.copy(RECEIPT, {**tracked(RECEIPT), "schema": "someone-else/1"}))
        with self.subTest("a group-readable receipt is refused"), self.assertRaises(na.Refused):
            na.read_state(self.copy(RECEIPT, mode=0o640))

    @cfg(DISPATCH, "LOAD", POSITIVE, "the tracked Stage B dispatch source manifest",
         "worker_runtime.load_json accepts it; every path is relative, unique and not excluded, and web/manage.py is present")
    def test_dispatch_source_manifest_loads(self):
        manifest = wr.load_json(REPO_ROOT / DISPATCH, wr.SOURCE_SCHEMA)
        paths = [row["path"] for row in manifest["files"]]
        self.assertIn("web/manage.py", paths)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertFalse([p for p in paths if p.startswith("/") or ".." in Path(p).parts or wr.excluded(p)])

    @cfg(DISPATCH, "MALFORMED", NEGATIVE, "a copy declaring another schema / truncated JSON", "worker_runtime.load_json refuses each")
    def test_dispatch_source_manifest_copies_are_refused(self):
        with self.subTest("another schema is refused"), self.assertRaises(wr.Refused):
            wr.load_json(self.copy(DISPATCH, {**tracked(DISPATCH), "schema": wr.OVERLAY_SCHEMA}), wr.SOURCE_SCHEMA)
        truncated = self.tmp / "truncated.json"
        truncated.write_bytes((REPO_ROOT / DISPATCH).read_bytes()[:200])
        with self.subTest("truncated JSON is refused"), self.assertRaises(wr.Refused):
            wr.load_json(truncated, wr.SOURCE_SCHEMA)


class ResearchReleaseArtifactTests(ReleaseFixture):
    @cfg(RELEASE, "LOAD", POSITIVE, "the tracked COMPLETE-11 research activation release, re-bound in a copy",
         "research_release.validate accepts its exact file list, identities and bindings: the current controller still "
         "generates the reviewed host policy and the historical receipt's legacy digest (the tracked hashes are a record)")
    def test_release_graph_validates_when_rebound(self):
        out = rr.validate(self.path, self.root)
        self.assertEqual((out["result"], out["release_id"], out["files"]), ("valid", tracked(RELEASE)["release_id"], 18))
        self.assertEqual(out["legacy_digest"], tracked(RECEIPT)["config_digest"])

    @cfg(RELEASE, "MALFORMED", NEGATIVE, "the tracked release against today's tree / a copy with an extra key",
         "research_release.validate refuses each (input drift; invalid schema)")
    def test_release_drift_and_schema_copies_are_refused(self):
        with self.subTest("the tracked release is refused as drifted"), self.assertRaisesRegex(ValueError, "release input drift"):
            rr.validate(REPO_ROOT / RELEASE, REPO_ROOT)
        extra = self.root / "extra.json"
        extra.write_text(json.dumps({**self.manifest, "note": "unreviewed"}), encoding="utf-8")
        with self.subTest("an extra key is refused"), self.assertRaisesRegex(ValueError, "invalid research release schema"):
            rr.validate(extra, self.root)
