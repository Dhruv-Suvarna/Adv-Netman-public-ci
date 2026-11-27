"""Direct tests for the runbook evidence model and DAG registry (troubleshooting/runbooks/base.py and runbooks/__init__.py).

The evidence rules under test are the ones every runbook depends on: the latest observation per (key, device, subject) wins,
freshness is judged against a fixed ``now``, and a test may only use FRESH, trusted, non-missing evidence -- anything else is a
``Gap`` (UNAVAILABLE for a capability/permission reason, INCONCLUSIVE otherwise), never a silent absence.
"""

from __future__ import annotations

import tempfile
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from core.services.troubleshooting import runbooks
from core.services.troubleshooting.runbooks import base
from core.tests.test_troubleshooting_engine import T0


def obs(key="interface.oper_state", device="r1", subject="Eth1", value="up", *, age=0, **kw):
    return base.Obs(key=key, device=device, subject=subject, value=value, observed_at=T0 - timedelta(seconds=age), **kw)


def ctx(*observations, intent=None, path_fwd=None, flow=None, **kw):
    return base.Ctx(view=base.EvidenceView(observations, T0), now=T0, case={}, flow=flow or {}, intent=intent or {"nodes": [], "links": []},
                    baselines={}, changes=[], path_fwd=path_fwd or [], path_ret=[], **kw)


class KeyAndResultPrimitiveTests(SimpleTestCase):
    def test_gap_carries_status_and_reason(self):
        gap = base.Gap("UNAVAILABLE", "permission denied")
        self.assertEqual((gap.status, gap.reason, str(gap)), ("UNAVAILABLE", "permission denied", "permission denied"))

    def test_gap_is_raised_as_an_exception_not_returned(self):
        with self.assertRaises(base.Gap) as caught:
            raise base.Gap("INCONCLUSIVE", "stale")
        self.assertEqual(caught.exception.status, "INCONCLUSIVE")

    def test_split_and_join_key_round_trip_a_subject(self):
        stored = base.join_key("route.rib", "10.2.2.0/24")
        self.assertEqual(base.split_key(stored), ("route.rib", "10.2.2.0/24"))

    def test_key_without_subject_has_no_separator(self):
        with self.subTest("a key with no subject carries no separator"):
            self.assertEqual(base.join_key("maintenance.state"), "maintenance.state")
        with self.subTest("a stored key with no separator yields an empty subject"):
            self.assertEqual(base.split_key("maintenance.state"), ("maintenance.state", ""))

    def test_obs_ref_names_key_subject_and_device(self):
        self.assertEqual(obs().ref, f"interface.oper_state{base.KEY_SEP}Eth1@r1")
        self.assertEqual(obs(subject="").ref, "interface.oper_state@r1")

    def test_result_constructors_build_each_verdict(self):
        finding = base.Finding("F-x", "title", "L1")
        passed = base.ok("fine", "nothing implicated", checked=2)
        failed = base.fault("broken", finding, "cause", "fix it", port="Eth1")
        self.assertEqual((passed.verdict, passed.observed), ("PASS", {"checked": 2}))
        self.assertEqual((failed.verdict, failed.finding, failed.next_action, failed.observed), ("FAIL", finding, "fix it", {"port": "Eth1"}))

    def test_skip_and_inconclusive_constructors_build_their_status(self):
        self.assertEqual(base.inconclusive("partial", "summary", n=1).observed, {"n": 1})
        self.assertEqual(base.not_applicable("no LAG").summary, "no LAG")
        self.assertEqual(base.unsafe("would disturb traffic").reason, "would disturb traffic")

    def test_non_verdict_constructors_are_never_a_verdict(self):
        with self.subTest("inconclusive is not a verdict and reuses the reason as summary"):
            r = base.inconclusive("no evidence")
            self.assertEqual((r.verdict, r.summary), ("INCONCLUSIVE", "no evidence"))
        with self.subTest("not applicable is skipped, not executed"):
            r = base.not_applicable("no LAG")
            self.assertEqual((r.verdict, r.status, r.reason), ("SKIPPED", "NOT_APPLICABLE", "no LAG"))
        with self.subTest("unsafe is skipped, not executed"):
            r = base.unsafe("would disturb traffic")
            self.assertEqual((r.verdict, r.status), ("SKIPPED", "UNSAFE_TO_EXECUTE"))
        with self.subTest("a fault is never green"):
            self.assertNotEqual(base.fault("x", base.Finding("F", "t", "L1")).verdict, "PASS")
        with self.subTest("a healthy result holds no finding"):
            self.assertIsNone(base.ok("x").finding)


class EvidenceViewTests(SimpleTestCase):
    def test_latest_observation_per_key_wins_and_freshness_is_evaluated(self):
        view = base.EvidenceView([obs(value="down", age=60), obs(value="up", age=10), obs(subject="Eth2", value="up", age=10)], T0)
        latest = view.latest("interface.oper_state", "r1", "Eth1")
        self.assertEqual((latest.value, latest.freshness), ("up", base.c.FRESH))
        self.assertEqual([o.subject for o in view.each("interface.oper_state", "r1")], ["Eth1", "Eth2"])
        self.assertEqual(len(view.all()), 2)

    def test_absent_or_stale_observations_are_not_live(self):
        view = base.EvidenceView([obs(age=1000, max_age_seconds=300)], T0)
        with self.subTest("an unknown key is none"):
            self.assertIsNone(view.latest("interface.oper_state", "r9", "Eth1"))
        with self.subTest("an unknown device has no instances"):
            self.assertEqual(view.each("interface.oper_state", "r9"), [])
        with self.subTest("an over-age observation is not fresh"):
            self.assertNotEqual(view.latest("interface.oper_state", "r1", "Eth1").freshness, base.c.FRESH)
        with self.subTest("an empty view holds no observations"):
            self.assertEqual(base.EvidenceView([], T0).all(), [])


class CtxEvidenceAccessTests(SimpleTestCase):
    def test_ctx_defaults_and_need_records_used_evidence(self):
        c = ctx(obs(evidence_ids=("ev1", "ev2")))
        self.assertEqual((c.exceptions, c.results, c.alarms, c.correlation, c.used), ([], {}, [], {}, []))
        self.assertEqual(c.need("interface.oper_state", "r1", "Eth1").value, "up")
        self.assertEqual(c.used, ["ev1", "ev2"])

    def test_ctx_with_no_optional_parts_holds_none(self):
        c = ctx()
        with self.subTest("no exceptions, results or alarms are invented"):
            self.assertEqual((c.exceptions, c.results, c.alarms, c.gaps), ([], {}, [], []))

    def test_need_refuses_unusable_evidence_with_the_precise_gap(self):
        cases = (
            ("not collected", ctx(), "INCONCLUSIVE", "not collected"),
            ("missing for a capability reason", ctx(obs(is_missing=True, missing_reason="UNSUPPORTED: no eAPI")), None, "unavailable"),
            ("untrusted parse", ctx(obs(quality="UNTRUSTED")), "INCONCLUSIVE", "UNTRUSTED"),
            ("stale", ctx(obs(age=1000, max_age_seconds=300)), "INCONCLUSIVE", "not used as live state"),
        )
        for label, c, status, text in cases:
            with self.subTest(f"{label} evidence is refused"):
                with self.assertRaises(base.Gap) as caught:
                    c.need("interface.oper_state", "r1", "Eth1")
                if status:
                    self.assertEqual(caught.exception.status, status)
                self.assertIn(text, caught.exception.reason)
                self.assertTrue(c.gaps)
        with self.subTest("a reason in the capability list is refused as unavailable"):
            reason = f"{base.UNAVAILABLE_REASONS[0]}: denied"
            with self.assertRaises(base.Gap) as caught:
                ctx(obs(is_missing=True, missing_reason=reason)).need("interface.oper_state", "r1", "Eth1")
            self.assertEqual(caught.exception.status, "UNAVAILABLE")

    def test_need_any_returns_the_first_usable_instance(self):
        c = ctx(obs(device="r2", subject="Eth9"))
        self.assertEqual(c.need_any("interface.oper_state", ["r1", "r2"]).subject, "Eth9")

    def test_need_any_refuses_when_no_device_has_the_key(self):
        with self.subTest("no device collected the key"):
            with self.assertRaises(base.Gap) as caught:
                ctx().need_any("interface.oper_state", ["r1"])
            self.assertIn("not collected", caught.exception.reason)
        with self.subTest("no device list at all is refused"):
            with self.assertRaises(base.Gap):
                ctx().need_any("interface.oper_state", [])
        with self.subTest("a stale first instance is refused, not skipped"):
            with self.assertRaises(base.Gap):
                ctx(obs(age=1000, max_age_seconds=300)).need_any("interface.oper_state", ["r1"])

    def test_opt_and_each_return_only_usable_evidence(self):
        c = ctx(obs(evidence_ids=("a",)), obs(subject="Eth2", quality="UNTRUSTED"), obs(subject="Eth3", is_missing=True))
        self.assertEqual(c.opt("interface.oper_state", "r1", "Eth1").value, "up")
        self.assertEqual([o.subject for o in c.each("interface.oper_state", "r1")], ["Eth1"])

    def test_opt_and_each_yield_none_for_unusable_evidence(self):
        c = ctx(obs(quality="UNTRUSTED"))
        with self.subTest("untrusted evidence is none for opt"):
            self.assertIsNone(c.opt("interface.oper_state", "r1", "Eth1"))
        with self.subTest("untrusted evidence is not listed by each"):
            self.assertEqual(c.each("interface.oper_state"), [])

    def test_use_intent_and_result_record_lookups(self):
        r = base.ok("fine")
        c = ctx(intent_evidence_ids={"intent": "ev-intent"}, results={"HC01": r})
        c.use_intent("intent", "intent")
        self.assertEqual(c.used, ["ev-intent"])
        self.assertIs(c.result("HC01"), r)

    def test_unknown_intent_source_and_result_are_not_recorded(self):
        c = ctx()
        with self.subTest("an unknown intent source adds no evidence id"):
            c.use_intent("nothing")
            self.assertEqual(c.used, [])
        with self.subTest("a test that did not run has no result"):
            self.assertIsNone(c.result("HC99"))


class CtxTopologyTests(SimpleTestCase):
    INTENT = {"nodes": [{"name": "h1", "role": "host"}, {"name": "r1", "role": "router"}, {"name": "sw1", "role": "switch"}], "links": []}

    def test_topology_helpers_read_flow_path_and_intent(self):
        c = ctx(intent=self.INTENT, flow={"src": "h1", "dst": "h2"},
                path_fwd=[{"device": "h1"}, {"device": "sw1"}, {"device": "r1"}, {"device": "r1"}])
        self.assertEqual((c.src, c.dst), ("h1", "h2"))
        self.assertEqual(c.devices_on_path(), ["h1", "sw1", "r1"])
        self.assertEqual(c.devices_on_path(routers_only=True), ["r1"])
        self.assertEqual(c.node("r1")["role"], "router")
        self.assertEqual(c.nodes_by_role("router", "switch"), ["r1", "sw1"])
        self.assertEqual(c.since(60), T0 - timedelta(seconds=60))

    def test_unknown_topology_yields_no_path_or_node(self):
        c = ctx(intent=self.INTENT)
        with self.subTest("no resolved path lists no devices"):
            self.assertEqual(c.devices_on_path(), [])
        with self.subTest("an unknown node is empty"):
            self.assertEqual(c.node("r9"), {})
        with self.subTest("an absent role lists no nodes"):
            self.assertEqual(c.nodes_by_role("firewall"), [])
        with self.subTest("a zero window is not before now"):
            self.assertEqual(c.since(0), T0)


class RunbookRegistryTests(SimpleTestCase):
    def test_get_by_id_and_order_respect_the_dag(self):
        rb = runbooks.get("RB06")
        self.assertIn("MT03", rb.by_id)
        order = rb.order(sorted(rb.orders)[0])
        self.assertEqual(sorted(order), sorted(rb.by_id))
        for i, tid in enumerate(order):
            self.assertTrue(set(rb.by_id[tid].requires) | set(rb.by_id[tid].after) <= set(order[:i]))

    def test_unknown_runbook_or_strategy_is_refused(self):
        with self.subTest("an unknown runbook id is refused"):
            with self.assertRaises(KeyError) as caught:
                runbooks.get("RB99")
            self.assertIn("unknown runbook", str(caught.exception))
        with self.subTest("an unknown strategy is refused"):
            with self.assertRaises(KeyError):
                runbooks.get("RB01").order("no-such-strategy")

    def test_order_refuses_a_dependency_cycle(self):
        rb = runbooks.get("RB06")
        a, b = rb.tests[0], rb.tests[1]
        cyclic = base.Runbook(id="RBX", name="x", version="1", title="x", hypotheses=rb.hypotheses, select_strategy=rb.select_strategy, doc="x.md",
                              tests=(base.TestSpec(**{**a.__dict__, "requires": (b.id,), "after": ()}),
                                     base.TestSpec(**{**b.__dict__, "requires": (a.id,), "after": ()})),
                              orders={"s": (a.id, b.id)})
        with self.assertRaises(ValueError) as caught:
            cyclic.order("s")
        self.assertIn("cycle", str(caught.exception))

    def test_render_dag_block_lists_every_test_and_hypothesis(self):
        rb = runbooks.get("RB03")
        block = runbooks.render_dag_block(rb)
        self.assertTrue(block.startswith(runbooks.BEGIN) and block.endswith(runbooks.END))
        for t in rb.tests:
            self.assertIn(f"| {t.id} v{t.version} |", block)
        for h in rb.hypotheses:
            self.assertIn(f"| {h.id} |", block)

    def test_render_dag_block_refuses_a_cyclic_dag(self):
        rb = runbooks.get("RB06")
        a, b = rb.tests[0], rb.tests[1]
        cyclic = base.Runbook(id="RBX", name="x", version="1", title="x", hypotheses=(), select_strategy=rb.select_strategy, doc="x.md",
                              tests=(base.TestSpec(**{**a.__dict__, "requires": (b.id,)}), base.TestSpec(**{**b.__dict__, "requires": (a.id,)})),
                              orders={"s": (a.id, b.id)})
        with self.assertRaises(ValueError):
            runbooks.render_dag_block(cyclic)

    def test_doc_path_and_check_sync_for_the_shipped_documents(self):
        for rb in runbooks.REGISTRY.values():
            self.assertEqual(runbooks.doc_path(rb).name, rb.doc)
            self.assertEqual(runbooks.check_sync(rb), [])

    def test_missing_or_unmarked_documents_are_not_in_sync(self):
        rb = runbooks.get("RB01")
        with tempfile.TemporaryDirectory() as d:
            with self.subTest("a missing document is reported"):
                self.assertEqual(runbooks.check_sync(rb, Path(d) / "none.md"), ["none.md: document missing"])
            with self.subTest("a document without DAG markers is reported"):
                p = Path(d) / "nomarks.md"
                p.write_text("# no markers\n")
                self.assertEqual(runbooks.check_sync(rb, p), ["nomarks.md: DAG block markers missing"])
            with self.subTest("a document outside the docs directory has no path for an unknown doc"):
                fake = base.Runbook(**{**rb.__dict__, "doc": "no-such-runbook.md"})
                self.assertFalse(runbooks.doc_path(fake).exists())

    def test_dag_writer_returns_each_out_of_date_document_once(self):
        with tempfile.TemporaryDirectory() as d:
            for rb in runbooks.REGISTRY.values():
                (Path(d) / rb.doc).write_text(runbooks.doc_path(rb).read_text())
            stale = runbooks.get("RB02")
            text = (Path(d) / stale.doc).read_text()
            (Path(d) / stale.doc).write_text(text.replace(runbooks.render_dag_block(stale), f"{runbooks.BEGIN}\nold\n{runbooks.END}"))
            with mock.patch.object(runbooks, "DOCS_DIR", Path(d)):
                self.assertEqual(runbooks.write_dag_blocks(), [stale.doc])
                self.assertEqual(runbooks.write_dag_blocks(), [])
                self.assertEqual(runbooks.check_sync(stale), [])
