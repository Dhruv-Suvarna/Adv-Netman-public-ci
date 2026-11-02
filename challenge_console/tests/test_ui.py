"""The Tk shell: hidden views keep collecting, the worker -> Tk bridge, the three-way close workflow, and the absence of controls.

These tests need Tkinter and a display (``xvfb-run -a`` provides one).  Without either they are skipped; the collector-continuity
guarantee is also proven without Tk in ``test_core`` (collectors have no reference to the UI at all).
"""

from __future__ import annotations

import gc
import threading
import time
import unittest

from challenge_console import models as m
from challenge_console.runtime import CANCEL, DISCARD, SAVE, ConsoleRuntime
from challenge_console.sessionlog import read_session

from .helpers import ConsoleTestCase, CountingCollector

try:
    import tkinter as tk
    from tkinter import ttk

    _probe = tk.Tk()
    _probe.destroy()
    TK_REASON = ""
except Exception as exc:  # noqa: BLE001 - no tkinter module, or no display
    TK_REASON = f"Tk is not usable here ({type(exc).__name__})"

if not TK_REASON:
    from challenge_console.ui.app import CloseDialog, ConsoleApp
    from challenge_console.ui.bridge import UiBridge
    from challenge_console.ui.views import VIEWS

NAMES = m.COLLECTORS


class SampleCollector(CountingCollector):
    """Feeds the real store models, so the views have something real to draw."""

    def collect(self) -> None:
        super().collect()
        now = m.utcnow()
        if self.name == m.CONNECTIVITY:
            self.store.add_probe_sample(m.ProbeSample(now, "H1/IPV4", "H1", m.V4, "H2", "192.168.10.102", "192.168.20.101", self.count % 5 != 0, 3.1))
        elif self.name == m.COUNTERS:
            self.store.apply_counters("R1", now, [m.InterfaceCounters("R1", "Ethernet1", m.UP, m.UP, rx_bytes=self.count * 1000, tx_bytes=0)])
        elif self.name == m.SERVICES:
            self.store.set_service(m.ServiceObservation(now, "nmas-web", "NMAS Web", m.DOWN, (m.Check("http", False, "CONNECTION_REFUSED"),)))
            self.store.set_telemetry(ts=now, available=True, rows=[m.FreshnessRow("R1", True, now, 1.0, "FRESH")], thresholds={"healthy": 60.0, "stale": 120.0})
        elif self.name == m.NSOT:
            self.store.set_document(m.NSOT, ts=now, data={"devices": [{"name": "R1", "role": "Router", "platform": "", "device_type": "cEOS", "status": "Active",
                                    "managed": True, "primary_ip4": "192.0.2.1/24", "primary_ip6": "", "interfaces": [], "address_count": 0}],
                                    "counts": {"devices": 1}, "consistency": [], "prefixes": [], "vlans": [], "lab": {"running": 15, "expected": 15}})
        elif self.name == m.AUTOMATION:
            self.store.set_document(m.AUTOMATION, ts=now, data={"soaks": [], "golden": None})


@unittest.skipIf(TK_REASON, TK_REASON)
class UiTestCase(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        # Registered before any test body runs, so it runs LAST: after each test's own root / app / runtime cleanups.
        self.addCleanup(self._release_tk_on_main_thread)

    def _release_tk_on_main_thread(self) -> None:
        """Free this test's Tk interpreters on the main thread.

        Tcl aborts the whole process (``Tcl_AsyncDelete: async handler deleted by the wrong thread``) when a Tk interpreter is freed
        on any other thread.  Tk widgets sit in reference cycles, so a finished test's interpreter waits for the cyclic collector,
        and that collector can run on the next test's collector threads.  Drop the references this test holds (the runtime and the
        bus, whose subscribers reach the bridge and its root) and collect here, on the main thread.
        """
        self.__dict__.pop("runtime", None)
        self.__dict__.pop("bus", None)
        gc.collect()

    def app(self, chooser=None):
        factory = lambda config, store, bus: [SampleCollector(config, store, bus, name) for name in NAMES]  # noqa: E731
        self.runtime = ConsoleRuntime(self.config, collector_factory=factory)
        self.addCleanup(self.runtime.stop)
        app = ConsoleApp(self.runtime, close_chooser=chooser or (lambda _app: (CANCEL, None)))
        self.addCleanup(lambda: None if app.closed else (app.bridge.stop(), app.root.destroy()))
        app.start()
        return app

    def pump(self, app, seconds: float = 0.25) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not app.closed:
            app.root.update()
            time.sleep(0.005)

    def cycles(self):
        return {name: status.cycles for name, status in self.runtime.store.collector_status().items()}


class NavigationTests(UiTestCase):
    def test_five_views_and_a_persistent_sidebar(self):
        app = self.app()
        self.assertEqual([view.title for view in VIEWS], ["Continuous Connectivity", "NMAS / Telemetry", "NSOT", "Automation", "Interface Counters"])
        self.assertEqual(list(app.views), list(NAMES))
        self.assertEqual(list(app.nav), list(NAMES))
        frames = {key: view.winfo_id() for key, view in app.views.items()}
        for key in NAMES:
            app.show(key)
            self.pump(app, 0.05)
            self.assertEqual(app.visible, key)
        self.assertEqual(frames, {key: view.winfo_id() for key, view in app.views.items()})          # views are raised, never rebuilt

    def test_every_collector_keeps_running_while_its_view_is_hidden(self):
        app = self.app()
        self.pump(app, 0.3)
        for hidden in NAMES:
            visible = next(name for name in NAMES if name != hidden)
            app.show(visible)
            before = self.cycles()[hidden]
            self.pump(app, 0.3)
            self.assertGreater(self.cycles()[hidden], before + 3, f"{hidden} stopped collecting while hidden")
        self.assertEqual(sorted(self.runtime.supervisor.alive()), sorted(NAMES))
        self.assertEqual({s.restarts for s in self.runtime.store.collector_status().values()}, {0})  # navigation never restarted anything

    def test_connectivity_history_grows_while_other_views_are_shown(self):
        app = self.app()
        app.show(m.CONNECTIVITY)
        self.pump(app, 0.3)
        first = self.runtime.store.probe_history("H1/IPV4")
        self.assertGreater(len(first), 2)
        app.show(m.NSOT)
        self.pump(app, 0.3)
        app.show(m.COUNTERS)
        self.pump(app, 0.3)
        app.show(m.CONNECTIVITY)
        self.pump(app, 0.1)
        after = self.runtime.store.probe_history("H1/IPV4")
        self.assertGreater(len(after), len(first) + 10)
        self.assertEqual(after[:len(first)], first)                                                  # history continued; nothing was reset
        hidden_window = [s for s in after[len(first):]]
        gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(hidden_window, hidden_window[1:])]
        self.assertLess(max(gaps), 0.25)                                                             # no hole while hidden
        self.assertEqual(self.runtime.store.probe_rows()[0].samples, len(self.runtime.store.probe_history("H1/IPV4")))
        self.assertTrue(app.views[m.CONNECTIVITY].matrix.get_children())

    def test_only_the_visible_view_is_rendered(self):
        app = self.app()
        app.show(m.AUTOMATION)
        renders = {key: view.renders for key, view in app.views.items()}
        self.pump(app, 0.5)
        for key, view in app.views.items():
            if key == m.AUTOMATION:
                self.assertGreater(view.renders, renders[key])
            else:
                self.assertEqual(view.renders, renders[key])

    def test_nmas_web_down_is_shown_and_the_console_keeps_working(self):
        app = self.app()
        app.show(m.SERVICES)
        self.pump(app, 0.3)
        view = app.views[m.SERVICES]
        self.assertEqual(view.components.item("nmas-web", "values")[:2], ("NMAS Web", "DOWN"))
        self.assertIn("NMAS Web: DOWN", view.summary.cget("text"))
        app.show(m.COUNTERS)
        self.pump(app, 0.2)
        self.assertTrue(app.views[m.COUNTERS].table.get_children())


class BridgeTests(UiTestCase):
    def test_widgets_are_only_touched_on_the_tk_thread(self):
        app = self.app()
        seen = set()
        for view in app.views.values():
            original = view.render
            view.render = lambda original=original: (seen.add(threading.get_ident()), original())[1]
        original_topics = app._on_topics
        app.bridge._on_topics = lambda topics: (seen.add(threading.get_ident()), original_topics(topics))[1]
        for key in NAMES:
            app.show(key)
            self.pump(app, 0.15)
        self.assertEqual(seen, {threading.get_ident()})                                              # this (the Tk) thread, never a worker

    def test_events_published_from_worker_threads_are_delivered_as_topics(self):
        root = tk.Tk()
        self.addCleanup(root.destroy)
        received = []
        bridge = UiBridge(root, self.bus, received.append, period_ms=10)
        bridge.start()
        workers = [threading.Thread(target=lambda name=name: [self.bus.emit(name, "x") for _ in range(200)]) for name in NAMES]
        [w.start() for w in workers]
        [w.join() for w in workers]
        self.bus.emit(m.SUPERVISOR, "collector.stall", "nsot")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and bridge.delivered < 1001:
            root.update()
        self.assertEqual(bridge.delivered, 1001)                                                     # nothing lost crossing threads
        self.assertEqual(set().union(*received), set(NAMES) | {"collectors"})
        bridge.stop()
        count = len(received)
        self.bus.emit("nsot", "x")
        root.update()
        time.sleep(0.05)
        root.update()
        self.assertEqual(len(received), count)                                                       # a stopped bridge no longer calls back

    def test_a_slow_render_does_not_delay_collection(self):
        app = self.app()
        app.views[m.CONNECTIVITY].render = lambda: time.sleep(0.2)
        app.show(m.CONNECTIVITY)
        before = self.cycles()
        self.pump(app, 0.6)
        after = self.cycles()
        self.assertTrue(all(after[name] > before[name] + 10 for name in NAMES))                      # the UI was busy ~all the time; polling was not


class CloseTests(UiTestCase):
    def test_cancel_returns_to_the_running_console_without_resetting_anything(self):
        app = self.app(lambda _app: (CANCEL, None))
        self.pump(app, 0.2)
        history = self.runtime.store.probe_history("H1/IPV4")
        before = self.cycles()
        self.assertEqual(app.request_close(), CANCEL)
        self.assertFalse(app.closed)
        self.assertTrue(self.runtime.running)
        self.assertTrue(app.root.winfo_exists())
        self.pump(app, 0.3)
        self.assertTrue(all(self.cycles()[name] > before[name] for name in NAMES))                   # collectors continued
        self.assertEqual(self.runtime.store.probe_history("H1/IPV4")[:len(history)], history)        # no state reset
        self.assertEqual({s.restarts for s in self.runtime.store.collector_status().values()}, {0})
        self.assertTrue(self.runtime.log.path.exists())

    def test_save_persists_then_exits_cleanly(self):
        app = self.app(lambda _app: (SAVE, None))
        self.pump(app, 0.3)
        self.assertEqual(app.request_close(), SAVE)
        self.assertTrue(app.closed)
        self.assertEqual(self.runtime.supervisor.alive(), [])
        self.assertFalse([t for t in threading.enumerate() if t.name.startswith("console-")])        # no orphan worker
        self.assertEqual(app.saved_path.parent, self.config.save_dir)
        records = read_session(app.saved_path)
        self.assertEqual((records[0]["kind"], records[-1]["kind"]), ("session.meta", "app.stop"))
        self.assertIn("connectivity.sample", {r["kind"] for r in records})
        with self.assertRaises(tk.TclError):
            app.root.winfo_exists()                                                                  # the Tk root is destroyed

    def test_save_to_a_chosen_destination(self):
        target = self.tmp / "elsewhere" / "proof.jsonl"
        app = self.app(lambda _app: (SAVE, target))
        self.pump(app, 0.1)
        app.request_close()
        self.assertEqual(app.saved_path, target)
        self.assertTrue(target.exists())

    def test_dont_save_discards_and_exits_cleanly(self):
        app = self.app(lambda _app: (DISCARD, None))
        self.pump(app, 0.2)
        spool = self.runtime.log.path
        self.assertEqual(app.request_close(), DISCARD)
        self.assertTrue(app.closed)
        self.assertIsNone(app.saved_path)
        self.assertFalse(spool.exists())
        self.assertFalse(self.config.save_dir.exists() and list(self.config.save_dir.iterdir()))
        self.assertEqual(self.runtime.supervisor.alive(), [])

    def test_the_dialog_offers_exactly_save_dont_save_cancel(self):
        root = tk.Tk()
        self.addCleanup(root.destroy)
        dialog = CloseDialog(root, self.tmp / "s.jsonl", {"written": 10, "pending": 0})
        choices = [dialog.save_button.cget("text"), dialog.discard_button.cget("text"), dialog.cancel_button.cget("text")]
        self.assertEqual(choices, ["Save", "Don't Save", "Cancel"])
        self.assertEqual(dialog.result, (CANCEL, None))                                              # dismissing the dialog is Cancel
        dialog.discard_button.invoke()
        self.assertEqual(dialog.result, (DISCARD, None))
        dialog = CloseDialog(root, self.tmp / "s.jsonl", {"written": 10, "pending": 0})
        dialog.save_button.invoke()
        self.assertEqual(dialog.result, (SAVE, self.tmp / "s.jsonl"))
        dialog = CloseDialog(root, self.tmp / "s.jsonl", {"written": 10, "pending": 0})
        dialog.event_generate("<Escape>")
        dialog.cancel_button.invoke()
        self.assertEqual(dialog.result, (CANCEL, None))

    def test_the_window_close_button_goes_through_the_chooser(self):
        asked = []
        app = self.app(lambda _app: (asked.append(1), (CANCEL, None))[1])
        self.assertIn("request_close", app.root.protocol("WM_DELETE_WINDOW"))
        app.root.tk.call(app.root.protocol("WM_DELETE_WINDOW"))
        self.assertEqual((asked, app.closed), ([1], False))


class ReadOnlySurfaceTests(UiTestCase):
    def walk(self, widget):
        yield widget
        for child in widget.winfo_children():
            yield from self.walk(child)

    def test_no_view_offers_a_control_action(self):
        app = self.app()
        forbidden = ("execute", "approve", "rollback", "roll back", "provision", "promot", "golden", "rotate", "push", "onboard", "apply", "deploy",
                     "start soak", "cancel soak", "restart", "delete", "commit")
        buttons = [w for view in app.views.values() for w in self.walk(view) if isinstance(w, (ttk.Button, tk.Button, ttk.Menubutton, tk.Menubutton))]
        self.assertEqual(buttons, [])                                                                # the views have no buttons at all
        for widget in self.walk(app.root):
            if isinstance(widget, (ttk.Button, tk.Button)):
                self.assertFalse([word for word in forbidden if word in str(widget.cget("text")).lower()], widget.cget("text"))
        self.assertEqual(str(app.root.cget("menu")), "")                                             # no menu bar hiding an action either
        nav = sorted(str(w.cget("text")) for w in self.walk(app.root) if isinstance(w, ttk.Button))
        self.assertEqual(len(nav), 5)                                                                # the five navigation buttons, nothing else

    def test_automation_view_shows_the_soak_without_any_promotion_action(self):
        app = self.app()
        soak = {"soak_id": "SOAK-000001", "state": "RUNNING", "result": "", "terminal_reason": "", "bundle_id": "BND-PROB-000001",
                "root_bundle": "BND-DEP-000001", "change_id": "CHG-20261006-0002", "devices": ["R1"], "started_at": "2026-10-06T10:56:22.446Z",
                "due_at": "2026-10-13T10:56:22.446Z", "elapsed_seconds": 10.0, "remaining_seconds": 20.0, "duration_seconds": 604800.0,
                "collector": {"state": "FRESH", "last_sample_at": "2026-10-06T11:12:58.000Z", "expected_every_seconds": 900}, "samples": 2,
                "latest_sample": {"result": "PASS", "bucket": 1, "expected_state": "PASS", "telemetry_freshness": "FRESH", "integrity_ok": True},
                "drift": [{"device": "R1", "state": "MATCH", "baseline": "9cd6f5a17cf1", "current": "9cd6f5a17cf1"}], "drift_state": "MATCH",
                "health": "HEALTHY", "eligibility": {"code": "IN_PROBATION", "text": "In probation."}}
        self.runtime.supervisor.stop()
        self.runtime.store.set_document(m.AUTOMATION, ts=m.utcnow(), data={"soaks": [soak], "golden": None, "executions": [
            {"change_id": "CHG-1", "mode": "COMPLETE", "state": "FINISHED", "outcome": "SUCCEEDED", "actor": "dhruv", "started_at": "", "finished_at": "", "run_id": "x"}]})
        view = app.views[m.AUTOMATION]
        app.show(m.AUTOMATION)
        shown = {key: label.cget("text") for key, label in view.soak_values.items()}
        self.assertIn("SOAK-000001", shown["soak"])
        self.assertIn("BND-PROB-000001", shown["bundle"])
        self.assertEqual(shown["devices"], "R1")
        self.assertTrue(shown["state"].startswith("RUNNING"))
        self.assertEqual((shown["started"], shown["due"]), ("2026-10-06 10:56:22Z", "2026-10-13 10:56:22Z"))
        self.assertTrue(shown["collector"].startswith("FRESH"))
        self.assertTrue(shown["sample"].startswith("PASS"))
        self.assertTrue(shown["drift"].startswith("MATCH"))
        self.assertEqual(shown["health"], "HEALTHY")
        self.assertTrue(shown["eligibility"].startswith("IN_PROBATION"))
        self.assertNotEqual(shown["elapsed"], "-")
        self.assertNotEqual(shown["remaining"], "-")
        self.assertEqual(view.tables["executions"].item("executions0", "values")[3], "SUCCEEDED")
        soak["state"], soak["eligibility"] = "INVALIDATED", {"code": "NOT_ELIGIBLE", "text": "ended"}  # the state shown is whatever was read
        self.runtime.store.set_document(m.AUTOMATION, ts=m.utcnow(), data={"soaks": [soak], "golden": None})
        view.refresh()
        self.assertTrue(view.soak_values["state"].cget("text").startswith("INVALIDATED"))
