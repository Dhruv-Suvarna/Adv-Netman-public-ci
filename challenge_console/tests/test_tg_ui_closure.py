"""Lab 7 closure: the Tk console's public functions, each called directly from a test.

``test_ui.py`` proves the operator-visible behaviour through the running application; this module calls every remaining UI entry
point itself: the table helpers, the ``View`` base, each view's ``build``, the worker -> Tk bridge, the close dialog, ``run`` and the
scripted ``live_proof`` helpers.  Like ``test_ui.py`` it needs Tkinter and a display (``xvfb-run -a``) and skips without them.

No collector touches the network here: the runtimes are built with no collectors at all (or the scripted sample collectors of
``test_ui.py``), every session file goes to the test's temporary directory, and signal handlers are never installed for real.
"""

from __future__ import annotations

import json
import signal
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from challenge_console import models as m
from challenge_console.runtime import CANCEL, DISCARD, SAVE, ConsoleRuntime

from .helpers import ConsoleTestCase

try:
    import tkinter as tk
    from tkinter import ttk

    _probe = tk.Tk()
    _probe.destroy()
    TK_REASON = ""
except Exception as exc:  # noqa: BLE001 - no tkinter module, or no display
    TK_REASON = f"Tk is not usable here ({type(exc).__name__})"

if not TK_REASON:
    from challenge_console.ui import app as app_module
    from challenge_console.ui import live_proof
    from challenge_console.ui.app import CloseDialog, ConsoleApp
    from challenge_console.ui.bridge import COLLECTORS_TOPIC, UiBridge
    from challenge_console.ui.views import VIEWS
    from challenge_console.ui.widgets import View, make_table, selected, sync_table


class _ProbeView(View if not TK_REASON else object):
    """A minimal concrete view: records its own build / render calls."""

    key, title = "probe", "Probe"

    def build(self) -> None:
        self.built = True
        self.label = ttk.Label(self, text="built")

    def render(self) -> None:
        self.label.configure(text=f"render {self.renders}")


@unittest.skipIf(TK_REASON, TK_REASON)
class TkCase(ConsoleTestCase):
    def setUp(self):
        super().setUp()
        self.root = tk.Tk()
        self.addCleanup(self._destroy_root)

    def _destroy_root(self):
        try:
            self.root.destroy()
        except tk.TclError:
            pass                                     # the code under test already closed it

    def runtime(self, collectors=()) -> ConsoleRuntime:
        runtime = ConsoleRuntime(self.config, collectors=list(collectors))
        self.addCleanup(runtime.stop)
        return runtime

    def app(self, runtime=None, **kwargs) -> "ConsoleApp":
        app = ConsoleApp(runtime or self.runtime(), root=self.root, **kwargs)
        self.addCleanup(lambda: None if app.closed else app.bridge.stop())
        return app


class WidgetHelperTests(TkCase):
    def test_make_table_builds_headings_widths_anchors_and_scrollbars(self):
        frame, tree = make_table(self.root, [("name", "Name", 120), ("rate", "Rate", 90, tk.E)], height=4)
        self.assertEqual(tree["columns"], ("name", "rate"))
        self.assertEqual((tree.heading("name")["text"], tree.heading("rate")["text"]), ("Name", "Rate"))
        self.assertEqual((tree.column("name")["width"], tree.column("rate")["width"]), (120, 90))
        self.assertEqual((str(tree.column("name")["anchor"]), str(tree.column("rate")["anchor"])), ("w", "e"))
        self.assertEqual(sorted(type(child).__name__ for child in frame.winfo_children()), ["Scrollbar", "Scrollbar", "Treeview"])
        self.assertEqual(str(tree.cget("selectmode")), "browse")

    def test_make_table_with_a_malformed_column_raises(self):
        with self.assertRaises(IndexError):
            make_table(self.root, [("name", "Name")])          # (id, heading) without a width

    def test_sync_table_inserts_updates_reorders_and_deletes_rows_in_place(self):
        _frame, tree = make_table(self.root, [("v", "Value", 80)])
        sync_table(tree, [("a", (1,), "ok"), ("b", (2,), ""), ("c", (3,), "bad")])
        self.assertEqual(tree.get_children(""), ("a", "b", "c"))
        tree.selection_set("b")
        sync_table(tree, [("b", (20,), "warn"), ("a", (10,), "")])
        self.assertEqual(tree.get_children(""), ("b", "a"))                        # c deleted, b moved first
        self.assertEqual((tree.item("b")["values"], tuple(tree.item("b")["tags"])), ([20], ("warn",)))
        self.assertEqual(tree.item("a")["tags"], "")
        self.assertEqual(tree.selection(), ("b",))                                  # an updated row keeps its selection

    def test_sync_table_with_a_duplicate_row_id_raises(self):
        _frame, tree = make_table(self.root, [("v", "Value", 80)])
        with self.assertRaisesRegex(tk.TclError, "already exists"):
            sync_table(tree, [("x", (1,), ""), ("x", (2,), "")])

    def test_selected_returns_the_chosen_row(self):
        _frame, tree = make_table(self.root, [("v", "Value", 80)])
        sync_table(tree, [("r1", (1,), ""), ("r2", (2,), "")])
        tree.selection_set("r2")
        self.assertEqual(selected(tree), "r2")

    def test_selected_without_a_selection_is_empty(self):
        _frame, tree = make_table(self.root, [("v", "Value", 80)])
        sync_table(tree, [("r1", (1,), "")])
        self.assertEqual(selected(tree), "")


class ViewBaseTests(TkCase):
    def test_a_view_binds_the_runtime_store_and_config_then_builds(self):
        runtime = SimpleNamespace(store=self.store, config=self.config)
        view = _ProbeView(self.root, runtime)
        self.assertEqual((view.runtime, view.store, view.cfg, view.renders, view.built), (runtime, self.store, self.config, 0, True))

    def test_the_base_view_without_build_raises(self):
        with self.assertRaises(NotImplementedError):
            View(self.root, SimpleNamespace(store=self.store, config=self.config))

    def test_refresh_counts_and_renders(self):
        view = _ProbeView(self.root, SimpleNamespace(store=self.store, config=self.config))
        view.refresh()
        view.refresh()
        self.assertEqual((view.renders, view.label.cget("text")), (2, "render 2"))


class ViewBuildTests(TkCase):
    """Each view's ``build`` called directly on a bare frame: the widgets its ``render`` relies on exist, nothing is pre-filled."""

    EXPECTED = {
        "ConnectivityView": ("Waiting for the first probes ...", ("matrix", "samples", "buffer")),
        "TelemetryView": ("Waiting for the first observation ...", ("components", "freshness", "freshness_note")),
        "NsotView": ("Waiting for the first NetBox read ...", ("devices", "detail", "prefixes", "vlans", "role_box")),
        "AutomationView": ("Waiting for the first read ...", ("tables", "soak_values")),
        "CountersView": ("Waiting for the first counter read ...", ("table", "device_box", "shown")),
    }

    def test_each_view_build_creates_its_summary_and_tables(self):
        for view_class in VIEWS:
            summary, attributes = self.EXPECTED[view_class.__name__]
            with self.subTest(view=view_class.__name__):
                view = view_class.__new__(view_class)
                ttk.Frame.__init__(view, self.root)
                view.runtime, view.store, view.cfg, view.renders = None, self.store, self.config, 0
                view.build()
                self.assertEqual(view.summary.cget("text"), summary)
                for attribute in attributes:
                    self.assertTrue(hasattr(view, attribute), attribute)
                tables = [getattr(view, name) for name in attributes if isinstance(getattr(view, name), ttk.Treeview)]
                tables += list(getattr(view, "tables", {}).values())
                self.assertTrue(tables)
                self.assertEqual({len(table.get_children("")) for table in tables}, {0})

    def test_the_automation_view_builds_every_tab_and_soak_field(self):
        view_class = next(v for v in VIEWS if v.key == m.AUTOMATION)
        view = view_class.__new__(view_class)
        ttk.Frame.__init__(view, self.root)
        view.runtime, view.store, view.cfg, view.renders = None, self.store, self.config, 0
        view.build()
        self.assertEqual(list(view.tables), ["executions", "changes", "validations", "config_validations", "checks", "bundles", "traffic",
                                             "provisioning", "rotation_runs", "rotation_policy"])
        self.assertEqual(len(view.soak_values), 13)


class BridgeTests(TkCase):
    def test_drain_returns_each_changed_topic_once_and_counts_deliveries(self):
        bridge = UiBridge(self.root, self.bus, lambda topics: None)
        for collector in (m.CONNECTIVITY, m.CONNECTIVITY, m.NSOT, "app"):
            bridge._on_event(SimpleNamespace(collector=collector))
        self.assertEqual(bridge.drain(), {m.CONNECTIVITY, m.NSOT, COLLECTORS_TOPIC})
        self.assertEqual(bridge.delivered, 4)
        self.assertEqual(bridge.drain(), set())

    def test_a_bus_that_refuses_the_subscription_raises(self):
        class RefusingBus:
            def subscribe(self, _callback):
                raise RuntimeError("bus closed")

        with self.assertRaisesRegex(RuntimeError, "bus closed"):
            UiBridge(self.root, RefusingBus(), lambda topics: None)


class CloseDialogTests(TkCase):
    def dialog(self, destination, log_status):
        dialog = CloseDialog(self.root, destination, log_status)
        self.root.after(3000, lambda: dialog.winfo_exists() and dialog.destroy())   # fail-safe: a broken test fails, never hangs
        return dialog

    def test_ask_returns_save_with_the_destination(self):
        destination = self.tmp / "sessions" / "s.jsonl"
        dialog = self.dialog(destination, {"written": 3, "pending": 2})
        self.root.after(50, dialog.save_button.invoke)
        self.assertEqual(dialog.ask(), (SAVE, destination))

    def test_ask_returns_cancel_when_the_dialog_window_is_closed(self):
        dialog = self.dialog(self.tmp / "s.jsonl", {"written": 0, "pending": 0})
        self.root.after(50, lambda: dialog.tk.call(dialog.protocol("WM_DELETE_WINDOW")))   # the window manager's close button
        self.assertEqual(dialog.ask(), (CANCEL, None))

    def test_close_dialog_with_an_incomplete_log_status_raises(self):
        with self.assertRaises(KeyError):
            CloseDialog(self.root, self.tmp / "s.jsonl", {"written": 3})


class ConsoleAppSignalTests(TkCase):
    def test_stop_from_signal_shuts_down_on_the_next_pump_and_keeps_the_spool(self):
        runtime = self.runtime()
        app = self.app(runtime, close_chooser=lambda _app: (CANCEL, None))
        app.start()
        app.stop_from_signal(signal.SIGTERM, None)
        self.assertFalse(app.closed)                       # only flagged: the handler itself touches no widget
        app._on_topics(set())                               # the next bridge pump, on the Tk thread
        self.assertTrue(app.closed)
        self.assertEqual(app.saved_path, Path(runtime.log.path))
        self.assertFalse(runtime.running)


class RunTests(ConsoleTestCase):
    """``app.run``: the real entry point, with the runtime built without collectors and signal handlers recorded, not installed."""

    @unittest.skipIf(TK_REASON, TK_REASON)
    def test_run_opens_the_console_and_returns_0_after_a_discard_close(self):
        installed = []

        class ClosingApp(ConsoleApp):
            def __init__(inner, runtime):                                       # noqa: N805 - test double
                super().__init__(runtime, close_chooser=lambda _app: (DISCARD, None))
                inner.root.after(150, inner.request_close)

        runtimes = []

        def runtime_factory(_config):
            runtimes.append(ConsoleRuntime(self.config, collectors=[]))
            return runtimes[-1]

        with mock.patch.object(app_module, "ConsoleRuntime", runtime_factory), mock.patch.object(app_module, "ConsoleApp", ClosingApp), \
                mock.patch.object(app_module.signal, "signal", lambda number, handler: installed.append(number)):
            self.assertEqual(app_module.run(self.config), 0)
        self.assertEqual(installed, [signal.SIGINT, signal.SIGTERM])
        self.assertFalse(runtimes[0].running)
        self.assertFalse(Path(runtimes[0].log.path).exists())                   # Don't Save removed the spool

    @unittest.skipIf(TK_REASON, TK_REASON)
    def test_run_without_a_display_exits_2_and_discards_the_session(self):
        finished = []
        runtime = SimpleNamespace(finish=lambda action, destination=None: finished.append(action))

        def no_display(_runtime):
            raise tk.TclError("couldn't connect to display")

        with mock.patch.object(app_module, "ConsoleRuntime", lambda _config: runtime), mock.patch.object(app_module, "ConsoleApp", no_display), \
                mock.patch("builtins.print") as printed:
            self.assertEqual(app_module.run(self.config), 2)
        self.assertEqual(finished, [DISCARD])
        self.assertIn("Cannot open a display", printed.call_args.args[0])


class LiveProofHelperTests(TkCase):
    def test_table_rows_counts_the_top_level_rows(self):
        _frame, tree = make_table(self.root, [("v", "Value", 80)])
        sync_table(tree, [("a", (1,), ""), ("b", (2,), "")])
        self.assertEqual(live_proof.table_rows(tree), 2)

    def test_table_rows_of_an_empty_table(self):
        _frame, tree = make_table(self.root, [("v", "Value", 80)])
        self.assertEqual(live_proof.table_rows(tree), 0)

    def test_pump_updates_the_window_for_the_given_time(self):
        updates = []
        fake = SimpleNamespace(closed=False, root=SimpleNamespace(update=lambda: updates.append(time.monotonic())))
        started = time.monotonic()
        live_proof.pump(fake, 0.1)
        self.assertGreaterEqual(time.monotonic() - started, 0.1)
        self.assertGreater(len(updates), 1)

    def test_pump_of_a_closed_console_never_updates(self):
        fake = SimpleNamespace(closed=True, root=SimpleNamespace(update=lambda: self.fail("a closed console must not be pumped")))
        live_proof.pump(fake, 0.5)

    def test_press_opens_the_real_close_dialog_and_presses_cancel(self):
        app = self.app()                                                       # the real chooser: CloseDialog
        seen = live_proof.press(app, "cancel_button", delay_ms=50)
        self.assertEqual(seen["action"], CANCEL)
        self.assertEqual(seen["buttons"], ["Save", "Don't Save", "Cancel"])
        self.assertTrue(seen["destination"].endswith(".jsonl"))
        self.assertFalse(app.closed)

    def test_press_on_a_closed_console_never_opens_a_dialog(self):
        app = self.app()
        app.closed = True
        self.assertEqual(live_proof.press(app, "save_button", delay_ms=50), {"action": CANCEL})
        self.assertEqual([w for w in self.root.winfo_children() if isinstance(w, CloseDialog)], [])


class LiveProofMainTests(ConsoleTestCase):
    @unittest.skipIf(TK_REASON, TK_REASON)
    def test_main_without_out_raises_system_exit(self):
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit) as raised:
            live_proof.main([])
        self.assertEqual(raised.exception.code, 2)

    @unittest.skipIf(TK_REASON, TK_REASON)
    def test_main_writes_the_evidence_for_cancel_save_and_discard(self):
        """The whole scripted proof on collector-free runtimes that stay off the lab, every wait shortened."""
        original_pump = live_proof.pump
        runtimes = []

        def runtime_factory(_config):
            runtimes.append(ConsoleRuntime(self.config, collectors=[]))
            self.addCleanup(runtimes[-1].stop)
            return runtimes[-1]

        out = self.tmp / "evidence" / "live.json"
        with mock.patch.object(live_proof, "ConsoleRuntime", runtime_factory), \
                mock.patch.object(live_proof.ConsoleConfig, "from_env", classmethod(lambda cls: self.config)), \
                mock.patch.object(live_proof, "pump", lambda app, seconds: original_pump(app, min(seconds, 0.05))), \
                mock.patch("builtins.print"):
            self.assertEqual(live_proof.main(["--out", str(out), "--hidden-seconds", "0", "--warmup-seconds", "0"]), 0)
        evidence = json.loads(out.read_text())
        self.assertEqual(sorted(evidence["views"]), sorted(m.COLLECTORS))
        self.assertEqual((evidence["cancel_close"]["action"], evidence["cancel_close"]["window_still_open"]), (CANCEL, True))
        self.assertEqual((evidence["save_close"]["action"], evidence["save_close"]["window_closed"]), (SAVE, True))
        self.assertTrue(Path(evidence["save_close"]["saved_path"]).is_file())
        self.assertEqual((evidence["dont_save_close"]["action"], evidence["dont_save_close"]["spool_exists_after"]), (DISCARD, False))
        self.assertEqual(len(runtimes), 2)
        self.assertFalse(any(runtime.running for runtime in runtimes))
