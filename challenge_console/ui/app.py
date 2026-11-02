"""The console window: a persistent sidebar, five stacked views, a status bar, and the Save / Don't Save / Cancel close workflow.

Navigation only raises a frame.  It does not create, destroy, start, stop or pause anything: all five views exist from start-up and
all five collectors run for the whole lifetime of ``ConsoleRuntime`` regardless of which frame is on top.
"""

from __future__ import annotations

import signal
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import APP_TITLE, VERSION
from .. import filters as f
from .. import models as m
from ..runtime import CANCEL, DISCARD, SAVE, ConsoleRuntime
from .bridge import COLLECTORS_TOPIC, UiBridge
from .views import VIEWS

STATE_COLOUR = {"RUNNING": "#1b7f3b", "STARTING": "#6b7280", "FAILING": "#b3261e", "STALLED": "#b3261e", "STOPPED": "#6b7280"}
LABELS = {m.CONNECTIVITY: "Connectivity", m.SERVICES: "Telemetry", m.NSOT: "NSOT", m.AUTOMATION: "Automation", m.COUNTERS: "Counters"}


class CloseDialog(tk.Toplevel):
    """Modal, three explicit choices.  ``result`` is (action, destination): save / discard / cancel."""

    def __init__(self, parent, default_destination: Path, log_status: dict):
        super().__init__(parent)
        self.title("Close the console?")
        self.transient(parent)
        self.resizable(False, False)
        self.result: tuple[str, Path | None] = (CANCEL, None)
        self.destination = Path(default_destination)
        body = ttk.Frame(self, padding=16)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="Save this session before closing?", style="Section.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(body, text=f"The session log holds {log_status['written'] + log_status['pending']:,} recorded events "
                             "(probes, service and telemetry observations, NSOT and automation snapshots, counters, errors).",
                  wraplength=560, justify=tk.LEFT).grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 8))
        ttk.Label(body, text="Save to:", style="Muted.TLabel").grid(row=2, column=0, sticky="w")
        self.path_label = ttk.Label(body, text=str(self.destination), wraplength=430, justify=tk.LEFT)
        self.path_label.grid(row=2, column=1, columnspan=2, sticky="w", padx=(6, 6))
        ttk.Button(body, text="Change...", command=self._choose).grid(row=2, column=3, sticky="e")
        buttons = ttk.Frame(body)
        buttons.grid(row=3, column=0, columnspan=4, sticky="e", pady=(16, 0))
        self.save_button = ttk.Button(buttons, text="Save", command=lambda: self._finish(SAVE))
        self.discard_button = ttk.Button(buttons, text="Don't Save", command=lambda: self._finish(DISCARD))
        self.cancel_button = ttk.Button(buttons, text="Cancel", command=lambda: self._finish(CANCEL))
        for button in (self.save_button, self.discard_button, self.cancel_button):
            button.pack(side=tk.LEFT, padx=(8, 0))
        self.protocol("WM_DELETE_WINDOW", lambda: self._finish(CANCEL))      # closing the dialog is Cancel, never a silent discard
        self.bind("<Escape>", lambda _e: self._finish(CANCEL))
        self.save_button.focus_set()

    def _choose(self) -> None:
        chosen = filedialog.asksaveasfilename(parent=self, initialdir=str(self.destination.parent), initialfile=self.destination.name,
                                              defaultextension=".jsonl", filetypes=[("JSON Lines session log", "*.jsonl"), ("All files", "*")])
        if chosen:
            self.destination = Path(chosen)
            self.path_label.configure(text=str(self.destination))

    def _finish(self, action: str) -> None:
        self.result = (action, self.destination if action == SAVE else None)
        self.destroy()

    def ask(self) -> tuple[str, Path | None]:
        try:
            self.grab_set()                  # modal; a window manager that refuses the grab still gets a working dialog
        except tk.TclError:
            pass
        self.wait_window(self)
        return self.result


class ConsoleApp:
    def __init__(self, runtime: ConsoleRuntime, *, root: tk.Tk | None = None, close_chooser=None):
        self.runtime = runtime
        self.root = root or tk.Tk()
        self.root.title(f"{APP_TITLE} {VERSION} -- read-only")
        self.root.geometry("1500x900")
        self.root.minsize(1100, 650)
        self._close_chooser = close_chooser or self._ask_close
        self.closed = False
        self.close_result: tuple[str, Path | None] | None = None
        self.saved_path: Path | None = None
        self._external_stop = False
        self._dirty: set[str] = set()
        self._ticks = 0
        self._style()
        self._build()
        self.bridge = UiBridge(self.root, runtime.bus, self._on_topics)
        self.root.protocol("WM_DELETE_WINDOW", self.request_close)
        self.show(VIEWS[0].key)

    # --- construction -----------------------------------------------------------------------------------------------------------
    def _style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Sidebar.TFrame", background="#1f2937")
        style.configure("SidebarTitle.TLabel", background="#1f2937", foreground="#f9fafb", font=("TkDefaultFont", 12, "bold"))
        style.configure("SidebarNote.TLabel", background="#1f2937", foreground="#9ca3af")
        style.configure("Nav.TButton", anchor="w", padding=(12, 9))
        style.configure("NavActive.TButton", anchor="w", padding=(12, 9), font=("TkDefaultFont", 10, "bold"))
        style.map("NavActive.TButton", background=[("!disabled", "#bfdbfe")])
        style.configure("Summary.TLabel", font=("TkDefaultFont", 11, "bold"))
        style.configure("Section.TLabel", font=("TkDefaultFont", 10, "bold"))
        style.configure("Muted.TLabel", foreground="#6b7280")
        style.configure("Treeview", rowheight=22)

    def _build(self) -> None:
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        sidebar = ttk.Frame(self.root, style="Sidebar.TFrame", padding=(10, 14))
        sidebar.grid(row=0, column=0, sticky="ns")
        ttk.Label(sidebar, text="NMAS Console", style="SidebarTitle.TLabel").pack(anchor="w", pady=(0, 2))
        ttk.Label(sidebar, text="observation only", style="SidebarNote.TLabel").pack(anchor="w", pady=(0, 14))
        content = ttk.Frame(self.root)
        content.grid(row=0, column=1, sticky="nsew")
        content.rowconfigure(0, weight=1)
        content.columnconfigure(0, weight=1)
        self.views, self.nav = {}, {}
        for index, view_class in enumerate(VIEWS, start=1):
            view = view_class(content, self.runtime)
            view.grid(row=0, column=0, sticky="nsew")
            self.views[view.key] = view
            button = ttk.Button(sidebar, text=f"{index}  {view.title}", style="Nav.TButton", width=24, command=lambda key=view.key: self.show(key))
            button.pack(fill=tk.X, pady=2)
            self.nav[view.key] = button
            self.root.bind(f"<Control-Key-{index}>", lambda _e, key=view.key: self.show(key))
        ttk.Label(sidebar, text="Collectors (always running)", style="SidebarNote.TLabel").pack(anchor="w", pady=(22, 4))
        self.collector_labels = {}
        for name in m.COLLECTORS:
            label = tk.Label(sidebar, text=f"{LABELS[name]}: starting", bg="#1f2937", fg="#9ca3af", anchor="w", justify=tk.LEFT)
            label.pack(fill=tk.X)
            self.collector_labels[name] = label
        status = ttk.Frame(self.root, padding=(8, 4))
        status.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_left = ttk.Label(status, text="")
        self.status_left.pack(side=tk.LEFT)
        self.status_right = ttk.Label(status, text="", style="Muted.TLabel")
        self.status_right.pack(side=tk.RIGHT)

    # --- navigation -------------------------------------------------------------------------------------------------------------
    def show(self, key: str) -> None:
        """Raise one view.  Nothing else changes: no collector is touched and no history is reset."""
        self.visible = key
        self.views[key].tkraise()
        for name, button in self.nav.items():
            button.configure(style="NavActive.TButton" if name == key else "Nav.TButton")
        self.views[key].refresh()
        self._dirty.discard(key)

    # --- the Tk-thread side of the bridge -----------------------------------------------------------------------------------------
    def _on_topics(self, topics: set[str]) -> None:
        if self._external_stop:
            self._shutdown(SAVE, None, keep_in_spool=True)
            return
        self._dirty |= topics
        self._ticks += 1
        tick = self._ticks % 3 == 0                      # about once a second: ages / elapsed times move even without new data
        if self.visible in self._dirty or tick:
            self._dirty.discard(self.visible)
            self.views[self.visible].refresh()           # only the visible view is drawn; hidden ones keep collecting into the store
        if COLLECTORS_TOPIC in self._dirty or tick:
            self._dirty.discard(COLLECTORS_TOPIC)
            self._render_status()

    def _render_status(self) -> None:
        statuses = self.runtime.store.collector_status()
        for name, label in self.collector_labels.items():
            status = statuses.get(name)
            if status is None:
                continue
            extra = f"  err {status.errors}" if status.errors else ""
            label.configure(text=f"{LABELS[name]}: {status.state.lower()}  #{status.cycles}{extra}", fg={"#1b7f3b": "#86efac", "#b3261e": "#fca5a5"}.get(
                STATE_COLOUR.get(status.state, ""), "#9ca3af"))
        log = self.runtime.log.status()
        uptime = (m.utcnow() - self.runtime.store.started_at).total_seconds()
        self.status_left.configure(text=f"Session {self.runtime.log.session_id}   up {f.fmt_duration(uptime)}   "
                                        f"{log['written']:,} events logged" + (f"   LOG WRITE FAILED ({log['failed']})" if log["failed"] else ""))
        self.status_right.configure(text=f"append-only log: {log['path']}")

    # --- closing ----------------------------------------------------------------------------------------------------------------
    def _ask_close(self, _app) -> tuple[str, Path | None]:
        return CloseDialog(self.root, self.runtime.log.default_destination(self.runtime.config.save_dir), self.runtime.log.status()).ask()

    def request_close(self) -> str:
        """The window-close handler.  Never exits by itself: the operator chooses Save, Don't Save or Cancel."""
        if self.closed:
            return CANCEL
        action, destination = self.close_result = self._close_chooser(self)
        if action not in (SAVE, DISCARD):
            return CANCEL                                 # collectors were never touched; the console simply carries on
        self._shutdown(action, destination)
        return action

    def _shutdown(self, action: str, destination: Path | None, *, keep_in_spool: bool = False) -> None:
        self.closed = True
        self.bridge.stop()
        self.status_left.configure(text="Stopping collectors and flushing the session log ...")
        self.root.update_idletasks()
        try:
            if keep_in_spool:
                self.runtime.stop()
                self.saved_path = Path(self.runtime.log.path)
            else:
                self.saved_path = self.runtime.finish(action, destination)
        except OSError:
            self.runtime.stop()
            self.saved_path = Path(self.runtime.log.path)
            messagebox.showerror("Save failed", f"The session could not be written to the chosen location.\nIt is kept at:\n{self.saved_path}",
                                 parent=self.root)
        finally:
            self.root.destroy()

    def stop_from_signal(self, *_args) -> None:
        self._external_stop = True                        # acted on by the next pump, on the Tk thread

    def start(self) -> None:
        self.runtime.start()
        self.bridge.start()


def run(config=None) -> int:
    runtime = ConsoleRuntime(config)
    try:
        app = ConsoleApp(runtime)
    except tk.TclError as exc:
        runtime.finish(DISCARD)
        print(f"Cannot open a display: {exc}\nRun on the desktop session, or use --headless.", flush=True)
        return 2
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, app.stop_from_signal)
    app.start()
    try:
        app.root.mainloop()
    finally:
        leftover = runtime.stop()                         # no-op after a normal close; the safety net for any other exit
    if app.saved_path:
        print(f"Session saved: {app.saved_path}", flush=True)
    return 1 if leftover else 0
