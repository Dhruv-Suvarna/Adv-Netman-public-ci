"""View 2 -- NMAS / Telemetry: observed component state, and telemetry freshness per device."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ... import filters as f
from ... import models as m
from ..widgets import BAD, MUTED, OK, WARN, View, make_table, sync_table

COMPONENTS = [("component", "Component", 240), ("state", "State", 90), ("observed", "Observed (UTC)", 100), ("since", "In this state since", 130),
              ("lastup", "Last seen UP", 110), ("latency", "Response", 80, tk.E), ("evidence", "Evidence", 620)]
FRESHNESS = [("device", "Device", 100), ("scope", "Scope", 90), ("freshness", "Freshness", 90), ("age", "Age", 80, tk.E),
             ("last", "Latest telemetry sample (UTC)", 200), ("health", "Health", 90), ("cpu", "CPU %", 70, tk.E), ("mem", "Memory %", 80, tk.E)]
STATE_TAG = {m.UP: OK, m.DOWN: BAD, m.DEGRADED: WARN, m.UNKNOWN: MUTED}
FRESH_TAG = {"FRESH": OK, "STALE": WARN, "EXPIRED": BAD, "UNKNOWN": MUTED}


class TelemetryView(View):
    key, title = m.SERVICES, "NMAS / Telemetry"

    def build(self) -> None:
        self.summary = ttk.Label(self, text="Waiting for the first observation ...", style="Summary.TLabel")
        self.summary.grid(row=0, column=0, sticky="w", pady=(0, 6))
        frame, self.components = make_table(self, COMPONENTS, height=12)
        frame.grid(row=1, column=0, sticky="nsew")
        ttk.Label(self, text="Telemetry freshness", style="Section.TLabel").grid(row=2, column=0, sticky="w", pady=(10, 2))
        self.freshness_note = ttk.Label(self, text="", style="Muted.TLabel")
        self.freshness_note.grid(row=3, column=0, sticky="w", pady=(0, 4))
        frame, self.freshness = make_table(self, FRESHNESS, height=10)
        frame.grid(row=4, column=0, sticky="nsew")
        self.rowconfigure(1, weight=1)
        self.rowconfigure(4, weight=1)
        self.columnconfigure(0, weight=1)

    def render(self) -> None:
        services = self.store.services()
        table, down = [], []
        for entry in services:
            obs = entry["observation"]
            if obs.state != m.UP:
                down.append(f"{obs.label.split(' (')[0]}: {obs.state}")
            table.append((obs.component, (obs.label, obs.state, f.fmt_time(obs.ts), f.fmt_time(entry["since"]), f.fmt_time(entry["last_up"]),
                                          "-" if obs.latency_ms is None else f"{obs.latency_ms:.0f} ms", obs.detail), STATE_TAG.get(obs.state, MUTED)))
        sync_table(self.components, table)
        if services:
            up = sum(1 for entry in services if entry["observation"].state == m.UP)
            self.summary.configure(text=f"{up} / {len(services)} components UP" + ("     " + "   ".join(down) if down else ""),
                                   foreground="#b3261e" if down else "#1b7f3b")
        telemetry = self.store.telemetry()
        thresholds = telemetry.get("thresholds") or {}
        if telemetry["available"]:
            note = (f"source: topology service (InfluxDB backend {telemetry.get('backend', '?')}), read {f.fmt_time(telemetry['ts'])}"
                    f"     FRESH <= {thresholds.get('healthy', '?'):g} s < STALE <= {thresholds.get('stale', '?'):g} s < EXPIRED; no sample = UNKNOWN")
            colour = ""
        else:
            note = (f"Telemetry source unavailable ({telemetry['reason']}) at {f.fmt_time(telemetry['ts'])}; "
                    f"last successful read {f.fmt_time(telemetry.get('last_ok'))}. Rows below are the last values read, not current.")
            colour = "#b3261e"
        self.freshness_note.configure(text=note, foreground=colour)
        now = m.utcnow()
        sync_table(self.freshness, [(row.device, (
            row.device, "managed" if row.managed else "unmanaged", row.freshness if telemetry["available"] else f"({row.freshness})",
            "-" if row.last_sample is None else f.fmt_age(row.last_sample, now), f.fmt_time(row.last_sample, date=True), row.health or "-",
            "-" if row.cpu_percent is None else f"{row.cpu_percent:.0f}", "-" if row.memory_percent is None else f"{row.memory_percent:.1f}"),
            FRESH_TAG.get(row.freshness, MUTED) if telemetry["available"] else MUTED) for row in telemetry["rows"]])
