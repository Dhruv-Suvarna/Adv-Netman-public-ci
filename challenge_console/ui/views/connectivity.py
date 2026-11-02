"""View 1 -- Continuous Connectivity: the status matrix on top, the per-sample history below."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ... import filters as f
from ... import models as m
from ..widgets import BAD, MUTED, OK, View, make_table, selected, sync_table

MATRIX = [("endpoint", "Endpoint", 80), ("family", "Family", 60), ("source", "Source address", 170), ("dest", "Destination", 90),
          ("target", "Target address", 170), ("state", "State", 70), ("rtt", "Last RTT", 80, tk.E), ("consec", "Consec. fails", 95, tk.E),
          ("fails", "Fails / samples", 110, tk.E), ("loss", "Loss (buffer)", 95, tk.E), ("last", "Last sample", 85),
          ("success", "Last success", 95), ("failure", "Last failure", 95), ("change", "Last change", 95), ("recent", "Recent (old > new)", 330)]
SAMPLES = [("time", "Time (UTC)", 100), ("endpoint", "Endpoint", 80), ("family", "Family", 60), ("dest", "Destination", 90),
           ("target", "Target address", 190), ("result", "Result", 70), ("rtt", "RTT", 90, tk.E), ("reason", "Reason", 220)]


class ConnectivityView(View):
    key, title = m.CONNECTIVITY, "Continuous Connectivity"

    def build(self) -> None:
        self.summary = ttk.Label(self, text="Waiting for the first probes ...", style="Summary.TLabel")
        self.summary.grid(row=0, column=0, sticky="w", pady=(0, 6))
        frame, self.matrix = make_table(self, MATRIX, height=8)
        frame.grid(row=1, column=0, sticky="nsew")
        bar = ttk.Frame(self)
        bar.grid(row=2, column=0, sticky="ew", pady=(10, 4))
        ttk.Label(bar, text="Sample history", style="Section.TLabel").pack(side=tk.LEFT)
        self.failures_only = tk.BooleanVar(value=False)
        self.selected_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Failures only", variable=self.failures_only, command=self.refresh).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Checkbutton(bar, text="Selected row only", variable=self.selected_only, command=self.refresh).pack(side=tk.LEFT, padx=(12, 0))
        self.buffer = ttk.Label(bar, text="", style="Muted.TLabel")
        self.buffer.pack(side=tk.RIGHT)
        frame, self.samples = make_table(self, SAMPLES, height=12)
        frame.grid(row=3, column=0, sticky="nsew")
        self.rowconfigure(1, weight=1)
        self.rowconfigure(3, weight=2)
        self.columnconfigure(0, weight=1)
        self.matrix.bind("<<TreeviewSelect>>", lambda _event: self.refresh() if self.selected_only.get() else None)

    def render(self) -> None:
        rows = sorted(self.store.probe_rows(), key=lambda row: (row.spec.source, row.spec.family))
        table, up, span = [], 0, 0.0
        for row in rows:
            history = self.store.probe_history(row.spec.key)
            span = max(span, self.store.history_span_seconds(row.spec.key))
            loss = f.loss_percent(history)
            up += row.state == m.UP
            tag = OK if row.state == m.UP else BAD if row.state == m.DOWN else MUTED
            table.append((row.spec.key, (
                row.spec.source, "IPv4" if row.spec.family == m.V4 else "IPv6", row.source_address or "-", row.spec.destination,
                row.target_address or "-", row.state, "-" if row.last_rtt_ms is None else f"{row.last_rtt_ms:.2f} ms",
                row.consecutive_failures, f"{row.failures} / {row.samples}", "-" if loss is None else f"{loss:.1f} %",
                f.fmt_time(row.last_ts), f.fmt_time(row.last_success), f.fmt_time(row.last_failure), f.fmt_time(row.last_change),
                f.sparkline(history)), tag))
        sync_table(self.matrix, table)
        down = [row.spec.key for row in rows if row.state == m.DOWN]
        self.summary.configure(
            text=f"{up} / {len(rows)} required paths UP" + (f"   DOWN: {', '.join(down)}" if down else "")
                 + f"     one ICMP echo per path every {self.cfg.connectivity_interval:g} s",
            foreground="#b3261e" if down else "#1b7f3b" if rows and up == len(rows) else "")
        self.buffer.configure(text=f"in-memory history {f.fmt_duration(span)} of {f.fmt_duration(self.cfg.retention_seconds)} retained")
        key = selected(self.matrix) if self.selected_only.get() else None
        recent = self.store.recent_samples(limit=400, failures_only=self.failures_only.get(), key=key or None)
        sync_table(self.samples, [(f"{sample.key}@{sample.ts.timestamp():.3f}", (
            f.fmt_time(sample.ts), sample.source, "IPv4" if sample.family == m.V4 else "IPv6", sample.destination, sample.target_address or "-",
            "PASS" if sample.success else "FAIL", "-" if sample.rtt_ms is None else f"{sample.rtt_ms:.2f} ms", sample.reason),
            OK if sample.success else BAD) for sample in recent])
