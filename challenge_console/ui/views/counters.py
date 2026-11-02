"""View 5 -- Interface Counters: raw counters and derived rates for every interface of every managed device, filterable."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ... import filters as f
from ... import models as m
from ..widgets import BAD, MUTED, OK, WARN, View, make_table, sync_table

COLUMNS = [("device", "Device", 80), ("name", "Interface", 120), ("admin", "Admin", 60), ("oper", "Oper", 60), ("speed", "Speed", 90, tk.E),
           ("rxbps", "RX rate", 110, tk.E), ("txbps", "TX rate", 110, tk.E), ("rxpps", "RX pkt/s", 90, tk.E), ("txpps", "TX pkt/s", 90, tk.E),
           ("rxb", "RX bytes", 130, tk.E), ("txb", "TX bytes", 130, tk.E), ("rxp", "RX packets", 110, tk.E), ("txp", "TX packets", 110, tk.E),
           ("err", "Errors rx/tx", 100, tk.E), ("drop", "Drops rx/tx", 100, tk.E), ("ts", "Sampled", 85), ("change", "Last change", 95),
           ("note", "Note", 280)]


def _pair(a, b) -> str:
    return "-" if a is None and b is None else f"{f.fmt_count(a)} / {f.fmt_count(b)}"


class CountersView(View):
    key, title = m.COUNTERS, "Interface Counters"

    def build(self) -> None:
        self.summary = ttk.Label(self, text="Waiting for the first counter read ...", style="Summary.TLabel")
        self.summary.grid(row=0, column=0, sticky="w", pady=(0, 6))
        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        self.device, self.search, self.state = tk.StringVar(value="All"), tk.StringVar(), tk.StringVar(value="All")
        ttk.Label(bar, text="Device").pack(side=tk.LEFT)
        self.device_box = ttk.Combobox(bar, textvariable=self.device, values=("All",), state="readonly", width=12)
        self.device_box.pack(side=tk.LEFT, padx=(6, 14))
        ttk.Label(bar, text="Interface").pack(side=tk.LEFT)
        ttk.Entry(bar, textvariable=self.search, width=24).pack(side=tk.LEFT, padx=(6, 14))
        ttk.Label(bar, text="Show").pack(side=tk.LEFT)
        state_box = ttk.Combobox(bar, textvariable=self.state, values=f.STATE_FILTERS, state="readonly", width=18)
        state_box.pack(side=tk.LEFT, padx=(6, 14))
        self.shown = ttk.Label(bar, text="", style="Muted.TLabel")
        self.shown.pack(side=tk.RIGHT)
        self.search.trace_add("write", lambda *_: self.refresh())
        self.device_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        state_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        frame, self.table = make_table(self, COLUMNS, height=28)
        frame.grid(row=2, column=0, sticky="nsew")
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)

    def render(self) -> None:
        devices = self.store.counter_devices()
        names = ("All", *sorted(devices))
        if tuple(self.device_box.cget("values")) != names:
            self.device_box.configure(values=names)
        failing = [f"{name} ({status['reason']})" for name, status in sorted(devices.items()) if not status.get("ok")]
        if devices:
            good = len(devices) - len(failing)
            self.summary.configure(
                text=f"{good} / {len(devices)} managed devices read" + (f"     NOT READ: {', '.join(failing)}" if failing else "")
                     + f"     every {self.cfg.counters_interval:g} s; rate = counter delta / time delta",
                foreground="#b3261e" if failing else "#1b7f3b")
        everything = self.store.interface_rows()
        now = m.utcnow()
        rows = []
        for row in f.filter_interfaces(everything, device=self.device.get(), text=self.search.get(), state=self.state.get(), now=now):
            sample = row.sample
            stale = not devices.get(sample.device, {}).get("ok", False)
            recent = row.last_change is not None and now - row.last_change <= f.RECENT_CHANGE
            note = "removed" if not row.present else "device not read; last values shown" if stale else \
                   "counter reset: no rate this interval" if row.counter_reset else (row.change_note if recent else "")
            tag = MUTED if stale or not row.present else BAD if sample.oper == m.DOWN and sample.admin == m.UP else \
                  WARN if recent else MUTED if sample.admin == m.DOWN else OK if f.carrying_traffic(row) else ""   # amber = changed in the last 5 min
            rows.append((f"{sample.device}|{sample.name}", (
                sample.device, sample.name, sample.admin, sample.oper if row.present else "GONE", f.fmt_speed(sample.speed_bps),
                f.fmt_rate(row.rx_bps), f.fmt_rate(row.tx_bps), f.fmt_rate(row.rx_pps, "pkt/s"), f.fmt_rate(row.tx_pps, "pkt/s"),
                f.fmt_count(sample.rx_bytes), f.fmt_count(sample.tx_bytes), f.fmt_count(sample.rx_packets), f.fmt_count(sample.tx_packets),
                _pair(sample.rx_errors, sample.tx_errors), _pair(sample.rx_drops, sample.tx_drops), f.fmt_time(row.ts),
                f.fmt_time(row.last_change), note), tag))
        sync_table(self.table, rows)
        self.shown.configure(text=f"showing {len(rows)} of {len(everything)} interfaces")
