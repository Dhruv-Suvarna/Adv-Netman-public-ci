"""View 3 -- NSOT: NetBox's structured state (devices, interfaces, addresses, prefixes, VLANs), searchable, with consistency checks."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ... import filters as f
from ... import models as m
from ..widgets import BAD, MUTED, OK, View, make_table, selected, sync_table

DEVICES = [("name", "Device", 100), ("role", "Role", 170), ("platform", "Platform / type", 150), ("status", "Status", 70), ("scope", "Scope", 90),
           ("v4", "Management IPv4", 150), ("v6", "Management IPv6", 190), ("ifs", "Ifaces", 60, tk.E), ("addrs", "Addrs", 60, tk.E),
           ("mgmt", "Mgmt addr vs inventory", 160), ("scopecheck", "Scope vs inventory", 130), ("runtime", "Lab container", 110)]
DETAIL = [("interface", "Interface", 130), ("type", "Type", 110), ("enabled", "Enabled", 70), ("mgmt", "Mgmt only", 80),
          ("address", "Assigned address", 230), ("family", "Family", 60), ("status", "Status", 80), ("role", "Role", 90), ("description", "Description", 420)]
PREFIXES = [("prefix", "Prefix", 220), ("status", "Status", 90), ("role", "Role", 130), ("vlan", "VLAN", 150), ("vrf", "VRF", 100),
            ("description", "Description", 640)]
VLANS = [("vid", "VID", 60, tk.E), ("name", "Name", 180), ("status", "Status", 90), ("role", "Role", 130), ("description", "Description", 760)]


class NsotView(View):
    key, title = m.NSOT, "NSOT"

    def build(self) -> None:
        self.summary = ttk.Label(self, text="Waiting for the first NetBox read ...", style="Summary.TLabel")
        self.summary.grid(row=0, column=0, sticky="w", pady=(0, 6))
        bar = ttk.Frame(self)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        self.search, self.role, self.scope = tk.StringVar(), tk.StringVar(value="All"), tk.StringVar(value="All")
        ttk.Label(bar, text="Search").pack(side=tk.LEFT)
        entry = ttk.Entry(bar, textvariable=self.search, width=32)
        entry.pack(side=tk.LEFT, padx=(6, 14))
        ttk.Label(bar, text="Role").pack(side=tk.LEFT)
        self.role_box = ttk.Combobox(bar, textvariable=self.role, values=("All",), state="readonly", width=24)
        self.role_box.pack(side=tk.LEFT, padx=(6, 14))
        ttk.Label(bar, text="Scope").pack(side=tk.LEFT)
        scope_box = ttk.Combobox(bar, textvariable=self.scope, values=f.SCOPE_FILTERS, state="readonly", width=12)
        scope_box.pack(side=tk.LEFT, padx=(6, 0))
        self.search.trace_add("write", lambda *_: self.refresh())
        self.role_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        scope_box.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        book = ttk.Notebook(self)
        book.grid(row=2, column=0, sticky="nsew")
        devices_tab = ttk.Frame(book)
        frame, self.devices = make_table(devices_tab, DEVICES, height=12)
        frame.grid(row=0, column=0, sticky="nsew")
        self.detail_title = ttk.Label(devices_tab, text="Select a device to see its interfaces and assigned addresses", style="Section.TLabel")
        self.detail_title.grid(row=1, column=0, sticky="w", pady=(8, 2))
        frame, self.detail = make_table(devices_tab, DETAIL, height=10)
        frame.grid(row=2, column=0, sticky="nsew")
        devices_tab.rowconfigure(0, weight=1)
        devices_tab.rowconfigure(2, weight=1)
        devices_tab.columnconfigure(0, weight=1)
        self.devices.bind("<<TreeviewSelect>>", lambda _e: self._render_detail())
        frame_p, self.prefixes = make_table(book, PREFIXES, height=20)
        frame_v, self.vlans = make_table(book, VLANS, height=20)
        book.add(devices_tab, text="Devices")
        book.add(frame_p, text="Prefixes")
        book.add(frame_v, text="VLANs")
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)
        self._snapshot: dict = {}

    def render(self) -> None:
        document = self.store.document(m.NSOT)
        data = self._snapshot = document.get("data") or {}
        counts, lab = data.get("counts") or {}, data.get("lab") or {}
        if document["available"]:
            text = (f"NetBox (read-only) refreshed {f.fmt_time(document['ts'])}: {counts.get('devices', 0)} devices, {counts.get('interfaces', 0)} interfaces, "
                    f"{counts.get('addresses', 0)} addresses, {counts.get('prefixes', 0)} prefixes, {counts.get('vlans', 0)} VLANs"
                    f"     lab containers running: {lab.get('running', '?')} / {lab.get('expected', '?')}")
            colour = ""
        elif document["stale"]:
            text = (f"NetBox unavailable ({document['reason']}) at {f.fmt_time(document['ts'])} -- showing the STALE snapshot from "
                    f"{f.fmt_time(document.get('last_ok'))}")
            colour = "#b3261e"
        else:
            text, colour = f"NetBox: {document['reason']}" + (f" ({f.fmt_time(document['ts'])})" if document["ts"] else ""), "#b3261e" if document["ts"] else ""
        self.summary.configure(text=text, foreground=colour)
        devices = data.get("devices") or []
        roles = ("All", *sorted({device["role"] for device in devices if device["role"]}))
        if tuple(self.role_box.cget("values")) != roles:
            self.role_box.configure(values=roles)
        checks = {row["device"]: row for row in data.get("consistency") or []}
        rows = []
        for device in f.filter_devices(devices, text=self.search.get(), role=self.role.get(), scope=self.scope.get()):
            check = checks.get(device["name"], {})
            bad = "MISMATCH" in (check.get("management_address"), check.get("managed_scope")) or check.get("runtime") == "NOT_RUNNING"
            scope = "managed" if device["managed"] is True else "unmanaged" if device["managed"] is False else "untagged"
            rows.append((device["name"], (
                device["name"], device["role"] or "-", device["platform"] or device["device_type"] or "-", device["status"] or "-", scope,
                device["primary_ip4"] or "-", device["primary_ip6"] or "-", len(device["interfaces"]), device["address_count"],
                check.get("management_address", "-"), check.get("managed_scope", "-"), check.get("runtime", "-")),
                BAD if bad else MUTED if device["managed"] is False else OK if document["available"] else MUTED))
        sync_table(self.devices, rows)
        sync_table(self.prefixes, [(f"p{index}", (p["prefix"], p["status"], p["role"], p["vlan"], p["vrf"], p["description"]), "")
                                   for index, p in enumerate(data.get("prefixes") or [])])
        sync_table(self.vlans, [(f"v{index}", (v["vid"], v["name"], v["status"], v["role"], v["description"]), "")
                                for index, v in enumerate(data.get("vlans") or [])])
        self._render_detail()

    def _render_detail(self) -> None:
        name = selected(self.devices)
        device = next((d for d in self._snapshot.get("devices") or [] if d["name"] == name), None)
        if device is None:
            sync_table(self.detail, [])
            self.detail_title.configure(text="Select a device to see its interfaces and assigned addresses")
            return
        self.detail_title.configure(text=f"{name}: interfaces and assigned addresses (NetBox)")
        rows = []
        for interface in device["interfaces"]:
            base = (interface["name"], interface["type"], "yes" if interface["enabled"] else "no", "yes" if interface["mgmt_only"] else "")
            if not interface["addresses"]:
                rows.append((f"{interface['name']}#", (*base, "-", "", "", "", interface["description"]), MUTED))
            for address in interface["addresses"]:
                rows.append((f"{interface['name']}#{address['address']}", (*base, address["address"], address["family"], address["status"],
                                                                         address["role"], address["description"] or interface["description"]), ""))
        sync_table(self.detail, rows)
