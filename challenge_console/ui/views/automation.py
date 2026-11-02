"""View 4 -- Automation: status and history of NMAS automation, read-only.

There is no control on this page that starts, approves, executes, rolls back, provisions, rotates or promotes anything -- only
tables and labels.  ``tests/test_ui.py`` walks the widget tree to keep it that way.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ... import filters as f
from ... import models as m
from ..widgets import BAD, MUTED, OK, WARN, View, make_table, sync_table

GOOD = {"PASS", "PASSED", "SUCCEEDED", "SUCCESS", "FRESH", "MATCH", "HEALTHY", "RUNNING", "FINISHED", "COMPLETE", "COMPLETED", "ACTIVE"}
POOR = {"FAIL", "FAILED", "BLOCKED", "INVALIDATED", "TIMED_OUT", "INTERRUPTED", "ROLLED_BACK", "DRIFT", "STALE", "ERROR", "CANCELLED"}
TABS = (
    ("executions", "Executions", [("change_id", "Change", 150), ("mode", "Mode", 90), ("state", "State", 90), ("outcome", "Outcome", 110),
                                  ("actor", "Actor", 110), ("started_at", "Started (UTC)", 160), ("finished_at", "Finished (UTC)", 160),
                                  ("run_id", "Run", 280)], "outcome"),
    ("changes", "Changes", [("change_id", "Change", 150), ("title", "Title", 330), ("category", "Category", 190), ("execution_mode", "Mode", 90),
                            ("lifecycle_state", "Lifecycle", 110), ("validation_state", "Validation", 100), ("created_by", "By", 110),
                            ("updated_at", "Updated (UTC)", 160)], "lifecycle_state"),
    ("validations", "Validation", [("change_id", "Change", 150), ("status", "Status", 110), ("created_by", "By", 150),
                                   ("created_at", "Created (UTC)", 160), ("run_id", "Run", 280)], "status"),
    ("config_validations", "Config validation", [("change_id", "Change", 150), ("operation_type", "Operation", 150), ("status", "Status", 110),
                                                 ("device", "Device", 90), ("platform", "Platform", 110), ("created_at", "Created (UTC)", 160),
                                                 ("run_id", "Run", 280)], "status"),
    ("checks", "Precheck / postcheck", [("change_id", "Change", 150), ("mode", "Check", 170), ("status", "Status", 120), ("device", "Device", 90),
                                        ("started_at", "Started (UTC)", 160), ("finished_at", "Finished (UTC)", 160), ("run_id", "Run", 280)], "status"),
    ("bundles", "Bundles", [("bundle_id", "Bundle", 150), ("kind", "Kind", 110), ("provenance", "Provenance", 160), ("parent", "Parent", 150),
                            ("change_id", "Change", 150), ("created_by", "By", 110), ("created_at", "Created (UTC)", 160)], ""),
    ("traffic", "Traffic runs", [("source", "Source", 80), ("destination", "Destination", 90), ("address_family", "Family", 70),
                                 ("family", "Test", 100), ("protocol", "Protocol", 80), ("status", "Status", 100), ("failure_reason", "Failure", 170),
                                 ("operator", "Operator", 100), ("started_at", "Started (UTC)", 160), ("finished_at", "Finished (UTC)", 160)], "status"),
    ("provisioning", "Provisioning", [("device_name", "Device", 120), ("platform", "Platform", 110), ("role", "Role", 100), ("status", "Status", 150),
                                      ("bootstrap_state", "Bootstrap", 170), ("requested_by", "By", 110), ("created_at", "Created (UTC)", 160),
                                      ("finished_at", "Finished (UTC)", 160)], "status"),
    ("rotation_runs", "Credential rotation", [("device_name", "Device", 100), ("username", "Account", 140), ("trigger_reason", "Trigger", 100),
                                              ("phase", "Phase", 110), ("final_status", "Status", 100), ("error_category", "Error", 150),
                                              ("started_at", "Started (UTC)", 160), ("completed_at", "Completed (UTC)", 160)], "final_status"),
    ("rotation_policy", "Rotation schedule", [("device_name", "Device", 100), ("username", "Account", 140), ("account_kind", "Kind", 110),
                                              ("rotation_interval_days", "Every (days)", 100), ("last_rotated_at", "Last rotated (UTC)", 160),
                                              ("next_due_at", "Next due (UTC)", 160), ("last_status", "Last status", 110)], "last_status"),
)
SOAK_FIELDS = (("soak", "Soak"), ("bundle", "Probation bundle"), ("devices", "Device(s)"), ("state", "State"), ("started", "Started"),
               ("due", "Due"), ("elapsed", "Elapsed"), ("remaining", "Remaining"), ("collector", "Collector freshness"),
               ("sample", "Last sample"), ("drift", "Configuration drift"), ("health", "Health"), ("eligibility", "Golden eligibility"))
WIDE = ("collector", "sample", "drift", "eligibility")


def _tag(value) -> str:
    text = str(value or "").upper()
    return OK if text in GOOD else BAD if text in POOR else ""


class AutomationView(View):
    key, title = m.AUTOMATION, "Automation"

    def build(self) -> None:
        self.summary = ttk.Label(self, text="Waiting for the first read ...", style="Summary.TLabel")
        self.summary.grid(row=0, column=0, sticky="w", pady=(0, 6))
        box = ttk.LabelFrame(self, text="Probation soak (observed, read-only)", padding=8)
        box.grid(row=1, column=0, sticky="ew")
        self.soak_values: dict[str, ttk.Label] = {}
        short = [item for item in SOAK_FIELDS if item[0] not in WIDE]
        for index, (key, label) in enumerate(short):                          # short facts in two columns ...
            row, column = divmod(index, 2)
            ttk.Label(box, text=label + ":", style="Muted.TLabel").grid(row=row, column=column * 2, sticky="w", padx=(0, 8), pady=1)
            value = ttk.Label(box, text="-")
            value.grid(row=row, column=column * 2 + 1, sticky="w", padx=(0, 40), pady=1)
            self.soak_values[key] = value
        for offset, key in enumerate(WIDE):                                   # ... long ones on full-width rows, so nothing is cut off
            row = (len(short) + 1) // 2 + offset
            ttk.Label(box, text=dict(SOAK_FIELDS)[key] + ":", style="Muted.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=1)
            value = ttk.Label(box, text="-")
            value.grid(row=row, column=1, columnspan=3, sticky="w", pady=1)
            self.soak_values[key] = value
        book = ttk.Notebook(self)
        book.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        self.tables: dict[str, ttk.Treeview] = {}
        for key, title, columns, _status in TABS:
            frame, table = make_table(book, columns, height=12)
            book.add(frame, text=title)
            self.tables[key] = table
        self.rowconfigure(2, weight=1)
        self.columnconfigure(0, weight=1)

    def render(self) -> None:
        document = self.store.document(m.AUTOMATION)
        data = document.get("data") or {}
        if document["available"]:
            golden = data.get("golden")
            text = (f"NMAS automation records (read-only database, mode=ro) refreshed {f.fmt_time(document['ts'])}"
                    f"     current Golden: {golden['bundle_id'] if golden else 'none'}")
            colour = ""
        elif document["stale"]:
            text = (f"Automation database unavailable ({document['reason']}) at {f.fmt_time(document['ts'])} -- showing the STALE read from "
                    f"{f.fmt_time(document.get('last_ok'))}")
            colour = "#b3261e"
        else:
            text, colour = f"Automation database: {document['reason']}", "#b3261e" if document["ts"] else ""
        self.summary.configure(text=text, foreground=colour)
        self._render_soak(data.get("soaks") or [], stale=not document["available"])
        for key, _title, columns, status in TABS:
            names = [column[0] for column in columns]
            sync_table(self.tables[key], [(f"{key}{index}", tuple(
                f.fmt_iso(row.get(name) or "") if name.endswith("_at") else ("-" if row.get(name) in (None, "") else row.get(name)) for name in names),
                _tag(row.get(status)) if status else "") for index, row in enumerate(data.get(key) or [])])

    def _render_soak(self, soaks: list, *, stale: bool) -> None:
        soak = next((s for s in soaks if s["state"] == "RUNNING"), soaks[0] if soaks else None)
        if soak is None:
            for label in self.soak_values.values():
                label.configure(text="-", foreground="")
            self.soak_values["soak"].configure(text="no probation soak recorded")
            return
        # elapsed / remaining keep moving between database reads: they are recomputed from the recorded start / due instants
        now, started, due = m.utcnow(), m.parse_time(soak["started_at"]), m.parse_time(soak["due_at"])
        live = soak["state"] == "RUNNING" and started and due
        elapsed = min((now - started).total_seconds(), soak["duration_seconds"]) if live else soak["elapsed_seconds"]
        remaining = max(0.0, (due - now).total_seconds()) if live else soak["remaining_seconds"]
        collector, sample = soak["collector"], soak["latest_sample"]
        values = {
            "soak": (soak["soak_id"] + (f"  (change {soak['change_id']})" if soak["change_id"] else ""), ""),
            "bundle": (soak["bundle_id"] + (f"  (root {soak['root_bundle']})" if soak["root_bundle"] else ""), ""),
            "devices": (", ".join(soak["devices"]) or "-", ""),
            "state": (soak["state"] + (f" / {soak['result']}" if soak["result"] else "") + (f" ({soak['terminal_reason']})" if soak["terminal_reason"] else ""),
                      _tag(soak["state"])),
            "started": (f.fmt_iso(soak["started_at"]), ""), "due": (f.fmt_iso(soak["due_at"]), ""),
            "elapsed": (f"{f.fmt_duration(elapsed)}" + (f"  ({100.0 * elapsed / soak['duration_seconds']:.2f} %)" if soak["duration_seconds"] else ""), ""),
            "remaining": (f.fmt_duration(remaining), ""),
            "collector": (f"{collector['state']}  (last sample {f.fmt_iso(collector['last_sample_at'])}, expected every "
                          f"{collector['expected_every_seconds']} s; {soak['samples']} samples)", _tag(collector["state"])),
            "sample": ((f"{sample['result']}  (bucket {sample['bucket']}; expected state {sample['expected_state']}; telemetry "
                        f"{sample['telemetry_freshness']}; integrity {'ok' if sample['integrity_ok'] else 'FAILED'})", _tag(sample["result"]))
                       if sample else ("no sample yet", MUTED)),
            "drift": (soak["drift_state"] + "   " + ", ".join(f"{d['device']} {d['state']} ({d['current'] or d['baseline']})" for d in soak["drift"]),
                      _tag(soak["drift_state"])),
            "health": (soak["health"] or "-", _tag(soak["health"])),
            "eligibility": (f"{soak['eligibility']['code']} -- {soak['eligibility']['text']}",
                            WARN if soak["eligibility"]["code"] == "IN_PROBATION" else _tag(soak["state"])),
        }
        colours = {OK: "#1b7f3b", BAD: "#b3261e", WARN: "#9a6700", MUTED: "#6b7280", "": ""}
        for key, (text, tag) in values.items():
            self.soak_values[key].configure(text=text + ("   [stale]" if stale and key == "state" else ""), foreground=colours[tag])
