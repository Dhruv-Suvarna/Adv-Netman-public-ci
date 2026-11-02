"""Scripted live proof of the real console against the real lab (read-only): ``python -m challenge_console.ui.live_proof``.

It drives the actual ``ConsoleApp`` -- the real collectors, the real views, the real close dialog -- exactly as an operator would:
open every view, leave Connectivity hidden behind other views, cancel a close, then save; and, in a second short session, close with
"Don't Save".  It writes one JSON evidence document.  It needs a display (``xvfb-run -a`` is enough) and changes nothing anywhere.
"""

from __future__ import annotations

import argparse
import collections
import json
import threading
import time
from pathlib import Path

from .. import models as m
from ..config import ConsoleConfig
from ..runtime import CANCEL, DISCARD, SAVE, ConsoleRuntime
from ..sessionlog import read_session
from .app import CloseDialog, ConsoleApp


def pump(app, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and not app.closed:
        app.root.update()
        time.sleep(0.02)


def press(app, attribute: str, delay_ms: int = 400) -> dict:
    """Open the REAL close dialog through the window-close path and press one of its three buttons."""
    seen: dict = {}

    def click():
        dialogs = [w for w in app.root.winfo_children() if isinstance(w, CloseDialog)]
        if not dialogs:
            app.root.after(100, click)
            return
        dialog = dialogs[0]
        seen["buttons"] = [dialog.save_button.cget("text"), dialog.discard_button.cget("text"), dialog.cancel_button.cget("text")]
        seen["destination"] = str(dialog.destination)
        getattr(dialog, attribute).invoke()

    app.root.after(delay_ms, click)
    seen["action"] = app.request_close()
    return seen


def table_rows(tree) -> int:
    return len(tree.get_children(""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="evidence JSON to write")
    parser.add_argument("--hidden-seconds", type=float, default=25.0, help="how long Connectivity stays hidden behind each other view")
    parser.add_argument("--warmup-seconds", type=float, default=25.0)
    args = parser.parse_args(argv)
    config = ConsoleConfig.from_env()
    evidence: dict = {"started_at": m.iso(m.utcnow()), "config": {k: v for k, v in config.public_dict().items() if k.endswith("_interval")}}

    # ---- session 1: everything, cancel, save -------------------------------------------------------------------------------
    runtime = ConsoleRuntime(config)
    app = ConsoleApp(runtime)
    app.start()
    pump(app, args.warmup_seconds)
    store = runtime.store
    evidence["collectors_running"] = {"threads": sorted(t.name for t in threading.enumerate() if t.name.startswith("console-")),
                                      "alive": runtime.supervisor.alive(),
                                      "cycles": {name: s.cycles for name, s in store.collector_status().items()}}
    views = {}
    for key, view in app.views.items():
        app.show(key)
        pump(app, 2.0)
        main_table = getattr(view, "matrix", None) or getattr(view, "components", None) or getattr(view, "devices", None) or \
            getattr(view, "table", None) or view.tables["executions"]
        views[key] = {"title": view.title, "renders": view.renders, "rows": table_rows(main_table), "summary": view.summary.cget("text")}
    evidence["views"] = views

    app.show(m.CONNECTIVITY)
    pump(app, 1.0)
    before = {row.spec.key: row.samples for row in store.probe_rows()}
    marks = {"before": before}
    for hidden_behind in (m.NSOT, m.COUNTERS):
        app.show(hidden_behind)
        pump(app, args.hidden_seconds)
        marks[f"after_{hidden_behind}_visible"] = {row.spec.key: row.samples for row in store.probe_rows()}
    app.show(m.CONNECTIVITY)
    pump(app, 1.0)
    history = store.probe_history("H1/IPV4")
    gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(history, history[1:])]
    evidence["hidden_collection"] = {
        "connectivity_sample_counts": marks, "hidden_for_seconds": 2 * args.hidden_seconds,
        "grew_while_hidden": all(marks[f"after_{m.COUNTERS}_visible"][key] > before[key] for key in before),
        "largest_gap_between_samples_seconds": round(max(gaps), 3) if gaps else None, "probe_interval_seconds": config.connectivity_interval,
        "other_collectors_cycles": {name: s.cycles for name, s in store.collector_status().items()},
        "restarts": {name: s.restarts for name, s in store.collector_status().items()}}

    rows = sorted(store.probe_rows(), key=lambda row: row.spec.key)
    evidence["connectivity"] = [{"row": row.spec.key, "destination": row.spec.destination, "source_address": row.source_address,
                                 "target_address": row.target_address, "state": row.state, "samples": row.samples, "failures": row.failures,
                                 "last_rtt_ms": row.last_rtt_ms, "last_sample": m.iso(row.last_ts)} for row in rows]
    evidence["connectivity_expectation"] = {"rows": [row.spec.key for row in rows], "h4_ipv4_row_exists": any(row.spec.key == "H4/IPV4" for row in rows)}
    evidence["services"] = {entry["observation"].component: {"state": entry["observation"].state, "evidence": entry["observation"].detail}
                            for entry in store.services()}
    telemetry = store.telemetry()
    evidence["telemetry"] = {"available": telemetry["available"], "thresholds": telemetry["thresholds"], "backend": telemetry.get("backend"),
                             "devices": {row.device: {"managed": row.managed, "freshness": row.freshness, "last_sample": m.iso(row.last_sample),
                                                      "age_seconds": None if row.age_seconds is None else round(row.age_seconds, 1)}
                                         for row in telemetry["rows"]}}
    nsot = store.document(m.NSOT)
    evidence["nsot"] = {"available": nsot["available"], "counts": nsot["data"].get("counts"), "lab": nsot["data"].get("lab"),
                        "devices": [{"name": d["name"], "role": d["role"], "managed": d["managed"], "primary_ip4": d["primary_ip4"],
                                     "primary_ip6": d["primary_ip6"], "interfaces": len(d["interfaces"]), "addresses": d["address_count"]}
                                    for d in nsot["data"].get("devices", [])],
                        "consistency": nsot["data"].get("consistency")}
    automation = store.document(m.AUTOMATION)
    evidence["automation"] = {"available": automation["available"], "soaks": automation["data"].get("soaks"),
                              "counts": {name: len(value) for name, value in automation["data"].items() if isinstance(value, list)},
                              "golden": automation["data"].get("golden")}
    interfaces = store.interface_rows()
    by_device = collections.Counter(row.sample.device for row in interfaces)
    busiest = sorted((row for row in interfaces if row.rx_bps), key=lambda row: row.rx_bps, reverse=True)[:5]
    first = {(row.sample.device, row.sample.name): row.sample.rx_bytes for row in interfaces}
    pump(app, config.counters_interval * 2 + 2)
    second = {(row.sample.device, row.sample.name): row.sample.rx_bytes for row in store.interface_rows()}
    evidence["counters"] = {"devices": dict(sorted(by_device.items())), "device_status": {n: s.get("ok") for n, s in store.counter_devices().items()},
                            "interfaces": len(interfaces), "with_rates": sum(1 for row in interfaces if row.rx_bps is not None),
                            "counters_that_changed_between_two_reads": sum(1 for key in first if first[key] is not None and second.get(key) != first[key]),
                            "busiest_rx": [{"device": row.sample.device, "interface": row.sample.name, "rx_bps": round(row.rx_bps, 1),
                                            "rx_bytes": row.sample.rx_bytes} for row in busiest]}

    cycles_before_cancel = {name: s.cycles for name, s in store.collector_status().items()}
    cancel = press(app, "cancel_button")
    pump(app, 12.0)
    evidence["cancel_close"] = {**cancel, "window_still_open": not app.closed, "runtime_running": runtime.running,
                                "collectors_advanced_after_cancel": all(s.cycles > cycles_before_cancel[name] or name == m.NSOT
                                                                        for name, s in store.collector_status().items()),
                                "cycles_before": cycles_before_cancel, "cycles_after": {name: s.cycles for name, s in store.collector_status().items()}}
    save = press(app, "save_button")
    records = read_session(app.saved_path) if app.saved_path else []
    evidence["save_close"] = {**save, "saved_path": str(app.saved_path), "window_closed": app.closed, "leftover_workers": runtime.leftover_workers,
                              "threads_after": sorted(t.name for t in threading.enumerate() if t.name.startswith("console-")),
                              "file_mode": oct(app.saved_path.stat().st_mode & 0o777) if app.saved_path else None,
                              "bytes": app.saved_path.stat().st_size if app.saved_path else 0, "records": len(records),
                              "first_last": [records[0]["kind"], records[-1]["kind"]] if records else [],
                              "kinds": dict(sorted(collections.Counter(record["kind"] for record in records).items())),
                              "collectors_in_log": sorted({record["collector"] for record in records})}

    # ---- session 2: Don't Save -------------------------------------------------------------------------------------------------
    runtime2 = ConsoleRuntime(config)
    app2 = ConsoleApp(runtime2)
    app2.start()
    pump(app2, 12.0)
    spool = Path(runtime2.log.path)
    existed = spool.exists()
    discard = press(app2, "discard_button")
    evidence["dont_save_close"] = {**discard, "spool_existed_while_running": existed, "spool_exists_after": spool.exists(),
                                   "window_closed": app2.closed, "leftover_workers": runtime2.leftover_workers,
                                   "threads_after": sorted(t.name for t in threading.enumerate() if t.name.startswith("console-")),
                                   "saved_path": app2.saved_path}
    evidence["finished_at"] = m.iso(m.utcnow())
    assert discard["action"] == DISCARD and save["action"] == SAVE and cancel["action"] == CANCEL
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(evidence, indent=2, default=str) + "\n")
    print(json.dumps({"out": args.out, "saved_session": str(app.saved_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
