"""Automation status: periodic read-only snapshots of the NMAS automation records, through ``adapters/automation_db``.

This collector observes.  It has no method that changes anything, and the adapter beneath it cannot write (see its docstring).
The soak is described from what the database says NOW: its state is read every cycle, never assumed to stay RUNNING.
"""

from __future__ import annotations

from .. import models as m
from ..adapters import automation_db
from ..supervisor import Collector, CollectorError


class AutomationCollector(Collector):
    name = m.AUTOMATION

    def __init__(self, config, store, bus, *, reader=automation_db.read_snapshot):
        super().__init__(config, store, bus, interval=config.automation_interval)
        self._reader = reader
        self._soak_states: dict[str, tuple] = {}

    def collect(self) -> None:
        now = m.utcnow()
        try:
            snapshot = self._reader(self.config.automation_db_path, now=now, limit=self.config.automation_rows,
                                    busy_timeout=self.config.db_busy_timeout)
        except automation_db.AutomationUnavailable as exc:
            self.store.fail_document(m.AUTOMATION, ts=now, reason=exc.code)
            raise CollectorError(exc.code, "automation-db") from None
        self.store.set_document(m.AUTOMATION, ts=now, data=snapshot)
        self.emit("automation.snapshot", target="automation-db", outcome=m.OK, ts=now, data={
            "counts": {name: len(rows) for name, rows in snapshot.items() if isinstance(rows, list)},
            "soaks": [{k: soak[k] for k in ("soak_id", "state", "result", "bundle_id", "devices", "due_at", "remaining_seconds", "samples",
                                            "drift_state", "health")} | {"collector": soak["collector"]["state"],
                                                                         "eligibility": soak["eligibility"]["code"]}
                      for soak in snapshot["soaks"]],
            "latest_execution": ({k: snapshot["executions"][0][k] for k in ("run_id", "change_id", "mode", "state", "outcome")}
                                 if snapshot["executions"] else None),
            "latest_traffic": ({k: snapshot["traffic"][0][k] for k in ("run_id", "source", "destination", "family", "status")}
                               if snapshot["traffic"] else None),
        })
        for soak in snapshot["soaks"]:
            marker = (soak["state"], soak["result"], soak["collector"]["state"], soak["drift_state"], soak["eligibility"]["code"])
            before = self._soak_states.get(soak["soak_id"])
            if before is not None and before != marker:
                self.emit("automation.soak_change", target=soak["soak_id"], ts=now,
                          outcome=m.OK if soak["state"] == "RUNNING" and soak["collector"]["state"] == automation_db.FRESH else m.INFO,
                          data={"from": list(before), "to": list(marker)})
            self._soak_states[soak["soak_id"]] = marker
