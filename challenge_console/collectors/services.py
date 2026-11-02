"""NMAS / monitoring stack state and telemetry freshness.

Two independent halves per cycle, so one cannot hide the other: the component checks (every component is observed even when
another is down -- this is where "NMAS Web: DOWN" comes from) and the telemetry freshness read.
"""

from __future__ import annotations

from .. import models as m
from ..adapters import http, inventory, process, telemetry
from ..adapters import services as service_adapter
from ..supervisor import Collector


class ServiceTelemetryCollector(Collector):
    name = m.SERVICES
    backoff_on_error = False

    def __init__(self, config, store, bus, *, runner=process.run, getter=http.get, netbox_target=None, managed: set[str] | None = None):
        super().__init__(config, store, bus, interval=config.services_interval)
        self._runner, self._getter = runner, getter
        self._netbox_target = netbox_target or (lambda: ("", {}))     # -> (url, auth headers)
        self._managed = managed
        self._freshness: dict[str, str] = {}
        self._telemetry_ok: bool | None = None

    def setup(self) -> None:
        if self._managed is None:
            try:
                self._managed = {device.name for device in inventory.managed_devices(inventory.load(self.config.inventory_path))}
            except Exception:  # noqa: BLE001 - without the inventory every monitored node is still shown, just not flagged managed
                self._managed = set()
                self.emit("collector.error", outcome=m.ERROR, data={"code": "INVENTORY_UNREADABLE", "phase": "setup"})

    def collect(self) -> None:
        self._observe_services()
        self._observe_telemetry()

    def _observe_services(self) -> None:
        netbox_url, netbox_headers = self._netbox_target()
        for observation in service_adapter.observe_all(self.config, runner=self._runner, getter=self._getter,
                                                       netbox_url=netbox_url, netbox_headers=netbox_headers):
            previous = self.store.set_service(observation)
            self.emit("service.sample", target=observation.component, ts=observation.ts,
                      outcome=m.OK if observation.state == m.UP else m.FAIL if observation.state == m.DOWN else m.INFO,
                      data=observation.to_dict())
            if previous is not None:
                self.emit("service.transition", target=observation.component, ts=observation.ts,
                          outcome=m.OK if observation.state == m.UP else m.FAIL, data={"from": previous, "to": observation.state})

    def _observe_telemetry(self) -> None:
        now = m.utcnow()
        try:
            found = telemetry.read(self.config, managed=self._managed or set(), now=now, getter=self._getter)
        except telemetry.TelemetryUnavailable as exc:
            self.store.set_telemetry(ts=now, available=False, reason=exc.code)
            # a failed read is an event every cycle it fails: the gap in freshness evidence must be visible in the log
            self.emit("telemetry.error", target="topology-api", outcome=m.ERROR, ts=now, data={"code": exc.code})
            self._telemetry_ok = False
            return
        if self._telemetry_ok is False:
            self.emit("telemetry.recovered", target="topology-api", outcome=m.OK, ts=now)
        self._telemetry_ok = True
        self.store.set_telemetry(ts=now, available=True, rows=found["rows"], thresholds=found["thresholds"], backend=found["backend"],
                                 generated_at=found["generated_at"])
        self.emit("telemetry.sample", target="fleet", ts=now,
                  outcome=m.OK if all(row.freshness == telemetry.FRESH for row in found["rows"] if row.managed) else m.FAIL,
                  data={"backend": found["backend"], "thresholds": found["thresholds"],
                        "devices": {row.device: {"freshness": row.freshness, "age_seconds": None if row.age_seconds is None else round(row.age_seconds, 1),
                                                 "last_sample": m.iso(row.last_sample)} for row in found["rows"]}})
        for row in found["rows"]:
            before = self._freshness.get(row.device)
            if before is not None and before != row.freshness:
                self.emit("telemetry.transition", target=row.device, ts=now,
                          outcome=m.OK if row.freshness == telemetry.FRESH else m.FAIL, data={"from": before, "to": row.freshness})
            self._freshness[row.device] = row.freshness
