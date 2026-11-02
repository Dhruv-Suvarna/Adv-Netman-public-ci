"""Interface counters for every managed device, discovered dynamically each cycle.

The device list is the inventory's managed set; the interface list is whatever each device reports this cycle (nothing is a fixed
list, so an interface that appears or disappears is noticed).  Devices are read in parallel and independently: one unreachable device
is an event and a flagged row, and the others are still read on time.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .. import models as m
from ..adapters import counters as counter_adapter
from ..adapters import inventory, process
from ..supervisor import Collector


class InterfaceCounterCollector(Collector):
    name = m.COUNTERS
    backoff_on_error = False

    def __init__(self, config, store, bus, *, runner=process.run, devices: list | None = None):
        super().__init__(config, store, bus, interval=config.counters_interval)
        self._runner = runner
        self._devices = devices
        self._failing: dict[str, str] = {}
        self._pool: ThreadPoolExecutor | None = None

    def setup(self) -> None:
        if self._devices is None:
            self._devices = inventory.managed_devices(inventory.load(self.config.inventory_path))
        self._pool = ThreadPoolExecutor(max_workers=max(2, len(self._devices)), thread_name_prefix="console-counters")
        self.emit("counters.plan", data={"devices": [{"name": d.name, "platform": d.platform} for d in self._devices]})

    def teardown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)

    def _read(self, device):
        stamp = m.utcnow()
        try:
            return stamp, counter_adapter.read(device.name, device.container, device.platform, runner=self._runner,
                                               timeout=self.config.command_timeout), ""
        except counter_adapter.CounterReadError as exc:
            return stamp, None, exc.code
        except Exception:  # noqa: BLE001
            return stamp, None, "INTERNAL_ERROR"

    def collect(self) -> None:
        futures = [(device, self._pool.submit(self._read, device)) for device in self._devices]
        for device, future in futures:
            try:
                stamp, samples, code = future.result(timeout=self.config.command_timeout * 2)
            except Exception:  # noqa: BLE001
                stamp, samples, code = m.utcnow(), None, "TIMEOUT"
            if samples is None:
                self.store.fail_counters(device.name, stamp, code)
                # every failed read is logged (not only the first): the gap in the counter series must be explainable later
                self.emit("counters.error", target=device.name, outcome=m.ERROR, ts=stamp, data={"code": code})
                self._failing[device.name] = code
                continue
            if self._failing.pop(device.name, None):
                self.emit("counters.recovered", target=device.name, outcome=m.OK, ts=stamp)
            changes = self.store.apply_counters(device.name, stamp, samples)
            self.emit("counters.sample", target=device.name, outcome=m.OK, ts=stamp, data={
                "fields": ["name", "admin", "oper", "speed_bps", *m.COUNTER_FIELDS],
                "interfaces": [[s.name, s.admin, s.oper, s.speed_bps, *s.counters()] for s in samples]})
            for change in changes:
                self.emit("counters.change", target=f"{device.name}:{change['interface']}", outcome=m.INFO, ts=stamp, data={"note": change["note"]})
