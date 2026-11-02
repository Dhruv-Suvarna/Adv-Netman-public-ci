"""Continuous connectivity: every required endpoint / family pair, probed every cycle, every result recorded.

The matrix is the inventory's own endpoint policy (H1-H3 dual-stack, H4 IPv6 only): a family an endpoint does not have by design is
not a row and is never probed.  Each cycle sends ONE echo request per row.  Every result -- pass, timeout, unreachable, or "the probe
itself could not run" -- becomes a timestamped sample in the row's ring and a line in the session log; a state change additionally
produces a failure / recovery event.  Nothing is recorded only on transitions.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from .. import models as m
from ..adapters import endpoints as endpoint_adapter
from ..adapters import inventory, process
from ..supervisor import Collector


class ConnectivityCollector(Collector):
    name = m.CONNECTIVITY
    backoff_on_error = False        # a failed probe is a sample, not a reason to probe less often

    def __init__(self, config, store, bus, *, runner=process.run, inventory_document: dict | None = None):
        super().__init__(config, store, bus, interval=config.connectivity_interval)
        self._runner = runner
        self._document = inventory_document
        self._endpoints: dict[str, inventory.Endpoint] = {}
        self._plan: list[m.ProbeSpec] = []
        self._addresses: dict[str, dict[str, str]] = {}
        self._discovery_error: dict[str, str] = {}
        self._last_discovery = 0.0
        self._pool: ThreadPoolExecutor | None = None

    def setup(self) -> None:
        document = self._document if self._document is not None else inventory.load(self.config.inventory_path)
        found = inventory.endpoints(document)
        self._endpoints = {endpoint.name: endpoint for endpoint in found}
        self._plan = inventory.probe_plan(found)
        self.store.set_probe_specs(self._plan)
        self._pool = ThreadPoolExecutor(max_workers=max(2, len(self._plan)), thread_name_prefix="console-probe")
        self.emit("connectivity.plan", data={"rows": [{"source": s.source, "family": s.family, "destination": s.destination} for s in self._plan]})

    def teardown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)

    # --- address discovery ---------------------------------------------------------------------------------------------------
    def _discover(self, force: bool = False) -> None:
        due = time.monotonic() - self._last_discovery >= self.config.address_refresh_interval
        missing = any(family not in self._addresses.get(name, {}) for name, endpoint in self._endpoints.items() for family in endpoint.families)
        if not (force or due or missing):
            return
        self._last_discovery = time.monotonic()
        for name, endpoint in self._endpoints.items():
            if self.stopping:
                return
            try:
                found = endpoint_adapter.discover(endpoint.container, runner=self._runner, timeout=self.config.command_timeout,
                                                  exclude_interface=self.config.endpoint_mgmt_interface)
            except endpoint_adapter.DiscoveryError as exc:
                if self._discovery_error.get(name) != exc.code:
                    self.emit("connectivity.discovery_error", target=name, outcome=m.ERROR, data={"code": exc.code})
                self._discovery_error[name] = exc.code
                self._addresses.pop(name, None)          # an address we can no longer confirm is not probed as if it were current
                continue
            self._discovery_error.pop(name, None)
            found = {family: address for family, address in found.items() if family in endpoint.families}
            if found != self._addresses.get(name):
                self.emit("connectivity.addresses", target=name, outcome=m.OK, data={"addresses": found})
            self._addresses[name] = found

    # --- one cycle ---------------------------------------------------------------------------------------------------------------
    def _probe(self, spec: m.ProbeSpec) -> m.ProbeSample:
        source_address = self._addresses.get(spec.source, {}).get(spec.family, "")
        target_address = self._addresses.get(spec.destination, {}).get(spec.family, "")
        stamp = m.utcnow()
        if not source_address:
            reason = "SOURCE_" + self._discovery_error[spec.source] if spec.source in self._discovery_error else "NO_SOURCE_ADDRESS"
            return m.ProbeSample(stamp, spec.key, spec.source, spec.family, spec.destination, "", target_address, False, None, reason)
        if not target_address:
            return m.ProbeSample(stamp, spec.key, spec.source, spec.family, spec.destination, source_address, "", False, None, "NO_TARGET_ADDRESS")
        try:
            success, rtt, reason = endpoint_adapter.ping(self._endpoints[spec.source].container, target_address, spec.family,
                                                         runner=self._runner, wait=self.config.ping_wait_seconds,
                                                         timeout=self.config.command_timeout)
        except Exception:  # noqa: BLE001 - the probe failing to run is itself a recorded failure sample
            success, rtt, reason = False, None, "PROBE_ERROR"
        return m.ProbeSample(stamp, spec.key, spec.source, spec.family, spec.destination, source_address, target_address, success, rtt, reason)

    def collect(self) -> None:
        self._discover()
        futures = [self._pool.submit(self._probe, spec) for spec in self._plan]
        for spec, future in zip(self._plan, futures):
            try:
                sample = future.result(timeout=self.config.command_timeout * 2)
            except Exception:  # noqa: BLE001 - never lose the row: a sample is recorded for it regardless
                sample = m.ProbeSample(m.utcnow(), spec.key, spec.source, spec.family, spec.destination, "", "", False, None, "PROBE_ERROR")
            self.record(sample)

    def record(self, sample: m.ProbeSample) -> None:
        transition = self.store.add_probe_sample(sample)
        self.emit("connectivity.sample", target=sample.key, outcome=m.PASS if sample.success else m.FAIL, ts=sample.ts,
                  data={"destination": sample.destination, "source_address": sample.source_address,
                        "target_address": sample.target_address, "rtt_ms": sample.rtt_ms, "reason": sample.reason})
        if transition:
            self.emit("connectivity.recovery" if transition == "RECOVERED" else "connectivity.failure", target=sample.key,
                      outcome=m.OK if transition == "RECOVERED" else m.FAIL, ts=sample.ts,
                      data={"destination": sample.destination, "target_address": sample.target_address, "reason": sample.reason})
        if not sample.success and sample.reason in ("NO_SOURCE_ADDRESS", "NO_TARGET_ADDRESS"):
            self._last_discovery = 0.0     # re-discover on the next cycle
