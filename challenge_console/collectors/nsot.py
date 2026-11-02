"""NSOT: periodic read-only snapshots of NetBox, with consistency indicators against the tracked inventory and the running lab."""

from __future__ import annotations

from .. import models as m
from ..adapters import http, inventory, netbox, process
from ..supervisor import Collector, CollectorError


class NsotCollector(Collector):
    name = m.NSOT

    def __init__(self, config, store, bus, *, reader: netbox.NetboxReader | None = None, getter=http.get, runner=process.run,
                 inventory_document: dict | None = None):
        super().__init__(config, store, bus, interval=config.nsot_interval)
        self._reader = reader
        self._getter, self._runner = getter, runner
        self._document = inventory_document
        self._inventory: dict[str, dict] = {}

    def _ensure_reader(self) -> netbox.NetboxReader:
        if self._reader is None:
            self._reader = netbox.NetboxReader.from_config(self.config, getter=self._getter)
        return self._reader

    def health_target(self) -> tuple[str, dict]:
        """(url, auth headers) for the services collector's NetBox liveness read; headers are {} when no token is configured."""
        try:
            reader = self._ensure_reader()
            return reader.url, reader.health_headers()
        except Exception:  # noqa: BLE001
            return "", {}

    def setup(self) -> None:
        document = self._document if self._document is not None else inventory.load(self.config.inventory_path)
        managed = {device.name for device in inventory.managed_devices(document)}
        for name, entry in (document.get("network_devices") or {}).items():
            monitoring = (entry or {}).get("monitoring") or {}
            address = monitoring.get("address")
            self._inventory[str(name)] = {"address": "" if address in (None, "auto") else str(address),
                                          "address_v6": str(monitoring.get("address_v6") or ""), "managed": name in managed}

    def _running(self) -> set[str] | None:
        prefix = f"clab-{self.config.lab_name}-"
        result = self._runner(("docker", "ps", "--filter", f"name={prefix}", "--format", "{{.Names}}"), timeout=self.config.command_timeout)
        if not result.ok:
            return None
        return {line[len(prefix):] for line in result.stdout.split() if line.startswith(prefix)}

    def collect(self) -> None:
        now = m.utcnow()
        try:
            snapshot = self._ensure_reader().snapshot()
        except netbox.NetboxUnavailable as exc:
            self.store.fail_document(m.NSOT, ts=now, reason=exc.code)
            raise CollectorError(exc.code, "netbox") from None
        running = self._running()
        snapshot["consistency"] = netbox.consistency(snapshot, inventory_devices=self._inventory, running=running)
        snapshot["lab"] = {"running": None if running is None else len(running), "expected": self.config.expected_lab_containers}
        self.store.set_document(m.NSOT, ts=now, data=snapshot)
        problems = [row for row in snapshot["consistency"] if "MISMATCH" in (row["management_address"], row["managed_scope"])
                    or row["runtime"] == "NOT_RUNNING"]
        self.emit("nsot.snapshot", target="netbox", outcome=m.OK if not problems else m.FAIL, ts=now,
                  data={"counts": snapshot["counts"], "lab": snapshot["lab"], "inconsistent": problems,
                        "devices": [{"name": d["name"], "role": d["role"], "platform": d["platform"], "managed": d["managed"],
                                     "primary_ip4": d["primary_ip4"], "primary_ip6": d["primary_ip6"], "interfaces": len(d["interfaces"]),
                                     "addresses": d["address_count"]} for d in snapshot["devices"]]})
