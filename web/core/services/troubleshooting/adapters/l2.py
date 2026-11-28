"""L2 source adapter (HC08 VLAN/port mode, HC09 MAC movement): wires the version-gated cEOS ``show interfaces switchport | json`` and
``show mac address-table | json`` parsers into the existing runtime without a new collector.

Flow: ``collectors.CliCollector`` (catalogue keys ``switchport`` / ``mac_table``, read-only) -> ``normalization.normalize_l2_ports`` /
``normalize_mac_table`` (parsers ``l2.port`` / ``mac.table``, ``eos-json-1.0``) -> ``runtime.map_observations`` -> engine keys ``l2.port@<interface>``
and ``mac.table@<vlan>`` consumed by ``runbooks.hc`` HC08 / HC09.  Nothing here touches a device.  ``L2Context`` is caller-owned and kept per case:
MAC movement is derived only from historical samples, so without it HC09 stays INCONCLUSIVE.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
PARSER_IDS = ("l2.port", "mac.table")
SUPPORTED = {"platform": "ceos", "os_min": "4.28", "os_max_exclusive": "5.0",
             "commands": ("show interfaces switchport | json", "show mac address-table | json")}
LIVE, RECORDED, SIMULATED = "LIVE_GATEWAY_PINNED", "RECORDED", "SIMULATED"


@dataclass
class L2Context:
    """``RuntimeDeps.l2_context``: previous-sample MAC history shared across polls of one case.  The default is in memory (not restart-persistent);
    opt in to restart continuity with :func:`persistent_l2_context`."""

    history: nz.MacHistory = field(default_factory=nz.MacHistory)


def describe_source(*, gateway: dict | None = None, recorded: bool = False) -> dict:
    """Provenance label.  Only a gateway-recorded run (``gateway['live'] is True``) is LIVE; anything else is never presented as live."""
    label = LIVE if gateway and gateway.get("live") is True else (RECORDED if recorded else SIMULATED)
    return {"source": "l2", "label": label, "live": label == LIVE,
            "parsers": {p: nz.PARSERS[p][0].version for p in PARSER_IDS}, "supported": dict(SUPPORTED), "gateway": gateway or None, "adapter_version": SOURCE_VERSION}


def is_supported(platform: str, os_version: str) -> bool:
    try:
        for p in PARSER_IDS:
            nz.select_parser(p, platform, os_version)
        return True
    except nz.ParserSelectionError:
        return False


HISTORY_ADAPTER = "l2-mac-history"
HISTORY_SCHEMA = 1


class PersistentMacHistory(nz.MacHistory):
    """Opt-in restart-safe ``MacHistory``: every accepted sample is stored as immutable case evidence (``repository.store_evidence``) scoped by
    tenant (actor) / case / device / VLAN / parser version, and read back lazily on the first ``previous()`` of a key after a restart.

    Safeguards are inherited, not re-implemented: ``normalize_mac_table`` still decides usable/short/gap/non-monotonic and still refuses to call
    ``record`` on partial parses.  Here, anything unreadable, foreign-scoped, wrong-version or malformed is treated as *no history* (movement stays
    UNKNOWN); persistence failures never raise into the collector and never fabricate a sample.  Instances never share state across scopes."""

    def __init__(self, actor, case_id: str, *, parser_version: str | None = None):
        super().__init__()
        self.actor, self.case_id = actor, case_id
        self.parser_version = parser_version or nz.PARSERS["mac.table"][0].version
        self.problems: list[str] = []
        self._loaded: set[tuple] = set()

    @staticmethod
    def _command(vlan) -> str:
        return f"l2.mac_history@vlan{vlan}"

    def _scope(self, device: str, vlan: str) -> dict:
        return {"schema": HISTORY_SCHEMA, "tenant": self.actor.tenant, "case_id": self.case_id, "device": device, "vlan": str(vlan),
                "parser_version": self.parser_version}

    def _case(self):
        from .. import repository as repo
        return repo, repo.get_case(self.actor, self.case_id)

    def previous(self, device: str, vlan: str) -> dict | None:
        key = (device, vlan)
        if key not in self._prev and key not in self._loaded:
            self._loaded.add(key)
            try:
                entry = self._load(device, vlan)
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - class name only; history is then simply unknown
                self.problems.append(f"load({device},{vlan}): {type(exc).__name__}")
                entry = None
            if entry is not None:
                self._prev[key] = entry
        return self._prev.get(key)

    def _load(self, device: str, vlan: str) -> dict | None:
        from core import models as m
        repo, case = self._case()
        want = self._scope(device, vlan)
        ref = (m.TsEvidenceRef.objects.filter(case=case, device=device, adapter=HISTORY_ADAPTER, parser_version=self.parser_version,
                                              command_or_api=self._command(vlan)).select_related("raw_blob").order_by("-collected_at", "-id").first())
        if ref is None or ref.scope != want or ref.raw_blob is None:
            return None
        doc = json.loads(repo.read_raw_evidence(self.actor, ref.evidence_id, privileged=True))
        if doc.get("scope") != want:
            return None
        def ts(v):
            return nz.to_utc(datetime.fromisoformat(v))
        macs = doc["macs"]
        if not isinstance(macs, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in macs.items()):
            return None
        events = [(ts(e[0]), str(e[1]), str(e[2]), str(e[3])) for e in doc["events"]]
        return {"macs": dict(macs), "at": ts(doc["at"]), "events": events, "coverage_start": ts(doc["coverage_start"])}

    def record(self, device: str, vlan: str, entry: dict) -> None:
        super().record(device, vlan, entry)
        self._loaded.add((device, vlan))
        try:
            repo, case = self._case()
            doc = {"scope": self._scope(device, vlan), "macs": entry["macs"], "at": entry["at"].isoformat(),
                   "coverage_start": entry["coverage_start"].isoformat(), "events": [[e[0].isoformat(), *e[1:]] for e in entry["events"]]}
            repo.store_evidence(self.actor, case, source_type="replay", device=device, command_or_api=self._command(vlan), adapter=HISTORY_ADAPTER,
                                adapter_version=SOURCE_VERSION, parser="mac.table", parser_version=self.parser_version, collected_at=entry["at"],
                                raw=json.dumps(doc, sort_keys=True), scope=self._scope(device, vlan))
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - in-process continuity remains; nothing is invented
            self.problems.append(f"persist({device},{vlan}): {type(exc).__name__}")


def persistent_l2_context(actor, case_id: str, *, parser_version: str | None = None) -> L2Context:
    """Opt-in factory for ``l2_context_provider`` bindings: ``lambda: persistent_l2_context(actor, case_id)``.  No DB access until first use."""
    return L2Context(history=PersistentMacHistory(actor, case_id, parser_version=parser_version))
