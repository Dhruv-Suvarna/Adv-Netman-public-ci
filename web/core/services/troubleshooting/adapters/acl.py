"""ACL source adapter (HC18 ``acl.counters``): one explicitly version-gated, READ-ONLY cEOS source.

Flow: ``collectors.CliCollector`` (catalogue keys ``acl_rules`` = ``show ip access-lists | json`` and ``acl_attach`` = ``show ip access-lists summary | json``)
-> ``normalization.normalize_acl_rules`` / ``normalize_acl_attachment`` (parsers ``acl.rules`` / ``acl.attachment``, ``eos-json-1.0``, EOS 4.28 <= v < 5.0)
-> ``runtime.map_observations`` / ``runtime.join_acl_observations`` -> engine key ``acl.counters@<interface>-<direction>`` consumed by ``runbooks.hc.hc18``.
Unsupported platform/version is refused BEFORE any device contact.  Nothing here touches a device.  ``AclContext`` is caller-owned and kept per case:
counter deltas are derived only from historical samples, so without it HC18 can never call a deny "live".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime

from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
PARSER_IDS = ("acl.rules", "acl.attachment")
SUPPORTED = {"platform": "ceos", "os_min": "4.28", "os_max_exclusive": "5.0", "address_family": "ipv4",
             "commands": ("show ip access-lists | json", "show ip access-lists summary | json"),
             "rule_grammar": "(permit|deny) (ip|tcp|udp|icmp) <any|host A|A/len> <any|host A|A/len> [eq <port>] [log]"}
UNSUPPORTED = ("IPv6 ACLs", "standard ACLs", "wildcard-mask addresses", "source-port operators", "port ranges / neq / gt / lt", "named ports / ICMP types",
               "tcp flags / established / fragments / tracked", "object groups", "VRF-aware attachment (VRF stays unknown)", "dynamic / PBR / zone-based firewall policy",
               "iosxe / linux platforms")
LIVE, RECORDED, SIMULATED = "LIVE_GATEWAY_PINNED", "RECORDED", "SIMULATED"


@dataclass
class AclContext:
    """``RuntimeDeps.acl_context``: previous-sample counter history shared across polls of one case (in memory by default; opt in to restart continuity with :func:`persistent_acl_context`)."""

    history: nz.AclHistory = field(default_factory=nz.AclHistory)


def describe_source(*, gateway: dict | None = None, recorded: bool = False) -> dict:
    """Provenance label.  Only a gateway-recorded run (``gateway['live'] is True``) is LIVE; anything else is never presented as live."""
    label = LIVE if gateway and gateway.get("live") is True else (RECORDED if recorded else SIMULATED)
    return {"source": "acl", "label": label, "live": label == LIVE, "parsers": {p: nz.PARSERS[p][0].version for p in PARSER_IDS},
            "supported": dict(SUPPORTED), "unsupported": list(UNSUPPORTED), "gateway": gateway or None, "adapter_version": SOURCE_VERSION}


def is_supported(platform: str, os_version: str) -> bool:
    try:
        for p in PARSER_IDS:
            nz.select_parser(p, platform, os_version)
        return True
    except nz.ParserSelectionError:
        return False


HISTORY_ADAPTER = "acl-counter-history"
HISTORY_SCHEMA = 1
_MAX_RULES = 5000


def _rule_id(seq, text) -> str:
    return hashlib.sha256(f"{seq}|{text}".encode("utf-8", "replace")).hexdigest()[:16]


class PersistentAclHistory(nz.AclHistory):
    """Opt-in restart-safe ``AclHistory``: each accepted complete sample is stored as immutable case evidence (``repository.store_evidence``) scoped by
    tenant (actor) / case / device / ACL / parser version, with a per-rule identity (sequence + text digest) that is re-verified on reload.

    ``normalize_acl_rules`` still decides stale (> ``ACL_MAX_GAP_S``), short (< ``ACL_MIN_SPAN_S``), counter reset, changed rule and partial parses
    (partial samples are never recorded).  Here anything unreadable, foreign-scoped, wrong-version, incomplete, internally inconsistent or malformed is
    treated as *no history* (``prev_hits`` stays None => counter delta UNKNOWN); persistence failures never raise into the collector and never fabricate
    a sample.  Instances never share state across scopes.  Construction performs no database access."""

    def __init__(self, actor, case_id: str, *, parser_version: str | None = None):
        super().__init__()
        self.actor, self.case_id = actor, case_id
        self.parser_version = parser_version or nz.PARSERS["acl.rules"][0].version
        self.problems: list[str] = []
        self._loaded: set[tuple] = set()

    @staticmethod
    def _command(acl: str) -> str:
        return "acl.counter_history@" + hashlib.sha256(str(acl).encode("utf-8", "replace")).hexdigest()[:24]

    def _scope(self, device: str, acl: str) -> dict:
        return {"schema": HISTORY_SCHEMA, "tenant": self.actor.tenant, "case_id": self.case_id, "device": device, "acl": acl,
                "parser_version": self.parser_version}

    def _case(self):
        from .. import repository as repo
        return repo, repo.get_case(self.actor, self.case_id)

    def previous(self, device: str, acl: str) -> dict | None:
        key = (device, acl)
        if key not in self._prev and key not in self._loaded:
            self._loaded.add(key)
            try:
                entry = self._load(device, acl)
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - class name only; history is then simply unknown
                self.problems.append(f"load({device},{acl}): {type(exc).__name__}")
                entry = None
            if entry is not None:
                self._prev[key] = entry
        return self._prev.get(key)

    def _load(self, device: str, acl: str) -> dict | None:
        from core import models as m
        repo, case = self._case()
        want = self._scope(device, acl)
        ref = (m.TsEvidenceRef.objects.filter(case=case, device=device, adapter=HISTORY_ADAPTER, parser_version=self.parser_version,
                                              command_or_api=self._command(acl)).select_related("raw_blob").order_by("-collected_at", "-id").first())
        if ref is None or ref.scope != want or ref.raw_blob is None:
            return None
        doc = json.loads(repo.read_raw_evidence(self.actor, ref.evidence_id, privileged=True))
        if doc.get("scope") != want or doc.get("complete") is not True:
            return None
        at = nz.to_utc(datetime.fromisoformat(doc["at"]))
        if at != nz.to_utc(ref.collected_at):
            return None
        rules = doc["rules"]
        if not isinstance(rules, list) or len(rules) > _MAX_RULES:
            return None
        out: dict = {}
        for row in rules:
            seq, text, hits, rid = row["seq"], row["text"], row["hits"], row["id"]
            if isinstance(seq, bool) or not isinstance(seq, int) or not isinstance(text, str) or seq in out:
                return None
            if hits is not None and (isinstance(hits, bool) or not isinstance(hits, int) or hits < 0):
                return None
            if rid != _rule_id(seq, text):
                return None
            out[seq] = {"hits": hits, "text": text}
        return {"at": at, "rules": out}

    def record(self, device: str, acl: str, entry: dict) -> None:
        super().record(device, acl, entry)
        self._loaded.add((device, acl))
        try:
            repo, case = self._case()
            rules = [{"seq": s, "text": r["text"], "hits": r["hits"], "id": _rule_id(s, r["text"])} for s, r in sorted(entry["rules"].items())]
            doc = {"scope": self._scope(device, acl), "complete": True, "at": entry["at"].isoformat(), "rules": rules}
            repo.store_evidence(self.actor, case, source_type="replay", device=device, command_or_api=self._command(acl), adapter=HISTORY_ADAPTER,
                                adapter_version=SOURCE_VERSION, parser="acl.rules", parser_version=self.parser_version, collected_at=entry["at"],
                                raw=json.dumps(doc, sort_keys=True), scope=self._scope(device, acl))
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - in-process continuity remains; nothing is invented
            self.problems.append(f"persist({device},{acl}): {type(exc).__name__}")


def persistent_acl_context(actor, case_id: str, *, parser_version: str | None = None) -> AclContext:
    """Opt-in factory for ``acl_context_provider`` bindings: ``lambda: persistent_acl_context(actor, case_id)``.  No DB access until first use."""
    return AclContext(history=PersistentAclHistory(actor, case_id, parser_version=parser_version))
