"""The Ubuntu / FRR trusted-upstream isolation executor: one NMAS-owned nftables table, created and deleted atomically.

It speaks only the isolation transaction's two operation shapes (``isolation.frr``):

    ADD     object type ``isolation``: ``table inet nmas_iso_devNNNNNN { ... }`` exactly as ``frr.render_table`` renders it
    REMOVE  object type ``config_removal_delete``: ``delete table inet nmas_iso_devNNNNNN`` whose restore lines are that table

Anything else is refused.  The transport is the authorized SSH session of ``management.linux_ssh`` (inventory-resolved
writable target, pinned host key, key-only service account, ``sudo -n`` for nft and the FRR shell only; FRR is only ever read); never ``docker exec``.  Every
command is an argv list quoted token by token; a Configlet line is never handed to a shell, the table statement is
re-rendered from its parsed parameters and must match byte for byte before it is sent (as one argv token).  ``config_state_digest`` covers the whole nftables ruleset (counter values
removed) and the FRR running configuration, so a change anywhere between two steps is an out-of-band change.

Reads used for planning and verification are bundled in ``snapshot`` (read-only).
"""

from __future__ import annotations

import hashlib
import json

from ...isolation import frr
from ..codes import device_timeout_seconds
from .base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError
from ...management import linux_ssh
from .linux import frr_config_digest, nft_digest
from .state import COMPENSATION_NOT_PROVABLE

ADD_OBJECT, REMOVE_OBJECT = "isolation", "config_removal_delete"
# A check-only (never committed) transaction proving the kernel accepts what the policy needs: an inet table with filter base
# chains on forward / input / output, interface-name matches, counters and drops.
CAPABILITY_CANARY = ("table inet nmas_iso_capability_probe {\n"
                     "  chain forward {\n    type filter hook forward priority filter; policy accept;\n    iifname \"lo\" counter drop\n  }\n"
                     "  chain input {\n    type filter hook input priority filter; policy accept;\n    iifname \"lo\" udp dport 67 accept\n  }\n"
                     "  chain output {\n    type filter hook output priority filter; policy accept;\n    oifname \"lo\" icmpv6 type { nd-router-advert } accept\n  }\n}")
PROCESS_LIST = "for p in /proc/[0-9]*; do tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null && echo; done"


def state_digest(ruleset_text: str, frr_text: str) -> str:
    return hashlib.sha256(f"{nft_digest(ruleset_text)}\n{frr_config_digest(frr_text)}".encode()).hexdigest()


class FrrIsolationExecutor(DeviceExecutor):
    platform = frr.PLATFORM

    def __init__(self, device: dict, *, runner=None, connector=None):
        """``runner(argv, timeout) -> (status, stdout)`` replaces the session (tests); ``connector(name, timeout=)`` opens one."""
        self._device = device
        self._runner = runner
        self._connector = connector
        self._session = None
        self._timeout = device_timeout_seconds()
        self._before: dict[str, str] = {}            # cfg_id -> digest immediately before that apply

    # ----------------------------------------------------------------------------------------------------------- reads
    def _exec(self, argv: list[str]):
        if self._runner is not None:
            return self._runner(argv, self._timeout)
        if self._session is None:
            raise ExecutorError("CONNECTION_FAILED")
        return self._session.run(argv, self._timeout)

    def _must(self, argv: list[str]) -> str:
        code, out = self._exec(argv)
        if code:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return out

    def _json(self, argv: list[str]):
        code, out = self._exec(argv)
        if code:
            return None
        try:
            return json.loads(out or "null")
        except ValueError:
            return None

    def ruleset(self) -> str:
        return self._must(["nft", "list", "ruleset"])

    def frr_config(self) -> str:
        out = self._must(linux_ssh.frr_show("show running-config"))
        if "failed to connect" in out.lower():
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return out

    def table_listing(self, table: str) -> str | None:
        code, out = self._exec(["nft", "list", "table", frr.FAMILY, table])
        return out if code == 0 else None

    def table_json(self, table: str):
        """``nft -j list table`` of one table (its rule counters), or None when absent / unreadable."""
        return self._json(["nft", "-j", "list", "table", frr.FAMILY, table])

    def neighbors(self):
        """``ip -j neigh show`` (the upstream's own observation of the device on the port)."""
        rows = self._json(["ip", "-j", "neigh", "show"])
        if not isinstance(rows, list):
            raise ExecutorError("VERIFICATION_UNAVAILABLE")
        return rows

    def reachable(self, address: str) -> bool:
        """Two pings from the upstream (admission evidence); the address is validated, never shell-interpreted."""
        import ipaddress

        try:
            ip = ipaddress.ip_address(str(address))
        except ValueError:
            return False
        code, _out = self._exec(["ping", "-6" if ip.version == 6 else "-4", "-c", "2", "-W", "1", str(ip)])
        return code == 0

    def config_state_digest(self) -> str:
        return state_digest(self.ruleset(), self.frr_config())

    def snapshot(self, nmas_sources=()) -> dict:
        """Everything planning and verification read, in one bundle.  Unreadable optional facts are None (never a pass)."""
        code, version = self._exec(["nft", "--version"])
        snap: dict = {"nft_version": version.strip() if code == 0 else ""}
        code, text = self._exec(["nft", "list", "ruleset"])
        snap["nft_text"] = text if code == 0 else None
        snap["nft_json"] = self._json(["nft", "-j", "list", "ruleset"])
        code, _out = self._exec(["nft", "-c", CAPABILITY_CANARY])
        snap["nft_check_ok"] = code == 0
        code, hooks = self._exec(["nft", "list", "hooks"])
        snap["hooks_listable"], snap["hooks"] = code == 0, hooks if code == 0 else ""
        tables = [t["table"]["name"] for t in ((snap["nft_json"] or {}).get("nftables") or [])
                  if isinstance(t, dict) and "table" in t and t["table"].get("family") == frr.FAMILY
                  and str(t["table"].get("name", "")).startswith(frr.TABLE_PREFIX)]
        snap["table_listing"] = {name: self.table_listing(name) for name in tables}
        snap["table_json"] = {name: self.table_json(name) for name in tables}
        code, conf = self._exec(linux_ssh.frr_show("show running-config"))
        snap["frr"] = conf if code == 0 and "failed to connect" not in conf.lower() else ""
        snap["links"] = self._json(["ip", "-d", "-j", "addr", "show"])
        snap["routes4"] = self._json(["ip", "-j", "-4", "route", "show"])
        snap["routes6"] = self._json(["ip", "-j", "-6", "route", "show"])
        snap["route_get"] = {}
        for source in nmas_sources:
            rows = self._json(["ip", "-j", "route", "get", str(source)])
            snap["route_get"][str(source)] = str((rows or [{}])[0].get("dev") or "") if isinstance(rows, list) else ""
        code, out = self._exec(linux_ssh.frr_show("show ip ospf neighbor json"))
        snap["ospf_neighbors"] = out if code == 0 else ""
        code, out = self._exec(linux_ssh.frr_show("show ipv6 ospf6 neighbor json"))
        snap["ospf6_neighbors"] = out if code == 0 else ""
        code, out = self._exec(["sh", "-c", PROCESS_LIST])
        snap["processes"] = [line.strip() for line in out.splitlines() if line.strip()] if code == 0 else []
        snap["neighbors"] = self._json(["ip", "-j", "neigh", "show"])
        snap["digest"] = state_digest(snap["nft_text"], snap["frr"]) if snap["nft_text"] is not None and snap["frr"] else ""
        return snap

    # ----------------------------------------------------------------------------------------------------------- contract
    def connect(self) -> None:
        if not self._device.get("name"):
            raise ExecutorError("NOT_CONFIGURED")
        if self._runner is None and self._session is None:
            self._session = (self._connector or linux_ssh.connect)(self._device["name"], timeout=self._timeout)
        try:
            self.ruleset()                   # a probe: nft must answer (with privilege) before anything else
        except ExecutorError:
            self.close()
            raise

    @staticmethod
    def _parse(spec: ConfigletSpec) -> tuple[str, dict | None, str]:
        """-> (ADD | REMOVE | "", table params, table name) for the two shapes this executor accepts."""
        if spec.platform != frr.PLATFORM or spec.origin not in ("STRUCTURED", "REMOVAL"):
            return "", None, ""
        if spec.object_type == ADD_OBJECT and spec.origin == "STRUCTURED":
            params = frr.parse_table(spec.lines)
            return ("ADD", params, params["table"]) if params else ("", None, "")
        if spec.object_type == REMOVE_OBJECT and spec.origin == "REMOVAL":
            table = frr.parse_delete(spec.lines)
            params = frr.parse_table((spec.removal or {}).get("restore_lines") or [])
            if table and params and params["table"] == table:
                return "REMOVE", params, table
        return "", None, ""

    def _exact(self, params: dict, listing: str | None) -> bool:
        wanted = frr.render_table(params["table"], params["port"], params["bootstrap"])
        return listing is not None and frr.normalize_listing(listing) == frr.normalize_listing("\n".join(wanted))

    def assess(self, spec: ConfigletSpec) -> Assessment:
        kind, params, table = self._parse(spec)
        if not kind:
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        listing = self.table_listing(table)
        before = {"kind": "nft_table", "table": table, "present": listing is not None, "ruleset_digest": nft_digest(self.ruleset())}
        if kind == "ADD":
            if listing is None:
                return Assessment(APPLY, True, before)
            if self._exact(params, listing):
                return Assessment(SKIP_SATISFIED, True, before)
            return Assessment(APPLY, False, before, COMPENSATION_NOT_PROVABLE)   # a table of our name we did not render
        if listing is None:
            return Assessment(SKIP_SATISFIED, True, before)
        if self._exact(params, listing):
            return Assessment(APPLY, True, before)
        return Assessment(REFUSE, False, before, COMPENSATION_NOT_PROVABLE)     # drifted: its restore path is not the truth

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        kind, params, table = self._parse(spec)
        if not kind or not assessment.restorable:
            return ApplyOutcome(False, "UNSUPPORTED")
        try:
            listing = self.table_listing(table)
            if (kind == "ADD" and listing is not None) or (kind == "REMOVE" and not self._exact(params, listing)):
                return ApplyOutcome(False, "COMMAND_REJECTED")                  # changed since the assessment: never merge
            self._before[spec.cfg_id] = self.config_state_digest()
            argv = ["nft", "\n".join(frr.render_table(table, params["port"], params["bootstrap"]))] if kind == "ADD" \
                else ["nft", "delete", "table", frr.FAMILY, table]
            code, _out = self._exec(argv)
            if code:
                return ApplyOutcome(False, "COMMAND_REJECTED", partial_effects=False, lines_sent=1)   # one atomic nft transaction
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code)
        return ApplyOutcome(True, lines_sent=1)

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        kind, params, table = self._parse(spec)
        wanted = self._before.get(spec.cfg_id)
        if not kind or not wanted:
            return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
        try:
            if self.config_state_digest() == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            listing = self.table_listing(table)
            if kind == "ADD":
                if listing is None or not self._exact(params, listing):
                    return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")   # never delete what we did not render
                argv = ["nft", "delete", "table", frr.FAMILY, table]
            else:
                if listing is not None:
                    return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
                argv = ["nft", "\n".join(frr.render_table(table, params["port"], params["bootstrap"]))]
            code, _out = self._exec(argv)
            if code:
                return CompensationOutcome("COMPENSATION_FAILED", "COMMAND_REJECTED")
            if self.config_state_digest() != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "commands": 1})

    def close(self) -> None:
        session, self._session = self._session, None
        if session is not None:
            session.close()
