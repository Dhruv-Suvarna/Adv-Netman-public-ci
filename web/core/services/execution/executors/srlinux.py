"""Nokia SR Linux executor: gNMI Get for captured state, one atomic CLI-origin gNMI Set per Configlet.

Evidence for each design choice (isolated SR Linux 24.10.7 node, ``nmas-cap-validation``):

* statements             the Configlet's own rendered ``set`` paths, parsed by ``srlinux_model`` into leaf operations.  A
                         statement outside ``srlinux_model.MODELLED`` is REFUSED: its list keys are not verified, so no
                         safe inverse could be derived.
* apply                  ``GnmiSession.set_cli`` -- a single SetRequest.  SR Linux commits every statement of it or none,
                         so a rejected Configlet leaves no partial effect.
* previous state         the whole running configuration, read with gNMI Get immediately before THIS Configlet is
                         applied.  The inverse is computed against that tree: an object the Configlet creates is deleted
                         at the topmost node that did not exist, a replaced leaf gets its captured value back, and nothing
                         that already existed is ever removed.
* restoration proof      after compensation the running configuration must be IDENTICAL (canonical tree digest) to the
                         capture.  A difference is COMPENSATION_FAILED / STATE_NOT_RESTORED, never an assumed success.
* leaf-lists             an SR Linux ``set`` replaces a leaf-list (24.10.7).  A Configlet adds ONE member (a DHCP relay
                         server, an export policy), so the executor sends the captured members plus the Configlet's own:
                         a member another Configlet or the operator configured is never dropped, and the inverse puts the
                         captured members back exactly.
* persistence            the change is committed to the running datastore only; no ``save startup`` is issued.
"""

from __future__ import annotations

import hashlib

from ... import srlinux_model as model
from ..writers.srlinux_gnmi import GnmiError, inventory_session
from . import state
from .base import APPLY, REFUSE, SKIP_SATISFIED, ApplyOutcome, Assessment, CompensationOutcome, ConfigletSpec, DeviceExecutor, ExecutorError

ROUTING_TYPES = frozenset({"routing_ospf", "routing_binding", "routing_bgp", "bgp_neighbor", "bgp_neighbor_af", "bgp_network"})
SERVICE_TYPES = frozenset({"acl", "acl_attachment", "dhcp_relay"})
OBJECT_TYPES = frozenset({"interface", "address", "static_route", *ROUTING_TYPES, *SERVICE_TYPES})


def _operations(spec_lines, tree: dict):
    return model.additive(model.operations(spec_lines, strict=True), tree)


def config_inverse(spec_lines, tree: dict) -> list[str] | None:
    """Exact inverse statements of a Configlet relative to ``tree``; None when the Configlet cannot be inverted safely."""
    try:
        return model.inverse(_operations(spec_lines, tree), tree)
    except model.ModelError:
        return None


def outgoing(spec_lines, tree: dict) -> list[str]:
    """The statements sent for a Configlet: its own rendered lines, except that a leaf-list carries the members ``tree``
    already holds plus the Configlet's (see ``srlinux_model.additive``)."""
    lines = model.statements(spec_lines)
    return [model.statement(op) if op.multi else line
            for line, op in zip(lines, _operations(lines, tree))]


class SrLinuxExecutor(DeviceExecutor):
    platform = "nokia_srlinux"

    def __init__(self, device: dict, *, connection_factory=None, reader=None):
        self._device = device
        self._connection_factory = connection_factory or inventory_session
        self._reader = reader                               # accepted for registry symmetry; state comes from gNMI
        self._conn = None
        self._inverses: dict[str, list[str]] = {}           # cfg_id -> inverse statements (never persisted)
        self._applied: dict[str, str] = {}                  # cfg_id -> configuration digest captured right before apply

    # -- session --------------------------------------------------------------------------------------------------------
    def connect(self) -> None:
        try:
            self._conn = self._connection_factory(self._device)
        except GnmiError as exc:
            raise ExecutorError(exc.code) from None

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def config_tree(self) -> dict:
        """The running configuration as a plain tree (the import parser's input shape)."""
        if self._conn is None:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        try:
            tree = model.tree_from_gnmi(self._conn.get("/", "config"))
        except (GnmiError, ValueError, TypeError, KeyError, AttributeError):
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE") from None
        if not tree:
            raise ExecutorError("PREVIOUS_STATE_UNAVAILABLE")
        return tree

    @staticmethod
    def tree_digest(tree: dict) -> str:
        return hashlib.sha256(model.digest_text(tree).encode()).hexdigest()

    def running_config_digest(self) -> str:
        return self.tree_digest(self.config_tree())

    # -- contract -------------------------------------------------------------------------------------------------------
    def assess(self, spec: ConfigletSpec) -> Assessment:
        if spec.origin != "STRUCTURED" or not spec.lines or spec.object_type not in OBJECT_TYPES:
            return Assessment(REFUSE, False, {}, spec.integrity_error or "PLATFORM_EXECUTION_UNSUPPORTED")
        try:
            model.operations(spec.lines, strict=True)
        except model.ModelError:
            return Assessment(REFUSE, False, {}, "PLATFORM_EXECUTION_UNSUPPORTED")
        tree = self.config_tree()
        inverse = config_inverse(spec.lines, tree)
        facts = {"kind": "config_tree", "modelled": True}
        if inverse is None:
            return Assessment(APPLY, False, facts, state.COMPENSATION_NOT_PROVABLE)
        facts["config_digest"] = self.tree_digest(tree)
        if not inverse:
            return Assessment(SKIP_SATISFIED, True, facts)      # every leaf already holds the wanted value
        facts["created"] = sum(line.startswith("delete ") for line in inverse)
        facts["restored_values"] = sum(line.startswith("set ") for line in inverse)
        self._inverses[spec.cfg_id] = inverse
        return Assessment(APPLY, True, facts)

    def _send(self, statements) -> ApplyOutcome:
        try:
            sent = self._conn.set_cli(statements)
        except GnmiError as exc:
            # A rejected SetRequest commits nothing; any other failure leaves the outcome unknown.
            return ApplyOutcome(False, exc.code, partial_effects=exc.code != "COMMAND_REJECTED", lines_sent=len(statements))
        return ApplyOutcome(True, lines_sent=sent)

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:
        # Preflight ran before any Configlet of the plan was applied: capture the tree as it is NOW, so reverse-order
        # compensation restores exactly the state this Configlet found.
        try:
            tree = self.config_tree()
        except ExecutorError as exc:
            return ApplyOutcome(False, exc.code)
        inverse = config_inverse(spec.lines, tree)
        if inverse is None:
            return ApplyOutcome(False, "COMMAND_REJECTED")      # nothing sent: no inverse is provable any more
        self._inverses[spec.cfg_id], self._applied[spec.cfg_id] = inverse, self.tree_digest(tree)
        if not inverse:
            return ApplyOutcome(True, lines_sent=0)
        statements = outgoing(spec.lines, tree)
        sent = self._send(statements)
        if not sent.ok and sent.error_code == "SESSION_EXPIRED":
            # The writer renewed its channel. Never replay a possibly committed Set without comparing the captured
            # pre-apply tree; any changed or unreadable tree is left for compensation to resolve.
            try:
                if self.running_config_digest() == self._applied[spec.cfg_id]:
                    sent = self._send(statements)
            except ExecutorError as exc:
                return ApplyOutcome(False, exc.code, partial_effects=True, lines_sent=len(statements))
        return sent

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:
        wanted = self._applied.get(spec.cfg_id) or assessment.previous_state.get("config_digest")
        inverse = self._inverses.get(spec.cfg_id)
        try:
            if wanted and self.running_config_digest() == wanted:
                return CompensationOutcome("COMPENSATED", detail={"action": "NONE_NEEDED"})
            if not wanted or not inverse:
                return CompensationOutcome("COMPENSATION_FAILED", "UNSUPPORTED")
            sent = self._send(inverse)
            if not sent.ok and sent.error_code == "SESSION_EXPIRED":
                # The stale session rejected the Set. Read through the renewed channel first: a write result is never
                # assumed, and the inverse is sent again only if the captured configuration is still absent.
                if self.running_config_digest() == wanted:
                    return CompensationOutcome("COMPENSATED", detail={"action": "READBACK_RESTORED"})
                sent = self._send(inverse)
            if not sent.ok:
                return CompensationOutcome("COMPENSATION_FAILED", sent.error_code)
            if self.running_config_digest() != wanted:
                return CompensationOutcome("COMPENSATION_FAILED", "STATE_NOT_RESTORED")
        except ExecutorError as exc:
            return CompensationOutcome("COMPENSATION_UNVERIFIED", exc.code)
        return CompensationOutcome("COMPENSATED", detail={"action": "INVERSE_APPLIED", "statements": len(inverse)})
