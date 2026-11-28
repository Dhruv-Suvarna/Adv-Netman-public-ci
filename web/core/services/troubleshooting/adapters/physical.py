"""Physical-state evidence source adapter (RB01 LF03/LF04, RB07 PH01/PH03..PH09, HC04/HC05): request building for the injected read-only ``physical-source/1`` reader.

Flow: ``RuntimeDeps.phy_source`` -> ``collectors.PhysicalCollector`` -> ``normalization.normalize_physical_state`` (parser ``phy.state``) -> observations
``interface.transceiver`` / ``interface.fec`` / ``interface.rate.<framing counter>`` / ``interface.counter_event`` / ``interface.l1_events`` -> ``runtime.map_observations`` (existing
pass-through / rate / reset paths) -> the existing RB01/RB07 keys.

Scope: one bounded read per admitted device.  The TARGET interface is read on the target device; its PEER end is read only on the peer device (which must itself be admitted and in the
case scope) and only when ``PhysicalContext.links`` names the link -- data for another port inside a document is discarded, never re-attributed.  Without the source the keys
stay explicit NOT_CONFIGURED gaps.  Nothing here issues a device command, clears a counter or bounces a port.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import normalization as nz

SOURCE_VERSION = "1.0.0"
PHYSICAL_KEYS = frozenset({"interface.transceiver", "interface.fec", "interface.l1_events"})
PHY_GAP_REASON = ("NOT_CONFIGURED: no injected read-only physical-state source is available; transceiver/DOM/FEC/L1-event evidence is UNKNOWN "
                  "(virtual or unsupported optics are never reported healthy and no command is invented)")
WINDOW_S = 3600


@dataclass
class PhysicalContext:
    """``RuntimeDeps.phy_context``.  ``links`` = intent links ``{a, a_if, b, b_if}`` used only to name the peer end of the target interface."""

    links: tuple = field(default_factory=tuple)

    def peer(self, device: str, interface: str):
        want = nz.canonical_interface(interface)
        for ln in self.links:
            if ln.get("a") == device and nz.canonical_interface(str(ln.get("a_if", ""))) == want:
                return ln.get("b"), ln.get("b_if")
            if ln.get("b") == device and nz.canonical_interface(str(ln.get("b_if", ""))) == want:
                return ln.get("a"), ln.get("a_if")
        return None, None


def wanted_here(wanted) -> bool:
    return any(w in PHYSICAL_KEYS or w.startswith(("interface.rate.", "interface.counter")) for w in wanted)


def requests_for_device(target: dict | None, device: str, wanted, context: PhysicalContext | None) -> list[dict]:
    """-> ``[]`` or one request ``{interfaces, include, window_s}`` for ``device``."""
    target = target or {}
    if not wanted_here(wanted) or not target.get("device") or not target.get("interface"):
        return []
    ifn = None
    if target["device"] == device:
        ifn = target["interface"]
    elif context is not None:
        pdev, pif = context.peer(target["device"], target["interface"])
        if pdev == device and pif:
            ifn = pif
    if not ifn:
        return []
    return [{"interfaces": [ifn], "include": ["optics", "fec", "counters", "events"], "window_s": WINDOW_S}]


def gap_reason(source_configured: bool, has_request: bool) -> str:
    if not source_configured:
        return PHY_GAP_REASON
    if not has_request:
        return "SCOPE_MISMATCH: this device is neither the target end nor a link-mapped peer end of the target interface; physical state is not read"
    return "UNKNOWN: the injected physical source produced no usable evidence for this key (see the collector run)"
