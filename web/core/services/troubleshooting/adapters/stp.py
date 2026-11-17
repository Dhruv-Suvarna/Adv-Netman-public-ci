"""STP source adapter: wires the version-gated cEOS ``show spanning-tree | json`` parser into the existing runtime without a new collector.

Flow (all pieces pre-exist except the parser):  ``collectors.CliCollector`` (catalogue key ``spanning_tree``, read-only) ->
``normalization.normalize_stp`` (parser ``stp.state``/``eos-json-1.0``) -> ``runtime.map_observations`` -> engine keys ``stp.state@<vlan>`` /
``stp.port_protection@<interface>`` consumed by RB04 ST02..ST06.

This module only provides (a) ``StpContext`` -- the previous-sample history and single-instance VLAN aliases that turn the cumulative EOS
topology-change counter into windowed facts, and (b) honest source labelling: ``describe_source`` states whether STP evidence is gateway-pinned or
recorded/simulated.  Nothing here touches a device. Context is caller-owned and must be kept per case; losing it produces UNKNOWN diagnoses until history is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .. import normalization as nz

SOURCE_VERSION = "1.1.0"
PARSER_ID = "stp.state"
SUPPORTED = {"platform": "ceos", "os_min": "4.28", "os_max_exclusive": "5.0", "command": "show spanning-tree | json"}
LIVE, RECORDED, SIMULATED = "LIVE_GATEWAY_PINNED", "RECORDED", "SIMULATED"


@dataclass
class StpContext:
    """``RuntimeDeps.stp_context``.  ``history`` is shared across polls of one case; ``vlans`` are the VLANs a single-instance mode (RSTP/MST0) serves."""

    history: nz.StpHistory = field(default_factory=nz.StpHistory)
    vlans: tuple = ()

    @classmethod
    def for_vlans(cls, vlans: Iterable) -> "StpContext":
        return cls(vlans=tuple(str(v) for v in vlans))


def describe_source(*, gateway: dict | None = None, recorded: bool = False) -> dict:
    """Provenance label for STP evidence.  Only a gateway-recorded run (``gateway['live']``) is LIVE; anything else is never presented as live."""
    if gateway and gateway.get("live") is True:
        label = LIVE
    else:
        label = RECORDED if recorded else SIMULATED
    return {"source": "stp", "label": label, "live": label == LIVE, "parser": {"id": PARSER_ID, "version": nz.PARSERS[PARSER_ID][0].version},
            "supported": dict(SUPPORTED), "gateway": gateway or None, "adapter_version": SOURCE_VERSION}


def is_supported(platform: str, os_version: str) -> bool:
    try:
        nz.select_parser(PARSER_ID, platform, os_version)
        return True
    except nz.ParserSelectionError:
        return False
