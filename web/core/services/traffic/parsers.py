"""Pure parsers of the diagnostic tools' output.  Each returns bounded, typed metrics or raises ``ParseError`` -- never a guess."""

from __future__ import annotations

import json
import re

from ..health import live


class ParseError(ValueError):
    pass


def ping(text: str) -> dict:
    """iputils ping summary -> transmitted / received / loss_percent / rtt_min_ms / rtt_avg_ms / rtt_max_ms / rtt_mdev_ms."""
    try:
        metrics = live.parse_ping_output(text)
    except live.LiveError as exc:
        raise ParseError("ping") from exc
    mdev = re.search(r"=\s*[\d.]+/[\d.]+/[\d.]+/([\d.]+)\s*ms", text or "")
    metrics["rtt_mdev_ms"] = float(mdev.group(1)) if mdev else None
    return metrics


_HOP = re.compile(r"^\s*(\d+)\s+(.*)$")
_HOP_REPLY = re.compile(r"([0-9a-fA-F:.]+)\s+([\d.]+)\s*ms")


def traceroute(text: str, destination: str) -> dict:
    """``traceroute -n -q 1`` -> {"hops": [{"hop", "address", "rtt_ms"}], "hop_count", "reached"}.  A silent hop has address None."""
    hops = []
    for line in (text or "").splitlines():
        match = _HOP.match(line)
        if not match or line.lstrip().lower().startswith("traceroute"):
            continue
        reply = _HOP_REPLY.search(match.group(2))
        hops.append({"hop": int(match.group(1)), "address": reply.group(1) if reply else None,
                     "rtt_ms": float(reply.group(2)) if reply else None})
    if not hops:
        raise ParseError("traceroute")
    hops = hops[:64]
    return {"hops": hops, "hop_count": len(hops), "reached": hops[-1]["address"] == destination,
            "silent_hops": sum(1 for h in hops if h["address"] is None)}


def iperf3(text: str, *, udp: bool) -> dict:
    """iperf3 ``--json`` client report -> throughput, and for UDP jitter / loss.  An ``error`` member is a ParseError carrying its text."""
    try:
        document = json.loads(text or "")
    except ValueError as exc:
        raise ParseError("iperf3: not JSON") from exc
    if not isinstance(document, dict) or document.get("error"):
        raise ParseError(f"iperf3: {str((document or {}).get('error', 'malformed'))[:200]}" if isinstance(document, dict) else "iperf3: malformed")
    end = document.get("end") or {}
    try:
        if udp:
            total = end["sum"]
            return {
                "bits_per_second": float(total["bits_per_second"]), "bytes": int(total["bytes"]), "seconds": float(total["seconds"]),
                "jitter_ms": float(total["jitter_ms"]), "lost_packets": int(total["lost_packets"]), "packets": int(total["packets"]),
                "loss_percent": float(total["lost_percent"]),
            }
        sent, received = end["sum_sent"], end["sum_received"]
        return {
            "bits_per_second": float(received["bits_per_second"]), "sent_bits_per_second": float(sent["bits_per_second"]),
            "bytes": int(received["bytes"]), "seconds": float(received["seconds"]), "retransmits": int(sent.get("retransmits", 0)),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise ParseError("iperf3: summary missing") from exc


def probe(text: str) -> dict:
    """The fixed TCP / UDP probe script's one JSON line -> {"result", "elapsed_ms", ...}."""
    try:
        document = json.loads((text or "").strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise ParseError("probe") from exc
    if not isinstance(document, dict) or "result" not in document:
        raise ParseError("probe")
    return document
