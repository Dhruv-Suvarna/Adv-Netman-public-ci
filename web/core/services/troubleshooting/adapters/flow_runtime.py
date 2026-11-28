"""Deployment-owned wire input binding; no receiver, exporter configuration or capability promotion."""
from dataclasses import dataclass
from typing import Any

from .flow_wire import FlowWireInput
from ..collectors import check_admission


@dataclass(frozen=True)
class FlowRuntimeInput:
    """An authorized receiver supplies this binding through RuntimeDeps.flow_input.

    Selector uses normalize_flow_records' protocol/ports/prefix contract. Prefix
    privacy is mandatory at this runtime seam. Receiver owns queue replay/durability.
    """
    wire: FlowWireInput
    selector: dict
    expected_exporters: tuple = ()

    def collect(self, collector: Any, target: Any, *, limit: int) -> dict:
        if not any(self.selector.get(k) for k in ("protocol", "src_ports", "dst_ports", "src_prefixes", "dst_prefixes")):
            raise ValueError("UNSCOPED_FLOW_QUERY: deployment service selector required")
        admission = check_admission(target, collector.source_type, capability_probe=collector.capability_probe,
                                    authorized_sources=collector.authorized_sources)
        if not admission.ok:
            # Preserve the deployment queue when platform authorization refuses collection.
            return collector.collect(target, [], self.selector, expected_exporters=self.expected_exporters, privacy="prefix")
        metadata = []

        class Bridge:
            def collect(self, target, records, selector, **kwargs):
                # Records have already been scoped and privacy-masked by wire.collect.
                for r in records:
                    metadata.append({k: r.get(k) for k in ("exporter", "sampling_rate", "sampling_source", "wire", "first", "last")})
                return collector.collect(target, records, selector, **kwargs)

        bundle = self.wire.collect(Bridge(), target, self.selector, expected_exporters=self.expected_exporters,
                                   privacy="prefix", limit=limit)
        bundle["wire_ingest"].update(schema="nmas.troubleshooting.flow-runtime/1", records=metadata,
                                    production_health="UNKNOWN", measured_packet_loss=None,
                                    limitation="Export volume and sequence gaps do not measure production loss, latency or availability.")
        # Health is receiver-wide and cumulative, not attributed to this service.
        bundle["wire_ingest"]["health_scope"] = "receiver-wide cumulative; may include other exporters/services"
        bundle["wire_ingest"]["templates"] = self.wire.health()["templates"]
        if bundle["wire_ingest"]["health"]["data_loss"]:
            for o in bundle.get("observations", []):
                o.setdefault("flags", []).append("WIRE_DATA_LOSS")
                if o["quality"] == "OK":
                    o["quality"] = "PARTIAL"
            for e in bundle.get("evidence", []):
                e["status"] = "PARTIAL"
        for e in bundle.get("evidence", []):
            e["parser"] = {"id": "netflow.ipfix", "version": "1.0"}
        return bundle
