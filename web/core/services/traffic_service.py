"""Facade of the traffic / test workbench (V2 Phase 5B).  Views and commands import this module only."""

from __future__ import annotations

import uuid

from .. import models
from .traffic import endpoints, limits, service

FAILURES, REFUSALS = service.FAILURES, service.REFUSALS
validate = service.validate
request_run = service.request_run
reconcile = service.reconcile
catalogue = endpoints.catalogue


def get_run(run_id):
    try:
        return models.TrafficRun.objects.filter(run_id=uuid.UUID(str(run_id))).first()
    except (ValueError, AttributeError):
        return None


def list_runs(*, limit: int = 50):
    return list(models.TrafficRun.objects.select_related("change", "provisioning_run", "soak_run")[:limit])


def active_run():
    return models.TrafficRun.objects.filter(status__in=list(models.TRAFFIC_ACTIVE)).first()


def form_limits() -> dict:
    """The bounds the page shows.  Presentation only: ``traffic.limits`` enforces them on the server."""
    return {
        "ping_count": limits.PING_COUNT, "ping_size": limits.PING_SIZE, "max_hops": limits.TRACEROUTE_MAX_HOPS, "port": limits.PORT,
        "probe_timeout": limits.PROBE_TIMEOUT, "udp_count": limits.UDP_PROBE_COUNT, "udp_size": limits.UDP_PROBE_SIZE,
        "iperf_ports": limits.IPERF_PORTS, "iperf_duration": limits.IPERF_DURATION, "iperf_bandwidth_kbps": limits.IPERF_BANDWIDTH_KBPS,
        "iperf_parallel": limits.IPERF_PARALLEL, "iperf_udp_length": limits.IPERF_UDP_LENGTH, "max_active": limits.MAX_ACTIVE_RUNS,
    }
