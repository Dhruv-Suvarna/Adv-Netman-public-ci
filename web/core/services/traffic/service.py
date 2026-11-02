"""The traffic workbench lifecycle on the WEBSITE: validate -> create -> ask the runner -> finalise, plus reconciliation of abandoned runs.

    request  (browser: endpoint NAMES, a family, a few bounded numbers)
        -> validate()      every value checked against ``limits``; unknown fields ignored; nothing is sent for a refused request
        -> TrafficRun      CREATED (the DB constraint admits ONE active run)
        -> execute()       RUNNING; ONE structured request goes to the traffic runner over its Unix socket (``client``)
        -> finalised ONCE  PASSED / FAILED / TIMED_OUT with parsed metrics, the structured operation and bounded raw output

The website starts no process and holds no runtime privilege for a test: the runner (a separate service) revalidates the request against
its own limits and its own endpoint catalogue, runs the tool from a pinned tools image inside the endpoint's network namespace, and
removes what it created.  The operator never supplies an address, a container, an image, a flag or a command.  Test families are separate
things -- a ping is not a throughput test and is never reported as one.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from ... import models
from . import client, endpoints, limits, parsers
from .limits import BoundsError, bounded_int

F, Status, AF = models.TrafficTestFamily, models.TrafficRunStatus, models.TrafficAddressFamily

REFUSALS = {
    "FAMILY_UNKNOWN": "Unknown test family.",
    "ADDRESS_FAMILY_UNKNOWN": "Choose IPv4 or IPv6.",
    "PROTOCOL_NOT_APPLICABLE": "That protocol does not apply to this test family.",
    "SOURCE_NOT_AN_ENDPOINT": "The source is not a traffic endpoint.",
    "DESTINATION_NOT_AN_ENDPOINT": "The destination is not a traffic endpoint.",
    "SAME_ENDPOINT": "Source and destination must be different endpoints.",
    "FAMILY_NOT_SUPPORTED_BY_ENDPOINT": "An endpoint has no address of that family in the lab design.",
    "PARAMETER_OUT_OF_BOUNDS": "A parameter is outside its allowed range.",
    "REFERENCE_UNKNOWN": "A related Change / provisioning / soak reference does not exist.",
    "TEST_ALREADY_RUNNING": "Another traffic test is running; only one may run at a time.",
}
FAILURES = {
    # the runner could not reach, or lost, an endpoint
    "ENDPOINT_NOT_FOUND": "An endpoint container does not exist.", "ENDPOINT_NOT_RUNNING": "An endpoint container is not running.",
    "ENDPOINT_WRONG_LAB": "An endpoint container does not belong to the lab.", "ENDPOINT_INVALID": "An endpoint reference is invalid.",
    "ENDPOINT_LOST": "An endpoint stopped or was replaced while the test was running.",
    "RUNTIME_UNAVAILABLE": "The container runtime is unavailable to the traffic runner.",
    "TOOLS_IMAGE_MISSING": "The pinned diagnostic tools image is not present on the host.",
    "TOOLS_START_FAILED": "The diagnostic tools container could not be started.",
    "RUNTIME_NOT_CLEANED": "A temporary diagnostic container of this run could not be confirmed removed.",
    "ADDRESS_DISCOVERY_FAILED": "The endpoint addresses could not be read.",
    "NO_ADDRESS_FOR_FAMILY": "An endpoint holds no address of the requested family right now.",
    "OPERATION_NOT_ALLOWED": "The operation is not allowed by the process boundary.",
    # the runner refused the request (its own, second validation) or was busy
    "MALFORMED_REQUEST": "The traffic runner refused the request as malformed.", "UNAUTHORIZED": "The traffic runner does not accept requests from this service.",
    "UNSUPPORTED_VERSION": "The traffic runner speaks a different protocol version.", "UNKNOWN_ENDPOINT": "The traffic runner does not know that endpoint.",
    "SAME_ENDPOINT": "The traffic runner refused identical endpoints.", "FAMILY_NOT_SUPPORTED_BY_ENDPOINT": "The traffic runner refused the address family for an endpoint.",
    "UNSUPPORTED_TEST_TYPE": "The traffic runner does not offer that test type.", "ADDRESS_FAMILY_UNKNOWN": "The traffic runner refused the address family.",
    "PROTOCOL_NOT_APPLICABLE": "The traffic runner refused the protocol for that test type.",
    "PARAMETER_OUT_OF_BOUNDS": "The traffic runner refused a parameter outside its own limits.",
    "BUSY": "The traffic runner is already running a test.", "RUN_ID_REPLAYED": "The traffic runner has already seen this run.",
    # the website could not talk to the runner
    "RUNNER_UNAVAILABLE": "The traffic runner service is not reachable from the website.",
    "RUNNER_TIMEOUT": "The traffic runner did not answer within the run's time budget.",
    "RUNNER_PROTOCOL_ERROR": "The traffic runner's reply was not a valid answer to this run.",
    # the test ran and failed
    "PACKET_LOSS": "Some or all probes were lost.", "DESTINATION_UNREACHABLE": "The destination did not answer.",
    "PATH_INCOMPLETE": "The path did not reach the destination within the hop limit.",
    "CONNECTION_REFUSED": "The destination refused the connection (port closed).", "CONNECTION_TIMEOUT": "The connection attempt timed out.",
    "SERVER_START_FAILED": "The temporary iperf3 server did not start listening.", "CLIENT_FAILED": "The iperf3 client reported an error.",
    "SERVER_NOT_STOPPED": "The temporary iperf3 server could not be confirmed stopped.",
    "PARSE_ERROR": "The tool output could not be parsed.", "TIMEOUT": "The test exceeded its time budget and was stopped.",
    "PROCESS_LOST": "The run was abandoned (process or application restart) and never finished.", "INTERNAL_ERROR": "The workbench failed internally.",
}


@dataclass
class Request:
    """A validated request: only names, enumerations and bounded integers."""

    source: str
    destination: str
    address_family: str
    family: str
    protocol: str
    requested: dict
    parameters: dict
    change: object | None = None
    provisioning_run: object | None = None
    soak_run: object | None = None


@dataclass
class Validation:
    request: Request | None
    errors: list = field(default_factory=list)      # [{"code", "message", "field"?, "low"?, "high"?}]

    @property
    def ok(self) -> bool:
        return self.request is not None and not self.errors

    @property
    def codes(self) -> list[str]:
        return [e["code"] for e in self.errors]


def _error(code: str, **details) -> dict:
    return {"code": code, "message": REFUSALS[code], **details}


_FIELDS = ("source", "destination", "address_family", "family", "protocol", "count", "size", "max_hops", "port", "timeout", "duration",
           "bandwidth_kbps", "parallel", "length", "change_id", "prov_id", "soak_id")


def _parameters(family: str, protocol: str, data: dict) -> dict:
    """The bounded parameters of one family.  Raises BoundsError.  A parameter another family owns is simply not read."""
    if family == F.ICMP:
        return {"count": bounded_int(data.get("count"), "count", limits.PING_COUNT, 3), "size": bounded_int(data.get("size"), "size", limits.PING_SIZE, 56)}
    if family == F.TRACEROUTE:
        return {"max_hops": bounded_int(data.get("max_hops"), "max_hops", limits.TRACEROUTE_MAX_HOPS, 15)}
    if family == F.TCP_CONNECT:
        return {"port": bounded_int(data.get("port"), "port", limits.PORT), "timeout": bounded_int(data.get("timeout"), "timeout", limits.PROBE_TIMEOUT, 3)}
    if family == F.UDP_PROBE:
        return {"port": bounded_int(data.get("port"), "port", limits.PORT), "timeout": bounded_int(data.get("timeout"), "timeout", limits.PROBE_TIMEOUT, 2),
                "count": bounded_int(data.get("count"), "count", limits.UDP_PROBE_COUNT, 3), "size": bounded_int(data.get("size"), "size", limits.UDP_PROBE_SIZE, 64)}
    parameters = {
        "port": bounded_int(data.get("port"), "port", limits.IPERF_PORTS, limits.IPERF_PORTS[0]),
        "duration": bounded_int(data.get("duration"), "duration", limits.IPERF_DURATION, 5),
        "bandwidth_kbps": bounded_int(data.get("bandwidth_kbps"), "bandwidth_kbps", limits.IPERF_BANDWIDTH_KBPS, limits.IPERF_DEFAULT_BANDWIDTH_KBPS),
        "parallel": bounded_int(data.get("parallel"), "parallel", limits.IPERF_PARALLEL, 1),
    }
    if protocol == "UDP":
        parameters["length"] = bounded_int(data.get("length"), "length", limits.IPERF_UDP_LENGTH, 1200)
    return parameters


def validate(data) -> Validation:
    """Check a request against the catalogue and the hard limits.  READ-ONLY: contacts nothing and spawns nothing."""
    data = {key: data.get(key) for key in _FIELDS}
    errors = []
    family, address_family = str(data["family"] or ""), str(data["address_family"] or "")
    if family not in F.values:
        errors.append(_error("FAMILY_UNKNOWN"))
    if address_family not in AF.values:
        errors.append(_error("ADDRESS_FAMILY_UNKNOWN"))
    catalogue = endpoints.catalogue()
    source, destination = catalogue.get(str(data["source"] or "")), catalogue.get(str(data["destination"] or ""))
    if source is None:
        errors.append(_error("SOURCE_NOT_AN_ENDPOINT"))
    if destination is None:
        errors.append(_error("DESTINATION_NOT_AN_ENDPOINT"))
    if source is not None and destination is not None and source.name == destination.name:
        errors.append(_error("SAME_ENDPOINT"))
    if errors:
        return Validation(None, errors)
    lacking = [e.name for e in (source, destination) if address_family not in e.families]
    if lacking:   # e.g. IPv4 from / to H4: not applicable by design, refused up front -- never reported as a failed test
        errors.append(_error("FAMILY_NOT_SUPPORTED_BY_ENDPOINT", endpoints=lacking, address_family=address_family))
    allowed = limits.PROTOCOL[family]
    protocol = str(data["protocol"] or allowed[0]).upper()
    if protocol not in allowed:
        errors.append(_error("PROTOCOL_NOT_APPLICABLE", allowed=list(allowed)))
        protocol = allowed[0]
    parameters = {}
    try:
        parameters = _parameters(family, protocol, data)
    except BoundsError as exc:
        errors.append(_error("PARAMETER_OUT_OF_BOUNDS", field=exc.field, low=exc.low, high=exc.high))
    references = {}
    for key, lookup in (("change_id", lambda v: models.Change.objects.filter(change_id=v).first()),
                        ("prov_id", _provisioning), ("soak_id", _soak)):
        value = str(data[key] or "").strip()
        if value:
            references[key] = lookup(value)
            if references[key] is None:
                errors.append(_error("REFERENCE_UNKNOWN", field=key))
    if errors:
        return Validation(None, errors)
    requested = {k: str(v)[:64] for k, v in data.items() if v not in (None, "")}
    return Validation(Request(source.name, destination.name, address_family, family, protocol, requested, parameters,
                              references.get("change_id"), references.get("prov_id"), references.get("soak_id")))


def _provisioning(value: str):
    return models.ProvisioningRun.objects.filter(pk=int(value[5:])).first() if value.startswith("PROV-") and value[5:].isdigit() else None


def _soak(value: str):
    return models.ProbationSoakRun.objects.filter(pk=int(value[5:])).first() if value.startswith("SOAK-") and value[5:].isdigit() else None


def repository_head() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=settings.REPO_ROOT, capture_output=True, check=True, text=True,  # noqa: S603,S607
                              timeout=5).stdout.strip()[:40]
    except (OSError, subprocess.SubprocessError):
        return ""


# --- abandoned runs ------------------------------------------------------------------------------------------------------------
def reconcile(*, now=None) -> list:
    """Finalise every active run whose deadline passed (a crash or restart left it behind) as INTERRUPTED.  Never as a pass."""
    now = now or timezone.now()
    reconciled = []
    for run in models.TrafficRun.objects.filter(status__in=list(models.TRAFFIC_ACTIVE), deadline_at__lt=now):
        run.status, run.failure_reason, run.finished_at = Status.INTERRUPTED, "PROCESS_LOST", now
        run.save(update_fields=["status", "failure_reason", "finished_at"])
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.TRAFFIC_RUN_RECONCILED, object_type="TrafficRun", object_id=str(run.run_id), actor="traffic-reconciler",
            summary=f"traffic run {run.run_id} abandoned; marked INTERRUPTED"[:255], metadata={"run_id": str(run.run_id), "family": run.family})
        reconciled.append(run)
    return reconciled


# --- create --------------------------------------------------------------------------------------------------------------------
def create_run(request: Request, *, operator: str, now=None):
    """-> (run, None) or (None, refusal).  The DB constraint, not a check-then-act, decides whether a test may start."""
    now = now or timezone.now()
    reconcile(now=now)
    budget = limits.run_timeout_seconds(request.family, request.parameters)
    try:
        with transaction.atomic():
            run = models.TrafficRun.objects.create(
                operator=operator[:150], source=request.source, destination=request.destination, address_family=request.address_family,
                family=request.family, protocol=request.protocol, requested=request.requested, parameters=request.parameters,
                deadline_at=now + timedelta(seconds=budget + 30), change=request.change, provisioning_run=request.provisioning_run,
                soak_run=request.soak_run, repository_head=repository_head(), engine_version=limits.ENGINE_VERSION,
            )
    except IntegrityError:
        return None, _error("TEST_ALREADY_RUNNING")
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.TRAFFIC_RUN_STARTED, change=request.change, object_type="TrafficRun", object_id=str(run.run_id),
        actor=operator[:150], summary=f"traffic {run.family} {run.source} -> {run.destination} ({run.address_family})"[:255],
        metadata={"run_id": str(run.run_id), "family": run.family, "source": run.source, "destination": run.destination})
    return run, None


# --- run -----------------------------------------------------------------------------------------------------------------------
@dataclass
class Outcome:
    status: str
    reason: str = ""
    metrics: dict = field(default_factory=dict)
    raw: str = ""
    operation: dict = field(default_factory=dict)


def _icmp(run, reply) -> Outcome:
    out, operation = reply.get("stdout", ""), reply.get("operation") or {}
    try:
        metrics = parsers.ping(out)
    except parsers.ParseError:
        return Outcome(Status.FAILED, "DESTINATION_UNREACHABLE" if reply.get("exit_code") else "PARSE_ERROR", raw=out + reply.get("stderr", ""), operation=operation)
    if metrics["received"] == 0:
        return Outcome(Status.FAILED, "DESTINATION_UNREACHABLE", metrics, out, operation)
    if metrics["received"] < metrics["transmitted"]:
        return Outcome(Status.FAILED, "PACKET_LOSS", metrics, out, operation)
    return Outcome(Status.PASSED, "", metrics, out, operation)


def _traceroute(run, reply) -> Outcome:
    out, operation = reply.get("stdout", ""), reply.get("operation") or {}
    try:
        metrics = parsers.traceroute(out, reply.get("destination_address", ""))
    except parsers.ParseError:
        return Outcome(Status.FAILED, "PARSE_ERROR", raw=out + reply.get("stderr", ""), operation=operation)
    return Outcome(Status.PASSED if metrics["reached"] else Status.FAILED, "" if metrics["reached"] else "PATH_INCOMPLETE", metrics, out, operation)


def _probe(run, reply) -> Outcome:
    out, operation = reply.get("stdout", ""), reply.get("operation") or {}
    try:
        metrics = parsers.probe(out)
    except parsers.ParseError:
        return Outcome(Status.FAILED, "PARSE_ERROR", raw=out + reply.get("stderr", ""), operation=operation)
    reason = {"connected": "", "open_or_filtered": "", "refused": "CONNECTION_REFUSED", "timeout": "CONNECTION_TIMEOUT"}.get(
        metrics["result"], "DESTINATION_UNREACHABLE")
    return Outcome(Status.FAILED if reason else Status.PASSED, reason, metrics, out, operation)


def _iperf(run, reply) -> Outcome:
    out, operation, p = reply.get("stdout", ""), reply.get("operation") or {}, run.parameters
    try:
        metrics = parsers.iperf3(out, udp=run.protocol == "UDP")
        metrics["requested_bits_per_second"] = p["bandwidth_kbps"] * 1000 * p["parallel"]
        return Outcome(Status.PASSED, "", metrics, out, operation)
    except parsers.ParseError as exc:
        return Outcome(Status.FAILED, "CLIENT_FAILED", {"client_error": str(exc)[:240]}, out + reply.get("stderr", ""), operation)


_VERDICT = {F.ICMP: _icmp, F.TRACEROUTE: _traceroute, F.TCP_CONNECT: _probe, F.UDP_PROBE: _probe, F.IPERF3: _iperf}


def _interpret(run, reply) -> Outcome:
    """The runner's reply -> the run's verdict.  The runner reports what happened; what it MEANS is decided here, from parsed output."""
    server = reply.get("server") if isinstance(reply.get("server"), dict) else None
    runtime = {"runner": str(reply.get("runner", ""))[:32], "image": str(reply.get("image", ""))[:80], "cleanup": reply.get("cleanup") or {}}
    if not reply["ok"]:
        code = reply["code"] if reply["code"] in FAILURES else "INTERNAL_ERROR"
        outcome = Outcome(Status.FAILED, code, operation=dict(reply.get("operation") or {}))
    elif reply.get("timed_out"):
        outcome = Outcome(Status.TIMED_OUT, "TIMEOUT", raw=reply.get("stdout", ""), operation=dict(reply.get("operation") or {}))
    else:
        outcome = _VERDICT[run.family](run, reply)
    if server is not None:
        outcome.metrics = {**outcome.metrics, "server": server}
    outcome.operation = {**outcome.operation, "runtime": runtime}
    return outcome


def execute(run):
    """Run a CREATED test to its single final state.  Never raises: every failure is a recorded outcome."""
    run.status, run.started_at = Status.RUNNING, timezone.now()
    run.save(update_fields=["status", "started_at"])
    source_address, destination_address = "", ""
    try:
        reply = client.submit(run)
        source_address, destination_address = str(reply.get("source_address", ""))[:64], str(reply.get("destination_address", ""))[:64]
        outcome = _interpret(run, reply)
    except client.ClientError as exc:
        outcome = Outcome(Status.TIMED_OUT if exc.code == "RUNNER_TIMEOUT" else Status.FAILED, exc.code)
    except Exception:  # noqa: BLE001 - a workbench defect is a recorded FAILED run, never a half-finished one
        outcome = Outcome(Status.FAILED, "INTERNAL_ERROR")
    return _finalise(run, outcome, source_address, destination_address)


def _finalise(run, outcome: Outcome, source_address: str, destination_address: str):
    run.status, run.failure_reason, run.metrics = outcome.status, outcome.reason, outcome.metrics
    run.raw_output, run.operation = (outcome.raw or "")[: limits.RAW_OUTPUT_LIMIT], outcome.operation
    run.source_address, run.destination_address = source_address, destination_address     # discovered facts, written once with the verdict
    run.finished_at = timezone.now()
    run.save(update_fields=["status", "failure_reason", "metrics", "raw_output", "operation", "finished_at", "source_address", "destination_address"])
    models.AuditEvent.objects.create(
        event_type=models.AuditEventType.TRAFFIC_RUN_FINISHED, change=run.change, object_type="TrafficRun", object_id=str(run.run_id),
        actor=run.operator, summary=f"traffic {run.family} {run.source} -> {run.destination}: {run.status}"[:255],
        metadata={"run_id": str(run.run_id), "status": run.status, "reason": run.failure_reason})
    return run


def request_run(data, *, operator: str):
    """The one entry point of the page: validate, create, execute.  -> (run or None, errors)"""
    checked = validate(data)
    if not checked.ok:
        models.AuditEvent.objects.create(
            event_type=models.AuditEventType.TRAFFIC_RUN_REFUSED, object_type="TrafficRun", object_id="", actor=operator[:150],
            summary="traffic test request refused"[:255], metadata={"codes": checked.codes})
        return None, checked.errors
    run, refusal = create_run(checked.request, operator=operator)
    if run is None:
        return None, [refusal]
    return execute(run), []
