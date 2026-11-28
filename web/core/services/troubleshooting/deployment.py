"""Deployment factory: read-only ``RuntimeDeps`` for the troubleshooting API *and* the AI continuation (NMAS V2).

ONE zero-argument factory, :func:`runtime_deps`, serves both consumers, which previously used different settings:

* ``troubleshooting_views._runtime_deps``      -> ``settings.NMAS_TS_RUNTIME_FACTORY``   (``import_string(path)()``)
* ``troubleshooting_ai`` management command    -> ``settings.TROUBLESHOOTING_RUNTIME_DEPS`` / ``--deps`` (``getattr(module, attr)()`` must be ``RuntimeDeps``)

Point both at ``core.services.troubleshooting.deployment.runtime_deps``; both then build identical dependencies from ``settings.NMAS_TS_DEPLOYMENT``
(see ``docs/troubleshooting/deployment-bindings.md``).  :func:`consistency_problems` reports a mismatch between the two settings.

Guarantees (all fail closed)
* Nothing here reads credentials, opens a connection or contacts a device.  Transports / sessions are produced by *operator-supplied provider
  callables* (dotted paths) that are only invoked per admitted device during a run.  Their output is wrapped so that only ``execute`` /
  ``walk`` / ``get`` / ``provenance`` are reachable (no config/write method) and their provenance is passed through verbatim, never invented.
* Admission is resolved from the authoritative inventory + an authoritative **version provider** + an authoritative **lifecycle provider**.
  Device version and admission are never taken from case/client data.  Missing inventory entry, unsupported platform, missing/unparseable version,
  missing lifecycle answer, withdrawn or non-admitted lifecycle state => the device is refused (never probed).
* A misconfigured admission-affecting provider refuses every device; a misconfigured transport provider yields "no transport" (evidence UNAVAILABLE).
* No write capability exists in ``RuntimeDeps``; this module adds none.
"""

from __future__ import annotations

import importlib
from typing import Any, Callable

from . import baselines as bl
from .adapters.dns import DnsContext
from .adapters.probes import ProbeContext
from .adapters.stp import StpContext
from .adapters.l2 import L2Context
from .adapters.acl import AclContext
from .adapters.forwarding import ForwardingContext
from .adapters.physical import PhysicalContext
from . import collectors as col
from . import normalization as nz
from . import runtime as rt
from .adapters import capabilities as caps

FACTORY_PATH = "core.services.troubleshooting.deployment.runtime_deps"
SETTING = "NMAS_TS_DEPLOYMENT"
CONSUMER_SETTINGS = ("NMAS_TS_RUNTIME_FACTORY", "TROUBLESHOOTING_RUNTIME_DEPS")
KNOWN_PLATFORMS = frozenset(caps.KNOWN_PLATFORMS)
_KEYS = frozenset({"inventory", "version_provider", "lifecycle_provider", "cli_transport_factory", "snmp_session_factory", "syslog_source",
                   "dns_runner_factory", "dns_context_provider", "probe_runner_factory", "probe_context_provider", "stp_context_provider", "l2_context_provider", "acl_context_provider", "forwarding_context_provider", "flow_input", "baseline_sources_provider", "fib_reader_factory", "qos_reader_factory", "phy_reader_factory", "proto_reader_factory", "phy_context_provider",
                   "gnmi_getter_factory", "gnmi_paths", "gateway_platforms", "use_health_capability", "syslog_window_s"})
_NETWORK_PROVIDER_KEYS = frozenset({
    "cli_transport_factory", "snmp_session_factory", "gnmi_getter_factory", "dns_runner_factory",
    "probe_runner_factory", "fib_reader_factory", "qos_reader_factory", "phy_reader_factory", "proto_reader_factory",
})


def _load(path: str) -> Callable:
    mod, _, attr = str(path).replace(":", ".").rpartition(".")
    if not mod or not attr:
        raise ValueError(f"not a dotted path: {path!r}")
    obj = getattr(importlib.import_module(mod), attr)
    if not callable(obj):
        raise TypeError(f"{path!r} is not callable")
    return obj


def _resolve(value: Any) -> Callable | None:
    """A provider may be a dotted path or an already-callable object (tests / programmatic use)."""
    if value in (None, ""):
        return None
    return value if callable(value) else _load(value)


# ---------------------------------------------------------------------------------------------------------------- read-only wrappers
class ReadOnlyCli:
    """Exposes ONLY ``execute``/``provenance``/``close``; provenance is forwarded verbatim from the wrapped transport (or absent)."""

    def __init__(self, inner: Any):
        if not callable(getattr(inner, "execute", None)):
            raise TypeError("CLI transport must provide execute(rendered)")
        self._inner = inner
        if callable(getattr(inner, "provenance", None)):
            self.provenance = inner.provenance

    def execute(self, rendered):
        return self._inner.execute(rendered)

    def close(self) -> None:
        fn = getattr(self._inner, "close", None)
        if callable(fn):
            fn()


class ReadOnlySnmp:
    """Exposes ONLY ``walk``/``get`` (no set)."""

    def __init__(self, inner: Any):
        if not (callable(getattr(inner, "walk", None)) and callable(getattr(inner, "get", None))):
            raise TypeError("SNMP session must provide walk(oid) and get(oid)")
        self._inner = inner
        for name in ("provenance",):
            if callable(getattr(inner, name, None)):
                setattr(self, name, getattr(inner, name))

    def walk(self, oid):
        return self._inner.walk(oid)

    def get(self, oid):
        return self._inner.get(oid)


class ReadOnlyProbe:
    """Exposes ONLY ``execute`` / ``capabilities`` / ``provenance`` of an injected active-probe runner.  A runner without ``capabilities()`` is rejected (fail closed)."""

    def __init__(self, inner: Any):
        if not callable(getattr(inner, "execute", None)) or not callable(getattr(inner, "capabilities", None)):
            raise TypeError("probe runner must provide execute(request) and capabilities()")
        self._inner = inner
        if callable(getattr(inner, "provenance", None)):
            self.provenance = inner.provenance

    def capabilities(self):
        return tuple(self._inner.capabilities())

    def execute(self, request):
        return self._inner.execute(request)


class ReadOnlyReader:
    """Exposes ONLY ``read(request)`` / ``provenance`` of an injected FIB or QoS source reader (documents are returned verbatim; provenance verbatim or absent)."""

    def __init__(self, inner: Any):
        if not callable(getattr(inner, "read", None)):
            raise TypeError("reader must provide read(request)")
        self._inner = inner
        if callable(getattr(inner, "provenance", None)):
            self.provenance = inner.provenance

    def read(self, request):
        return self._inner.read(request)


def _guard(factory: Callable | None, wrap: Callable[[Any], Any], problems: list[str], label: str) -> Callable | None:
    """Per-device provider -> wrapped object; ANY provider failure means "no source" (UNAVAILABLE), never a partial/guessed one."""
    if factory is None:
        return None

    def build(info):
        try:
            obj = factory(info)
            return None if obj is None else wrap(obj)
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - sanitized: only the exception class is kept, never its text (may contain connection details)
            problems.append(f"{label}({getattr(info, 'device', '?')}): {type(exc).__name__}")
            return None
    return build


class LazyContext:
    """Resolve a typed context on first use, never during factory construction."""

    def __init__(self, provider, expected, problems, label):
        self._provider, self._expected = provider, expected
        self._problems, self._label = problems, label
        self._value = None

    def __getattr__(self, name):
        if self._value is None:
            try:
                value = self._provider()
                if not isinstance(value, self._expected):
                    raise TypeError("invalid context")
                self._value = value
            except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - a broken lazy context provider degrades to an empty context and is reported as a problem
                self._problems.append(f"{self._label}: {type(exc).__name__}")
                self._value = self._expected()
        return getattr(self._value, name)


class LazyBaselineSources:
    """Read-only baseline protocol; failed bindings never fall back to another source."""

    METHODS = ("intent", "golden", "history", "slo", "changes", "configs")

    def __init__(self, provider, problems):
        self._provider, self._problems = provider, problems
        self._source, self._loaded = None, False

    def _call(self, name, *args):
        try:
            if not self._loaded:
                self._loaded = True
                candidate = self._provider() if self._provider else None
                if not all(callable(getattr(candidate, n, None)) for n in self.METHODS):
                    raise TypeError("invalid baseline source")
                self._source = candidate
            if self._source is None:
                return bl.unavailable(name, "deployment baseline source unavailable")
            result = getattr(self._source, name)(*args)
            if not isinstance(result, dict) or result.get("status") not in ("available", "unavailable"):
                raise TypeError("invalid baseline result")
            return result
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - a failing baseline provider is reported as UNAVAILABLE, never as data
            self._problems.append(f"baseline.{name}: {type(exc).__name__}")
            return bl.unavailable(name, f"deployment provider failed: {type(exc).__name__}")

    def intent(self, *args): return self._call("intent", *args)
    def golden(self, *args): return self._call("golden", *args)
    def history(self, *args): return self._call("history", *args)
    def slo(self, *args): return self._call("slo", *args)
    def changes(self, *args): return self._call("changes", *args)
    def configs(self, *args): return self._call("configs", *args)


def _flow_binding(value):
    if not isinstance(value, rt.FlowRuntimeInput):
        raise TypeError("flow provider must return FlowRuntimeInput")
    if not isinstance(value.selector, dict) or not any(value.selector.get(k) for k in
            ("protocol", "src_ports", "dst_ports", "src_prefixes", "dst_prefixes")):
        raise ValueError("flow selector required")
    if not callable(getattr(value.wire, "collect", None)) or not callable(getattr(value.wire, "health", None)):
        raise TypeError("flow wire input required")
    return value


# ------------------------------------------------------------------------------------------------------------------- admission
class DeploymentAdmission(rt.InventoryAdmission):
    """Strict authoritative admission.  ``version(device, inventory_entry) -> str | None``; ``lifecycle(device) -> {"state", "withdrawn", "maintenance"} | None``.
    A device is VERIFIED only if every one of: in inventory, supported platform, version provider answers a parseable version, lifecycle provider answers an
    admitted state and not withdrawn.  Inventory-embedded ``os_version`` is deliberately IGNORED."""

    def __init__(self, *, inventory=None, version=None, lifecycle=None, misconfigured: str = ""):
        super().__init__(inventory=inventory, lifecycle=lifecycle)
        self._version, self._misconfigured = version, misconfigured

    def resolve(self, devices: list[str]) -> dict[str, rt.DeviceAdmission]:
        if self._misconfigured:
            return {d: rt.DeviceAdmission(d, "UNKNOWN", source="deployment", reason=self._misconfigured) for d in devices}
        try:
            known = self._load()
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return {d: rt.DeviceAdmission(d, "UNKNOWN", source="inventory", reason=f"inventory unavailable: {type(exc).__name__}") for d in devices}
        out: dict[str, rt.DeviceAdmission] = {}
        for d in devices:
            src = "inventory+lifecycle+version"
            entry = known.get(d)
            if entry is None:
                out[d] = rt.DeviceAdmission(d, "UNKNOWN", source="inventory", reason="device is not in the authoritative inventory")
                continue
            platform = nz.canonical_platform(entry.get("platform") or "")
            if platform not in KNOWN_PLATFORMS:
                out[d] = rt.DeviceAdmission(d, "UNSUPPORTED_PLATFORM", platform=platform, source="inventory", reason=f"platform {platform!r} has no read-only collector support")
                continue
            life = None
            if self._lifecycle is not None:
                try:
                    life = self._lifecycle(d)
                except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                    out[d] = rt.DeviceAdmission(d, "LIFECYCLE_UNKNOWN", platform=platform, source=src, reason=f"lifecycle provider failed: {type(exc).__name__}")
                    continue
            if not isinstance(life, dict):
                out[d] = rt.DeviceAdmission(d, "LIFECYCLE_UNKNOWN", platform=platform, source=src, reason="no authoritative lifecycle answer")
                continue
            maint = bool(life.get("maintenance"))
            if life.get("withdrawn"):
                out[d] = rt.DeviceAdmission(d, "WITHDRAWN", platform=platform, maintenance=maint, source=src, reason="device is withdrawn")
                continue
            state = str(life.get("state") or "").upper()
            if state not in col.ADMITTED_STATES:
                out[d] = rt.DeviceAdmission(d, state or "LIFECYCLE_UNKNOWN", platform=platform, maintenance=maint, source=src,
                                            reason=f"lifecycle state {state or 'missing'} is not admitted")
                continue
            version = ""
            if self._version is not None:
                try:
                    version = str(self._version(d, dict(entry)) or "").strip()
                except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                    out[d] = rt.DeviceAdmission(d, "VERSION_UNKNOWN", platform=platform, maintenance=maint, source=src, reason=f"version provider failed: {type(exc).__name__}")
                    continue
            if not nz.parse_version(version):
                out[d] = rt.DeviceAdmission(d, "VERSION_UNKNOWN", platform=platform, maintenance=maint, source=src, reason="no authoritative parseable OS version")
                continue
            out[d] = rt.DeviceAdmission(d, "VERIFIED", platform=platform, os_version=version, maintenance=maint, source=src)
        return out


# ---------------------------------------------------------------------------------------------------------------------- factory
def build_runtime_deps(*, inventory=None, version_provider=None, lifecycle_provider=None, cli_transport_factory=None, diagnostic_worker=None, snmp_session_factory=None,
                       syslog_source=None, gnmi_getter_factory=None, gnmi_paths: tuple | None = None, capability_probe=None, gateway_platforms=(),
                       health_capability=None, syslog_window_s: int | None = None, sources=None, raw_store=None, misconfigured: str = "",
                       problems: list[str] | None = None, dns_runner_factory=None, dns_context_provider=None, probe_runner_factory=None, probe_context_provider=None,
                       stp_context_provider=None, l2_context_provider=None, acl_context_provider=None, forwarding_context_provider=None, flow_input=None, baseline_sources_provider=None, fib_reader_factory=None, qos_reader_factory=None, phy_reader_factory=None, proto_reader_factory=None, phy_context_provider=None, **clock) -> rt.RuntimeDeps:
    """Compose ``RuntimeDeps`` from callables (all optional; absent => the corresponding evidence is UNAVAILABLE / the device is refused).
    ``clock`` may carry ``clock``/``sleep``/``now`` for tests.  ``capability_probe`` defaults to :func:`caps.make_capability_probe`."""
    problems = problems if problems is not None else []
    probe = capability_probe or caps.make_capability_probe(health_capability=health_capability, gateway_platforms=tuple(gateway_platforms))
    kw: dict[str, Any] = dict(
        admission=DeploymentAdmission(inventory=inventory, version=version_provider, lifecycle=lifecycle_provider, misconfigured=misconfigured),
        cli_transport=_guard(cli_transport_factory, ReadOnlyCli, problems, "cli"),
        diagnostic_worker=diagnostic_worker,
        snmp_session=_guard(snmp_session_factory, ReadOnlySnmp, problems, "snmp"),
        syslog_lines=_guard(syslog_source, lambda lines: list(lines), problems, "syslog"),
        gnmi_getter=_guard(gnmi_getter_factory, lambda g: g if callable(g) else (_ for _ in ()).throw(TypeError("gNMI getter must be callable")), problems, "gnmi"),
        sources=LazyBaselineSources(baseline_sources_provider, problems) if baseline_sources_provider is not None else sources,
        dns_runner=_guard(dns_runner_factory, ReadOnlyCli, problems, "dns"),
        dns_context=LazyContext(dns_context_provider, DnsContext, problems, "dns_context") if dns_context_provider else None,
        probe_runner=_guard(probe_runner_factory, ReadOnlyProbe, problems, "probe"),
        probe_context=LazyContext(probe_context_provider, ProbeContext, problems, "probe_context") if probe_context_provider else None,
        stp_context=LazyContext(stp_context_provider, StpContext, problems, "stp_context") if stp_context_provider else None,
        l2_context=LazyContext(l2_context_provider, L2Context, problems, "l2_context") if l2_context_provider else None,
        acl_context=LazyContext(acl_context_provider, AclContext, problems, "acl_context") if acl_context_provider else None,
        forwarding_context=LazyContext(forwarding_context_provider, ForwardingContext, problems, "forwarding_context") if forwarding_context_provider else None,
        flow_input=_guard(flow_input, _flow_binding, problems, "flow"),
        fib_source=_guard(fib_reader_factory, ReadOnlyReader, problems, "fib"),
        qos_source=_guard(qos_reader_factory, ReadOnlyReader, problems, "qos"),
        phy_source=_guard(phy_reader_factory, ReadOnlyReader, problems, "phy"),
        proto_source=_guard(proto_reader_factory, ReadOnlyReader, problems, "proto"),
        phy_context=LazyContext(phy_context_provider, PhysicalContext, problems, "phy_context") if phy_context_provider else None,
        capability_probe=probe, raw_store=raw_store)
    if gnmi_paths:
        kw["gnmi_paths"] = tuple(gnmi_paths)
    if syslog_window_s:
        kw["syslog_window_s"] = int(syslog_window_s)
    kw.update({k: v for k, v in clock.items() if k in ("clock", "sleep", "now")})
    deps = rt.RuntimeDeps(**kw)
    deps.deployment_problems = problems          # type: ignore[attr-defined]  # diagnostics only; never consulted for trust decisions
    return deps


def _settings_config() -> dict:
    from django.conf import settings
    cfg = getattr(settings, SETTING, None) or {}
    if not isinstance(cfg, dict):
        raise TypeError(f"{SETTING} must be a dict")
    unknown = set(cfg) - _KEYS
    if unknown:
        raise ValueError(f"unknown {SETTING} keys: {sorted(unknown)}")
    # Direct in-process network providers predate the sandbox boundary and may
    # connect while being constructed.  They cannot prove exact destination
    # authorization.  Keep programmatic injection for isolated unit fixtures,
    # but production settings must use the separately activated grant-enforcing
    # worker rather than enabling one of these provider hooks directly.
    enforce = bool(getattr(settings, "NMAS_TS_SANDBOX_ENFORCEMENT", True))
    unsafe = sorted(key for key in _NETWORK_PROVIDER_KEYS if enforce and cfg.get(key) not in (None, ""))
    if unsafe:
        raise ValueError("direct network providers are prohibited by the Troubleshooter sandbox: " + ", ".join(unsafe))
    return cfg


def runtime_deps(config: dict | None = None) -> rt.RuntimeDeps:
    """The shared zero-argument factory (``NMAS_TS_RUNTIME_FACTORY`` and ``TROUBLESHOOTING_RUNTIME_DEPS``).  Reads ``settings.NMAS_TS_DEPLOYMENT``.
    Never raises on bad configuration: it returns deps that refuse every device (or have no transport) and records the problems."""
    problems: list[str] = []
    try:
        cfg = dict(config) if config is not None else _settings_config()
        if set(cfg) - _KEYS:
            raise ValueError("unknown deployment keys")
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        return build_runtime_deps(misconfigured=f"deployment configuration invalid: {type(exc).__name__}", problems=[f"config: {type(exc).__name__}"])

    admission_bad = ""
    resolved: dict[str, Any] = {}
    for key in ("inventory", "version_provider", "lifecycle_provider"):
        try:
            resolved[key] = _resolve(cfg.get(key))
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            resolved[key] = None
            admission_bad = f"{key} could not be loaded: {type(exc).__name__}"
            problems.append(admission_bad)
    for key in ("cli_transport_factory", "snmp_session_factory", "syslog_source", "gnmi_getter_factory", "dns_runner_factory", "dns_context_provider",
                "probe_runner_factory", "probe_context_provider", "stp_context_provider", "l2_context_provider", "acl_context_provider", "forwarding_context_provider", "flow_input", "baseline_sources_provider", "fib_reader_factory", "qos_reader_factory",
                "phy_reader_factory", "proto_reader_factory", "phy_context_provider"):
        try:
            resolved[key] = _resolve(cfg.get(key))
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            resolved[key] = None
            problems.append(f"{key} could not be loaded: {type(exc).__name__}")
            if key == "baseline_sources_provider":
                resolved[key] = lambda: None
    health_capability = None
    if cfg.get("use_health_capability", True):
        try:
            from core.services.health import live   # lazy: needs Django settings
            health_capability = live.get_capability
        except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            problems.append(f"health capability unavailable: {type(exc).__name__}")
    diagnostic_worker = None
    try:
        from django.conf import settings
        worker_cfg = getattr(settings, "NMAS_TS_DIAGNOSTIC_WORKER", {}) or {}
        if worker_cfg:
            if not isinstance(worker_cfg, dict) or set(worker_cfg) - {"socket", "key_env", "timeout"} \
                    or not worker_cfg.get("socket") or not worker_cfg.get("key_env"):
                raise ValueError("invalid NMAS_TS_DIAGNOSTIC_WORKER")
            from .diagnostic_worker import DiagnosticCliTransport, DiagnosticWorkerClient
            from .worker_ipc import load_key

            def _worker_transport(info, context):
                required = {"agent", "tenant", "authorization_ref", "authorization_expires_at"}
                if not isinstance(context, dict) or set(context) != required:
                    raise ValueError("a complete live handoff context is required")
                from .adapters.nmas_providers import target_policy
                client = DiagnosticWorkerClient(
                    socket_path=str(worker_cfg["socket"]), key=load_key(str(worker_cfg["key_env"])),
                    agent=str(context["agent"]), tenant=str(context["tenant"]), topology_id=target_policy().topology_id,
                    authorization_ref=str(context["authorization_ref"]),
                    authorization_expires_at=context["authorization_expires_at"],
                    timeout_seconds=float(worker_cfg.get("timeout", 20)),
                )
                return DiagnosticCliTransport(device=info.device, platform=info.platform, client=client)

            diagnostic_worker = _worker_transport
    except Exception as exc:  # pylint: disable=broad-exception-caught  # configuration/key errors leave the runtime without a network transport
        problems.append(f"diagnostic worker unavailable: {type(exc).__name__}")
        diagnostic_worker = None
    return build_runtime_deps(health_capability=health_capability, diagnostic_worker=diagnostic_worker,
                              gateway_platforms=tuple(cfg.get("gateway_platforms") or ()), gnmi_paths=cfg.get("gnmi_paths"),
                              syslog_window_s=cfg.get("syslog_window_s"), misconfigured=admission_bad, problems=problems, **resolved)


def consistency_problems(settings_obj=None) -> list[str]:
    """Empty list iff both consumer settings are unset-together or both point at an equivalent factory (documentation/deploy check)."""
    if settings_obj is None:
        from django.conf import settings as settings_obj
    vals = {n: str(getattr(settings_obj, n, "") or "").replace(":", ".") for n in CONSUMER_SETTINGS}
    out = []
    if len(set(vals.values())) > 1:
        out.append(f"consumer settings disagree: {vals}")
    for n, v in vals.items():
        if v and v != FACTORY_PATH:
            out.append(f"{n} does not point at {FACTORY_PATH}")
        if not v:
            out.append(f"{n} is unset (consumer falls back to a deps object with no transports)")
    return out
