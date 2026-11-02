"""The platform-executor contract (an explicit adapter boundary; no platform branching lives in the engine or a view).

An executor owns ONE managed device for the duration of one run.  The engine calls, in order:

    connect()                       open the (bounded) device session; raises ExecutorError(code)
    assess(spec)                    READ-ONLY: capture the Configlet's previous state from the CURRENT device state and
                                    decide APPLY / SKIP (already satisfied) / REFUSE, and whether exact compensation is
                                    provable (``restorable``).  Called for every Configlet BEFORE the first mutation.
    apply(spec, assessment)         the only mutating call.  Returns an ApplyOutcome; device failures are outcomes, never
                                    exceptions, and never carry device text -- only a code from ``codes.ERROR_CATEGORIES``.
    compensate(spec, assessment)    undo exactly what ``apply`` added, then READ BACK and verify the captured state.
    close()                         always called.

The engine treats transport acceptance, command acceptance and operational verification as three different things: an
``ApplyOutcome(ok=True)`` only says the device accepted the commands; success is decided by the Phase-15 postcheck.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ....models import ConfigletOperationType
from ...raw_configlets import text as raw_text


class ExecutorError(Exception):
    """A sanitized executor failure: only ``code`` (a key of ``codes.ERROR_CATEGORIES``) ever leaves an executor."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ConfigletSpec:
    """The immutable, structured facts of one plan Configlet an executor needs.  Built from the frozen plan row only."""

    cfg_id: str
    sequence: int
    device: str
    platform: str            # Device Builder platform value, e.g. "arista_ceos"
    object_type: str         # planning.priorities.CATALOGUE key
    operation: str
    lines: tuple[str, ...]   # the Configlet's own rendered_config, comment lines removed
    expected: dict = field(default_factory=dict)   # the secret-free verification facts (interface, address, prefix, ...)
    derived: dict | None = None
    pk: int | None = None
    origin: str = "STRUCTURED"                     # Phase 18: STRUCTURED or RAW
    raw: dict | None = None                        # RAW: the compact pins (raw_id, revision, content_hash, verification_run_id)
    integrity_error: str = ""                      # RAW: a BLOCKERS code when the pinned revision cannot be trusted
    removal: dict | None = None                    # REMOVAL: restore lines, verification paths, snapshot provenance

    @classmethod
    def from_configlet(cls, configlet) -> "ConfigletSpec":
        source = (configlet.desired_state_ref or {}).get("source") or {}
        requirements = (configlet.verification_spec or {}).get("requirements") or []
        expected = dict((requirements[0].get("expected") or {})) if requirements else {}
        origin, raw, integrity, removal = "STRUCTURED", None, "", None
        if getattr(configlet, "origin", "STRUCTURED") == "REMOVAL":
            # Intentional removal: the lines are the plan's own deterministic rendering (re-derived from the hashed snapshot at plan
            # time); restore lines / verification paths travel in the plan row's metadata, never from the browser.
            origin, removal = "REMOVAL", dict((configlet.metadata or {}).get("removal") or {})
            lines = tuple(line.rstrip() for line in (configlet.rendered_config or "").splitlines() if line.strip())
        elif getattr(configlet, "origin", "STRUCTURED") == "RAW":
            # A RAW Configlet's payload is ALWAYS re-read from the pinned, immutable revision -- never from the browser and not
            # from the copied plan text -- and only if it still hashes to the value the plan pinned.
            origin = "RAW"
            revision, pins = configlet.raw_revision, (configlet.metadata or {}).get("raw") or {}
            if revision is None:
                integrity, lines = "RAW_REVISION_INTEGRITY", ()
            elif raw_text.content_hash(revision.content) != revision.content_hash or revision.content_hash != pins.get("content_hash"):
                integrity, lines = "RAW_REVISION_INTEGRITY", ()
            else:
                lines = tuple(raw_text.command_lines(revision.content))
                raw = {k: pins.get(k) for k in ("raw_id", "revision", "content_hash", "verification_run_id")}
        else:
            lines = tuple(
                line.rstrip() for line in (configlet.rendered_config or "").splitlines()
                if line.strip() and not line.strip().startswith(("!", "#"))
            )
        return cls(
            cfg_id=configlet.cfg_id, sequence=configlet.sequence, device=configlet.target_device,
            platform=str(source.get("platform") or ""), object_type=str(source.get("object_type") or ""),
            operation=str(configlet.operation_type or ConfigletOperationType.CREATE_DEFINE),
            lines=lines, expected=expected, derived=(configlet.metadata or {}).get("derived"), pk=configlet.pk,
            origin=origin, raw=raw, integrity_error=integrity, removal=removal,
        )


# assessment actions
APPLY, SKIP_SATISFIED, REFUSE = "APPLY", "SKIP_SATISFIED", "REFUSE"


@dataclass
class Assessment:
    action: str
    restorable: bool                       # exact compensation is provable from the captured state
    previous_state: dict = field(default_factory=dict)   # bounded, secret-free facts (persisted with the result)
    reason: str = ""                       # a codes.BLOCKERS key when action == REFUSE or not restorable


@dataclass
class ApplyOutcome:
    ok: bool
    error_code: str = ""
    partial_effects: bool = False          # a device change may remain even though ``ok`` is False
    lines_sent: int = 0


@dataclass
class CompensationOutcome:
    status: str                            # COMPENSATED | COMPENSATION_FAILED | COMPENSATION_UNVERIFIED
    error_code: str = ""
    detail: dict = field(default_factory=dict)


class DeviceExecutor:
    """Abstract base.  Concrete executors: ``ceos.CeosExecutor``, ``linux.LinuxExecutor`` (and test fakes)."""

    platform = ""

    def connect(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def assess(self, spec: ConfigletSpec) -> Assessment:  # pragma: no cover - interface
        raise NotImplementedError

    def apply(self, spec: ConfigletSpec, assessment: Assessment) -> ApplyOutcome:  # pragma: no cover - interface
        raise NotImplementedError

    def compensate(self, spec: ConfigletSpec, assessment: Assessment) -> CompensationOutcome:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        return None


def bounded_lines(lines, *, limit: int = 40, width: int = 200) -> list[str]:
    """Bounded copy of config-like lines for persistence (never unbounded device text)."""
    return [str(line)[:width] for line in list(lines)[:limit]]
