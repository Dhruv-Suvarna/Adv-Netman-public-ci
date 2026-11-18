"""Contained fault-campaign controller used by the repository-root ``break.py``.

The controller accepts only a pre-reviewed fault ID from an exact allowlist.
It has no SSH, Docker, shell, address, or raw-command parameter.  A deployment
must inject a narrow driver whose methods implement the fixed protocol below;
the default CLI has no live driver and therefore fails closed.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol


POLICY_SCHEMA = "nmas.troubleshooting.fault-policy/1"
STATE_SCHEMA = "nmas.troubleshooting.fault-state/1"
ALLOWED_TOPOLOGIES = frozenset({"srlceos01", "nmas-disposable-fixture"})
ALLOWED_FAULT_TYPES = frozenset({"admin_shutdown", "carrier_loss", "link_flap", "peer_carrier_loss"})
LINK_FAULTS = ("carrier_loss", "link_flap", "peer_carrier_loss")
# peer_carrier_loss: the OBSERVED device (read-only) keeps its configuration and its own kernel link UP; the Linux END HOST on the
# other end of the tracked Containerlab veth takes its interface down, so the observed interface genuinely loses carrier and stays
# operationally DOWN for as long as the fault is held (a cEOS node reasserts its own kernel link within ~1 s, a Linux host does not).
# Only end hosts that carry no protected flow are allowed, never eth0 (Containerlab management), and the pairing must be a link
# of the tracked topology file.  No device configuration is written, so no management path / write eligibility is claimed.
PEER_HOSTS = frozenset({"H3", "H4"})
PEER_INTERFACE = re.compile(r"^eth[1-9][0-9]{0,2}$")
# carrier_loss / link_flap act on the lab LINK, never on device configuration: the kernel end of the Containerlab veth inside the
# named node goes down, so the far end genuinely loses carrier while both devices stay administratively UP.
FLAP_KEYS = {"cycles", "down_seconds", "up_seconds"}
FLAP_LIMITS = {"cycles": (2, 6), "down_seconds": (3, 20), "up_seconds": (5, 60)}
PROHIBITED_DEVICES = frozenset({"R5"})
IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
OBJECT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9/_.:-]{0,63}$")
FORBIDDEN_POLICY_KEYS = re.compile(r"(?i)(^|_)(ip|ipv4|ipv6|address|hostname|command|cli|shell|password|secret|credential)(_|$)")


class FaultRefused(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


class FaultDriver(Protocol):
    restricted_interface: bool

    def capture_baseline(self, fault: dict) -> dict: ...
    def protected_health(self, flows: list[dict]) -> dict: ...
    def inject(self, fault: dict, operation_id: str) -> dict: ...
    def rollback(self, fault: dict, baseline: dict, operation_id: str) -> dict: ...
    def matches_baseline(self, fault: dict, baseline: dict) -> bool: ...


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise FaultRefused("INVALID_TIME") from exc
    if parsed.tzinfo is None:
        raise FaultRefused("INVALID_TIME")
    return parsed.astimezone(timezone.utc)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def policy_digest(policy: dict) -> str:
    return hashlib.sha256(_canonical(policy)).hexdigest()


def _walk_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if FORBIDDEN_POLICY_KEYS.search(str(key)):
                raise FaultRefused("FORBIDDEN_POLICY_FIELD", str(key))
            _walk_keys(nested)
    elif isinstance(value, list):
        for item in value:
            _walk_keys(item)


def validate_policy(policy: Any, *, now: datetime | None = None) -> dict:
    now = now or _now()
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise FaultRefused("INVALID_POLICY_SCHEMA")
    allowed_top = {"schema", "topology", "campaign", "allowed_faults", "protected_flows", "loss_threshold_pct"}
    if set(policy) != allowed_top:
        raise FaultRefused("INVALID_POLICY_FIELDS", ",".join(sorted(set(policy) ^ allowed_top)))
    _walk_keys(policy)
    if policy["topology"] not in ALLOWED_TOPOLOGIES:
        raise FaultRefused("TOPOLOGY_NOT_ALLOWED")
    campaign = policy.get("campaign")
    if not isinstance(campaign, dict) or set(campaign) != {"id", "authorization_id", "expires_at", "fixture_only"}:
        raise FaultRefused("INVALID_CAMPAIGN")
    for key in ("id", "authorization_id"):
        if not isinstance(campaign[key], str) or not IDENTIFIER.fullmatch(campaign[key]):
            raise FaultRefused("INVALID_CAMPAIGN", key)
    if not isinstance(campaign["fixture_only"], bool) or _parse_time(campaign["expires_at"]) <= now:
        raise FaultRefused("CAMPAIGN_EXPIRED_OR_INVALID")
    if campaign["fixture_only"] != (policy["topology"] == "nmas-disposable-fixture"):
        raise FaultRefused("FIXTURE_CLASSIFICATION_MISMATCH")
    faults = policy.get("allowed_faults")
    required_fault = {"id", "device", "platform", "object_type", "object_name", "fault_type", "management_path_ref",
                      "identity_verified", "lifecycle_eligible", "write_eligible", "maximum_seconds"}
    if not isinstance(faults, list) or not faults:
        raise FaultRefused("EMPTY_FAULT_ALLOWLIST")
    seen = set()
    for fault in faults:
        extra = {"flap"} if isinstance(fault, dict) and fault.get("fault_type") == "link_flap" else set()
        peer_type = isinstance(fault, dict) and fault.get("fault_type") == "peer_carrier_loss"
        expected = (required_fault - {"management_path_ref", "identity_verified", "lifecycle_eligible", "write_eligible"}
                    | {"peer", "observation_only"}) if peer_type else required_fault | extra
        if not isinstance(fault, dict) or set(fault) != expected:
            raise FaultRefused("INVALID_FAULT_ENTRY")
        if fault["id"] in seen or not IDENTIFIER.fullmatch(str(fault["id"])):
            raise FaultRefused("DUPLICATE_OR_INVALID_FAULT_ID")
        seen.add(fault["id"])
        if fault["device"] in PROHIBITED_DEVICES or not IDENTIFIER.fullmatch(str(fault["device"])):
            raise FaultRefused("DEVICE_NOT_ALLOWED", str(fault["device"]))
        if fault["object_type"] != "interface" or not OBJECT_NAME.fullmatch(str(fault["object_name"])):
            raise FaultRefused("OBJECT_NOT_ALLOWED")
        if fault["fault_type"] not in ALLOWED_FAULT_TYPES:
            raise FaultRefused("FAULT_TYPE_NOT_ALLOWED")
        if peer_type:
            _validate_peer(fault)
        else:
            if not IDENTIFIER.fullmatch(str(fault["management_path_ref"])):
                raise FaultRefused("MANAGEMENT_PATH_NOT_APPROVED")
            if fault["fault_type"] == "link_flap":
                _validate_flap(fault)
            if any(fault[key] is not True for key in ("identity_verified", "lifecycle_eligible", "write_eligible")):
                raise FaultRefused("TARGET_NOT_ELIGIBLE")
        duration = fault["maximum_seconds"]
        if isinstance(duration, bool) or not isinstance(duration, int) or not 10 <= duration <= 300:
            raise FaultRefused("INVALID_MAXIMUM_DURATION")
    flows = policy.get("protected_flows")
    if not isinstance(flows, list) or not flows or {f.get("family") for f in flows if isinstance(f, dict)} != {"IPv4", "IPv6"}:
        raise FaultRefused("DUAL_STACK_PROTECTED_FLOWS_REQUIRED")
    for flow in flows:
        if not isinstance(flow, dict) or set(flow) != {"id", "family", "selector_ref"} \
                or not IDENTIFIER.fullmatch(str(flow["id"])) or not IDENTIFIER.fullmatch(str(flow["selector_ref"])):
            raise FaultRefused("INVALID_PROTECTED_FLOW")
    threshold = policy.get("loss_threshold_pct")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0 <= float(threshold) <= 1:
        raise FaultRefused("INVALID_LOSS_THRESHOLD")
    return policy


def _validate_peer(fault: dict) -> None:
    """Observation-only target; the physical fault is at an allowlisted end host's NIC (never eth0, never a protected-flow host)."""
    if fault.get("observation_only") is not True:
        raise FaultRefused("PEER_FAULT_MUST_BE_OBSERVATION_ONLY")
    peer = fault.get("peer")
    if not isinstance(peer, dict) or set(peer) != {"node", "interface"}:
        raise FaultRefused("INVALID_PEER_SPEC")
    if peer["node"] not in PEER_HOSTS or not PEER_INTERFACE.fullmatch(str(peer["interface"])):
        raise FaultRefused("PEER_NOT_ALLOWED", f'{peer.get("node")}:{peer.get("interface")}')


def topology_peer(topology: str, node: str, interface: str, *, root: Path | None = None) -> tuple[str, str] | None:
    """The other end of ``node:interface`` in the TRACKED topology file (``<repo>/<topology>.clab.yml``), or None."""
    path = (root or Path(__file__).resolve().parents[4]) / f"{topology}.clab.yml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for a_node, a_if, b_node, b_if in re.findall(
            r'endpoints:\s*\[\s*"([A-Za-z0-9_]+):(eth[0-9]+)"\s*,\s*"([A-Za-z0-9_]+):(eth[0-9]+)"\s*\]', text):
        if (a_node, a_if) == (node, interface):
            return b_node, b_if
        if (b_node, b_if) == (node, interface):
            return a_node, a_if
    return None


def _validate_flap(fault: dict) -> None:
    """A bounded flap: fixed cycle count and durations, and the whole sequence ends well inside the hard deadline."""
    flap = fault.get("flap")
    if not isinstance(flap, dict) or set(flap) != FLAP_KEYS:
        raise FaultRefused("INVALID_FLAP_SPEC")
    for key, (low, high) in FLAP_LIMITS.items():
        value = flap[key]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise FaultRefused("INVALID_FLAP_SPEC", key)
    if flap["cycles"] * (flap["down_seconds"] + flap["up_seconds"]) > fault["maximum_seconds"] - 30:
        raise FaultRefused("FLAP_EXCEEDS_DEADLINE")


def load_policy(path: str, *, now: datetime | None = None) -> dict:
    policy_path = Path(path)
    if policy_path.is_symlink() or not policy_path.is_file():
        raise FaultRefused("UNSAFE_POLICY_PATH")
    try:
        value = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FaultRefused("POLICY_UNREADABLE") from exc
    return validate_policy(value, now=now)


class StateStore:
    def __init__(self, root: str, campaign_id: str):
        if not IDENTIFIER.fullmatch(campaign_id):
            raise FaultRefused("INVALID_CAMPAIGN_ID")
        self.root = Path(root)
        self.state_path = self.root / f"{campaign_id}.json"
        self.lock_path = self.root / f"{campaign_id}.lock"

    def prepare(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise FaultRefused("UNSAFE_STATE_DIRECTORY")
        os.chmod(self.root, 0o700)

    def locked(self):
        self.prepare()
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return os.fdopen(fd, "r+")

    def load(self) -> dict:
        if self.state_path.is_symlink() or not self.state_path.exists():
            raise FaultRefused("CAMPAIGN_STATE_NOT_FOUND")
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise FaultRefused("CAMPAIGN_STATE_UNREADABLE") from exc

    def save(self, state: dict) -> None:
        self.prepare()
        fd, name = tempfile.mkstemp(prefix=f".{self.state_path.name}.", dir=self.root)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(_canonical(state) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass


@dataclass
class CampaignController:
    policy: dict
    fault_id: str
    store: StateStore
    driver: FaultDriver
    now: Callable[[], datetime] = _now

    def __post_init__(self):
        validate_policy(self.policy, now=self.now())
        if not getattr(self.driver, "restricted_interface", False):
            raise FaultRefused("UNRESTRICTED_DRIVER_REFUSED")
        matches = [fault for fault in self.policy["allowed_faults"] if fault["id"] == self.fault_id]
        if len(matches) != 1:
            raise FaultRefused("FAULT_ID_NOT_ALLOWLISTED")
        self.fault = matches[0]

    def _authorize(self, authorization_id: str, confirm: str) -> None:
        expected = self.policy["campaign"]["authorization_id"]
        digest = policy_digest(self.policy)
        if authorization_id != expected:
            raise FaultRefused("AUTHORIZATION_MISMATCH")
        if len(confirm) < 16 or not digest.startswith(confirm.lower()):
            raise FaultRefused("POLICY_CONFIRMATION_MISMATCH")

    def _check_health(self, health: dict) -> str:
        if not isinstance(health, dict) or not health.get("management_ok") or not health.get("monitoring_ok"):
            return "management or monitoring health failed"
        families = health.get("families")
        if not isinstance(families, dict) or set(families) != {"IPv4", "IPv6"}:
            return "dual-stack protected-flow health unavailable"
        threshold = float(self.policy["loss_threshold_pct"])
        for family in ("IPv4", "IPv6"):
            sample = families[family]
            if not isinstance(sample, dict) or sample.get("measured") is not True or sample.get("loss_pct") is None:
                return f"{family} protected-flow evidence unavailable"
            if float(sample["loss_pct"]) > threshold:
                return f"{family} loss exceeds {threshold}%"
        return ""

    def prepare(self, *, authorization_id: str, confirm: str) -> dict:
        self._authorize(authorization_id, confirm)
        with self.store.locked():
            if self.store.state_path.exists():
                state = self.store.load()
                if state.get("status") not in {"RESTORED", "CANCELLED"}:
                    raise FaultRefused("CAMPAIGN_ALREADY_RUNNING")
            health = self.driver.protected_health(self.policy["protected_flows"])
            problem = self._check_health(health)
            if problem:
                raise FaultRefused("PREINJECTION_HEALTH_FAILED", problem)
            baseline = self.driver.capture_baseline(self.fault)
            if not isinstance(baseline, dict) or not baseline:
                raise FaultRefused("BASELINE_UNAVAILABLE")
            when = self.now()
            state = {"schema": STATE_SCHEMA, "campaign_id": self.policy["campaign"]["id"], "policy_digest": policy_digest(self.policy),
                     "fault_id": self.fault_id, "status": "ARMED", "armed_at": _iso(when), "started_at": None, "deadline": None,
                     "baseline": baseline, "injection_receipt": {}, "rollback_receipt": {}, "last_health": health,
                     "events": [{"at": _iso(when), "event": "ARMED"}]}
            self.store.save(state)
            return self.summary(state)

    def inject(self, *, authorization_id: str, confirm: str) -> dict:
        self._authorize(authorization_id, confirm)
        with self.store.locked():
            state = self.store.load()
            if state.get("policy_digest") != policy_digest(self.policy) or state.get("fault_id") != self.fault_id:
                raise FaultRefused("CAMPAIGN_BINDING_MISMATCH")
            if state.get("status") != "ARMED":
                raise FaultRefused("CAMPAIGN_NOT_ARMED")
            when = self.now()
            operation_id = hashlib.sha256(f"{state['campaign_id']}:{self.fault_id}:{_iso(when)}".encode()).hexdigest()[:32]
            try:
                if self.fault["fault_type"] in LINK_FAULTS:
                    # link faults: persist ACTIVE + hard deadline BEFORE touching the link, so an interrupted process can
                    # always be rolled back independently (``break.py rollback``)
                    state.update(status="ACTIVE", started_at=_iso(when), deadline=_iso(when + timedelta(seconds=self.fault["maximum_seconds"])))
                    state["events"].append({"at": _iso(when), "event": "INJECTING", "operation_id": operation_id})
                    self.store.save(state)
                    if hasattr(self.driver, "_flow_stop"):
                        self.driver._flow_stop = lambda: bool(self._check_health(self.driver.protected_health(self.policy["protected_flows"])))  # pylint: disable=protected-access
                receipt = self.driver.inject(self.fault, operation_id)
                state.update(status="ACTIVE", started_at=_iso(when),
                             deadline=_iso(when + timedelta(seconds=self.fault["maximum_seconds"])), injection_receipt=receipt)
                state["events"].append({"at": _iso(self.now()), "event": "INJECTED", "operation_id": operation_id})
                for t in receipt.get("transitions", []) if isinstance(receipt, dict) else []:
                    if isinstance(t, dict):
                        state["events"].append({"at": t.get("at"), "event": f"LINK_{str(t.get('state')).upper()}", "cycle": t.get("cycle")})
                for c in receipt.get("hold_checks", []) if isinstance(receipt, dict) else []:
                    if isinstance(c, dict):
                        state["events"].append({"at": c.get("at"), "event": "HOLD_CHECK", "status": c.get("interfaceStatus"),
                                                "protocol": c.get("lineProtocolStatus"), "admin_up": c.get("observed_admin_up"),
                                                "carrier": c.get("observed_carrier")})
                self.store.save(state)
                if self.fault["fault_type"] == "peer_carrier_loss" and not (isinstance(receipt, dict) and receipt.get("held")):
                    return self._rollback_locked(state, "INJECTION_NOT_HELD: observed interface did not stay operationally down")
                problem = self._check_health(self.driver.protected_health(self.policy["protected_flows"]))
                if problem:
                    return self._rollback_locked(state, f"post-injection stop condition: {problem}")
                return self.summary(state)
            except Exception as exc:
                if state.get("status") == "ACTIVE":
                    self._rollback_locked(state, f"injection exception: {type(exc).__name__}")
                raise

    def watchdog(self) -> dict:
        with self.store.locked():
            state = self.store.load()
            if state.get("status") != "ACTIVE":
                return self.summary(state)
            now = self.now()
            health = self.driver.protected_health(self.policy["protected_flows"])
            state["last_health"] = health
            problem = self._check_health(health)
            if _parse_time(state["deadline"]) <= now:
                problem = problem or "maximum fault duration expired"
            if problem:
                return self._rollback_locked(state, problem)
            state["events"].append({"at": _iso(now), "event": "WATCHDOG_HEALTHY"})
            self.store.save(state)
            return self.summary(state)

    def rollback(self, *, reason: str = "operator emergency rollback") -> dict:
        with self.store.locked():
            state = self.store.load()
            if state.get("status") not in {"ACTIVE", "ROLLBACK_FAILED"}:
                return self.summary(state)
            return self._rollback_locked(state, reason)

    def _rollback_locked(self, state: dict, reason: str) -> dict:
        when = self.now()
        operation_id = hashlib.sha256(f"rollback:{state['campaign_id']}:{_iso(when)}".encode()).hexdigest()[:32]
        state["status"] = "ROLLING_BACK"
        state["events"].append({"at": _iso(when), "event": "ROLLBACK_STARTED", "reason": reason[:160]})
        self.store.save(state)
        try:
            receipt = self.driver.rollback(self.fault, state["baseline"], operation_id)
            health = self.driver.protected_health(self.policy["protected_flows"])
            restored = self.driver.matches_baseline(self.fault, state["baseline"])
            problem = self._check_health(health)
            state["rollback_receipt"] = receipt
            state["last_health"] = health
            state["status"] = "RESTORED" if restored and not problem else "ROLLBACK_FAILED"
            state["events"].append({"at": _iso(self.now()), "event": state["status"], "reason": (problem or reason)[:160]})
            self.store.save(state)
            if state["status"] != "RESTORED":
                raise FaultRefused("ROLLBACK_VERIFICATION_FAILED", problem or "baseline mismatch")
            return self.summary(state)
        except FaultRefused:
            raise
        except Exception as exc:
            state["status"] = "ROLLBACK_FAILED"
            state["events"].append({"at": _iso(self.now()), "event": "ROLLBACK_FAILED", "reason": type(exc).__name__})
            self.store.save(state)
            raise FaultRefused("ROLLBACK_FAILED", type(exc).__name__) from exc

    @staticmethod
    def summary(state: dict) -> dict:
        """Ground-truth fault and baseline stay in the mode-0600 state file."""
        return {"schema": STATE_SCHEMA, "campaign_id": state.get("campaign_id"), "status": state.get("status"),
                "armed_at": state.get("armed_at"), "started_at": state.get("started_at"), "deadline": state.get("deadline"),
                "event_count": len(state.get("events", []))}


class FixtureDriver:
    """Deterministic mock-device driver; never contacts a host or container."""

    restricted_interface = True

    def __init__(self):
        self.up = True
        self.management_ok = True
        self.monitoring_ok = True
        self.loss = {"IPv4": 0.0, "IPv6": 0.0}
        self.calls: list[str] = []

    def capture_baseline(self, fault: dict) -> dict:
        self.calls.append("capture")
        return {"admin_up": self.up, "object_digest": hashlib.sha256(fault["object_name"].encode()).hexdigest()}

    def protected_health(self, flows: list[dict]) -> dict:
        self.calls.append("health")
        return {"management_ok": self.management_ok, "monitoring_ok": self.monitoring_ok,
                "families": {family: {"measured": True, "loss_pct": self.loss[family]} for family in ("IPv4", "IPv6")}}

    def inject(self, fault: dict, operation_id: str) -> dict:
        self.calls.append("inject")
        if fault["fault_type"] == "link_flap":
            transitions = []
            for _ in range(fault["flap"]["cycles"]):
                self.up = False
                transitions.append("down")
                self.up = True
                transitions.append("up")
            return {"operation_id": operation_id, "accepted": True, "transitions": transitions, "final_up": self.up}
        self.up = False
        return {"operation_id": operation_id, "accepted": True}

    def rollback(self, fault: dict, baseline: dict, operation_id: str) -> dict:
        self.calls.append("rollback")
        self.up = bool(baseline["admin_up"])
        self.loss = {"IPv4": 0.0, "IPv6": 0.0}
        return {"operation_id": operation_id, "restored": True}

    def matches_baseline(self, fault: dict, baseline: dict) -> bool:
        self.calls.append("verify")
        return self.up == bool(baseline["admin_up"])



class ContainerlabCeosDriver:
    """Live driver for one cEOS interface inside the operator's own Containerlab topology.

    This is the lab owner's fault-injection channel, deliberately outside NMAS: it uses the container host's console
    (``docker exec <node> Cli``), holds no NMAS credential and is never reachable from a model or the Troubleshooter.
    It changes only the running configuration (never ``write memory``), so a container restart also clears the fault.
    Repair of the fault remains the Change Engine's job; ``rollback`` here is the independent safety net.
    """

    restricted_interface = True
    _NODE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
    _INTERFACE = re.compile(r"^Ethernet[0-9]{1,3}$")
    _ADDRESS = re.compile(r"^[0-9A-Fa-f:.]{3,45}$")

    def __init__(self, topology: str, flow_map: dict, *, run: Any = None, management_probe: Any = None):
        if topology != "srlceos01":
            raise FaultRefused("TOPOLOGY_NOT_ALLOWED")
        self.topology = topology
        self.flow_map = dict(flow_map or {})
        self._run = run or self._subprocess
        self._management_probe = management_probe or self._nmas_health
        self._flow_stop = None              # set by the controller during a flap: () -> True to stop early

    @staticmethod
    def _subprocess(argv: list[str], timeout: int = 20) -> tuple[int, str]:
        import subprocess

        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return done.returncode, done.stdout

    @staticmethod
    def _nmas_health() -> bool:
        import urllib.request

        try:
            with urllib.request.urlopen("http://127.0.0.1:8001/healthz", timeout=4) as response:
                return response.status == 200
        except Exception:  # noqa: BLE001
            return False

    def _container(self, node: str) -> str:
        if not self._NODE.fullmatch(str(node)) or node in PROHIBITED_DEVICES:
            raise FaultRefused("DEVICE_NOT_ALLOWED", str(node))
        return f"clab-{self.topology}-{node}"

    def _target(self, fault: dict) -> tuple[str, str]:
        if fault.get("platform") != "arista_ceos" or not self._INTERFACE.fullmatch(str(fault.get("object_name"))):
            raise FaultRefused("OBJECT_NOT_ALLOWED")
        return self._container(fault["device"]), fault["object_name"]

    def _cli(self, container: str, commands: list[str]) -> str:
        code, output = self._run(["/usr/bin/docker", "exec", container, "Cli", "-p", "15", "-c", "\n".join(commands)])
        if code != 0:
            raise FaultRefused("DEVICE_COMMAND_FAILED")
        return output

    _KERNEL_IF = re.compile(r"^Ethernet([0-9]{1,3})$")

    def _kernel_if(self, interface: str) -> str:
        """cEOS ``EthernetN`` is the Containerlab veth ``ethN`` inside the node's network namespace."""
        m = self._KERNEL_IF.fullmatch(str(interface))
        if not m:
            raise FaultRefused("OBJECT_NOT_ALLOWED")
        return f"eth{m.group(1)}"

    def _link(self, container: str, interface: str) -> dict:
        code, out = self._run(["/usr/bin/docker", "exec", container, "ip", "-j", "link", "show", "dev", self._kernel_if(interface)])
        try:
            row = json.loads(out)[0] if code == 0 else None
        except (ValueError, IndexError, TypeError):
            row = None
        if not isinstance(row, dict):
            raise FaultRefused("BASELINE_UNAVAILABLE", "kernel link unreadable")
        return {"kernel_up": "UP" in (row.get("flags") or []), "carrier": "LOWER_UP" in (row.get("flags") or [])}

    def _set_link(self, container: str, interface: str, state: str) -> None:
        if state not in ("up", "down"):
            raise FaultRefused("OBJECT_NOT_ALLOWED")
        code, _ = self._run(["/usr/bin/docker", "exec", container, "ip", "link", "set", "dev", self._kernel_if(interface), state])
        if code != 0:
            raise FaultRefused("DEVICE_COMMAND_FAILED")

    def _link_state(self, container: str, interface: str) -> dict:
        """Baseline of a link fault: the node's configuration of the interface (must stay unchanged) and the kernel link."""
        return {**self._interface_state(container, interface), **self._link(container, interface)}

    def _interface_state(self, container: str, interface: str) -> dict:
        config = self._cli(container, [f"show running-config interfaces {interface}"])
        lines = [line.strip() for line in config.splitlines() if line.strip()]
        if not any(line == f"interface {interface}" for line in lines):
            raise FaultRefused("BASELINE_UNAVAILABLE", "interface not present in running configuration")
        return {"admin_up": "shutdown" not in lines, "object_digest": hashlib.sha256("\n".join(lines).encode()).hexdigest()}

    # ------------------------------------------------------------------------------------------- peer_carrier_loss helpers
    PEER_HOLD_CHECKS = (3, 5)            # seconds: the fault must still be present at both checks (no reassertion / no flap)
    RESTORE_WAIT_SECONDS = 45            # link-up -> RA-learned routes back (router solicitation is sent on link-up)

    def _peer_target(self, fault: dict) -> tuple[str, str, str, str]:
        """(observed container, observed interface, peer container, peer interface); the pairing is re-checked against the
        tracked topology on every use, so a policy can never name an arbitrary host interface."""
        container, interface = self._target(fault)
        peer = fault.get("peer") or {}
        if peer.get("node") not in PEER_HOSTS or not PEER_INTERFACE.fullmatch(str(peer.get("interface"))):
            raise FaultRefused("PEER_NOT_ALLOWED")
        actual = topology_peer(self.topology, fault["device"], self._kernel_if(interface))
        if actual != (peer["node"], peer["interface"]):
            raise FaultRefused("PEER_NOT_TOPOLOGY_LINK", f"{fault['device']}:{interface} -> {actual}")
        return container, interface, self._container(peer["node"]), peer["interface"]

    def _json(self, argv: list[str]):
        code, out = self._run(argv)
        try:
            return json.loads(out) if code == 0 else None
        except ValueError:
            return None

    def _host_l3(self, container: str, interface: str) -> dict:
        """The end host's link + L3 state on ``interface``, lifetimes excluded (they change with time, the entries must not)."""
        link = self._json(["/usr/bin/docker", "exec", container, "ip", "-j", "addr", "show", "dev", interface])
        if not isinstance(link, list) or not link or not isinstance(link[0], dict):
            raise FaultRefused("BASELINE_UNAVAILABLE", "peer link unreadable")
        addrs = sorted(f'{a.get("family")} {a.get("local")}/{a.get("prefixlen")}' for a in link[0].get("addr_info") or []
                       if a.get("scope") == "global")
        routes = []
        for family in ("-4", "-6"):
            rows = self._json(["/usr/bin/docker", "exec", container, "ip", "-j", family, "route", "show", "dev", interface])
            if not isinstance(rows, list):
                raise FaultRefused("BASELINE_UNAVAILABLE", "peer routes unreadable")
            routes += [f'{family} {r.get("dst")} via={r.get("gateway", "")} proto={r.get("protocol", "")} metric={r.get("metric", "")}'
                       for r in rows if isinstance(r, dict)]
        code, keep = self._run(["/usr/bin/docker", "exec", container, "sysctl", "-n", f"net.ipv6.conf.{interface}.keep_addr_on_down"])
        if code != 0 or keep.strip() not in ("0", "1", "-1"):
            raise FaultRefused("BASELINE_UNAVAILABLE", "peer sysctl unreadable")
        flags = link[0].get("flags") or []
        return {"kernel_up": "UP" in flags, "carrier": "LOWER_UP" in flags, "addrs": addrs, "routes": sorted(routes),
                "keep_addr_on_down": keep.strip()}

    def _peer_dynamic_addrs(self, container: str, interface: str) -> list[str]:
        """Global addresses with a finite lifetime (DHCPv6 lease, SLAAC).  Linux ``keep_addr_on_down`` preserves only
        PERMANENT addresses across a link down; dynamic ones are flushed and come back only when their source (a DHCPv6
        client renewal, an RA) re-installs them, which may be hours later.  Campaign 017 lost H4's DHCPv6 /128 this way."""
        link = self._json(["/usr/bin/docker", "exec", container, "ip", "-j", "addr", "show", "dev", interface])
        if not isinstance(link, list) or not link or not isinstance(link[0], dict):
            raise FaultRefused("BASELINE_UNAVAILABLE", "peer link unreadable")
        out = []
        for a in link[0].get("addr_info") or []:
            if a.get("scope") != "global":
                continue
            valid = a.get("valid_life_time")
            if a.get("dynamic") or (isinstance(valid, int) and valid != 0xFFFFFFFF):
                out.append(f'{a.get("family")} {a.get("local")}/{a.get("prefixlen")}')
        return sorted(out)

    def _device_status(self, container: str, interface: str) -> dict:
        """Device-reported state (cEOS ``show interfaces X | json``): the evidence the observed fault is real."""
        doc = self._json(["/usr/bin/docker", "exec", container, "Cli", "-p", "15", "-c", f"show interfaces {interface} | json"])
        row = ((doc or {}).get("interfaces") or {}).get(interface) or {}
        counters = row.get("interfaceCounters") or {}
        return {"interfaceStatus": row.get("interfaceStatus"), "lineProtocolStatus": row.get("lineProtocolStatus"),
                "linkStatusChanges": counters.get("linkStatusChanges"), "lastStatusChangeTimestamp": row.get("lastStatusChangeTimestamp")}

    def _peer_restore_wait(self, fault: dict, baseline: dict) -> bool:
        import time

        deadline = time.monotonic() + self.RESTORE_WAIT_SECONDS
        while True:
            if self.matches_baseline(fault, baseline):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(3)

    def capture_baseline(self, fault: dict) -> dict:
        if fault["fault_type"] == "peer_carrier_loss":
            container, interface, peer_c, peer_if = self._peer_target(fault)
            observed = self._link_state(container, interface)
            peer = self._host_l3(peer_c, peer_if)
            if not (observed["admin_up"] and observed["kernel_up"] and observed["carrier"] and peer["kernel_up"] and peer["carrier"]):
                raise FaultRefused("BASELINE_UNAVAILABLE", "observed link or peer is not up with carrier")
            dynamic = self._peer_dynamic_addrs(peer_c, peer_if)
            if dynamic:
                # Refuse before anything is touched: the harness could restore such an address only by fabricating the lease
                # (re-adding it by hand), which would misstate the host's state.  Use a peer without dynamic addresses.
                raise FaultRefused("PEER_ADDRESS_NOT_PRESERVABLE",
                                   f"peer holds dynamic address(es) {dynamic} that a link down flushes despite keep_addr_on_down")
            return {**observed, "peer": peer, "device_status": self._device_status(container, interface)}
        container, interface = self._target(fault)
        if fault["fault_type"] in ("carrier_loss", "link_flap"):
            state = self._link_state(container, interface)
            if not (state["admin_up"] and state["kernel_up"] and state["carrier"]):
                raise FaultRefused("BASELINE_UNAVAILABLE", "link is not up with carrier")
            return state
        state = self._interface_state(container, interface)
        if not state["admin_up"]:
            raise FaultRefused("BASELINE_UNAVAILABLE", "interface is already administratively down")
        return state

    def protected_health(self, flows: list[dict]) -> dict:
        families: dict[str, dict] = {}
        for flow in flows:
            entry = self.flow_map.get(flow["selector_ref"])
            sample = {"measured": False, "loss_pct": None}
            if isinstance(entry, dict) and self._ADDRESS.fullmatch(str(entry.get("destination", ""))):
                binary = "ping6" if flow["family"] == "IPv6" and entry.get("ping6") else "ping"
                argv = ["/usr/bin/docker", "exec", self._container(entry.get("source", "")), binary]
                argv += (["-6"] if flow["family"] == "IPv6" and binary == "ping" else []) + ["-c", "5", "-i", "0.2", "-W", "1", entry["destination"]]
                _code, output = self._run(argv)
                match = re.search(r"([0-9.]+)% packet loss", output or "")
                if match:
                    sample = {"measured": True, "loss_pct": float(match.group(1))}
            worst = families.get(flow["family"])
            if worst is None or not sample["measured"] or (worst["measured"] and sample["loss_pct"] > worst["loss_pct"]):
                families[flow["family"]] = sample
        healthy = bool(self._management_probe())
        return {"management_ok": healthy, "monitoring_ok": healthy, "families": families}

    def inject(self, fault: dict, operation_id: str) -> dict:
        if fault["fault_type"] == "peer_carrier_loss":
            return self._peer_inject(fault, operation_id)
        container, interface = self._target(fault)
        if fault["fault_type"] == "carrier_loss":
            self._set_link(container, interface, "down")
            state = self._link_state(container, interface)
            return {"operation_id": operation_id, "accepted": True, "verified_link_down": not state["kernel_up"],
                    "config_unchanged_admin_up": state["admin_up"]}
        if fault["fault_type"] == "link_flap":
            return self._flap(fault, container, interface, operation_id)
        self._cli(container, ["configure", f"interface {interface}", "shutdown", "end"])
        return {"operation_id": operation_id, "accepted": True, "verified_down": not self._interface_state(container, interface)["admin_up"]}

    def _peer_inject(self, fault: dict, operation_id: str) -> dict:
        """Keep the host's IPv6 addresses across the down (namespaced sysctl, restored on rollback), take the host NIC down, then
        prove the observed interface is admin UP / oper DOWN and STILL down at every hold check (a reasserted link is reported
        as not held, never as a sustained fault)."""
        import time

        container, interface, peer_c, peer_if = self._peer_target(fault)
        code, _ = self._run(["/usr/bin/docker", "exec", peer_c, "sysctl", "-w", f"net.ipv6.conf.{peer_if}.keep_addr_on_down=1"])
        if code != 0:
            raise FaultRefused("DEVICE_COMMAND_FAILED", "peer sysctl")
        self._set_peer_link(peer_c, peer_if, "down")
        checks = []
        for wait in self.PEER_HOLD_CHECKS:
            time.sleep(wait)
            observed, status = self._link_state(container, interface), self._device_status(container, interface)
            checks.append({"at": _iso(_now()), "observed_admin_up": observed["admin_up"], "observed_kernel_up": observed["kernel_up"],
                           "observed_carrier": observed["carrier"], **status})
        held = all(c["observed_admin_up"] and c["observed_kernel_up"] and not c["observed_carrier"]
                   and c["interfaceStatus"] != "connected" and c["lineProtocolStatus"] != "up" for c in checks)
        return {"operation_id": operation_id, "accepted": True, "verified_link_down": held, "held": held,
                "config_unchanged_admin_up": all(c["observed_admin_up"] for c in checks), "hold_checks": checks,
                "peer": f"{fault['peer']['node']}:{peer_if}"}

    def _set_peer_link(self, container: str, interface: str, state: str) -> None:
        if state not in ("up", "down") or not PEER_INTERFACE.fullmatch(interface):
            raise FaultRefused("OBJECT_NOT_ALLOWED")
        code, _ = self._run(["/usr/bin/docker", "exec", container, "ip", "link", "set", "dev", interface, state])
        if code != 0:
            raise FaultRefused("DEVICE_COMMAND_FAILED")

    def _flap(self, fault: dict, container: str, interface: str, operation_id: str) -> dict:
        """A bounded, synchronous flap: exactly ``cycles`` DOWN/UP pairs; the link is ALWAYS left up (finally), and the
        sequence stops early if a protected flow degrades.  No background process survives this call."""
        import time

        spec, transitions, stopped = fault["flap"], [], ""
        try:
            for cycle in range(spec["cycles"]):
                self._set_link(container, interface, "down")
                transitions.append({"at": _iso(_now()), "state": "down", "cycle": cycle + 1})
                time.sleep(spec["down_seconds"])
                self._set_link(container, interface, "up")
                transitions.append({"at": _iso(_now()), "state": "up", "cycle": cycle + 1})
                time.sleep(spec["up_seconds"])
                if self._flow_stop and self._flow_stop():
                    stopped = "protected-flow stop condition"
                    break
        finally:
            try:
                self._set_link(container, interface, "up")
            except FaultRefused:
                stopped = stopped or "final link-up failed (rollback will retry)"
        return {"operation_id": operation_id, "accepted": True, "transitions": transitions, "cycles_completed": len(transitions) // 2,
                "stopped": stopped, "final_link_up": self._link(container, interface)["kernel_up"]}

    def rollback(self, fault: dict, baseline: dict, operation_id: str) -> dict:
        if fault["fault_type"] == "peer_carrier_loss":
            _container, _interface, peer_c, peer_if = self._peer_target(fault)
            peer = baseline.get("peer") or {}
            if peer.get("kernel_up") is True:
                self._set_peer_link(peer_c, peer_if, "up")
            keep = str(peer.get("keep_addr_on_down", ""))
            if keep in ("0", "1", "-1"):
                self._run(["/usr/bin/docker", "exec", peer_c, "sysctl", "-w", f"net.ipv6.conf.{peer_if}.keep_addr_on_down={keep}"])
            restored = self._peer_restore_wait(fault, baseline)
            return {"operation_id": operation_id, "restored": restored,
                    "peer_after": self._host_l3(peer_c, peer_if) if not restored else None}
        container, interface = self._target(fault)
        if fault["fault_type"] in ("carrier_loss", "link_flap"):
            if baseline.get("kernel_up") is True:
                self._set_link(container, interface, "up")
            return {"operation_id": operation_id, "restored": self.matches_baseline(fault, baseline)}
        if baseline.get("admin_up") is True:
            self._cli(container, ["configure", f"interface {interface}", "no shutdown", "end"])
        return {"operation_id": operation_id, "restored": self.matches_baseline(fault, baseline)}

    def matches_baseline(self, fault: dict, baseline: dict) -> bool:
        if fault["fault_type"] == "peer_carrier_loss":
            container, interface, peer_c, peer_if = self._peer_target(fault)
            state = self._link_state(container, interface)
            return (state["admin_up"], state["object_digest"], state["kernel_up"], state["carrier"]) == \
                (baseline.get("admin_up"), baseline.get("object_digest"), baseline.get("kernel_up"), True) \
                and self._host_l3(peer_c, peer_if) == baseline.get("peer")
        container, interface = self._target(fault)
        if fault["fault_type"] in ("carrier_loss", "link_flap"):
            state = self._link_state(container, interface)
            return (state["admin_up"], state["object_digest"], state["kernel_up"]) == \
                (baseline.get("admin_up"), baseline.get("object_digest"), baseline.get("kernel_up")) and state["carrier"] is True
        return self._interface_state(container, interface) == {"admin_up": baseline.get("admin_up"), "object_digest": baseline.get("object_digest")}
