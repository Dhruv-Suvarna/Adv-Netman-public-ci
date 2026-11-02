"""Recoverable EOS transaction used only by managed credential rotation.

The delicate CLI primitives are the same ones proven by the Phase-25 MFA
rollout: commands containing a secret travel only on ``docker exec -i``
stdin, a named configuration session is committed with an EOS timer, a
pre-change checkpoint is hashed, and persistence is verified by comparing
normalized startup and running configuration.

Nothing in this module owns provider promotion.  The credential engine keeps
both provider candidates until this controller has confirmed, persisted and
verified the device transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Callable

from ...models import DeviceLoginMfaPolicy
from .. import nsot_live
from . import r1_pilot as eos
from .r1_pilot_runner import nmas_read_paths


COMMIT_TIMER = "00:10:00"
_VERSION_MARKER = "Software image version"


class CeosTransactionError(RuntimeError):
    code = "CEOS_TRANSACTION_FAILED"
    uncertain = False

    def __init__(self, code: str | None = None, *, evidence: dict | None = None):
        self.code = code or self.code
        self.evidence = evidence or {}
        super().__init__(self.code)


class CeosTransactionRejected(CeosTransactionError):
    code = "DEVICE_CHANGE_REJECTED"


class CeosTransactionUncertain(CeosTransactionError):
    code = "DEVICE_CHANGE_UNCERTAIN"
    uncertain = True


class CeosOperationalValidationFailed(CeosTransactionError):
    code = "OPERATIONAL_VALIDATION_FAILED"
    uncertain = True


class CeosConfirmationFailed(CeosTransactionError):
    code = "TRANSACTION_CONFIRM_FAILED"
    uncertain = True


class CeosPersistenceFailed(CeosTransactionError):
    code = "PERSISTENCE_FAILED"
    uncertain = True


@dataclass(frozen=True)
class SafeDeviceTransaction:
    session_name: str
    checkpoint_file: str
    checkpoint_sha256: str
    checkpoint_md5: str
    pre_change_digest: str
    post_change_digest: str
    commit_timer: str
    baseline: dict

    def metadata(self) -> dict:
        return {
            "session_name": self.session_name,
            "checkpoint_file": self.checkpoint_file,
            "checkpoint_sha256": self.checkpoint_sha256,
            "checkpoint_md5": self.checkpoint_md5,
            "pre_change_digest": self.pre_change_digest,
            "post_change_digest": self.post_change_digest,
            "commit_timer": self.commit_timer,
            "baseline": self.baseline,
        }

    @classmethod
    def from_run(cls, run) -> "SafeDeviceTransaction":
        metadata = run.transaction_metadata or {}
        return cls(
            session_name=run.session_name or metadata.get("session_name", ""),
            checkpoint_file=run.checkpoint_file or metadata.get("checkpoint_file", ""),
            checkpoint_sha256=run.checkpoint_sha256 or metadata.get("checkpoint_sha256", ""),
            checkpoint_md5=run.checkpoint_md5 or metadata.get("checkpoint_md5", ""),
            pre_change_digest=run.pre_change_digest or metadata.get("pre_change_digest", ""),
            post_change_digest=run.post_change_digest or metadata.get("post_change_digest", ""),
            commit_timer=metadata.get("commit_timer", COMMIT_TIMER),
            baseline=metadata.get("baseline") or {},
        )


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def normalized_digest(text: str) -> str:
    return _digest(eos._normalized_config(text))


def _masked_rotation_config(text: str, username: str) -> str:
    """Mask only the rotating account's stored secret, preserving all else."""
    pattern = re.compile(
        rf"^(\s*username\s+{re.escape(username)}\b.*?\bsecret(?:\s+(?:sha512|0|5|7|8a))?\s+)\S+(\s*)$"
    )
    count = 0
    lines = []
    for line in eos._normalized_config(text).splitlines():
        match = pattern.match(line)
        if match:
            count += 1
            line = f"{match.group(1)}<ROTATED>{match.group(2)}"
        lines.append(line)
    if count != 1:
        raise CeosTransactionRejected("ROTATION_ACCOUNT_CONFIG_AMBIGUOUS")
    return "\n".join(lines)


def _interface_section(text: str, name: str) -> str:
    lines = eos._normalized_config(text).splitlines()
    start = next((i for i, line in enumerate(lines) if line == f"interface {name}"), None)
    if start is None:
        return ""
    section = [lines[start]]
    for line in lines[start + 1:]:
        if line.startswith((" ", "\t")):
            section.append(line)
        else:
            break
    return "\n".join(section)


def _policy_snapshot(device_name: str) -> dict:
    row = DeviceLoginMfaPolicy.objects.filter(device_name=device_name).values(
        "mechanism", "enforcement_state", "central_aaa_state", "required",
        "radius_server", "radius_source_interface", "automation_exempt",
        "candidate_digest", "last_verified_at", "last_verification_result",
    ).first()
    if row and row.get("last_verified_at") is not None:
        row["last_verified_at"] = row["last_verified_at"].isoformat()
    return row or {}


def _identity_routes() -> dict[str, list[str]]:
    routes = {}
    for name in eos.MANAGED_CEOS_MFA_DEVICES:
        metadata = nsot_live.get_live_target_metadata(name, purpose="WRITE") or {}
        routes[name] = [profile["username"] for profile in metadata.get("access_profiles", ())]
    return routes


class CeosRotationTransactionController:
    """EOS session/checkpoint/timer/persistence controller with no provider writes."""

    def __init__(
        self,
        *,
        transport_factory: Callable | None = None,
        read_paths: Callable[[str], dict] = nmas_read_paths,
        reachable: Callable[[str], bool] = eos.management_reachable,
    ):
        self.transport_factory = transport_factory or (lambda target: eos.EosCliTransport(container=target.container))
        self.read_paths = read_paths
        self.reachable = reachable

    @staticmethod
    def _target(credential):
        from ..management import resolve as management_resolve

        if management_resolve.endpoint(credential.device_name, purpose="WRITE").source != management_resolve.LEGACY:
            raise CeosTransactionRejected("PATH_ROTATION_NOT_IMPLEMENTED")
        try:
            target = eos.target_for(credential.device_name)
        except eos.PilotError:
            raise CeosTransactionRejected("TARGET_NOT_CONFIGURED") from None
        if credential.platform != "arista_ceos":
            raise CeosTransactionRejected("TARGET_NOT_CONFIGURED")
        return target

    def preflight(self, credential) -> None:
        target = self._target(credential)
        transport = self.transport_factory(target)
        try:
            sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosTransactionRejected("TRANSACTION_PREFLIGHT_FAILED") from None
        if eos.open_sessions(sessions):
            raise CeosTransactionRejected("OPEN_CONFIGURATION_SESSION")
        if not self.reachable(target.management_address):
            raise CeosTransactionRejected("MANAGEMENT_UNREACHABLE")

    def _baseline(self, credential, target, config: str) -> dict:
        routes = _identity_routes()
        return {
            "masked_config_digest": _digest(_masked_rotation_config(config, credential.username)),
            "vlan200_digest": _digest(_interface_section(config, "Vlan200")),
            "policy": _policy_snapshot(credential.device_name),
            "target_identities": routes.get(credential.device_name, []),
            "other_identities": {name: identities for name, identities in routes.items() if name != credential.device_name},
            "management_address": target.management_address,
        }

    def arm(self, credential, command: str, current_value: str, replacement: str, run_id: str) -> SafeDeviceTransaction:
        target = self._target(credential)
        transport = self.transport_factory(target)
        try:
            config = eos.running_config(transport)
            sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosTransactionRejected("TRANSACTION_PREFLIGHT_FAILED") from None
        if eos.open_sessions(sessions):
            raise CeosTransactionRejected("OPEN_CONFIGURATION_SESSION")

        token = re.sub(r"[^A-Za-z0-9]", "", credential.device_name.upper())
        run_token = re.sub(r"[^a-f0-9]", "", str(run_id).lower())[:10]
        if not token or len(run_token) != 10:
            raise CeosTransactionRejected("INVALID_TRANSACTION_METADATA")
        session = f"NMAS-CR-{token}-{run_token.upper()}"
        checkpoint_name = f"nmas-credrot-{credential.device_name.lower()}-{run_token}.cfg"
        checkpoint_path = f"/mnt/flash/{checkpoint_name}"
        if transport.file_digests(checkpoint_path) is not None:
            raise CeosTransactionRejected("CHECKPOINT_ALREADY_EXISTS")

        try:
            pre_digest = normalized_digest(config)
            baseline = self._baseline(credential, target, config)
            copied = transport.run([f"copy running-config flash:{checkpoint_name}"])
            checkpoint = transport.file_digests(checkpoint_path)
        except CeosTransactionError:
            raise
        except Exception:
            raise CeosTransactionRejected("CHECKPOINT_CREATE_FAILED") from None
        if not copied.clean or checkpoint is None or checkpoint["normalized"] != eos._normalized_config(config):
            raise CeosTransactionRejected("CHECKPOINT_CREATE_FAILED")

        known = eos.SecretSet((current_value, replacement))
        try:
            staged = transport.run([f"configure session {session}", command, "show session-config diffs"], known)
        except Exception:
            try:
                transport.run([f"configure session {session} abort"], known)
                remaining = eos.open_sessions(eos.config_sessions(transport))
            except Exception:
                remaining = {session: {}}
            if session in remaining:
                raise CeosTransactionUncertain("SESSION_STAGE_UNCERTAIN") from None
            raise CeosTransactionRejected("DEVICE_CHANGE_REJECTED") from None
        try:
            staged_sessions = eos.config_sessions(transport)
        except Exception:
            staged_sessions = {}
        if not staged.clean or session not in eos.open_sessions(staged_sessions):
            try:
                transport.run([f"configure session {session} abort"], known)
            except Exception:
                pass
            raise CeosTransactionRejected("DEVICE_CHANGE_REJECTED")

        try:
            committed = transport.run([f"configure session {session} commit timer {COMMIT_TIMER}"], known)
        except Exception:
            raise CeosTransactionUncertain("DEVICE_CHANGE_UNCERTAIN") from None
        try:
            post_config = eos.running_config(transport)
            post_sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosTransactionUncertain("DEVICE_CHANGE_UNCERTAIN") from None
        open_sessions = eos.open_sessions(post_sessions)
        timer_armed = session in open_sessions and bool(open_sessions[session].get("timer_pending"))
        if not committed.clean or not timer_armed:
            raise CeosTransactionUncertain("COMMIT_TIMER_NOT_PROVEN")
        post_digest = normalized_digest(post_config)
        if post_digest == pre_digest:
            raise CeosTransactionUncertain("DEVICE_CHANGE_NOT_OBSERVED")
        if _digest(_masked_rotation_config(post_config, credential.username)) != baseline["masked_config_digest"]:
            raise CeosTransactionUncertain("UNRELATED_CONFIGURATION_DRIFT")

        return SafeDeviceTransaction(
            session_name=session,
            checkpoint_file=f"flash:{checkpoint_name}",
            checkpoint_sha256=checkpoint["sha256"],
            checkpoint_md5=checkpoint["md5"],
            pre_change_digest=pre_digest,
            post_change_digest=post_digest,
            commit_timer=COMMIT_TIMER,
            baseline=baseline,
        )

    @staticmethod
    def _validation_code(checks: dict[str, bool]) -> str:
        mapping = (
            ("new_login", "NEW_LOGIN_VERIFICATION_FAILED"),
            ("old_rejected", "OLD_CREDENTIAL_STILL_ACCEPTED"),
            ("health", "HEALTH_VALIDATION_FAILED"),
            ("health_blocking_empty", "HEALTH_VALIDATION_FAILED"),
            ("health_warning_policy", "HEALTH_VALIDATION_FAILED"),
            ("nsot", "NSOT_VALIDATION_FAILED"),
            ("config_retrieval", "CONFIG_RETRIEVAL_VALIDATION_FAILED"),
            ("privileged_recovery", "RECOVERY_PROBE_FAILED"),
            ("target_identity", "IDENTITY_ROUTING_CHANGED"),
            ("other_identity_routing", "FLEET_IDENTITY_ROUTING_CHANGED"),
            ("policy_unchanged", "MFA_POLICY_CHANGED"),
            ("vlan200_unchanged", "VLAN200_CHANGED"),
            ("management_reachable", "MANAGEMENT_UNREACHABLE"),
            ("no_unrelated_drift", "UNRELATED_CONFIGURATION_DRIFT"),
            ("transaction_state", "TRANSACTION_STATE_INVALID"),
        )
        return next((code for name, code in mapping if not checks.get(name)), "OPERATIONAL_VALIDATION_FAILED")

    def validate(
        self,
        credential,
        transaction: SafeDeviceTransaction,
        *,
        new_verified: bool,
        old_rejected: bool,
        expect_timer: bool,
    ) -> dict:
        target = self._target(credential)
        transport = self.transport_factory(target)
        try:
            config = eos.running_config(transport)
            sessions = eos.config_sessions(transport)
            reads = self.read_paths(credential.device_name)
            recovery = _VERSION_MARKER in transport.show("show version")
        except Exception:
            raise CeosOperationalValidationFailed("OPERATIONAL_READ_FAILED") from None

        opened = eos.open_sessions(sessions)
        if expect_timer:
            transaction_state = (
                set(opened) == {transaction.session_name}
                and bool(opened[transaction.session_name].get("timer_pending"))
            )
        else:
            transaction_state = not opened
        current_routes = {
            "target": reads.get("target_identities", []),
            "other": reads.get("other_identities", {}),
        }
        baseline = transaction.baseline
        try:
            tolerated_warnings = reads.get("health_tolerated_warnings", [])
            checks = {
                "new_login": bool(new_verified),
                "old_rejected": bool(old_rejected),
                "health": reads.get("health") is True,
                "health_blocking_empty": not reads.get("health_blocking"),
                "health_warning_policy": all(
                    warning.get("check_code") == "CRITICAL_EVENTS_RECENT"
                    for warning in tolerated_warnings
                ),
                "nsot": reads.get("nsot") is True,
                "config_retrieval": reads.get("config_retrieval") is True,
                "privileged_recovery": recovery,
                "target_identity": current_routes["target"][:1] == [credential.username],
                "other_identity_routing": current_routes["other"] == baseline.get("other_identities", {}),
                "policy_unchanged": _policy_snapshot(credential.device_name) == baseline.get("policy", {}),
                "vlan200_unchanged": _digest(_interface_section(config, "Vlan200")) == baseline.get("vlan200_digest"),
                "management_reachable": self.reachable(target.management_address),
                "no_unrelated_drift": _digest(_masked_rotation_config(config, credential.username)) == baseline.get("masked_config_digest"),
                "post_change_digest": normalized_digest(config) == transaction.post_change_digest,
                "transaction_state": transaction_state,
            }
        except Exception:
            raise CeosOperationalValidationFailed("OPERATIONAL_STATE_INVALID") from None
        evidence = {
            "checks": checks,
            "health_status": reads.get("health_status"),
            "health_tolerated_warnings": tolerated_warnings,
            "target_identities": current_routes["target"],
            "other_identity_routing_unchanged": checks["other_identity_routing"],
            "passed": all(checks.values()),
        }
        if not evidence["passed"]:
            raise CeosOperationalValidationFailed(self._validation_code(checks), evidence=evidence)
        return evidence

    def confirm(self, credential, transaction: SafeDeviceTransaction) -> str:
        target = self._target(credential)
        transport = self.transport_factory(target)
        try:
            before = eos.running_config(transport)
            sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosConfirmationFailed("TRANSACTION_CONFIRM_READ_FAILED") from None
        opened = eos.open_sessions(sessions)
        if (
            normalized_digest(before) != transaction.post_change_digest
            or set(opened) != {transaction.session_name}
            or not opened[transaction.session_name].get("timer_pending")
        ):
            raise CeosConfirmationFailed("COMMIT_TIMER_NOT_ARMED")
        try:
            result = transport.run([f"configure session {transaction.session_name} commit"])
            after = eos.running_config(transport)
            after_sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosConfirmationFailed("TRANSACTION_CONFIRM_UNCERTAIN") from None
        if not result.clean or eos.open_sessions(after_sessions) or normalized_digest(after) != transaction.post_change_digest:
            raise CeosConfirmationFailed("TRANSACTION_CONFIRM_FAILED")
        return normalized_digest(after)

    def persist(self, credential, transaction: SafeDeviceTransaction) -> dict:
        target = self._target(credential)
        transport = self.transport_factory(target)
        try:
            before = eos.running_config(transport)
            sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosPersistenceFailed("PERSISTENCE_PREFLIGHT_FAILED") from None
        if eos.open_sessions(sessions) or normalized_digest(before) != transaction.post_change_digest:
            raise CeosPersistenceFailed("PERSISTENCE_STATE_MISMATCH")
        try:
            result = transport.run(["write memory"])
            running = eos.running_config(transport)
            startup = transport.show("show startup-config")
            after_sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosPersistenceFailed("PERSISTENCE_UNCERTAIN") from None
        startup_matches = eos._normalized_config(startup) == eos._normalized_config(running)
        evidence = {
            "running_digest": normalized_digest(running),
            "startup_matches_running": startup_matches,
            "no_open_sessions": not eos.open_sessions(after_sessions),
        }
        if (
            not result.clean
            or evidence["running_digest"] != transaction.post_change_digest
            or not startup_matches
            or not evidence["no_open_sessions"]
        ):
            raise CeosPersistenceFailed("STARTUP_VERIFICATION_FAILED", evidence=evidence)
        return evidence

    def inspect(self, credential, transaction: SafeDeviceTransaction) -> dict:
        target = self._target(credential)
        transport = self.transport_factory(target)
        try:
            running = eos.running_config(transport)
            startup = transport.show("show startup-config")
            sessions = eos.config_sessions(transport)
        except Exception:
            raise CeosTransactionUncertain("RECOVERY_STATE_UNAVAILABLE") from None
        digest = normalized_digest(running)
        opened = eos.open_sessions(sessions)
        return {
            "timer_pending": (
                transaction.session_name in opened
                and bool(opened[transaction.session_name].get("timer_pending"))
            ),
            "pre_change_matches": digest == transaction.pre_change_digest,
            "post_change_matches": digest == transaction.post_change_digest,
            "startup_matches_running": eos._normalized_config(startup) == eos._normalized_config(running),
            "no_open_sessions": not opened,
            "running_digest": digest,
        }

    def complete_recovery(self, credential, transaction: SafeDeviceTransaction) -> dict:
        validation = self.validate(
            credential, transaction, new_verified=True, old_rejected=True, expect_timer=False,
        )
        state = self.inspect(credential, transaction)
        persistence = (
            {"running_digest": state["running_digest"], "startup_matches_running": True, "no_open_sessions": True}
            if state["startup_matches_running"] and state["no_open_sessions"]
            else self.persist(credential, transaction)
        )
        return {"validation": validation, "persistence": persistence}
