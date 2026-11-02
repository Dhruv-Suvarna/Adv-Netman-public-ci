"""One-device-at-a-time Linux human-MFA rollout orchestration."""
from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
import time
from dataclasses import dataclass, field

from django.db import transaction
from django.utils import timezone

from modules.device_credentials import FileSecretProvider, SecretProviderError

from ...models import (CentralAaaState, DeviceCredential, DeviceLoginMfaPolicy,
                       MfaEnforcementState)
from .. import nsot_service
from ..config_import import service as config_import
from ..health.device import run_device_health
from . import linux_mfa as lm
from . import r1_pilot as ceos
from .r1_pilot_runner import PilotEvidence, health_verdict

CEOS_POSITIVE_EVIDENCE_STEP = "verify:positive"
PAM_RADIUS_MODULE = "/lib/x86_64-linux-gnu/security/pam_radius_auth.so"
VISUDO_MISSING = "REQUIRED_DEPENDENCY_MISSING: visudo"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _clean_output(completed) -> str:
    return (completed.stdout or "").strip()


def normalize_ospf_v4_neighbors(neighbor_payload: dict, interface_payload: dict) -> list[dict]:
    """Stable FRR 8.4 IPv4 adjacency identity/state; timers and counters are excluded."""
    neighbors = neighbor_payload.get("neighbors") if isinstance(neighbor_payload, dict) else None
    interfaces = interface_payload.get("interfaces") if isinstance(interface_payload, dict) else None
    if not isinstance(neighbors, dict) or not isinstance(interfaces, dict):
        raise ValueError("FRR IPv4 OSPF JSON schema is not recognized.")
    normalized = []
    for neighbor_id, rows in neighbors.items():
        if not isinstance(rows, list):
            raise ValueError("FRR IPv4 OSPF neighbor rows are invalid.")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("FRR IPv4 OSPF neighbor row is invalid.")
            raw_interface = row.get("ifaceName")
            interface = raw_interface.split(":", 1)[0] if isinstance(raw_interface, str) else ""
            details = interfaces.get(interface) if interface else None
            state = row.get("converged") or str(row.get("state", "")).split("/", 1)[0]
            item = {
                "address_family": "ipv4",
                "neighbor_id": str(neighbor_id),
                "neighbor_address": str(row.get("address", "")),
                "interface": interface,
                "area": str(details.get("area", "")) if isinstance(details, dict) else "",
                "state": str(state),
            }
            if not all(item.values()):
                raise ValueError("FRR IPv4 OSPF stable identity fields are incomplete.")
            normalized.append(item)
    return sorted(normalized, key=lambda item: tuple(item[key] for key in (
        "neighbor_id", "neighbor_address", "interface", "area", "state",
    )))


def normalize_ospf_v6_neighbors(neighbor_payload: dict, interface_payload: dict) -> list[dict]:
    """Stable FRR 8.4 IPv6 adjacency identity/state; timers and counters are excluded."""
    neighbors = neighbor_payload.get("neighbors") if isinstance(neighbor_payload, dict) else None
    if not isinstance(neighbors, list) or not isinstance(interface_payload, dict):
        raise ValueError("FRR IPv6 OSPF JSON schema is not recognized.")
    normalized = []
    for row in neighbors:
        if not isinstance(row, dict):
            raise ValueError("FRR IPv6 OSPF neighbor row is invalid.")
        interface = row.get("interfaceName")
        details = interface_payload.get(interface) if isinstance(interface, str) else None
        item = {
            "address_family": "ipv6",
            "neighbor_id": str(row.get("neighborId", "")),
            "interface": str(interface or ""),
            "area": str(details.get("areaId", "")) if isinstance(details, dict) else "",
            "state": str(row.get("state", "")),
        }
        if not all(item.values()):
            raise ValueError("FRR IPv6 OSPF stable identity fields are incomplete.")
        normalized.append(item)
    return sorted(normalized, key=lambda item: tuple(item[key] for key in (
        "neighbor_id", "interface", "area", "state",
    )))


def ospf_adjacencies_healthy(snapshot: dict) -> bool:
    families = snapshot.get("ospf_neighbors") or {}
    return all(
        isinstance(families.get(family), list) and families[family]
        and all(item.get("state", "").casefold() == "full" for item in families[family])
        for family in ("ipv4", "ipv6")
    )


@dataclass
class Dependencies:
    runner: callable = subprocess.run
    clock: callable = time.time
    provider: FileSecretProvider = field(default_factory=FileSecretProvider)
    evidence: PilotEvidence | None = None
    privacyidea: object = field(default_factory=ceos.PrivacyIdeaReader)
    human_factors: callable | None = None
    actor: str = "manage.py linux_mfa_rollout"


class LinuxMfaRunner:
    def __init__(self, device: str, deps: Dependencies | None = None):
        self.target = lm.target_for(device)
        self.device = device
        self.deps = deps or Dependencies()
        self.deps.evidence = self.deps.evidence or PilotEvidence(device=device)
        self.transport = lm.DockerTransport(self.target, runner=self.deps.runner)

    def _known(self, extra=()) -> ceos.SecretSet:
        values = list(extra)
        try:
            values += [self.deps.provider.current(self.target.service_key_ref).value,
                       self.deps.provider.current(self.target.breakglass_ref).value,
                       lm.private_runtime_value(lm.radius_secret_path(self.device))]
        except (SecretProviderError, lm.LinuxMfaError):
            pass
        return ceos.SecretSet(values)

    def _record(self, step: str, *, ok: bool, extra_secrets=(), **data) -> dict:
        return self.deps.evidence.record(step, ok=ok, known=self._known(extra_secrets),
                                         at=self.deps.clock(), actor=self.deps.actor, **data)

    def _container(self, argv, *, timeout=30):
        return self.transport.run(list(argv), timeout=timeout)

    def _dependency_state(self) -> dict:
        """Return bounded Ubuntu dependency state without persisting command output."""
        module = self._container(["test", "-f", PAM_RADIUS_MODULE])
        sudo_package = self._container(["dpkg-query", "-W", "-f=${Status}", "sudo"])
        visudo_path = self._container(["sh", "-c", "command -v visudo >/dev/null 2>&1"])
        visudo_version = self._container(["visudo", "-V"])
        return {
            "pam_radius_installed": module.returncode == 0,
            "sudo_package_installed": (
                sudo_package.returncode == 0 and _clean_output(sudo_package) == "install ok installed"
            ),
            "visudo_available": visudo_path.returncode == 0,
            "visudo_executable": visudo_version.returncode == 0,
        }

    @staticmethod
    def _dependency_errors(state: dict) -> list[str]:
        errors = []
        if not state.get("pam_radius_installed"):
            errors.append("REQUIRED_DEPENDENCY_MISSING: pam_radius_auth.so")
        if not state.get("visudo_available") or not state.get("visudo_executable"):
            errors.append(VISUDO_MISSING)
        if not state.get("sudo_package_installed"):
            errors.append("REQUIRED_DEPENDENCY_MISSING: sudo")
        return errors

    def _require_passing_dependency_precheck(self) -> dict:
        entry = self.deps.evidence.latest_entry("linux-precheck")
        if not entry or not entry[1].get("ok"):
            raise lm.LinuxMfaError("A latest passing Linux MFA precheck is required before backup or timer arming.")
        recorded = entry[1].get("checks") or {}
        if not recorded.get("sudo_dependency_satisfied"):
            raise lm.LinuxMfaError(VISUDO_MISSING)
        state = self._dependency_state()
        errors = self._dependency_errors(state)
        if errors:
            raise lm.LinuxMfaError(errors[0])
        return state

    def _operational_snapshot(self) -> dict:
        commands = {
            "frr": ["vtysh", "-c", "show running-config"],
            "addresses": ["ip", "-j", "addr", "show"],
            "routes4": ["ip", "-j", "-4", "route", "show"],
            "routes6": ["ip", "-j", "-6", "route", "show"],
        }
        digests, errors = {}, []
        for name, argv in commands.items():
            result = self._container(argv)
            if result.returncode:
                errors.append(name)
            else:
                digests[name] = _sha(_clean_output(result))
        ospf_commands = {
            "v4_neighbors": ["vtysh", "-c", "show ip ospf neighbor json"],
            "v4_interfaces": ["vtysh", "-c", "show ip ospf interface json"],
            "v6_neighbors": ["vtysh", "-c", "show ipv6 ospf6 neighbor json"],
            "v6_interfaces": ["vtysh", "-c", "show ipv6 ospf6 interface json"],
        }
        ospf_payloads = {}
        for name, argv in ospf_commands.items():
            result = self._container(argv)
            if result.returncode:
                errors.append(name)
                continue
            try:
                ospf_payloads[name] = json.loads(_clean_output(result))
            except (TypeError, ValueError):
                errors.append(name)
        neighbors = {"ipv4": [], "ipv6": []}
        if not any(name in errors for name in ospf_commands):
            try:
                neighbors = {
                    "ipv4": normalize_ospf_v4_neighbors(ospf_payloads["v4_neighbors"], ospf_payloads["v4_interfaces"]),
                    "ipv6": normalize_ospf_v6_neighbors(ospf_payloads["v6_neighbors"], ospf_payloads["v6_interfaces"]),
                }
            except ValueError:
                errors.append("ospf_semantic_normalization")
        snapshot = {"digests": digests, "ospf_neighbors": neighbors, "errors": errors}
        snapshot["ospf_healthy"] = ospf_adjacencies_healthy(snapshot)
        return snapshot

    def _reads(self) -> dict:
        _health_run, report = run_device_health(self.device, persist=False)
        health = health_verdict(report)
        fetched, _message = config_import.fetch_sanitized_running_config(self.device)
        nsot = nsot_service.get_device_detail(self.device, force_refresh=True)
        from .. import nsot_live
        route = nsot_live.get_live_target_metadata(self.device, purpose="WRITE") or {}
        return {
            "health": health["ok"], "health_status": report.get("status"), "health_blocking": health["blocking"],
            "health_tolerated_warnings": health["tolerated_warnings"],
            "config_retrieval": fetched is not None, "nsot": nsot.get("status") == "available",
            "identity": route.get("username"), "ssh_key_ref": route.get("ssh_key_ref"),
        }

    def precheck(self) -> dict:
        candidate = lm.reviewed_candidate(self.target)
        inspect = self.deps.runner(["docker", "inspect", "-f", "{{.State.Running}}", self.target.container],
                                   capture_output=True, text=True, timeout=15, check=False)
        recovery = self._container(["id", "-u"])
        sshd = self._container(["sshd", "-t"])
        dependencies = self._dependency_state()
        users = self._container(["getent", "passwd", lm.HUMAN_USERNAME, lm.SERVICE_USERNAME,
                                 self.target.breakglass_username])
        reads = self._reads()
        operations = self._operational_snapshot()
        radius_stage = self.deps.evidence.latest("linux-radius-staged", ok=True)
        r1_regression = PilotEvidence(device="R1").latest(CEOS_POSITIVE_EVIDENCE_STEP, ok=True,
                                                                  since=radius_stage["at"] if radius_stage else self.deps.clock())
        failures = []
        checks = {
            "container_running": inspect.returncode == 0 and _clean_output(inspect) == "true",
            "candidate_unblocked": candidate.supported and not candidate.blockers,
            "docker_exec_recovery": recovery.returncode == 0 and _clean_output(recovery) == "0",
            "sshd_valid": sshd.returncode == 0,
            "pam_radius_installed": dependencies["pam_radius_installed"],
            "sudo_dependency_satisfied": all((
                dependencies["sudo_package_installed"],
                dependencies["visudo_available"],
                dependencies["visudo_executable"],
            )),
            "radius_client_staged": bool(radius_stage),
            "ceos_mfa_regression_after_radius_change": bool(r1_regression),
            "phase26b_accounts_absent": users.returncode == 2 and not _clean_output(users),
            "health": reads["health"], "nsot": reads["nsot"], "config_retrieval": reads["config_retrieval"],
            "identity_routing": reads["identity"] == lm.SERVICE_USERNAME and reads["ssh_key_ref"] == self.target.service_key_ref,
            "frr_network_state_readable": not operations["errors"],
            "ospf_adjacencies_healthy": operations["ospf_healthy"],
        }
        failures = [name for name, ok in checks.items() if not ok]
        result = {
            "device": self.device, "PASS": not failures, "checks": checks, "failures": failures,
            "dependency_state": dependencies, "dependency_errors": self._dependency_errors(dependencies),
            "candidate_digest": candidate.digest, "management_address": self.target.address,
            "recovery": "docker exec UID 0 plus device-specific local break-glass",
            "reads": reads, "operational_baseline": operations,
        }
        self._record("linux-precheck", ok=result["PASS"], **result)
        return result

    def stage_radius(self) -> dict:
        from monitoring.human_mfa import render_radius_clients
        live_ceos = list(render_radius_clients.CEOS_ELIGIBLE)
        live_linux = list(DeviceLoginMfaPolicy.objects.filter(
            platform="ubuntu_frr", enforcement_state=MfaEnforcementState.LIVE_VERIFIED,
        ).values_list("device_name", flat=True))
        selected = [*live_ceos, *live_linux]
        if self.device not in selected:
            selected.append(self.device)
        destination = render_radius_clients.RUNTIME / "freeradius" / "clients.conf"
        before = destination.read_bytes() if destination.exists() else None
        text = render_radius_clients.render(selected)
        render_radius_clients.write_atomic(text, destination)
        del text
        validate = self.deps.runner(["docker", "exec", "human_mfa-human-mfa-radius-1", "freeradius", "-XC"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=False)
        restart = None
        if validate.returncode == 0:
            restart = self.deps.runner(["docker", "restart", "human_mfa-human-mfa-radius-1"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
        infrastructure_ok = False
        if validate.returncode == 0 and restart is not None and restart.returncode == 0:
            for _attempt in range(30):
                infrastructure_ok, _missing = ceos.mfa_infrastructure_healthy()
                if infrastructure_ok:
                    break
                time.sleep(1)
        ok = validate.returncode == 0 and restart is not None and restart.returncode == 0 and infrastructure_ok
        if not ok:
            if before is not None:
                render_radius_clients.write_atomic(before.decode(), destination)
            else:
                destination.unlink(missing_ok=True)
            self.deps.runner(["docker", "restart", "human_mfa-human-mfa-radius-1"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
            raise lm.LinuxMfaError("FreeRADIUS client staging failed and the prior protected file was restored.")
        with transaction.atomic():
            policy = DeviceLoginMfaPolicy.objects.select_for_update().get(device_name=self.device)
            policy.central_aaa_state = CentralAaaState.CONFIGURED
            policy.save()
        result = {"device": self.device, "PASS": True, "clients": selected + ["local_fixture"],
                  "protected_config_replaced": True,
                  "prior_config_present": before is not None,
                  "freeradius_config_valid": True, "freeradius_restarted": True,
                  "mfa_infrastructure_healthy": infrastructure_ok,
                  "ceos_regression_required_after": True}
        self._record("linux-radius-staged", ok=True, **result)
        return result

    def install_module(self) -> dict:
        before = self._container(["sha256sum", "/etc/pam.d/common-auth", "/etc/pam.d/sshd"])
        if before.returncode:
            raise lm.LinuxMfaError("Could not capture pre-install PAM hashes.")
        initial = self._dependency_state()
        missing_packages = []
        if not initial["pam_radius_installed"]:
            missing_packages.append("libpam-radius-auth")
        if not initial["sudo_package_installed"]:
            missing_packages.append("sudo")
        update = install = None
        if missing_packages:
            update = self._container(["apt-get", "update"], timeout=180)
            if update.returncode == 0:
                install = self._container(
                    ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", *missing_packages],
                    timeout=180,
                )
        after = self._container(["sha256sum", "/etc/pam.d/common-auth", "/etc/pam.d/sshd"])
        final = self._dependency_state()
        package_action_ok = not missing_packages or (
            update is not None and update.returncode == 0 and install is not None and install.returncode == 0
        )
        errors = self._dependency_errors(final)
        ok = package_action_ok and after.returncode == 0 and before.stdout == after.stdout and not errors
        result = {
            "device": self.device, "PASS": ok,
            "required_packages": ["libpam-radius-auth", "sudo"],
            "packages_requested": missing_packages,
            "package_install_invoked": bool(missing_packages),
            "apt_update_ok": None if update is None else update.returncode == 0,
            "package_install_ok": None if install is None else install.returncode == 0,
            "pam_files_unchanged": before.stdout == after.stdout,
            "dependency_state": final,
            "dependency_errors": errors,
        }
        self._record("linux-install-module", ok=ok, **result)
        if not ok:
            if errors:
                raise lm.LinuxMfaError(errors[0])
            raise lm.LinuxMfaError("Linux MFA dependency installation failed without modifying the PAM stack.")
        return result

    def backup(self) -> dict:
        self._require_passing_dependency_precheck()
        token = secrets.token_hex(12)
        data = lm.backup(self.transport, token)
        result = {"device": self.device, "PASS": True, "rollback_token": token,
                  "backup_root": data["root"], "files": data["files"]}
        self._record("linux-backup", ok=True, **result)
        return result

    def arm(self, token: str) -> dict:
        self._require_passing_dependency_precheck()
        backup = self.deps.evidence.latest("linux-backup", ok=True)
        if not backup or backup.get("rollback_token") != token:
            raise lm.LinuxMfaError("The rollback token has no matching successful backup evidence.")
        unit = lm.arm_timer(self.device, token, runner=self.deps.runner)
        ok = lm.timer_active(self.device, token, runner=self.deps.runner)
        result = {"device": self.device, "PASS": ok, "rollback_token": token, "unit": unit,
                  "deadline_seconds": lm.ROLLBACK_SECONDS}
        self._record("linux-timer-armed", ok=ok, **result)
        if not ok:
            raise lm.LinuxMfaError("Automatic rollback timer was not active after creation.")
        return result

    def activate(self, token: str) -> dict:
        armed = self.deps.evidence.latest("linux-timer-armed", ok=True)
        if not armed or armed.get("rollback_token") != token or not lm.timer_active(self.device, token, runner=self.deps.runner):
            raise lm.LinuxMfaError("A matching active rollback timer is required before activation.")
        dependency_errors = self._dependency_errors(self._dependency_state())
        if dependency_errors:
            raise lm.LinuxMfaError(dependency_errors[0])
        try:
            applied = lm.apply(self.transport, self.deps.provider)
        except lm.LinuxMfaActivationError as exc:
            self._record_activation_failure(token, exc)
            raise lm.LinuxMfaError(str(exc)) from None
        try:
            hashes = lm.config_hashes(self.transport)
        except lm.LinuxMfaError:
            exc = lm.LinuxMfaActivationError(
                stage="post_reload_configuration_inspection", return_code=None, exception_class="RuntimeError",
                stage_trace=applied.get("stage_trace"),
            )
            self._record_activation_failure(token, exc)
            raise lm.LinuxMfaError(str(exc)) from None
        ok = bool(applied.get("applied")) and hashes.get("sshd_valid") is True
        if not ok:
            exc = lm.LinuxMfaActivationError(
                stage="post_reload_configuration_inspection", return_code=None, exception_class="RuntimeError",
                stage_trace=applied.get("stage_trace"),
            )
            self._record_activation_failure(token, exc)
            raise lm.LinuxMfaError(str(exc))
        result = {"device": self.device, "PASS": ok, "rollback_token": token,
                  "sshd_valid": hashes.pop("sshd_valid"), "config_hashes": hashes,
                  "accounts_created": applied.get("users", []),
                  "activation_stage_trace": applied.get("stage_trace", [])}
        self._record("linux-activated", ok=ok, **result)
        return result

    def _record_activation_failure(self, token: str, exc: lm.LinuxMfaActivationError) -> dict:
        rollback_armed = lm.timer_active(self.device, token, runner=self.deps.runner)
        timer_evidence = self.deps.evidence.latest_entry("linux-timer-armed", ok=True)
        precheck_evidence = self.deps.evidence.latest_entry("linux-precheck", ok=True)
        result = {
            "device": self.device, "PASS": False, "rollback_token": token,
            "rollback_timer_armed": rollback_armed,
            "timer_evidence_id": timer_evidence[0] if timer_evidence else None,
            "precheck_evidence_id": precheck_evidence[0] if precheck_evidence else None,
            **exc.as_dict(),
        }
        self._record("linux-activation-failed", ok=False, **result)
        return result

    def verify_machine_recovery(self, token: str) -> dict:
        if not lm.timer_active(self.device, token, runner=self.deps.runner):
            raise lm.LinuxMfaError("Rollback timer is not active during verification.")
        machine = lm.ssh_key_login(self.target)
        try:
            password = self.deps.provider.current(self.target.breakglass_ref).value
            emergency = lm.ssh_password_login(self.target, self.target.breakglass_username, password, privileged=True)
        except SecretProviderError:
            raise lm.LinuxMfaError("Break-glass provider value is unavailable.") from None
        finally:
            password = ""
        try:
            root_row = DeviceCredential.objects.get(device_name=self.device, username="root")
            root_password = self.deps.provider.current(root_row.secret_ref).value
            legacy_root = lm.ssh_password_login(self.target, "root", root_password)
        except (DeviceCredential.DoesNotExist, SecretProviderError):
            raise lm.LinuxMfaError("Protected legacy-root rejection probe could not be prepared.") from None
        finally:
            root_password = ""
        legacy_ubuntu = lm.ssh_password_login(self.target, "ubuntu", secrets.token_urlsafe(24))
        recovery = self._container(["id", "-u"])
        root_ref = DeviceLoginMfaPolicy.objects.get(device_name=self.device)  # policy existence is also a gate
        ok = (machine.get("login") == "ACCEPT" and emergency.get("login") == "ACCEPT"
              and emergency.get("privileged") is True and legacy_root.get("login") == "REJECT"
              and legacy_ubuntu.get("login") == "REJECT"
              and recovery.returncode == 0 and _clean_output(recovery) == "0"
              and root_ref.automation_exempt)
        result = {"device": self.device, "PASS": ok, "rollback_token": token,
                  "automation_login": machine.get("login"), "automation_totp_required": False,
                  "breakglass_login": emergency.get("login"), "breakglass_privileged": emergency.get("privileged"),
                  "legacy_root_ssh": legacy_root.get("login"), "legacy_ubuntu_ssh": legacy_ubuntu.get("login"),
                  "docker_exec_privileged": recovery.returncode == 0 and _clean_output(recovery) == "0"}
        self._record("linux-machine-recovery", ok=ok, **result)
        return result

    def verify_operational(self, token: str) -> dict:
        if not lm.timer_active(self.device, token, runner=self.deps.runner):
            raise lm.LinuxMfaError("Rollback timer is not active during verification.")
        baseline = self.deps.evidence.latest("linux-precheck", ok=True)
        if not baseline:
            raise lm.LinuxMfaError("A passing pre-change operational baseline is required.")
        reads = self._reads(); current = self._operational_snapshot()
        baseline_operations = baseline["operational_baseline"]
        stable_neighbors_unchanged = current["ospf_neighbors"] == baseline_operations["ospf_neighbors"]
        unchanged = (current["digests"] == baseline_operations["digests"]
                     and stable_neighbors_unchanged and current["ospf_healthy"] and not current["errors"])
        ok = all((reads["health"], reads["nsot"], reads["config_retrieval"], unchanged,
                  reads["identity"] == lm.SERVICE_USERNAME))
        result = {"device": self.device, "PASS": ok, "rollback_token": token, "reads": reads,
                  "network_state_unchanged": unchanged,
                  "ospf_semantic_state_unchanged": stable_neighbors_unchanged,
                  "ospf_adjacencies_healthy": current["ospf_healthy"], "operational_after": current}
        self._record("linux-operational", ok=ok, **result)
        return result

    def verify_human(self, token: str, factor_reader) -> dict:
        if not lm.timer_active(self.device, token, runner=self.deps.runner):
            raise lm.LinuxMfaError("Rollback timer is not active during human verification.")
        token_before = self.deps.privacyidea.token(ceos.HUMAN_TOKEN_SERIAL)
        audit_before = int(self.deps.privacyidea.audit(lm.HUMAN_USERNAME)["max_id"])
        password, otp = factor_reader()
        if not password or len(otp) != 6 or not otp.isdigit():
            password = otp = ""
            raise lm.LinuxMfaError("Human factors were not supplied in the required protected format.")
        wrong = otp[:-1] + str((int(otp[-1]) + 1) % 10)
        password_only = lm.ssh_keyboard_login(self.target, password)
        wrong_totp = lm.ssh_keyboard_login(self.target, password + wrong)
        accepted = lm.ssh_keyboard_login(self.target, password + otp)
        audit_after = self.deps.privacyidea.audit(lm.HUMAN_USERNAME, after_id=audit_before)
        audit_rows = audit_after.get("rows") or []
        backend_success = any(row.get("success") and row.get("serial") == ceos.HUMAN_TOKEN_SERIAL
                              and "nmas-human-password-totp" in str(row.get("policies", "")) for row in audit_rows)
        backend_reject = any(not row.get("success") for row in audit_rows)
        token_ok = (token_before.get("serial") == ceos.HUMAN_TOKEN_SERIAL
                    and token_before.get("owner") == lm.HUMAN_USERNAME and token_before.get("active") is True
                    and not token_before.get("locked") and not token_before.get("revoked")
                    and int(token_before.get("failcount", 0)) <= 7)
        ok = (password_only.get("login") == "REJECT" and wrong_totp.get("login") == "REJECT"
              and accepted.get("login") == "ACCEPT" and accepted.get("privileged") is True
              and token_ok and backend_success and backend_reject)
        result = {"device": self.device, "PASS": ok, "rollback_token": token,
                  "password_only": password_only.get("login"), "incorrect_totp": wrong_totp.get("login"),
                  "password_plus_totp": accepted.get("login"), "human_privileged": accepted.get("privileged"),
                  "privacyidea_token_ok": token_ok, "privacyidea_success_audited": backend_success,
                  "privacyidea_rejection_audited": backend_reject,
                  "privacyidea_audit_ids": [row.get("id") for row in audit_rows]}
        self._record("linux-human", ok=ok, extra_secrets=(password, otp, wrong, password + otp, password + wrong), **result)
        password = otp = wrong = ""
        return result

    def finalize(self, token: str) -> dict:
        required = ("linux-activated", "linux-machine-recovery", "linux-operational", "linux-human")
        evidence = {step: self.deps.evidence.latest_entry(step, ok=True) for step in required}
        if any(value is None or value[1].get("rollback_token") != token for value in evidence.values()):
            raise lm.LinuxMfaError("All passing verification evidence from this rollback window is required.")
        timer_was_active = lm.timer_active(self.device, token, runner=self.deps.runner)
        hashes = lm.config_hashes(self.transport)
        if not hashes.pop("sshd_valid") or not all(item["exists"] for item in hashes.values()):
            raise lm.LinuxMfaError("Final configuration integrity check failed; leave rollback armed.")
        activated_hashes = evidence["linux-activated"][1].get("config_hashes") or {}
        if hashes != activated_hashes:
            raise lm.LinuxMfaError("Final configuration differs from the verified activation; do not mark it successful.")
        ready = self.deps.evidence.latest("linux-finalize-ready", ok=True)
        if timer_was_active:
            self._record("linux-finalize-ready", ok=True, rollback_token=token, configuration_hashes=hashes)
            lm.cancel_timer(self.device, token, runner=self.deps.runner)
            if lm.timer_active(self.device, token, runner=self.deps.runner):
                raise lm.LinuxMfaError("Rollback timer remains active after cancellation.")
        elif not ready or ready.get("rollback_token") != token or ready.get("configuration_hashes") != hashes:
            raise lm.LinuxMfaError("Inactive timer has no matching finalize-ready evidence; inspect rollback state.")
        with transaction.atomic():
            policy = DeviceLoginMfaPolicy.objects.select_for_update().get(device_name=self.device)
            policy.central_aaa_state = CentralAaaState.VERIFIED
            policy.enforcement_state = MfaEnforcementState.LIVE_VERIFIED
            policy.last_verified_at = timezone.now()
            policy.last_verification_result = f"linux-human PASS evidence#{evidence['linux-human'][0]}"[:64]
            policy.save()
        result = {"device": self.device, "PASS": True, "rollback_token": token,
                  "rollback_canceled": True, "reconciled_after_cancel": not timer_was_active,
                  "configuration_hashes": hashes,
                  "evidence_ids": {step: value[0] for step, value in evidence.items()},
                  "policy": {"central_aaa_state": policy.central_aaa_state,
                             "enforcement_state": policy.enforcement_state,
                             "last_verified_at": policy.last_verified_at.isoformat()}}
        final = self._record("linux-finalized", ok=True, **result)
        entry = self.deps.evidence.latest_entry("linux-finalized", ok=True)
        result["final_evidence_id"] = entry[0] if entry else None
        return result

    def status(self) -> dict:
        policy = DeviceLoginMfaPolicy.objects.get(device_name=self.device)
        hashes = lm.config_hashes(self.transport)
        latest = self.deps.evidence.latest("linux-finalized", ok=True)
        return {"device": self.device, "configuration": hashes,
                "policy": {"central_aaa_state": policy.central_aaa_state,
                           "enforcement_state": policy.enforcement_state,
                           "last_verified_at": policy.last_verified_at.isoformat() if policy.last_verified_at else None,
                           "last_verification_result": policy.last_verification_result},
                "finalized": latest}
