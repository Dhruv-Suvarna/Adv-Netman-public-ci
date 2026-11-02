"""Per-platform verifier adapters.  Each one proves ONLY that the platform's own parser accepts the statements (syntax).

* ``ubuntu_frr``   ``frr_vtysh_dryrun``   ``vtysh -C -f /dev/stdin`` in an UNPRIVILEGED, network-less, read-only, capability-less,
                                         non-root one-shot container built from the FRR version R3/R4 run.  No daemon runs.
* ``arista_ceos``  ``ceos_config_session`` a DISPOSABLE cEOS (the local ``ceos:4.36.2F`` image) parses the statements inside a
                                         ``configure session`` that is always ABORTED, so nothing is ever committed.  cEOS can only
                                         start with ``--privileged``; the backend is therefore DISABLED unless a server setting opts in.

Neither adapter contacts a managed lab device, receives a credential, an environment variable or a mount, or claims semantic
correctness.  A sandbox failure of ANY kind (missing image, runtime down, timeout, unparseable output, failed cleanup) is an
INCOMPLETE finding, never a PASS.  Adapters return structured findings; they never persist anything.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from . import sandbox, text as text_module
from .codes import finding

ADAPTER_VERSION = "1.0.0"
MAX_REJECTION_FINDINGS = 12


@dataclass
class AdapterOutcome:
    findings: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    sandbox: dict = field(default_factory=dict)
    started: bool = False

    def add(self, code: str, message: str = "", **kwargs) -> None:
        self.findings.append(finding(code, message, **kwargs))


class PlatformVerifier:
    adapter_id = ""
    adapter_version = ADAPTER_VERSION
    platform = ""
    short = ""
    requires_privileged = False

    def backend(self, config: sandbox.SandboxConfig) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, normalized: str, *, config, runner, clock, sleep) -> AdapterOutcome:  # pragma: no cover - interface
        raise NotImplementedError

    # -- shared lifecycle -------------------------------------------------------------------------------------------------
    def _finish(self, out: AdapterOutcome, box: sandbox.Sandbox) -> None:
        """ALWAYS runs (success, failure, timeout, exception).  A leftover sandbox is never turned into a PASS."""
        if not out.started:
            out.sandbox["cleanup"] = "NOT_NEEDED"
            return
        try:
            cleaned = box.remove()
        except Exception:  # noqa: BLE001 - cleanup must never raise past the verifier
            cleaned = False
        out.sandbox["cleanup"] = "OK" if cleaned else "FAILED"
        if not cleaned:
            out.add("SANDBOX_CLEANUP_FAILED")

    @staticmethod
    def _process_problem(result, out: AdapterOutcome) -> bool:
        """Record a runtime / timeout problem.  True when the process did not produce usable output."""
        if result.error == "DOCKER_UNAVAILABLE":
            out.add("SANDBOX_UNAVAILABLE")
        elif result.error:
            out.add("SANDBOX_START_FAILED")
        elif result.timed_out:
            out.add("SANDBOX_TIMEOUT")
        else:
            return False
        return True


# --- FRR --------------------------------------------------------------------------------------------------------------------
_FRR_LINE = re.compile(r"^line (\d+): % (.*)$")


class FrrVtyshDryRun(PlatformVerifier):
    adapter_id, platform, short = "frr_vtysh_dryrun", "ubuntu_frr", "frr"

    def backend(self, config) -> str:
        return f"docker:{config.frr_image}"

    def verify(self, normalized, *, config, runner, clock=time.monotonic, sleep=time.sleep) -> AdapterOutcome:
        out = AdapterOutcome()
        box = sandbox.Sandbox(self.short, config, runner)
        out.sandbox = {"backend": self.backend(config), "container": box.name, "privileged": False, "network": "none",
                       "limits": dict(zip(("memory", "cpus", "pids"), sandbox.FRR_LIMITS))}
        try:
            image = box.image_state(config.frr_image)
            if image != "OK":
                out.add("SANDBOX_IMAGE_MISSING" if image == "MISSING" else "SANDBOX_UNAVAILABLE")
                return out
            items = text_module.statements(normalized)
            payload = ("\n".join(statement for _, statement in items) + "\n").encode("ascii")
            argv = sandbox.oneshot_argv(box.name, config.frr_image, "vtysh", ["-C", "-f", "/dev/stdin"], sandbox.FRR_LIMITS)
            out.started = True
            result = runner(argv, stdin=payload, timeout=config.timeout)
            self._interpret(result, items, out)
        except Exception:  # noqa: BLE001 - a verifier defect is INCOMPLETE, never PASS
            out.add("VERIFIER_INTERNAL_ERROR")
        finally:
            self._finish(out, box)
        return out

    def _interpret(self, result, items, out: AdapterOutcome) -> None:
        if self._process_problem(result, out):
            return
        if result.truncated:
            out.add("SANDBOX_OUTPUT_TRUNCATED")
        out.evidence = {"exit_code": result.returncode, "statements": len(items), "output": sandbox.sanitize_output(result.output)}
        rejected, warned, unparsed = [], [], []
        for line in result.output.splitlines():
            if not line.strip() or "vtysh.conf" in line:  # the known benign notice about the (absent) integrated config file
                continue
            match = _FRR_LINE.match(line.strip())
            if match:
                number, message = int(match.group(1)), match.group(2)
                (warned if message.lower().startswith("warning") else rejected).append((number, message))
            elif line.strip().startswith("%"):
                unparsed.append(line)
        for number, message in rejected[:MAX_REJECTION_FINDINGS]:
            source = items[number - 1][0] if 1 <= number <= len(items) else None
            out.add("SYNTAX_REJECTED", line=source, reason=sandbox.sanitize_line(message))
        for number, message in warned[:MAX_REJECTION_FINDINGS]:
            out.add("PLATFORM_WARNING", line=items[number - 1][0] if 1 <= number <= len(items) else None, reason=sandbox.sanitize_line(message))
        if rejected or unparsed:
            if unparsed and not rejected:
                out.add("SYNTAX_REJECTED", reason=sandbox.sanitize_line(unparsed[0]))
            return
        if result.returncode != 0:
            out.add("VERIFIER_OUTPUT_UNPARSEABLE", exit_code=result.returncode)
            return
        out.add("SYNTAX_ACCEPTED")
        out.add("SEMANTICS_NOT_VERIFIED")


# --- cEOS -------------------------------------------------------------------------------------------------------------------
_EOS_LINE = re.compile(r"at line (\d+)")


class CeosConfigSession(PlatformVerifier):
    adapter_id, platform, short, requires_privileged = "ceos_config_session", "arista_ceos", "ceos", True
    SENTINEL_COMMAND = "show version | include Architecture"
    SENTINEL = "Architecture"
    SESSION = "rawverify"

    def backend(self, config) -> str:
        return f"docker:{config.ceos_image}"

    def verify(self, normalized, *, config, runner, clock=time.monotonic, sleep=time.sleep) -> AdapterOutcome:
        out = AdapterOutcome()
        box = sandbox.Sandbox(self.short, config, runner)
        out.sandbox = {"backend": self.backend(config), "container": box.name, "privileged": True, "network": "none",
                       "limits": dict(zip(("memory", "cpus", "pids"), sandbox.CEOS_LIMITS)),
                       "note": "cEOS requires --privileged; reduced isolation, enabled by explicit server policy"}
        if not config.allow_privileged:  # no runtime call at all: nothing was started
            out.add("SANDBOX_DISABLED")
            return out
        try:
            image = box.image_state(config.ceos_image)
            if image != "OK":
                out.add("SANDBOX_IMAGE_MISSING" if image == "MISSING" else "SANDBOX_UNAVAILABLE")
                return out
            items = text_module.statements(normalized)
            stream = text_module.ceos_command_stream([statement for _, statement in items])
            sources = text_module.stream_sources(items, stream)
            out.started = True
            started = runner(sandbox.detached_argv(box.name, config.ceos_image, sandbox.CEOS_INIT_COMMAND, sandbox.CEOS_LIMITS, privileged=True),
                             timeout=config.cleanup_timeout)
            if self._process_problem(started, out):
                return out
            if started.returncode != 0:
                out.add("SANDBOX_START_FAILED")
                return out
            if not self._wait_ready(box, config, runner, clock, sleep, out):
                return out
            script = [f"configure session {self.SESSION}", *stream, "abort", self.SENTINEL_COMMAND]
            result = runner(sandbox.exec_argv(box.name, ["FastCli", "-p", "15"], interactive=True),
                            stdin=("\n".join(script) + "\n").encode("ascii"), timeout=config.timeout)
            self._interpret(result, sources, len(stream), out)
        except Exception:  # noqa: BLE001 - a verifier defect is INCOMPLETE, never PASS
            out.add("VERIFIER_INTERNAL_ERROR")
        finally:
            self._finish(out, box)
        return out

    def _wait_ready(self, box, config, runner, clock, sleep, out: AdapterOutcome) -> bool:
        deadline = clock() + config.boot_timeout
        probe = sandbox.exec_argv(box.name, ["FastCli", "-p", "15", "-c", self.SENTINEL_COMMAND])
        while True:
            result = runner(probe, timeout=15)
            if result.error == "DOCKER_UNAVAILABLE":
                out.add("SANDBOX_UNAVAILABLE")
                return False
            if result.returncode == 0 and self.SENTINEL in result.output:
                return True
            if "is not running" in result.output or "No such container" in result.output:
                out.add("SANDBOX_START_FAILED")
                return False
            if clock() >= deadline:
                out.add("SANDBOX_TIMEOUT", message="The cEOS sandbox did not become ready in time.")
                return False
            sleep(3)

    def _interpret(self, result, sources: list[int], stream_len: int, out: AdapterOutcome) -> None:
        if self._process_problem(result, out):
            return
        if result.truncated:
            out.add("SANDBOX_OUTPUT_TRUNCATED")
        out.evidence = {"exit_code": result.returncode, "commands": stream_len, "output": sandbox.sanitize_output(result.output)}
        if self.SENTINEL not in result.output:  # positive evidence that the CLI ran the whole script
            out.add("VERIFIER_OUTPUT_UNPARSEABLE", message="The cEOS CLI did not run the whole verification script.")
            return
        rejected, warned = [], []
        for raw in result.output.splitlines():
            line = raw.strip()
            if not line.startswith("%"):
                continue
            match = _EOS_LINE.search(line)
            script_line = int(match.group(1)) if match else None
            index = script_line - 2 if script_line is not None else None  # script line 1 is `configure session`
            if script_line is not None and (script_line < 2 or index >= stream_len):  # an error in OUR preamble / postamble
                out.add("VERIFIER_OUTPUT_UNPARSEABLE", message="The cEOS CLI rejected a verifier control command.")
                return
            source = sources[index] if index is not None and 0 <= index < len(sources) else None
            (warned if line.lower().startswith("% warning") else rejected).append((source or None, line))
        for source, line in rejected[:MAX_REJECTION_FINDINGS]:
            out.add("SYNTAX_REJECTED", line=source, reason=sandbox.sanitize_line(line))
        for source, line in warned[:MAX_REJECTION_FINDINGS]:
            out.add("PLATFORM_WARNING", line=source, reason=sandbox.sanitize_line(line))
        if rejected:
            return
        out.add("SYNTAX_ACCEPTED")
        out.add("SEMANTICS_NOT_VERIFIED")


REGISTRY = {adapter.adapter_id: adapter for adapter in (FrrVtyshDryRun(), CeosConfigSession())}


def adapter_for(adapter_id: str) -> PlatformVerifier | None:
    return REGISTRY.get(adapter_id)
