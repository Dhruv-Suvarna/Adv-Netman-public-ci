"""The deterministic static safety gate for Raw Configlet text.

Defence in depth BEFORE any sandbox: a denylist is NOT a complete security parser and is not presented as one.  The real
boundaries are (1) the isolated sandbox for verification, (2) the Phase-17 engine for execution, and (3) the fact that
nothing here is ever handed to a host shell.  The gate runs at save time (a failing revision is never persisted, so a secret
never reaches the table) and again at verification time (the policy may have tightened, and a database row may have been
edited by hand).

Findings are structured and carry stable codes.  They carry line numbers, pattern NAMES and command words only -- never the
matched text -- so a finding can never itself leak the secret it found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..ci import redact as ci_redact
from . import codes, text as text_module
from .codes import finding

# --- command-word denylists (matched against the FIRST token of a statement, after an optional leading ``no``) -------------
HOST_SHELL_COMMANDS = frozenset({
    "bash", "sh", "zsh", "csh", "ksh", "dash", "python", "python2", "python3", "perl", "ruby", "node", "lua", "sudo", "su",
    "docker", "podman", "kubectl", "ssh", "telnet", "scp", "sftp", "ftp", "tftp", "curl", "wget", "nc", "ncat", "netcat", "socat",
    "chmod", "chown", "rm", "mv", "cp", "dd", "kill", "pkill", "killall", "systemctl", "service", "mount", "umount", "eval", "exec",
    "source", "env", "export", "cat", "echo", "tee", "sed", "awk", "xargs", "nohup", "crontab", "at",
})
MODE_CONTROL_COMMANDS = frozenset({
    "exit", "end", "quit", "abort", "commit", "configure", "conf", "logout", "exit-config", "top",
})
# ``enable`` / ``disable`` are mode control only when they stand ALONE (``enable password ...`` is a configuration command,
# handled -- as a secret -- by the secret rules instead)
MODE_CONTROL_WHEN_ALONE = frozenset({"enable", "disable"})
EXEC_MODE_COMMANDS = frozenset({
    "show", "clear", "debug", "undebug", "reload", "reboot", "reset", "erase", "write", "wr", "copy", "delete", "format", "install",
    "upgrade", "terminal", "ping", "ping6", "traceroute", "traceroute6", "dir", "more", "pwd", "cd", "mkdir", "rmdir", "do", "boot",
    "tcpdump", "watch", "run", "start-shell",
})
HOST_EXECUTION_CONSTRUCTS = frozenset({"event-handler", "daemon", "schedule", "alias", "trigger"})
UNSUPPORTED_CONTEXTS = frozenset({"banner"})
FREE_TEXT_COMMANDS = frozenset({"description", "remark", "comment", "label"})
SNMP_COMMUNITY_COMMANDS = frozenset({"snmp-server", "snmp", "snmp-agent", "rocommunity", "rwcommunity"})

_PROMPT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}(\([A-Za-z0-9_.-]+\))?[#>](\s|$)")
_METACHAR_RE = re.compile(r"(`|\$\(|\$\{|&&|\|\||;)")
_ACTION_SHELL_RE = re.compile(r"(?i)\baction\s+(?:\d+\s+)?(?:bash|lambda|python)\b")
_SNMPV3_KEY_RE = re.compile(r"(?i)\b(?:auth\s+(?:md5|sha|sha256|sha384|sha512)|priv\s+(?:des|3des|aes|aes192|aes256))\s+\S+")
# whole-token keywords whose FOLLOWING token is a credential value (BGP ``send-community`` / ``set community`` are NOT matched:
# the token must equal the keyword exactly, and ``community`` only counts on SNMP commands)
_SECRET_TOKENS = frozenset({
    "password", "passwd", "secret", "token", "webhook", "credential", "credentials", "apikey", "api-key", "api_key", "private-key",
    "private_key", "priv-key", "priv_key", "auth-key", "auth_key", "authentication-key", "message-digest-key", "key-string",
    "pre-shared-key",
})


@dataclass
class GateResult:
    normalized: str | None = None
    findings: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.normalized is not None and not any(f["blocking"] for f in self.findings)

    @property
    def codes(self) -> list[str]:
        return sorted({f["code"] for f in self.findings})


def _first_token(line: str) -> str:
    tokens = line.split()
    if not tokens:
        return ""
    if tokens[0].lower() == "no" and len(tokens) > 1:
        return tokens[1].lower()
    return tokens[0].lower()


def secret_patterns(line: str) -> list[str]:
    """Names of every secret-shaped construct in one statement (NEVER the matched text)."""
    tokens = [t.lower() for t in line.split()]
    if not tokens or _first_token(line) in FREE_TEXT_COMMANDS:
        return []
    names = list(ci_redact.scan_line(line))
    snmp = _first_token(line) in SNMP_COMMUNITY_COMMANDS
    for token in tokens[:-1]:  # a keyword is only secret-shaped when a VALUE follows it
        if token in _SECRET_TOKENS or (token == "community" and snmp):
            names.append(f"KEYWORD:{token}")
    if _SNMPV3_KEY_RE.search(line):
        names.append("SNMPV3_KEY_MATERIAL")
    return sorted(set(names))


def evaluate(text: object) -> GateResult:
    """Run the whole static gate over submitted text.  ``result.normalized`` is set only when the text is structurally valid."""
    result = GateResult()
    add = result.findings.append
    if not isinstance(text, str):
        add(finding("RAW_INVALID_ENCODING"))
        return result
    if "\x00" in text:
        add(finding("RAW_NUL_BYTE"))
        return result
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        add(finding("RAW_INVALID_ENCODING"))
        return result

    normalized = text_module.normalize(text)
    if not normalized.strip():
        add(finding("RAW_EMPTY"))
        return result

    lines = normalized.splitlines()
    size = len(normalized.encode("utf-8"))
    if size > codes.MAX_BYTES:
        add(finding("RAW_TOO_LARGE", f"The configuration is {size} bytes; the maximum is {codes.MAX_BYTES}.", bytes=size, limit=codes.MAX_BYTES))
        return result
    if len(lines) > codes.MAX_LINES:
        add(finding("RAW_TOO_MANY_LINES", f"The configuration has {len(lines)} lines; the maximum is {codes.MAX_LINES}.", lines=len(lines), limit=codes.MAX_LINES))
        return result

    structural = False
    for number, line in enumerate(lines, start=1):
        if len(line) > codes.MAX_LINE_LENGTH:
            add(finding("RAW_LINE_TOO_LONG", line=number, length=len(line), limit=codes.MAX_LINE_LENGTH))
            structural = True
        for char in line:
            code = ord(char)
            if code < 0x20 or code == 0x7F:
                add(finding("RAW_CONTROL_CHARACTER", line=number, codepoint=code))
                structural = True
                break
            if code > 0x7E:
                add(finding("RAW_NON_ASCII_CHARACTER", line=number))
                structural = True
                break
    if structural:
        return result

    result.normalized = normalized
    for number, line in enumerate(lines, start=1):
        statement = line.strip()
        if not statement or statement.startswith(("!", "#")):
            continue  # full-line comments / documentation are never scanned (no naive false positives)
        first = _first_token(statement)
        if _PROMPT_RE.match(statement):
            add(finding("RAW_PROMPT_TRANSCRIPT", line=number))
            continue
        if first in FREE_TEXT_COMMANDS:
            continue  # free text: not scanned for shell metacharacters or secret keywords
        if first in MODE_CONTROL_COMMANDS or (first in MODE_CONTROL_WHEN_ALONE and len(statement.split()) <= (2 if statement.lower().startswith("no ") else 1)):
            add(finding("RAW_MODE_CONTROL_COMMAND", line=number, command=first))
        elif first in HOST_SHELL_COMMANDS:
            add(finding("RAW_HOST_SHELL_COMMAND", line=number, command=first))
        elif first in EXEC_MODE_COMMANDS:
            add(finding("RAW_EXEC_MODE_COMMAND", line=number, command=first))
        elif first in HOST_EXECUTION_CONSTRUCTS or _ACTION_SHELL_RE.search(statement):
            add(finding("RAW_HOST_EXECUTION_CONSTRUCT", line=number, command=first))
        elif first in UNSUPPORTED_CONTEXTS:
            add(finding("RAW_UNSUPPORTED_CONTEXT", line=number, command=first))
        if _METACHAR_RE.search(statement):
            add(finding("RAW_SHELL_METACHARACTER", line=number))
        patterns = secret_patterns(statement)
        if patterns:
            add(finding("RAW_SECRET_SHAPED_CONTENT", line=number, patterns=patterns))
    result.findings = codes.bounded_findings(result.findings)
    return result
