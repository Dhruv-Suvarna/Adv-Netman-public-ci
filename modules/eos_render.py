"""Shared, dependency-light Jinja/EOS-command rendering helpers.

Extracted from `master.py` (Phase 3C) so a lightweight, NetBox-only script
(`netbox/scripts/render_r2_dhcp.py`) can reuse the exact same
indentation-to-command-list flattening `master.py`'s real device-push path
uses, without importing `master.py` itself -- `master.py` unconditionally
imports the full monitoring stack (netmiko, paramiko, every `modules.*`
infrastructure module) at module load time, which a render-only validation
script has no business depending on. `master.py` now imports `render()`/
`eos_commands()` from here instead of defining them locally; this is a
pure extraction, not a behavior change (see monitoring/tests/test_eos_render.py
for a regression test against the exact same commands `master.py` produced
before this refactor).

Nothing in this module ever connects to a device, NetBox, or the network --
it is pure text transformation.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

BASE = Path(__file__).resolve().parents[1]

#: Command prefixes that open an EOS configuration sub-mode, keyed off the
#: exact CLI grammar this repository's templates use. "dhcp server",
#: "subnet ", and "range " (Phase 3C) were added for
#: `templates/R2_dhcp_server.cfg.j2` -- see docs/NETBOX_IPAM.md "Phase 3C"
#: for the live-image evidence (`CliPlugin/DhcpServerCli.py`'s
#: `EnterDhcpServerVrfMode`/`EnterDhcpServerSubnetMode`/
#: `EnterDhcpServerV4RangeMode`/`EnterDhcpServerV6RangeMode` syntax
#: classes -- `range START END` is registered as a MODE-ENTERING command
#: under `subnet` mode, not a leaf, confirmed by which class NetBox's own
#: `DhcpServerSubnetV4Mode.addCommandClass(...)` actually registers) that
#: all three truly open EOS config sub-modes, exactly like
#: `interface `/`vlan `/`router ` already did. Adding these prefixes
#: changes nothing for any existing template: none of them contain a
#: "dhcp server"/"subnet "/"range " line today.
MODE_STARTS = (
    "interface ", "vlan ", "router ", "ipv6 router ", "route-map ",
    "nexthop-group ", "ip decap-group ", "ipv6 prefix-list ", "ip prefix-list ",
    "address-family ", "dhcp server", "subnet ", "range ",
)

#: "dhcp server ipv4"/"dhcp server ipv6" (`InterfaceEnterDhcpServerEnable`)
#: are per-INTERFACE leaf commands, not the global "dhcp server [VRFNAME]"
#: mode-entry command (`EnterDhcpServerVrfMode`) -- but both share the
#: "dhcp server" prefix, so a plain `startswith(MODE_STARTS)` check would
#: incorrectly treat the interface leaf command as opening a phantom nested
#: mode too. Excluded here by exact match rather than making "dhcp server"
#: a longer, still-ambiguous prefix (the global command also legitimately
#: takes an optional VRF name, e.g. "dhcp server MGMT").
_DHCP_SERVER_INTERFACE_LEAVES = ("dhcp server ipv4", "dhcp server ipv6")


def render(name: str, context: dict, base: Path | None = None) -> str:
    """Render a repository-relative Jinja2 template path (e.g.
    "templates/R1.cfg.j2") with StrictUndefined -- identical semantics to
    `master.py`'s original `render()`."""
    env = Environment(
        loader=FileSystemLoader(str(base or BASE)), undefined=StrictUndefined,
        trim_blocks=True, lstrip_blocks=True,
    )
    return env.get_template(name).render(**context)


def eos_commands(text: str) -> list[str]:
    """Flatten indented EOS config text into a flat command list with
    explicit `exit`s, using indentation to infer nesting -- identical
    logic to `master.py`'s original `eos_commands()`, with `MODE_STARTS`
    (above) as the only change (Phase 3C's two new prefixes)."""
    commands, stack = [], []
    rows = []
    for raw in text.splitlines():
        cmd = raw.strip()
        if not cmd or cmd == "!" or cmd in {"configure", "configure terminal", "end"}:
            continue
        rows.append((len(raw) - len(raw.lstrip()), cmd))
    for indent, cmd in rows:
        while stack and indent <= stack[-1]:
            commands.append("exit")
            stack.pop()
        commands.append(cmd)
        if cmd.startswith(MODE_STARTS) and cmd not in _DHCP_SERVER_INTERFACE_LEAVES:
            stack.append(indent)
    commands.extend("exit" for _ in stack)
    return commands
