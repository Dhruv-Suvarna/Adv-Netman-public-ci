#!/usr/bin/env python3
"""Phase 3C/3D: render-only R2 secondary-DHCP-server candidate configuration.

Phase 3D integrated the DHCP fragment into the real push path
(`templates/R2.cfg.j2` + `master.py`'s `push_eos()`/`_build_eos_config()`)
-- this script now renders exactly that SAME integrated template, with the
SAME context-building/validation calls `master.py` uses
(`modules.ipam_context.build_and_validate_r2_dhcp_context()`/
`validate_r2_candidate_render()`), so what this prints is a genuine
preview of what `master.py` would push, not a separate parallel artifact.
It additionally validates the standalone DHCP fragment's own nested
grammar (Step 11) and reports the semantic delta against R2's config
rendered WITHOUT a `dhcp` context, to prove the change is DHCP-only.

This script NEVER connects to R2 (or any device), NEVER pushes
configuration, and NEVER restarts anything -- see docs/NETBOX_IPAM.md
"Phase 3C"/"Phase 3D" for the full capability evidence, the live
configuration-session dry-run proof, and remaining activation
prerequisites.

Usage:
    python3 netbox/scripts/render_r2_dhcp.py [-v] [--write]

Exit codes:
    0  candidate rendered and passed every safety/structure check
    1  NetBox itself was not ready, or the DHCP context/render failed a
       fail-closed check (unreachable, incomplete pools, pool-safety
       problem, missing DHCP section, or Vlan200 static address lost)
    3  the standalone DHCP fragment or the semantic delta failed
       structural validation
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE))

from modules import ipam_context as ic  # noqa: E402
from modules import netbox_ipam as nb  # noqa: E402
from modules.eos_render import eos_commands, render  # noqa: E402

FRAGMENT_TEMPLATE = "templates/R2_dhcp_server.cfg.j2"
FULL_TEMPLATE = "templates/R2.cfg.j2"
OUT_DIR = BASE / "netbox" / "runtime" / "r2_dhcp"
INVENTORY_PATH = BASE / "inventory.yml"


def _base_render_context(node: str = "R2") -> dict:
    inventory = yaml.safe_load(INVENTORY_PATH.read_text())
    return {"management": inventory["management"], "node": node}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--write", action="store_true", help=f"Also write the full candidate under {OUT_DIR}")
    args = parser.parse_args(argv)

    try:
        ic.validate_netbox_ready()
        client = nb.build_client()
        dhcp_context = ic.build_and_validate_r2_dhcp_context(client)
    except nb.NetboxError as exc:
        print(f"FAIL: NetBox/DHCP-context pre-push gate failed: {exc}", file=sys.stderr)
        return 1
    print(f"Pool safety + context build: PASS ({len(dhcp_context['ipv4_subnets']) + len(dhcp_context['ipv6_subnets'])} secondary pools)")

    if args.verbose:
        print("\nSecondary (R2) pools:")
        for pool in dhcp_context["ipv4_subnets"] + dhcp_context["ipv6_subnets"]:
            print(f"  VLAN{pool.vlan} IPv{pool.family}: {pool.prefix} range {pool.start}-{pool.end} "
                  f"gateway={pool.gateway or '-'} relay_targets={list(pool.relay_targets)}")

    base_context = _base_render_context()

    # The SAME integrated template/context master.py's _build_eos_config()
    # uses for a real R2 push -- this is the "COMPLETE R2 config" proof
    # (Step 6), not a separate standalone artifact.
    integrated_candidate = render(FULL_TEMPLATE, {**base_context, "dhcp": dhcp_context}, base=BASE)
    try:
        ic.validate_r2_candidate_render(integrated_candidate, client)
    except nb.NetboxError as exc:
        print(f"FAIL: integrated R2 candidate failed post-render validation: {exc}", file=sys.stderr)
        return 1
    print("Integrated candidate: PASS (DHCP section present, Vlan200 static IPv4/IPv6 preserved)")

    # Semantic delta (Step 5/9): R2 rendered WITHOUT a dhcp context (the
    # exact text/commands produced for every other device today, and for
    # R2 itself before this phase) vs. WITH one -- the delta must be
    # DHCP-only.
    base_candidate = render(FULL_TEMPLATE, base_context, base=BASE)
    base_commands = eos_commands(base_candidate)
    integrated_commands = eos_commands(integrated_candidate)
    delta = ic.dhcp_render_delta(base_commands, integrated_commands)
    delta_problems = _validate_delta_is_dhcp_only(delta)
    if delta_problems:
        print("FAIL: semantic delta includes non-DHCP change(s):", file=sys.stderr)
        for problem in delta_problems:
            print(f"  - {problem}", file=sys.stderr)
        return 3
    print(f"Semantic delta: PASS (DHCP-only -- {len(delta['added'])} line(s) added, {len(delta['removed'])} removed)")
    if args.verbose:
        print("  added:")
        for line in delta["added"]:
            print(f"    + {line}")
        if delta["removed"]:
            print("  removed:")
            for line in delta["removed"]:
                print(f"    - {line}")

    # The standalone fragment's own nested-grammar check (Step 11) --
    # narrower and more precise than trying to validate the entire
    # multi-protocol R2.cfg.j2 against one small grammar table.
    fragment_candidate = render(FRAGMENT_TEMPLATE, {"dhcp": dhcp_context}, base=BASE)
    nesting_problems = _validate_nesting(fragment_candidate)
    if nesting_problems:
        print("FAIL: DHCP fragment failed EOS nested-grammar validation:", file=sys.stderr)
        for problem in nesting_problems:
            print(f"  - {problem}", file=sys.stderr)
        return 3
    print("DHCP fragment structure: PASS (correctly nested per the transcribed grammar)")

    print("\n--- integrated templates/R2.cfg.j2 candidate render (what master.py would push) ---\n")
    print(integrated_candidate)

    if args.write:
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        out_path = OUT_DIR / "R2.cfg"
        out_path.write_text(integrated_candidate)
        print(f"\nWritten to {out_path} (never applied to any device).")

    print("\nOverall: PASS -- candidate only. Nothing was pushed to R2 or any other device.")
    return 0


#: A small, explicit nested-command grammar transcribed read-only from the
#: live cEOS 4.36.2F image's CliPlugin/DhcpServerCli.py (see
#: docs/NETBOX_IPAM.md "Phase 3C" for the exact evidence/class names) --
#: NOT a general EOS parser. Scoped to exactly the commands the standalone
#: DHCP fragment emits.
_ALLOWED_CHILDREN = {
    "dhcp server": ("lease time ", "subnet "),
    "subnet ": ("name ", "default-gateway ", "range "),
    "range ": (),  # nothing is nested under range in this template
}


def _parent_mode_key(cmd: str) -> str | None:
    return next((key for key in _ALLOWED_CHILDREN if cmd.startswith(key)), None)


def _validate_nesting(text: str) -> list[str]:
    """Walk the RAW indented fragment text (not the flattened command
    list) with the same indentation-stack algorithm `eos_commands()` uses,
    checking every line against `_ALLOWED_CHILDREN` for its nearest
    enclosing mode."""
    problems: list[str] = []
    stack: list[tuple[int, str]] = []  # (indent, mode_key)
    for raw in text.splitlines():
        cmd = raw.strip()
        if not cmd or cmd == "!":
            continue
        indent = len(raw) - len(raw.lstrip())
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if stack:
            _, parent_key = stack[-1]
            allowed = _ALLOWED_CHILDREN.get(parent_key, ())
            if not any(cmd.startswith(prefix) for prefix in allowed):
                problems.append(f"{cmd!r} is not a recognized child of {parent_key!r} mode")
        mode_key = _parent_mode_key(cmd)
        if mode_key:
            stack.append((indent, mode_key))
    return problems


#: Prefixes an added/removed command line is allowed to have for the
#: semantic delta (Step 9) to be accepted as "DHCP-only". Anything outside
#: these must be treated as an unrelated, unacceptable change.
_DHCP_ONLY_PREFIXES = ("dhcp server", "lease time ", "subnet ", "name ", "default-gateway ", "range ", "exit")


def _validate_delta_is_dhcp_only(delta: dict[str, list[str]]) -> list[str]:
    problems: list[str] = []
    if delta["removed"]:
        problems.append(f"non-empty 'removed' set (nothing should ever disappear): {delta['removed']}")
    for line in delta["added"]:
        if line == "exit":
            continue  # exits are structural, driven entirely by the DHCP additions' own nesting
        if not line.startswith(_DHCP_ONLY_PREFIXES):
            problems.append(f"added line is not DHCP-shaped: {line!r}")
    return problems


if __name__ == "__main__":
    raise SystemExit(main())
