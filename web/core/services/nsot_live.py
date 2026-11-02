"""
Bounded, read-only live-device retrieval for NSOT device-detail pages.

Security model (see docs/DJANGO_NSOT_INTEGRATION.md "Live read safety"):
  * Target IP/account/reference metadata comes only from inventory.yml;
    actual passwords are resolved from the ignored mode-0600 runtime provider
    and never from a browser-supplied hostname/IP.
  * The command issued is a single, fixed, allowlisted string
    ("show running-config"). No browser input ever reaches the CLI.
  * After connecting, `conn.check_enable_mode()` / `conn.enable()` is
    called -- exactly master.py's own read-only `verify_eos()` pattern,
    reused rather than reinvented -- because EOS requires PRIVILEGED EXEC
    to return anything for "show running-config". This raises CLI
    privilege level only; it is NOT configuration mode.
    `config_mode()` / `send_config_set()` are never called -- this module
    cannot change device state even in principle.
  * Every connection has a finite timeout (settings.NSOT_LIVE_READ_TIMEOUT_
    SECONDS) and is always closed in a `finally` block.
  * Returned text is redacted before it leaves this module (see
    `redact_config`); no exception message is ever relayed verbatim, since
    a Netmiko exception can otherwise echo connection parameters.

Only cEOS (platform "ceos") is supported here. The R3/R4 FRR Linux routers
have no established safe read-only "show running-config" equivalent
anywhere in this codebase (no prior `vtysh` usage was found) -- rather than
invent one, this module honestly reports NOT_SUPPORTED for that platform.
This mirrors the Phase-7 rule: an honest gap beats a fabricated result.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import yaml
from django.conf import settings

_REPO_ROOT = settings.REPO_ROOT
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from modules.device_credentials import (  # noqa: E402
    FileSecretProvider,
    SecretProviderError,
    ceos_access_profiles,
    linux_access_profile,
    load_ssh_private_key,
)

SOURCE = "LIVE"
ALLOWED_COMMAND = "show running-config"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_inventory() -> dict:
    with open(_REPO_ROOT / "inventory.yml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_live_target_metadata(device_name: str, *, purpose: str = "READ") -> dict | None:
    """Trusted, non-secret target/account metadata from inventory.yml.

    The target is resolved by the shared managed-device resolver: only an ``inventory.yml`` device in WRITABLE scope with a
    declared management address qualifies (``auto`` and Containerlab management addresses are never candidates, so there is
    no hidden fallback to the lab management plane). Device-specific account
    profiles come from the inventory document; shared fleet fallback is forbidden.

    V2 Phase 4: the ADDRESS is then chosen by the management-path resolver (``management.resolve.endpoint``).  A device with
    no registered management path keeps its inventory address exactly as before; a device WITH registrations gets its active
    path's endpoint, or ``None`` (fail closed) when no path is usable -- and, for ``purpose="WRITE"``, also while the device
    needs reconciliation. Pending or revoked-only registrations never restore legacy access. A selected path's credential
    source is resolved at use time by ``get_live_target``; the inventory
    account is not substituted. ``management`` says which path (or LEGACY) was used.
    """
    from .devices import resolver
    from .management import resolve as management_resolve

    inventory = _load_inventory()
    entry = (inventory.get("network_devices") or {}).get(device_name)
    if not entry:
        return None
    target = resolver.resolve(device_name, document=inventory, with_lifecycle=False)
    if target is None or target.authority != resolver.Authority.INVENTORY_FILE or not target.writable:
        return None
    address = target.primary_address(4)
    selected = management_resolve.endpoint(device_name, legacy_address=address, purpose=purpose)
    if not selected.usable:
        return None
    address = selected.address
    if not address:
        return None
    management = selected.as_dict()
    platform = (entry.get("monitoring") or {}).get("platform")
    if selected.source == management_resolve.PATH:
        return {"device_name": device_name, "purpose": purpose, "platform": platform,
                "address": address, "management": management, "username": "", "credential_ref": "",
                "ssh_key_ref": "", "access_profiles": ()}
    try:
        if platform == "linux":
            profile = linux_access_profile(inventory, device_name)
            return {
                "device_name": device_name, "purpose": purpose,
                "platform": platform,
                "address": address,
                "management": management,
                "username": profile.username,
                "credential_ref": "",
                "ssh_key_ref": profile.ssh_key_ref,
                "access_profiles": ({
                    "username": profile.username, "credential_ref": "", "ssh_key_ref": profile.ssh_key_ref,
                },),
            }
        profiles = ceos_access_profiles(inventory, device_name)
    except SecretProviderError:
        return None
    return {
        "device_name": device_name, "purpose": purpose,
        "platform": platform,
        "address": address,
        "management": management,
        "username": profiles[0].username,
        "credential_ref": profiles[0].credential_ref,
        # Optional SSH key for the machine identity (legacy Phase-23 path); a
        # provider REFERENCE only -- the private key never enters inventory.
        "ssh_key_ref": profiles[0].ssh_key_ref,
        "access_profiles": tuple({
            "username": profile.username,
            "credential_ref": profile.credential_ref,
            "ssh_key_ref": profile.ssh_key_ref,
        } for profile in profiles),
    }


def get_live_target(device_name: str, *, purpose: str = "READ", platform: str = "") -> dict | None:
    """Resolve a trusted target plus current/pending recovery candidates.

    ``platform`` is the caller's NOS.  Only a cEOS caller (``"ceos"``) may resolve a natively onboarded device, so no other
    platform's executor or reader consults the device registry for a name the inventory does not know."""
    target = get_live_target_metadata(device_name, purpose=purpose)
    if target is None:
        # V2 Phase 6: a natively onboarded device has no inventory entry; it is reached only over its pinned ZTP host key with
        # the service credential that replaced its retired bootstrap credential, and written only while commissioning allows
        if platform == "ceos" and not (_load_inventory().get("network_devices") or {}).get(device_name):
            from .commissioning import transport as commissioning_transport

            return commissioning_transport.live_target(device_name, purpose=purpose)
        return None
    if (target.get("management") or {}).get("source") == "PATH":
        from .management import ssh_transport, probes

        try:
            path = ssh_transport.active_path(target)
            username, methods = probes.auth_material(path)
        except (ssh_transport.ManagedConnectionRejected, probes.CredentialUnavailable):
            return None
        keys = [item["pkey"] for item in methods if "pkey" in item]
        passwords = [item["password"] for item in methods if "password" in item]
        attempts = ([(key, password) for key in keys for password in passwords]
                    + [(key, "") for key in keys] + [(None, password) for password in passwords])
        candidates = tuple(
            {"username": username, "password": password,
             "ssh_auth": ({"use_keys": True, "pkey": key, "allow_agent": False} if key is not None else {})}
            for key, password in attempts
        )
        if not candidates:
            return None
        return {**target, "username": username, "password": candidates[0]["password"],
                "password_candidates": tuple(item["password"] for item in candidates),
                "ssh_auth": candidates[0]["ssh_auth"], "auth_candidates": candidates}
    if not target.get("credential_ref"):
        return None
    auth_candidates = []
    for profile in target.get("access_profiles", (target,)):
        try:
            passwords = FileSecretProvider().candidates(profile["credential_ref"])
        except SecretProviderError:
            continue
        ssh_auth = {}
        if profile.get("ssh_key_ref"):
            try:
                ssh_auth = {
                    "use_keys": True,
                    "pkey": load_ssh_private_key(profile["ssh_key_ref"]),
                    "allow_agent": False,
                }
            except SecretProviderError:
                # An enrolled key that cannot load fails the whole resolver;
                # it never degrades to any password-only profile.
                return None
        auth_candidates.extend({
            "username": profile["username"],
            "password": material.value,
            "ssh_auth": ssh_auth,
        } for material in passwords)
    if not auth_candidates:
        return None
    primary = auth_candidates[0]
    return {
        **target,
        "username": primary["username"],
        "password": primary["password"],
        "password_candidates": tuple(item["password"] for item in auth_candidates),
        "ssh_auth": primary["ssh_auth"],
        "auth_candidates": tuple(auth_candidates),
    }


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
# Targets known Arista EOS config syntax. This is NOT a universal secret
# detector -- see docs/DJANGO_NSOT_INTEGRATION.md "Known limitations" for
# what it does not (and cannot reliably) catch, e.g. secrets embedded in a
# free-text banner or a custom vendor-specific extension.
import re  # noqa: E402

_SECRET_KEYWORDS = (
    r"secret",
    r"password",
    r"community",
    r"key-string",
    r"authentication-key",
    r"pre-shared-key",
)

# Matched independently per line (never across a `.*` spanning multiple
# lines -- a greedy multiline pattern here would risk a keyword on one line
# "absorbing" an unrelated secret on an earlier line into its unredacted
# prefix). The keyword may appear anywhere on the line (e.g. "neighbor X
# password Y", "username ... secret sha512 Y", "snmp-server community Y
# ro"); only the trailing/adjacent token is masked, so surrounding context
# (command keyword, indentation, trailing flags) stays readable.
_LINE_PATTERN = re.compile(
    r"(?i)^(.*\b(?:" + "|".join(_SECRET_KEYWORDS) + r")\s+(?:(?:\d+|sha512|md5)\s+)?)(\S+)(\s.*)?$"
)

# SNMPv3 localized auth/priv key material (e.g. "snmp-server user <name>
# <group> v3 localized <engineID> auth sha256 <authkey> priv aes <privkey>")
# does not contain any of the generic keywords above -- "auth"/"priv" are
# their own trigger, scoped to the algorithm-name + hex-key shape so a
# stray "auth"/"priv" substring elsewhere isn't over-matched. Applied
# in-line (not full-line) since both can appear on the same line.
_SNMPV3_AUTH_PATTERN = re.compile(r"(?i)(\bauth\s+(?:md5|sha|sha256|sha384|sha512)\s+)(\S+)")
_SNMPV3_PRIV_PATTERN = re.compile(r"(?i)(\bpriv\s+(?:des|3des|aes|aes192|aes256)\s+)(\S+)")


def _redact_line(line: str) -> str:
    match = _LINE_PATTERN.match(line)
    line = f"{match.group(1)}********{match.group(3) or ''}" if match else line
    line = _SNMPV3_AUTH_PATTERN.sub(r"\1********", line)
    line = _SNMPV3_PRIV_PATTERN.sub(r"\1********", line)
    return line


def redact_config(text: str) -> str:
    """Deterministic, line-oriented redaction of known EOS secret syntax.
    Preserves surrounding context (command keyword, indentation) so the
    configuration remains readable; only the secret token is masked.
    Documented limitation: pattern-based, not a semantic parser -- an
    unrecognized or vendor-extension secret directive will not be caught.
    """
    return "\n".join(_redact_line(line) for line in text.splitlines())


def fetch_running_config(device_name: str) -> dict:
    """Explicit, bounded, read-only fetch. Never called automatically on
    page load -- only from the dedicated running-config route."""
    target = get_live_target(device_name)
    if target is None:
        return {
            "status": "unavailable",
            "source": SOURCE,
            "message": f"{device_name!r} has no known read-only management address.",
            "data": None,
        }
    if target["platform"] != "ceos":
        return {
            "status": "not_supported",
            "source": SOURCE,
            "message": "Live read-only retrieval currently supports cEOS devices only.",
            "data": None,
        }
    try:
        from .management.ssh_transport import connect_eos
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError as exc:  # pragma: no cover - Netmiko is a project dependency
        return {"status": "unavailable", "source": SOURCE, "message": f"Netmiko unavailable ({exc.__class__.__name__}).", "data": None}

    timeout = settings.NSOT_LIVE_READ_TIMEOUT_SECONDS
    conn = None
    try:
        auth_error = None
        for auth in target.get("auth_candidates", ({
            "username": target["username"], "password": target["password"], "ssh_auth": target.get("ssh_auth", {}),
        },)):
            try:
                conn = connect_eos(target, auth, timeout)
                break
            except NetmikoAuthenticationException as exc:
                auth_error = exc
        if conn is None:
            raise auth_error or NetmikoAuthenticationException("authentication failed")
        # Mirrors master.py::verify_eos()'s own established read-only
        # pattern exactly: EOS requires PRIVILEGED EXEC to return anything
        # for "show running-config". This raises CLI privilege level only
        # -- it is not configuration mode, and no config-entering call is
        # ever made below this line.
        if not conn.check_enable_mode():
            conn.enable()
        raw = conn.send_command(ALLOWED_COMMAND, read_timeout=timeout * 2)
    except NetmikoAuthenticationException:
        return {"status": "unavailable", "source": SOURCE, "message": "LIVE UNAVAILABLE: authentication failed.", "data": None}
    except NetmikoTimeoutException:
        return {"status": "unavailable", "source": SOURCE, "message": "LIVE UNAVAILABLE: device did not respond within the timeout.", "data": None}
    except Exception as exc:  # noqa: BLE001 - never leak connection details
        return {"status": "unavailable", "source": SOURCE, "message": f"LIVE UNAVAILABLE: {exc.__class__.__name__}.", "data": None}
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001
                pass

    return {
        "status": "available",
        "source": SOURCE,
        "observed_at": _now_iso(),
        "command": ALLOWED_COMMAND,
        "data": redact_config(raw),
    }
