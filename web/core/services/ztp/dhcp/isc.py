"""The operational ISC DHCP (isc-dhcp-server 4.4) provider for isolated bootstrap networks.

Rendering: one ``class`` per reservation matching the trusted relay (``packet(24, 4)`` = giaddr) AND the relay-inserted
option 82 circuit id (AND the adapter's vendor-class prefix), one single-address pool that only that class may draw from,
and the adapter's options inside the class.  No dynamic pool exists.  An ``on commit`` block stashes the relay and claim
fields into the lease database so ingestion reads them from the provider's own state, not from a device.

Application contract with the isolated service: ``dhcpd.conf`` in ``config_root`` is the live file, ``dhcpd.conf.previous``
the recovery copy, and a ``restart`` marker asks the service supervisor to restart dhcpd (``labs/ztp-isolated``).
"""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timezone

from .base import ApplyResult, BootstrapPolicy, DhcpProvider, ProviderError, atomic_write, check_value, safe_root, sha256_text

# ISC option names NMAS may render (anything else from an adapter is refused) and the custom definitions they need.
OPTION_NAMES = {"bootfile-name", "tftp-server-name", "vendor-encapsulated-options", "nmas-sonic-provisioning-script"}
CUSTOM_DEFINITIONS = ("option nmas-sonic-provisioning-script code 239 = text;",)
_HEX_OPTIONS = {"vendor-encapsulated-options"}
_LEASE = re.compile(r"^lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)^\}", re.S | re.M)


def _octets(address: str) -> str:
    return ":".join(f"{int(o):02x}" for o in str(ipaddress.IPv4Address(address)).split("."))


class IscDhcpProvider(DhcpProvider):
    kind = "ISC_DHCP"
    config_name = "dhcpd.conf"
    operational = True
    settle_seconds = 10.0       # how long apply / rollback wait for the supervisor to restart dhcpd before reporting it

    def render(self, policy: BootstrapPolicy) -> str:
        subnet = ipaddress.IPv4Network(policy.subnet)
        service = ipaddress.IPv4Network(policy.service_prefix)
        out = [
            f"# NMAS V2 Phase 3 isolated bootstrap DHCP policy -- network {check_value(policy.network)} (generated; never edit).",
            "# One class-scoped single-address pool per authorized ZTP session; no dynamic pool; never VLAN 200.",
            "authoritative;", "ddns-update-style none;", "log-facility local7;",
            f"default-lease-time {int(policy.lease_seconds)};", f"max-lease-time {int(policy.lease_seconds) * 2};",
            *CUSTOM_DEFINITIONS,
            "on commit {",
            '  set nmas-giaddr = binary-to-ascii(10, 8, ".", packet(24, 4));',
            '  set nmas-client-id = binary-to-ascii(16, 8, ":", option dhcp-client-identifier);',
            "  set nmas-vendor-class = option vendor-class-identifier;",
            "  set nmas-user-class = option user-class;",
            "  set nmas-circuit-id = option agent.circuit-id;",
            "  set nmas-remote-id = option agent.remote-id;",
            "}",
        ]
        for res in sorted(policy.reservations, key=lambda r: r.session_id):
            address = ipaddress.IPv4Address(res.address)
            if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
                raise ProviderError("BOOTSTRAP_NETWORK_INVALID", "a reservation lies outside the bootstrap subnet")
            match = [f"packet(24, 4) = {_octets(res.relay_address)}", f'option agent.circuit-id = "{check_value(res.circuit_id)}"']
            if res.vendor_class_prefix:
                prefix = check_value(res.vendor_class_prefix)
                match.append(f'substring(option vendor-class-identifier, 0, {len(prefix.encode())}) = "{prefix}"')
            out.append(f'class "nmas-{check_value(res.session_id)}" {{  # {check_value(res.device)}')
            out.append("  match if " + " and ".join(match) + ";")
            for name, value in res.options:
                if name not in OPTION_NAMES:
                    raise ProviderError("DHCP_PROVIDER_ERROR", f"option {name!r} is not renderable")
                if name in _HEX_OPTIONS and not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2})*", str(value)):
                    raise ProviderError("DHCP_PROVIDER_ERROR", "a hex option value is malformed")
                rendered = str(value) if name in _HEX_OPTIONS else f'"{check_value(value)}"'
                out.append(f"  option {name} {rendered};")
            out.append("}")
        out.append(f"subnet {service.network_address} netmask {service.netmask} {{ }}  # NMAS bootstrap-service link (no pool)")
        out.append(f"subnet {subnet.network_address} netmask {subnet.netmask} {{")
        out.append(f"  option routers {ipaddress.IPv4Address(policy.gateway)};")
        for res in sorted(policy.reservations, key=lambda r: r.session_id):
            out.append(f'  pool {{ allow members of "nmas-{res.session_id}"; range {res.address} {res.address}; }}')
        out.append("}")
        return "\n".join(out) + "\n"

    def validate(self, text: str) -> dict:
        return self._validate_file(text, "dhcpd.conf.candidate")

    def apply(self, policy: BootstrapPolicy) -> ApplyResult:
        text = self.render(policy)
        root = safe_root(self.config_root)
        live = root / self.config_name
        previous_text = live.read_text(encoding="utf-8") if live.exists() else ""
        validation = self.validate(text)
        if not validation["ok"]:
            return ApplyResult(False, "FAILED", text, sha256_text(text), sha256_text(previous_text) if previous_text else "",
                               validation, code="DHCP_PROVIDER_ERROR")
        if previous_text:
            atomic_write(root / f"{self.config_name}.previous", previous_text)
        atomic_write(live, text)
        (root / "restart").touch()
        read_back = self.read_back(settle_seconds=self.settle_seconds)
        ok = self._read_back_ok(read_back, text)
        if not ok:
            read_back["restored_previous"] = self._restore(live, previous_text)
        return ApplyResult(ok, "APPLIED" if ok else "FAILED", text, sha256_text(text), sha256_text(previous_text) if previous_text else "",
                           validation, read_back, "" if ok else "DHCP_PROVIDER_ERROR")

    @staticmethod
    def _read_back_ok(read_back: dict, text: str) -> bool:
        """The deployed file is the candidate AND the service was positively seen running (no status command = not proven)."""
        return read_back.get("config_sha256") == sha256_text(text) and (read_back.get("service") or {}).get("running") is True

    def _restore(self, live, previous_text: str) -> bool:
        """Put back what was live before an unverified write (or remove the candidate when nothing was) and ask for a restart."""
        if previous_text:
            atomic_write(live, previous_text)
        else:
            live.unlink(missing_ok=True)
        (live.parent / "restart").touch()
        return True

    def rollback(self) -> ApplyResult:
        root = safe_root(self.config_root)
        previous = root / f"{self.config_name}.previous"
        if not previous.exists():
            raise ProviderError("DHCP_PROVIDER_ERROR", "no previous isolated configuration exists to recover")
        text = previous.read_text(encoding="utf-8")
        current = (root / self.config_name).read_text(encoding="utf-8") if (root / self.config_name).exists() else ""
        validation = self.validate(text)
        if not validation["ok"]:
            return ApplyResult(False, "FAILED", text, sha256_text(text), sha256_text(current) if current else "", validation,
                               code="DHCP_PROVIDER_ERROR")
        atomic_write(root / self.config_name, text)
        (root / "restart").touch()
        read_back = self.read_back(settle_seconds=self.settle_seconds)
        ok = self._read_back_ok(read_back, text)
        if not ok:
            read_back["restored_previous"] = self._restore(root / self.config_name, current)
        return ApplyResult(ok, "ROLLED_BACK" if ok else "FAILED", text, sha256_text(text), sha256_text(current) if current else "",
                           validation, read_back, "" if ok else "DHCP_PROVIDER_ERROR")

    def read_back(self, *, settle_seconds: float = 0.0) -> dict:
        """The deployed file's digest, the provider's own parse of it and (when configured) the service process status.

        After a restart request the isolated service's supervisor needs a moment to restart dhcpd; ``settle_seconds`` polls
        the status command for that long instead of reporting the instant between the stop and the start."""
        root = safe_root(self.config_root)
        live = root / self.config_name
        if not live.exists():
            return {"present": False}
        text = live.read_text(encoding="utf-8")
        found = {"present": True, "config_sha256": sha256_text(text),
                 "classes": sorted(re.findall(r'^class "([^"]+)"', text, re.M))}
        if self.status_command:
            deadline = time.monotonic() + settle_seconds
            while True:
                restart_pending = (root / "restart").exists()
                rc, output = self.runner(list(self.status_command))
                if (rc == 0 and not restart_pending) or time.monotonic() >= deadline:
                    break
                time.sleep(1)
            found["service"] = {"running": rc == 0 and not restart_pending, "restart_pending": restart_pending, "output": output[-300:]}
        else:
            found["service"] = {"running": None, "output": "no status command is configured: the service state cannot be read back"}
        return found

    # --- leases ---------------------------------------------------------------------------------------------------------------
    def parse_leases(self, text: str) -> list[dict]:
        """dhcpd.leases -> one dict per lease block (later blocks of the same address are newer)."""
        rows = []
        for address, body in _LEASE.findall(str(text or "")):
            row = {"address": address, "client_mac": "", "client_id": "", "vendor_class": "", "user_class": "", "hostname": "",
                   "relay_address": "", "circuit_id": "", "remote_id": "", "binding_state": "", "starts": None, "ends": None}
            for line in body.splitlines():
                line = line.strip().rstrip(";")
                if line.startswith("starts "):
                    row["starts"] = _lease_time(line)
                elif line.startswith("ends "):
                    row["ends"] = _lease_time(line)
                elif line.startswith("binding state "):
                    row["binding_state"] = line.split()[-1]
                elif line.startswith("hardware ethernet "):
                    row["client_mac"] = line.split()[-1].lower()
                elif line.startswith("client-hostname "):
                    row["hostname"] = _unquote(line.split(" ", 1)[1])
                elif line.startswith("set nmas-"):
                    name, _, value = line[4:].partition(" = ")
                    key = {"nmas-giaddr": "relay_address", "nmas-client-id": "client_id", "nmas-vendor-class": "vendor_class",
                           "nmas-user-class": "user_class", "nmas-circuit-id": "circuit_id", "nmas-remote-id": "remote_id"}.get(name.strip())
                    if key:
                        row[key] = _unquote(value)
            if row["relay_address"] == "0.0.0.0":
                row["relay_address"] = ""      # a direct (unrelayed) request carries no relay evidence
            rows.append(row)
        return rows


def _unquote(value: str) -> str:
    text = value.strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    # ISC escapes non-printable bytes as \ooo; keep the printable text, drop control bytes
    text = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)) if 32 <= int(m.group(1), 8) < 127 else "", text)
    return text[:128]


def _lease_time(line: str):
    match = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    if not match:
        return None
    return datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
