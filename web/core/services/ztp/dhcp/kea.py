"""The ISC Kea DHCPv4 provider: real configuration generation and validation with Kea's own parser (``kea-dhcp4 -t``).

Implemented: rendering the same provider-neutral policy (one client class per reservation testing the trusted relay's giaddr
and option 82 circuit id, a class-restricted single-address pool, adapter options inside the class), validation through the
configured Kea binary, and parsing of the memfile lease CSV.  NOT implemented: applying a configuration to a running Kea
(control socket / config-set), read-back of the running server and live lease observation -- so Kea is NOT operationally
supported and ``apply`` / ``rollback`` / ``read_back`` refuse with DHCP_PROVIDER_UNSUPPORTED.  The rendering targets Kea 2.4
(``client-class`` on pools; ``store-extended-info`` keeps option 82 in the lease user context).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from datetime import datetime, timezone

from .base import BootstrapPolicy, DhcpProvider, ProviderError, check_value

# ISC option name -> Kea option-data name / custom definition
KEA_OPTION = {"bootfile-name": "boot-file-name", "tftp-server-name": "tftp-server-name",
              "vendor-encapsulated-options": "vendor-encapsulated-options", "nmas-sonic-provisioning-script": "nmas-sonic-provisioning-script"}
OPTION_DEFS = [{"name": "nmas-sonic-provisioning-script", "code": 239, "type": "string", "space": "dhcp4"}]


class KeaDhcp4Provider(DhcpProvider):
    kind = "KEA"
    config_name = "kea-dhcp4.conf"
    operational = False

    def render(self, policy: BootstrapPolicy) -> str:
        subnet = ipaddress.IPv4Network(policy.subnet)
        classes, pools, relays = [], [], set()
        for res in sorted(policy.reservations, key=lambda r: r.session_id):
            if ipaddress.IPv4Address(res.address) not in subnet:
                raise ProviderError("BOOTSTRAP_NETWORK_INVALID", "a reservation lies outside the bootstrap subnet")
            name = f"nmas-{check_value(res.session_id)}"
            test = [f"pkt4.giaddr == {ipaddress.IPv4Address(res.relay_address)}", f"relay4[1].text == '{check_value(res.circuit_id)}'"]
            if res.vendor_class_prefix:
                prefix = check_value(res.vendor_class_prefix)
                test.append(f"substring(option[60].text, 0, {len(prefix.encode())}) == '{prefix}'")
            data = []
            for option, value in res.options:
                if option not in KEA_OPTION:
                    raise ProviderError("DHCP_PROVIDER_ERROR", f"option {option!r} is not renderable")
                entry = {"name": KEA_OPTION[option], "data": check_value(value)}
                if option == "vendor-encapsulated-options":
                    entry.update({"csv-format": False, "data": str(value).replace(":", "")})
                data.append(entry)
            classes.append({"name": name, "test": " and ".join(f"({t})" for t in test), "option-data": data,
                            "user-context": {"device": res.device}})
            pools.append({"pool": f"{res.address} - {res.address}", "client-class": name})
            relays.add(str(ipaddress.IPv4Address(res.relay_address)))
        config = {"Dhcp4": {
            "interfaces-config": {"interfaces": []},
            "lease-database": {"type": "memfile", "persist": True, "name": "kea-leases4.csv"},
            "valid-lifetime": int(policy.lease_seconds), "store-extended-info": True, "authoritative": True,
            "option-def": OPTION_DEFS, "client-classes": classes,
            "subnet4": [{"id": 1, "subnet": str(subnet), "relay": {"ip-addresses": sorted(relays)},
                         "option-data": [{"name": "routers", "data": str(ipaddress.IPv4Address(policy.gateway))}], "pools": pools}],
            "user-context": {"generated-by": "NMAS V2 Phase 3", "network": check_value(policy.network)},
        }}
        return json.dumps(config, indent=2, sort_keys=True) + "\n"

    def validate(self, text: str) -> dict:
        return self._validate_file(text, "kea-dhcp4.conf.candidate")

    def parse_leases(self, text: str) -> list[dict]:
        """Kea memfile CSV (``address,hwaddr,client_id,valid_lifetime,expire,...,hostname,state,user_context``) -> lease dicts.
        Relay evidence comes from ``user_context`` ISC relay-agent-info (``store-extended-info``)."""
        rows = []
        for record in csv.DictReader(io.StringIO(str(text or ""))):
            try:
                expire = datetime.fromtimestamp(int(record.get("expire") or 0), tz=timezone.utc)
                lifetime = int(record.get("valid_lifetime") or 0)
            except ValueError:
                continue
            context = {}
            try:
                context = json.loads((record.get("user_context") or "{}").replace("&#x2c", ","))
            except ValueError:
                context = {}
            relay = ((context.get("ISC") or {}).get("relay-agent-info") or {})
            sub = relay.get("sub-options", "") if isinstance(relay, dict) else ""
            rows.append({
                "address": record.get("address", ""), "client_mac": (record.get("hwaddr") or "").lower(), "client_id": record.get("client_id", ""),
                "vendor_class": "", "user_class": "", "hostname": record.get("hostname", ""),
                "relay_address": "", "circuit_id": _circuit_from_hex(sub), "remote_id": "",
                "binding_state": {"0": "active", "1": "declined", "2": "expired-reclaimed"}.get(record.get("state", ""), ""),
                "starts": datetime.fromtimestamp(expire.timestamp() - lifetime, tz=timezone.utc), "ends": expire,
            })
        return rows


def _circuit_from_hex(sub_options: str) -> str:
    """Option 82 sub-option 1 (circuit id) from Kea's hex dump ``0x0109...``."""
    text = str(sub_options or "").lower().removeprefix("0x")
    try:
        data = bytes.fromhex(text)
    except ValueError:
        return ""
    index = 0
    while index + 2 <= len(data):
        code, length = data[index], data[index + 1]
        if code == 1:
            return data[index + 2:index + 2 + length].decode("ascii", "replace")[:64]
        index += 2 + length
    return ""
