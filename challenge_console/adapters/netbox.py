"""A read-only NetBox adapter: GET requests against the REST API, normalised into plain rows.

NetBox stays the authoritative structured source of truth; this adapter copies nothing into a second database -- each refresh is a
snapshot held in memory.  It can only read: the transport underneath (``adapters/http.py``) has no method but GET.

The API token is read from the protected env file (the same ``netbox/.env`` the project's ``modules/netbox_ipam.py`` reads, with the
same ``KEY=VALUE`` format and the same v1 / v2 Authorization rule).  It lives only in this object, is sent only as a request header,
and is never returned, logged or included in an error.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from . import http

MANAGED_TAG, UNMANAGED_TAG = "managed", "unmanaged"       # the project's NetBox scope tags (modules/netbox_ipam.py)
PAGE_LIMIT = 250
MAX_PAGES = 40
MAX_PAGE_BYTES = 8_000_000


class NetboxUnavailable(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_env_file(path: Path) -> dict[str, str]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return {}
    values = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def auth_header(token: str) -> dict[str, str]:
    v2 = token.startswith("nbt_") and "." in token[4:]
    return {"Authorization": f"{'Bearer' if v2 else 'Token'} {token}"}


class NetboxReader:
    def __init__(self, url: str, token: str = "", *, getter=http.get, timeout: float = 4.0):
        self.url = url.rstrip("/")
        self._headers = auth_header(token) if token else {}
        self._getter = getter
        self._timeout = timeout

    @classmethod
    def from_config(cls, config, *, getter=http.get) -> "NetboxReader":
        env = parse_env_file(config.netbox_env_file)
        url = config.netbox_url or env.get("NETBOX_URL") or "http://127.0.0.1:8000"
        return cls(url, env.get("NETBOX_TOKEN", ""), getter=getter, timeout=max(config.http_timeout, 8.0))

    def __repr__(self) -> str:   # never the token
        return f"NetboxReader(url={self.url!r}, authenticated={bool(self._headers)})"

    @property
    def authenticated(self) -> bool:
        return bool(self._headers)

    def health_headers(self) -> dict:
        """Headers for the authenticated ``/api/status/`` liveness read (used by the services collector)."""
        return dict(self._headers)

    def _list(self, path: str) -> list[dict]:
        url, rows = f"{self.url}{path}?limit={PAGE_LIMIT}", []
        origin = urlsplit(self.url)
        for _ in range(MAX_PAGES):
            result = self._getter(url, timeout=self._timeout, headers=self._headers, max_bytes=MAX_PAGE_BYTES)
            if result.status is None:
                raise NetboxUnavailable(result.error or "UNREACHABLE")
            if result.status in (401, 403):
                raise NetboxUnavailable("AUTHENTICATION_FAILED" if self._headers else "TOKEN_NOT_CONFIGURED")
            if not result.ok:
                raise NetboxUnavailable(f"HTTP_{result.status}" if not result.error else result.error)
            page = result.json()
            if not isinstance(page, dict) or not isinstance(page.get("results"), list):
                raise NetboxUnavailable("PARSE_ERROR")
            rows.extend(row for row in page["results"] if isinstance(row, dict))
            following = page.get("next")
            if not following:
                return rows
            nxt = urlsplit(str(following))
            if (nxt.scheme, nxt.hostname, nxt.port) != (origin.scheme, origin.hostname, origin.port):
                raise NetboxUnavailable("PARSE_ERROR")       # the token is only ever sent to the configured NetBox origin
            url = str(following)
        raise NetboxUnavailable("RESPONSE_TOO_LARGE")

    def snapshot(self) -> dict:
        """Devices (with their interfaces and addresses), prefixes and VLANs.  Raises ``NetboxUnavailable`` with a fixed code."""
        return normalise(self._list("/api/dcim/devices/"), self._list("/api/dcim/interfaces/"), self._list("/api/ipam/ip-addresses/"),
                         self._list("/api/ipam/prefixes/"), self._list("/api/ipam/vlans/"))


# --- normalisation (pure) ---------------------------------------------------------------------------------------------------------
def _label(value) -> str:
    if isinstance(value, dict):
        return str(value.get("display") or value.get("name") or value.get("label") or value.get("value") or "")
    return "" if value is None else str(value)


def _address(value) -> str:
    return str(value.get("address") or "") if isinstance(value, dict) else ""


def _tags(row: dict) -> list[str]:
    return sorted(str(tag.get("slug") or tag.get("name") or "") for tag in row.get("tags") or [] if isinstance(tag, dict))


def normalise(devices: list, interfaces: list, addresses: list, prefixes: list, vlans: list) -> dict:
    by_device: dict[str, dict] = {}
    for row in devices:
        name = str(row.get("name") or "")
        if not name:
            continue
        tags = _tags(row)
        managed = True if MANAGED_TAG in tags else False if UNMANAGED_TAG in tags else None
        by_device[name] = {
            "name": name, "role": _label(row.get("role") or row.get("device_role")), "platform": _label(row.get("platform")),
            "device_type": _label(row.get("device_type")), "site": _label(row.get("site")), "status": _label(row.get("status")),
            "primary_ip4": _address(row.get("primary_ip4")), "primary_ip6": _address(row.get("primary_ip6")),
            "oob_ip": _address(row.get("oob_ip")), "tags": tags, "managed": managed, "interfaces": [],
        }
    interface_index: dict[int, dict] = {}
    for row in interfaces:
        device = by_device.get(_label((row.get("device") or {}).get("name") if isinstance(row.get("device"), dict) else ""))
        if device is None:
            continue
        entry = {"name": str(row.get("name") or ""), "type": _label(row.get("type")), "enabled": row.get("enabled"),
                 "mgmt_only": bool(row.get("mgmt_only")), "description": str(row.get("description") or ""),
                 "mode": _label(row.get("mode")), "untagged_vlan": _label(row.get("untagged_vlan")), "addresses": []}
        device["interfaces"].append(entry)
        if isinstance(row.get("id"), int):
            interface_index[row["id"]] = entry
    unassigned = []
    for row in addresses:
        entry = {"address": str(row.get("address") or ""), "family": _label(row.get("family")), "status": _label(row.get("status")),
                 "role": _label(row.get("role")), "dns_name": str(row.get("dns_name") or ""), "description": str(row.get("description") or "")}
        target = interface_index.get(row.get("assigned_object_id")) if row.get("assigned_object_type") == "dcim.interface" else None
        (target["addresses"] if target is not None else unassigned).append(entry)
    for device in by_device.values():
        device["interfaces"].sort(key=lambda item: item["name"])
        device["address_count"] = sum(len(item["addresses"]) for item in device["interfaces"])
    return {
        "devices": sorted(by_device.values(), key=lambda item: item["name"]),
        "prefixes": sorted(({"prefix": str(row.get("prefix") or ""), "status": _label(row.get("status")), "role": _label(row.get("role")),
                             "vlan": _label(row.get("vlan")), "vrf": _label(row.get("vrf")), "description": str(row.get("description") or "")}
                            for row in prefixes), key=lambda item: item["prefix"]),
        "vlans": sorted(({"vid": row.get("vid"), "name": str(row.get("name") or ""), "status": _label(row.get("status")),
                          "role": _label(row.get("role")), "description": str(row.get("description") or "")} for row in vlans),
                        key=lambda item: (item["vid"] is None, item["vid"] or 0)),
        "unassigned_addresses": unassigned,
        "counts": {"devices": len(by_device), "interfaces": len(interfaces), "addresses": len(addresses), "prefixes": len(prefixes),
                   "vlans": len(vlans)},
    }


def consistency(snapshot: dict, *, inventory_devices: dict[str, dict], running: set[str] | None) -> list[dict]:
    """Per NetBox device: does what NSOT expects agree with the tracked inventory and with what is running?

    ``inventory_devices``: {name: {"address", "address_v6", "managed"}} from ``inventory.yml``.  ``running``: node names whose lab
    container is running, or None when the container runtime could not be read (then the runtime column is UNKNOWN, not a guess).
    """
    found = []
    for device in snapshot.get("devices", []):
        name = device["name"]
        tracked = inventory_devices.get(name)
        nsot_v4 = {a["address"].split("/")[0] for i in device["interfaces"] for a in i["addresses"] if ":" not in a["address"]}
        nsot_v6 = {a["address"].split("/")[0] for i in device["interfaces"] for a in i["addresses"] if ":" in a["address"]}
        if tracked is None:
            mgmt = "NOT_IN_INVENTORY"
        elif not tracked.get("address"):
            mgmt = "NO_INVENTORY_ADDRESS"
        else:
            ok4 = tracked["address"] in nsot_v4
            ok6 = not tracked.get("address_v6") or tracked["address_v6"] in nsot_v6
            mgmt = "MATCH" if ok4 and ok6 else "MISMATCH"
        scope = "N/A" if tracked is None or device["managed"] is None else "MATCH" if bool(tracked.get("managed")) == device["managed"] else "MISMATCH"
        runtime = "UNKNOWN" if running is None else "RUNNING" if name in running else "NOT_RUNNING"
        found.append({"device": name, "management_address": mgmt, "managed_scope": scope, "runtime": runtime})
    return found
