"""Pure filter / format helpers used by the views (no Tk here, so they are tested without a display)."""

from __future__ import annotations

from datetime import datetime, timedelta

from .models import DOWN, UP, InterfaceRow, utcnow

STATE_FILTERS = ("All", "Up", "Down", "Admin down", "Errors / drops", "Carrying traffic", "Changed recently")
SCOPE_FILTERS = ("All", "Managed", "Unmanaged")
RECENT_CHANGE = timedelta(minutes=5)


# --- formatting -------------------------------------------------------------------------------------------------------------
def fmt_time(moment: datetime | None, *, date: bool = False) -> str:
    if moment is None:
        return "-"
    return moment.strftime("%Y-%m-%d %H:%M:%SZ" if date else "%H:%M:%SZ")


def fmt_iso(text: str) -> str:
    """Compact form of an ISO timestamp string from a snapshot document."""
    return text[:19].replace("T", " ") + "Z" if text else "-"


def fmt_duration(seconds) -> str:
    if seconds is None:
        return "-"
    seconds = int(max(0, seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}" if days else f"{hours:02d}:{minutes:02d}:{secs:02d}"


def fmt_age(moment: datetime | None, now: datetime | None = None) -> str:
    if moment is None:
        return "-"
    seconds = ((now or utcnow()) - moment).total_seconds()
    return f"{seconds:.0f} s" if seconds < 120 else fmt_duration(seconds)


def fmt_count(value) -> str:
    return "-" if value is None else f"{value:,}"


def fmt_rate(value, unit: str = "bit/s") -> str:
    """A derived rate; "-" when there is not yet enough data to derive one (never a made-up zero)."""
    if value is None:
        return "-"
    for scale, prefix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if abs(value) >= scale:
            return f"{value / scale:.2f} {prefix}{unit}"
    return f"{value:.1f} {unit}"


def fmt_speed(value) -> str:
    return "-" if not value else fmt_rate(float(value)).replace(".00", "")


def sparkline(samples, width: int = 40) -> str:
    """The last ``width`` probe results, oldest first: '.' = reply, 'X' = failure."""
    return "".join("." if sample.success else "X" for sample in samples[-width:])


def loss_percent(samples) -> float | None:
    return None if not samples else 100.0 * sum(1 for sample in samples if not sample.success) / len(samples)


# --- interface counters ---------------------------------------------------------------------------------------------------------
def has_errors(row: InterfaceRow) -> bool:
    sample = row.sample
    return any((value or 0) > 0 for value in (sample.rx_errors, sample.tx_errors, sample.rx_drops, sample.tx_drops))


def carrying_traffic(row: InterfaceRow) -> bool:
    return any((value or 0) > 0 for value in (row.rx_bps, row.tx_bps))


def filter_interfaces(rows: list[InterfaceRow], *, device: str = "All", text: str = "", state: str = "All",
                      now: datetime | None = None) -> list[InterfaceRow]:
    now = now or utcnow()
    needle = text.strip().lower()
    found = []
    for row in rows:
        sample = row.sample
        if device not in ("", "All") and sample.device != device:
            continue
        if needle and needle not in sample.name.lower() and needle not in sample.description.lower():
            continue
        if state == "Up" and not (row.present and sample.oper == UP):
            continue
        if state == "Down" and not (not row.present or sample.oper == DOWN):
            continue
        if state == "Admin down" and sample.admin != DOWN:
            continue
        if state == "Errors / drops" and not has_errors(row):
            continue
        if state == "Carrying traffic" and not carrying_traffic(row):
            continue
        if state == "Changed recently" and not (row.last_change and now - row.last_change <= RECENT_CHANGE):
            continue
        found.append(row)
    return sorted(found, key=lambda item: (item.sample.device, _natural(item.sample.name)))


def _natural(name: str):
    head = name.rstrip("0123456789./")
    tail = name[len(head):]
    return head, [int(part) for part in tail.replace("/", ".").split(".") if part.isdigit()]


# --- NSOT -------------------------------------------------------------------------------------------------------------------------
def filter_devices(devices: list[dict], *, text: str = "", role: str = "All", scope: str = "All") -> list[dict]:
    """Search matches the device name, role, platform / type, any management address, and any interface name or address."""
    needle = text.strip().lower()
    found = []
    for device in devices:
        if role not in ("", "All") and device.get("role") != role:
            continue
        if scope == "Managed" and device.get("managed") is not True:
            continue
        if scope == "Unmanaged" and device.get("managed") is not False:
            continue
        if needle:
            haystack = [device.get("name", ""), device.get("role", ""), device.get("platform", ""), device.get("device_type", ""),
                        device.get("primary_ip4", ""), device.get("primary_ip6", "")]
            for interface in device.get("interfaces", []):
                haystack.append(interface.get("name", ""))
                haystack.extend(address.get("address", "") for address in interface.get("addresses", []))
            if not any(needle in str(value).lower() for value in haystack):
                continue
        found.append(device)
    return found
