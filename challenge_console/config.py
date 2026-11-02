"""The one configuration layer of the console: every path, endpoint, name and period lives here.

Defaults target the lab.  Each can be overridden with an ``NMAS_CONSOLE_<FIELD>`` environment variable (upper-cased field name).  No
secret is ever a field of this object: the NetBox token is read from its protected env file by the NetBox adapter alone.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path

from . import APP_NAME

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PREFIX = "NMAS_CONSOLE_"
MIN_RETENTION_SECONDS = 3600  # the challenge requirement: never less than one hour of connectivity history in memory


def _xdg(variable: str, fallback: str) -> Path:
    return Path(os.environ.get(variable) or Path.home() / fallback) / APP_NAME


@dataclass(frozen=True)
class ConsoleConfig:
    # --- lab identity -------------------------------------------------------------------------------------------------
    lab_name: str = "srlceos01"
    expected_lab_containers: int = 15
    repo_root: Path = REPO_ROOT
    inventory_path: Path = REPO_ROOT / "inventory.yml"
    topology_policy_path: Path = REPO_ROOT / "monitoring/config/topology.yml"
    deploy_root: Path = Path("/home/student/Scripts/clab_dualstack_lab-deploy")
    endpoint_mgmt_interface: str = "eth0"          # Containerlab's own management NIC inside an endpoint; never a probe address
    container_runtime: str = "docker"

    # --- read-only data sources -----------------------------------------------------------------------------------------
    automation_db_path: Path | None = None         # default: <deploy_root>/web/db.sqlite3
    netbox_env_file: Path | None = None            # default: <deploy_root>/netbox/.env  (URL + token; the token never leaves the adapter)
    netbox_url: str = ""                           # default: NETBOX_URL from the env file, else http://127.0.0.1:8000
    topology_api_url: str = "http://127.0.0.1:8050/api/topology"
    topology_health_url: str = "http://127.0.0.1:8050/healthz"
    nmas_web_health_url: str = "http://127.0.0.1:8001/healthz"
    influxdb_health_url: str = "http://127.0.0.1:8086/health"
    grafana_health_url: str = "http://127.0.0.1:3000/api/health"
    privacyidea_url: str = "https://192.168.200.100:8443/"
    traffic_runner_socket: Path = Path("/run/nmas-traffic-runner/runner.sock")
    netbox_container: str = "netbox-netbox-1"
    influxdb_container: str = "monitoring-influxdb-1"
    grafana_container: str = "monitoring-grafana-1"
    freeradius_container: str = "human_mfa-human-mfa-radius-1"
    privacyidea_container: str = "nmas-human-mfa-pi-privacyidea-1"

    # --- polling periods (seconds): observation, not load generation ------------------------------------------------------
    connectivity_interval: float = 5.0
    counters_interval: float = 10.0
    services_interval: float = 15.0
    automation_interval: float = 20.0
    nsot_interval: float = 120.0
    address_refresh_interval: float = 60.0         # how often endpoint addresses are re-discovered

    # --- bounds -----------------------------------------------------------------------------------------------------------
    retention_seconds: float = 7200.0              # in-memory connectivity history (clamped to >= one hour)
    ping_wait_seconds: int = 1
    command_timeout: float = 8.0
    http_timeout: float = 4.0
    db_busy_timeout: float = 2.0
    max_backoff: float = 120.0
    stall_factor: float = 6.0                      # a collector silent for stall_factor * interval (+ timeouts) is reported stalled
    join_timeout: float = 6.0
    recent_events: int = 2000                      # the in-memory "recent events" ring shown in the UI
    automation_rows: int = 25

    # --- local persistence (never inside the Git checkout) ------------------------------------------------------------------
    save_dir: Path = field(default_factory=lambda: _xdg("XDG_DATA_HOME", ".local/share") / "sessions")
    spool_dir: Path = field(default_factory=lambda: _xdg("XDG_STATE_HOME", ".local/state") / "spool")

    def __post_init__(self):
        object.__setattr__(self, "retention_seconds", max(float(self.retention_seconds), MIN_RETENTION_SECONDS))
        if self.automation_db_path is None:
            object.__setattr__(self, "automation_db_path", Path(self.deploy_root) / "web" / "db.sqlite3")
        if self.netbox_env_file is None:
            object.__setattr__(self, "netbox_env_file", Path(self.deploy_root) / "netbox" / ".env")
        for name in ("connectivity_interval", "counters_interval", "services_interval", "automation_interval", "nsot_interval"):
            if float(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")

    @property
    def history_maxlen(self) -> int:
        """Samples one connectivity row keeps: the retention window at the probe period, with headroom for jitter."""
        return int(self.retention_seconds / self.connectivity_interval * 1.25) + 16

    def container(self, node: str) -> str:
        return f"clab-{self.lab_name}-{node}"

    def with_overrides(self, **changes) -> "ConsoleConfig":
        return replace(self, **changes)

    @classmethod
    def from_env(cls, env: dict | None = None, **overrides) -> "ConsoleConfig":
        env = os.environ if env is None else env
        values: dict = {}
        for item in fields(cls):
            raw = env.get(ENV_PREFIX + item.name.upper())
            if raw is None or raw == "":
                continue
            kind = str(item.type)
            if "Path" in kind:
                values[item.name] = Path(raw).expanduser()
            elif kind == "int":
                values[item.name] = int(raw)
            elif kind == "float":
                values[item.name] = float(raw)
            else:
                values[item.name] = raw
        values.update(overrides)
        return cls(**values)

    def public_dict(self) -> dict:
        """What may be written to the session log: paths, names and periods.  There is no secret field to leave out."""
        return {item.name: (str(value) if isinstance(value := getattr(self, item.name), Path) else value) for item in fields(self)}
