"""Read-only live capture through the execution gateway -> replay fixtures.

Usage (inside an orchestrator sandbox):
  python3 -I capture_live.py OUT_DIR PIN_ID  FIXTURE_ID:NODE:PLATFORM:OSVERSION [...]
Runs ``CliCollector`` (catalogued show commands only) over ``GatewayTransport`` and writes, per node, the bundle JSON plus the redacted raw
outputs.  Nothing here uses the gateway ``config`` kind.  Output files are what the replay tests read; the live-vs-replay distinction is
the ``run.gateway.live`` flag + gateway evidence sequence numbers.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, "/opt/ai-orchestrator/gateway/client")
# Import the collectors from THIS worktree (the one the gateway pins), never from another checkout: a hard-coded path would
# record evidence produced by unpinned code (it pointed at the legacy archive before the port).
WEB_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(WEB_ROOT))
from aiorch_gw import Gateway   # noqa: E402
from core.services.troubleshooting import collectors as c, normalization as nz   # noqa: E402
from core.services.troubleshooting.adapters.transports import GatewayTransport   # noqa: E402

KEYS = {"ceos": ["version", "interfaces", "ospf_neighbors", "bgp_summary", "ip_route", "spanning_tree", "interface_transceiver", "running_config"],
        "iosxe": ["version", "interfaces", "ospf_neighbors", "ip_route", "spanning_tree", "interface_transceiver", "running_config"],
        "linux": ["version", "addr", "ospf_neighbors", "bgp_summary", "route4", "link_stats", "frr_config"]}
PARAMS = {"interface_transceiver": {"interface": "Ethernet1"}}

out_dir, pin = Path(sys.argv[1]), sys.argv[2]
gw = Gateway()
for spec in sys.argv[3:]:
    fixture, node, platform, version = spec.split(":", 3)
    transport = GatewayTransport(gw, fixture, node, platform, pin_id=pin or None, label="s2-collectors-live")
    store = c.InMemoryRawStore()
    params = dict(PARAMS)
    if platform == "iosxe":
        params["interface_transceiver"] = {"interface": "GigabitEthernet2"}
    collector = c.CliCollector(raw_store=store, adapter="gateway-fixture", budget=c.Budget(max_commands=12, min_interval_s=0.2, max_seconds=240),
                               capability_probe=lambda p, s: {"status": "SUPPORTED"} if s == c.SourceType.CLI else {"status": "UNKNOWN"})
    target = c.Target(device=node, platform=platform, os_version=version)
    bundle = collector.collect(target, KEYS[platform], transport, params=params, transport_name="gateway-fixture")
    name = f"{platform}_{node}"
    (out_dir / f"{name}.bundle.json").write_text(json.dumps(bundle, indent=1, sort_keys=True))
    (out_dir / f"{name}.raw.json").write_text(json.dumps({e["command_or_api"]: {"hash": e["raw_ref"]["hash"], "redacted_text": store.items.get(e["raw_ref"]["hash"])}
                                                          for e in bundle["evidence"]}, indent=1, sort_keys=True))
    print(name, bundle["run"]["status"], "evidence", len(bundle["evidence"]), "obs", len(bundle["observations"]), "missing", [(m["reason"], m["command_or_api"]) for m in bundle["missing"]])
