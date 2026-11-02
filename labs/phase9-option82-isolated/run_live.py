"""NMAS V2 Phase 9 option-82 live run against the disposable fixture (``fixture.sh up`` first).

Run from web/:  DJANGO_DEBUG=1 python manage.py shell -c \
    "import runpy; runpy.run_path('../labs/phase9-option82-isolated/run_live.py', run_name='__main__')"
Importing the module runs nothing (the helpers are unit-tested by core.tests.test_tg_phase9_live_runner_closure).
Writes secret-free evidence to docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json.  Touches only nmas-p9-* containers.
"""
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from core.services import dhcp_relay_option82 as o82
from core.services.ztp.dhcp import base as dhcp_base
from core.services.ztp.dhcp.isc import IscDhcpProvider

ROOT = Path.cwd().parent
RUNTIME = ROOT / "labs/phase9-option82-isolated/runtime"
OUT = ROOT / "docs/evidence/v2-phase7-9/phase9/option82-ceos-live.json"
RELAY, SVC, CLIENT = "nmas-p9-relay", "nmas-p9-svc", "nmas-p9-client"


def run(*argv, timeout=60):
    r = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
    return r.returncode, r.stdout + r.stderr


def cli(command):
    return run("docker", "exec", RELAY, "Cli", "-p", "15", "-c", command)[1]


def apply(lines):
    rc, out = run("docker", "exec", RELAY, "Cli", "-p", "15", "--abort-on-error", "-c", o82.change_payload(lines))
    return {"rc": rc, "output": out.strip()[-400:], "lines": lines}


def capture_start(name):
    run("docker", "exec", SVC, "rm", "-f", f"/srv/dhcp/{name}.pcap")
    run("docker", "exec", "-d", SVC, "tcpdump", "-i", "eth1", "-n", "-U", "-w", f"/srv/dhcp/{name}.pcap", "udp", "port", "67")
    time.sleep(1.5)


def capture_stop(name):
    time.sleep(1)
    run("docker", "exec", SVC, "pkill", "-x", "tcpdump")
    time.sleep(0.5)
    return run("docker", "exec", SVC, "tcpdump", "-n", "-vv", "-r", f"/srv/dhcp/{name}.pcap")[1]


def client(*extra):
    run("docker", "exec", CLIENT, "ip", "addr", "flush", "dev", "eth1")
    rc, out = run("docker", "exec", CLIENT, "udhcpc", "-i", "eth1", "-n", "-q", "-f", "-t", "3", "-T", "2", "-s", "/bin/true", *extra,
                  timeout=40)
    return {"rc": rc, "lease_obtained": rc == 0, "output": [l for l in out.splitlines() if "udhcpc" in l][-6:]}


def summarize(pcap):
    keep = [l.strip() for l in pcap.splitlines() if any(k in l for k in ("Agent-Information", "Circuit-ID", "Remote-ID", "Gateway-IP",
                                                                          "DHCP-Message", "BOOTP/DHCP", "Your-IP"))]
    return keep[:40]



def main():
    """The live run (needs the fixture up): every step's output goes to the evidence file."""
    evidence = {"schema": "nmas.v2.phase9.option82.live/1", "started_at": datetime.now(timezone.utc).isoformat(),
                "fixture": "labs/phase9-option82-isolated (docker --network none + veth; cEOS relay, ISC dhcpd, alpine udhcpc)",
                "relay_version": [l for l in cli("show version").splitlines() if "Software image" in l or "cEOS" in l][:2]}
    pre_text = cli("show running-config")
    pre = o82.parse_eos(pre_text)
    evidence["pre"] = {"digest": o82.config_digest(pre_text), "readback": pre}
    intent = o82.Option82Intent("Ethernet1", circuit_id="", remote_id="P9-R6")
    evidence["intent"] = intent.__dict__
    evidence["validation"] = o82.validate_intent("arista_ceos", intent)
    rendered = o82.render_eos(intent)
    evidence["rendered"] = rendered

    # ISC policy rendered by NMAS: one reservation bound to giaddr 10.254.90.1 AND circuit id Ethernet1 (no dynamic pool)
    policy = dhcp_base.BootstrapPolicy("p9-option82", "10.254.90.0/24", "10.254.90.1", "10.254.91.0/30", (
        dhcp_base.Reservation("ZTP-P9-1", "P9NEW", "10.254.90.10", "10.254.90.1", "Ethernet1"),))
    conf = IscDhcpProvider(config_root=str(RUNTIME / "dhcp")).render(policy)
    (RUNTIME / "dhcp" / "dhcpd.conf").write_text(conf)
    evidence["isc"] = {"config_sha256": dhcp_base.sha256_text(conf),
                       "match_lines": [l.strip() for l in conf.splitlines() if "match if" in l],
                       "dhcpd_t": run("docker", "exec", SVC, "dhcpd", "-t", "-cf", "/srv/dhcp/dhcpd.conf")[0]}
    time.sleep(5)
    evidence["isc"]["dhcpd_running"] = run("docker", "exec", SVC, "pgrep", "-x", "dhcpd")[0] == 0

    # negative before apply: relay without option 82 forwards no circuit id -> no class match -> no lease
    capture_start("before")
    evidence["negative_before_apply"] = {"client": client(), "packets": summarize(capture_stop("before"))}

    evidence["apply"] = apply(rendered)
    post_text = cli("show running-config")
    post = o82.parse_eos(post_text)
    network = SimpleNamespace(name="p9-option82", service_address="10.254.91.2",
                              trusted_relays=[{"relay_address": "10.254.90.1", "upstream_device": "P9RELAY"}])
    attachment = SimpleNamespace(upstream_device="P9RELAY", upstream_interface="Ethernet1", approval_state="APPROVED",
                                 verification_state="VERIFIED")
    evidence["post"] = {"digest": o82.config_digest(post_text), "readback": post, "postcheck": o82.postcheck(intent, post),
                        "effective_circuit_id": o82.effective_circuit_id(post, "Ethernet1"),
                        "ztp_relay_trust_problems": o82.relay_trust_problems(network=network, attachment=attachment, readback=post),
                        "interface_section": cli("show running-config interfaces Ethernet1").splitlines()[-4:]}

    capture_start("positive")
    positive = client()
    evidence["positive"] = {"client": positive, "packets": summarize(capture_stop("positive")),
                            "dhcpd_log": [l for l in run("docker", "exec", SVC, "tail", "-n", "30", "/srv/dhcp/dhcpd.log")[1].splitlines()
                                          if "DHCP" in l][-8:]}
    leases = run("docker", "exec", SVC, "cat", "/srv/dhcp/dhcpd.leases")[1]
    evidence["positive"]["parsed_leases"] = [{k: r.get(k) for k in ("address", "relay_address", "circuit_id", "remote_id", "binding_state")}
                                             for r in IscDhcpProvider(config_root=str(RUNTIME / "dhcp")).parse_leases(leases)]

    # forged: the client inserts its own option 82 (sub-option 1 'Ethernet1') -- with relay option 82 ON
    forged_hex = "0109" + "Ethernet1".encode().hex() + "0205" + "FORGE".encode().hex()
    capture_start("forged_on")
    evidence["forged_client_option82_relay_on"] = {"client": client("-x", f"0x52:{forged_hex}"), "packets": summarize(capture_stop("forged_on"))}

    # shared-giaddr attack: a reservation bound to circuit 'Ethernet7' (another port behind the SAME giaddr); the client on
    # Ethernet1 forges circuit 'Ethernet7'.  A lease here proves the circuit id alone is forgeable on this relay.
    policy7 = dhcp_base.BootstrapPolicy("p9-option82", "10.254.90.0/24", "10.254.90.1", "10.254.91.0/30", (
        dhcp_base.Reservation("ZTP-P9-7", "P9OTHER", "10.254.90.17", "10.254.90.1", "Ethernet7"),))
    (RUNTIME / "dhcp" / "dhcpd.conf").write_text(IscDhcpProvider(config_root=str(RUNTIME / "dhcp")).render(policy7))
    (RUNTIME / "dhcp" / "restart").touch()
    time.sleep(6)
    forged7 = "0109" + "Ethernet7".encode().hex()
    capture_start("forged7")
    evidence["shared_giaddr_forged_circuit"] = {"reservation_circuit": "Ethernet7", "client_port": "Ethernet1",
                                                "client": client("-x", f"0x52:{forged7}"), "packets": summarize(capture_stop("forged7"))}
    evidence["shared_giaddr_honest_client"] = {"client": client()}
    (RUNTIME / "dhcp" / "dhcpd.conf").write_text(conf)
    (RUNTIME / "dhcp" / "restart").touch()
    time.sleep(6)
    svi = {"enabled": True, "interfaces": {"Vlan90": {"circuit_id": "", "remote_id": "", "helpers": ["10.254.91.2"], "addresses": ["10.254.90.1"]}}}
    evidence["ztp_gate_refuses_shared_giaddr_port"] = o82.relay_trust_problems(
        network=network, attachment=SimpleNamespace(upstream_device="P9RELAY", upstream_interface="Vlan90", approval_state="APPROVED",
                                                    verification_state="VERIFIED"), readback=svi)

    # compensation: exact inverse from the pre-change read-back, then the prior digest must return
    comp = o82.compensation_eos(pre, intent)
    evidence["compensation"] = apply(comp)
    after_text = cli("show running-config")
    evidence["restored"] = {"digest": o82.config_digest(after_text), "equals_pre": o82.config_digest(after_text) == evidence["pre"]["digest"],
                            "readback": o82.parse_eos(after_text),
                            "ztp_relay_trust_problems": o82.relay_trust_problems(network=network, attachment=attachment,
                                                                                 readback=o82.parse_eos(after_text))}
    # forged with relay option 82 OFF (the prior state): what reaches the server, and does ISC grant?
    capture_start("forged_off")
    evidence["forged_client_option82_relay_off"] = {"client": client("-x", f"0x52:{forged_hex}"), "packets": summarize(capture_stop("forged_off"))}
    capture_start("after")
    evidence["negative_after_compensation"] = {"client": client(), "packets": summarize(capture_stop("after"))}
    evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
    OUT.write_text(json.dumps(evidence, indent=2, default=str) + "\n")
    print(json.dumps({k: evidence[k] for k in ("validation", "rendered")}, indent=1))
    print("positive lease:", positive["lease_obtained"], "post:", evidence["post"]["postcheck"], evidence["post"]["ztp_relay_trust_problems"])
    print("neg before:", evidence["negative_before_apply"]["client"]["lease_obtained"],
          "forged on:", evidence["forged_client_option82_relay_on"]["client"]["lease_obtained"],
          "forged off:", evidence["forged_client_option82_relay_off"]["client"]["lease_obtained"],
          "forged7:", evidence["shared_giaddr_forged_circuit"]["client"]["lease_obtained"],
          "honest7:", evidence["shared_giaddr_honest_client"]["client"]["lease_obtained"],
          "after comp:", evidence["negative_after_compensation"]["client"]["lease_obtained"], "restored:", evidence["restored"]["equals_pre"])


if __name__ == "__main__":
    main()
