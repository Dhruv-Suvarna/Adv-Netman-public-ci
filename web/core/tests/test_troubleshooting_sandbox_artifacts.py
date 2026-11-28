"""Static/adversarial checks for staged host containment artifacts."""

import importlib.util
from pathlib import Path

from django.test import SimpleTestCase, override_settings

from core.services.troubleshooting import deployment


ROOT = Path(__file__).resolve().parents[3]
SANDBOX = ROOT / "deploy" / "sandbox"
SPEC = importlib.util.spec_from_file_location("render_policy", SANDBOX / "render_policy.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SandboxArtifactTests(SimpleTestCase):
    def manifest(self):
        return {"topology_id": "srlceos01", "inventory_revision": "a" * 64,
                "deployment_paths": {
                    "production_database": "/home/student/Scripts/clab_dualstack_lab-deploy/web/db.sqlite3",
                    "production_web_directory": "/home/student/Scripts/clab_dualstack_lab-deploy/web",
                    "production_inventory": "/home/student/Scripts/clab_dualstack_lab-deploy/inventory.yml",
                    "device_credential_store": "/home/student/Scripts/clab_dualstack_lab-deploy/monitoring/runtime/device-credentials/store.json"},
                "protected_addresses": ["10.224.77.10", "192.168.200.100", "2001:db8:200::100"],
                "approved_targets": [{"device": "R6", "identity_state": "VERIFIED", "lifecycle_state": "IN_SERVICE",
                                      "admission_state": "ADMITTED", "approved_path_endpoints": ["192.168.200.6", "2001:db8:200::6"]}],
                "dns_resolvers": ["1.1.1.1", "2606:4700:4700::1111"],
                "research_destinations": [{"hostname": "www.rfc-editor.org",
                                             "addresses": ["104.18.20.81", "2606:4700::6812:1451"]}]}

    def test_renders_exact_ipv4_and_ipv6_cgroup_allows_and_default_deny(self):
        out = MODULE.render(self.manifest(), (SANDBOX / "nmas-troubleshooter-device-worker.service.in").read_text(),
                            (SANDBOX / "research-egress.nft.in").read_text())
        service = out["nmas-troubleshooter-device-worker.service"]
        self.assertIn("IPAddressDeny=any", service)
        self.assertIn("IPAddressAllow=192.168.200.6/32", service)
        self.assertIn("IPAddressAllow=2001:db8:200::6/128", service)
        self.assertNotIn("SupplementaryGroups=docker", service)
        self.assertNotIn("ExecStart=docker", service)
        self.assertNotIn("@PRODUCTION_", service)
        self.assertIn("NetworkNamespacePath=/run/netns/nmas-ts-diagnostic", service)
        self.assertIn("InaccessiblePaths=/run/docker.sock", service)
        diagnostic_nft = out["diagnostic-egress.nft"]
        self.assertIn("192.168.200.6 . 22", diagnostic_nft)
        self.assertIn("2001:db8:200::6 . 22", diagnostic_nft)
        self.assertIn("policy drop", diagnostic_nft)
        for chain in ("input", "forward", "output"):
            self.assertIn(f"chain {chain}", diagnostic_nft)
        self.assertIn("nd-neighbor-solicit", diagnostic_nft)
        self.assertEqual(out["diagnostic-targets.env"], "TARGETS=tcp:192.168.200.6:22 tcp:[2001:db8:200::6]:22\n")
        self.assertEqual(out["research-targets.env"],
                         "HTTPS_TARGETS=tcp:104.18.20.81:443 tcp:[2606:4700::6812:1451]:443\n")
        runtime = out["nmas-troubleshooter-runtime@.service"]
        self.assertIn("User=nmas-ts-runtime", runtime)
        self.assertIn("PrivateNetwork=yes", runtime)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", runtime)
        self.assertIn("IPAddressDeny=any", runtime)
        self.assertIn("BindPaths=/home/student/Scripts/clab_dualstack_lab-deploy/web:/var/lib/nmas-ts-runtime/dbroot", runtime)
        self.assertIn("StateDirectory=nmas-ts-runtime", runtime)
        self.assertNotIn("BindPaths=/home/student/Scripts/clab_dualstack_lab-deploy/web/db.sqlite3:/opt/nmas/current/web/db.sqlite3", runtime)
        self.assertNotIn("@PRODUCTION_", runtime)

    def test_research_namespace_blocks_private_metadata_and_mapped_ipv4(self):
        nft = (SANDBOX / "research-egress.nft.in").read_text()
        for value in ("10.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16", "fc00::/7", "fe80::/10", "::ffff:0:0/96"):
            self.assertIn(value, nft)
        self.assertIn("set https4 { type ipv4_addr . inet_service; @HTTPS4@ }", nft)
        self.assertIn("ip daddr . tcp dport @https4 accept", nft)
        self.assertNotIn("meta l4proto tcp tcp dport 443 accept", nft)
        self.assertNotIn('oifname "lo" accept', nft)

    def test_workers_are_distinct_unprivileged_identities_with_separate_sockets_and_state(self):
        device = (SANDBOX / "nmas-troubleshooter-device-worker.service.in").read_text()
        research = (SANDBOX / "nmas-research-broker.service.in").read_text()
        self.assertIn("User=nmas-ts-diagnostic", device)
        self.assertIn("User=nmas-research", research)
        self.assertIn("CapabilityBoundingSet=\n", device)
        self.assertIn("CapabilityBoundingSet=\n", research)
        self.assertIn("/var/lib/nmas-ts-diagnostic", device)
        self.assertNotIn("device-credentials", research.replace("/opt/nmas/current/monitoring/runtime/device-credentials", ""))
        self.assertIn("NetworkNamespacePath=/run/netns/nmas-ts-research", research)
        self.assertIn("BindReadOnlyPaths=/etc/netns/nmas-ts-research/resolv.conf:/etc/resolv.conf", research)
        for optional_protected_path in (
            "/etc/nmas/troubleshooter-device-worker.env",
            "/var/lib/nmas-ts-diagnostic",
            "/var/log/nmas-ts-diagnostic",
            "/opt/nmas/current/web/db.sqlite3",
            "/opt/nmas/current/device_configs",
            "/opt/nmas/current/configs",
        ):
            self.assertIn(f"-{optional_protected_path}", research)
            self.assertNotIn(f" {optional_protected_path}", research)
        for required_protected_path in (
            "/run/docker.sock",
            "/var/run/docker.sock",
            "/run/containerd/containerd.sock",
            "/opt/nmas/current/inventory.yml",
            "/opt/nmas/current/monitoring",
        ):
            self.assertIn(required_protected_path, research)
        self.assertIn("service-preflight research /etc/nmas/research-namespace.env", research)
        self.assertIn("ConditionPathExists=/etc/netns/nmas-ts-research/resolv.conf", research)
        namespace = (SANDBOX / "namespace-activate.sh").read_text()
        controller = (SANDBOX / "namespace_activation.py").read_text()
        self.assertIn("namespace_activation.py", namespace)
        self.assertIn('"preflight", "service-preflight", "prepare-resolver", "activate", "validate", "deactivate", "rollback"', controller)
        self.assertIn('"nmas-ts-diagnostic"', controller)
        self.assertIn('"nmas-ts-research"', controller)
        self.assertIn("state ownership mismatch", controller)
        self.assertNotIn("ip route get", controller)
        # VM-local veth only: no child of an existing interface, no bridge membership, and no
        # change to host forwarding, existing addresses, default routes or foreign firewall tables.
        for forbidden in ("ipvlan", "macvlan", '"master"', "PARENT_INTERFACE", "SOURCE_UNIQUENESS", "flush ruleset", "flush table",
                          "iptables", "DOCKER", '"default", "via", family["gateway"], "dev", config["egress"]'):
            self.assertNotIn(forbidden, controller.replace('host_end.get("master")', ""))
        self.assertIn('"type", "veth"', controller)
        self.assertIn("the controller never changes it", controller)
        for template, egress in (("diagnostic-namespace.env.in", "@DIAGNOSTIC_EGRESS_INTERFACE@"),
                                 ("research-namespace.env.in", "@RESEARCH_EGRESS_INTERFACE@")):
            text = (SANDBOX / template).read_text()
            self.assertIn(f"EGRESS_INTERFACE={egress}", text)
            self.assertIn("HOST_NETWORKING_APPROVAL_ID=@", text)
            self.assertNotIn("SOURCE_CIDR", text)
            self.assertNotIn("UPSTREAM_ACL", text)
        retired = (SANDBOX / "troubleshooter-namespaces.env.in").read_text()
        self.assertIn("RETIRED COMBINED TEMPLATE", retired)
        self.assertTrue((SANDBOX / "diagnostic-namespace.env.in").is_file())
        self.assertTrue((SANDBOX / "research-namespace.env.in").is_file())
        sysusers = (SANDBOX / "nmas-troubleshooter.sysusers.in").read_text()
        self.assertIn("g nmas-ts-model-ipc -", sysusers)
        self.assertIn("m nmas-ts-runtime nmas-ts-model-ipc", sysusers)
        runtime_env = (SANDBOX / "troubleshooter-ipc-client.env.in").read_text()
        self.assertIn("TROUBLESHOOTING_AI_PROVIDER=core.services.troubleshooting.model_provider.completion_only_provider", runtime_env)
        self.assertIn("NMAS_TS_RUNTIME_DATABASE=/var/lib/nmas-ts-runtime/db.sqlite3", runtime_env)

    def test_host_policy_is_scoped_to_the_owned_veth_and_mirrors_namespace_denies(self):
        spec = importlib.util.spec_from_file_location("namespace_activation", SANDBOX / "namespace_activation.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        template = (SANDBOX / "research-egress.nft.in").read_text()
        for network in module.RESEARCH_DENY4 + module.RESEARCH_DENY6:
            self.assertIn(network, template)
        link4 = {"source": "169.254.87.2/30", "gateway": "169.254.87.1", "network": "169.254.87.0/30"}
        base = {"activation_id": "TEST-ACTIVATION-0001", "config_digest": "0" * 64, "extra_deny": [], "targets": [],
                "https_targets": [],
                "dns_servers": [], "ipv6": None}
        research = module.host_policy({**base, "kind": "research", "host_interface": "nmas-ts-resh0", "egress": "ens33",
                                       "host_table": "nmas_host_research", "dns_servers": ["1.1.1.1"],
                                       "https_targets": [["93.184.216.34", 443]],
                                       "extra_deny": ["128.138.0.0/16"], "ipv4": {**link4, "nat": "masquerade"}})
        diagnostic = module.host_policy({**base, "kind": "diagnostic", "host_interface": "nmas-ts-diagh0",
                                         "egress": "nmas-mgmt", "host_table": "nmas_host_diagnostic",
                                         "targets": [["192.168.200.6", 22]],
                                         "ipv4": {**link4, "nat": "192.168.200.100"}})
        for policy, link in ((research, "nmas-ts-resh0"), (diagnostic, "nmas-ts-diagh0")):
            self.assertEqual(policy.count("table "), 1)
            self.assertIn(f'iifname != "{link}" return', policy)
            self.assertIn(f'oifname != "{link}" return', policy)
            self.assertIn(f'iifname != "{link}" oifname != "{link}" return', policy)
            self.assertNotIn("policy drop", policy)  # never a host-wide default; only the owned link is dropped
            self.assertNotIn("ip6 saddr", policy)  # a disabled family gets no accept and no NAT rule
            for line in policy.splitlines():
                if line.strip().endswith(("accept", "masquerade")) or " snat " in line:
                    self.assertTrue(link in line or "icmpv6" in line or "saddr 169.254.87.2" in line, line)
        self.assertIn('oifname != "ens33" counter drop', research)
        self.assertIn("128.138.0.0/16", research)
        self.assertIn("192.168.0.0/16", research)
        self.assertLess(research.index("@deny4 counter drop"), research.index("@https4 accept"))
        self.assertIn("93.184.216.34 . 443", research)
        self.assertIn('iifname "nmas-ts-resh0" oifname "ens33" ip saddr 169.254.87.2 masquerade', research)
        self.assertIn('oifname != "nmas-mgmt" counter drop', diagnostic)
        self.assertIn("192.168.200.6 . 22", diagnostic)
        self.assertIn("snat ip to 192.168.200.100", diagnostic)
        self.assertNotIn("masquerade", diagnostic)
        self.assertNotIn("dport 443", diagnostic)

    def test_r5_unverified_protected_and_empty_scope_are_refused(self):
        cases = []
        r5 = self.manifest(); r5["approved_targets"][0]["device"] = "R5"; cases.append(r5)
        unverified = self.manifest(); unverified["approved_targets"][0]["identity_state"] = "UNVERIFIED"; cases.append(unverified)
        protected = self.manifest(); protected["approved_targets"][0]["approved_path_endpoints"] = ["192.168.200.100"]; cases.append(protected)
        empty = self.manifest(); empty["approved_targets"] = []; cases.append(empty)
        for manifest in cases:
            with self.assertRaises(MODULE.ManifestRefused):
                MODULE.validate(manifest)

    @override_settings(NMAS_TS_SANDBOX_ENFORCEMENT=True,
                       NMAS_TS_DEPLOYMENT={"cli_transport_factory": "unsafe.provider.factory"})
    def test_production_settings_refuse_direct_network_provider(self):
        deps = deployment.runtime_deps()
        self.assertIsNone(deps.cli_transport)
        self.assertTrue(any("config" in problem for problem in deps.deployment_problems))


class ModelBrokerArtifactTests(SimpleTestCase):
    """Deployment templates for the three completion-only model brokers and the lease-bound dispatch unit."""

    def test_broker_unit_is_completion_only_and_cannot_reach_private_networks(self):
        unit = (SANDBOX / "nmas-ts-model-broker@.service.in").read_text()
        for line in ("User=nmas-ts-model-%i", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectSystem=strict",
                     "RestrictAddressFamilies=AF_UNIX AF_INET", "IPAddressAllow=127.0.0.53/32", "SocketBindDeny=any",
                     "ExecStart=/opt/nmas-model/venv/bin/python -s -m core.services.troubleshooting.model_broker"):
            self.assertIn(line + "\n", unit)
        deny = next(line for line in unit.splitlines() if line.startswith("IPAddressDeny="))
        for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "::/0"):
            self.assertIn(network, deny.split("=", 1)[1].split())
        inaccessible = next(line for line in unit.splitlines() if line.startswith("InaccessiblePaths="))
        # The broker runs from its own minimal code tree; the worker runtime (a full source copy with inventory and
        # monitoring), every home directory and the other NMAS secret files are not reachable at all.
        self.assertIn("WorkingDirectory=/opt/nmas-model/current/web\n", unit)
        self.assertNotIn("/opt/nmas/current", unit)
        for path in ("/run/docker.sock", "/run/containerd/containerd.sock", "-/opt/nmas", "-/home", "-/etc/nmas/nmas-web.env",
                     "-/etc/nmas/troubleshooter-ipc-client.env"):
            self.assertIn(path, inaccessible.split("=", 1)[1].split())
        self.assertNotIn("[Install]\n", unit)
        self.assertNotIn("ExecStartPre", unit)

    def test_each_broker_has_its_own_locked_identity_key_and_credential_slot(self):
        sysusers = (SANDBOX / "nmas-ts-model.sysusers.in").read_text()
        for slug in ("codex", "claude-a", "claude-b"):
            self.assertIn(f"u nmas-ts-model-{slug} - ", sysusers)
            self.assertIn(f"m nmas-ts-model-{slug} nmas-ts-model-ipc", sysusers)
        self.assertEqual(sysusers.count("/usr/sbin/nologin"), 3)
        self.assertNotIn("docker", sysusers)
        self.assertNotIn("sudo", sysusers)
        env = (SANDBOX / "model-broker.env.in").read_text()
        for key in ("NMAS_TS_MODEL_AGENT=@AGENT@", "NMAS_TS_MODEL_IPC_KEY=@MODEL_IPC_KEY@",
                    "NMAS_TS_MODEL_PROVIDER_CREDENTIAL=@PROVIDER_CREDENTIAL@", "NMAS_TS_MODEL_CLIENT_UID=@RUNTIME_UID@"):
            self.assertIn(key, env)
        self.assertEqual((SANDBOX / "nmas-ts-model.tmpfiles.in").read_text().splitlines()[-1],
                         "d /run/nmas-ts-model 1770 root nmas-ts-model-ipc -")

    def test_dispatch_unit_keeps_runtime_containment_and_holds_no_provider_credential(self):
        runtime = (SANDBOX / "nmas-troubleshooter-runtime@.service.in").read_text()
        dispatch = (SANDBOX / "nmas-troubleshooter-dispatch@.service.in").read_text()
        self.assertIn("manage.py troubleshooting_ai dispatch --handoff %i --tenant default --actor nmas-ts-runtime\n", dispatch)
        self.assertIn("WorkingDirectory=/opt/nmas-dispatch/current/web\n", dispatch)
        self.assertIn("ExecStart=/opt/nmas-dispatch/venv/bin/python /opt/nmas-dispatch/current/web/manage.py ", dispatch)
        self.assertIn("BindPaths=@PRODUCTION_WEB_DIRECTORY@/db.sqlite3:/var/lib/nmas-ts-runtime/db.sqlite3\n", dispatch)
        self.assertNotIn("BindPaths=@PRODUCTION_WEB_DIRECTORY@:/", dispatch)
        hardening = [line for line in runtime.splitlines() if "=" in line and not line.startswith(
            ("Description", "After", "Requires", "WorkingDirectory", "ExecStart", "ReadOnlyPaths", "BindReadOnlyPaths",
             "BindPaths", "InaccessiblePaths", "TimeoutStartSec"))]
        for line in hardening:
            self.assertIn(line + "\n", dispatch)
        self.assertIn("PrivateNetwork=yes\n", dispatch)
        inaccessible = next(line for line in dispatch.splitlines() if line.startswith("InaccessiblePaths=")).split("=", 1)[1].split()
        for slug in ("codex", "claude-a", "claude-b"):
            self.assertIn(f"-/etc/nmas/model-broker-{slug}.env", inaccessible)
        runtime_env = (SANDBOX / "troubleshooter-ipc-client.env.in").read_text()
        self.assertNotIn("PROVIDER_CREDENTIAL", runtime_env)
        self.assertIn("NMAS_TS_RUNTIME_DATABASE=/var/lib/nmas-ts-runtime/db.sqlite3\n", runtime_env)
        for prefix in ("CODEX", "CLAUDEA", "CLAUDEB"):
            self.assertIn(f"NMAS_TS_{prefix}_MODEL_IPC_KEY=@{prefix}_MODEL_IPC_KEY@", runtime_env)
