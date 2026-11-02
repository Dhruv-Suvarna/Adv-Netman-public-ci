"""Lab 7 -- structured (YAML / JSON) and executable (shell / systemd / service configuration) artifacts, systematically.

    CFG:<path>:LOAD:POSITIVE        the tracked file goes through the loader NMAS really uses (cpu_alerts.load_policy,
                                    topology.load_config, nmas.validate_inventory, populate_netbox.load_manifest, the
                                    template package loader, the governance policy / schema loaders) and its required
                                    keys / references hold; externally consumed files get their structure checked
    CFG:<path>:MALFORMED:NEGATIVE   a malformed / incomplete COPY in a temporary directory is refused by that loader
                                    (externally consumed files are EXEMPT: NMAS has no loader that could refuse them)
    EXE:<path>:STATIC:POSITIVE      shell: ``bash -n`` parse (never executed), shebang, strict mode; systemd: required
                                    sections and keys, absolute (or installer-substituted) ExecStart; service
                                    configuration: balanced structure.  Nothing on the host is changed.

A structured artifact whose consumer does no validation at all (it is read verbatim) has no negative case here: that is
shown as a MISSING case in the Unit Test Matrix, not hidden.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import yaml
from django.test import SimpleTestCase

from core.services.test_governance import inventory, policy as policy_module, schema
from core.services.test_governance.cases import NEGATIVE, POSITIVE, case
from core.services.test_governance.constants import REPO_ROOT, ArtifactType, Scope

if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from modules import cpu_alerts, gnmi, monitoring_config, nmas, snmp, topology  # noqa: E402
from modules.nmas import NmasError  # noqa: E402


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(f"tg_{name}", REPO_ROOT / "netbox" / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _yaml(path: str) -> dict:
    return yaml.safe_load((REPO_ROOT / path).read_text(encoding="utf-8"))


def _copy(path: str, mutate) -> Path:
    tmp = Path(tempfile.mkdtemp())
    data = _yaml(path)
    mutate(data)
    target = tmp / Path(path).name
    target.write_text(yaml.safe_dump(data), encoding="utf-8")
    return target


def cfg(path: str, stage: str, polarity: str, condition: str, expected: str):
    return case(f"CFG:{path}:{stage}:{polarity}", target=path, polarity=polarity, condition=condition, expected=expected)


INVENTORY, CPU, TOPO, IPAM = "inventory.yml", "monitoring/config/cpu_threshold_policy.yml", "monitoring/config/topology.yml", "netbox/ipam.yml"
GNMI, OIDS, POLICY, SCHEMA = "monitoring/config/gnmi_paths.yml", "monitoring/config/snmp_oids.yml", \
    "web/core/services/test_governance/policy.yml", "web/core/services/test_governance/report.schema.json"
GOV_BASELINE = "web/core/services/test_governance/baseline.json"
BASELINES = sorted(p.relative_to(REPO_ROOT).as_posix() for p in (REPO_ROOT / "templates" / "baselines").glob("*.nmas-template.yaml"))


class InventoryAndPolicyLoaderTests(SimpleTestCase):
    @cfg(INVENTORY, "LOAD", POSITIVE, "the tracked Lab-1 inventory", "nmas.validate_inventory accepts it; every device names an existing template")
    def test_inventory_loads_and_references_resolve(self):
        nmas.validate_inventory(require_address=False)
        inv = _yaml(INVENTORY)
        self.assertEqual(sorted(inv["network_devices"]), ["R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4", "mgmt_swt"])
        for name, meta in inv["network_devices"].items():
            with self.subTest(device=name):
                self.assertTrue((REPO_ROOT / "templates" / meta["template"]).is_file())

    @cfg(INVENTORY, "MALFORMED", NEGATIVE, "an inventory whose NMAS address no longer matches the receiver bindings / no host interface",
         "NmasError: the inventory is refused before any receiver is provisioned")
    def test_inventory_with_wrong_receiver_address_is_refused(self):
        for mutate, label in ((lambda d: d["management"].update(nmas_ipv4="192.168.200.99/24"), "wrong address"),
                              (lambda d: d["management"].pop("host_interface"), "no host interface")):
            target = _copy(INVENTORY, mutate)
            with self.subTest(case=f"invalid {label}"), mock.patch.object(nmas, "BASE", target.parent):
                with self.assertRaises(NmasError):
                    nmas.validate_inventory(require_address=False)

    @cfg(CPU, "LOAD", POSITIVE, "the tracked CPU threshold policy", "load_policy returns 0 < recovery < warning < critical <= 100")
    def test_cpu_policy_loads(self):
        policy = cpu_alerts.load_policy()
        self.assertLess(policy["recovery_pct"], policy["warning_pct"])
        self.assertLess(policy["warning_pct"], policy["critical_pct"])
        self.assertEqual(cpu_alerts.classify(policy["critical_pct"] + 1, policy)[0], "critical")

    @cfg(CPU, "MALFORMED", NEGATIVE, "a CPU policy with a missing key / inverted thresholds / zero samples", "NmasError for each")
    def test_malformed_cpu_policy_is_refused(self):
        for mutate, label in ((lambda d: d.pop("critical_pct"), "missing critical_pct"),
                              (lambda d: d.update(warning_pct=99, critical_pct=50), "inverted thresholds"),
                              (lambda d: d.update(consecutive_samples=0), "zero samples")):
            target = _copy(CPU, mutate)
            with self.subTest(case=f"invalid {label}"), mock.patch.object(cpu_alerts, "POLICY_FILE", target):
                with self.assertRaises(cpu_alerts.NmasError):
                    cpu_alerts.load_policy()

    @cfg(TOPO, "LOAD", POSITIVE, "the tracked dynamic-topology configuration", "load_config returns it; loopback-only bind")
    def test_topology_config_loads(self):
        config = topology.load_config()
        self.assertEqual(config["bind_address"], "127.0.0.1")

    @cfg(TOPO, "MALFORMED", NEGATIVE, "a topology configuration binding 0.0.0.0 / missing keys / healthy >= stale", "NmasError for each")
    def test_malformed_topology_config_is_refused(self):
        for mutate, label in ((lambda d: d.update(bind_address="0.0.0.0"), "public bind"), (lambda d: d.pop("port"), "missing port"),
                              (lambda d: d.update(healthy_seconds=999, stale_seconds=10), "healthy after stale")):
            target = _copy(TOPO, mutate)
            with self.subTest(case=f"invalid {label}"), mock.patch.object(topology, "CONFIG_PATH", target):
                with self.assertRaises(topology.NmasError):
                    topology.load_config()

    @cfg(IPAM, "LOAD", POSITIVE, "the tracked NetBox desired-state manifest", "populate_netbox.load_manifest validates it (no duplicates, no dangling references)")
    def test_ipam_manifest_loads(self):
        manifest = _load_script("populate_netbox").load_manifest()
        self.assertTrue(manifest["prefixes"])
        self.assertIn(200, {v["vid"] for v in manifest["vlans"]})

    @cfg(IPAM, "MALFORMED", NEGATIVE, "a manifest with a duplicated VLAN id / a malformed prefix", "ValueError naming the defect; NetBox is never touched")
    def test_malformed_ipam_manifest_is_refused(self):
        populate = _load_script("populate_netbox")
        for mutate, label in ((lambda d: d["vlans"].append(dict(d["vlans"][0])), "duplicate VLAN"),
                              (lambda d: d["prefixes"][0].update(prefix="10.0.0.0/99"), "malformed prefix")):
            target = _copy(IPAM, mutate)
            with self.subTest(case=f"invalid {label}"):
                with self.assertRaises(ValueError):
                    populate.load_manifest(target)

    @cfg(GNMI, "LOAD", POSITIVE, "the tracked gNMI subscription inventory",
         "monitoring_config.load_gnmi_paths validates it; modules.gnmi uses exactly that; 6 unique paths and fields")
    def test_gnmi_paths_load(self):
        loaded = monitoring_config.load_gnmi_paths()
        self.assertEqual(gnmi.PATHS_CONFIG, loaded)
        self.assertEqual(loaded["sample_interval_ns"], 20_000_000_000)
        self.assertEqual([s["path"] for s in loaded["streams"]],
                         ["/system/state/hostname", "/system/cpus/cpu[index=*]/state/total/instant", "/system/memory/state",
                          "/interfaces/interface[name=*]/state/oper-status", "/interfaces/interface[name=*]/state/admin-status",
                          "/interfaces/interface[name=*]/state/counters"])

    @cfg(GNMI, "MALFORMED", NEGATIVE,
         "malformed YAML / duplicate key / missing interval / interval of the wrong type or out of range / empty streams / "
         "relative path / duplicated path / unknown kind / duplicated field / non-identifier measurement",
         "NmasError naming the defect for each; the collector never receives the file")
    def test_malformed_gnmi_paths_are_refused(self):
        def stream(i, **change):
            return lambda d: d["streams"][i].update(change)
        mutations = {
            "missing sample_interval_ns": lambda d: d.pop("sample_interval_ns"),
            "interval wrong type": lambda d: d.update(sample_interval_ns="20s"),
            "interval bool": lambda d: d.update(sample_interval_ns=True),
            "interval too short": lambda d: d.update(sample_interval_ns=10),
            "empty streams": lambda d: d.update(streams=[]),
            "stream not a mapping": lambda d: d["streams"].append("/x"),
            "relative path": stream(0, path="system/state/hostname"),
            "duplicate path": stream(1, path="/system/state/hostname"),
            "unknown kind": stream(0, kind="float"),
            "duplicate field": stream(1, field="hostname"),
            "invalid measurement": stream(0, measurement="gnmi telemetry"),
            "missing description": stream(0, description=""),
            "invalid tags": stream(1, tags=["CPU Index"]),
            "limitations not strings": lambda d: d.update(limitations=[1]),
        }
        for label, mutate in mutations.items():
            target = _copy(GNMI, mutate)
            with self.subTest(case=f"invalid {label}"), self.assertRaises(NmasError):
                monitoring_config.load_gnmi_paths(target)
        tmp = Path(tempfile.mkdtemp())
        for label, text in (("malformed YAML", "streams: [\n"), ("not a mapping", "- a\n- b\n"),
                            ("duplicate key", (REPO_ROOT / GNMI).read_text() + "sample_interval_ns: 1000000000\n")):
            (tmp / "g.yml").write_text(text)
            with self.subTest(case=f"invalid {label}"), self.assertRaises(NmasError) as caught:
                monitoring_config.load_gnmi_paths(tmp / "g.yml")
            self.assertIn("gnmi_paths.yml", str(caught.exception))
        with self.assertRaises(NmasError):
            monitoring_config.load_gnmi_paths(tmp / "missing.yml")

    @cfg(OIDS, "LOAD", POSITIVE, "the tracked SNMP OID map",
         "monitoring_config.load_snmp_oids validates it; modules.snmp uses exactly that; every referenced OID is numeric")
    def test_snmp_oids_load(self):
        loaded = monitoring_config.load_snmp_oids()
        self.assertEqual(snmp.OIDS, loaded)
        self.assertEqual((loaded["ifOperStatus"], loaded["linkDown"], loaded["cpu"]),
                         ("1.3.6.1.2.1.2.2.1.8", "1.3.6.1.6.3.1.1.5.3", {"ceos": "1.3.6.1.2.1.25.3.3.1.2", "linux": "1.3.6.1.2.1.25.3.3.1.2"}))

    @cfg(OIDS, "MALFORMED", NEGATIVE,
         "a missing OID / a non-numeric OID / an OID of the wrong type / an unknown or missing CPU platform / two names sharing "
         "one OID / a duplicated YAML key / malformed YAML",
         "NmasError naming the defect for each; the poller never starts with it")
    def test_malformed_snmp_oids_are_refused(self):
        mutations = {
            "missing linkDown": lambda d: d.pop("linkDown"),
            "missing cpu": lambda d: d.pop("cpu"),
            "symbolic OID": lambda d: d.update(sysName="SNMPv2-MIB::sysName.0"),
            "OID wrong type": lambda d: d.update(ifIndex=1.3),
            "OID leading dot": lambda d: d.update(ifName=".1.3.6.1.2.1.31.1.1.1.1"),
            "unknown cpu platform": lambda d: d["cpu"].update(junos="1.3.6.1.2.1.25.3.3.1.2"),
            "missing cpu platform": lambda d: d["cpu"].pop("linux"),
            "cpu not a mapping": lambda d: d.update(cpu="1.3.6.1.2.1.25.3.3.1.2"),
            "conflicting identifiers": lambda d: d.update(linkUp=d["linkDown"]),
            "non-string name": lambda d: d.update({7: "1.3.6.1"}),
        }
        for label, mutate in mutations.items():
            target = _copy(OIDS, mutate)
            with self.subTest(case=f"invalid {label}"), self.assertRaises(NmasError):
                monitoring_config.load_snmp_oids(target)
        tmp = Path(tempfile.mkdtemp())
        for label, text in (("malformed YAML", "sysName: [\n"), ("duplicate key", (REPO_ROOT / OIDS).read_text() + "sysName: '1.3.6.1.2.1.1.5.0'\n")):
            (tmp / "o.yml").write_text(text)
            with self.subTest(case=f"invalid {label}"), self.assertRaises(NmasError):
                monitoring_config.load_snmp_oids(tmp / "o.yml")

    def test_validate_snmp_oids_returns_the_document_unchanged(self):
        document = _yaml(OIDS)
        self.assertIs(monitoring_config.validate_snmp_oids(document), document)

    def test_validate_snmp_oids_refuses_a_document_without_required_names(self):
        with self.assertRaises(NmasError) as caught:
            monitoring_config.validate_snmp_oids({"cpu": {"ceos": "1.3.6", "linux": "1.3.6"}})
        self.assertTrue(str(caught.exception).startswith("snmp_oids.yml: missing required OID(s): sysName, sysUpTime"))

    def test_validate_gnmi_paths_returns_the_document_unchanged(self):
        document = _yaml(GNMI)
        self.assertIs(monitoring_config.validate_gnmi_paths(document), document)

    def test_validate_gnmi_paths_refuses_an_empty_document(self):
        with self.assertRaises(NmasError) as caught:
            monitoring_config.validate_gnmi_paths({})
        self.assertIn("sample_interval_ns must be an integer", str(caught.exception))

    @cfg(POLICY, "LOAD", POSITIVE, "the tracked governance policy", "load_policy returns groups, exemptions with reasons and the Lab 7 examples")
    def test_governance_policy_loads(self):
        policy = policy_module.load_policy()
        self.assertTrue(all(rule.reason for rule in policy.artifact_exemptions))

    @cfg(POLICY, "MALFORMED", NEGATIVE, "a policy with an exemption that has no reason", "PolicyError")
    def test_malformed_governance_policy_is_refused(self):
        target = _copy(POLICY, lambda d: d["artifact_exemptions"].append({"pattern": "x/**", "reason": ""}))
        with self.assertRaises(policy_module.PolicyError):
            policy_module.load_policy(target)

    @cfg(SCHEMA, "LOAD", POSITIVE, "the tracked report schema", "parses; every keyword it uses is supported by the validator")
    def test_report_schema_loads(self):
        loaded = schema.load_schema()
        self.assertEqual(loaded["properties"]["schema_version"], {"const": 1})
        self.assertEqual(schema.validate({"schema_version": 2}, {"type": "object", "properties": {"schema_version": {"const": 1}}}),
                         ["$.schema_version: must equal 1"])

    @cfg(SCHEMA, "MALFORMED", NEGATIVE, "a schema using a keyword the validator does not implement", "ValueError (never silently ignored)")
    def test_schema_with_unsupported_keyword_is_refused(self):
        with self.assertRaises(ValueError):
            schema.validate({}, {"type": "object", "patternProperties": {}})

    @cfg(GOV_BASELINE, "LOAD", POSITIVE, "the tracked closure-gate baseline (ratchet)",
         "gate.load_baseline returns schema 1 with debt, closed artifacts / cells, locked declared cases and Pylint allowances")
    def test_governance_baseline_loads(self):
        from core.services.test_governance import gate

        data = gate.load_baseline()
        self.assertEqual(data["schema_version"], 1)
        self.assertLessEqual({"case_debt", "closed_artifacts", "closed_cells", "declared_cases", "pylint", "from_payload_sha256"}, set(data))
        self.assertEqual(data["case_debt"], sorted(set(data["case_debt"])))           # sorted, no duplicate debt entries

    @cfg(GOV_BASELINE, "MALFORMED", NEGATIVE, "a baseline with another schema version / not a JSON object / not JSON",
         "refused (ValueError) -- the gate never runs against an unreadable allowance")
    def test_malformed_governance_baseline_is_refused(self):
        from core.services.test_governance import gate

        tmp = Path(tempfile.mkdtemp())
        for label, text in (("schema version 2", json.dumps({"schema_version": 2})), ("a list", "[]"), ("not json", "{debt")):
            target = tmp / "baseline.json"
            target.write_text(text, encoding="utf-8")
            with self.subTest(case=f"invalid {label}"), self.assertRaises(ValueError):
                gate.load_baseline(target)


class TemplateBaselinePackageTests(SimpleTestCase):
    pass


def _add_baseline_cases() -> None:
    from core.services.config_templates import package

    for path in BASELINES:
        slug = re.sub(r"[^a-z0-9]+", "_", Path(path).stem.lower())

        @cfg(path, "LOAD", POSITIVE, "the tracked baseline template package", "the portable package loader accepts it with its manifest and digest")
        def positive(self, path=path):
            loaded = package.load((REPO_ROOT / path).read_bytes())
            self.assertTrue(loaded["manifest"]["template_id"])
            self.assertRegex(loaded["digest"], r"^[0-9a-f]{64}$")

        @cfg(path, "MALFORMED", NEGATIVE, "the same package with an unknown top-level key / wrong kind / truncated",
             "PackageError for each (an untrusted package is never partially imported)")
        def negative(self, path=path):
            raw = (REPO_ROOT / path).read_bytes()
            document = yaml.safe_load(raw)
            for label, data in (("unknown key", yaml.safe_dump({**document, "smuggled": 1}).encode()),
                                ("wrong kind", yaml.safe_dump({**document, "kind": "other"}).encode()),
                                ("truncated", raw[: len(raw) // 3]), ("empty", b"")):
                with self.subTest(case=f"invalid {label}"):
                    with self.assertRaises(package.PackageError):
                        package.load(data)

        setattr(TemplateBaselinePackageTests, f"test_loads_{slug}", positive)
        setattr(TemplateBaselinePackageTests, f"test_refuses_malformed_{slug}", negative)


_add_baseline_cases()


class ExternallyConsumedStructureTests(SimpleTestCase):
    @cfg(".github/workflows/tier3-validation.yml", "LOAD", POSITIVE, "the tracked Tier-3 workflow",
         "read-only permissions; runs tier3.py; uploads the Tier-3 and test-governance artifacts")
    def test_tier3_workflow_structure(self):
        wf = _yaml(".github/workflows/tier3-validation.yml")
        self.assertEqual(wf["permissions"], {"contents": "read"})
        steps = wf["jobs"]["tier3"]["steps"]
        self.assertTrue(any("tier3.py" in str(s.get("run", "")) for s in steps))
        self.assertIn("test-governance", json.dumps(steps))

    @cfg(".github/workflows/configuration-validation.yml", "LOAD", POSITIVE, "the tracked Configuration Validation workflow",
         "repository_dispatch only; read-only permissions")
    def test_configuration_validation_workflow_structure(self):
        wf = _yaml(".github/workflows/configuration-validation.yml")
        self.assertEqual(wf["permissions"], {"contents": "read"})
        self.assertEqual(list((wf.get("on") or wf.get(True))), ["repository_dispatch"])

    def _compose(self, path):
        data = _yaml(path)
        self.assertIsInstance(data.get("services"), dict)
        for name, service in data["services"].items():
            with self.subTest(service=name):
                self.assertTrue(service.get("image") or service.get("build"))
        return data

    @cfg("monitoring/docker-compose.yml", "LOAD", POSITIVE, "the monitoring stack definition", "every service names an image or build")
    def test_monitoring_compose(self):
        self.assertIn("influxdb", self._compose("monitoring/docker-compose.yml")["services"])

    @cfg("monitoring/human_mfa/docker-compose.yml", "LOAD", POSITIVE, "the RADIUS / MFA stack definition", "every service names an image or build")
    def test_human_mfa_compose(self):
        self._compose("monitoring/human_mfa/docker-compose.yml")

    @cfg("netbox/docker-compose.yml", "LOAD", POSITIVE, "the NetBox stack definition", "every service names an image or build")
    def test_netbox_compose(self):
        self.assertIn("netbox", self._compose("netbox/docker-compose.yml")["services"])

    @cfg("monitoring/grafana/provisioning/dashboards/provider.yml", "LOAD", POSITIVE, "the Grafana dashboard provider",
         "apiVersion 1 and a file provider pointing at the generated dashboards")
    def test_grafana_provider(self):
        data = _yaml("monitoring/grafana/provisioning/dashboards/provider.yml")
        self.assertEqual(data["apiVersion"], 1)
        self.assertEqual(data["providers"][0]["type"], "file")

    @cfg("monitoring/grafana/provisioning/datasources/influxdb.yml", "LOAD", POSITIVE, "the Grafana InfluxDB datasource",
         "one InfluxDB datasource; the token is an environment reference, never a literal")
    def test_grafana_datasource(self):
        data = _yaml("monitoring/grafana/provisioning/datasources/influxdb.yml")
        source = data["datasources"][0]
        self.assertEqual(source["type"], "influxdb")
        self.assertRegex(json.dumps(source.get("secureJsonData", {})), r"\$")

    @cfg("srlceos01.clab.yml", "LOAD", POSITIVE, "the frozen Lab-1 containerlab topology",
         "every inventory device is a node; every link endpoint names a node")
    def test_lab_topology(self):
        data = _yaml("srlceos01.clab.yml")
        nodes = data["topology"]["nodes"]
        for device in _yaml(INVENTORY)["network_devices"]:
            with self.subTest(device=device):
                self.assertIn(device, nodes)
        for link in data["topology"]["links"]:
            # brief form ``endpoints: [a:x, b:y]`` or extended form (``type: host`` + one ``endpoint`` mapping)
            names = [e.split(":")[0] for e in link.get("endpoints", ())] or [link["endpoint"]["node"]]
            for name in names:
                self.assertIn(name, nodes)


# --- executables -------------------------------------------------------------------------------------------------------

def _units(text: str) -> dict[str, dict[str, list[str]]]:
    sections: dict[str, dict[str, list[str]]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], {})
            continue
        if current is None or "=" not in line:
            raise ValueError(f"not a unit-file line: {line[:60]!r}")
        key, _, value = line.partition("=")
        current.setdefault(key.strip(), []).append(value.strip())
    return sections


def _sourced_libraries() -> set[str]:
    out = set()
    for script in REPO_ROOT.rglob("*.sh"):
        if "docs" in script.parts:
            continue
        for match in re.findall(r"^\s*(?:source|\.)\s+\"?[^\s\"]*?/?([A-Za-z0-9_.-]+\.sh)", script.read_text(errors="replace"), re.M):
            out.add(match)
    return out


def check_shell(path: str) -> list[str]:
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    problems = []
    if not text.startswith("#!/usr/bin/env bash") and not text.startswith("#!/bin/bash"):
        problems.append("missing bash shebang")
    if shutil.which("bash"):
        proc = subprocess.run(["bash", "-n", str(REPO_ROOT / path)], capture_output=True, text=True, timeout=30, check=False)  # parse only
        if proc.returncode:
            problems.append("bash -n: " + proc.stderr.strip()[:200])
    else:
        problems.append("bash is not available to parse the script")
    if Path(path).name not in _sourced_libraries() and not re.search(r"^set -[a-z]*e[a-z]*u|^set -euo pipefail", text, re.M):
        problems.append("no strict mode (set -euo pipefail) in an executed script")
    return problems


def check_systemd(path: str) -> list[str]:
    units = _units((REPO_ROOT / path).read_text(encoding="utf-8"))
    problems = []
    if "Description" not in units.get("Unit", {}):
        problems.append("[Unit] Description missing")
    suffix = Path(path).suffix
    if suffix == ".service":
        service = units.get("Service", {})
        starts = service.get("ExecStart", [])
        if not starts:
            problems.append("[Service] ExecStart missing")
        for command in starts:
            if not re.match(r"^[-@+!]*(/|@[A-Z_]+@)", command):
                problems.append(f"ExecStart is not an absolute / installer-substituted path: {command[:60]}")
    elif suffix == ".timer":
        timer = units.get("Timer", {})
        if not (timer.get("OnCalendar") or timer.get("OnUnitActiveSec") or timer.get("OnBootSec")):
            problems.append("[Timer] has no schedule")
        if "timers.target" not in " ".join(units.get("Install", {}).get("WantedBy", [])):
            problems.append("timer is not WantedBy timers.target")
    elif suffix == ".socket":
        if not (units.get("Socket", {}).get("ListenStream") or units.get("Socket", {}).get("ListenDatagram")):
            problems.append("[Socket] listens on nothing")
    return problems


def check_config(path: str) -> list[str]:
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    problems = [] if text.strip() else ["empty configuration"]
    if text.lstrip().startswith("["):
        try:
            if not _units(text):
                problems.append("no section")
        except ValueError as exc:
            problems.append(str(exc))
    opened = re.findall(r"^\s*<([A-Za-z]+)[\s>]", text, re.M)
    closed = re.findall(r"^\s*</([A-Za-z]+)>", text, re.M)
    if sorted(opened) != sorted(closed):
        problems.append(f"unbalanced block tags: opened {sorted(opened)} closed {sorted(closed)}")
    return problems


CHECKERS = {ArtifactType.SHELL: check_shell, ArtifactType.SYSTEMD: check_systemd, ArtifactType.CONFIG: check_config}


class ExecutableStaticTests(SimpleTestCase):
    def test_the_checkers_detect_broken_artifacts(self):
        with tempfile.TemporaryDirectory(dir=REPO_ROOT / "web") as tmp:
            rel = Path(tmp).relative_to(REPO_ROOT)
            (Path(tmp) / "broken.sh").write_text("#!/usr/bin/env bash\nif then\n")
            (Path(tmp) / "broken.service").write_text("[Unit]\n[Service]\nExecStart=relative/cmd\n")
            (Path(tmp) / "broken.conf").write_text("<VirtualHost *:80>\n")
            self.assertTrue(any(p.startswith("bash -n") for p in check_shell(f"{rel}/broken.sh")))
            self.assertIn("no strict mode (set -euo pipefail) in an executed script", check_shell(f"{rel}/broken.sh"))
            self.assertEqual(check_systemd(f"{rel}/broken.service"),
                             ["[Unit] Description missing", "ExecStart is not an absolute / installer-substituted path: relative/cmd"])
            self.assertTrue(check_config(f"{rel}/broken.conf")[0].startswith("unbalanced block tags"))


def _add_executable_cases() -> None:
    for artifact in inventory.build_inventory().artifacts:
        if artifact.scope != Scope.CURRENT or artifact.type not in CHECKERS:
            continue
        slug = re.sub(r"[^a-z0-9]+", "_", artifact.path.lower())

        @case(f"EXE:{artifact.path}:STATIC:POSITIVE", target=artifact.path, polarity=POSITIVE,
              condition="static verification of the deployed file (parsed, never executed; the host is not modified)",
              expected="no structural problem (shell: bash -n, shebang, strict mode; systemd: sections / keys / ExecStart; config: structure)")
        def static(self, path=artifact.path, kind=artifact.type):
            self.assertEqual(CHECKERS[kind](path), [])

        setattr(ExecutableStaticTests, f"test_static_{slug}", static)


_add_executable_cases()
