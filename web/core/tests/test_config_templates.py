"""V2 Phase 3 -- intent-based configuration templates: model immutability, extraction, normalization / parameterization,
baselines, the Multilayer Switch semantic combination, portable packages and clone-to-working-intent.

No test contacts a device, NetBox or the network: device reads are fake read-only sessions and the management scope is patched.
"""
from __future__ import annotations

import json
from copy import deepcopy
from types import SimpleNamespace

import yaml
from django.test import SimpleTestCase, TestCase

from core import models
from core.services import change_plan_service as cps
from core.services import change_validation_service as cvs
from core.services import field_commit_service, routing_intent_service
from core.services.config_templates import baselines, clone, combine, normalize, package, schema, secret_scan, service
from core.services.config_workbench import snapshots
from core.tests.helpers import health as h
from core.tests.helpers.validation import make_sources
from core.tests.helpers.workbench import use_scope

SECRET = "TEST_ONLY_TEMPLATE_SECRET_NEVER_REAL"
ACCESS = """hostname {name}
username admin privilege 15 secret sha512 {secret}
snmp-server community {secret} ro
vlan 10,99,200
interface Ethernet1
   description UPLINK_TO_R{n}
   no switchport
   ip address 192.168.110.{up}/31
interface Ethernet2
   description {name}_PEER_TRUNK
   switchport mode trunk
   switchport trunk allowed vlan 10,99
interface Ethernet3
   description HOST_VLAN10
   switchport access vlan 10
interface Loopback0
   description ROUTER-ID
   ip address 192.168.255.1{n}/32
interface Management0
   ip address 172.20.20.1{n}/24
interface Vlan10
   ip address 192.168.10.{gw}/24
   ip helper-address 192.168.200.100
   ip virtual-router address 192.168.10.1
interface Vlan200
   ip address 192.168.200.1{n}/24
   ipv6 address 2001:db8:200::1{n}/64
ip route 0.0.0.0/0 172.20.20.1
ipv6 route 2001:db8::/32 2001:db8:110:{n}::1
router rip
   network 192.168.10.0/24
   no shutdown
end
"""
GATEWAY = """hostname {name}
interface Ethernet1
   description FABRIC_TRUNK
   switchport mode trunk
   switchport trunk allowed vlan 10{n}
interface Ethernet2
   description DOWNLINK_TO_S{n}
   no switchport
   ip address 192.168.110.{down}/31
interface Ethernet3
   description MANAGEMENT
   switchport access vlan 200
interface Loopback0
   description ROUTER-ID
   ip address 192.168.255.{n}/32
   ipv6 address 2001:db8:255::{n}/128
interface Vlan10{n}
   ip address 192.168.100.{n}/31
   ip ospf area 0.0.0.0
interface Vlan200
   ip address 192.168.200.{n}/24
   ipv6 address 2001:db8:200::{n}/64
router ospf 10
   router-id 192.168.255.{n}
end
"""
SPINE = """hostname {name}
interface Ethernet1
   description FABRIC_A
   switchport mode trunk
   switchport trunk allowed vlan 101,10{n}
interface Vlan200
   ip address 192.168.200.1{n}/24
end
"""
FRR = """frr version 8.4.4
hostname {name}
interface Vlan101
 ipv6 ospf6 area 0.0.0.0
exit
router bgp 6500{n}
 bgp router-id 192.168.255.{n}
 neighbor 172.20.5.{n} remote-as 65005
 neighbor 172.20.5.{n} password {secret}
 address-family ipv4 unicast
  network 192.168.10.0/24
 exit-address-family
exit
end
"""


def eos(text, **fmt):
    return h.eos_outputs(config=text.format(secret=SECRET, **fmt))


def frr(name, n):
    return h.linux_outputs(frr_config=FRR.format(name=name, n=n, secret=SECRET),
                           interfaces={"eth0": [f"172.20.20.{n}/24"], "lo": [f"192.168.255.{n}/32"], "Vlan101": [f"192.168.100.{n}/31", f"fe80::{n}/64"],
                                       "Vlan200": [f"192.168.200.{n}/24", f"2001:db8:200::{n}/64"]})


def lab_outputs():
    return {
        "S1": eos(ACCESS, name="S1", n=1, up=1, gw=2), "S2": eos(ACCESS, name="S2", n=2, up=3, gw=3),
        "R1": eos(GATEWAY, name="R1", n=1, down=0), "R2": eos(GATEWAY, name="R2", n=2, down=2),
        "S3": eos(SPINE, name="S3", n=3), "S4": eos(SPINE, name="S4", n=4),
        "R3": frr("R3", 3), "R4": frr("R4", 4),
    }


class Recorder:
    """A read-only session factory that records which devices were contacted."""

    def __init__(self, outputs=None):
        self.devices = []
        self._factory = h.session_factory(outputs or lab_outputs())

    def __call__(self, device):
        self.devices.append(device["name"] if isinstance(device, dict) else str(device))
        return self._factory(device)


def version_blob(version) -> str:
    return json.dumps(package.version_content(version), sort_keys=True)


class LabCase(TestCase):
    def setUp(self):
        use_scope(self)
        self.factory = Recorder()

    def extract(self, device="S1", **kwargs):
        return service.extract_from_device(device, actor="tester", session_factory=self.factory, **kwargs)

    def published(self, device="S1"):
        return service.publish(self.extract(device), actor="approver")


# --- models ------------------------------------------------------------------------------------------------------------
class ImmutabilityTests(LabCase):
    def test_a_published_version_cannot_be_edited_bulk_updated_or_deleted(self):
        version = self.published()
        version.notes = "tampered"
        with self.assertRaises(ValueError):
            version.save()
        fresh = models.ConfigurationTemplateVersion.objects.get(pk=version.pk)
        fresh.intent = {"device": {"hostname": "x"}}
        with self.assertRaises(ValueError):
            fresh.save()
        with self.assertRaises(ValueError):
            models.ConfigurationTemplateVersion.objects.filter(pk=version.pk).update(notes="x")
        with self.assertRaises(ValueError):
            models.ConfigurationTemplateVersion.objects.filter(pk=version.pk).delete()
        with self.assertRaises(ValueError):
            models.ConfigurationTemplateVersion.objects.get(pk=version.pk).delete()
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get(pk=version.pk).notes, "")

    def test_a_draft_can_only_be_published_or_discarded(self):
        draft = self.extract()
        draft.parameters = {}
        with self.assertRaises(ValueError):
            draft.save()
        draft = models.ConfigurationTemplateVersion.objects.get(pk=draft.pk)
        service.publish(draft, actor="approver")
        self.assertTrue(models.ConfigurationTemplateVersion.objects.get(pk=draft.pk).is_published)
        with self.assertRaises(service.TemplateError):
            service.discard_draft(draft, actor="tester")

    def test_template_identity_is_immutable_and_versions_are_numbered(self):
        version = self.published()
        template = version.template
        template.template_id = "TPL-OTHER"
        with self.assertRaises(ValueError):
            template.save()
        template = models.ConfigurationTemplate.objects.get(pk=template.pk)
        second = service.create_version(template, package.version_content(version), actor="tester")
        self.assertEqual((version.version, second.version), (1, 2))
        self.assertEqual(second.digest, version.digest)

    def test_discarding_the_only_draft_removes_the_empty_template(self):
        draft = self.extract()
        service.discard_draft(draft, actor="tester")
        self.assertFalse(models.ConfigurationTemplate.objects.exists())
        self.assertTrue(models.AuditEvent.objects.filter(event_type="TEMPLATE_DRAFT_DISCARDED").exists())


# --- schema / parameters -----------------------------------------------------------------------------------------------
class ParameterTests(SimpleTestCase):
    INTENT = {"device": {"hostname": "{{ hostname }}"}, "interfaces": [
        {"name": "Vlan10", "kind": "SVI", "vlan_id": "{{ vlan }}", "description": "gw of {{ hostname }}",
         "addresses": [{"family": "IPV4", "cidr": "{{ gw }}"}]},
        {"_when": "with_loop", "name": "Loopback9", "kind": "LOOPBACK", "addresses": [{"family": "IPV4", "cidr": "{{ loop }}"}]}]}
    PARAMS = {"hostname": {"type": "hostname", "required": True}, "vlan": {"type": "vlan_id", "required": True, "default": 10},
              "gw": {"type": "ipv4_interface", "required": True}, "loop": {"type": "ipv4_interface", "required": True},
              "with_loop": {"type": "boolean", "required": False, "default": False}}

    def test_typed_and_embedded_placeholders_resolve(self):
        intent, values, problems = schema.resolve(self.INTENT, self.PARAMS, {"hostname": "S9", "gw": "10.0.0.1/24"})
        self.assertEqual(problems, [])
        row = intent["interfaces"][0]
        self.assertEqual((row["vlan_id"], row["description"], row["addresses"][0]["cidr"]), (10, "gw of S9", "10.0.0.1/24"))
        self.assertEqual(len(intent["interfaces"]), 1)                      # the _when object is off and needs no "loop" value
        self.assertNotIn("_when", json.dumps(intent))

    def test_an_enabled_optional_object_requires_its_parameters(self):
        _i, _v, problems = schema.resolve(self.INTENT, self.PARAMS, {"hostname": "S9", "gw": "10.0.0.1/24", "with_loop": True})
        self.assertEqual(problems, ["Parameter loop is required."])
        intent, _v, problems = schema.resolve(self.INTENT, self.PARAMS, {"hostname": "S9", "gw": "10.0.0.1/24", "with_loop": True, "loop": "10.9.9.9/32"})
        self.assertEqual((problems, len(intent["interfaces"])), ([], 2))

    def test_invalid_and_unknown_parameter_values_are_rejected_before_rendering(self):
        for supplied, needle in (({"hostname": "bad name!", "gw": "10.0.0.1/24"}, "hostname"), ({"hostname": "S9", "gw": "not-an-ip"}, "gw"),
                                 ({"hostname": "S9", "gw": "2001:db8::1/64"}, "IPv4"), ({"hostname": "S9", "gw": "10.0.0.1/24", "vlan": 5000}, "vlan"),
                                 ({"hostname": "S9", "gw": "10.0.0.1/24", "rogue": "x"}, "Unknown parameter")):
            with self.subTest(supplied=supplied):
                intent, _v, problems = schema.resolve(self.INTENT, self.PARAMS, supplied)
                self.assertEqual(intent, {})
                self.assertTrue(any(needle in p for p in problems), problems)

    def test_only_plain_placeholders_are_accepted_no_template_logic(self):
        for hostile in ("{% for x in y %}", "{{ hostname.__class__ }}", "{{ 7*7 }}", "{# c #}", "{{ hostname | upper }}"):
            intent = deepcopy(self.INTENT)
            intent["interfaces"][0]["description"] = hostile
            with self.subTest(hostile=hostile):
                self.assertTrue(schema.validate_intent(intent, self.PARAMS))
        self.assertEqual(schema.validate_intent(self.INTENT, self.PARAMS), [])
        undefined = deepcopy(self.INTENT)
        undefined["interfaces"][0]["description"] = "{{ nope }}"
        self.assertIn("Placeholder {{ nope }} has no parameter definition.", schema.validate_intent(undefined, self.PARAMS))

    def test_structure_problems_are_reported(self):
        self.assertTrue(schema.validate_intent({"interfaces": []}, {}))                                   # no hostname
        self.assertTrue(schema.validate_intent({"device": {"hostname": "x"}, "rogue": 1}, {}))
        self.assertTrue(schema.validate_intent({"device": {"hostname": "x"}, "interfaces": [{"name": "E1", "cli": "x"}]}, {}))
        self.assertTrue(schema.validate_intent({"device": {"hostname": "x"}, "interfaces": [{"name": "E1"}, {"name": "E1"}]}, {}))
        self.assertTrue(schema.validate_parameter_definitions({"Bad-Name": {"type": "string"}, "ok": {"type": "nope"}}))


# --- normalization -----------------------------------------------------------------------------------------------------
class NormalizeTests(SimpleTestCase):
    def test_clean_removes_runtime_management_link_local_and_secret_values(self):
        intent = {"device": {"hostname": "R3"}, "interfaces": [
            {"name": "eth0", "kind": "ROUTED_PHYSICAL", "addresses": [{"family": "IPV4", "cidr": "172.20.20.6/24"}]},
            {"name": "Vlan101", "kind": "SVI", "addresses": [{"family": "IPV4", "cidr": "10.0.0.1/31"}, {"family": "IPV6", "cidr": "fe80::1/64"}]},
            {"name": "eth3", "kind": "ROUTED_PHYSICAL", "access_vlan": 10}],
            "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "172.20.20.1"},
                              {"family": "IPV4", "destination": "10.9.0.0/24", "next_hop_address": "10.0.0.0"}],
            "routing": [{"family": "bgp", "fields": {"local_asn": 65003},
                         "neighbors": [{"peer_address": "10.0.0.0", "remote_asn": 65005, "password": SECRET, "password_ref": "runtime://x/y"}]}]}
        cleaned, exclusions = normalize.clean(intent, "ubuntu_frr")
        self.assertEqual([i["name"] for i in cleaned["interfaces"]], ["Vlan101", "eth3"])
        self.assertEqual(cleaned["interfaces"][0]["addresses"], [{"family": "IPV4", "cidr": "10.0.0.1/31"}])
        self.assertEqual(cleaned["interfaces"][1]["kind"], "ACCESS")
        self.assertEqual([r["destination"] for r in cleaned["static_routes"]], ["10.9.0.0/24"])
        neighbor = cleaned["routing"][0]["neighbors"][0]
        self.assertNotIn("password", neighbor)
        self.assertEqual(neighbor["password_ref"], "")
        self.assertNotIn(SECRET, json.dumps([cleaned, exclusions]))
        self.assertEqual({e["category"] for e in exclusions}, {"RUNTIME_MANAGEMENT", "DEVICE_IDENTITY", "NORMALIZED", "SECRET_REDACTED"})

    def _two(self):
        def device(n, extra=False):
            intent = {"device": {"hostname": f"S{n}"}, "interfaces": [
                {"name": "Ethernet1", "kind": "TRUNK", "description": "FABRIC", "trunk_allowed_vlans": [10, 20]},
                {"name": "Ethernet2", "kind": "ROUTED_PHYSICAL", "description": f"TO_R{n}", "addresses": [{"family": "IPV4", "cidr": f"10.0.{n}.1/31"}]},
                {"name": "Loopback0", "kind": "LOOPBACK", "addresses": [{"family": "IPV4", "cidr": f"192.168.255.{n}/32"}]},
                {"name": "Vlan200", "kind": "SVI", "vlan_id": 200, "addresses": [{"family": "IPV4", "cidr": f"192.168.200.{n}/24"},
                                                                               {"family": "IPV6", "cidr": f"2001:db8:200::{n}/64"}]}],
                "routing": [{"family": "bgp", "fields": {"local_asn": 65000 + n, "router_id": f"192.168.255.{n}"},
                             "neighbors": [{"peer_address": f"172.20.5.{n}", "remote_asn": 65005, "family": "IPV4"}]}]}
            if extra:
                intent["interfaces"].append({"name": "Vlan30", "kind": "SVI", "vlan_id": 30, "addresses": [{"family": "IPV4", "cidr": "10.30.0.2/24"}]})
            return intent
        return {"S1": device(1, extra=True), "S2": device(2)}

    def test_generalize_parameterizes_identity_and_differences_and_keeps_common_values(self):
        sources = self._two()
        result = normalize.generalize(sources)
        intent, parameters = result["intent"], result["parameters"]
        by_name = {row["name"]: row for row in intent["interfaces"]}
        self.assertEqual(intent["device"]["hostname"], "{{ hostname }}")
        self.assertEqual([a["cidr"] for a in by_name["Vlan200"]["addresses"]], ["{{ mgmt_ipv4 }}", "{{ mgmt_ipv6 }}"])
        self.assertEqual(by_name["Loopback0"]["addresses"][0]["cidr"], "{{ loopback_ipv4 }}")
        bgp = intent["routing"][0]
        self.assertEqual((bgp["fields"]["local_asn"], bgp["fields"]["router_id"]), ("{{ bgp_asn }}", "{{ bgp_router_id }}"))
        self.assertEqual(bgp["neighbors"][0]["peer_address"], "{{ bgp_peer_ipv4_1_address }}")
        self.assertEqual(bgp["neighbors"][0]["remote_asn"], "{{ bgp_peer_ipv4_1_asn }}")      # a peer AS is identity even when the sources agree
        # common role behaviour stays a literal baseline default
        self.assertEqual((by_name["Ethernet1"]["description"], by_name["Ethernet1"]["trunk_allowed_vlans"]), ("FABRIC", [10, 20]))
        # a differing non-identity value becomes a typed parameter
        self.assertEqual(by_name["Ethernet2"]["addresses"][0]["cidr"], "{{ ethernet2_ipv4_1 }}")
        self.assertEqual(parameters["ethernet2_ipv4_1"]["type"], "ipv4_interface")
        self.assertEqual(parameters["bgp_asn"]["type"], "asn")
        self.assertEqual(parameters["mgmt_ipv6"]["type"], "ipv6_interface")
        # an object only one source has is kept, optional, and reported
        self.assertEqual(by_name["Vlan30"]["_when"], "enable_vlan30")
        self.assertEqual((result["parameter_sets"]["S1"]["enable_vlan30"], result["parameter_sets"]["S2"]["enable_vlan30"]), (True, False))
        self.assertIn({"path": "interfaces/Vlan30", "kind": "ONLY_ON_SOME_SOURCES", "present_on": ["S1"]}, result["differences"])
        self.assertEqual(schema.validate_intent(intent, parameters), [])

    def test_each_source_parameter_set_reproduces_that_source_exactly(self):
        sources = self._two()
        result = normalize.generalize(sources)
        for device, original in sources.items():
            with self.subTest(device=device):
                resolved, _values, problems = schema.resolve(result["intent"], result["parameters"], result["parameter_sets"][device])
                self.assertEqual(problems, [])
                self.assertEqual(resolved, original)

    def test_a_single_source_still_parameterizes_identity_but_not_everything(self):
        result = normalize.generalize({"S1": self._two()["S1"]})
        self.assertLessEqual({"hostname", "mgmt_ipv4", "mgmt_ipv6", "loopback_ipv4", "bgp_asn", "bgp_router_id"}, set(result["parameters"]))
        self.assertNotIn("ethernet2_ipv4_1", result["parameters"])             # not identity-class, no second source to differ from
        self.assertEqual(result["differences"], [])


# --- extraction --------------------------------------------------------------------------------------------------------
class ExtractionTests(LabCase):
    def test_ceos_extraction_creates_a_draft_with_provenance_and_no_secret(self):
        version = self.extract("S1", name="Access from S1", family=models.TemplateFamily.ACCESS_SWITCH)
        self.assertEqual((version.status, version.version, version.template.origin), ("DRAFT", 1, "EXTRACTED"))
        snapshot = models.RunningConfigSnapshot.objects.get()
        source = version.provenance["sources"][0]
        self.assertEqual((source["device"], source["running_config_digest"], source["snapshot_id"]), ("S1", snapshot.digest, str(snapshot.snapshot_id)))
        self.assertEqual(version.provenance["method"], "live-read-only-capture")
        self.assertEqual(version.platforms and "arista_ceos" in version.platforms, True)
        names = [row["name"] for row in version.intent["interfaces"]]
        self.assertNotIn("Management0", names)
        self.assertIn("interface.SVI", version.required_features)
        self.assertEqual(version.parameter_sets["S1"]["mgmt_ipv4"], "192.168.200.11/24")
        self.assertNotIn(SECRET, version_blob(version))
        self.assertNotIn("sha512", version_blob(version))
        self.assertTrue(any(e["category"] == "UNMODELLED_CONFIGURATION" for e in version.exclusions))
        self.assertFalse(any("text" in e for e in version.exclusions))          # raw CLI is never carried, only labels
        self.assertEqual(service.publication_problems(version), [])
        self.assertEqual(self.factory.devices, ["S1"])

    def test_frr_extraction_uses_addresses_and_drops_runtime_and_link_local(self):
        version = self.extract("R3")
        by_name = {row["name"]: row for row in version.intent["interfaces"]}
        self.assertNotIn("eth0", by_name)
        self.assertEqual([a["cidr"] for a in by_name["Vlan101"]["addresses"]], ["192.168.100.3/31"])
        self.assertEqual([a["cidr"] for a in by_name["Vlan200"]["addresses"]], ["{{ mgmt_ipv4 }}", "{{ mgmt_ipv6 }}"])
        self.assertIn("ubuntu_frr", version.platforms)
        self.assertEqual(version.parameter_sets["R3"]["bgp_asn"], 65003)
        self.assertNotIn(SECRET, version_blob(version))

    def test_extraction_is_audited_and_recorded_as_capability_evidence(self):
        version = self.extract("S1")
        event = models.AuditEvent.objects.get(event_type="TEMPLATE_EXTRACTED")
        self.assertEqual((event.actor, event.object_id, event.metadata["device"]), ("tester", version.ref, "S1"))
        self.assertNotIn("192.168.200.11", json.dumps(event.metadata))
        rows = models.CapabilityEvidence.objects.filter(source="template-extraction", platform="arista_ceos")
        self.assertEqual(set(rows.values_list("axis", flat=True)), {"PARSER_IMPORT", "LIVE_READ"})
        self.assertEqual(set(rows.values_list("feature", flat=True)), set(version.required_features))
        self.assertEqual(set(rows.values_list("status", flat=True)), {"VERIFIED"})

    def test_unmanaged_and_unknown_devices_are_refused_and_never_contacted(self):
        for device, code in (("R5", "DEVICE_OUT_OF_SCOPE"), ("H1", "DEVICE_NOT_FOUND"), ("WebServer", "DEVICE_NOT_FOUND")):
            with self.subTest(device=device):
                with self.assertRaises(service.TemplateError) as raised:
                    self.extract(device)
                self.assertEqual(raised.exception.code, code)
        self.assertEqual(self.factory.devices, [])
        self.assertFalse(models.ConfigurationTemplate.objects.exists())

    def test_a_failed_read_creates_nothing(self):
        failing = h.session_factory({}, fail={"S1": "TIMEOUT"})
        with self.assertRaises(service.TemplateError):
            service.extract_from_device("S1", actor="tester", session_factory=failing)
        self.assertFalse(models.ConfigurationTemplate.objects.exists())

    def test_a_stored_snapshot_can_be_extracted_without_contacting_the_device(self):
        snapshot, _error = snapshots.capture_snapshot("S1", actor="tester", session_factory=self.factory)
        self.factory.devices.clear()
        version = service.extract_from_snapshot(snapshot, actor="tester")
        self.assertEqual(self.factory.devices, [])
        self.assertEqual(version.provenance["method"], "stored-running-config-snapshot")
        self.assertFalse(models.CapabilityEvidence.objects.filter(axis="LIVE_READ", source="template-extraction").exists())

    def test_secret_shaped_content_blocks_publication(self):
        draft = self.extract("S1")
        content = package.version_content(draft)
        content["intent"]["interfaces"][0]["description"] = f"password {SECRET}"
        hostile = service.create_version(draft.template, content, actor="tester")
        with self.assertRaises(service.TemplateError) as raised:
            service.publish(hostile, actor="approver")
        self.assertEqual(raised.exception.code, "PUBLICATION_REFUSED")
        self.assertNotIn(SECRET, str(raised.exception))


# --- baselines ---------------------------------------------------------------------------------------------------------
class BaselineTests(LabCase):
    def generate(self):
        return baselines.generate(actor="tester", live=True, session_factory=self.factory)

    def test_six_baseline_families_are_generated_published_and_immutable(self):
        results = self.generate()
        self.assertEqual([r["key"] for r in results], list(baselines.ALL_KEYS))
        families = {t.family: t for t in models.ConfigurationTemplate.objects.all()}
        self.assertEqual(set(families), {"ACCESS_SWITCH", "GATEWAY_ROUTER", "MULTILAYER_SWITCH", "SPINE", "INTERNET_UPLINK", "END_DEVICE"})
        for template in families.values():
            with self.subTest(template=template.template_id):
                version = template.latest_published()
                self.assertTrue(template.is_baseline and version.is_published)
                self.assertEqual(service.publication_problems(version), [])
                self.assertNotIn(SECRET, version_blob(version))
        expected = {"ACCESS_SWITCH": ["S1", "S2"], "GATEWAY_ROUTER": ["R1", "R2"], "SPINE": ["S3", "S4"], "INTERNET_UPLINK": ["R3", "R4"],
                    "END_DEVICE": ["H1", "H2", "H3", "H4"]}
        for family, sources in expected.items():
            self.assertEqual(families[family].latest_published().provenance["source_devices"], sources)
        uplink = families["INTERNET_UPLINK"].latest_published()
        self.assertIn("ubuntu_frr", uplink.platforms)
        self.assertEqual(uplink.provenance["platforms"], ["ubuntu_frr"])                 # where it came from vs. where it can render

    def test_only_the_eight_managed_sources_are_read_and_hosts_are_never_contacted(self):
        self.generate()
        self.assertEqual(sorted(self.factory.devices), ["R1", "R2", "R3", "R4", "S1", "S2", "S3", "S4"])
        end = service.get_template("TPL-BASELINE-END-DEVICE").latest_published()
        self.assertEqual((end.constraints["deployable"], end.constraints["managed_scope"], end.platforms), (False, False, []))
        self.assertEqual(sorted(end.parameter_sets), ["H1", "H2", "H3", "H4"])
        self.assertFalse(end.parameter_sets["H4"]["ipv4_enabled"])                     # the documented H4 difference is kept
        self.assertEqual(end.provenance["method"], "repository-lab-definition")
        self.assertFalse(models.RunningConfigSnapshot.objects.filter(device_name__in=["H1", "H2", "H3", "H4", "R5", "WebServer"]).exists())

    def test_source_differences_are_documented_not_hidden(self):
        self.generate()
        gateway = service.get_template("TPL-BASELINE-GATEWAY-ROUTER").latest_published()
        kinds = {(d["path"], d["kind"]) for d in gateway.provenance["differences"]}
        self.assertIn(("interfaces/Vlan101", "ONLY_ON_SOME_SOURCES"), kinds)
        self.assertIn(("interfaces/Ethernet1/trunk_allowed_vlans", "VALUE_DIFFERS"), kinds)
        self.assertEqual(sorted(gateway.parameter_sets), ["R1", "R2"])

    def test_regeneration_is_idempotent_and_a_changed_source_publishes_a_new_version(self):
        self.generate()
        again = self.generate()
        self.assertFalse(any(r["created"] for r in again))
        outputs = lab_outputs()
        outputs["S3"] = eos(SPINE.replace("FABRIC_A", "FABRIC_CHANGED"), name="S3", n=3)
        outputs["S4"] = eos(SPINE.replace("FABRIC_A", "FABRIC_CHANGED"), name="S4", n=4)
        changed = baselines.generate(actor="tester", live=True, session_factory=Recorder(outputs))
        self.assertEqual([r["key"] for r in changed if r["created"]], ["spine-device"])
        spine = service.get_template("TPL-BASELINE-SPINE")
        self.assertEqual(list(spine.versions.order_by("version").values_list("version", "status")), [(1, "PUBLISHED"), (2, "PUBLISHED")])

    def test_tracked_packages_round_trip_into_another_instance(self):
        import tempfile
        from pathlib import Path

        self.generate()
        digests = {t.template_id: t.latest_published().digest for t in models.ConfigurationTemplate.objects.all()}
        with tempfile.TemporaryDirectory() as directory:
            written = baselines.write_packages(Path(directory), actor="tester")
            self.assertEqual(len(written), 6)
            for row in models.ConfigurationTemplateVersion.objects.order_by("-id"):     # "another instance": an empty library
                models.ConfigurationTemplateVersion.objects.filter(pk=row.pk)._raw_delete(row._state.db)
            models.ConfigurationTemplate.objects.all().delete()
            loaded = baselines.load_packages(Path(directory), actor="tester")
            self.assertTrue(all(r["created"] for r in loaded))
            self.assertFalse(any(r["created"] for r in baselines.load_packages(Path(directory), actor="tester")))
        self.assertEqual({t.template_id: t.latest_published().digest for t in models.ConfigurationTemplate.objects.all()}, digests)
        self.assertTrue(all(t.is_baseline for t in models.ConfigurationTemplate.objects.all()))


# --- Multilayer Switch -------------------------------------------------------------------------------------------------
class CombineTests(SimpleTestCase):
    ACCESS = {"intent": {"device": {"hostname": "{{ hostname }}"}, "interfaces": [
        {"name": "Ethernet1", "kind": "ROUTED_PHYSICAL", "description": "{{ ethernet1_description }}", "addresses": [{"family": "IPV4", "cidr": "{{ ethernet1_ipv4_1 }}"}]},
        {"name": "Ethernet3", "kind": "ACCESS", "access_vlan": 10},
        {"name": "Ethernet4", "kind": "ACCESS", "access_vlan": 40},
        {"name": "Ethernet5", "kind": "ACCESS", "description": "MANAGEMENT", "access_vlan": 200},
        {"name": "Loopback0", "kind": "LOOPBACK", "addresses": [{"family": "IPV4", "cidr": "{{ loopback_ipv4 }}"}]},
        {"name": "Vlan10", "kind": "SVI", "vlan_id": 10, "addresses": [{"family": "IPV4", "cidr": "{{ vlan10_ipv4_1 }}"}]},
        {"name": "Vlan200", "kind": "SVI", "vlan_id": 200, "addresses": [{"family": "IPV4", "cidr": "{{ mgmt_ipv4 }}"}]}],
        "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "{{ access_default_gw }}"}],
        "routing": [{"family": "rip", "fields": {"address_family": "IPV4", "enabled": True},
                     "bindings": [{"interface_name": "Vlan10", "passive": False}, {"interface_name": "Ethernet1", "passive": False}]}]},
        "parameters": {n: {"type": t, "required": True} for n, t in (
            ("hostname", "hostname"), ("ethernet1_description", "string"), ("ethernet1_ipv4_1", "ipv4_interface"), ("loopback_ipv4", "ipv4_interface"),
            ("vlan10_ipv4_1", "ipv4_interface"), ("mgmt_ipv4", "ipv4_interface"), ("access_default_gw", "ipv4_address"))}}
    GATEWAY = {"intent": {"device": {"hostname": "{{ hostname }}"}, "interfaces": [
        {"name": "Ethernet1", "kind": "TRUNK", "description": "{{ ethernet1_description }}", "trunk_allowed_vlans": [101]},
        {"name": "Ethernet3", "kind": "ACCESS", "description": "MANAGEMENT", "access_vlan": 200},
        {"name": "Loopback0", "kind": "LOOPBACK", "addresses": [{"family": "IPV4", "cidr": "{{ loopback_ipv4 }}"}, {"family": "IPV6", "cidr": "{{ loopback_ipv6 }}"}]},
        {"name": "Vlan10", "kind": "SVI", "vlan_id": 10, "addresses": [{"family": "IPV4", "cidr": "10.99.0.1/24"}]},
        {"name": "Vlan101", "kind": "SVI", "vlan_id": 101, "addresses": [{"family": "IPV4", "cidr": "{{ vlan101_ipv4_1 }}"}]},
        {"name": "Vlan200", "kind": "SVI", "vlan_id": 200, "addresses": [{"family": "IPV4", "cidr": "{{ mgmt_ipv4 }}"}]}],
        "static_routes": [{"family": "IPV4", "destination": "0.0.0.0/0", "next_hop_address": "{{ uplink_gw }}"},
                          {"family": "IPV4", "destination": "10.50.0.0/16", "next_hop_interface": "Ethernet1"}],
        "routing": [{"family": "rip", "fields": {"address_family": "IPV4", "enabled": True}, "bindings": [{"interface_name": "Ethernet1", "passive": True}]},
                    {"family": "ospf", "fields": {"version": "OSPFV2", "process_id": 10, "router_id": "{{ ospf_router_id }}"},
                     "bindings": [{"interface_name": "Vlan101", "area": "0.0.0.0"}]}]},
        "parameters": {n: {"type": t, "required": True} for n, t in (
            ("hostname", "hostname"), ("ethernet1_description", "string"), ("loopback_ipv4", "ipv4_interface"), ("loopback_ipv6", "ipv6_interface"),
            ("vlan101_ipv4_1", "ipv4_interface"), ("mgmt_ipv4", "ipv4_interface"), ("uplink_gw", "ipv4_address"), ("ospf_router_id", "ipv4_address"))}}

    def setUp(self):
        self.result = combine.combine(self.ACCESS, self.GATEWAY)
        self.by_name = {row["name"]: row for row in self.result["intent"]["interfaces"]}
        self.codes = {(c["code"], c["subject"]) for c in self.result["conflicts"]}

    def test_the_inputs_are_not_modified_and_the_result_is_a_valid_template(self):
        before = (json.dumps(self.ACCESS, sort_keys=True), json.dumps(self.GATEWAY, sort_keys=True))
        combine.combine(self.ACCESS, self.GATEWAY)
        self.assertEqual(before, (json.dumps(self.ACCESS, sort_keys=True), json.dumps(self.GATEWAY, sort_keys=True)))
        self.assertEqual(schema.validate_intent(self.result["intent"], self.result["parameters"]), [])

    def test_a_duplicate_interface_identity_is_rehomed_and_references_follow_it(self):
        self.assertIn(("DUPLICATE_INTERFACE", "Ethernet1"), self.codes)
        self.assertEqual(self.by_name["Ethernet1"]["kind"], "ROUTED_PHYSICAL")            # the access role keeps the port
        self.assertEqual(self.by_name["Ethernet2"]["kind"], "TRUNK")                      # the gateway role's port moved to the next free one
        names = [row["name"] for row in self.result["intent"]["interfaces"]]
        self.assertEqual(len(names), len(set(names)))
        rip = next(r for r in self.result["intent"]["routing"] if r["family"] == "rip")
        self.assertEqual([b["interface_name"] for b in rip["bindings"]], ["Vlan10", "Ethernet1", "Ethernet2"])
        route = next(r for r in self.result["intent"]["static_routes"] if r["destination"] == "10.50.0.0/16")
        self.assertEqual(route["next_hop_interface"], "Ethernet2")

    def test_a_parameter_with_another_meaning_is_renamed_and_identity_parameters_are_shared(self):
        self.assertEqual(self.by_name["Ethernet1"]["description"], "{{ ethernet1_description }}")
        self.assertEqual(self.by_name["Ethernet2"]["description"], "{{ ethernet2_description }}")   # followed the re-homed port
        self.assertIn("ethernet2_description", self.result["parameters"])
        for shared in ("hostname", "mgmt_ipv4", "loopback_ipv4", "ospf_router_id"):
            self.assertIn(shared, self.result["parameters"])
        self.assertFalse(any(name.startswith("gw_") for name in ("hostname", "mgmt_ipv4") if name not in self.result["parameters"]))

    def test_management_is_deduplicated(self):
        self.assertIn(("DUPLICATE_MANAGEMENT", "Vlan200"), self.codes)
        self.assertIn(("DUPLICATE_MANAGEMENT", "Ethernet3"), self.codes)
        self.assertEqual(sum(1 for row in self.result["intent"]["interfaces"] if row.get("access_vlan") == 200), 1)
        self.assertEqual(sum(1 for row in self.result["intent"]["interfaces"] if row["name"] == "Vlan200"), 1)
        self.assertEqual(self.by_name["Ethernet3"]["access_vlan"], 10)                    # the access role's edge port survived

    def test_one_loopback_carries_both_roles_addresses_and_the_router_id(self):
        self.assertIn(("LOOPBACK_ROUTER_ID", "Loopback0"), self.codes)
        self.assertEqual([a["cidr"] for a in self.by_name["Loopback0"]["addresses"]], ["{{ loopback_ipv4 }}", "{{ loopback_ipv6 }}"])

    def test_overlapping_addressing_keeps_the_vlan_gateway_role(self):
        self.assertIn(("OVERLAPPING_ADDRESSING", "Vlan10"), self.codes)
        self.assertEqual(self.by_name["Vlan10"]["addresses"][0]["cidr"], "{{ vlan10_ipv4_1 }}")

    def test_the_same_protocol_becomes_one_process_and_other_protocols_are_added(self):
        families = [r["family"] for r in self.result["intent"]["routing"]]
        self.assertEqual(families, ["rip", "ospf"])
        self.assertIn(("ROUTING_PROCESS_COLLISION", "rip"), self.codes)

    def test_a_conflicting_default_route_keeps_the_gateway_role(self):
        self.assertIn(("DEFAULT_GATEWAY_ROLE", "ipv4_0.0.0.0/0"), self.codes)
        defaults = [r for r in self.result["intent"]["static_routes"] if r["destination"] == "0.0.0.0/0"]
        self.assertEqual([r["next_hop_address"] for r in defaults], ["{{ uplink_gw }}"])
        self.assertNotIn("access_default_gw", self.result["parameters"])                  # an unused parameter does not survive

    def test_vlan_svi_relationships_are_reported(self):
        self.assertIn(("VLAN_WITHOUT_SVI", "VLAN 40"), self.codes)
        self.assertNotIn(("VLAN_WITHOUT_SVI", "VLAN 10"), self.codes)
        self.assertNotIn(("SVI_WITHOUT_PORT", "Vlan101"), self.codes)                     # carried on the re-homed trunk


class MlsBaselineTests(LabCase):
    def test_the_mls_baseline_is_a_semantic_combination_with_recorded_lineage(self):
        baselines.generate(actor="tester", live=True, session_factory=self.factory)
        mls = service.get_template("TPL-BASELINE-MULTILAYER-SWITCH").latest_published()
        access = service.get_template("TPL-BASELINE-ACCESS-SWITCH").latest_published()
        gateway = service.get_template("TPL-BASELINE-GATEWAY-ROUTER").latest_published()
        self.assertEqual(mls.provenance["method"], "semantic-combination")
        self.assertEqual([(d["template_id"], d["digest"]) for d in mls.provenance["derived_from"]],
                         [(access.template.template_id, access.digest), (gateway.template.template_id, gateway.digest)])
        self.assertTrue(mls.provenance["conflicts"])
        kinds = {row["kind"] for row in mls.intent["interfaces"]}
        self.assertLessEqual({"SVI", "TRUNK", "ACCESS", "LOOPBACK", "ROUTED_PHYSICAL"}, kinds)
        self.assertEqual({r["family"] for r in mls.intent["routing"]}, {"rip", "ospf"})
        self.assertEqual(mls.parameter_sets, {})                                           # no source device is an MLS
        self.assertNotIn("hostname S1", version_blob(mls))
        self.assertIn("arista_ceos", mls.platforms)


# --- packages ----------------------------------------------------------------------------------------------------------
class PackageTests(LabCase):
    def setUp(self):
        super().setUp()
        self.version = self.published("S1")
        self.name, self.data = service.export_package(self.version, actor="tester")

    def document(self):
        return yaml.safe_load(self.data)

    def repack(self, document, *, fix_digest=False):
        if fix_digest:
            compatibility = document.get("compatibility") or {}
            document["manifest"]["digest"] = package.content_digest({
                "schema_version": document["schema_version"], "family": document["manifest"]["family"], "intent": document["intent"],
                "parameters": document["parameters"], "parameter_sets": document["parameter_sets"], "platforms": compatibility.get("platforms"),
                "required_features": compatibility.get("required_features"), "constraints": compatibility.get("constraints"),
                "provenance": document["provenance"], "exclusions": document["exclusions"], "notes": document["notes"]})
        return package.dump(document)

    def rejected(self, data, code):
        with self.assertRaises(service.TemplateError) as raised:
            service.import_package(data, actor="tester")
        self.assertEqual(raised.exception.code, code, raised.exception.problems)
        return raised.exception

    def test_export_is_deterministic_self_contained_and_secret_free(self):
        _name, again = service.export_package(self.version, actor="tester")
        self.assertEqual(self.data, again)
        self.assertTrue(self.name.endswith(".nmas-template.yaml"))
        document = self.document()
        self.assertEqual(document["kind"], "nmas-configuration-template")
        self.assertEqual(set(document), {"kind", "schema_version", "manifest", "compatibility", "provenance", "parameters", "parameter_sets",
                                         "intent", "exclusions", "notes", "rendering"})
        self.assertEqual((document["manifest"]["digest"], document["manifest"]["digest_algorithm"]), (self.version.digest, "sha256"))
        self.assertEqual(document["rendering"]["engine"], "jinja2")
        self.assertIn("ceos/interface_svi.j2", document["rendering"]["feature_templates"])
        self.assertNotIn(SECRET.encode(), self.data)
        for needle in (b"sha512", b"password", b"community", b"runtime://"):
            self.assertNotIn(needle, self.data)
        self.assertEqual(secret_scan.scan({k: document[k] for k in ("intent", "parameters", "parameter_sets", "notes")}), [])
        self.assertTrue(models.AuditEvent.objects.filter(event_type="TEMPLATE_EXPORTED", actor="tester", object_id=self.version.ref).exists())

    def test_a_draft_cannot_be_exported(self):
        draft = self.extract("S2")
        with self.assertRaises(service.TemplateError) as raised:
            service.export_package(draft, actor="tester")
        self.assertEqual(raised.exception.code, "NOT_PUBLISHED")

    def test_import_reconstructs_the_template_without_the_original_database(self):
        template_id, digest, intent = self.version.template.template_id, self.version.digest, deepcopy(self.version.intent)
        models.ConfigurationTemplateVersion.objects.filter(pk=self.version.pk)._raw_delete("default")
        models.ConfigurationTemplate.objects.all().delete()
        imported, created = service.import_package(self.data, actor="importer")
        self.assertTrue(created)
        self.assertEqual((imported.template.template_id, imported.digest, imported.intent), (template_id, digest, intent))
        self.assertEqual((imported.status, imported.template.origin), ("PUBLISHED", "IMPORTED"))
        metadata = service.import_metadata(imported)
        self.assertEqual((metadata["imported_by"], metadata["original_template_id"], metadata["local_identity"]), ("importer", template_id, "kept"))
        self.assertEqual(imported.provenance["sources"][0]["device"], "S1")              # original provenance preserved
        with self.assertRaises(ValueError):                                                # imported versions are immutable
            imported.notes = "x"
            imported.save()
        self.assertEqual(service.import_package(self.data, actor="importer")[1], False)   # idempotent
        self.assertFalse(models.Change.objects.exists())                                   # nothing was executed or even drafted
        self.assertTrue(models.AuditEvent.objects.filter(event_type="TEMPLATE_IMPORTED", actor="importer").exists())

    def test_an_imported_version_can_be_cloned_into_a_working_intent(self):
        models.ConfigurationTemplateVersion.objects.filter(pk=self.version.pk)._raw_delete("default")
        models.ConfigurationTemplate.objects.all().delete()
        imported, _created = service.import_package(self.data, actor="importer")
        result = clone.clone_into_change(version=imported, device_name="S9", platform="arista_ceos", parameter_set="S1", actor="tester",
                                         target_type="NEW_DEVICE")
        self.assertTrue(result.revision.sections["interfaces"])

    def test_same_version_with_other_content_gets_a_new_local_identity(self):
        document = self.document()
        document["notes"] = "changed elsewhere"
        imported, created = service.import_package(self.repack(document, fix_digest=True), actor="importer")
        self.assertTrue(created)
        self.assertNotEqual(imported.template.template_id, self.version.template.template_id)
        self.assertEqual(service.import_metadata(imported)["local_identity"], "reassigned")
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get(pk=self.version.pk).notes, "")   # the local one is untouched

    def test_altered_content_fails_the_integrity_check(self):
        document = self.document()
        document["intent"]["interfaces"][0]["description"] = "altered in transit"
        self.rejected(self.repack(document), "DIGEST_MISMATCH")
        document = self.document()
        document["parameter_sets"]["S1"]["mgmt_ipv4"] = "10.66.66.66/24"
        self.rejected(self.repack(document), "DIGEST_MISMATCH")

    def test_malformed_and_unsafe_yaml_is_rejected(self):
        for data in (b"", b"\xff\xfe\x00", b"kind: [unclosed", b"- just\n- a list\n", b"kind: something-else\nschema_version: 1\n",
                     b"a: &a [x, x]\nb: [*a, *a]\nkind: nmas-configuration-template\nschema_version: 1\n",
                     b"kind: nmas-configuration-template\nschema_version: 1\nmanifest: !!python/object/apply:os.system ['id']\n"):
            with self.subTest(data=data[:30]):
                with self.assertRaises(service.TemplateError) as raised:
                    service.import_package(data, actor="tester")
                self.assertIn(raised.exception.code, ("EMPTY_PACKAGE", "MALFORMED_PACKAGE", "NOT_A_TEMPLATE_PACKAGE"))
        self.rejected(b"x" * (package.MAX_PACKAGE_BYTES + 1), "PACKAGE_TOO_LARGE")

    def test_unsupported_schema_versions_are_rejected_cleanly(self):
        for value in (2, 0, "1", None, True):
            document = self.document()
            document["schema_version"] = value
            with self.subTest(value=value):
                self.rejected(self.repack(document), "UNSUPPORTED_SCHEMA_VERSION")

    def test_schema_violations_are_rejected(self):
        for mutate in (lambda d: d.pop("manifest"), lambda d: d.pop("intent"), lambda d: d["manifest"].update(template_id="../../etc/passwd"),
                       lambda d: d["manifest"].update(version=0), lambda d: d["manifest"].update(digest_algorithm="md5"), lambda d: d.update(extra_section={}),
                       lambda d: d["intent"].update(cli_blob="hostname x"), lambda d: d["intent"]["interfaces"][0].update(description="{% include '/etc/passwd' %}"),
                       lambda d: d["parameters"].update({"Bad Name": {"type": "string"}}), lambda d: d["compatibility"].update(platforms=["../x"])):
            document = self.document()
            mutate(document)
            with self.subTest(document=sorted(document)):
                self.rejected(self.repack(document, fix_digest="intent" in document and "manifest" in document), "INVALID_PACKAGE")

    def test_secret_bearing_packages_are_rejected_even_with_a_valid_digest(self):
        cases = (lambda d: d["intent"]["interfaces"][0].update(description=f"password {SECRET}"),
                 lambda d: d["intent"].update(host={"password": SECRET}),
                 lambda d: d["parameter_sets"]["S1"].update(hostname="-----BEGIN OPENSSH " + "PRIVATE KEY-----"),
                 lambda d: d.update(notes="otpauth://totp/NMAS:admin?secret=JBSWY3DPEHPK3PXP"),
                 lambda d: d["intent"].update(host={"auth_secret_ref": "plaintext-not-a-reference"}),
                 lambda d: d["provenance"].update(radius_secret=SECRET))
        for mutate in cases:
            document = self.document()
            mutate(document)
            with self.subTest(index=cases.index(mutate)):
                error = self.rejected(self.repack(document, fix_digest=True), "SECRET_MATERIAL_REFUSED")
                self.assertNotIn(SECRET, str(error))
        self.assertEqual(models.ConfigurationTemplate.objects.count(), 1)

    def test_path_traversal_in_template_references_is_rejected(self):
        for reference in ("../../../etc/passwd", "/etc/passwd", "ceos/../../secrets.j2", "ceos\\x.j2", "ceos/x.txt", 7):
            document = self.document()
            document["rendering"]["feature_templates"] = [reference]
            with self.subTest(reference=reference):
                self.rejected(self.repack(document), "UNSAFE_TEMPLATE_REFERENCE")

    def test_every_rejection_is_audited_without_content(self):
        document = self.document()
        document["intent"]["interfaces"][0]["description"] = f"password {SECRET}"
        self.rejected(self.repack(document, fix_digest=True), "SECRET_MATERIAL_REFUSED")
        event = models.AuditEvent.objects.get(event_type="TEMPLATE_IMPORT_REJECTED")
        self.assertEqual((event.actor, event.metadata["code"]), ("tester", "SECRET_MATERIAL_REFUSED"))
        self.assertNotIn(SECRET, json.dumps(event.metadata) + event.summary)


# --- clone -------------------------------------------------------------------------------------------------------------
class CloneTests(LabCase):
    def setUp(self):
        super().setUp()
        self.version = self.published("R1")
        self.frozen = version_blob(self.version)

    def clone(self, **kwargs):
        defaults = {"version": self.version, "device_name": "R1", "platform": "arista_ceos", "parameter_set": "R1", "actor": "tester"}
        return clone.clone_into_change(**{**defaults, **kwargs})

    def assert_template_untouched(self):
        self.assertEqual(version_blob(models.ConfigurationTemplateVersion.objects.get(pk=self.version.pk)), self.frozen)
        self.assertEqual(models.ConfigurationTemplateVersion.objects.count(), 1)

    def test_full_clone_creates_a_new_editable_working_intent_through_the_device_builder_services(self):
        result = self.clone()
        change, revision = result.change, result.revision
        self.assertEqual((change.lifecycle_state, revision.revision, result.intent.device_name), ("DRAFT", 1, "R1"))
        names = sorted(row["name"] for row in revision.sections["interfaces"].values())
        self.assertEqual(names, ["Ethernet1", "Ethernet2", "Ethernet3", "Loopback0", "Vlan101", "Vlan200"])
        self.assertTrue(revision.field_states.filter(validation_state="VALID").exists())
        self.assertFalse(revision.field_states.filter(validation_state="INVALID").exists())
        self.assertEqual(len(revision.sections["routing"]["ospf"]), 1)
        provenance = revision.metadata["template_clone"]
        self.assertEqual((provenance["template_id"], provenance["version"], provenance["digest"], provenance["mode"]),
                         (self.version.template.template_id, 1, self.version.digest, "FULL"))
        self.assertEqual(change.metadata["template_sources"][0]["device"], "R1")
        self.assert_template_untouched()

    def test_editing_the_clone_never_changes_the_source_template(self):
        result = self.clone()
        change, intent, revision = result.change, result.intent, result.revision
        loopback = next(row for row in revision.sections["interfaces"].values() if row["name"] == "Loopback0")
        state = field_commit_service.commit_field(change=change, intent=intent, revision=revision,
                                                  path=f"interfaces.{loopback['id']}.description", raw_value="EDITED-IN-CLONE")
        self.assertEqual(state.validation_state, "VALID")
        ospf_id = next(iter(revision.sections["routing"]["ospf"]))
        revision.refresh_from_db()
        routing_intent_service.remove_protocol_instance(revision=revision, family="ospf", instance_id=ospf_id, confirmation="REMOVE")
        revision.refresh_from_db()
        self.assertEqual(revision.sections["routing"]["ospf"], {})                        # OSPF removed from the working clone only
        self.assertIn("EDITED-IN-CLONE", json.dumps(revision.sections))
        self.assert_template_untouched()
        self.assertTrue(any(r["family"] == "ospf" for r in self.version.intent["routing"]))

    def test_field_validation_applies_to_template_values(self):
        invalid = field_commit_service.commit_field(
            change=(result := self.clone()).change, intent=result.intent, revision=result.revision,
            path=f"interfaces.{next(iter(result.revision.sections['interfaces']))}.mtu", raw_value="not-a-number")
        self.assertEqual(invalid.validation_state, "INVALID")

    def test_invalid_parameters_create_nothing(self):
        for values, needle in (({"mgmt_ipv4": "999.1.1.1/24"}, "mgmt_ipv4"), ({"ospf_router_id": "not-an-ip"}, "ospf_router_id"),
                               ({"hostname": "bad host"}, "hostname")):
            with self.subTest(values=values):
                with self.assertRaises(service.TemplateError) as raised:
                    self.clone(parameter_values=values)
                self.assertEqual(raised.exception.code, "INVALID_PARAMETERS")
                self.assertTrue(any(needle in p for p in raised.exception.problems))
        with self.assertRaises(service.TemplateError):
            self.clone(parameter_set="", parameter_values={})                              # required identity values missing
        self.assertFalse(models.Change.objects.exists())
        self.assert_template_untouched()

    def test_clone_refusals(self):
        draft = self.extract("S1")
        cases = (({"version": draft, "device_name": "S1", "parameter_set": "S1"}, "CLONE_REFUSED"),
                 ({"platform": "ubuntu_frr"}, "CLONE_REFUSED"),
                 ({"device_name": "bad name"}, "CLONE_REFUSED"),
                 ({"parameter_set": "nope"}, "CLONE_REFUSED"),
                 ({"mode": "SIDEWAYS"}, "CLONE_REFUSED"),
                 ({"device_name": "R5"}, "DEVICE_OUT_OF_SCOPE"),
                 ({"device_name": "H1"}, "DEVICE_OUT_OF_SCOPE"),
                 ({"device_name": "R3"}, "DEVICE_OUT_OF_SCOPE"))                       # a managed device of another platform
        for kwargs, code in cases:
            with self.subTest(kwargs={k: str(v) for k, v in kwargs.items()}):
                with self.assertRaises(service.TemplateError) as raised:
                    self.clone(**kwargs)
                self.assertEqual(raised.exception.code, code, raised.exception.problems)
        service.retire(self.version.template, actor="approver")
        with self.assertRaises(service.TemplateError):
            self.clone()
        self.assertFalse(models.Change.objects.exists())

    def test_the_end_device_template_can_never_become_a_managed_working_intent(self):
        baselines.generate(actor="tester", live=True, session_factory=self.factory, only=("end-device",))
        end = service.get_template("TPL-BASELINE-END-DEVICE").latest_published()
        for target_type in ("EXISTING_DEVICE", "NEW_DEVICE"):
            with self.assertRaises(service.TemplateError) as raised:
                clone.clone_into_change(version=end, device_name="H1", platform="ubuntu_frr", parameter_set="H1", actor="tester", target_type=target_type)
            self.assertEqual(raised.exception.code, "CLONE_REFUSED")
        self.assertFalse(models.Change.objects.exists())
        self.assertFalse(models.DeviceIntent.objects.filter(device_name__in=["H1", "H2", "H3", "H4"]).exists())

    def test_clone_into_an_existing_draft_change_and_duplicate_device_refusal(self):
        first = self.clone()
        with self.assertRaises(service.TemplateError):
            self.clone(change=first.change)
        second = self.clone(change=first.change, device_name="R2", parameter_set="R1",
                            parameter_values={"hostname": "R2", "mgmt_ipv4": "192.168.200.2/24", "mgmt_ipv6": "2001:db8:200::2/64"})
        self.assertEqual(second.change.pk, first.change.pk)
        self.assertEqual(len(models.Change.objects.get(pk=first.change.pk).metadata["template_sources"]), 2)

    def test_clone_is_audited_with_identifiers_only_and_records_render_evidence(self):
        result = self.clone()
        event = models.AuditEvent.objects.get(event_type="TEMPLATE_CLONED")
        self.assertEqual((event.actor, event.change_id, event.object_id), ("tester", result.change.pk, self.version.ref))
        self.assertIn("mgmt_ipv4", event.metadata["parameter_names"])
        self.assertNotIn("192.168.200.1", json.dumps(event.metadata))
        rendered = models.CapabilityEvidence.objects.filter(source="template-render", platform="arista_ceos")
        self.assertEqual(set(rendered.values_list("axis", "status")), {("RENDERER", "VERIFIED")})
        self.assertIn("routing.OSPFV2", set(rendered.values_list("feature", flat=True)))

    def test_a_new_version_from_an_extracted_templates_clone_keeps_the_lineage(self):
        result = self.clone()
        loopback = next(row for row in result.revision.sections["interfaces"].values() if row["name"] == "Loopback0")
        field_commit_service.commit_field(change=result.change, intent=result.intent, revision=result.revision,
                                          path=f"interfaces.{loopback['id']}.description", raw_value="V2-DESCRIPTION")
        result.revision.refresh_from_db()
        draft = service.version_from_revision(result.revision, actor="tester")
        self.assertEqual((draft.template.pk, draft.version, draft.status, draft.source_version_id), (self.version.template.pk, 2, "DRAFT", self.version.pk))
        self.assertIn("V2-DESCRIPTION", json.dumps(draft.intent))
        self.assertEqual(draft.provenance["derived_from"]["digest"], self.version.digest)
        self.assertEqual(service.publication_problems(draft), [])
        self.assert_template_untouched_except_new_version()

    def assert_template_untouched_except_new_version(self):
        self.assertEqual(version_blob(models.ConfigurationTemplateVersion.objects.get(pk=self.version.pk)), self.frozen)

    def test_a_baseline_is_never_versioned_by_an_operator_edit(self):
        baselines.generate(actor="tester", live=True, session_factory=self.factory, only=("spine-device",))
        spine = service.get_template("TPL-BASELINE-SPINE").latest_published()
        result = clone.clone_into_change(version=spine, device_name="S3", platform="arista_ceos", parameter_set="S3", actor="tester")
        draft = service.version_from_revision(result.revision, actor="tester", name="My spine")
        self.assertNotEqual(draft.template.pk, spine.template.pk)
        self.assertEqual((draft.template.origin, draft.template.family, draft.source_version_id), ("DERIVED", "SPINE", spine.pk))
        self.assertEqual(spine.template.versions.count(), 1)


class IncrementalCloneTests(LabCase):
    """Template push to an EXISTING running device: only what the template adds becomes the plan."""

    def setUp(self):
        super().setUp()
        self.sources = make_sources()
        base = service.publish(self.extract("R1"), actor="approver")
        content = deepcopy(package.version_content(base))
        content["intent"]["interfaces"].append({"name": "Loopback103", "kind": "LOOPBACK", "description": "{{ test_loopback_description }}",
                                                "addresses": [{"family": "IPV4", "cidr": "{{ test_loopback_ipv4 }}"}]})
        content["parameters"]["test_loopback_description"] = {"type": "string", "required": False, "default": "NMAS-TEMPLATE-TEST"}
        content["parameters"]["test_loopback_ipv4"] = {"type": "ipv4_interface", "required": True}
        content["parameter_sets"]["R1"]["test_loopback_ipv4"] = "10.255.103.1/32"
        content["required_features"] = sorted(set(content["required_features"]) | {"interface.LOOPBACK"})
        self.version = service.publish(service.create_version(base.template, content, actor="tester", source_version=base), actor="approver")

    def clone(self, **kwargs):
        defaults = {"version": self.version, "device_name": "R1", "platform": "arista_ceos", "parameter_set": "R1", "actor": "tester",
                    "mode": clone.INCREMENTAL, "session_factory": self.factory, "parameter_values": {"test_loopback_ipv4": "10.255.103.1/32"}}
        return clone.clone_into_change(**{**defaults, **kwargs})

    def test_only_the_template_addition_is_planned_and_the_running_config_is_context(self):
        result = self.clone()
        change = models.Change.objects.get(pk=result.change.pk)
        baseline = set(change.metadata["contribution_baseline"]["object_ids"])
        loopback = next(row for row in result.revision.sections["interfaces"].values() if row["name"] == "Loopback103")
        self.assertNotIn(loopback["id"], baseline)
        self.assertTrue(baseline)
        snapshot = models.RunningConfigSnapshot.objects.order_by("-id").first()
        self.assertEqual(change.metadata["workflow_snapshot"], {"device": "R1", "digest": snapshot.digest, "snapshot_id": str(snapshot.snapshot_id)})
        self.assertEqual((result.applied["new_interfaces"], result.applied["operations"]), (1, 0))
        self.assertTrue(any("context, not re-deployed" in w for w in result.warnings))
        run = cvs.validate_change(change, actor="tester", sources=self.sources)
        self.assertIn(run.status, ("PASS", "PASS_WITH_WARNINGS"), [(f["code"], f["message"]) for f in run.report["findings"] if f["severity"] == "ERROR"])
        plan, _created = cps.build_change_plan(change, actor="tester", sources=self.sources)
        rendered = "\n".join(c.rendered_config for c in plan.configlets.order_by("sequence"))
        self.assertIn("interface Loopback103", rendered)
        self.assertIn("NMAS-TEMPLATE-TEST", rendered)
        self.assertIn("10.255.103.1/32", rendered)
        for untouched in ("Vlan200", "192.168.200.1", "router ospf", "Ethernet1", "FABRIC_TRUNK"):
            self.assertNotIn(untouched, rendered)
        self.assertIn("CONTRIBUTION_CONTEXT_EXCLUDED", [w["code"] for w in plan.warnings])

    def test_the_working_clone_is_editable_before_validation(self):
        result = self.clone()
        loopback = next(row for row in result.revision.sections["interfaces"].values() if row["name"] == "Loopback103")
        state = field_commit_service.commit_field(change=result.change, intent=result.intent, revision=result.revision,
                                                  path=f"interfaces.{loopback['id']}.description", raw_value="EDITED-BEFORE-PUSH")
        self.assertEqual(state.validation_state, "VALID")
        change = models.Change.objects.get(pk=result.change.pk)
        cvs.validate_change(change, actor="tester", sources=self.sources)
        plan, _created = cps.build_change_plan(change, actor="tester", sources=self.sources)
        rendered = "\n".join(c.rendered_config for c in plan.configlets.order_by("sequence"))
        self.assertIn("EDITED-BEFORE-PUSH", rendered)
        self.assertNotIn("NMAS-TEMPLATE-TEST", rendered)
        self.assertEqual(models.ConfigurationTemplateVersion.objects.get(pk=self.version.pk).parameters["test_loopback_description"]["default"],
                         "NMAS-TEMPLATE-TEST")

    def test_a_differing_existing_object_is_reported_and_not_overwritten(self):
        result = self.clone(parameter_values={"test_loopback_ipv4": "10.255.103.1/32", "mgmt_ipv4": "192.168.200.77/24"})
        self.assertEqual(result.applied["operations"], 1)                                  # the new address is an explicit, visible operation
        delta = clone.overlay({"interfaces": [{"name": "Vlan200", "kind": "SVI", "description": "other"}]},
                              {"interfaces": [{"name": "Vlan200", "kind": "SVI", "description": "mine"}]})
        self.assertEqual((delta["new"], delta["operations"], delta["differs"]), ({}, [], ["interface Vlan200 description"]))

    def test_the_running_context_is_normalized_like_a_source_so_only_real_differences_are_reported(self):
        # R1's management access port is imported as a routed port (EOS hides its default switchport mode); the template
        # carries it normalized to ACCESS.  That is the same object, not a difference.
        result = self.clone()
        self.assertEqual(result.applied["differing_objects"], 0, result.warnings)
        self.assertFalse(any("Differs on" in w for w in result.warnings))

    def test_incremental_needs_the_authoritative_scope_and_a_readable_device(self):
        with self.assertRaises(service.TemplateError) as raised:
            self.clone(session_factory=h.session_factory({}, fail={"R1": "TIMEOUT"}))
        self.assertEqual(raised.exception.code, "CONNECTION_FAILED")
        with self.assertRaises(service.TemplateError):
            self.clone(target_type="NEW_DEVICE")
        self.assertFalse(models.Change.objects.exists())

    def test_a_verified_template_derived_push_is_recorded_against_the_template(self):
        result = self.clone()
        run = SimpleNamespace(change=models.Change.objects.get(pk=result.change.pk), run_id="11111111-1111-1111-1111-111111111111")
        validation = SimpleNamespace(run_id="22222222-2222-2222-2222-222222222222", status="PASS", operation_type="POST_PUSH")
        clone.record_push(run, validation, actor="executor")
        event = models.AuditEvent.objects.get(event_type="TEMPLATE_PUSH_RECORDED")
        self.assertEqual((event.actor, event.object_id, event.metadata["live_status"], event.metadata["device"]),
                         ("executor", self.version.ref, "PASS", "R1"))


class TrackedBaselinePackageTests(TestCase):
    """The packages committed under templates/baselines/ (generated from live read-only captures of the lab)."""

    def test_the_six_tracked_packages_are_valid_secret_free_and_register_as_immutable_baselines(self):
        paths = sorted(baselines.PACKAGE_DIR.glob(f"*{package.FILE_SUFFIX}"))
        self.assertEqual([p.name.removesuffix(package.FILE_SUFFIX) for p in paths], sorted(baselines.ALL_KEYS))
        expected_sources = {"ACCESS_SWITCH": ["S1", "S2"], "GATEWAY_ROUTER": ["R1", "R2"], "SPINE": ["S3", "S4"], "INTERNET_UPLINK": ["R3", "R4"],
                            "END_DEVICE": ["H1", "H2", "H3", "H4"]}
        for path in paths:
            with self.subTest(package=path.name):
                data = path.read_bytes()
                loaded = package.load(data)                                       # schema, secret scan and digest
                self.assertEqual(package.dump(yaml.safe_load(data)), data)        # canonical, deterministic bytes
                family = loaded["content"]["family"]
                if family in expected_sources:
                    self.assertEqual(loaded["content"]["provenance"]["source_devices"], expected_sources[family])
                if family not in ("END_DEVICE", "MULTILAYER_SWITCH"):
                    for source in loaded["content"]["provenance"]["sources"]:
                        self.assertRegex(source["running_config_digest"], r"^[0-9a-f]{64}$")
                        self.assertEqual(loaded["content"]["provenance"]["method"], "live-read-only-capture")
                mgmt = [a["cidr"] for row in loaded["content"]["intent"].get("interfaces", []) if row.get("name") == "Vlan200"
                        for a in row.get("addresses", [])]
                self.assertTrue(all(value.startswith("{{ mgmt_ipv") for value in mgmt), mgmt)   # VLAN 200 stays static and per-device
        results = baselines.load_packages(actor="tester")
        self.assertEqual(len(results), 6)
        self.assertTrue(all(row["created"] for row in results))
        templates = list(models.ConfigurationTemplate.objects.all())
        self.assertEqual({t.family for t in templates}, {"ACCESS_SWITCH", "GATEWAY_ROUTER", "MULTILAYER_SWITCH", "SPINE", "INTERNET_UPLINK", "END_DEVICE"})
        self.assertTrue(all(t.is_baseline and t.latest_published().is_published for t in templates))
        self.assertFalse(any(row["created"] for row in baselines.load_packages(actor="tester")))
        mls = service.get_template("TPL-BASELINE-MULTILAYER-SWITCH").latest_published()
        self.assertEqual([d["template_id"] for d in mls.provenance["derived_from"]], ["TPL-BASELINE-ACCESS-SWITCH", "TPL-BASELINE-GATEWAY-ROUTER"])
        end = service.get_template("TPL-BASELINE-END-DEVICE").latest_published()
        self.assertEqual((end.constraints["deployable"], end.platforms), (False, []))
