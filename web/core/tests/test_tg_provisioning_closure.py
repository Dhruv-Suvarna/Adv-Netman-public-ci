"""Lab 7 closure -- new-device provisioning, each symbol called directly: the IPAM rules / planning / reservation / release / activation and the
real ``NetboxGateway`` (over an in-memory pynetbox double), the device registry, the bootstrap classifier and docker prober, the capability gate,
the engine hooks (``gate`` and ``lifecycle``), reconciliation, probation sealing and the read helpers of ``provisioning_service``.

Hermetic: NetBox is ``FakeNetbox`` / ``helpers.provisioning.FakeGateway``; the device is the simulated ``FakeWorld`` of ``helpers.execution``;
``docker`` is replaced by a canned ``_run`` and the Linux reads by patched ``read_frr_config`` / ``docker_exec``.  The only process started is a
read-only local ``git rev-parse HEAD`` (``repository_head``).  No device, NetBox, Docker or socket is reached.  POSITIVE: exact plans, ids,
statuses, digests, rows.  NEGATIVE: malformed management input, VLAN 200 policy violations, conflicts, upstream failures (never leaking upstream
text), missing objects, unknown codes / ids, an unapproved or unreadable device and a run without an execution are refused or reported.
"""
from __future__ import annotations

import hashlib
import ipaddress
import itertools
import json
import subprocess
from types import SimpleNamespace
from unittest import mock

from django.conf import settings
from django.test import SimpleTestCase, TestCase

from core import models
from core.services import provisioning_service as ps
from core.services.health import inventory
from core.services.provisioning import bootstrap, capability_gate, codes, gate, ipam, lifecycle, registry
from core.tests.helpers import provisioning as p

S = models.ProvisioningStatus
DOC = {"device": {"name": "EDGE9", "platform": "ubuntu_frr", "role": "router", "site": "", "status": "planned"},
       "interfaces": [{"name": "eth0", "management": True, "vlan": None}],
       "addresses": [{"address": "172.31.250.11/24", "family": 4, "interface": "eth0", "prefix": "172.31.250.0/24", "role": "management"}],
       "new_prefixes": ["172.31.250.0/24"], "assignment": "static", "tags": [ipam.PROVISIONING_TAG]}


def run_of(management=None, *, disposable=True, name="EDGE9"):
    return SimpleNamespace(management=management if management is not None else dict(p.MANAGEMENT), disposable=disposable, device_name=name,
                           platform="ubuntu_frr", role="router", site="")


# ------------------------------------------------------------------------------------------------------------ pynetbox double
class Obj(SimpleNamespace):
    def update(self, values):
        self.log.append(("update", self.id, values))
        self.__dict__.update(values)

    def delete(self):
        self.log.append(("delete", self.id))
        self.store.pop(self.id, None)


class Endpoint:
    def __init__(self, log, ids, rows=(), *, fail=False):
        self.log, self.ids, self.fail, self.store = log, ids, fail, {}
        for row in rows:
            self._add(**row)

    def _add(self, **values):
        obj = Obj(id=next(self.ids), log=self.log, store=self.store, **values)
        self.store[obj.id] = obj
        return obj

    def _check(self):
        if self.fail:
            raise RuntimeError("upstream said: token abc123 rejected")

    def filter(self, **criteria):
        self._check()
        if "contains" in criteria:
            return [o for o in self.store.values() if ipaddress.ip_address(criteria["contains"]) in ipaddress.ip_network(o.prefix)]
        return [o for o in self.store.values() if all(str(getattr(o, k, "")).split("/")[0] == str(v) for k, v in criteria.items())]

    def all(self):
        self._check()
        return list(self.store.values())

    def get(self, obj_id=None, **criteria):
        self._check()
        if obj_id is not None:
            return self.store.get(obj_id)
        return next(iter(self.filter(**criteria)), None)

    def create(self, **values):
        self._check()
        self.log.append(("create", values.get("name") or values.get("prefix") or values.get("address")))
        return self._add(**values)


class FakeNetbox:
    def __init__(self, *, fail=False, roles=("router",), types=("ubuntu-frr",)):
        self.log, ids = [], itertools.count(1)
        self.dcim = SimpleNamespace(devices=Endpoint(self.log, ids, [{"name": "R1"}], fail=fail), interfaces=Endpoint(self.log, ids, fail=fail),
                                    sites=Endpoint(self.log, ids, [{"name": "lab"}]), device_roles=Endpoint(self.log, ids, [{"slug": r} for r in roles]),
                                    device_types=Endpoint(self.log, ids, [{"slug": t} for t in types]))
        self.ipam = SimpleNamespace(
            prefixes=Endpoint(self.log, ids, [{"prefix": "172.31.250.0/24"}, {"prefix": "172.31.0.0/16"}], fail=fail),
            ip_addresses=Endpoint(self.log, ids, [{"address": "172.31.250.1/24", "status": SimpleNamespace(value="active"),
                                                   "assigned_object": SimpleNamespace(device=SimpleNamespace(name="R1"))}], fail=fail),
            ip_ranges=Endpoint(self.log, ids, [{"start_address": "172.31.250.100/24", "end_address": "172.31.250.200/24"}], fail=fail))
        self.extras = SimpleNamespace(tags=Endpoint(self.log, ids))


class NetboxGatewayTests(SimpleTestCase):
    def setUp(self):
        self.netbox = FakeNetbox()
        self.gw = ipam.NetboxGateway(client=self.netbox)
        self.broken = ipam.NetboxGateway(client=FakeNetbox(fail=True))

    def assertUnavailable(self, call):
        with self.assertRaises(ipam.IpamUnavailable) as raised:
            call()
        self.assertNotIn("abc123", str(raised.exception))

    def test_client_is_the_injected_client(self):
        self.assertIs(self.gw.client, self.netbox)

    def test_reads_return_the_netbox_facts(self):
        self.assertTrue(self.gw.device_exists("R1"))
        self.assertEqual(self.gw.address_holders("172.31.250.1"), [{"address": "172.31.250.1/24", "status": "active", "device": "R1"}])
        self.assertEqual(self.gw.containing_prefix("172.31.250.11"), "172.31.250.0/24")
        self.assertEqual(self.gw.dhcp_ranges_containing("172.31.250.150"), ["172.31.250.100/24-172.31.250.200/24"])

    def test_reads_of_an_unknown_host_or_name_are_empty(self):
        self.assertFalse(self.gw.device_exists("EDGE9"))
        self.assertEqual((self.gw.address_holders("10.9.9.9"), self.gw.containing_prefix("10.9.9.9"), self.gw.dhcp_ranges_containing("10.9.9.9")),
                         ([], None, []))

    def test_reads_of_an_unavailable_netbox_raise_without_upstream_text(self):
        for label, call in (("refused device", lambda: self.broken.device_exists("R1")), ("refused holders", lambda: self.broken.address_holders("172.31.250.1")),
                            ("refused prefix", lambda: self.broken.containing_prefix("172.31.250.1")),
                            ("refused ranges", lambda: self.broken.dhcp_ranges_containing("172.31.250.1"))):
            with self.subTest(label):
                self.assertUnavailable(call)

    def test_creates_activate_and_delete_write_tagged_objects(self):
        provenance = {"prov_id": "PROV-000009", "requested_by": "requester"}
        prefix = self.gw.create_prefix("172.31.251.0/24", tags=["nmas-provisioning"], provenance=provenance)
        device = self.gw.create_device(DOC["device"], tags=["nmas-provisioning"], provenance=provenance)
        interface = self.gw.create_interface(device, DOC["interfaces"][0], tags=["nmas-provisioning"])
        address = self.gw.create_address(DOC["addresses"][0], interface, tags=["nmas-provisioning"], provenance=provenance)
        stored = self.netbox.dcim.devices.store[device]
        self.assertEqual((stored.status, stored.comments), ("planned", "NMAS provisioning PROV-000009 requested by requester"))
        self.assertEqual((self.netbox.dcim.interfaces.store[interface].mgmt_only, self.netbox.ipam.ip_addresses.store[address].assigned_object_id), (True, interface))
        self.assertEqual(len(self.netbox.extras.tags.store), 1)                       # the tag is created once and reused
        created = [{"kind": "prefix", "id": prefix}, {"kind": "device", "id": device}, {"kind": "interface", "id": interface}, {"kind": "ip_address", "id": address}]
        self.gw.activate(created, managed=False)
        self.assertEqual([self.netbox.dcim.devices.store[device].status, self.netbox.ipam.ip_addresses.store[address].status], ["active", "active"])
        self.gw.delete("device", device)
        self.assertNotIn(device, self.netbox.dcim.devices.store)

    def test_creates_of_an_unavailable_netbox_or_unknown_role_raise(self):
        tags, provenance = ["nmas-provisioning"], {"prov_id": "PROV-1"}
        for label, call in (("refused prefix", lambda: self.broken.create_prefix("10.0.0.0/24", tags=tags, provenance=provenance)),
                            ("refused device", lambda: self.broken.create_device(DOC["device"], tags=tags, provenance=provenance)),
                            ("refused unknown role", lambda: ipam.NetboxGateway(client=FakeNetbox(roles=())).create_device(DOC["device"], tags=tags, provenance=provenance)),
                            ("refused interface", lambda: self.broken.create_interface(1, DOC["interfaces"][0], tags=tags)),
                            ("refused address", lambda: self.broken.create_address(DOC["addresses"][0], 1, tags=tags, provenance=provenance))):
            with self.subTest(label):
                self.assertUnavailable(call)

    def test_activate_of_a_missing_object_and_delete_on_an_unavailable_netbox_raise(self):
        self.assertUnavailable(lambda: self.gw.activate([{"kind": "device", "id": 999}], managed=True))
        self.assertUnavailable(lambda: self.broken.delete("device", 1))


# ------------------------------------------------------------------------------------------------------------------ IPAM rules
class IpamRuleTests(TestCase):
    def test_inventory_networks_names_and_addresses_come_from_the_tracked_inventory(self):
        document = inventory.load_inventory()
        management = document.get("management") or {}
        expected = [ipaddress.ip_interface(str(management[k])).network for k in ("nmas_ipv4", "nmas_ipv6") if management.get(k)]
        self.assertEqual(ipam.management_networks(), expected)
        self.assertTrue({"R1", "WebServer"} <= ipam.inventory_names())
        r1 = (document["network_devices"]["R1"].get("monitoring") or {}).get("address")
        self.assertIn(str(ipaddress.ip_address(r1)), ipam.inventory_addresses())

    def test_parse_management_normalizes_a_static_request(self):
        parsed, blockers = ipam.parse_management({**p.MANAGEMENT, "vlan": "201"})
        self.assertEqual(blockers, [])
        self.assertEqual((parsed["interface"], parsed["vlan"], parsed["assignment"], [str(a) for a in parsed["addresses"]]),
                         ("eth0", 201, "static", ["172.31.250.11/24", "fd00:ca:250::11/64"]))

    def test_parse_management_refuses_malformed_input(self):
        for label, management in (("refused swapped family", {"interface": "eth0", "ipv4": "fd00::1/64"}), ("refused missing prefix", {"interface": "eth0", "ipv4": "10.0.0.1"}),
                                  ("refused missing interface", {"ipv4": "10.0.0.1/24"}), ("refused unknown assignment", {**p.MANAGEMENT, "assignment": "bootp"})):
            with self.subTest(label):
                self.assertEqual(ipam.parse_management(management), (None, [codes.blocker("MANAGEMENT_ADDRESS_INVALID")]))

    def test_vlan_policy_allows_static_dual_stack_and_other_vlans(self):
        parsed, _ = ipam.parse_management({"interface": "Vlan200", "vlan": 200, "ipv4": "192.168.200.77/24", "ipv6": "2001:db8:200::77/64"})
        self.assertEqual(ipam.vlan_policy_blockers(parsed, disposable=False), [])
        self.assertEqual(ipam.vlan_policy_blockers(ipam.parse_management(p.MANAGEMENT)[0], disposable=True), [])

    def test_vlan_policy_refuses_dhcp_disposable_or_single_stack_on_vlan200(self):
        base = {"interface": "Vlan200", "vlan": 200, "ipv4": "192.168.200.77/24", "ipv6": "2001:db8:200::77/64"}
        for label, management, disposable, code in (("refused dhcp", {**base, "assignment": "dhcp"}, False, "VLAN200_DHCP_FORBIDDEN"),
                                                    ("refused disposable", base, True, "DISPOSABLE_IN_PRODUCTION_MANAGEMENT"),
                                                    ("refused single stack", {k: v for k, v in base.items() if k != "ipv6"}, False, "VLAN200_DUAL_STACK_REQUIRED")):
            with self.subTest(label):
                self.assertEqual([b["code"] for b in ipam.vlan_policy_blockers(ipam.parse_management(management)[0], disposable=disposable)], [code])

    def test_plan_of_a_free_disposable_device_reserves_new_prefixes(self):
        document, blockers = ipam.plan(run_of(), p.FakeGateway())
        self.assertEqual(blockers, [])
        self.assertEqual((document["new_prefixes"], document["tags"]), (["172.31.250.0/24", "fd00:ca:250::/64"], [ipam.PROVISIONING_TAG, ipam.DISPOSABLE_TAG]))
        self.assertEqual([a["address"] for a in document["addresses"]], ["172.31.250.11/24", "fd00:ca:250::11/64"])

    def test_plan_refuses_conflicts_invalid_input_and_an_unavailable_netbox(self):
        with self.subTest("refused conflicts"):
            _doc, blockers = ipam.plan(run_of(name="R1"), p.FakeGateway(addresses={"172.31.250.11": "OTHER"}))
            self.assertEqual([b["code"] for b in blockers], ["NAME_CONFLICT", "MGMT_IP_DUPLICATE"])
        with self.subTest("refused invalid input"):
            self.assertEqual(ipam.plan(run_of({"interface": ""}), p.FakeGateway()), ({}, [codes.blocker("MANAGEMENT_ADDRESS_INVALID")]))
        with self.subTest("refused unavailable netbox"):
            self.assertEqual(ipam.plan(run_of(), p.FakeGateway(available=False)), ({}, [codes.blocker("IPAM_UNAVAILABLE")]))

    def test_reserve_activate_and_release_write_exactly_the_planned_objects(self):
        gateway = p.FakeGateway()
        refs = ipam.reserve(DOC, gateway, provenance={"prov_id": "PROV-9"})
        self.assertEqual([c["kind"] for c in refs["created"]], ["prefix", "device", "interface", "ip_address"])
        self.assertEqual(ipam.activate(gateway, refs, managed=True)["status"], "active")
        report = ipam.release(gateway, refs["created"])
        self.assertEqual(([r["kind"] for r in report], all(r["released"] for r in report), gateway.objects), (["ip_address", "interface", "device", "prefix"], True, {}))

    def test_reserve_failure_releases_what_it_created_and_raises(self):
        gateway = p.FakeGateway()
        gateway.fail_on = "ip_address"
        with self.assertRaises(ipam.ReservationFailed) as raised:
            ipam.reserve(DOC, gateway, provenance={})
        self.assertEqual(([c["kind"] for c in raised.exception.created], gateway.objects), (["prefix", "device", "interface"], {}))

    def test_release_reports_an_object_it_could_not_delete_and_activate_of_an_unavailable_netbox_raises(self):
        gateway = p.FakeGateway()
        refs = ipam.reserve(DOC, gateway, provenance={})
        gateway.fail_delete = {"device"}
        self.assertEqual([r["released"] for r in ipam.release(gateway, refs["created"])], [True, True, False, True])
        gateway.available = False
        with self.assertRaises(ipam.IpamUnavailable):
            ipam.activate(gateway, refs, managed=False)

    def test_reservation_failed_carries_what_was_created_and_released(self):
        with self.subTest("created and released lists kept"):
            error = ipam.ReservationFailed([{"kind": "device", "released": True}], [{"kind": "device"}])
        self.assertEqual((str(error), error.released, error.created), ("IPAM_RESERVATION_FAILED", [{"kind": "device", "released": True}], [{"kind": "device"}]))
        with self.subTest("refused reservation keeps a leftover"):
            leftover = ipam.ReservationFailed([{"kind": "device", "released": False}], [{"kind": "device"}])
            self.assertFalse(leftover.released[0]["released"])

    def test_blocker_carries_message_remediation_and_details(self):
        with self.subTest("name code with details"):
            found = codes.blocker("NAME_CONFLICT", name="R1")
        self.assertEqual((found["code"], found["details"]), ("NAME_CONFLICT", {"name": "R1"}))
        self.assertEqual(set(found), {"code", "message", "remediation", "details"})

    def test_blocker_of_an_unknown_code_raises(self):
        with self.assertRaises(KeyError):
            codes.blocker("NOT_A_CODE")


# ------------------------------------------------------------------------------------------------- bootstrap, capability gate
def docker(answers):
    def run(argv):
        key = argv[1] if argv[1] == "inspect" else argv[3]
        code, out = answers[key]
        return subprocess.CompletedProcess(argv, code, out, "")
    return run


INSPECT = json.dumps([{"State": {"Running": True}, "Config": {"Image": "frr:9", "Labels": {"containerlab": "nmas-prov-proof", "clab-node-kind": "linux"}}}])
PRISTINE = {"inspect": (0, INSPECT), "vtysh": (0, "frr version 9\n!\n"), "ip": (0, json.dumps([{"ifname": "lo"}, {"ifname": "eth0"}, {"ifname": "eth1"}]))}


class BootstrapCapabilityTests(TestCase):
    def test_transport_support_and_target_blockers_accept_docker_exec_on_frr(self):
        self.assertEqual(bootstrap.transport_support("ubuntu_frr", "DOCKER_EXEC")[0], True)
        self.assertEqual(bootstrap.target_blockers("ubuntu_frr", "DOCKER_EXEC", p.TARGET), [])
        self.assertEqual(bootstrap.production_lab(), inventory.load_inventory()["lab_name"])

    def test_transport_and_target_refuse_unproven_or_production_targets(self):
        with self.subTest("refused unproven transport"):
            self.assertEqual(bootstrap.transport_support("arista_ceos", "DOCKER_EXEC"), (False, bootstrap.UNSUPPORTED_REASON["arista_ceos"]))
        production = bootstrap.production_lab()
        for label, platform, target, code in (("refused transport", "arista_ceos", p.TARGET, "BOOTSTRAP_TRANSPORT_UNSUPPORTED"),
                                              ("refused invalid", "ubuntu_frr", {"container": "bad name", "lab": "x"}, "BOOTSTRAP_TARGET_INVALID"),
                                              ("refused production", "ubuntu_frr", {"container": f"clab-{production}-R1", "lab": "other"}, "BOOTSTRAP_TARGET_IS_PRODUCTION")):
            with self.subTest(label):
                self.assertEqual([b["code"] for b in bootstrap.target_blockers(platform, "DOCKER_EXEC", target)], [code])

    def test_configured_interfaces_never_counts_lo_management_or_unaddressed_links(self):
        links = [{"ifname": "lo", "addr_info": [{"scope": "global"}]}, {"ifname": "eth0", "addr_info": [{"scope": "global"}]}, {"ifname": "eth1", "addr_info": [{"scope": "link"}]}]
        self.assertEqual(bootstrap.configured_interfaces(links, "eth0"), [])

    def test_docker_prober_reads_a_pristine_running_container(self):
        with mock.patch.object(bootstrap, "_run", side_effect=docker(PRISTINE)):
            probe = bootstrap.docker_prober({**p.TARGET, "management_interface": "eth0"})
        self.assertEqual((probe.exists, probe.running, probe.lab, probe.answers, probe.configured, probe.error), (True, True, "nmas-prov-proof", True, False, ""))
        self.assertEqual(probe.facts["interfaces"], ["eth0", "eth1", "lo"])

    def test_classify_a_reachable_pristine_device(self):
        run = SimpleNamespace(platform="ubuntu_frr", bootstrap_transport="DOCKER_EXEC", bootstrap_target=dict(p.TARGET), management=dict(p.MANAGEMENT))
        state, evidence, blockers = bootstrap.classify(run, prober=p.prober())
        self.assertEqual((state, evidence["answers"], blockers), (models.BootstrapState.REACHABLE_BOOTSTRAP, True, []))

    def test_classify_refuses_a_target_in_another_lab_or_an_unproven_transport(self):
        run = SimpleNamespace(platform="ubuntu_frr", bootstrap_transport="DOCKER_EXEC", bootstrap_target=dict(p.TARGET), management={})
        with self.subTest("refused other lab"):
            self.assertEqual(bootstrap.classify(run, prober=p.prober(lab="elsewhere"))[2][0]["code"], "BOOTSTRAP_TARGET_INVALID")
        with self.subTest("refused transport"):
            self.assertEqual(bootstrap.classify(SimpleNamespace(**{**run.__dict__, "platform": "sonic"}))[0], models.BootstrapState.UNKNOWN)

    def test_supported_features_resolve_platform_and_plan_follow_the_evidence(self):
        p.support(p.FRR, "interface.LOOPBACK")
        self.assertEqual(capability_gate.supported_features(p.FRR), ["interface.LOOPBACK"])
        resolution, blockers = capability_gate.resolve_platform(p.FRR, "DOCKER_EXEC")
        self.assertEqual((blockers, resolution["supported_count"], resolution["transport"]["supported"]), ([], 1, True))
        lab = p.Lab()
        lab.through("plan")
        resolution, blockers = capability_gate.resolve_plan(p.FRR, lab.run.plan)
        self.assertEqual((blockers, [c["feature"] for c in resolution["cells"]]), ([], ["interface.LOOPBACK"]))

    def test_resolve_platform_and_features_without_evidence_are_refused(self):
        self.assertEqual(capability_gate.supported_features(p.FRR), [])
        _resolution, blockers = capability_gate.resolve_platform("sonic", "DOCKER_EXEC")
        self.assertEqual([b["code"] for b in blockers], ["BOOTSTRAP_TRANSPORT_UNSUPPORTED", "CAPABILITY_UNSUPPORTED"])


# ---------------------------------------------------------------------------------------------------------- registry, hooks
class RegistryHookTests(TestCase):
    def approved(self, name="EDGE1"):
        lab = p.Lab(name=name, target={**p.TARGET, "container": f"clab-nmas-prov-proof-{name.lower()}"})
        lab.through("approve")
        return lab

    def provisioned_without_hook(self):
        lab = self.approved()
        with mock.patch.object(gate, "after_execution"):
            lab.provision()
        lab.run.refresh_from_db()
        return lab

    def test_admit_devices_lookup_activate_and_retire_a_registry_entry(self):
        lab = p.Lab()
        lab.through("bootstrap")
        row = registry.admit(lab.run, netbox_device_id=7)
        self.assertEqual((registry.devices()["EDGE1"]["platform"], registry.devices()["EDGE1"]["address"]), ("linux", "172.31.250.11"))
        self.assertEqual((registry.live_entry("EDGE1").pk, registry.owner_of_container(p.TARGET["container"]).pk, registry.is_provisioned("EDGE1")), (row.pk, row.pk, True))
        self.assertEqual(registry.activate(row).state, registry.State.ACTIVE)
        self.assertEqual(registry.retire(row).state, registry.State.RETIRED)
        self.assertEqual(registry.devices(), {})

    def test_registry_lookups_of_unknown_or_retired_entries_are_none(self):
        lab = p.Lab()
        lab.through("bootstrap")
        row = registry.retire(registry.admit(lab.run))
        with self.subTest("refused second retire keeps the time"):
            self.assertEqual(registry.retire(row, now=None).retired_at, row.retired_at)
        self.assertEqual((registry.owner_of_container(""), registry.owner_of_container(p.TARGET["container"]), registry.is_provisioned("EDGE1")), (None, None, False))
        self.assertFalse(registry.admitted_for("EDGE1", lab.run.change))
        with self.subTest("refused activation of a retired entry"), self.assertRaisesMessage(ValueError, "A retired ProvisionedDevice is history"):
            registry.activate(row)

    def test_admit_refuses_a_second_live_entry_for_one_name(self):
        from django.db import IntegrityError, transaction

        lab = p.Lab()
        lab.through("bootstrap")
        registry.admit(lab.run)
        with self.assertRaises(IntegrityError), transaction.atomic():
            registry.admit(lab.run)

    def test_execution_hooks_pass_an_approved_reachable_device(self):
        lab = self.approved()
        self.assertEqual((gate.blockers(lab.run.change), lifecycle.execution_blockers(lab.run.change)), ([], []))
        with mock.patch.object(lifecycle, "CONFIG_READER", lab.config_reader):
            self.assertEqual(gate.before_first_mutation(lab.run.change), [])
        lab.run.refresh_from_db()
        self.assertEqual((lab.run.status, lab.run.pre_config_digest), (S.PROVISIONING, hashlib.sha256(lab.config_reader({"name": "EDGE1"}).encode()).hexdigest()))

    def test_execution_hooks_refuse_an_unapproved_or_unreadable_device(self):
        lab = p.Lab()
        lab.through("plan")
        with self.subTest("refused not approved"):
            self.assertEqual([b["code"] for b in gate.blockers(lab.run.change)], ["PROVISIONING_NOT_APPROVED"])
            self.assertEqual([b["code"] for b in lifecycle.execution_blockers(lab.run.change)], ["PROVISIONING_NOT_APPROVED"])
            self.assertEqual([b["code"] for b in lifecycle.before_first_mutation(lab.run.change)], ["PROVISIONING_NOT_APPROVED"])
        approved = self.approved("EDGE2")
        with self.subTest("refused unreadable"), mock.patch.object(lifecycle, "CONFIG_READER", side_effect=RuntimeError("READ_FAILED")):
            self.assertEqual([b["code"] for b in gate.before_first_mutation(approved.run.change)], ["PROVISIONING_BASELINE_UNREADABLE"])
            self.assertEqual(lifecycle.config_digest(approved.run), "")

    def test_lifecycle_before_first_mutation_records_the_baseline_digest(self):
        lab = self.approved("EDGE3")
        with mock.patch.object(lifecycle, "CONFIG_READER", lab.config_reader):
            self.assertEqual(lifecycle.before_first_mutation(lab.run.change), [])
        lab.run.refresh_from_db()
        self.assertEqual((lab.run.status, len(lab.run.pre_config_digest)), (S.PROVISIONING, 64))

    def test_lifecycle_after_execution_records_a_verified_provision(self):
        lab = self.provisioned_without_hook()
        with mock.patch.object(lifecycle, "CONFIG_READER", lab.config_reader):
            result = lifecycle.after_execution(lab.run.execution_run or models.ChangeExecutionRun.objects.get(change=lab.run.change))
        self.assertTrue(result.ok, result.blockers)
        lab.run.refresh_from_db()
        self.assertEqual((lab.run.status, lab.run.result["execution_outcome"]), (S.POSTCHECKED, "SUCCEEDED"))

    def test_gate_after_execution_records_a_verified_provision(self):
        lab = self.provisioned_without_hook()
        with mock.patch.object(lifecycle, "CONFIG_READER", lab.config_reader):
            self.assertIsNone(gate.after_execution(models.ChangeExecutionRun.objects.get(change=lab.run.change)))
        lab.run.refresh_from_db()
        self.assertEqual(lab.run.status, S.POSTCHECKED)

    def test_after_execution_of_an_ordinary_change_returns_none(self):
        with self.subTest("refused ordinary change is not a provisioning run"):
            self.assertIsNone(lifecycle.after_execution(SimpleNamespace(change_id=-1)))
            self.assertIsNone(gate.after_execution(SimpleNamespace(change_id=-1)))

    def test_config_digest_and_linux_config_reader_read_the_registered_device(self):
        lab = p.Lab()
        lab.through("bootstrap")
        registry.admit(lab.run)
        with mock.patch.object(lifecycle, "CONFIG_READER", lambda device: "frr 9"):
            self.assertEqual(lifecycle.config_digest(lab.run), hashlib.sha256(b"frr 9").hexdigest())
        from core.services.execution.executors import linux
        with mock.patch.object(linux, "read_frr_config", return_value="frr 9"), \
                mock.patch.object(linux, "docker_exec", return_value=subprocess.CompletedProcess([], 0, "[]", "")) as exec_:
            self.assertEqual(lifecycle.linux_config_reader({"container": "clab-x-edge1"}), "frr 9\n--links--\n[]")
        self.assertEqual(exec_.call_args.args[:2], ("clab-x-edge1", ["ip", "-j", "addr", "show"]))

    def test_config_digest_and_linux_config_reader_refuse_an_unknown_or_unreadable_device(self):
        self.assertEqual(lifecycle.config_digest(SimpleNamespace(device_name="NOPE")), "")
        from core.services.execution.executors import linux
        with mock.patch.object(linux, "read_frr_config", return_value="x"), \
                mock.patch.object(linux, "docker_exec", return_value=subprocess.CompletedProcess([], 1, "", "no container")), \
                self.assertRaisesMessage(RuntimeError, "READ_FAILED"):
            lifecycle.linux_config_reader({"container": "clab-x-edge1"})

    def test_candidate_text_lists_every_configlet_in_plan_order(self):
        lab = p.Lab()
        lab.through("plan")
        text = lifecycle.candidate_text(lab.run.plan)
        first = lab.run.plan.configlets.order_by("sequence").first()
        self.assertTrue(text.startswith(f"! {first.cfg_id} {first.target_device}\n"))
        self.assertTrue(text.endswith("\n"))

    def test_candidate_text_of_an_empty_plan_is_a_newline(self):
        self.assertEqual(lifecycle.candidate_text(SimpleNamespace(configlets=SimpleNamespace(order_by=lambda *_: []))), "\n")

    def test_reconcile_releases_the_reservation_and_retires_the_entry(self):
        lab = p.Lab()
        lab.through("ipam")
        lab.run.refresh_from_db()
        registry.admit(lab.run)
        report = lifecycle.reconcile(lab.run, gateway=lab.gateway)
        self.assertEqual((report["clean"], report["registry"], lab.gateway.objects), (True, "RETIRED", {}))

    def test_reconcile_reports_a_leftover_it_could_not_release(self):
        lab = p.Lab()
        lab.through("ipam")
        lab.run.refresh_from_db()
        lab.gateway.fail_delete = {"device"}
        report = lifecycle.reconcile(lab.run, gateway=lab.gateway)
        self.assertEqual((report["clean"], report["registry"], lab.gateway.kinds()), (False, "NONE", ["device"]))

    def test_probation_candidate_seals_the_probation_bundle(self):
        lab = p.Lab()
        lab.through("sync")
        bundle, blockers, eligibility = lifecycle.probation_candidate(lab.run, actor="approver")
        self.assertEqual((bundle.kind, blockers, eligibility.eligible), (models.BundleKind.PROBATION, [], True))

    def test_probation_candidate_without_an_execution_is_refused(self):
        self.assertEqual(lifecycle.probation_candidate(SimpleNamespace(execution_run=None), actor="a"),
                         (None, [codes.blocker("PROBATION_NOT_STARTABLE", step="EXECUTION")], None))

    def test_repository_head_is_the_checked_out_commit(self):
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=settings.REPO_ROOT, capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(lifecycle.repository_head(), head)


# ------------------------------------------------------------------------------------------------------- provisioning_service
class ProvisioningServiceReadTests(TestCase):
    def test_list_runs_returns_the_requests(self):
        lab = p.Lab()
        self.assertEqual([r.pk for r in ps.list_runs()], [lab.run.pk])

    def test_list_and_get_without_requests_or_with_a_malformed_id_are_empty(self):
        self.assertEqual((ps.list_runs(), ps.get_run("PROV-x1"), ps.get_run(None), ps.get_run("PROV-000099")), ([], None, None, None))

    def test_next_stage_of_a_finished_run_is_empty(self):
        self.assertEqual(ps.next_stage(SimpleNamespace(is_terminal=True, status=S.DRAFT)), "")

    def test_stage_rows_of_a_blocked_stage_report_it_blocked(self):
        lab = p.Lab(gateway=p.FakeGateway(available=False))
        lab.through("ipam")
        rows = {row["stage"] if "stage" in row else row.get("name"): row for row in ps.stage_rows(lab.run)}
        blocked = [row for row in ps.stage_rows(lab.run) if row.get("state") == "BLOCKED"]
        self.assertEqual(len(blocked), 1, rows)
