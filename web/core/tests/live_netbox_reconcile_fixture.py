"""V2 Phase 8 LIVE harness -- NSOT reconciliation against a REAL, disposable NetBox, plus the NetworkX rebuild proof.

NOT part of any automated suite (the module name does not match ``test*.py``; skipped unless ``NMAS_P8_NETBOX_ENV`` names the
disposable instance's client.env).  The NetBox is ``labs/managed-scope-isolated/netbox.sh`` (own containers, no named volumes,
API on 127.0.0.1:18069 only, seeded with the repository's populate_netbox.py production model); production NetBox
(127.0.0.1:8000) is never contacted -- the harness refuses any other URL.

    NMAS_P8_NETBOX_ENV=<netbox runtime>/client.env NMAS_P8_EVIDENCE=<dir> DJANGO_DEBUG=1 \\
        manage.py test core.tests.live_netbox_reconcile_fixture --testrunner core.tests.runner.NmasTestRunner

REAL: NetBox 4 and its API / validation, pynetbox, ``nsot.PynetboxClient``, the dispatcher, the outbox, the projection, the
topology rebuild and its NetworkX graph.  SUBSTITUTED: the NMAS database is the Django test database (the lab shape of
``helpers.management.lab``); the lifecycle transitions are the services' own (attachments, selector) or the test-only
``force_state`` the other Phase 8 tests use for DECOMMISSIONED.  OPERATOR DATA the harness seeds in the disposable NetBox (NMAS
never creates these): S1 Ethernet7 (physical, access VLAN 30), VRF MGMT, two management addresses (one deliberately assigned
to R2 for the conflict case); between runs it removes what an earlier run of this harness made.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import unittest
from datetime import timedelta
from pathlib import Path

from django.db import transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from core import models
from core.services.commissioning import outbox
from core.services.infrastructure import dispatcher, nsot, topology
from core.tests import test_infrastructure_fixtures as F

ENV = Path(os.environ["NMAS_P8_NETBOX_ENV"]) if os.environ.get("NMAS_P8_NETBOX_ENV") else None
EVIDENCE = Path(os.environ["NMAS_P8_EVIDENCE"]) if os.environ.get("NMAS_P8_EVIDENCE") else None
ALLOWED_URL = "http://127.0.0.1:18069"
NETBOX_CONTAINER = "nmas-p69-nb-netbox"
R1_MGMT, R1_MGMT_IP, CONFLICT_IP = "Ethernet3", "10.254.99.1/30", "10.254.99.5/30"
P, Topic = models.NsotProjectionState, models.OutboxTopic


def evidence(name: str, payload) -> None:
    if EVIDENCE is None:
        return
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    assert "nbt_" not in text and "Token " not in text, f"evidence {name} would carry the API token"
    (EVIDENCE / name).write_text(text + "\n", encoding="utf-8")


def client_env() -> dict:
    values = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    return values


@unittest.skipUnless(ENV, "live NetBox harness: set NMAS_P8_NETBOX_ENV to the disposable NetBox client.env")
@override_settings(NMAS_NSOT_RECONCILE_WRITE=True)
class LiveNetboxReconcile(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import pynetbox

        values = client_env()
        if values.get("NETBOX_URL", "").rstrip("/") != ALLOWED_URL:
            raise unittest.SkipTest("refusing: not the disposable NetBox")
        cls.api = pynetbox.api(ALLOWED_URL, token=values["NETBOX_TOKEN"])
        cls.api.http_session.trust_env = False
        cls.seeded = cls.seed()

    # -- operator data in the disposable NetBox ---------------------------------------------------------------------------------
    @classmethod
    def seed(cls) -> dict:
        api = cls.api
        s1, new1, r2 = (api.dcim.devices.get(name=n) for n in ("S1", "NEW1", "R2"))
        vlan30, = list(api.ipam.vlans.filter(vid=30))
        vlan20, = list(api.ipam.vlans.filter(vid=20))
        cls.vlans = {30: vlan30.id, 20: vlan20.id}
        for device, name in (("NEW1", "Ethernet1"), ("S1", "Ethernet7")):          # cables left by an earlier run
            row = api.dcim.interfaces.get(device=device, name=name)
            if row is not None and row.cable:
                api.dcim.cables.get(row.cable.id).delete()
        port = api.dcim.interfaces.get(device="S1", name="Ethernet7") or api.dcim.interfaces.create(device=s1.id, name="Ethernet7", type="1000base-t")
        port.update({"type": "1000base-t", "mode": "access", "untagged_vlan": vlan30.id, "tagged_vlans": []})
        new1_port = api.dcim.interfaces.get(device="NEW1", name="Ethernet1")
        new1_port.update({"type": "virtual"})                                         # the production model's type (populate_netbox)
        new1.update({"status": "active"})
        stale = api.dcim.interfaces.get(device="R1", name=R1_MGMT)
        for address in (R1_MGMT_IP, CONFLICT_IP):
            row = api.ipam.ip_addresses.get(address=address)
            if row is not None:
                row.delete()
        if stale is not None:
            stale.delete()
        vrf = api.ipam.vrfs.get(name="MGMT") or api.ipam.vrfs.create(name="MGMT", enforce_unique=True)
        api.ipam.ip_addresses.create(address=R1_MGMT_IP, status="active", description="NMAS P8 live: R1 management (operator IPAM)")
        r2_port = api.dcim.interfaces.get(device="R2", name="Ethernet2")
        api.ipam.ip_addresses.create(address=CONFLICT_IP, status="active", assigned_object_type="dcim.interface",
                                     assigned_object_id=r2_port.id, description="NMAS P8 live: held by R2 (conflict case)")
        return {"s1_ethernet7": {"type": "1000base-t", "mode": "access", "untagged": 30}, "new1_ethernet1": "virtual",
                "vrf": vrf.name, "ips": [R1_MGMT_IP, CONFLICT_IP], "r2": r2.name}

    def nsot_client(self):
        return nsot.PynetboxClient(self.api)

    def dispatch(self, **kwargs):
        return dispatcher.dispatch("nsot", limit=500, nsot_client=self.nsot_client(), **kwargs)

    def netbox(self, device, interface) -> dict:
        row = self.api.dcim.interfaces.get(device=device, name=interface)
        if row is None:
            return {}
        peers = list(row.link_peers or []) if row.cable else []
        return {"type": str(row.type.value), "cable": row.cable.id if row.cable else None,
                "peer": f"{peers[0].device.name}:{peers[0].name}" if peers else None}

    def projection(self, device) -> dict:
        row = models.NsotProjection.objects.get(device=device)
        return {"state": row.state, "codes": [p["code"] for p in row.discrepancies], "planned": [o["op"] for o in row.desired["planned_operations"]],
                "applied": len(row.applied)}

    def test_reconciliation_against_real_netbox(self):
        record = {"seed": self.seeded, "steps": []}
        self.addCleanup(lambda: evidence("netbox-reconcile.json", record))

        def step(label, **values):
            record["steps"].append({"step": label, "at": timezone.now().isoformat(), **values})

        env = F.lab()
        device, _attachment = F.new_device_with_verified_uplink()           # NEW1 Ethernet1 -> S1 Ethernet7, access VLAN 30

        # 1. writes disabled: planned only, NetBox untouched
        with override_settings(NMAS_NSOT_RECONCILE_WRITE=False):
            self.dispatch()
        first = self.projection(device)
        step("write disabled", projection=first, netbox_status=str(self.api.dcim.devices.get(name="NEW1").status.value))
        self.assertEqual(first["state"], P.PLANNED)
        self.assertEqual(str(self.api.dcim.devices.get(name="NEW1").status.value), "active")

        # 2. writes enabled: status written; the cable is refused -- NEW1 Ethernet1 is "virtual" in the production model
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        self.dispatch()
        second = self.projection(device)
        step("virtual endpoint", projection=second, netbox_status=str(self.api.dcim.devices.get(name="NEW1").status.value),
             new1_ethernet1=self.netbox("NEW1", "Ethernet1"))
        self.assertEqual((second["state"], second["codes"]), (P.DISCREPANCY, ["CABLE_ENDPOINT_NOT_CONNECTABLE"]))
        self.assertEqual(str(self.api.dcim.devices.get(name="NEW1").status.value), "planned")
        self.assertIsNone(self.netbox("NEW1", "Ethernet1")["cable"])

        # 3. the operator corrects the interface type in NetBox -> the cable is created once; a replay changes nothing
        self.api.dcim.interfaces.get(device="NEW1", name="Ethernet1").update({"type": "1000base-t"})
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        self.dispatch()
        third = self.projection(device)
        cable = self.netbox("NEW1", "Ethernet1")
        step("cable created", projection=third, new1_ethernet1=cable, s1_ethernet7=self.netbox("S1", "Ethernet7"))
        self.assertEqual((third["state"], cable["peer"]), (P.IN_SYNC, "S1:Ethernet7"))
        cables_before = self.api.dcim.cables.count()
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        self.dispatch()
        step("replay", projection=self.projection(device), cables=self.api.dcim.cables.count())
        self.assertEqual((self.api.dcim.cables.count(), self.netbox("NEW1", "Ethernet1")["cable"]), (cables_before, cable["cable"]))

        # 4. VLAN drift in NetBox (S1 Ethernet7 moved to VLAN 20): a discrepancy, the peer port is never edited by NMAS
        self.api.dcim.interfaces.get(device="S1", name="Ethernet7").update({"untagged_vlan": self.vlans[20]})
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        self.dispatch()
        drift = self.projection(device)
        step("vlan drift", projection=drift)
        self.assertEqual(drift["codes"], ["VLAN_MISMATCH"])
        self.assertEqual(self.api.dcim.interfaces.get(device="S1", name="Ethernet7").untagged_vlan.vid, 20)
        self.api.dcim.interfaces.get(device="S1", name="Ethernet7").update({"untagged_vlan": self.vlans[30]})
        F.fact(device, outbox.ATTACHMENT_CHANGED)
        self.dispatch()
        self.assertEqual(self.projection(device)["state"], P.IN_SYNC)

        # 5. admission hand-off + management VRF (R1 on its routed VRF path): interface, address and VRF assigned in NetBox
        r1 = env["devices"]["R1"]
        oob = F.activate(r1, F.oob_path(env))
        F.activate(r1, F.vrf_path(r1, env), previous=oob, kind=F.K.FAILOVER)
        self.admit(r1, R1_MGMT_IP)
        self.dispatch()
        address = self.api.ipam.ip_addresses.get(address=R1_MGMT_IP)
        r1_projection = self.projection(r1)
        step("admission + VRF", projection=r1_projection, address={"interface": address.assigned_object.name if address.assigned_object else None,
                                                                    "device": address.assigned_object.device.name if address.assigned_object else None,
                                                                    "vrf": address.vrf.name if address.vrf else None})
        self.assertEqual(r1_projection["state"], P.IN_SYNC, r1_projection)
        self.assertEqual((address.assigned_object.device.name, address.assigned_object.name, address.vrf.name), ("R1", R1_MGMT, "MGMT"))

        # 6. conflict: the admitted address is held by another device in NetBox -> discrepancy, never moved
        r3 = env["devices"]["S3"]
        self.admit(r3, CONFLICT_IP, interface="Ethernet1")
        self.dispatch()
        held = self.api.ipam.ip_addresses.get(address=CONFLICT_IP)
        step("address held elsewhere", projection=self.projection(r3), held_by=held.assigned_object.device.name)
        self.assertIn("MGMT_IP_ASSIGNED_ELSEWHERE", self.projection(r3)["codes"])
        self.assertEqual(held.assigned_object.device.name, "R2")

        # 7. maintenance: recorded in the projection; NetBox 4 has no maintenance device status, so the status is unchanged
        F.maintenance("NEW1")                                                # the maintenance engine's ACTIVE window
        F.fact(device, outbox.HEALTH_CHANGED)
        self.dispatch()
        maintenance = models.NsotProjection.objects.get(device=device).desired.get("maintenance")
        status = str(self.api.dcim.devices.get(name="NEW1").status.value)
        step("maintenance", desired_maintenance=maintenance, netbox_status=status)
        self.assertEqual((maintenance, status), (True, "planned"))
        models.MaintenanceRecord.objects.filter(device_name="NEW1").delete()

        # 8. NetBox unavailable (the disposable container paused) -> retried with backoff, then converges; nothing duplicated
        subprocess.run(["docker", "pause", NETBOX_CONTAINER], check=True, capture_output=True, timeout=60)
        try:
            self.api.http_session.request = _timeout(self.api.http_session.request, 5)
            F.fact(device, outbox.ATTACHMENT_CHANGED)
            down = self.dispatch()
        finally:
            subprocess.run(["docker", "unpause", NETBOX_CONTAINER], check=True, capture_output=True, timeout=60)
        failed = models.LifecycleOutboxEvent.objects.filter(device=device, topic=Topic.NSOT_DEVICE_STATE).order_by("-pk").first()
        step("netbox paused", results=[r.get("code") for r in down["results"]], projection=self.projection(device)["state"],
             attempts=failed.attempts, next_attempt_in_s=(failed.next_attempt_at - timezone.now()).total_seconds() if failed.next_attempt_at else None)
        self.assertIn("NSOT_UNAVAILABLE", {r.get("code") for r in down["results"]})
        self.assertEqual(self.projection(device)["state"], P.UNAVAILABLE)
        for _ in range(30):
            try:
                self.api.status()
                break
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001 - waiting for the unpaused container
                time.sleep(2)
        self.dispatch(now=timezone.now() + timedelta(hours=2))
        step("after restart", projection=self.projection(device), cables=self.api.dcim.cables.count())
        self.assertEqual((self.projection(device)["state"], self.api.dcim.cables.count()), (P.IN_SYNC, cables_before))

        # 9. decommission -> offline; restore -> the successor owns the object (active); the old registration's replay never writes
        old = F.force_state(device, models.DeviceLifecycleState.DECOMMISSIONED)
        F.fact(old, outbox.DECOMMISSIONED, {"decommission": "DEC-LIVE-P8"})
        self.dispatch()
        step("decommissioned", netbox_status=str(self.api.dcim.devices.get(name="NEW1").status.value), projection=self.projection(old))
        self.assertEqual(str(self.api.dcim.devices.get(name="NEW1").status.value), "offline")
        new = F.successor_of(old, admission=models.ProductionAdmissionState.ADMITTED)
        F.fact(new, outbox.RESTORED, {"restoration": "RST-LIVE-P8"})
        self.dispatch()
        step("restored", netbox_status=str(self.api.dcim.devices.get(name="NEW1").status.value), successor=self.projection(new))
        self.assertEqual(str(self.api.dcim.devices.get(name="NEW1").status.value), "active")
        F.fact(old, outbox.DECOMMISSIONED, {"decommission": "DEC-LIVE-P8-replay"})
        self.dispatch()
        old_projection = models.NsotProjection.objects.get(device=old)
        step("replay of the old registration", netbox_status=str(self.api.dcim.devices.get(name="NEW1").status.value),
             superseded_by=old_projection.desired.get("superseded_by"))
        self.assertEqual(str(self.api.dcim.devices.get(name="NEW1").status.value), "active")
        self.assertEqual(old_projection.desired.get("superseded_by"), new.device_id)

        # 10. NetworkX: the operational topology is reconstructable from the NMAS database alone, and replays converge
        dispatcher.dispatch("topology", limit=500)
        before = graph_signature()
        models.TopologyEdge.objects.all().delete()
        models.TopologyNode.objects.all().delete()
        rebuilt = topology.rebuild()
        after = graph_signature()
        dispatcher.dispatch("topology", limit=500)
        replayed = graph_signature()
        record["networkx"] = {"before": before, "after_rebuild": after, "rebuilt_devices": rebuilt, "equal_after_rebuild": before == after,
                              "equal_after_replay": before == replayed}
        self.assertEqual(before, after)
        self.assertEqual(before, replayed)
        record["result"] = "PASS"

    def admit(self, device, address, *, interface=R1_MGMT):
        payload = {"device_id": device.device_id, "name": device.name, "platform": device.platform, "role": device.role,
                   "admission": f"ADM-LIVE-{device.name}", "admitted_at": timezone.now().isoformat(),
                   "management": {"interface": interface, "ipv4": address}, "provisioning_run": "", "config_digest": ""}
        with transaction.atomic():
            outbox.record(device, Topic.NSOT_DEVICE_ADMITTED, payload, subject=payload["admission"], actor="system:p8-live")


def graph_signature() -> dict:
    g = topology.graph()
    return {"nodes": sorted((data.get("name"), data.get("state")) for _n, data in g.nodes(data=True)),
            "edges": sorted((*sorted((g.nodes[a].get("name"), g.nodes[b].get("name"))), data.get("kind")) for a, b, data in g.edges(data=True))}


def _timeout(request, seconds):
    def bounded(method, url, **kwargs):
        kwargs.setdefault("timeout", seconds)
        return request(method, url, **kwargs)
    return bounded
