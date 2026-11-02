"""Lab 7 closure -- Maintenance Mode service read paths, each called directly: the writable scope, the management
interfaces a maintenance must never touch, the production runtime wiring (built, never connected), the unresolved
record of a device, the Change conflict rule and the status view.  Test database only; no device, no NetBox call.
"""

from __future__ import annotations

from django.test import SimpleTestCase, TestCase

from core.services.maintenance_mode import collector, lifecycle, model, service, store
from core.services.maintenance_mode.model import ACTIVE
from core.services.route_shield import migration
from core.tests import test_maintenance_mode as mm
from core.tests.test_maintenance_live import topo


def runtime(writable=None):
    return service.Runtime(collector.Sources(topo(), read=None), environment=None, start_probes=None, definition=migration.PRODUCTION, writable=writable)


class RuntimeScopeTests(SimpleTestCase):
    def test_scope_is_the_writable_managed_set_or_the_whole_topology(self):
        self.assertEqual(runtime(lambda: ["R1", "S1"]).scope(), {"R1", "S1"})
        self.assertEqual(runtime().scope(), set(topo().devices))

    def test_management_interfaces_include_inventory_cabled_and_out_of_band_ports(self):
        found = service.management_interfaces({"network_devices": {"R1": {"monitoring": {"source_interface": "Vlan200"}}}}, topo())
        self.assertEqual(found["R1"], ("Management0", "Management1", "Vlan200", "eth0", "eth9"))

    def test_management_interfaces_of_an_uncabled_device_without_inventory_are_the_defaults_only(self):
        found = service.management_interfaces({}, topo())
        self.assertEqual(found["R5"], ("Management0", "Management1", "eth0"))
        self.assertNotIn("eth9", found["R5"])

    def test_production_runtime_wires_the_tracked_definition_only(self):
        found = service.production_runtime()
        self.assertIs(found.definition, migration.PRODUCTION)
        self.assertTrue(found.gated)
        self.assertTrue({"R1", "R2", "S1", "S2"} <= set(found.management_interfaces))
        self.assertTrue(all("Management0" in ports for ports in found.management_interfaces.values()))


class StoredServiceTests(TestCase):
    def active_r1(self):
        record = mm.LifecycleTests().active(device="R1", v6_north=ACTIVE, v6_south=ACTIVE)
        record.plan = {**record.plan, "baseline": {"intersects": ["R2", "S1"]}}
        return store.save(record), record

    def test_current_is_the_unresolved_row_of_the_device(self):
        row, _record = self.active_r1()
        self.assertEqual(service.current("R1").pk, row.pk)

    def test_current_none_for_a_device_without_or_with_only_resolved_maintenance(self):
        record = lifecycle.request("S2", "operator", "r", mm.HOUR, at=mm.T0)
        record.state = lifecycle.CANCELLED
        store.save(record)
        self.assertEqual((service.current("S2"), service.current("R4")), (None, None))

    def test_change_clash_names_the_device_in_maintenance_and_the_devices_carrying_its_traffic(self):
        self.active_r1()
        self.assertEqual(service.conflict("R1"), "R1 is ACTIVE in maintenance; no Change may run on it until it is restored")
        self.assertEqual(service.conflict("S1"), "S1 carries the traffic or the drain state of R1, which is ACTIVE in maintenance")
        self.assertEqual(service.conflict("R3"), "")

    def test_status_shows_state_steps_cells_and_history(self):
        row, record = self.active_r1()
        found = service.status(row.record_id, now=mm.T0 + mm.HOUR)
        self.assertEqual((found["id"], found["device"], found["state"], found["under_maintenance"]), (row.record_id, "R1", lifecycle.ACTIVE, True))
        self.assertEqual(found["steps"], [f"{s.family} {s.direction}: {s.mechanism}" for s in record.steps])
        self.assertEqual(len(found["cells"]), 4)
        self.assertEqual(found["history"][-1].split(" ", 1)[0], mm.T0.isoformat())
        with self.assertRaises(model.MaintenanceError):
            service.status("MNT-999999", now=mm.T0)
