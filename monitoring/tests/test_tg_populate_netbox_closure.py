"""Lab 7 closure -- ``netbox/scripts/populate_netbox.py``'s Populator steps, report and entry point.

Every step runs against an in-memory fake NetBox (``_FakeEndpoint`` from ``test_netbox_ipam``): records live only in
Python lists, so no live NetBox is read or written.  The stale-identity cleanups are covered by their own tests and
are stubbed here.  POSITIVE: an apply run creates exactly the manifest's objects, a rerun changes nothing, and the
report / exit code are exact.  NEGATIVE: a check run against an empty NetBox writes nothing and skips every child
whose parent is missing, an existing object with a different role is a CONFLICT exiting 2, and an unreadable manifest
or unreachable NetBox exits 1 before any reconciliation.
"""
from __future__ import annotations

import contextlib
import io
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import test_netbox_ipam as base  # sibling fixture modules (discover -s monitoring/tests)
import test_populate_netbox as pbase
from modules import netbox_ipam as nb

pn = pbase.populate_netbox


class InMemoryRecord(base._FakeRecord):
    """Like NetBox, a primary-IP foreign key written as an id reads back as a nested object with ``.id``."""

    def _apply(self, fields):
        super()._apply(fields)
        for key in ("primary_ip4", "primary_ip6"):
            if isinstance(getattr(self, key, None), int):
                setattr(self, key, SimpleNamespace(id=getattr(self, key)))


class InMemoryEndpoint(base._FakeEndpoint):
    def create(self, **kwargs):
        record = InMemoryRecord(self._next_id, kwargs)
        self._next_id += 1
        self.records.append(record)
        return record

    def get(self, record_id):
        return next(r for r in self.records if r.id == record_id)


class InMemoryNetBox:
    """``client.<app>.<endpoint>`` -> one InMemoryEndpoint per name; nothing leaves the process."""

    def __init__(self):
        self.endpoints = {}
        for app in ("dcim", "ipam", "extras"):
            setattr(self, app, _App(self.endpoints, app))

    def records(self, name):
        return self.endpoints[name].records if name in self.endpoints else []


class _App:
    def __init__(self, store, app):
        self._store, self._app = store, app

    def __getattr__(self, name):
        return self._store.setdefault(f"{self._app}.{name}", InMemoryEndpoint())


def expected_counts(manifest):
    devices = manifest["devices"]
    interfaces = [i for d in devices for i in d["interfaces"]]
    return {"tag": 5, "custom_field": 8, "site": 1, "manufacturer": len(manifest["manufacturers"]), "device_type": len(manifest["device_types"]),
            "device_role": len(manifest["device_roles"]), "ipam_role": len(manifest["ipam_roles"]), "vlan": len(manifest["vlans"]),
            "prefix": len(manifest["prefixes"]), "dhcp_range": len(manifest["dhcp_ranges"]), "device": len(devices), "interface": len(interfaces),
            "ip_address": sum(len(i["addresses"]) for i in interfaces) + len(manifest.get("virtual_ips", []))}


class PopulatorTests(unittest.TestCase):
    def setUp(self):
        for name in ("clear_stale_mac_identity_status", "clear_stale_dhcpv6_identity"):
            patcher = patch.object(pn.nb, name, return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.manifest = pn.load_manifest()

    STEPS = ("populate_tags", "populate_custom_fields", "populate_site", "populate_manufacturers", "populate_device_types",
             "populate_device_roles", "populate_ipam_roles", "populate_vlans", "populate_prefixes", "populate_dhcp_ranges",
             "populate_devices", "populate_virtual_ips")

    def run_populator(self, client, apply):
        """Each step called directly, in Populator.run()'s order (pinned by test_run_calls_the_steps_in_order)."""
        populator = pn.Populator(client, self.manifest, apply=apply)
        for step in self.STEPS:
            getattr(populator, step)()
        return populator

    def test_run_calls_the_steps_in_order(self):
        populator = pn.Populator(InMemoryNetBox(), self.manifest, apply=False)
        called = []
        for step in self.STEPS:
            setattr(populator, step, lambda name=step: called.append(name))
        populator.run()
        self.assertEqual(tuple(called), self.STEPS)

    def test_apply_run_creates_every_manifest_object_and_a_rerun_is_unchanged(self):
        client = InMemoryNetBox()
        first = self.run_populator(client, apply=True)
        kinds = Counter(kind for kind, _name, result in first.results if result.action == nb.CREATE and kind != "primary_ip")
        self.assertEqual(dict(kinds), expected_counts(self.manifest))
        self.assertEqual(len(client.records("dcim.devices")), len(self.manifest["devices"]))
        self.assertEqual(sorted(t.slug for t in client.records("dcim.devices")[0].tags)[:1], ["csci5840-iac"])
        second = self.run_populator(client, apply=True)
        self.assertEqual(set(pn.summarize(second.results)), {nb.UNCHANGED})
        self.assertEqual(len(client.records("ipam.ip_addresses")), expected_counts(self.manifest)["ip_address"])

    def test_check_run_against_an_empty_netbox_writes_nothing_and_skips_children(self):
        client = InMemoryNetBox()
        populator = pn.Populator(client, self.manifest, apply=False)
        populator.run()
        counts = pn.summarize(populator.results)
        self.assertEqual(set(counts), {nb.CHECK_CREATE, pn.SKIPPED})
        self.assertTrue({kind for kind, _n, r in populator.results if r.action == pn.SKIPPED} >= {"vlan", "device"})
        self.assertEqual(sum(len(e.records) for e in client.endpoints.values()), 0)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            pn.print_report(populator.results, verbose=False)
        self.assertIn(f"Note: {counts[pn.SKIPPED]} object(s) could not be previewed because a prerequisite does not exist in NetBox yet.", out.getvalue())
        self.assertIn("SKIPPED        vlan           VLAN", out.getvalue())

    def test_print_report_lists_changes_conflicts_and_the_summary(self):
        results = [("vlan", "VLAN10", nb.ReconcileResult(nb.CREATE, changes={"vid": 10})),
                   ("prefix", "10.0.0.0/24", nb.ReconcileResult(nb.UNCHANGED)),
                   ("vlan", "VLAN20", nb.ReconcileResult(nb.CONFLICT, conflicts={"role": {"existing": "a", "desired": "b"}}))]
        for verbose, expected in ((True, [f"{nb.CREATE:<14} {'vlan':<14} VLAN10  ({{'vid': 10}})", f"{nb.UNCHANGED:<14} {'prefix':<14} 10.0.0.0/24"]),
                                  (False, [f"{nb.CREATE:<14} {'vlan':<14} VLAN10"])):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertIsNone(pn.print_report(results, verbose=verbose))
            lines = out.getvalue().splitlines()
            self.assertEqual(lines[:len(expected)], expected)
            self.assertIn(f"{nb.CONFLICT:<14} {'vlan':<14} VLAN20  CONFLICT: {{'role': {{'existing': 'a', 'desired': 'b'}}}}", lines)
            self.assertEqual(lines[-1], "Summary: " + ", ".join(f"{a}={c}" for a, c in sorted(pn.summarize(results).items())))

    def test_an_existing_vlan_with_another_role_is_a_conflict(self):
        client = InMemoryNetBox()
        self.run_populator(client, apply=True)
        first_vlan = next(v for v in self.manifest["vlans"] if v.get("role"))
        record = next(r for r in client.records("ipam.vlans") if r.vid == first_vlan["vid"])
        record.role = {"slug": "intruder"}
        populator = self.run_populator(client, apply=True)
        conflicts = [(kind, name, r.conflicts) for kind, name, r in populator.results if r.action == nb.CONFLICT]
        self.assertEqual(conflicts, [("vlan", f"VLAN{first_vlan['vid']}", {"role": {"existing": "intruder", "desired": first_vlan["role"]}})])


class MainTests(unittest.TestCase):
    def main(self, argv, client=None, status_error=None, manifest_error=None):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(pn.nb, "build_client", return_value=client or InMemoryNetBox()), \
                patch.object(pn.nb, "load_config", return_value=MagicMock()), \
                patch.object(pn.nb, "check_status", side_effect=status_error), \
                patch.object(pn.nb, "clear_stale_mac_identity_status", return_value=None), \
                patch.object(pn.nb, "clear_stale_dhcpv6_identity", return_value=None), \
                patch.object(pn, "load_manifest", side_effect=manifest_error, wraps=None if manifest_error else pn.load_manifest), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pn.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_main_apply_returns_zero_with_a_create_summary(self):
        code, out, err = self.main(["--apply"])
        self.assertEqual((code, err), (0, ""))
        self.assertRegex(out.splitlines()[-1], r"^Summary: CREATE=\d+, UNCHANGED=\d+$")

    def test_main_refuses_an_unreadable_manifest_an_unreachable_netbox_or_conflicts(self):
        code, _out, err = self.main(["--check"], manifest_error=ValueError("bad manifest"))
        self.assertEqual((code, err), (1, "ERROR: bad manifest\n"))
        client = InMemoryNetBox()
        code, _out, err = self.main(["--check"], client=client, status_error=nb.NetboxConnectionError("unreachable"))
        self.assertEqual((code, err, client.endpoints), (1, "ERROR: NetBox is not reachable/usable: unreachable\n", {}))
        self.main(["--apply"], client=client)
        vlan = next(r for r in client.records("ipam.vlans") if getattr(r, "role", None))
        vlan.role = {"slug": "intruder"}
        code, _out, err = self.main(["--check"], client=client)
        self.assertEqual((code, err), (2, "\n1 CONFLICT(s) found -- nothing was overwritten for these objects.\n"))


if __name__ == "__main__":
    unittest.main()
