import unittest
from pathlib import Path

from modules import ipam_evidence


class IpamManifestEvidenceTests(unittest.TestCase):
    def test_expected_coverage_and_duplicate_contract(self):
        evidence = ipam_evidence.manifest_summary(ipam_evidence.load_manifest())
        self.assertEqual(evidence["prefix_count"], 34)
        self.assertEqual((evidence["prefix_ipv4_count"], evidence["prefix_ipv6_count"]), (18, 16))
        self.assertEqual((evidence["assigned_address_count"], evidence["virtual_address_count"], evidence["total_address_count"]), (80, 5, 85))
        self.assertEqual((evidence["assigned_ipv4_count"], evidence["assigned_ipv6_count"]), (39, 41))
        self.assertEqual(evidence["duplicate_assignment_count"], 0)
        self.assertEqual(evidence["dhcp_range_count"], 10)

    def test_validator_requires_full_static_management_coverage(self):
        evidence = {
            "live_prefix_count": 33, "prefix_count": 33,
            "live_address_count": 83, "total_address_count": 83,
            "live_dhcp_range_count": 10, "dhcp_range_count": 10,
            "management_dual_stack_count": 9, "management_static_count": 9, "management_device_count": 9,
            "missing_address_count": 0, "unexpected_address_count": 0,
            "duplicate_assignment_count": 0, "duplicate_live_address_count": 0,
            "vlan200_policy": "STATIC", "reservation_targets": 0,
        }
        self.assertEqual(ipam_evidence.validate(evidence), [])
        evidence["management_static_count"] = 8
        self.assertTrue(any("VLAN200" in row for row in ipam_evidence.validate(evidence)))


class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _ReadOnlyEndpoint:
    """Only the read verbs exist; any create/update/delete would raise AttributeError."""

    def __init__(self, rows=(), lookup=None, filt=None):
        self._rows, self._lookup, self._filter = list(rows), lookup or {}, filt or (lambda **kw: [])

    def all(self):
        return list(self._rows)

    def get(self, **kw):
        return self._lookup.get(tuple(sorted(kw.items())))

    def filter(self, **kw):
        return self._filter(**kw)


class _FakeNetBox:
    def __init__(self, manifest, *, non_static_device=None):
        summary = ipam_evidence.manifest_summary(manifest)
        addresses = [_Row(address=a) for a in summary["expected_addresses"]]
        devices, interfaces = {}, {}
        per_interface = {}
        for index, name in enumerate(ipam_evidence.MANAGED, start=1):
            devices[(("name", name),)] = _Row(id=index)
            mode = "dhcp" if name == non_static_device else "static"
            interfaces[(("device_id", index), ("name", "Vlan200"))] = _Row(
                id=100 + index, custom_fields={"ipv4_assignment_mode": mode, "ipv6_assignment_mode": "static"},
            )
            per_interface[100 + index] = [_Row(address=f"192.168.200.{index}/24"), _Row(address=f"2001:db8:200::{index}/64")]
        self.ipam = _Row(
            prefixes=_ReadOnlyEndpoint(rows=range(summary["prefix_count"])),
            ip_addresses=_ReadOnlyEndpoint(rows=addresses, filt=lambda interface_id: per_interface[interface_id]),
            ip_ranges=_ReadOnlyEndpoint(rows=range(summary["dhcp_range_count"])),
        )
        self.dcim = _Row(devices=_ReadOnlyEndpoint(lookup=devices), interfaces=_ReadOnlyEndpoint(lookup=interfaces))


class IpamLiveEvidenceTests(unittest.TestCase):
    def test_netbox_is_read_only_and_vlan200_policy_is_measured(self):
        manifest = ipam_evidence.load_manifest()
        evidence = ipam_evidence.collect_live_evidence(client=_FakeNetBox(manifest), manifest=manifest)
        self.assertEqual((evidence["vlan200_policy"], evidence["reservation_targets"]), ("STATIC", 0))
        self.assertEqual(ipam_evidence.validate(evidence), [])

        drifted = ipam_evidence.collect_live_evidence(client=_FakeNetBox(manifest, non_static_device="S3"), manifest=manifest)
        self.assertEqual((drifted["vlan200_policy"], drifted["reservation_targets"]), ("NOT_UNIFORMLY_STATIC", 1))
        self.assertTrue(ipam_evidence.validate(drifted))

    def test_no_parallel_ipam_store_or_netbox_writes(self):
        source = Path(ipam_evidence.__file__).read_text()
        for forbidden in (".create(", ".update(", ".delete(", ".save(", "to_csv", "csv.writer", "sqlite3"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
