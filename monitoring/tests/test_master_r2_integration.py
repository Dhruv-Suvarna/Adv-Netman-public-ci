"""Offline unit tests for master.py's R2 DHCP-context wiring (Phase 3D).

Imports master.py directly (it already imports cleanly without any live
device/NetBox/network access at import time -- only individual functions
touch the network, and only when called). Every test here mocks
modules.ipam_context's functions, so nothing connects to NetBox, R2, or
any other device; `master.push_eos()` itself (the part that actually opens
an SSH/netmiko session) is never called.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import master
from modules import ipam_context as ic
from modules import netbox_ipam as nb


def _inv():
    return master.load_inventory()


class BuildEosConfigR2Tests(unittest.TestCase):
    """master.py passes a NORMALIZED context (whatever
    build_and_validate_r2_dhcp_context() returns) rather than any
    hardcoded pool range -- these tests prove that by supplying a
    deliberately distinctive fake context and confirming it alone drives
    the render, with zero DHCP-specific logic duplicated in master.py."""

    def test_r2_build_attaches_whatever_context_is_returned(self):
        fake_context = {
            "ipv4_subnets": [ic.DhcpPool(vlan=10, family=4, server="secondary", prefix="192.168.10.0/24", start="192.168.10.240", end="192.168.10.250", gateway="192.168.10.1", relay_targets=(), description=None)],
            "ipv6_subnets": [],
        }
        with patch.object(master, "build_and_validate_r2_dhcp_context", return_value=fake_context), \
             patch.object(master, "validate_r2_candidate_render"):
            cfg = master._build_eos_config("R2", _inv())
        self.assertIn("range 192.168.10.240 192.168.10.250", cfg)
        self.assertIn("dhcp server ipv4", cfg)

    def test_r2_build_calls_the_post_render_validator(self):
        fake_context = {"ipv4_subnets": [], "ipv6_subnets": []}
        with patch.object(master, "build_and_validate_r2_dhcp_context", return_value=fake_context), \
             patch.object(master, "validate_r2_candidate_render") as mock_validate:
            master._build_eos_config("R2", _inv())
        mock_validate.assert_called_once()
        (rendered_arg,) = mock_validate.call_args.args
        self.assertIn("dhcp server", rendered_arg)

    def test_netbox_failure_fails_closed_before_any_render(self):
        """Step 7: a NetBox outage must abort BEFORE _build_eos_config()
        returns anything -- never silently fall back to rendering R2
        without its DHCP section."""
        with patch.object(master, "build_and_validate_r2_dhcp_context", side_effect=nb.NetboxConnectionError("down")):
            with self.assertRaises(nb.NetboxConnectionError):
                master._build_eos_config("R2", _inv())

    def test_pool_safety_failure_fails_closed(self):
        with patch.object(master, "build_and_validate_r2_dhcp_context", side_effect=nb.NetboxModelError("overlap")):
            with self.assertRaises(nb.NetboxModelError):
                master._build_eos_config("R2", _inv())

    def test_post_render_validation_failure_propagates(self):
        """If the post-render check finds the DHCP section absent (or
        Vlan200's static address lost), that failure must propagate out
        of _build_eos_config() -- never be swallowed."""
        fake_context = {"ipv4_subnets": [], "ipv6_subnets": []}
        with patch.object(master, "build_and_validate_r2_dhcp_context", return_value=fake_context), \
             patch.object(master, "validate_r2_candidate_render", side_effect=nb.NetboxModelError("lost Vlan200 address")):
            with self.assertRaises(nb.NetboxModelError):
                master._build_eos_config("R2", _inv())

    def test_other_devices_never_touch_netbox(self):
        """Only R2 triggers the DHCP context build -- every other managed
        device's render must be completely unaffected by NetBox's
        availability."""
        with patch.object(master, "build_and_validate_r2_dhcp_context", side_effect=AssertionError("must not be called for R1")):
            cfg = master._build_eos_config("R1", _inv())
        self.assertNotIn("dhcp server", cfg)


class SetupNmasDhcpTests(unittest.TestCase):
    """Phase 3G: setup_nmas() passes a NetBox-derived normalized context
    to the DHCP templates, and fails closed BEFORE any file write or
    service action if NetBox/pool-safety is unavailable. `master.run()`
    is mocked throughout -- no real subprocess/apt-get/systemctl call is
    ever made by these tests."""

    _FAKE_CONTEXT = {
        "management": {"v4_network": "192.168.200.0", "v4_netmask": "255.255.255.0", "v6_prefix": "2001:db8:200::/64"},
        "ipv4_subnets": [{"vlan": 10, "network": "192.168.10.0", "netmask": "255.255.255.0", "start": "192.168.10.240", "end": "192.168.10.250", "gateway": "192.168.10.1"}],
        "ipv6_subnets": [],
    }

    def test_dhcp_write_reflects_whatever_context_is_returned(self):
        written = {}

        def fake_write_text(self_path, content):
            written[str(self_path)] = content

        with patch.object(master, "run"), \
             patch.object(master, "build_and_validate_nmas_dhcp_context", return_value=self._FAKE_CONTEXT), \
             patch("pathlib.Path.write_text", fake_write_text):
            master.setup_nmas(_inv())
        v4_content = written.get("/tmp/clab-dhcpd.conf", "")
        self.assertIn("range 192.168.10.240 192.168.10.250", v4_content)

    def test_netbox_failure_fails_closed_before_apt_or_file_write(self):
        run_calls = []
        with patch.object(master, "run", side_effect=lambda *a, **k: run_calls.append(a)), \
             patch.object(master, "build_and_validate_nmas_dhcp_context", side_effect=nb.NetboxConnectionError("down")), \
             patch("pathlib.Path.write_text") as mock_write:
            with self.assertRaises(nb.NetboxConnectionError):
                master.setup_nmas(_inv())
        # ip link/addr/route calls (management plumbing) are allowed before
        # the DHCP gate; apt-get/install/file-write must NEVER be reached.
        self.assertFalse(any("apt-get" in " ".join(c[0]) for c in run_calls if c))
        mock_write.assert_not_called()

    def test_pool_safety_failure_fails_closed(self):
        with patch.object(master, "run"), \
             patch.object(master, "build_and_validate_nmas_dhcp_context", side_effect=nb.NetboxModelError("overlap")), \
             patch("pathlib.Path.write_text") as mock_write:
            with self.assertRaises(nb.NetboxModelError):
                master.setup_nmas(_inv())
        mock_write.assert_not_called()

    def test_dhcp_toggle_off_never_calls_context_builder(self):
        inv = _inv()
        inv["toggles"]["configure_nmas_dhcp"] = False
        with patch.object(master, "run"), \
             patch.object(master, "build_and_validate_nmas_dhcp_context", side_effect=AssertionError("must not be called")):
            master.setup_nmas(inv)  # must not raise


if __name__ == "__main__":
    unittest.main()
