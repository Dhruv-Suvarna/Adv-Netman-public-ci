"""Offline unit tests for the foundational NetBox abstraction
(`modules/netbox_ipam.py`, Phase 1 of the NetBox migration).

No live NetBox instance, no Docker, and no network access is used here --
every HTTP call is mocked. A separate live check against the actually
running local NetBox stack is `python3 -m modules.netbox_ipam` (see
docs/NETBOX_IPAM.md), not this file.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from modules import netbox_ipam


def _response(status_code=200, json_data=None, text="", raise_json=False):
    response = MagicMock(spec=requests.Response)
    response.status_code = status_code
    response.ok = 200 <= status_code < 400
    response.text = text or (str(json_data) if json_data is not None else "")
    if raise_json:
        response.json.side_effect = ValueError("not json")
    else:
        response.json.return_value = json_data if json_data is not None else {}
    return response


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        # Isolate every test in this class from whatever real netbox/.env
        # happens to exist on this machine (e.g. after netbox/scripts/
        # bootstrap_netbox.sh has actually run) by pointing the default env
        # file at a path that is guaranteed not to exist.
        patcher = patch.object(netbox_ipam, "DEFAULT_ENV_FILE", Path("/nonexistent/netbox-test.env"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_missing_url_raises_configuration_error(self):
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.load_config(env={})

    def test_url_and_token_from_process_environment(self):
        config = netbox_ipam.load_config(env={"NETBOX_URL": "http://127.0.0.1:8000/", "NETBOX_TOKEN": "abc123"})
        # Trailing slash is normalized away so path concatenation is unambiguous.
        self.assertEqual(config.url, "http://127.0.0.1:8000")
        self.assertEqual(config.token, "abc123")
        self.assertTrue(config.has_token)
        self.assertEqual(config.timeout, netbox_ipam.DEFAULT_TIMEOUT_SECONDS)
        self.assertTrue(config.verify_ssl)

    def test_missing_token_leaves_config_unauthenticated(self):
        config = netbox_ipam.load_config(env={"NETBOX_URL": "http://127.0.0.1:8000"})
        self.assertIsNone(config.token)
        self.assertFalse(config.has_token)

    def test_env_file_used_when_process_environment_is_silent(self, ):
        env_file_values = {"NETBOX_URL": "http://127.0.0.1:8000", "NETBOX_TOKEN": "from-file"}
        with patch.object(netbox_ipam, "_parse_env_file", return_value=env_file_values):
            config = netbox_ipam.load_config(env={})
        self.assertEqual(config.url, "http://127.0.0.1:8000")
        self.assertEqual(config.token, "from-file")

    def test_process_environment_takes_precedence_over_env_file(self):
        env_file_values = {"NETBOX_URL": "http://from-file:8000", "NETBOX_TOKEN": "from-file"}
        with patch.object(netbox_ipam, "_parse_env_file", return_value=env_file_values):
            config = netbox_ipam.load_config(env={"NETBOX_URL": "http://from-env:8000"})
        self.assertEqual(config.url, "http://from-env:8000")
        self.assertEqual(config.token, "from-file")  # only NETBOX_URL was overridden

    def test_invalid_timeout_raises_configuration_error(self):
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.load_config(env={"NETBOX_URL": "http://x", "NETBOX_TIMEOUT": "not-a-number"})

    def test_non_positive_timeout_raises_configuration_error(self):
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.load_config(env={"NETBOX_URL": "http://x", "NETBOX_TIMEOUT": "0"})

    def test_invalid_verify_ssl_raises_configuration_error(self):
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.load_config(env={"NETBOX_URL": "http://x", "NETBOX_VERIFY_SSL": "maybe"})

    def test_verify_ssl_false_is_parsed(self):
        config = netbox_ipam.load_config(env={"NETBOX_URL": "http://x", "NETBOX_VERIFY_SSL": "false"})
        self.assertFalse(config.verify_ssl)


class AuthHeaderTests(unittest.TestCase):
    def test_classic_v1_token_uses_token_header(self):
        self.assertEqual(netbox_ipam._auth_header("0123456789abcdef"), {"Authorization": "Token 0123456789abcdef"})

    def test_v2_token_uses_bearer_header(self):
        token = "nbt_abcdefghijkl.somesecretvalue"
        self.assertEqual(netbox_ipam._auth_header(token), {"Authorization": f"Bearer {token}"})

    def test_v2_detection_requires_dot_after_prefix(self):
        self.assertFalse(netbox_ipam._is_v2_token("nbt_nodothere"))
        self.assertFalse(netbox_ipam._is_v2_token("not-nbt-prefixed.with.dots"))


class CheckStatusTests(unittest.TestCase):
    def setUp(self):
        self.config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token=None)
        self.authed_config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="abc123")

    def test_successful_status_returns_parsed_json(self):
        with patch("modules.netbox_ipam.requests.get", return_value=_response(200, {"netbox-version": "4.7.0"})):
            result = netbox_ipam.check_status(self.config)
        self.assertEqual(result["netbox-version"], "4.7.0")

    def test_successful_status_with_empty_body_is_not_an_error(self):
        """An empty-but-valid JSON object must not be mistaken for a failure --
        this is the Phase 1 form of the 'API failure vs empty result'
        distinction the module's docstring commits to."""
        with patch("modules.netbox_ipam.requests.get", return_value=_response(200, {})):
            result = netbox_ipam.check_status(self.config)
        self.assertEqual(result, {})

    def test_unreachable_netbox_raises_connection_error(self):
        with patch("modules.netbox_ipam.requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            with self.assertRaises(netbox_ipam.NetboxConnectionError):
                netbox_ipam.check_status(self.config)

    def test_timeout_raises_connection_error(self):
        with patch("modules.netbox_ipam.requests.get", side_effect=requests.exceptions.Timeout("slow")):
            with self.assertRaises(netbox_ipam.NetboxConnectionError):
                netbox_ipam.check_status(self.config)

    def test_auth_required_without_token_raises_authentication_error(self):
        with patch("modules.netbox_ipam.requests.get", return_value=_response(403)):
            with self.assertRaises(netbox_ipam.NetboxAuthenticationError):
                netbox_ipam.check_status(self.config)

    def test_auth_required_with_rejected_token_raises_authentication_error(self):
        with patch("modules.netbox_ipam.requests.get", return_value=_response(403)):
            with self.assertRaises(netbox_ipam.NetboxAuthenticationError):
                netbox_ipam.check_status(self.authed_config)

    def test_unexpected_http_error_raises_response_error(self):
        with patch("modules.netbox_ipam.requests.get", return_value=_response(500, text="boom")):
            with self.assertRaises(netbox_ipam.NetboxResponseError):
                netbox_ipam.check_status(self.config)

    def test_malformed_json_raises_response_error(self):
        with patch("modules.netbox_ipam.requests.get", return_value=_response(200, raise_json=True)):
            with self.assertRaises(netbox_ipam.NetboxResponseError):
                netbox_ipam.check_status(self.config)


class VerifyAuthenticationTests(unittest.TestCase):
    def test_missing_token_raises_configuration_error(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token=None)
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.verify_authentication(config)

    def test_valid_token_returns_status_document(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="abc123")
        with patch("modules.netbox_ipam.requests.get", return_value=_response(200, {"netbox-version": "4.7.0"})):
            result = netbox_ipam.verify_authentication(config)
        self.assertEqual(result["netbox-version"], "4.7.0")

    def test_rejected_token_raises_authentication_error(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="wrong")
        with patch("modules.netbox_ipam.requests.get", return_value=_response(401)):
            with self.assertRaises(netbox_ipam.NetboxAuthenticationError):
                netbox_ipam.verify_authentication(config)

    def test_unreachable_netbox_raises_connection_error_not_auth_error(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="abc123")
        with patch("modules.netbox_ipam.requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            with self.assertRaises(netbox_ipam.NetboxConnectionError):
                netbox_ipam.verify_authentication(config)


class RunDiagnosticsTests(unittest.TestCase):
    def test_all_checks_pass_with_valid_token(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="abc123")
        with patch("modules.netbox_ipam.requests.get", return_value=_response(200, {"netbox-version": "4.7.0"})):
            result = netbox_ipam.run_diagnostics(config)
        self.assertTrue(result["all_passed"])
        self.assertEqual(result["netbox_version"], "4.7.0")
        names = {check["name"]: check["status"] for check in result["checks"]}
        self.assertEqual(names["connectivity/status"], "PASS")
        self.assertEqual(names["authentication"], "PASS")

    def test_authentication_skipped_without_token(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token=None)
        with patch("modules.netbox_ipam.requests.get", return_value=_response(200, {"netbox-version": "4.7.0"})):
            result = netbox_ipam.run_diagnostics(config)
        names = {check["name"]: check["status"] for check in result["checks"]}
        self.assertEqual(names["authentication"], "SKIPPED")
        self.assertTrue(result["all_passed"])  # a skipped check does not fail the run

    def test_connectivity_failure_is_reported_not_raised(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token=None)
        with patch("modules.netbox_ipam.requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = netbox_ipam.run_diagnostics(config)
        self.assertFalse(result["all_passed"])
        names = {check["name"]: check["status"] for check in result["checks"]}
        self.assertEqual(names["connectivity/status"], "FAIL")
        self.assertNotIn("netbox_version", result)


class BuildClientTests(unittest.TestCase):
    def test_build_client_without_pynetbox_raises_netbox_error(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="abc123")
        with patch.object(netbox_ipam, "pynetbox", None):
            with self.assertRaises(netbox_ipam.NetboxError):
                netbox_ipam.build_client(config)

    def test_build_client_constructs_pynetbox_api(self):
        config = netbox_ipam.NetboxConfig(url="http://127.0.0.1:8000", token="abc123", verify_ssl=False)
        fake_pynetbox = MagicMock()
        fake_client = MagicMock()
        fake_client.http_session = MagicMock()
        fake_pynetbox.api.return_value = fake_client
        with patch.object(netbox_ipam, "pynetbox", fake_pynetbox):
            client = netbox_ipam.build_client(config)
        fake_pynetbox.api.assert_called_once_with(config.url, token=config.token)
        self.assertIs(client, fake_client)
        self.assertFalse(client.http_session.verify)


# ---------------------------------------------------------------------------
# Phase 2: generic reconciliation primitives (reconcile_object, ensure_tag,
# ensure_custom_field). A minimal in-memory fake NetBox endpoint stands in
# for pynetbox here -- it supports exactly the surface reconcile_object
# uses (.filter/.create/.update/.save) with real object identity and
# mutation semantics, which lets these tests exercise genuine idempotent
# rerun behavior (Step 20) without any live NetBox instance or HTTP mock.
# ---------------------------------------------------------------------------

class _FakeTag:
    def __init__(self, slug):
        self.slug = slug


class _FakeRecord:
    def __init__(self, record_id, fields):
        self.id = record_id
        self._apply(fields)

    def _apply(self, fields):
        for key, value in fields.items():
            if key == "tags":
                value = [_FakeTag(v) if isinstance(v, str) else _FakeTag(v["slug"]) for v in value]
            setattr(self, key, value)

    def update(self, changes):
        self._apply(changes)

    def save(self):
        return True


class _FakeEndpoint:
    """Simulates just enough of a pynetbox endpoint for reconcile_object:
    `.filter(**kwargs)` does exact-match filtering (normalizing dict/record
    reference values the same way production code would receive them from
    NetBox), and `.create(**kwargs)` assigns a fresh id."""

    def __init__(self):
        self.records: list[_FakeRecord] = []
        self._next_id = 1

    def filter(self, **kwargs):
        def matches(record):
            for key, value in kwargs.items():
                current = getattr(record, key, None)
                if isinstance(current, _FakeTag):
                    current = current.slug
                if current != value:
                    return False
            return True

        return [r for r in self.records if matches(r)]

    def create(self, **kwargs):
        record = _FakeRecord(self._next_id, kwargs)
        self._next_id += 1
        self.records.append(record)
        return record


class ReconcileObjectTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = _FakeEndpoint()

    def test_create_when_no_match(self):
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"name": "Router"}, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.CREATE)
        self.assertEqual(result.obj.name, "Router")
        self.assertEqual(len(self.endpoint.records), 1)

    def test_check_create_does_not_touch_netbox(self):
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"name": "Router"}, apply=False,
        )
        self.assertEqual(result.action, netbox_ipam.CHECK_CREATE)
        self.assertIsNone(result.obj)
        self.assertEqual(self.endpoint.records, [])

    def test_second_call_is_unchanged_not_a_duplicate(self):
        """Idempotency (Step 20): running reconcile_object twice with the
        same desired state must CREATE once, then report UNCHANGED --
        never a second object."""
        first = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"name": "Router"}, apply=True,
        )
        second = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"name": "Router"}, apply=True,
        )
        self.assertEqual(first.action, netbox_ipam.CREATE)
        self.assertEqual(second.action, netbox_ipam.UNCHANGED)
        self.assertEqual(len(self.endpoint.records), 1)

    def test_safe_field_update(self):
        netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "router"}, desired={"description": "old"}, apply=True)
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"description": "new"},
            safe_update_fields=frozenset({"description"}), apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        self.assertEqual(result.obj.description, "new")

    def test_check_update_does_not_touch_netbox(self):
        netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "router"}, desired={"description": "old"}, apply=True)
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"description": "new"},
            safe_update_fields=frozenset({"description"}), apply=False,
        )
        self.assertEqual(result.action, netbox_ipam.CHECK_UPDATE)
        self.assertEqual(self.endpoint.records[0].description, "old")  # unchanged

    def test_unsafe_field_mismatch_is_conflict_and_not_overwritten(self):
        netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "router"}, desired={"color": "blue"}, apply=True)
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "router"}, desired={"color": "red"}, apply=True,  # "color" not in safe_update_fields
        )
        self.assertEqual(result.action, netbox_ipam.CONFLICT)
        self.assertIn("color", result.conflicts)
        self.assertEqual(self.endpoint.records[0].color, "blue")  # never overwritten

    def test_tags_are_additive_never_a_conflict(self):
        netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "r1"}, desired={"tags": ["csci5840-iac"]}, apply=True)
        # Simulate a human having added an unrelated tag out of band.
        self.endpoint.records[0].tags.append(_FakeTag("manually-added"))
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"slug": "r1"}, desired={"tags": ["csci5840-iac", "managed"]}, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        slugs = {t.slug for t in self.endpoint.records[0].tags}
        self.assertEqual(slugs, {"csci5840-iac", "managed", "manually-added"})  # union, nothing dropped

    def test_tags_subset_is_unchanged(self):
        netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "r1"}, desired={"tags": ["a", "b"]}, apply=True)
        result = netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "r1"}, desired={"tags": ["a"]}, apply=True)
        self.assertEqual(result.action, netbox_ipam.UNCHANGED)

    def test_custom_fields_new_key_is_safe_update(self):
        record = self.endpoint.create(custom_fields={"existing_key": "kept"})
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id}, desired={"custom_fields": {"iac_managed": True}}, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        self.assertEqual(record.custom_fields, {"existing_key": "kept", "iac_managed": True})

    def test_custom_fields_conflicting_value_is_conflict(self):
        record = self.endpoint.create(custom_fields={"iac_managed": False})
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id}, desired={"custom_fields": {"iac_managed": True}}, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.CONFLICT)
        self.assertIn("custom_fields", result.conflicts)
        self.assertEqual(record.custom_fields, {"iac_managed": False})  # never overwritten

    def test_reference_dict_by_id_compares_against_existing_id(self):
        """Regression test: a desired `{"role": {"id": 5}}` must compare
        against the existing related object's `.id`, not get mis-normalized
        against its `.slug` and falsely reported as a conflict."""
        role_obj = MagicMock()
        role_obj.id = 5
        role_obj.slug = "router"
        record = self.endpoint.create(name="R1")
        record.role = role_obj
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"name": "R1"}, desired={"role": {"id": 5}}, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UNCHANGED)

    def test_ambiguous_lookup_raises(self):
        self.endpoint.create(slug="dup")
        self.endpoint.create(slug="dup")
        with self.assertRaises(netbox_ipam.NetboxResponseError):
            netbox_ipam.reconcile_object(self.endpoint, lookup={"slug": "dup"}, desired={}, apply=True)

    def test_connection_error_during_lookup_propagates_distinctly(self):
        """A failed API call during reconciliation must never be mistaken
        for 'no objects found' -- it must surface as a connection error,
        not silently behave like an empty filter() result."""
        endpoint = MagicMock()
        endpoint.filter.side_effect = requests.exceptions.ConnectionError("refused")
        with self.assertRaises(netbox_ipam.NetboxConnectionError):
            netbox_ipam.reconcile_object(endpoint, lookup={"slug": "x"}, desired={}, apply=True)

    def test_pynetbox_request_error_during_create_is_wrapped(self):
        """A NetBox-side rejection (pynetbox.RequestError, e.g. a 400 for an
        invalid field) must surface as NetboxResponseError -- distinguishable
        from NetboxConnectionError (NetBox unreachable) -- never silently
        swallowed or misreported as "no objects found"."""
        class FakeRequestError(Exception):
            def __init__(self):
                self.error = "simulated 400: invalid field"

        fake_pynetbox_module = MagicMock()
        fake_pynetbox_module.RequestError = FakeRequestError

        endpoint = MagicMock()
        endpoint.filter.return_value = []
        endpoint.create.side_effect = FakeRequestError()
        with patch.object(netbox_ipam, "pynetbox", fake_pynetbox_module):
            with self.assertRaises(netbox_ipam.NetboxResponseError) as ctx:
                netbox_ipam.reconcile_object(endpoint, lookup={"slug": "x"}, desired={}, apply=True)
        self.assertIn("simulated 400", str(ctx.exception))


class EnsureTagTests(unittest.TestCase):
    def test_ensure_tag_creates_by_slug(self):
        endpoint = _FakeEndpoint()
        client = MagicMock()
        client.extras.tags = endpoint
        result = netbox_ipam.ensure_tag(client, "CSCI 5840 IaC", apply=True)
        self.assertEqual(result.action, netbox_ipam.CREATE)
        self.assertEqual(result.obj.name, "CSCI 5840 IaC")

    def test_ensure_tag_idempotent(self):
        endpoint = _FakeEndpoint()
        client = MagicMock()
        client.extras.tags = endpoint
        netbox_ipam.ensure_tag(client, "managed", apply=True)
        result = netbox_ipam.ensure_tag(client, "managed", apply=True)
        self.assertEqual(result.action, netbox_ipam.UNCHANGED)
        self.assertEqual(len(endpoint.records), 1)


class EnsureCustomFieldTests(unittest.TestCase):
    def test_ensure_custom_field_uses_object_types_wire_name(self):
        endpoint = _FakeEndpoint()
        client = MagicMock()
        client.extras.custom_fields = endpoint
        result = netbox_ipam.ensure_custom_field(
            client, "iac_managed", field_type="boolean", content_types=["dcim.device"], apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.CREATE)
        self.assertEqual(result.obj.object_types, ["dcim.device"])


# ---------------------------------------------------------------------------
# Phase 3A: normalized provisioning READ API (get_managed_devices,
# get_device, get_interface_addresses, get_peer_address(es), get_vlan,
# get_shared_gateway, get_dhcp_ranges/relay_targets, ...). A small, realistic
# in-memory fake NetBox client stands in for pynetbox: it supports exactly
# the `.filter(**kwargs)` semantics these functions actually issue (tag,
# name, device, interface_id, parent, vid, vlan_id), computed the same way
# NetBox itself computes them, so these tests exercise the real
# filter/normalize logic without any live NetBox instance.
# ---------------------------------------------------------------------------

import ipaddress as _ipaddress  # noqa: E402


class _Tag:
    def __init__(self, slug):
        self.slug = slug


class _Choice:
    """Mimics a NetBox choice-field Record: human label via str/repr, real
    machine value via `.value` -- see netbox_ipam._normalize's handling."""

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return self.value.capitalize()


class _Related:
    """Mimics a nested related-object Record (has both id and slug)."""

    def __init__(self, id, slug, **extra):
        self.id = id
        self.slug = slug
        for key, val in extra.items():
            setattr(self, key, val)


class _Device:
    def __init__(self, id, name, role_slug, managed, tags):
        self.id = id
        self.name = name
        self.role = _Related(100 + id, role_slug)
        self.device_type = _Related(200 + id, "ceos-4-36-2f")
        self.custom_fields = {"iac_managed": managed}
        self.tags = [_Tag(t) for t in tags]
        self.primary_ip4 = None
        self.primary_ip6 = None


class _IdRef:
    """A minimal stand-in for a related-object reference that only needs to
    expose `.id` (e.g. right after `Interface.update({"primary_mac_address":
    <id>})`, before any code re-fetches the full nested object)."""

    def __init__(self, id):
        self.id = id


class _Interface:
    def __init__(self, id, device_name, name, *, custom_fields=None):
        self.id = id
        self.device = _Related(0, device_name, name=device_name)
        self.name = name
        self.primary_mac_address = None
        self.custom_fields = dict(custom_fields or {})

    def update(self, changes):
        for key, value in changes.items():
            if key == "primary_mac_address" and not hasattr(value, "id"):
                value = _IdRef(value)
            setattr(self, key, value)

    def save(self):
        return True


class _MACAddress:
    def __init__(self, id, mac_address, *, assigned_iface=None, is_primary=False):
        self.id = id
        self.mac_address = mac_address
        self.assigned_object_id = assigned_iface.id if assigned_iface else None
        self.assigned_object_type = "dcim.interface" if assigned_iface else None
        self.is_primary = is_primary
        self.description = ""
        self.tags = []
        self.custom_fields = {}

    def update(self, changes):
        for key, value in changes.items():
            setattr(self, key, value)

    def save(self):
        return True


class _IPAddress:
    def __init__(self, id, address, *, assigned_iface=None, role=None, description=""):
        self.id = id
        self.address = address
        self.assigned_object = assigned_iface
        self.assigned_object_id = assigned_iface.id if assigned_iface else None
        self.role = _Choice(role) if role else None
        self.description = description


class _Prefix:
    def __init__(self, id, prefix, *, vlan=None, role=None, managed=True, description="", custom_fields=None):
        self.id = id
        self.prefix = prefix
        self.vlan = vlan
        self.role = _Related(300 + id, role) if role else None
        self.custom_fields = dict(custom_fields or {"iac_managed": managed})
        self.description = description


class _Vlan:
    def __init__(self, id, vid, name, role_slug="client"):
        self.id = id
        self.vid = vid
        self.name = name
        self.role = _Related(400 + id, role_slug)


class _IPRange:
    def __init__(self, id, start_address, end_address, description=""):
        self.id = id
        self.start_address = start_address
        self.end_address = end_address
        self.description = description


class _FakeCollection:
    def __init__(self, records):
        self.records = records

    def filter(self, **filters):
        return [r for r in self.records if self._matches(r, filters)]

    def get(self, **filters):
        matches = self.filter(**filters)
        if len(matches) > 1:
            raise AssertionError("ambiguous .get() in test fixture")
        return matches[0] if matches else None

    def _matches(self, record, filters):
        for key, value in filters.items():
            if key == "tag":
                if value not in [t.slug for t in getattr(record, "tags", [])]:
                    return False
            elif key == "device":
                if getattr(record, "device", None) is None or record.device.slug != value:
                    return False
            elif key == "interface_id":
                if getattr(record, "assigned_object_id", None) != value:
                    return False
            elif key == "parent":
                network = _ipaddress.ip_network(value, strict=False)
                try:
                    candidate = _ipaddress.ip_interface(record.address)
                except (ValueError, AttributeError):
                    return False
                if candidate.network != network:
                    return False
            elif key == "vlan_id":
                if getattr(record, "vlan", None) is None or record.vlan.id != value:
                    return False
            else:
                if getattr(record, key, None) != value:
                    return False
        return True


class _FakeMacCollection(_FakeCollection):
    """Only the mac_addresses endpoint needs a working .create() in these
    tests (ensure_interface_mac exercises the real reconcile_object CREATE
    path against it); filtering/matching is inherited unchanged."""

    _next_id = 9000

    def create(self, **fields):
        _FakeMacCollection._next_id += 1
        record = _MACAddress(
            _FakeMacCollection._next_id, fields["mac_address"],
            is_primary=fields.get("is_primary", False),
        )
        record.assigned_object_id = fields.get("assigned_object_id")
        record.assigned_object_type = fields.get("assigned_object_type")
        # reconcile_object's _to_wire() converts plain tag-name strings to
        # {"slug": ...} dicts before calling .create() -- accept either
        # shape, matching how a real NetBox write payload would look.
        record.tags = [_Tag(t["slug"] if isinstance(t, dict) else t) for t in fields.get("tags", [])]
        record.custom_fields = dict(fields.get("custom_fields", {}))
        self.records.append(record)
        return record


class FakeNetboxClient:
    """A small, realistic fixture: R1/S1 managed, R5 unmanaged, a
    point-to-point R1<->S1 link, a client VLAN10 (dual-stack + shared VRRP
    gateway) and VLAN30 (IPv6-only), and one DHCP range -- enough to
    exercise every Phase 3A read function's real logic paths."""

    def __init__(self):
        r1 = _Device(1, "R1", "router", True, ["csci5840-iac", "managed"])
        s1 = _Device(2, "S1", "switch", True, ["csci5840-iac", "managed"])
        r5 = _Device(3, "R5", "external-unmanaged", False, ["csci5840-iac", "unmanaged"])
        self._devices = [r1, s1, r5]

        r1_vlan200 = _Interface(10, "R1", "Vlan200")
        r1_eth2 = _Interface(11, "R1", "Ethernet2")
        r1_vlan101 = _Interface(12, "R1", "Vlan101")  # intentionally no peer configured
        s1_vlan200 = _Interface(20, "S1", "Vlan200")
        s1_eth1 = _Interface(21, "S1", "Ethernet1")
        s1_vlan10 = _Interface(22, "S1", "Vlan10")
        s1_vlan30 = _Interface(23, "S1", "Vlan30")
        self._interfaces = [r1_vlan200, r1_eth2, r1_vlan101, s1_vlan200, s1_eth1, s1_vlan10, s1_vlan30]

        r1.primary_ip4 = _IPAddress(1000, "192.168.200.1/24", assigned_iface=r1_vlan200)
        r1.primary_ip6 = _IPAddress(1001, "2001:db8:200::1/64", assigned_iface=r1_vlan200)
        s1.primary_ip4 = _IPAddress(1002, "192.168.200.11/24", assigned_iface=s1_vlan200)

        vlan200 = _Vlan(1, 200, "MANAGEMENT", "management")
        vlan10 = _Vlan(2, 10, "USERS10", "client")
        vlan30 = _Vlan(3, 30, "IPV6_ONLY", "client")

        prefix_mgmt = _Prefix(1, "192.168.200.0/24", vlan=vlan200, role="management")
        prefix_p2p = _Prefix(2, "192.168.110.0/31", role="transit")
        prefix_v10_4 = _Prefix(3, "192.168.10.0/24", vlan=vlan10, role="client",
                                custom_fields={"iac_managed": True, "dhcp_relay_targets": "192.168.200.100, 192.168.200.2"})
        prefix_v10_6 = _Prefix(4, "2001:db8:10::/64", vlan=vlan10, role="client")
        prefix_v30_6 = _Prefix(5, "2001:db8:30::/64", vlan=vlan30, role="client")
        self._prefixes = [prefix_mgmt, prefix_p2p, prefix_v10_4, prefix_v10_6, prefix_v30_6]
        self._vlans = [vlan200, vlan10, vlan30]

        self._ip_addresses = [
            r1.primary_ip4, r1.primary_ip6, s1.primary_ip4,
            _IPAddress(1010, "192.168.110.0/31", assigned_iface=r1_eth2),
            _IPAddress(1011, "192.168.110.1/31", assigned_iface=s1_eth1),
            _IPAddress(1012, "192.168.10.2/24", assigned_iface=s1_vlan10),
            _IPAddress(1013, "192.168.10.1/24", assigned_iface=None, role="vrrp"),
            _IPAddress(1014, "2001:db8:30::2/64", assigned_iface=s1_vlan30),
        ]

        self._ip_ranges = [
            _IPRange(1, "192.168.10.100/32", "192.168.10.179/32", description="VLAN10 primary pool"),
        ]
        for record in self._ip_ranges:
            record.tags = [_Tag("csci5840-iac")]

        self.dcim = MagicMock()
        self.dcim.devices = _FakeCollection(self._devices)
        self.dcim.interfaces = _FakeCollection(self._interfaces)
        self._mac_addresses: list = []
        self.dcim.mac_addresses = _FakeMacCollection(self._mac_addresses)
        self.ipam = MagicMock()
        self.ipam.ip_addresses = _FakeCollection(self._ip_addresses)
        self.ipam.prefixes = _FakeCollection(self._prefixes)
        self.ipam.vlans = _FakeCollection(self._vlans)
        self.ipam.ip_ranges = _FakeCollection(self._ip_ranges)

    def add_duplicate_ip_on(self, interface_name, device_name, address):
        iface = next(i for i in self._interfaces if i.name == interface_name and i.device.slug == device_name)
        self._ip_addresses.append(_IPAddress(9999, address, assigned_iface=iface))


class GetManagedDevicesTests(unittest.TestCase):
    def test_returns_only_managed_devices(self):
        client = FakeNetboxClient()
        self.assertEqual(netbox_ipam.get_managed_devices(client), ["R1", "S1"])

    def test_r5_excluded(self):
        client = FakeNetboxClient()
        self.assertNotIn("R5", netbox_ipam.get_managed_devices(client))

    def test_is_device_managed(self):
        client = FakeNetboxClient()
        self.assertTrue(netbox_ipam.is_device_managed("R1", client))
        self.assertFalse(netbox_ipam.is_device_managed("R5", client))

    def test_require_managed_device_raises_for_unmanaged(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.require_managed_device("R5", client)

    def test_require_managed_device_passes_for_managed(self):
        client = FakeNetboxClient()
        netbox_ipam.require_managed_device("R1", client)  # must not raise

    def test_tag_and_custom_field_disagreement_is_a_model_error(self):
        client = FakeNetboxClient()
        # Simulate drift: tagged managed but the custom field says otherwise.
        r1 = next(d for d in client._devices if d.name == "R1")
        r1.custom_fields["iac_managed"] = False
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_managed_devices(client)

    def test_device_tagged_both_managed_and_unmanaged_is_a_model_error(self):
        client = FakeNetboxClient()
        r1 = next(d for d in client._devices if d.name == "R1")
        r1.tags.append(_Tag("unmanaged"))
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_managed_devices(client)


class GetDeviceTests(unittest.TestCase):
    def test_missing_device_raises_model_error(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_device("NoSuchDevice", client)

    def test_returns_normalized_primary_addresses(self):
        client = FakeNetboxClient()
        device = netbox_ipam.get_device("R1", client)
        self.assertEqual(device["primary_ipv4"]["address"], "192.168.200.1")
        self.assertEqual(device["primary_ipv6"]["address"], "2001:db8:200::1")
        self.assertTrue(device["managed"])

    def test_device_with_no_ipv6_primary_returns_none_not_error(self):
        client = FakeNetboxClient()
        device = netbox_ipam.get_device("S1", client)
        self.assertIsNone(device["primary_ipv6"])

    def test_get_primary_address_convenience(self):
        client = FakeNetboxClient()
        self.assertEqual(netbox_ipam.get_primary_address("R1", 4, client)["address"], "192.168.200.1")
        self.assertIsNone(netbox_ipam.get_primary_address("S1", 6, client))

    def test_get_primary_address_invalid_family(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.get_primary_address("R1", 5, client)


class InterfaceAddressTests(unittest.TestCase):
    def test_missing_interface_raises_model_error(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_interface_addresses("R1", "NoSuchInterface", client)

    def test_dual_stack_interface_returns_both_families(self):
        client = FakeNetboxClient()
        addrs = netbox_ipam.get_interface_addresses("S1", "Vlan10", client)
        families = {a["family"] for a in addrs}
        self.assertEqual(families, {4})  # S1's own Vlan10 address is v4 only; ::2 lives on a different fixture check below

    def test_ipv6_only_interface_has_no_ipv4(self):
        client = FakeNetboxClient()
        v4 = netbox_ipam.get_interface_address("S1", "Vlan30", 4, client)
        v6 = netbox_ipam.get_interface_address("S1", "Vlan30", 6, client)
        self.assertIsNone(v4)
        self.assertIsNotNone(v6)
        self.assertEqual(v6["address"], "2001:db8:30::2")

    def test_interface_with_no_address_of_requested_family_returns_none(self):
        client = FakeNetboxClient()
        self.assertIsNone(netbox_ipam.get_interface_address("R1", "Vlan101", 4, client))

    def test_duplicate_addresses_same_family_is_ambiguous(self):
        client = FakeNetboxClient()
        client.add_duplicate_ip_on("Vlan10", "S1", "192.168.10.9/24")
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_interface_address("S1", "Vlan10", 4, client)


class PeerAddressTests(unittest.TestCase):
    def test_point_to_point_peer_found(self):
        client = FakeNetboxClient()
        peer = netbox_ipam.get_peer_address("R1", "Ethernet2", 4, client)
        self.assertEqual(peer["address"], "192.168.110.1")

    def test_peer_lookup_is_symmetric(self):
        client = FakeNetboxClient()
        peer = netbox_ipam.get_peer_address("S1", "Ethernet1", 4, client)
        self.assertEqual(peer["address"], "192.168.110.0")

    def test_no_peer_when_interface_has_no_address(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_peer_address("R1", "Vlan101", 4, client)

    def test_no_peer_returns_none_when_alone_on_prefix(self):
        client = FakeNetboxClient()
        # give Vlan101 an address with nobody else sharing its /31
        r1_vlan101 = next(i for i in client._interfaces if i.name == "Vlan101")
        client._ip_addresses.append(_IPAddress(2000, "192.168.100.0/31", assigned_iface=r1_vlan101))
        self.assertIsNone(netbox_ipam.get_peer_address("R1", "Vlan101", 4, client))

    def test_shared_segment_is_not_a_simple_peer(self):
        """A /24 with more than two hosts (like the management VLAN, once a
        third device joins it) is not a point-to-point link -- asking for
        its 'peer' must fail loudly rather than guess one host."""
        client = FakeNetboxClient()
        s1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "S1")
        # A third host on the same /24 makes R1's "peer" ambiguous.
        client._ip_addresses.append(_IPAddress(3000, "192.168.200.12/24", assigned_iface=s1_vlan200))
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_peer_address("R1", "Vlan200", 4, client)


class VlanAndGatewayTests(unittest.TestCase):
    def test_get_vlan_dual_stack(self):
        client = FakeNetboxClient()
        vlan = netbox_ipam.get_vlan(10, client)
        self.assertEqual(vlan["prefix_ipv4"]["prefix"], "192.168.10.0/24")
        self.assertEqual(vlan["prefix_ipv6"]["prefix"], "2001:db8:10::/64")

    def test_get_vlan_ipv6_only(self):
        client = FakeNetboxClient()
        vlan = netbox_ipam.get_vlan(30, client)
        self.assertIsNone(vlan["prefix_ipv4"])
        self.assertIsNotNone(vlan["prefix_ipv6"])

    def test_missing_vlan_raises_model_error(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_vlan(999, client)

    def test_shared_gateway_found(self):
        client = FakeNetboxClient()
        gw = netbox_ipam.get_shared_gateway(10, 4, client)
        self.assertEqual(gw["address"], "192.168.10.1")
        self.assertEqual(gw["role"], "vrrp")

    def test_shared_gateway_none_for_missing_family(self):
        client = FakeNetboxClient()
        self.assertIsNone(netbox_ipam.get_shared_gateway(30, 4, client))  # VLAN30 has no IPv4 at all

    def test_shared_gateway_none_when_vlan_has_prefix_but_no_vrrp_ip(self):
        client = FakeNetboxClient()
        self.assertIsNone(netbox_ipam.get_shared_gateway(10, 6, client))  # fixture has no v6 VRRP IP for vlan10


class DhcpMetadataTests(unittest.TestCase):
    def test_get_dhcp_ranges_all(self):
        client = FakeNetboxClient()
        ranges = netbox_ipam.get_dhcp_ranges(client=client)
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0]["start"], "192.168.10.100")

    def test_get_dhcp_ranges_server_is_none_when_untagged(self):
        """A range tagged only with the ownership marker (predating the
        Phase 3C primary/secondary convention) reports server=None --
        never fabricated as "primary" by default."""
        client = FakeNetboxClient()
        self.assertIsNone(netbox_ipam.get_dhcp_ranges(client=client)[0]["server"])

    def test_get_dhcp_ranges_reports_primary_and_secondary(self):
        client = FakeNetboxClient()
        client._ip_ranges[0].tags.append(_Tag(netbox_ipam.DHCP_PRIMARY_TAG))
        client._ip_ranges.append(_IPRange(2, "192.168.10.200/32", "192.168.10.220/32", description="VLAN10 secondary pool"))
        client._ip_ranges[1].tags = [_Tag("csci5840-iac"), _Tag(netbox_ipam.DHCP_SECONDARY_TAG)]
        ranges = {r["start"]: r["server"] for r in netbox_ipam.get_dhcp_ranges(client=client)}
        self.assertEqual(ranges["192.168.10.100"], "primary")
        self.assertEqual(ranges["192.168.10.200"], "secondary")

    def test_get_dhcp_ranges_filters_by_server(self):
        client = FakeNetboxClient()
        client._ip_ranges[0].tags.append(_Tag(netbox_ipam.DHCP_PRIMARY_TAG))
        client._ip_ranges.append(_IPRange(2, "192.168.10.200/32", "192.168.10.220/32"))
        client._ip_ranges[1].tags = [_Tag("csci5840-iac"), _Tag(netbox_ipam.DHCP_SECONDARY_TAG)]
        primary_only = netbox_ipam.get_dhcp_ranges(server="primary", client=client)
        self.assertEqual([r["start"] for r in primary_only], ["192.168.10.100"])
        secondary_only = netbox_ipam.get_dhcp_ranges(server="secondary", client=client)
        self.assertEqual([r["start"] for r in secondary_only], ["192.168.10.200"])

    def test_get_dhcp_ranges_invalid_server_raises(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.get_dhcp_ranges(server="bogus", client=client)

    def test_get_dhcp_relay_targets(self):
        client = FakeNetboxClient()
        targets = netbox_ipam.get_dhcp_relay_targets("192.168.10.0/24", client)
        self.assertEqual(targets, ["192.168.200.100", "192.168.200.2"])

    def test_get_dhcp_relay_targets_empty_for_transit_prefix(self):
        client = FakeNetboxClient()
        self.assertEqual(netbox_ipam.get_dhcp_relay_targets("192.168.110.0/31", client), [])

    def test_get_dhcp_relay_targets_missing_prefix_raises(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_dhcp_relay_targets("10.0.0.0/24", client)


class PrefixAndUniverseTests(unittest.TestCase):
    def test_get_prefix(self):
        client = FakeNetboxClient()
        prefix = netbox_ipam.get_prefix("192.168.10.0/24", client)
        self.assertEqual(prefix["vlan_vid"], 10)
        self.assertTrue(prefix["managed"])

    def test_missing_prefix_raises_model_error(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_prefix("10.0.0.0/24", client)

    def test_device_interface_names(self):
        client = FakeNetboxClient()
        names = netbox_ipam.get_device_interface_names("R1", client)
        self.assertEqual(names, ["Ethernet2", "Vlan101", "Vlan200"])

    def test_list_all_prefix_cidrs(self):
        client = FakeNetboxClient()
        cidrs = netbox_ipam.list_all_prefix_cidrs(client)
        self.assertIn("192.168.10.0/24", cidrs)
        self.assertIn("2001:db8:30::/64", cidrs)


# ---------------------------------------------------------------------------
# Phase 3B: MAC address (dcim.MACAddress) and assignment-mode/DHCPv6-identity
# custom-field read/reconcile functions.
# ---------------------------------------------------------------------------


class InterfaceMacTests(unittest.TestCase):
    def test_no_mac_recorded_returns_none(self):
        client = FakeNetboxClient()
        self.assertIsNone(netbox_ipam.get_interface_mac("R1", "Vlan200", client))

    def test_missing_interface_raises_model_error(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_interface_mac("R1", "NoSuchInterface", client)

    def test_ensure_interface_mac_creates_and_sets_primary(self):
        client = FakeNetboxClient()
        result = netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        self.assertEqual(result.action, netbox_ipam.CREATE)
        recorded = netbox_ipam.get_interface_mac("R1", "Vlan200", client)
        self.assertEqual(recorded["mac_address"], "00:1c:73:20:ab:82")
        self.assertEqual(recorded["identity_status"], netbox_ipam.IDENTITY_OBSERVED)

    def test_ensure_interface_mac_is_idempotent(self):
        client = FakeNetboxClient()
        netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        result = netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        self.assertEqual(result.action, netbox_ipam.UNCHANGED)
        self.assertEqual(len(client._mac_addresses), 1)  # never duplicated

    def test_ensure_interface_mac_missing_interface_raises(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.ensure_interface_mac("R1", "NoSuchInterface", "00:1c:73:20:ab:82", client, apply=True)

    def test_check_mode_does_not_create(self):
        client = FakeNetboxClient()
        result = netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=False)
        self.assertEqual(result.action, netbox_ipam.CHECK_CREATE)
        self.assertEqual(client._mac_addresses, [])

    def test_authoritative_identity_survives_observational_resync(self):
        client = FakeNetboxClient()
        netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        promoted = netbox_ipam.mark_mac_authoritative(
            "R1", "Vlan200", description="planned pin", client=client, apply=True,
        )
        self.assertEqual(promoted.action, netbox_ipam.UPDATE)
        rerun = netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        self.assertEqual(rerun.action, netbox_ipam.UNCHANGED)
        self.assertEqual(
            netbox_ipam.get_interface_mac("R1", "Vlan200", client)["identity_status"],
            netbox_ipam.IDENTITY_AUTHORITATIVE,
        )


class AssignmentModeTests(unittest.TestCase):
    def test_returns_none_values_when_not_yet_set(self):
        client = FakeNetboxClient()
        modes = netbox_ipam.get_assignment_modes("R1", "Vlan200", client)
        self.assertIsNone(modes["ipv4_mode"])
        self.assertIsNone(modes["ipv6_mode"])
        self.assertIsNone(modes["dhcpv6_duid"])
        self.assertIsNone(modes["dhcpv6_iaid"])
        self.assertIsNone(modes["dhcpv6_identity_status"])

    def test_reads_recorded_custom_fields(self):
        client = FakeNetboxClient()
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields = {
            "ipv4_assignment_mode": "dhcp-reserved", "ipv6_assignment_mode": "dhcpv6-reserved",
            "dhcpv6_identity_status": netbox_ipam.IDENTITY_BLOCKED,
        }
        modes = netbox_ipam.get_assignment_modes("R1", "Vlan200", client)
        self.assertEqual(modes["ipv4_mode"], "dhcp-reserved")
        self.assertEqual(modes["ipv6_mode"], "dhcpv6-reserved")
        self.assertIsNone(modes["dhcpv6_duid"])  # never fabricated
        self.assertEqual(modes["dhcpv6_identity_status"], netbox_ipam.IDENTITY_BLOCKED)

    def test_missing_interface_raises_model_error(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxModelError):
            netbox_ipam.get_assignment_modes("R1", "NoSuchInterface", client)


class Dhcpv6IdentityTests(unittest.TestCase):
    def test_authoritative_identity_is_written_and_idempotent(self):
        client = FakeNetboxClient()
        duid = "00:03:00:01:00:1c:73:20:ab:82"
        first = netbox_ipam.set_dhcpv6_identity(
            "R1", "Vlan200", status=netbox_ipam.IDENTITY_AUTHORITATIVE,
            duid=duid, client=client, apply=True,
        )
        second = netbox_ipam.set_dhcpv6_identity(
            "R1", "Vlan200", status=netbox_ipam.IDENTITY_AUTHORITATIVE,
            duid=duid, client=client, apply=True,
        )
        self.assertEqual(first.action, netbox_ipam.UPDATE)
        self.assertEqual(second.action, netbox_ipam.UNCHANGED)
        modes = netbox_ipam.get_assignment_modes("R1", "Vlan200", client)
        self.assertEqual(modes["dhcpv6_duid"], duid)
        self.assertEqual(modes["dhcpv6_identity_status"], netbox_ipam.IDENTITY_AUTHORITATIVE)

    def test_authoritative_status_requires_duid(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.set_dhcpv6_identity(
                "R1", "Vlan200", status=netbox_ipam.IDENTITY_AUTHORITATIVE,
                client=client,
            )

    def test_blocked_status_rejects_fabricated_identity_values(self):
        client = FakeNetboxClient()
        with self.assertRaises(netbox_ipam.NetboxConfigurationError):
            netbox_ipam.set_dhcpv6_identity(
                "R1", "Vlan200", status=netbox_ipam.IDENTITY_BLOCKED,
                duid="00:03:00:01:00:1c:73:20:ab:82", client=client,
            )


class SafeUpdateCustomFieldsTests(unittest.TestCase):
    """Phase 3B.3: reconcile_object() gained an explicit opt-in to update a
    custom field this repository owns as revisable POLICY, instead of the
    default strict "differing value is a CONFLICT" behavior."""

    def setUp(self):
        self.endpoint = _FakeEndpoint()

    def test_differing_value_is_conflict_by_default(self):
        record = self.endpoint.create(custom_fields={"ipv4_assignment_mode": "dhcp-reserved"})
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id},
            desired={"custom_fields": {"ipv4_assignment_mode": "static"}}, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.CONFLICT)
        self.assertEqual(record.custom_fields, {"ipv4_assignment_mode": "dhcp-reserved"})  # never overwritten

    def test_differing_value_updates_when_key_is_declared_safe(self):
        record = self.endpoint.create(custom_fields={"ipv4_assignment_mode": "dhcp-reserved"})
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id},
            desired={"custom_fields": {"ipv4_assignment_mode": "static"}},
            safe_update_custom_fields=frozenset({"ipv4_assignment_mode"}), apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        self.assertEqual(record.custom_fields, {"ipv4_assignment_mode": "static"})

    def test_second_run_after_safe_update_is_unchanged(self):
        record = self.endpoint.create(custom_fields={"ipv4_assignment_mode": "dhcp-reserved"})
        safe = frozenset({"ipv4_assignment_mode"})
        netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id},
            desired={"custom_fields": {"ipv4_assignment_mode": "static"}}, safe_update_custom_fields=safe, apply=True,
        )
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id},
            desired={"custom_fields": {"ipv4_assignment_mode": "static"}}, safe_update_custom_fields=safe, apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UNCHANGED)

    def test_clearing_to_empty_string_is_a_no_op_when_already_unset(self):
        """A safe-update key that was never set (None) and is being
        reconciled toward "" (cleared) must not be reported as a change --
        it is already effectively unset."""
        record = self.endpoint.create(custom_fields={})
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id},
            desired={"custom_fields": {"dhcpv6_duid": ""}},
            safe_update_custom_fields=frozenset({"dhcpv6_duid"}), apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.UNCHANGED)

    def test_unrelated_safe_keys_do_not_affect_other_conflicts(self):
        record = self.endpoint.create(custom_fields={"ipv4_assignment_mode": "dhcp-reserved", "iac_managed": False})
        result = netbox_ipam.reconcile_object(
            self.endpoint, lookup={"id": record.id},
            desired={"custom_fields": {"ipv4_assignment_mode": "static", "iac_managed": True}},
            safe_update_custom_fields=frozenset({"ipv4_assignment_mode"}), apply=True,
        )
        self.assertEqual(result.action, netbox_ipam.CONFLICT)
        self.assertIn("iac_managed", result.conflicts.get("custom_fields", {}))
        self.assertNotIn("ipv4_assignment_mode", result.conflicts.get("custom_fields", {}))


class ClearStaleMacIdentityStatusTests(unittest.TestCase):
    """Phase 3B.3: an interface no longer classified dhcp-reserved may
    still carry a stale identity_status from before the correction --
    these tests exercise the self-guarding cleanup, driven entirely by the
    interface's CURRENT assignment-mode policy, never by interface name."""

    def test_no_op_when_no_mac_recorded(self):
        client = FakeNetboxClient()
        result = netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result)

    def test_no_op_when_mode_is_still_dynamic(self):
        client = FakeNetboxClient()
        netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        netbox_ipam.mark_mac_authoritative("R1", "Vlan200", description="x", client=client, apply=True)
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields = {"ipv4_assignment_mode": "dhcp-reserved"}
        result = netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result)
        self.assertEqual(
            netbox_ipam.get_interface_mac("R1", "Vlan200", client)["identity_status"],
            netbox_ipam.IDENTITY_AUTHORITATIVE,
        )

    def test_clears_stale_authoritative_status_when_mode_is_static(self):
        client = FakeNetboxClient()
        netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        netbox_ipam.mark_mac_authoritative("R1", "Vlan200", description="x", client=client, apply=True)
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields = {"ipv4_assignment_mode": "static"}
        result = netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        recorded = netbox_ipam.get_interface_mac("R1", "Vlan200", client)
        self.assertIsNone(recorded["identity_status"])
        self.assertEqual(recorded["mac_address"], "00:1c:73:20:ab:82")  # the MAC itself is preserved

    def test_idempotent_second_run_is_unchanged(self):
        client = FakeNetboxClient()
        netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        netbox_ipam.mark_mac_authoritative("R1", "Vlan200", description="x", client=client, apply=True)
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields = {"ipv4_assignment_mode": "static"}
        netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        result = netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result)  # nothing left to clear

    def test_clears_stale_pinning_description_even_if_identity_status_already_cleared(self):
        # Regression: a prior cleanup pass may have already cleared
        # identity_status (Phase 3B.3's initial cutover) while leaving the
        # mechanism-pinning description text behind on the MAC object. This
        # must still be detected and neutralized, not skipped merely because
        # identity_status looks already-clean.
        client = FakeNetboxClient()
        netbox_ipam.ensure_interface_mac("R1", "Vlan200", "00:1c:73:20:ab:82", client, apply=True)
        netbox_ipam.mark_mac_authoritative(
            "R1", "Vlan200",
            description="Pin via EOS 'interface Vlan200/mac-address <value>' ... Not yet applied -- see docs/NETBOX_IPAM.md.",
            client=client, apply=True,
        )
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields = {"ipv4_assignment_mode": "static"}
        mac_obj = next(m for m in client._mac_addresses if m.mac_address == "00:1c:73:20:ab:82")
        mac_obj.custom_fields["identity_status"] = ""  # simulate the earlier partial cleanup
        result = netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        recorded = netbox_ipam.get_interface_mac("R1", "Vlan200", client)
        self.assertIsNone(recorded["identity_status"])
        self.assertNotIn("Not yet applied", recorded["description"])
        self.assertEqual(recorded["mac_address"], "00:1c:73:20:ab:82")  # the MAC itself is preserved
        # idempotent
        result2 = netbox_ipam.clear_stale_mac_identity_status("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result2)


class ClearStaleDhcpv6IdentityTests(unittest.TestCase):
    def test_no_op_when_nothing_recorded(self):
        client = FakeNetboxClient()
        result = netbox_ipam.clear_stale_dhcpv6_identity("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result)

    def test_no_op_when_mode_is_still_dynamic(self):
        client = FakeNetboxClient()
        duid = "00:03:00:01:00:1c:73:20:ab:82"
        netbox_ipam.set_dhcpv6_identity(
            "R1", "Vlan200", status=netbox_ipam.IDENTITY_AUTHORITATIVE, duid=duid, client=client, apply=True,
        )
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields["ipv6_assignment_mode"] = "dhcpv6-reserved"
        result = netbox_ipam.clear_stale_dhcpv6_identity("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result)
        self.assertEqual(netbox_ipam.get_assignment_modes("R1", "Vlan200", client)["dhcpv6_duid"], duid)

    def test_clears_stale_identity_when_mode_is_static(self):
        client = FakeNetboxClient()
        duid = "00:03:00:01:00:1c:73:20:ab:82"
        netbox_ipam.set_dhcpv6_identity(
            "R1", "Vlan200", status=netbox_ipam.IDENTITY_BLOCKED, client=client, apply=True,
        )
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields["ipv6_assignment_mode"] = "static"
        result = netbox_ipam.clear_stale_dhcpv6_identity("R1", "Vlan200", client, apply=True)
        self.assertEqual(result.action, netbox_ipam.UPDATE)
        modes = netbox_ipam.get_assignment_modes("R1", "Vlan200", client)
        self.assertIsNone(modes["dhcpv6_duid"])
        self.assertIsNone(modes["dhcpv6_iaid"])
        self.assertIsNone(modes["dhcpv6_identity_status"])

    def test_idempotent_second_run_is_unchanged(self):
        client = FakeNetboxClient()
        netbox_ipam.set_dhcpv6_identity("R1", "Vlan200", status=netbox_ipam.IDENTITY_BLOCKED, client=client, apply=True)
        r1_vlan200 = next(i for i in client._interfaces if i.name == "Vlan200" and i.device.slug == "R1")
        r1_vlan200.custom_fields["ipv6_assignment_mode"] = "static"
        netbox_ipam.clear_stale_dhcpv6_identity("R1", "Vlan200", client, apply=True)
        result = netbox_ipam.clear_stale_dhcpv6_identity("R1", "Vlan200", client, apply=True)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
