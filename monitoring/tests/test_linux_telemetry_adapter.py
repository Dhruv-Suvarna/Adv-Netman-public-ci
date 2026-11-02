"""Focused offline regressions for the Linux telemetry adapter wire helpers."""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

from pygnmi.spec.v080 import gnmi_ext_pb2, gnmi_pb2, gnmi_pb2_grpc


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "monitoring" / "scripts"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LinuxTelemetryAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The deployed server uses router-local sibling stubs. Map the same
        # module names to pygnmi's generated classes for offline tests.
        sys.modules.setdefault("gnmi_ext_pb2", gnmi_ext_pb2)
        sys.modules.setdefault("gnmi_pb2", gnmi_pb2)
        sys.modules.setdefault("gnmi_pb2_grpc", gnmi_pb2_grpc)
        cls.gnmi = load("test_linux_gnmi_server", SCRIPTS / "linux_gnmi_server.py")
        cls.netconf = load("test_linux_netconf_server", SCRIPTS / "linux_netconf_server.py")
        cls.collector = load("test_gnmi_collector", SCRIPTS / "gnmi_collector.py")

    def test_namespace_aware_get_and_close_session(self):
        get_rpc = (
            '<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">'
            '<nc:get><filter type="subtree"><system xmlns="http://openconfig.net/yang/system">'
            '<state><hostname/></state></system></filter></nc:get></nc:rpc>'
        )
        reply, should_close = self.netconf.dispatch(get_rpc)
        self.assertFalse(should_close)
        self.assertIn(b'message-id="101"', reply)
        self.assertIn(b"<hostname>", reply)

        close_rpc = (
            '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="102">'
            "<close-session/></rpc>"
        )
        reply, should_close = self.netconf.dispatch(close_rpc)
        self.assertTrue(should_close)
        self.assertIn(b'message-id="102"', reply)
        self.assertIn(b"<ok/>", reply)

    def test_interface_pathelem_key_filters_and_survives_output(self):
        interfaces = {
            "eth1": {"admin_status": "UP", "oper_status": "UP", "counters": {"in-octets": 10}},
            "eth2": {"admin_status": "UP", "oper_status": "DOWN", "counters": {"in-octets": 20}},
        }
        explicit = gnmi_pb2.Path(elem=[
            self.gnmi.pe("interfaces"), self.gnmi.pe("interface", name="eth1"),
            self.gnmi.pe("state"), self.gnmi.pe("oper-status"),
        ])
        wildcard = gnmi_pb2.Path(elem=[
            self.gnmi.pe("interfaces"), self.gnmi.pe("interface", name="*"),
            self.gnmi.pe("state"), self.gnmi.pe("oper-status"),
        ])
        with mock.patch.object(self.gnmi.metrics, "interfaces", return_value=interfaces):
            explicit_notifications = self.gnmi.notif_interface_leaf(1, "oper-status", explicit)
            wildcard_notifications = self.gnmi.notif_interface_leaf(1, "oper-status", wildcard)

        self.assertEqual(len(explicit_notifications), 1)
        path = explicit_notifications[0].update[0].path
        self.assertEqual(self.gnmi.path_elem_key(path, "interface", "name"), "eth1")
        self.assertEqual(len(wildcard_notifications), 2)

        flat_path, keys = self.collector.path_to_dict(path)
        self.assertEqual(flat_path, "interfaces/interface/state/oper-status")
        self.assertEqual(keys, {"name": "eth1"})
        line = self.collector.classify(flat_path, keys, "UP", False, "R3", "linux")
        self.assertIn("interface=eth1", line)
        self.assertIn("oper_status=\"UP\"", line)

    def test_on_change_is_honestly_rejected(self):
        request = gnmi_pb2.SubscribeRequest()
        request.subscribe.mode = gnmi_pb2.SubscriptionList.STREAM
        subscription = request.subscribe.subscription.add()
        subscription.path.CopyFrom(gnmi_pb2.Path(elem=[self.gnmi.pe("system")]))
        subscription.mode = gnmi_pb2.ON_CHANGE

        class Context:
            def abort(self, code, message):
                raise RuntimeError((code, message))

        with mock.patch.object(self.gnmi, "check_auth"):
            replies = self.gnmi.LinuxGnmiServicer().Subscribe(iter([request]), Context())
            with self.assertRaisesRegex(RuntimeError, "ON_CHANGE"):
                next(replies)


if __name__ == "__main__":
    unittest.main()
