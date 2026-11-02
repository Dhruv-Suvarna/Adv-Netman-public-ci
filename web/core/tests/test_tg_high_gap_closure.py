"""Lab 7 -- closure of the three HIGH platform x feature proof gaps found by the input-vector audit.

1. APPLY       cEOS ACL attachment and DHCP relay (IPv4 / IPv6): the complete ``interface`` block preflights to exactly
               APPLY with an exact inverse (the parent-less child alone used to read as SKIP_SATISFIED).
2. INVERSE     20 supported cells whose CELL compensation proof was only ``restorable is True``: the exact inverse is
               asserted, then a fake device runs APPLY -> COMPENSATE -> COMPARE through the executor's own compensate().
3. OWNERSHIP   cEOS ACL attachment, DHCP relay and VARP references: missing, foreign and removed interface / ACL ids are
               refused by the intent service's reference gate, and nothing is persisted.

Fake sessions and the test database only: no device, NetBox or credential is touched.
"""

from __future__ import annotations

from copy import deepcopy
from unittest import mock

from django.db import transaction
from django.test import TestCase

from core.services import service_policy_intent_service as sp, srlinux_model
from core.services.capabilities import offline_verify
from core.services.execution.executors import ceos, linux
from core.services.execution.executors.base import APPLY
from core.services.health.evidence import DeviceEvidence, FactGroup
from core.tests.test_tg_cells import CellContext

# -- 1. APPLY ----------------------------------------------------------------------------------------------------------
APPLY_CELLS = {
    "service_policy.ACL_ATTACH_IPV4": ("   ip access-group CAP_ACL in",
                                       ["interface Ethernet1", "   no ip access-group CAP_ACL in"]),
    "service_policy.DHCP_RELAY_IPV4": ("   ip helper-address 192.0.2.44",
                                       ["interface Ethernet1", "   no ip helper-address 192.0.2.44"]),
    "service_policy.DHCP_RELAY_IPV6": ("   ipv6 dhcp relay destination 2001:db8::44",
                                       ["interface Ethernet1", "   no ipv6 dhcp relay destination 2001:db8::44"]),
}

# -- 2. exact inverses relative to each cell's captured baseline -------------------------------------------------------
EXACT_INVERSES = {
    ("arista_ceos", "interface.ACCESS"): ["no interface Ethernet1"],
    ("arista_ceos", "interface.MANAGEMENT"): ["no interface Management1"],
    ("arista_ceos", "interface.TRUNK"): ["no interface Ethernet1"],
    ("arista_ceos", "routing.BGP_IPV6"): ["no router bgp 65044"],
    ("arista_ceos", "routing.OSPFV3"): ["no ipv6 router ospf 44", "interface Ethernet1", "   no ipv6 ospf network point-to-point",
                                        "   no ipv6 ospf cost 10", "   no ipv6 ospf 44 area 0"],
    ("arista_ceos", "routing.RIPV2"): ["no router rip"],
    ("arista_ceos", "routing.STATIC_IPV6"): ["no ipv6 route 2001:db8:113::/64 2001:db8:44::2 200"],
    ("arista_ceos", "service_policy.ACL_IPV4_STANDARD"): ["no ip access-list standard CAP_ACL"],
    ("arista_ceos", "service_policy.DHCP_RELAY_IPV4"): ["interface Ethernet1", "   no ip helper-address 192.0.2.44"],
    ("arista_ceos", "service_policy.DHCP_RELAY_IPV6"): ["interface Ethernet1", "   no ipv6 dhcp relay destination 2001:db8::44"],
    ("arista_ceos", "service_policy.FHRP_VARP_IPV6"): ["interface Ethernet1", "   no ipv6 virtual-router address 2001:db8:44::3",
                                                       "no ip virtual-router mac-address 00:1c:73:00:00:44"],
    ("cisco_c8000v_iosxe", "interface.SUBINTERFACE"): ["no interface GigabitEthernet2.44"],
    ("cisco_c8000v_iosxe", "routing.STATIC_IPV6"): ["no ipv6 route 2001:db8:113::/64 2001:db8:44::2 200"],
    ("nokia_srlinux", "interface.ROUTED_PHYSICAL"): ["delete / network-instance default", "delete / interface ethernet-1/1"],
    ("nokia_srlinux", "interface.SUBINTERFACE"): ["delete / network-instance default interface ethernet-1/1.44",
                                                  "delete / interface ethernet-1/1 subinterface 44",
                                                  "delete / interface ethernet-1/1 vlan-tagging"],
    ("nokia_srlinux", "routing.STATIC_IPV6"): ["delete / network-instance default next-hop-groups",
                                               "delete / network-instance default static-routes"],
    ("ubuntu_frr", "interface.MANAGEMENT"): [["ip", "link", "delete", "eth0"]],
    ("ubuntu_frr", "interface.SUBINTERFACE"): [["ip", "link", "delete", "eth1.44"]],
    ("ubuntu_frr", "interface.SVI"): [["ip", "link", "delete", "vlan44"]],
    ("ubuntu_frr", "routing.OSPFV3"): ["interface eth1", "   no ipv6 ospf6 network point-to-point", "   no ipv6 ospf6 cost 10",
                                       "   no ipv6 ospf6 area 0", "no router ospf6"],
}


def _stored_inverse(executor, spec):
    """The inverse the executor captured at preflight -- what compensate() would send."""
    for attr in ("_config_inverses", "_inverses", "_routing_inverses"):
        if spec.cfg_id in getattr(executor, attr, {}):
            return getattr(executor, attr)[spec.cfg_id]
    return ceos.inverse_lines(spec) if spec.platform == "arista_ceos" else linux.inverse_operations(spec)


def _facts(interfaces=None, routes=None):
    groups = (("interfaces", interfaces or {}), ("addresses", {}), ("routes", routes or []))
    return DeviceEvidence("CAPDUT", "fake", {name: FactGroup(value, "SYNTHETIC") for name, value in groups}, live_attempted=True)


class _TextDevice:
    """A disposable running configuration: ``applied`` until a configuration set is sent, then whatever ``after`` says."""

    def __init__(self, applied: str, after: str):
        self.text, self.after, self.sent = applied, after, []

    # netmiko surface used by the cEOS / IOS-XE executors
    def send_command(self, command, **_kwargs):
        if command == "show tcp brief":
            return ""
        if command != "show running-config":
            raise ValueError("fake device only serves the running configuration")
        return self.text

    def config_mode(self, **_kwargs):
        return ""

    def check_config_mode(self):
        return False

    def exit_config_mode(self):
        return ""

    def send_config_set(self, commands, **_kwargs):
        self.sent.append(list(commands))
        self.text = self.after
        return ""


class _TreeDevice:
    """A disposable SR Linux candidate datastore: ``set`` merges and ``delete`` removes, through the NMAS tree model."""

    def __init__(self, tree: dict):
        self.tree, self.sent = deepcopy(tree), []

    def get(self, path, datatype="config"):
        return offline_verify._FixtureGnmi(self.tree).get(path, datatype)    # pylint: disable=protected-access

    def set_cli(self, statements):
        self.sent.append(list(statements))
        for raw in statements:
            verb, _, rest = raw.strip().partition(" ")
            op = srlinux_model.operation("set " + rest.strip().removeprefix("/").strip())
            if verb == "set":
                srlinux_model.apply_operation(self.tree, op)
                continue
            *parents, last = op.steps
            node = self.tree
            for step in parents:
                node = srlinux_model._child(node, step, create=False)      # pylint: disable=protected-access
            if last.key:
                node[last.name] = [row for row in node.get(last.name, []) if str(row.get(last.key)) != str(last.value)]
                if not node[last.name]:
                    del node[last.name]
            else:
                node.pop(last.name, None)
        return len(statements)


def _runner(log, effect):
    """A fake ``docker exec``: records the argv, applies the device-side effect, exits 0."""
    def run(_container, argv, _timeout):
        log.append(argv)
        effect()
        return 0
    return run


def _config_set(log, effect):
    def send(commands, **_kwargs):
        log.append(list(commands))
        effect()
        return ""
    return send


def _prune(tree):
    """Containers left empty by a delete carry no configuration."""
    if isinstance(tree, dict):
        return {k: _prune(v) for k, v in tree.items() if _prune(v) not in ({}, [])}
    if isinstance(tree, list):
        return [_prune(v) for v in tree]
    return tree


def _cell_name(platform: str, feature: str) -> str:
    return f"{platform}_{feature}".lower().replace(".", "_")


class HighGapApplyTests(TestCase):
    """HIGH gap 1: the complete cEOS object preflights to exactly APPLY with an exact inverse."""

    def _check(self, feature: str):
        child, inverse = APPLY_CELLS[feature]
        ctx = CellContext("arista_ceos", feature)
        self.assertEqual(ctx.target, ["interface Ethernet1", child], "the child must travel with its rendered parent block")
        executor = ctx.executor()
        self.assertIsInstance(executor, ceos.CeosExecutor)
        self.assertIsInstance(executor._conn, offline_verify._FixtureConfigSession)   # pylint: disable=protected-access
        spec = ctx.spec(ctx.target)
        found = executor.assess(spec)
        self.assertEqual((found.action, found.restorable, found.reason), (APPLY, True, ""))
        self.assertEqual(found.previous_state["kind"], "config_block")
        self.assertEqual(executor._config_inverses[spec.cfg_id], inverse)           # pylint: disable=protected-access
        # the fixture session refuses any configuration command: nothing could have been sent
        self.assertFalse(hasattr(executor._conn, "send_config_set"))               # pylint: disable=protected-access
        # the weak proof this replaces: the parent-less child alone has nothing to apply or invert
        self.assertEqual(ctx.executor().assess(ctx.spec([child])).action, "SKIP_SATISFIED")


class HighGapInverseTests(TestCase):
    """HIGH gap 2: exact inverse, then APPLY -> COMPENSATE -> COMPARE on a fake device."""

    maxDiff = None

    def _restore_loop(self, ctx, executor, spec, found, inverse):
        platform = ctx.platform
        if platform == "nokia_srlinux":
            baseline = srlinux_model.tree_from_set_lines(ctx.base)
            device = _TreeDevice(baseline)
            executor._conn = device
            self.assertTrue(executor.apply(spec, found).ok)                          # APPLY onto the in-memory tree
            self.assertNotEqual(_prune(device.tree), _prune(baseline))
            outcome = executor.compensate(spec, found)                               # COMPENSATE
            self.assertEqual(device.sent, [srlinux_model.statements(spec.lines), inverse])
            self.assertEqual(_prune(device.tree), _prune(baseline), "compensation did not restore the captured tree")   # COMPARE
            self.assertEqual(outcome.status, "COMPENSATED", outcome.error_code)
            return
        if found.previous_state.get("kind") in ("config_block", "frr_config_block"):
            base = "\n".join(ctx.base)
            if platform == "cisco_c8000v_iosxe":
                base = "\n".join(["interface GigabitEthernet9", " no ip address", " shutdown", *ctx.base])
            applied = base + "\n" + "\n".join(ctx.target)
            for after, status in ((base, "COMPENSATED"), (applied, "COMPENSATION_FAILED")):
                device = _TextDevice(applied, after)
                if platform == "ubuntu_frr":
                    sent = []
                    executor._config_reader = lambda _c, _t, d=device: d.text
                    executor._run = _runner(sent, lambda d=device: setattr(d, "text", d.after))
                else:
                    executor._conn = device
                outcome = executor.compensate(spec, found)
                self.assertEqual(outcome.status, status, outcome.error_code)
                if platform == "ubuntu_frr":
                    commands = [part for argv in sent for part in argv[4::2]]
                    self.assertEqual([c.strip() for c in commands], [c.strip() for c in inverse])
                elif platform == "arista_ceos":
                    self.assertEqual(device.sent, [ceos._eos_commands(inverse)])   # pylint: disable=protected-access
                else:
                    self.assertEqual(device.sent, [[c.strip() for c in inverse]])
                if status != "COMPENSATED":
                    self.assertEqual(outcome.error_code, "STATE_NOT_RESTORED")
            return
        # modelled interface / static route: restored when the read groups show the captured state again
        name, prefix = spec.expected.get("interface"), spec.expected.get("prefix")
        applied = _facts(interfaces={name: {}} if name else None,
                         routes=[{"prefix": prefix, "type": "static", "next_hops": [spec.expected.get("next_hop")]}] if prefix else None)
        for restores, status in ((True, "COMPENSATED"), (False, "COMPENSATION_FAILED")):
            sent, state = [], {"facts": applied}
            executor._reader = lambda _device, s=state: s["facts"]
            if platform == "ubuntu_frr":
                executor._run = _runner(sent, lambda s=state, r=restores: s.update(facts=_facts() if r else applied))
            else:
                device = _TextDevice("\n".join(ctx.lines), "\n".join(ctx.lines))
                device.send_config_set = _config_set(sent, lambda s=state, r=restores: s.update(facts=_facts() if r else applied))
                executor._conn = device
            outcome = executor.compensate(spec, found)
            self.assertEqual(outcome.status, status, outcome.error_code)
            self.assertEqual(sent, inverse if platform == "ubuntu_frr" else [ceos._eos_commands(inverse)])  # pylint: disable=protected-access

    def _check(self, platform: str, feature: str):
        ctx = CellContext(platform, feature)
        executor = ctx.executor()
        spec = ctx.spec(ctx.target)
        found = executor.assess(spec)
        self.assertEqual((found.action, found.restorable), (APPLY, True), found.reason)
        inverse = _stored_inverse(executor, spec)
        self.assertEqual(inverse, EXACT_INVERSES[(platform, feature)])
        self._restore_loop(ctx, executor, spec, found, inverse)

    def test_srlinux_populated_network_instance_restores_only_the_cell_entries(self):
        """A device whose default network-instance already holds other interfaces / routes keeps them across the loop."""
        others = ["set network-instance default interface ethernet-1/9.0",
                  "set network-instance default static-routes route 10.9.0.0/24 admin-state enable",
                  "set network-instance default static-routes route 10.9.0.0/24 next-hop-group nhg-x",
                  "set network-instance default next-hop-groups group nhg-x nexthop 1 ip-address 10.0.0.9"]
        expected = {
            "interface.ROUTED_PHYSICAL": ["delete / network-instance default interface ethernet-1/1.0", "delete / interface ethernet-1/1"],
            "routing.STATIC_IPV6": ["delete / network-instance default next-hop-groups group nhg-route_0000000000000003",
                                    "delete / network-instance default static-routes route 2001:db8:113::/64"],
        }
        for feature, inverse in expected.items():
            with self.subTest(feature=feature):
                ctx = CellContext("nokia_srlinux", feature)
                baseline = srlinux_model.tree_from_set_lines([*ctx.base, *others])
                executor, spec = ctx.executor(), ctx.spec(ctx.target)
                device = executor._conn = _TreeDevice(baseline)
                found = executor.assess(spec)
                self.assertEqual((found.action, found.restorable), (APPLY, True))
                self.assertEqual(executor._inverses[spec.cfg_id], inverse)             # pylint: disable=protected-access
                self.assertTrue(executor.apply(spec, found).ok)
                self.assertEqual(executor.compensate(spec, found).status, "COMPENSATED")
                self.assertEqual(_prune(device.tree), _prune(baseline))

    def test_frr_existing_management_link_is_never_deleted(self):
        """The ``ip link delete`` inverse is exact only for a link that did not exist: an existing eth0 is not restorable."""
        ctx = CellContext("ubuntu_frr", "interface.MANAGEMENT")
        executor = ctx.executor()
        executor._reader = lambda _device: _facts(interfaces={"eth0": {}})
        found = executor.assess(ctx.spec(ctx.target))
        self.assertEqual((found.action, found.restorable), (APPLY, False))


def _add_cases():
    for feature in APPLY_CELLS:
        def apply_test(self, feature=feature):
            self._check(feature)
        setattr(HighGapApplyTests, f"test_{_cell_name('arista_ceos', feature)}_complete_block_applies", apply_test)
    for platform, feature in EXACT_INVERSES:
        def inverse_test(self, platform=platform, feature=feature):
            with transaction.atomic():
                self._check(platform, feature)
                transaction.set_rollback(True)
        setattr(HighGapInverseTests, f"test_{_cell_name(platform, feature)}_exact_inverse_restores_baseline", inverse_test)


_add_cases()


# -- 3. OWNERSHIP ------------------------------------------------------------------------------------------------------
OWNERSHIP = "does not belong to this candidate revision"
MISSING_IFACE = "if_0000000000000000"   # well-formed, never created


class HighGapOwnershipTests(TestCase):
    """HIGH gap 3: cEOS ACL attachment, DHCP relay and VARP references are refused by the ownership gate itself."""

    def setUp(self):
        from core import models
        from core.services import intent_service
        from core.tests.helpers.candidates import add_interface, make_candidate

        self.change, self.intent, self.revision = make_candidate(platform=models.Platform.ARISTA_CEOS, device_name="R1")
        self.eth = add_interface(self.revision, kind="ROUTED_PHYSICAL", name="Ethernet1")
        self.svi = add_interface(self.revision, kind="SVI", name="Vlan10")
        self.gone = add_interface(self.revision, kind="ROUTED_PHYSICAL", name="Ethernet7")
        from core.services import interface_intent_service
        interface_intent_service.remove_interface(revision=self.revision, interface_id=self.gone["id"], confirmation="REMOVE")
        self.acl = sp.add_acl(revision=self.revision, name="CAP_ACL", family="IPV4", acl_type="STANDARD")
        self.gone_acl = sp.add_acl(revision=self.revision, name="OLD_ACL", family="IPV4", acl_type="STANDARD")
        sp.remove_object(revision=self.revision, kind="acl", object_id=self.gone_acl["id"], confirmation="REMOVE")
        # a second device of the SAME change: its ids are real, but foreign to R1's candidate
        other, _ = intent_service.create_or_get_device_intent(change=self.change, device_name="R2", platform=models.Platform.ARISTA_CEOS)
        self.other_revision = intent_service.create_candidate_revision(device_intent=other)
        self.foreign = add_interface(self.other_revision, kind="SVI", name="Vlan10")
        self.foreign_acl = sp.add_acl(revision=self.other_revision, name="CAP_ACL", family="IPV4", acl_type="STANDARD")
        self.revision.refresh_from_db()
        self.other_revision.refresh_from_db()

    def bad_interfaces(self):
        return {"missing": MISSING_IFACE, "empty": "", "foreign": self.foreign["id"], "removed": self.gone["id"]}

    def unowned_interfaces(self):
        """Ids the Tier-1 reference rule refuses; a blank value is deferred to the project dependency graph (below)."""
        return {"missing": MISSING_IFACE, "foreign": self.foreign["id"], "removed": self.gone["id"]}

    def assert_unset_reference_missing(self, node_type, object_id, reason):
        """A blank reference passes Tier-1 syntax but is a MISSING ``(unset)`` edge in project validation: never resolved."""
        from core.services.validation import dependency_graph, snapshot
        from core.services.validation.context import ProjectModel

        graph = dependency_graph.build_graph(ProjectModel(snapshot.build_change_snapshot(self.change)))
        edges = [e for e in graph["edges"] if e["from"] == dependency_graph.node_id("R1", node_type, object_id)
                 and e["to"].endswith("/interface/<unset>")]
        self.assertEqual([(e["status"], e["reason"]) for e in edges], [("MISSING", f"{reason} (unset)")], graph["edges"])

    def assert_refused(self, call, label):
        """The ownership gate refuses; R1's candidate and its field states are untouched; R2 is untouched."""
        self.revision.refresh_from_db()
        before = (deepcopy(self.revision.sections), self.revision.field_states.count())
        other_before = deepcopy(self.other_revision.sections)
        with mock.patch("core.services.execution.executors.registry.executor_for", side_effect=AssertionError("device contacted")):
            with self.assertRaisesRegex(sp.CollectionOwnershipError, f"^{label} ID {OWNERSHIP}"):
                call()
        self.revision.refresh_from_db()
        self.other_revision.refresh_from_db()
        self.assertEqual((self.revision.sections, self.revision.field_states.count()), before)
        self.assertEqual(self.other_revision.sections, other_before)

    def assert_field_refused(self, path, value):
        """The Tier-1 reference rule of the committed field path refuses the same id; the stored value is unchanged."""
        from core.services import field_commit_service

        self.revision.refresh_from_db()
        sections = deepcopy(self.revision.sections)
        state = field_commit_service.commit_field(change=self.change, intent=self.intent, revision=self.revision, path=path, raw_value=value)
        self.assertEqual(state.validation_state, "INVALID", (path, value))
        self.revision.refresh_from_db()
        self.assertEqual(self.revision.sections, sections)

    # ACL attachment ---------------------------------------------------------------------------------------------------
    def test_acl_attachment_accepts_candidate_owned_interface_and_acl(self):
        obj = sp.add_acl_attachment(revision=self.revision, acl_id=self.acl["id"], interface_id=self.eth["id"])
        self.revision.refresh_from_db()
        self.assertEqual(self.revision.sections["security"]["attachments"][obj["id"]],
                         {"id": obj["id"], "sequence": obj["sequence"], "acl_id": self.acl["id"], "interface_id": self.eth["id"],
                          "direction": "IN"})

    def test_acl_attachment_refuses_missing_foreign_removed_interface(self):
        for kind, interface_id in self.bad_interfaces().items():
            with self.subTest(kind=kind):
                self.assert_refused(lambda i=interface_id: sp.add_acl_attachment(revision=self.revision, acl_id=self.acl["id"], interface_id=i),
                                    "Interface")
        self.assertEqual(self.revision.sections["security"]["attachments"], {})

    def test_acl_attachment_refuses_missing_foreign_removed_acl(self):
        for kind, acl_id in {"missing": "acl_0000000000000000", "empty": "", "foreign": self.foreign_acl["id"],
                             "removed": self.gone_acl["id"]}.items():
            with self.subTest(kind=kind):
                self.assert_refused(lambda a=acl_id: sp.add_acl_attachment(revision=self.revision, acl_id=a, interface_id=self.eth["id"]), "ACL")
        self.assertEqual(self.revision.sections["security"]["attachments"], {})

    def test_acl_attachment_field_paths_refuse_unowned_references(self):
        obj = sp.add_acl_attachment(revision=self.revision, acl_id=self.acl["id"], interface_id=self.eth["id"])
        for kind, interface_id in self.unowned_interfaces().items():
            with self.subTest(field="interface_id", kind=kind):
                self.assert_field_refused(f"security.attachments.{obj['id']}.interface_id", interface_id)
        for kind, acl_id in {"missing": "acl_0000000000000000", "foreign": self.foreign_acl["id"], "removed": self.gone_acl["id"]}.items():
            with self.subTest(field="acl_id", kind=kind):
                self.assert_field_refused(f"security.attachments.{obj['id']}.acl_id", acl_id)

    # DHCP relay -------------------------------------------------------------------------------------------------------
    RELAYS = {"IPV4": ("192.0.2.44", "192.0.2.44"), "IPV6": ("2001:DB8::44", "2001:db8::44")}

    def test_dhcp_relay_accepts_candidate_owned_interface_with_family_payload(self):
        for family, (raw, normalized) in self.RELAYS.items():
            with self.subTest(family=family):
                relay = sp.add_dhcp_relay(revision=self.revision, family=family, interface_id=self.eth["id"], destination=raw)
                self.revision.refresh_from_db()
                stored = self.revision.sections["services"]["dhcp"]["relays"][relay["id"]]
                self.assertEqual((stored["family"], stored["interface_id"], stored["destination"]), (family, self.eth["id"], normalized))
        self.assertEqual(self.other_revision.sections.get("services", {}).get("dhcp", {}).get("relays", {}) or {}, {})

    def test_dhcp_relay_refuses_missing_foreign_removed_interface(self):
        for family, (raw, _normalized) in self.RELAYS.items():
            for kind, interface_id in self.bad_interfaces().items():
                with self.subTest(family=family, kind=kind):
                    self.assert_refused(lambda f=family, i=interface_id, d=raw: sp.add_dhcp_relay(
                        revision=self.revision, family=f, interface_id=i, destination=d), "Interface")
        self.assertEqual((self.revision.sections.get("services", {}).get("dhcp", {}).get("relays") or {}), {})

    def test_dhcp_relay_field_path_refuses_unowned_interface(self):
        for family, (raw, normalized) in self.RELAYS.items():
            relay = sp.add_dhcp_relay(revision=self.revision, family=family, interface_id=self.eth["id"], destination=raw)
            for kind, interface_id in self.unowned_interfaces().items():
                with self.subTest(family=family, kind=kind):
                    self.assert_field_refused(f"services.dhcp.relays.{relay['id']}.interface_id", interface_id)
            stored = self.revision.sections["services"]["dhcp"]["relays"][relay["id"]]
            self.assertEqual((stored["family"], stored["destination"], stored["interface_id"]), (family, normalized, self.eth["id"]))

    # VARP -------------------------------------------------------------------------------------------------------------
    def test_varp_accepts_candidate_owned_svi(self):
        for family in ("IPV4", "IPV6"):
            with self.subTest(family=family):
                obj = sp.add_fhrp_instance(revision=self.revision, protocol="VARP", interface_id=self.svi["id"], address_family=family)
                self.revision.refresh_from_db()
                stored = self.revision.sections["fhrp"]["instances"][obj["id"]]
                self.assertEqual((stored["protocol"], stored["address_family"], stored["interface_id"]), ("VARP", family, self.svi["id"]))

    def test_varp_refuses_missing_foreign_removed_interface(self):
        for family in ("IPV4", "IPV6"):
            for kind, interface_id in self.bad_interfaces().items():
                with self.subTest(family=family, kind=kind):
                    self.assert_refused(lambda f=family, i=interface_id: sp.add_fhrp_instance(
                        revision=self.revision, protocol="VARP", interface_id=i, address_family=f), "Interface")
        self.assertEqual(self.revision.sections.get("fhrp", {}).get("instances") or {}, {})

    def test_varp_field_path_refuses_unowned_interface(self):
        for family in ("IPV4", "IPV6"):
            obj = sp.add_fhrp_instance(revision=self.revision, protocol="VARP", interface_id=self.svi["id"], address_family=family)
            for kind, interface_id in self.unowned_interfaces().items():
                with self.subTest(family=family, kind=kind):
                    self.assert_field_refused(f"fhrp.instances.{obj['id']}.interface_id", interface_id)

    def test_blank_reference_is_an_unresolved_dependency(self):
        from core.services import field_commit_service

        attachment = sp.add_acl_attachment(revision=self.revision, acl_id=self.acl["id"], interface_id=self.eth["id"])
        relays = {f: sp.add_dhcp_relay(revision=self.revision, family=f, interface_id=self.eth["id"], destination=raw)
                  for f, (raw, _n) in self.RELAYS.items()}
        varps = {f: sp.add_fhrp_instance(revision=self.revision, protocol="VARP", interface_id=self.svi["id"], address_family=f)
                 for f in ("IPV4", "IPV6")}
        paths = [f"security.attachments.{attachment['id']}.interface_id",
                 *(f"services.dhcp.relays.{r['id']}.interface_id" for r in relays.values()),
                 *(f"fhrp.instances.{v['id']}.interface_id" for v in varps.values())]
        for path in paths:
            self.revision.refresh_from_db()
            field_commit_service.commit_field(change=self.change, intent=self.intent, revision=self.revision, path=path, raw_value="")
        self.assert_unset_reference_missing("acl_attachment", attachment["id"], "ACL attachment interface")
        for relay in relays.values():
            self.assert_unset_reference_missing("dhcp_relay", relay["id"], "dhcp relay interface")
        for varp in varps.values():
            self.assert_unset_reference_missing("fhrp", varp["id"], "FHRP interface")

    def test_capability_gate_is_not_what_refuses(self):
        """The refusals above are ownership refusals, reached past a SUPPORTED capability gate (never 'unsupported')."""
        for feature in ("ACL_ATTACH_IPV4", "DHCP_RELAY_IPV4", "DHCP_RELAY_IPV6", "FHRP_VARP_IPV4", "FHRP_VARP_IPV6"):
            with self.subTest(feature=feature):
                self.assertTrue(sp._supported(self.revision, feature))                  # pylint: disable=protected-access
