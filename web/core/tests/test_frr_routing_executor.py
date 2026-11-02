"""Incremental FRR routing execution (OSPF, RIP/RIPng, BGP) and its captured-state inverse contract."""

from django.test import SimpleTestCase

from core.services.config_import import parser_frr
from core.services.execution.executors import frr_routing
from core.services.execution.executors.base import APPLY, REFUSE, ConfigletSpec
from core.services.execution.executors.linux import LinuxExecutor, frr_routing_blocks, frr_routing_inverse
from core.services.health import live
from core.services.health.evidence import DeviceEvidence

ALL_DAEMONS = {"zebra", *frr_routing.DAEMONS.values()}
BGP = "router bgp 65044"
EXISTING = (f"{BGP}\n bgp router-id 198.18.44.1\n no bgp default ipv4-unicast\n no bgp ebgp-requires-policy\n"
            " neighbor 198.18.9.9 remote-as 65099\n !\n address-family ipv4 unicast\n  network 192.0.2.0/24\n"
            " exit-address-family\nexit\n!\n")
PROCESS = (BGP, "   bgp router-id 198.18.44.1", "   no bgp default ipv4-unicast", "   no bgp ebgp-requires-policy")
NEIGHBOR = (BGP, "   neighbor 2001:db8:44::2 remote-as 65045")
ACTIVATE = (BGP, "   address-family ipv6 unicast", "      neighbor 2001:db8:44::2 activate", "   exit-address-family")
NETWORK = (BGP, "   address-family ipv6 unicast", "      network 2001:db8:113::/64", "   exit-address-family")


def spec(cfg, kind, lines):
    return ConfigletSpec(cfg, 1, "frr", "ubuntu_frr", kind, "CREATE_DEFINE", tuple(lines), {})


class FakeFrr:
    """A config store that understands exactly the commands under test: additive leaves and their ``no`` forms."""

    def __init__(self, text="", daemons=ALL_DAEMONS):
        self.text, self.daemons, self.sent = text, set(daemons), []

    def executor(self):
        return LinuxExecutor({"name": "frr", "container": "disposable"}, runner=self.run,
                             reader=lambda _device: DeviceEvidence("frr", "linux", live_attempted=True),
                             config_reader=lambda _c, _t: self.text, daemon_reader=lambda _c, _t: self.daemons)

    def run(self, _container, argv, _timeout):
        commands = argv[4::2]                      # vtysh -c "configure terminal" -c <command> ...
        self.sent.append(commands)
        header, family = commands[0], ""
        state = frr_routing.tree(self.text)
        if header.startswith("no "):
            state.pop(header[3:], None)
        else:
            block = state.setdefault(header, {"": []})
            for command in commands[1:]:
                if command.startswith("address-family"):
                    family = command
                    block.setdefault(family, [])
                elif command == frr_routing.EXIT_AF:
                    family = ""
                elif command.startswith("no neighbor ") and command.split()[3] == "remote-as":
                    address = command.split()[2]
                    for leaves in block.values():
                        leaves[:] = [leaf for leaf in leaves if not leaf.startswith(f"neighbor {address} ")]
                elif command.startswith("no "):
                    if command[3:] not in block[family]:
                        return 1
                    block[family].remove(command[3:])
                elif command not in block[family]:
                    block[family].append(command)
        out = []
        for name, block in state.items():
            out.append(name)
            out += [f" {leaf}" for leaf in block[""]]
            for fam, leaves in block.items():
                if fam and leaves:
                    out += [f" {fam}", *(f"  {leaf}" for leaf in leaves), f" {frr_routing.EXIT_AF}"]
            out.append("exit")
        self.text = "\n".join(out) + "\n" if out else ""
        return 0


class FrrRoutingExecutorTests(SimpleTestCase):
    def test_ospf_inverse_preserves_unrelated_routing(self):
        text = "router bgp 65001\n neighbor 192.0.2.2 remote-as 65002\nexit\n"
        device = FakeFrr(text)
        executor = device.executor()
        ospf = spec("ospf", "routing_ospf", ("router ospf", "   ospf router-id 198.18.44.1"))
        preflight = executor.assess(ospf)
        self.assertEqual((preflight.action, preflight.restorable), (APPLY, True))
        self.assertTrue(executor.apply(ospf, preflight).ok)
        self.assertIn("router ospf", device.text)
        self.assertEqual(executor.compensate(ospf, preflight).status, "COMPENSATED")
        self.assertEqual(device.text, text)
        self.assertIn(["no router ospf"], device.sent)

    def test_replacement_and_unbounded_commands_fail_closed(self):
        device = FakeFrr("router ospf\n ospf router-id 198.18.44.9\n")
        ospf = spec("ospf", "routing_ospf", ("router ospf", "   ospf router-id 198.18.44.1"))
        self.assertFalse(device.executor().assess(ospf).restorable)
        for lines in (("router ospf", "   shell rm /tmp/file"), ("router bgp 65044", "   neighbor 192.0.2.2 route-map X in"),
                      ("router rip", "   version 1"), ("router bgp 65044; reboot",), ("router ripng", "   version 2"),
                      ("router rip", "   address-family ipv4 unicast"), ("router bgp 65044", "      network 192.0.2.0/24"),
                      ("router bgp 65044", "   bgp ebgp-requires-policy")):
            self.assertIsNone(frr_routing_blocks(lines), lines)

    def test_bgp_commands_keep_address_family_context(self):
        rendered = (*PROCESS, NEIGHBOR[1], "!", *ACTIVATE[1:3], NETWORK[2], ACTIVATE[3], "!")
        self.assertEqual(frr_routing_blocks(rendered), [[
            BGP, "bgp router-id 198.18.44.1", "no bgp default ipv4-unicast", "no bgp ebgp-requires-policy",
            "neighbor 2001:db8:44::2 remote-as 65045", "address-family ipv6 unicast", "neighbor 2001:db8:44::2 activate",
            "network 2001:db8:113::/64", "exit-address-family"]])
        # a differential that lost its closing bracket is still closed before the next context
        self.assertEqual(frr_routing_blocks(NETWORK[:3])[0][-1], "exit-address-family")

    def test_new_bgp_process_is_removed_as_a_whole_and_other_asn_is_refused(self):
        self.assertEqual(frr_routing_inverse((*PROCESS, NEIGHBOR[1], *ACTIVATE[1:]), "router ospf\n ospf router-id 1.1.1.1\n"),
                         [f"no {BGP}"])
        refused = FakeFrr("router bgp 65001\n bgp router-id 1.1.1.1\nexit\n").executor().assess(spec("p", "routing_bgp", PROCESS))
        self.assertEqual((refused.action, refused.reason), (REFUSE, "BGP_PROCESS_CONFLICT"))

    def test_missing_daemon_is_refused_before_any_write(self):
        device = FakeFrr(daemons={"zebra", "ospfd"})
        for kind, lines in (("routing_bgp", PROCESS), ("routing_rip", ("router rip", "   version 2", "   network eth1")),
                            ("routing_rip", ("router ripng", "   network eth1"))):
            found = device.executor().assess(spec("x", kind, lines))
            self.assertEqual((found.action, found.reason), (REFUSE, "ROUTING_DAEMON_UNAVAILABLE"))
        self.assertEqual(device.sent, [])

    def test_existing_bgp_process_gets_additive_inverse_only(self):
        running = EXISTING
        self.assertEqual(frr_routing_inverse(PROCESS, running), [])                    # already satisfied
        self.assertEqual(frr_routing_inverse((*NEIGHBOR, *ACTIVATE[1:], *NETWORK[1:]), running), [
            BGP, "   address-family ipv6 unicast", "      no network 2001:db8:113::/64", "   exit-address-family",
            "   no neighbor 2001:db8:44::2 remote-as 65045"])                            # activation leaves go with the neighbor
        self.assertEqual(frr_routing_inverse((BGP, "   address-family ipv4 unicast", "      neighbor 198.18.9.9 activate",
                                              "   exit-address-family"), running),
                         [BGP, "   address-family ipv4 unicast", "      no neighbor 198.18.9.9 activate", "   exit-address-family"])
        for unsafe in ((BGP, "   bgp router-id 198.18.44.9"),                          # replaces the router-id
                       (BGP, "   neighbor 198.18.9.9 remote-as 65001"),                # changes an existing neighbor's AS
                       (BGP, "   no neighbor 198.18.9.9 remote-as 65099"),             # a removal is not an additive Configlet
                       ACTIVATE):                                                      # neighbor absent: nothing to attach to
            self.assertIsNone(frr_routing_inverse(unsafe, running), unsafe)
        # process-wide settings would change every existing neighbor: never added to a process NMAS did not create
        legacy = f"{BGP}\n bgp router-id 198.18.44.1\n neighbor 198.18.9.9 remote-as 65099\nexit\n"
        self.assertIsNone(frr_routing_inverse(PROCESS, legacy))
        # FRR default: an existing neighbor is already active for IPv4 unicast, so there is nothing to undo
        self.assertEqual(frr_routing_inverse((BGP, "   address-family ipv4 unicast", "      neighbor 198.18.9.9 activate",
                                              "   exit-address-family"), legacy), [])

    def test_plan_order_preflight_then_apply_then_reverse_compensation(self):
        """The engine preflights every Configlet before the first apply; each inverse is re-derived right before its apply."""
        device = FakeFrr(EXISTING)
        executor = device.executor()
        specs = [spec("p", "routing_bgp", PROCESS), spec("n", "bgp_neighbor", NEIGHBOR),
                 spec("a", "bgp_neighbor_af", ACTIVATE), spec("w", "bgp_network", NETWORK)]
        preflights = [executor.assess(s) for s in specs]
        self.assertEqual([(p.action, p.restorable) for p in preflights],
                         [("SKIP_SATISFIED", True), (APPLY, True), (APPLY, True), (APPLY, True)])
        for s, p in list(zip(specs, preflights))[1:]:
            self.assertTrue(executor.apply(s, p).ok)
        self.assertIn("  neighbor 2001:db8:44::2 activate", device.text)
        self.assertEqual([executor.compensate(s, p).status for s, p in reversed(list(zip(specs, preflights))[1:])],
                         ["COMPENSATED"] * 3)
        self.assertEqual(frr_routing.tree(device.text), frr_routing.tree(EXISTING))     # unrelated neighbor and network intact
        self.assertEqual(device.sent[-3:], [
            [BGP, "address-family ipv6 unicast", "no network 2001:db8:113::/64", "exit-address-family"],
            [BGP, "address-family ipv6 unicast", "no neighbor 2001:db8:44::2 activate", "exit-address-family"],
            [BGP, "no neighbor 2001:db8:44::2 remote-as 65045"]])

    def test_apply_refuses_when_the_proven_inverse_no_longer_holds(self):
        device = FakeFrr(EXISTING)
        executor = device.executor()
        activate = spec("a", "bgp_neighbor_af", ACTIVATE)
        preflight = executor.assess(activate)          # provable only if the neighbor Configlet runs first
        self.assertTrue(preflight.restorable)
        outcome = executor.apply(activate, preflight)  # ... it did not
        self.assertEqual((outcome.ok, outcome.error_code, device.sent), (False, "COMMAND_REJECTED", []))

    def test_compensation_reports_unrestored_state(self):
        device = FakeFrr()
        executor = device.executor()
        rip = spec("r", "routing_rip", ("router rip", "   version 2", "   network eth3"))
        preflight = executor.assess(rip)
        self.assertTrue(executor.apply(rip, preflight).ok)
        device.text += "router ripng\n network eth9\nexit\n"     # someone else changed the device meanwhile
        self.assertEqual((executor.compensate(rip, preflight).status, executor.compensate(rip, preflight).error_code),
                         ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))

    def test_rip_and_ripng_new_and_existing_process(self):
        for process, lines in (("router rip", ("router rip", "   version 2", "   network eth3")),
                               ("router ripng", ("router ripng", "   network eth3"))):
            self.assertEqual(frr_routing_inverse(lines, ""), [f"no {process}"])
            existing = f"{process}\n network eth2\n passive-interface eth2\n" + (" version 2\n" if process == "router rip" else "") + "exit\n"
            self.assertEqual(frr_routing_inverse(lines, existing), [process, "   no network eth3"])
            device = FakeFrr(existing)
            executor = device.executor()
            rip = spec("r", "routing_rip", lines)
            preflight = executor.assess(rip)
            self.assertTrue(executor.apply(rip, preflight).ok)
            self.assertEqual(executor.compensate(rip, preflight).status, "COMPENSATED")
            self.assertEqual(frr_routing.tree(device.text), frr_routing.tree(existing))


class FrrRoutingSemanticsTests(SimpleTestCase):
    def test_parser_models_frr_default_ipv4_activation(self):
        def neighbors(text):
            instance = next(i for i in parser_frr.parse(text).routing_instances if i.family == "bgp")
            return {n["peer_address"]: (n["activate_ipv4"], n["activate_ipv6"]) for n in instance.neighbors}

        explicit = ("router bgp 65044\n no bgp default ipv4-unicast\n neighbor 198.18.0.2 remote-as 65045\n"
                    " neighbor 2001:db8:44::2 remote-as 65045\n !\n address-family ipv4 unicast\n  neighbor 198.18.0.2 activate\n"
                    " exit-address-family\n !\n address-family ipv6 unicast\n  neighbor 2001:db8:44::2 activate\n"
                    "  neighbor 198.18.0.2 activate\n exit-address-family\nexit\n")
        self.assertEqual(neighbors(explicit), {"198.18.0.2": (True, True), "2001:db8:44::2": (False, True)})
        default = ("router bgp 65044\n neighbor 198.18.0.2 remote-as 65045\n neighbor 198.18.0.6 remote-as 65045\n !\n"
                   " address-family ipv4 unicast\n  no neighbor 198.18.0.6 activate\n exit-address-family\nexit\n")
        self.assertEqual(neighbors(default), {"198.18.0.2": (True, False), "198.18.0.6": (False, False)})

    def test_rip_table_and_bgp_prefix_counters(self):
        rip = ("Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP\n"
               "     Network            Next Hop         Metric From            Tag Time\n"
               "C(i) 198.18.0.0/30      0.0.0.0               1 self              0\n"
               "R(n) 198.51.100.0/24    198.18.0.2            2 198.18.0.2        0 02:26\n")
        ripng = ("   Network      Next Hop                      Via     Metric Tag Time\nC(i) 2001:db8:44::/64 \n"
                 "                  ::                          self       1    0  \nR(n) 2001:db8:114::/64 \n"
                 "                  fe80::a8c1:abff:fe29:e3c6   eth3       2    0  02:26\n")
        self.assertEqual(live.parse_frr_rip(rip, ""), [
            {"family": "IPV4", "prefix": "198.18.0.0/30", "learned": False},
            {"family": "IPV4", "prefix": "198.51.100.0/24", "learned": True}])   # ripngd not running: no IPv6 rows
        self.assertIn({"family": "IPV6", "prefix": "2001:db8:114::/64", "learned": True}, live.parse_frr_rip("", ripng))
        summary = ('{"ipv4Unicast":{"peers":{"2001:db8:44::2":{"remoteAs":65045,"state":"Established","pfxRcd":0,"pfxSnt":0}}},'
                   '"ipv6Unicast":{"peers":{"2001:db8:44::2":{"remoteAs":65045,"state":"Established","pfxRcd":1,"pfxSnt":2}}}}')
        (peer,) = live.parse_frr_bgp(summary)
        self.assertEqual((peer["state"], peer["prefixes"]["IPV6"], peer["prefixes"]["IPV4"]),
                         ("ESTABLISHED", {"received": 1, "sent": 2}, {"received": 0, "sent": 0}))


class FrrNatExecutorTests(SimpleTestCase):
    """NAT44 masquerade: one dedicated nftables table, created atomically and deleted as a whole."""

    TABLE = ('# Stateful NAT44/PAT (nftables; candidate only)', 'table ip DEVICE_BUILDER_PAT {', '    chain postrouting {',
             '        type nat hook postrouting priority srcnat; policy accept;',
             '        oifname "eth2" ip saddr 198.18.0.0/30 masquerade', '    }', '}')
    DOCKER = ('table ip nat {\n\tchain DOCKER_OUTPUT {\n\t\tip daddr 127.0.0.11 udp dport 53 counter packets %d bytes 603 xt target "DNAT"\n\t}\n}\n')

    def device(self, ruleset):
        from core.services.execution.executors import linux
        box = {"ruleset": ruleset, "sent": []}

        def run(_container, argv, _timeout):
            box["sent"].append(argv)
            if argv[:4] == ["nft", "delete", "table", "ip"]:
                box["ruleset"] = box["ruleset"].split("table ip DEVICE_BUILDER_PAT")[0]
            else:
                box["ruleset"] += argv[1] + "\n"
            return 0

        executor = linux.LinuxExecutor({"name": "frr", "container": "disposable"}, runner=run,
                                       reader=lambda _d: DeviceEvidence("frr", "linux", live_attempted=True),
                                       nft_reader=lambda _c, _t: box["ruleset"])
        return executor, box

    def test_table_is_created_atomically_and_deleted_with_unrelated_rules_intact(self):
        executor, box = self.device(self.DOCKER % 8)
        nat = spec("nat", "nat_rule", self.TABLE)
        preflight = executor.assess(nat)
        self.assertEqual((preflight.action, preflight.restorable), (APPLY, True))
        self.assertTrue(executor.apply(nat, preflight).ok)
        (argv,) = box["sent"]
        self.assertEqual(argv[0], "nft")
        self.assertEqual(len(argv), 2, "the whole table is one nft transaction")
        self.assertIn('oifname "eth2" ip saddr 198.18.0.0/30 masquerade', argv[1])
        self.assertEqual(executor.assess(nat).action, "SKIP_SATISFIED")
        box["ruleset"] = box["ruleset"].replace("packets 8", "packets 31")       # unrelated counters keep moving
        self.assertEqual(executor.compensate(nat, preflight).status, "COMPENSATED")
        self.assertEqual(box["sent"][-1], ["nft", "delete", "table", "ip", "DEVICE_BUILDER_PAT"])
        self.assertEqual(box["ruleset"], self.DOCKER % 31)

    def test_merge_into_existing_table_and_foreign_shapes_fail_closed(self):
        from core.services.execution.executors import linux
        existing = 'table ip DEVICE_BUILDER_PAT {\n chain postrouting {\n  oifname "eth9" ip saddr 10.0.0.0/8 masquerade\n }\n}\n'
        executor, box = self.device(existing)
        found = executor.assess(spec("nat", "nat_rule", self.TABLE))
        self.assertEqual((found.action, found.restorable, found.reason), (APPLY, False, "COMPENSATION_NOT_PROVABLE"))
        self.assertFalse(executor.apply(spec("nat", "nat_rule", self.TABLE), found).ok)
        self.assertEqual(box["sent"], [])
        for bad in (("table inet DEVICE_BUILDER_PAT {", *self.TABLE[2:]), (*self.TABLE[:4], '        oifname "eth2" ip saddr 198.18.0.1/30 masquerade', "    }", "}"),
                    (*self.TABLE[:4], '        oifname "eth2; flush ruleset" ip saddr 198.18.0.0/30 masquerade', "    }", "}"),
                    (*self.TABLE[:4], "        ip saddr 198.18.0.0/30 drop", "    }", "}"), self.TABLE[:5]):
            self.assertIsNone(linux.parse_nat_table(bad), bad)
        self.assertEqual(executor.assess(spec("nat", "nat_rule", ("flush ruleset",))).action, REFUSE)


class FrrNatStatefulDistinctionTests(SimpleTestCase):
    """PAT and stateful NAT44 are the same conntrack masquerade on nftables; an NMAS-owned rule comment carries the mode."""

    def rendered(self, mode):
        from core.services import platform_drivers
        rule = {"id": "nat_1", "sequence": 1, "family": "NAT44", "mode": mode, "original_source": "198.18.0.0/30",
                "outside_interface_id": "if_2"}
        rows = platform_drivers._render_nat("ubuntu_frr", "Ubuntu/FRR", {"pools": {}, "rules": {"nat_1": rule}},
                                            {"if_2": {"name": "eth2"}}, ubuntu=True)
        return [row["text"] for row in rows if row.get("text")]

    def test_renderer_parser_and_executor_agree_on_the_mode(self):
        from core.services import platform_drivers
        from core.services.execution.executors import linux
        self.assertEqual(platform_drivers.NAT_STATEFUL_COMMENT, parser_frr.NAT_STATEFUL_COMMENT)
        for mode, tail in (("PAT", "masquerade"), ("STATEFUL", 'masquerade comment "nmas-nat44-stateful"')):
            lines = self.rendered(mode)
            self.assertTrue(lines[-3].endswith(tail), lines)
            (parsed,) = parser_frr.parse("", nft_text="\n".join(lines)).nat_rules
            self.assertEqual((parsed.mode, parsed.outside_interface, parsed.original_source), (mode, "eth2", "198.18.0.0/30"))
            nat = linux.parse_nat_table(lines)
            self.assertIn(tail, linux.nat_statement(nat))
            # ``nft list ruleset`` prints the rule back exactly as rendered, comment included
            listed = "table ip DEVICE_BUILDER_PAT {\n\tchain postrouting {\n\t\t" + lines[-3].strip() + "\n\t}\n}\n"
            self.assertEqual(parser_frr.parse("", nft_text=listed).nat_rules[0].mode, mode)

    def test_foreign_comments_are_neither_imported_nor_executed(self):
        from core.services.execution.executors import linux
        lines = self.rendered("STATEFUL")
        foreign = [line.replace("nmas-nat44-stateful", "someone else") for line in lines]
        self.assertEqual(parser_frr.parse("", nft_text="\n".join(foreign)).nat_rules, [])
        self.assertIsNone(linux.parse_nat_table(foreign))
        # a PAT table already on the device does not satisfy a stateful Configlet (and merging is refused)
        box_rules = "\n".join(self.rendered("PAT")) + "\n"
        executor = linux.LinuxExecutor({"name": "frr", "container": "x"}, runner=lambda *_a: 0,
                                       reader=lambda _d: DeviceEvidence("frr", "linux", live_attempted=True),
                                       nft_reader=lambda _c, _t: box_rules)
        found = executor.assess(spec("nat", "nat_rule", lines))
        self.assertEqual((found.action, found.restorable), (APPLY, False))


class FrrExistingInterfaceTests(SimpleTestCase):
    """An interface that already exists: only requested fields change, and the captured state is restored exactly."""

    def device(self, mtu=9500, extra=()):
        from core.services.execution.executors import linux
        rows = [{"ifname": "eth1", "mtu": mtu, "flags": ["BROADCAST", "UP", "LOWER_UP"],
                 "addr_info": [{"family": "inet6", "local": "fe80::1", "prefixlen": 64}]}, *extra]
        sent = []

        def run(_container, argv, _timeout):
            sent.append(argv)
            if argv[:5] == ["ip", "link", "set", "dev", "eth1"] and argv[5] == "mtu":
                rows[0]["mtu"] = int(argv[6])
            return 0

        evidence = DeviceEvidence("frr", "linux", live_attempted=True)
        executor = linux.LinuxExecutor({"name": "frr", "container": "x"}, runner=run, reader=lambda _d: evidence,
                                       link_reader=lambda _c, _t: [dict(r) for r in rows])
        return executor, rows, sent

    @staticmethod
    def interface(*lines):
        return ConfigletSpec("if", 1, "frr", "ubuntu_frr", "interface", "CREATE_DEFINE", tuple(lines),
                             {"interface": "eth1", "admin_enabled": True})

    def test_omitted_mtu_never_overwrites_the_existing_mtu(self):
        executor, rows, sent = self.device()
        found = executor.assess(self.interface("ip link set dev eth1 up"))      # the renderer omits the MTU line
        self.assertEqual((found.action, found.restorable, found.previous_state["mtu"]), ("SKIP_SATISFIED", True, 9500))
        self.assertEqual((rows[0]["mtu"], sent), (9500, []))

    def test_explicit_mtu_change_is_reversible_and_restores_9500_exactly(self):
        executor, rows, sent = self.device()
        spec_ = self.interface("ip link set dev eth1 mtu 1500", "ip link set dev eth1 up")
        preflight = executor.assess(spec_)
        self.assertEqual((preflight.action, preflight.restorable, preflight.previous_state["changes"]), (APPLY, True, {"mtu": 1500}))
        self.assertTrue(executor.apply(spec_, preflight).ok)
        self.assertEqual((rows[0]["mtu"], sent), (1500, [["ip", "link", "set", "dev", "eth1", "mtu", "1500"]]),
                         "only the differing field is sent; the admin state already matched")
        self.assertEqual(executor.compensate(spec_, preflight).status, "COMPENSATED")
        self.assertEqual((rows[0]["mtu"], sent[-1]), (9500, ["ip", "link", "set", "dev", "eth1", "mtu", "9500"]))
        self.assertEqual(executor.compensate(spec_, preflight).detail, {"action": "NONE_NEEDED"})

    def test_changes_with_side_effects_fail_closed(self):
        child = {"ifname": "eth1.44", "link": "eth1", "mtu": 9000, "flags": ["UP"], "addr_info": []}
        for label, kwargs, lines in (
                ("admin down drops routes and IPv6 addresses", {}, ("ip link set dev eth1 down",)),
                ("child would be clamped", {"extra": (child,)}, ("ip link set dev eth1 mtu 1500",)),
                ("IPv6 needs 1280", {}, ("ip link set dev eth1 mtu 1000",))):
            executor, rows, sent = self.device(**kwargs)
            found = executor.assess(self.interface(*lines))
            self.assertEqual((found.action, found.restorable, found.reason), (APPLY, False, "COMPENSATION_NOT_PROVABLE"), label)

    def test_restoration_is_verified_against_the_whole_captured_link(self):
        executor, rows, sent = self.device()
        spec_ = self.interface("ip link set dev eth1 mtu 1500")
        preflight = executor.assess(spec_)
        executor.apply(spec_, preflight)
        rows[0]["addr_info"].append({"family": "inet", "local": "192.0.2.9", "prefixlen": 24})   # changed by someone else
        self.assertEqual((executor.compensate(spec_, preflight).status, executor.compensate(spec_, preflight).error_code),
                         ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))


class FrrManagementImportTests(SimpleTestCase):
    ADDR = ('[{"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536,"addr_info":[{"local":"127.0.0.1","prefixlen":8}]},'
            '{"ifname":"eth0","flags":["UP"],"mtu":1500,"addr_info":[{"local":"172.31.248.12","prefixlen":24},'
            '{"local":"fd00:ca:248::2","prefixlen":64}]},'
            '{"ifname":"eth1","flags":["UP"],"mtu":9500,"addr_info":[{"local":"198.18.0.1","prefixlen":30}]},'
            '{"ifname":"Vlan200","flags":["UP"],"mtu":1500,"addr_info":[{"local":"192.168.200.3","prefixlen":24}]}]')

    def kinds(self, *management):
        return {i.name: i for i in parser_frr.parse("", addr_json=self.ADDR, management_addresses=management).interfaces}

    def test_the_port_the_device_is_managed_through_is_management(self):
        found = self.kinds("172.31.248.12", "fd00:ca:248::2")
        eth0 = found["eth0"]
        self.assertEqual((eth0.kind, eth0.mtu, eth0.admin_state), ("MANAGEMENT", 1500, "ENABLED"))
        self.assertEqual([a["cidr"] for a in eth0.addresses], ["172.31.248.12/24", "fd00:ca:248::2/64"])
        self.assertEqual((found["eth1"].kind, found["lo"].kind), ("ROUTED_PHYSICAL", "LOOPBACK"))

    def test_in_band_vlan200_management_and_unknown_addresses_change_nothing(self):
        self.assertEqual(self.kinds("192.168.200.3")["Vlan200"].kind, "SVI")       # production model: stays an SVI
        self.assertEqual({i.kind for i in self.kinds().values()}, {"LOOPBACK", "ROUTED_PHYSICAL", "SVI"})
        self.assertEqual(self.kinds("auto", "", None, "203.0.113.9")["eth0"].kind, "ROUTED_PHYSICAL")


class FrrNatMergeTests(SimpleTestCase):
    """A second NMAS rule joins the exact NMAS table and leaves it exactly as captured on compensation."""

    LISTED = ('table ip nat {\n\tchain DOCKER_OUTPUT {\n\t\tcounter packets 8 bytes 603 xt target "DNAT"\n\t}\n}\n'
              'table ip DEVICE_BUILDER_PAT {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n'
              '\t\toifname "eth2" ip saddr 198.18.9.0/24 masquerade\n\t}\n}\n')
    NEW = ('table ip DEVICE_BUILDER_PAT {', '    chain postrouting {', '        type nat hook postrouting priority srcnat; policy accept;',
           '        oifname "eth2" ip saddr 198.18.0.0/30 masquerade comment "nmas-nat44-stateful"', '    }', '}')

    def device(self, ruleset):
        from core.services.execution.executors import linux
        box = {"ruleset": ruleset, "sent": []}

        def run(_container, argv, _timeout):
            box["sent"].append(argv)
            head, tail = box["ruleset"].rsplit("\t}\n}\n", 1)
            if argv[1:3] == ["add", "rule"]:
                box["ruleset"] = head + "\t\t" + " ".join(argv[6:]) + "\n\t}\n}\n" + tail
            elif argv[1].startswith("flush chain"):
                kept = head.split("policy accept;\n")[0] + "policy accept;\n"
                rules = [line.split("postrouting ", 1)[1] for line in argv[1].splitlines()[1:]]
                box["ruleset"] = kept + "".join(f"\t\t{rule}\n" for rule in rules) + "\t}\n}\n" + tail
            return 0

        executor = linux.LinuxExecutor({"name": "frr", "container": "x"}, runner=run,
                                       reader=lambda _d: DeviceEvidence("frr", "linux", live_attempted=True),
                                       nft_reader=lambda _c, _t: box["ruleset"])
        return executor, box

    def test_append_then_restore_the_captured_rule_list(self):
        executor, box = self.device(self.LISTED)
        nat = spec("nat", "nat_rule", self.NEW)
        preflight = executor.assess(nat)
        self.assertEqual((preflight.action, preflight.restorable, preflight.previous_state["existing_rules"]), (APPLY, True, 1))
        self.assertTrue(executor.apply(nat, preflight).ok)
        self.assertEqual(box["sent"], [["nft", "add", "rule", "ip", "DEVICE_BUILDER_PAT", "postrouting", "oifname", '"eth2"', "ip", "saddr",
                                        "198.18.0.0/30", "masquerade", "comment", '"nmas-nat44-stateful"']])
        self.assertEqual(executor.assess(nat).action, "SKIP_SATISFIED")
        self.assertEqual(executor.compensate(nat, preflight).status, "COMPENSATED")
        self.assertEqual(box["sent"][-1], ["nft", "flush chain ip DEVICE_BUILDER_PAT postrouting\n"
                                           'add rule ip DEVICE_BUILDER_PAT postrouting oifname "eth2" ip saddr 198.18.9.0/24 masquerade\n'])
        self.assertEqual(box["ruleset"], self.LISTED)

    def test_two_rules_of_one_plan_create_then_append_and_compensate_in_reverse(self):
        docker = self.LISTED.split("table ip DEVICE_BUILDER_PAT")[0]
        from core.services.execution.executors import linux
        box = {"ruleset": docker, "sent": []}

        def run(_container, argv, _timeout):
            box["sent"].append(argv)
            if argv[1:3] == ["delete", "table"]:
                box["ruleset"] = docker
            elif argv[1:3] == ["add", "rule"]:
                box["ruleset"] = box["ruleset"].replace("\t}\n}\n" + "", "", 0) [:-len("\t}\n}\n")] + "\t\t" + " ".join(argv[6:]) + "\n\t}\n}\n"
            elif argv[1].startswith("flush chain"):
                rules = [line.split("postrouting ", 1)[1] for line in argv[1].splitlines()[1:]]
                box["ruleset"] = box["ruleset"].split("policy accept;\n")[0] + "policy accept;\n" + "".join(f"\t\t{r}\n" for r in rules) + "\t}\n}\n"
            else:
                box["ruleset"] += "table ip DEVICE_BUILDER_PAT {\n\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n" \
                    + "".join(f"\t\t{line.strip()}\n" for line in argv[1].splitlines() if "oifname" in line) + "\t}\n}\n"
            return 0

        executor = linux.LinuxExecutor({"name": "frr", "container": "x"}, runner=run,
                                       reader=lambda _d: DeviceEvidence("frr", "linux", live_attempted=True),
                                       nft_reader=lambda _c, _t: box["ruleset"])
        first = spec("n1", "nat_rule", (*self.NEW[:3], '        oifname "eth2" ip saddr 198.18.9.0/24 masquerade', *self.NEW[4:]))
        second = spec("n2", "nat_rule", self.NEW)
        preflights = [executor.assess(first), executor.assess(second)]        # both see no table yet
        self.assertTrue(all(p.action == APPLY and p.restorable for p in preflights))
        self.assertTrue(executor.apply(first, preflights[0]).ok and executor.apply(second, preflights[1]).ok)
        self.assertEqual([argv[1] if len(argv) == 2 else argv[1:3] for argv in box["sent"]][1], ["add", "rule"])
        self.assertEqual(executor.compensate(second, preflights[1]).status, "COMPENSATED")
        self.assertIn("198.18.9.0/24", box["ruleset"])
        self.assertNotIn("198.18.0.0/30", box["ruleset"])
        self.assertEqual(executor.compensate(first, preflights[0]).status, "COMPENSATED")
        self.assertEqual(box["ruleset"], docker)

    def test_foreign_table_content_is_never_merged_into(self):
        foreign = self.LISTED.replace('oifname "eth2" ip saddr 198.18.9.0/24 masquerade', "ip saddr 10.0.0.0/8 counter packets 1 bytes 2 drop")
        executor, box = self.device(foreign)
        found = executor.assess(spec("nat", "nat_rule", self.NEW))
        self.assertEqual((found.action, found.restorable, found.reason), (APPLY, False, "COMPENSATION_NOT_PROVABLE"))
        self.assertEqual(box["sent"], [])
