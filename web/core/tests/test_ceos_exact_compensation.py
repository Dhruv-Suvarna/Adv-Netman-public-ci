"""cEOS compensation is proven by the EXACT configured state, never by the read groups alone.

Found live (Phases 7-9): a cEOS port without a backing veth is absent from interface telemetry, yet EOS keeps its configuration.
A failed Complete run that had configured such a port was compensated as ``NONE_NEEDED`` -- the read groups showed the port
"absent", exactly as before -- while ``interface EthernetN`` (and an address under it) stayed in the running configuration.
The executor now captures the configured-state digest right before each restorable modelled apply and accepts a compensation
only when the read groups AND that digest hold again.

The session below is a small EOS model: a running configuration that the sent commands really change, and an interface
telemetry that -- like cEOS -- reports only ports with a backing link.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from core.services.execution.executors import ceos
from core.services.execution.executors.base import APPLY, ConfigletSpec
from core.tests.helpers import health as h

BACKED = ("Ethernet1",)                     # ports with a veth: the only ones interface telemetry reports
BASE = ["hostname R1", "interface Ethernet1", "   no switchport", "   ip address 10.0.0.1/31"]


class EosSession:
    """Running configuration + configuration-mode semantics for ``interface``, ``description``, ``ip address`` and their ``no``."""

    def __init__(self, *, keep_on_delete=(), fail_show_after=None, fail_send_at=None):
        self.blocks = {"interface Ethernet1": ["   no switchport", "   ip address 10.0.0.1/31"]}
        self.sent, self.modes, self.shows = [], [], 0
        self.keep_on_delete, self.fail_show_after, self.fail_send_at = set(keep_on_delete), fail_show_after, fail_send_at
        self._config = False

    # exec
    def text(self) -> str:
        lines = ["hostname R1"]
        for header in sorted(self.blocks):
            lines += [header, *self.blocks[header]]
        return "\n".join(lines) + "\n"

    def send_command(self, command, **_):
        self.shows += 1
        if self.fail_show_after is not None and self.shows > self.fail_show_after:
            raise TimeoutError("lost response")
        assert command == "show running-config", command
        return self.text()

    # configuration mode
    def config_mode(self, **_):
        self._config = True
        self.modes.append("config")

    def check_config_mode(self):
        return self._config

    def exit_config_mode(self):
        self._config = False
        self.modes.append("exit")

    def send_config_set(self, commands, **_):
        self.sent.append(list(commands))
        current = None
        for index, command in enumerate(commands):
            if self.fail_send_at is not None and len(self.sent) == self.fail_send_at[0] and index == self.fail_send_at[1]:
                raise TimeoutError("no CLI response")      # the earlier commands of this set were applied
            stripped = command.strip()
            if stripped == "exit":
                current = None
            elif stripped.startswith("no interface "):
                header = stripped[3:]
                if header not in self.keep_on_delete:        # EOS keeps it: the staged state that must never read as restored
                    self.blocks.pop(header, None)
            elif stripped.startswith("interface "):
                current = stripped
                self.blocks.setdefault(current, [])
            elif current and stripped.startswith("no "):
                self.blocks[current] = [line for line in self.blocks[current] if line.strip() != stripped[3:]]
            elif current:
                self.blocks[current].append(f"   {stripped}")
        return ""

    def disconnect(self):
        return None

    # telemetry: like cEOS, only ports with a backing link exist in the read groups
    def evidence(self):
        interfaces = {name: {"admin": "UP", "oper": "UP"} for name in BACKED}
        addresses = {name: [line.split()[2] for line in self.blocks.get(f"interface {name}", []) if "ip address" in line]
                     for name in BACKED}
        return h.device_evidence("R1", interfaces=interfaces, addresses=addresses, routes=[], live_ok=True)


def spec(cfg_id, object_type, lines, **expected):
    return ConfigletSpec(cfg_id, int(cfg_id[-1]), "R1", "arista_ceos", object_type, "CREATE_DEFINE", tuple(lines), expected)


INTERFACE = spec("CFG-1", "interface", ["interface Ethernet9", "   description unbacked port"], interface="Ethernet9")
ADDRESS = spec("CFG-2", "address", ["interface Ethernet9", "   ip address 192.0.2.9/31"], interface="Ethernet9", address="192.0.2.9/31")


class ExactCompensationTests(SimpleTestCase):
    def executor(self, session):
        executor = ceos.CeosExecutor({"name": "R1"}, connection_factory=lambda device: session, reader=lambda device: session.evidence())
        executor.connect()
        return executor

    def applied(self, session, *specs):
        """Assess every Configlet first (as the engine does), then apply in order.  -> (executor, assessments)"""
        executor = self.executor(session)
        assessments = [executor.assess(s) for s in specs]
        self.assertEqual([(a.action, a.restorable) for a in assessments], [(APPLY, True)] * len(specs))
        for s, assessment in zip(specs, assessments):
            self.assertTrue(executor.apply(s, assessment).ok)
        return executor, assessments

    def compensate_all(self, executor, specs, assessments):
        return [executor.compensate(s, a) for s, a in reversed(list(zip(specs, assessments)))]

    # positive -----------------------------------------------------------------------------------------------------------------
    def test_unbacked_port_configuration_is_compensated_to_the_exact_prior_state(self):
        session = EosSession()
        before = session.text()
        executor, assessments = self.applied(session, INTERFACE, ADDRESS)
        self.assertIn("interface Ethernet9", session.text())
        outcomes = self.compensate_all(executor, [INTERFACE, ADDRESS], assessments)
        self.assertEqual([(o.status, o.detail.get("action")) for o in outcomes],
                         [("COMPENSATED", "INVERSE_APPLIED"), ("COMPENSATED", "INVERSE_APPLIED")])
        self.assertEqual(session.text(), before)
        self.assertEqual(session.sent[-2:], [["interface Ethernet9", "no ip address 192.0.2.9/31", "exit"], ["no interface Ethernet9"]])

    def test_repeated_compensation_sends_nothing_once_the_state_is_exact(self):
        session = EosSession()
        executor, (assessment,) = self.applied(session, INTERFACE)
        self.assertEqual(executor.compensate(INTERFACE, assessment).detail.get("action"), "INVERSE_APPLIED")
        sent = len(session.sent)
        self.assertEqual(executor.compensate(INTERFACE, assessment).detail.get("action"), "NONE_NEEDED")   # a retry
        self.assertEqual(len(session.sent), sent)

    def test_compensation_never_recreates_configuration_it_does_not_find(self):
        """Re-running a whole chain: ADDRESS found the state WITH Ethernet9; the port is already gone, and its inverse
        (``interface Ethernet9`` / ``no ip address``) would re-create it.  Refused, nothing sent."""
        session = EosSession()
        executor, assessments = self.applied(session, INTERFACE, ADDRESS)
        self.compensate_all(executor, [INTERFACE, ADDRESS], assessments)
        before, sent = session.text(), len(session.sent)
        outcome = executor.compensate(ADDRESS, assessments[1])
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))
        self.assertEqual((session.text(), len(session.sent)), (before, sent))

    def test_partially_applied_configlet_is_compensated_exactly(self):
        session = EosSession(fail_send_at=(1, 1))           # the header reached the device, the description did not
        before = session.text()
        executor = self.executor(session)
        assessment = executor.assess(INTERFACE)
        outcome = executor.apply(INTERFACE, assessment)
        self.assertEqual((outcome.ok, outcome.error_code, outcome.partial_effects), (False, "TIMEOUT", True))
        self.assertEqual(session.modes[-1], "exit")          # the failed session did not stay in configuration mode
        self.assertEqual(executor.compensate(INTERFACE, assessment).status, "COMPENSATED")
        self.assertEqual(session.text(), before)

    def test_backed_port_change_is_still_verified_by_its_read_groups(self):
        session = EosSession()
        address = spec("CFG-3", "address", ["interface Ethernet1", "   ip address 10.0.1.1/31 secondary"],
                       interface="Ethernet1", address="10.0.1.1/31")
        before = session.text()
        executor, (assessment,) = self.applied(session, address)
        outcome = executor.compensate(address, assessment)
        self.assertEqual((outcome.status, outcome.detail.get("exact_configuration")), ("COMPENSATED", True))
        self.assertEqual(session.text(), before)

    # negative -----------------------------------------------------------------------------------------------------------------
    def test_staged_configuration_left_on_the_device_never_reports_restored(self):
        session = EosSession(keep_on_delete={"interface Ethernet9"})
        executor, assessments = self.applied(session, INTERFACE)
        (outcome,) = self.compensate_all(executor, [INTERFACE], assessments)
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "STATE_NOT_RESTORED"))
        self.assertFalse(outcome.detail["exact_configuration"])

    def test_without_exact_digest_the_unbacked_port_would_not_be_noticed(self):
        """The read groups alone cannot see the leftover: the old verdict on this very state was ``NONE_NEEDED``."""
        session = EosSession()
        executor, (assessment,) = self.applied(session, INTERFACE)
        from core.services.execution.executors import state

        self.assertTrue(state.restored(INTERFACE, session.evidence(), assessment.previous_state))   # blind to Ethernet9
        self.assertNotEqual(executor.compensate(INTERFACE, assessment).detail.get("action"), "NONE_NEEDED")

    def test_lost_cli_response_during_compensation_fails(self):
        session = EosSession(fail_send_at=(2, 0))
        executor, (assessment,) = self.applied(session, INTERFACE)
        outcome = executor.compensate(INTERFACE, assessment)
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_FAILED", "TIMEOUT"))
        self.assertEqual(session.modes[-1], "exit")

    def test_lost_read_back_after_the_inverse_is_unverified(self):
        session = EosSession()
        executor, (assessment,) = self.applied(session, INTERFACE)
        session.fail_show_after = session.shows + 1           # the pre-compensation read works, the read-back does not
        outcome = executor.compensate(INTERFACE, assessment)
        self.assertEqual((outcome.status, outcome.error_code), ("COMPENSATION_UNVERIFIED", "PREVIOUS_STATE_UNAVAILABLE"))

    def test_unreadable_configuration_blocks_the_apply_before_any_command(self):
        session = EosSession(fail_show_after=0)
        executor = self.executor(session)
        assessment = executor.assess(INTERFACE)
        outcome = executor.apply(INTERFACE, assessment)
        self.assertEqual((outcome.ok, outcome.error_code), (False, "PREVIOUS_STATE_UNAVAILABLE"))
        self.assertEqual(session.sent, [])


class OwnLinesPresentTests(SimpleTestCase):
    """``own_lines_present``: only a line this Configlet added since the configuration it found counts as its own effect."""

    FOUND = "\n".join(BASE) + "\n"

    def test_own_lines_present_finds_a_header_or_child_added_since_apply(self):
        with_port = self.FOUND + "interface Ethernet9\n   description unbacked port\n"
        self.assertTrue(ceos.own_lines_present(list(INTERFACE.lines), with_port, self.FOUND))
        header_only = self.FOUND + "interface Ethernet9\n"                       # a partial apply: the header reached the device
        self.assertTrue(ceos.own_lines_present(list(INTERFACE.lines), header_only, self.FOUND))
        with_address = with_port + "   ip address 192.0.2.9/31\n"
        self.assertTrue(ceos.own_lines_present(list(ADDRESS.lines), with_address, with_port))

    def test_own_lines_not_present_when_only_preexisting_lines_remain(self):
        self.assertFalse(ceos.own_lines_present(list(INTERFACE.lines), self.FOUND, self.FOUND))
        existing = ["interface Ethernet1", "   ip address 10.0.0.1/31"]            # already there before the apply
        self.assertFalse(ceos.own_lines_present(existing, self.FOUND, self.FOUND))
        self.assertFalse(ceos.own_lines_present(list(ADDRESS.lines), self.FOUND, self.FOUND + "interface Ethernet9\n"))
