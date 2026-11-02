"""Health vocabularies, the stable check-code catalogue and the blocking policy.

Vocabularies are deliberately small and never conflated with Phase-13 validation statuses:

    check status       PASS  WARN  FAIL  UNKNOWN  NOT_APPLICABLE
    health aggregate   HEALTHY  DEGRADED  UNHEALTHY  UNKNOWN
    precheck result    PASS  PASS_WITH_WARNINGS  BLOCKED  INCOMPLETE
    postcheck result   PASS  PASS_WITH_WARNINGS  FAIL     INCOMPLETE

UNKNOWN means *evidence unavailable*; FAIL means *evidence demonstrates a failure*.  Nothing turns
UNKNOWN into PASS or FAIL.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

ENGINE_VERSION = "15.0.0"
REPORT_SCHEMA_VERSION = 1


class CheckStatus:
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ALL = (PASS, WARN, FAIL, UNKNOWN, NOT_APPLICABLE)


class Health:
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"
    ALL = (HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN)


class PrecheckResult:
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"
    ALL = (PASS, PASS_WITH_WARNINGS, BLOCKED, INCOMPLETE)


class PostcheckResult:
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"
    ALL = (PASS, PASS_WITH_WARNINGS, FAIL, INCOMPLETE)


class Mode:
    FLEET_QUICK = "FLEET_QUICK"
    DEVICE_DEEP = "DEVICE_DEEP"
    CHANGE_PRECHECK = "CHANGE_PRECHECK"
    CHANGE_POSTCHECK = "CHANGE_POSTCHECK"
    ALL = (FLEET_QUICK, DEVICE_DEEP, CHANGE_PRECHECK, CHANGE_POSTCHECK)


class Phase:
    PRECHECK = "PRECHECK"
    POSTCHECK = "POSTCHECK"
    ALL = (PRECHECK, POSTCHECK)


class Freshness:
    FRESH = "FRESH"        # age <= healthy threshold (or observed live in this run)
    STALE = "STALE"        # healthy < age <= stale threshold
    EXPIRED = "EXPIRED"    # age > stale threshold: too old to support a PASS or FAIL
    UNKNOWN = "UNKNOWN"    # no timestamp
    ALL = (FRESH, STALE, EXPIRED, UNKNOWN)


class Role:
    """Why a device is in a precheck's scope."""

    FLEET = "FLEET"      # fleet-wide view; never blocks
    TARGET = "TARGET"    # a plan Configlet is deployed to it (cross-device dependencies only ever join TARGETs)
    PEER = "PEER"        # validation-derived peer of a target (evidence for postchecks); never blocks
    PLAN = "PLAN"        # a plan-level gate / shared service the whole plan needs
    ALL = (FLEET, TARGET, PEER, PLAN)


class Capability:
    """Read-only *health* capability of a platform (independent of configuration support)."""

    SUPPORTED = "SUPPORTED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class Category:
    TELEMETRY = "TELEMETRY"
    REACHABILITY = "REACHABILITY"
    RESOURCE = "RESOURCE"
    INTERFACE = "INTERFACE"
    ROUTING = "ROUTING"
    SERVICE = "SERVICE"
    MONITORING = "MONITORING"
    PLAN = "PLAN"
    VERIFICATION = "VERIFICATION"
    CONNECTIVITY = "CONNECTIVITY"
    ALL = (TELEMETRY, REACHABILITY, RESOURCE, INTERFACE, ROUTING, SERVICE, MONITORING, PLAN, VERIFICATION, CONNECTIVITY)


@dataclass(frozen=True)
class CodeSpec:
    category: str
    description: str
    remediation: str
    blocking: bool = False        # a FAIL may block a precheck (on a TARGET device or a PLAN-level gate)
    unknown_blocks: bool = False  # an UNKNOWN (evidence unavailable) makes the precheck INCOMPLETE
    core: bool = False            # a liveness check: decides a device's aggregate when nothing else does


def _c(category, description, remediation, *, blocking=False, unknown_blocks=False, core=False) -> CodeSpec:
    return CodeSpec(category, description, remediation, blocking, unknown_blocks, core)


T, R, RES, IF, RT, SV, MON, PL, VER, CONN = (
    Category.TELEMETRY, Category.REACHABILITY, Category.RESOURCE, Category.INTERFACE, Category.ROUTING,
    Category.SERVICE, Category.MONITORING, Category.PLAN, Category.VERIFICATION, Category.CONNECTIVITY,
)

# The catalogue: every code a result may carry.  PASS results use the "EXPECTED"/"FRESH" spelling, failures the
# problem spelling, so a code alone tells an operator what was observed.  ``blocking`` is the DEFAULT policy for a
# TARGET device or PLAN-level gate; a PEER or fleet-wide result is never blocking (see ``results.effective_blocking``).
CODES = MappingProxyType({
    # -- device liveness / telemetry --------------------------------------------------------------------------
    "DEVICE_TELEMETRY_FRESH": _c(T, "Telemetry for the device is recent.", "None.", core=True),
    "DEVICE_TELEMETRY_STALE": _c(T, "Telemetry for the device is older than the freshness threshold.",
                                 "Check the gNMI collector and the device's management path.", blocking=True, core=True),
    "DEVICE_TELEMETRY_UNAVAILABLE": _c(T, "No telemetry evidence exists for the device (or the source is down).",
                                       "Check the topology service, InfluxDB and the collectors.", unknown_blocks=True, core=True),
    "DEVICE_REACHABLE": _c(R, "A read-only live query to the device succeeded.", "None.", core=True),
    "DEVICE_UNREACHABLE": _c(R, "A read-only live query to the device did not complete.",
                             "Verify the management path, credentials and that the device is running.", blocking=True, unknown_blocks=True, core=True),
    "CRITICAL_EVENTS_RECENT": _c(T, "Critical syslog events or SNMP traps were recorded recently.",
                                 "Review the Link Events monitoring page."),
    # -- resources ---------------------------------------------------------------------------------------------
    "CPU_HIGH": _c(RES, "CPU utilisation against the project alert thresholds.", "Investigate load before changing the device.", blocking=True),
    "MEMORY_HIGH": _c(RES, "Memory utilisation against the dashboard thresholds.", "Investigate memory use before changing the device.", blocking=True),
    # -- interfaces / links ------------------------------------------------------------------------------------
    "INTERFACE_EXPECTED_UP": _c(IF, "An interface is administratively and operationally up.", "None."),
    "INTERFACE_OPER_DOWN": _c(IF, "An interface is administratively up but operationally down.", "Check the link and the far end.", blocking=True),
    "INTERFACE_ADMIN_DOWN": _c(IF, "An addressed interface is administratively down.", "Confirm the shutdown is intended."),
    "INTERFACE_EXPECTED_PRESENT": _c(IF, "An expected interface exists on the device.", "None."),
    "INTERFACE_MISSING": _c(IF, "An expected interface does not exist on the device.", "Create the interface or correct the plan.", blocking=True),
    "INTERFACE_STATE_MISMATCH": _c(IF, "An interface's admin state differs from the requirement.", "Compare the plan with the device.", blocking=True),
    "LINK_HEALTH_DEGRADED": _c(IF, "A link adjacent to the device is down or degraded.", "Review the Link State & Traffic monitoring page."),
    # -- addressing / routing ----------------------------------------------------------------------------------
    "ADDRESS_EXPECTED_PRESENT": _c(RT, "An expected address is configured on its interface.", "None."),
    "ADDRESS_MISSING": _c(RT, "An expected address is not configured on its interface.", "Deploy or correct the address.", blocking=True),
    "ROUTE_EXPECTED_PRESENT": _c(RT, "An expected route is in the routing table.", "None."),
    "ROUTE_MISSING": _c(RT, "An expected route is not in the routing table.", "Check the next hop and the exit interface.", blocking=True),
    "OSPF_EXPECTED_FULL": _c(RT, "An OSPF adjacency is FULL.", "None."),
    "OSPF_ADJACENCY_DOWN": _c(RT, "An OSPF adjacency is not FULL.", "Check area, timers, MTU and the far end.", blocking=True),
    "ISIS_ROUTE_PRESENT": _c(RT, "An IS-IS route is installed with the expected paths.", "None."),
    "ISIS_ROUTE_ABSENT": _c(RT, "An IS-IS route that must be absent is absent.", "None."),
    "ISIS_ROUTE_MISSING": _c(RT, "An expected IS-IS route is not installed.", "Check the adjacency and what the far end advertises.", blocking=True),
    "ISIS_ROUTE_PATH_MISMATCH": _c(RT, "An IS-IS route is installed over different paths than expected.", "Check interface metrics and adjacencies.", blocking=True),
    "ISIS_ROUTE_UNEXPECTED": _c(RT, "An IS-IS route that must be absent is installed.", "Check what the originating router advertises.", blocking=True),
    "RIP_ROUTE_PRESENT": _c(RT, "A RIP route is installed with the expected paths.", "None."),
    "RIP_ROUTE_ABSENT": _c(RT, "A RIP route that must be absent is absent.", "None."),
    "RIP_ROUTE_MISSING": _c(RT, "An expected RIP route is not installed.", "Check the RIP peer and what it advertises.", blocking=True),
    "RIP_ROUTE_PATH_MISMATCH": _c(RT, "A RIP route is installed over different paths than expected.", "Check which peer the route was learned from.", blocking=True),
    "RIP_ROUTE_UNEXPECTED": _c(RT, "A RIP route that must be absent is installed.", "Check what the peer advertises.", blocking=True),
    "RIP_NEIGHBOR_PRESENT": _c(RT, "A RIP peer is present on the interface.", "None."),
    "RIP_NEIGHBOR_ABSENT": _c(RT, "No RIP peer exists on an interface where none is intended.", "None."),
    "RIP_NEIGHBOR_MISSING": _c(RT, "An expected RIP peer was not observed.", "Check the network statement and the far end.", blocking=True),
    "RIP_NEIGHBOR_UNEXPECTED": _c(RT, "A RIP peer exists on an interface where none is intended.", "Remove RIP from that interface.", blocking=True),
    "ISIS_EXPECTED_UP": _c(RT, "An IS-IS adjacency is UP.", "None."),
    "ISIS_ADJACENCY_DOWN": _c(RT, "An IS-IS adjacency is not UP.", "Check the NET area, level, address family and the far end.", blocking=True),
    "BGP_EXPECTED_ESTABLISHED": _c(RT, "A BGP session is Established.", "None."),
    "BGP_SESSION_DOWN": _c(RT, "A BGP session is not Established.", "Check reachability, AS numbers and the far end.", blocking=True),
    "ROUTING_CONFIG_PRESENT": _c(RT, "The intended routing configuration is present.", "None."),
    "ROUTING_CONFIG_MISMATCH": _c(RT, "Routing configuration differs from the intended state.", "Compare the process, binding, neighbor or network with the plan.", blocking=True),
    # -- services / policy -------------------------------------------------------------------------------------
    "FHRP_VIP_EXPECTED_PRESENT": _c(SV, "A virtual router address is configured.", "None."),
    "FHRP_VIP_MISSING": _c(SV, "A virtual router address is not configured.", "Deploy or correct the FHRP instance.", blocking=True),
    "DHCP_RELAY_EXPECTED_PRESENT": _c(SV, "A DHCP relay destination is configured on its interface.", "None."),
    "DHCP_RELAY_MISSING": _c(SV, "A DHCP relay destination is not configured on its interface.", "Deploy or correct the relay.", blocking=True),
    "ACL_DEFINITION_EXPECTED_PRESENT": _c(SV, "An ACL is defined on the device.", "None."),
    "ACL_DEFINITION_MISSING": _c(SV, "An ACL is not defined on the device.", "Deploy or correct the ACL.", blocking=True),
    "ACL_ATTACHMENT_EXPECTED_PRESENT": _c(SV, "An ACL is attached to its interface and direction.", "None."),
    "ACL_ATTACHMENT_MISSING": _c(SV, "An ACL is not attached to its interface and direction.", "Deploy or correct the attachment.", blocking=True),
    "PBR_POLICY_EXPECTED_PRESENT": _c(SV, "A PBR policy is defined and every intended sequence is installed.", "None."),
    "PBR_POLICY_MISSING": _c(SV, "A PBR policy is not defined, or an intended sequence is missing or not installed.",
                             "Deploy or correct the PBR policy; check its next hop is reachable.", blocking=True),
    "PBR_ATTACHMENT_EXPECTED_PRESENT": _c(SV, "A PBR policy is applied to its ingress interface.", "None."),
    "PBR_ATTACHMENT_MISSING": _c(SV, "A PBR policy is not applied (or not valid) on its ingress interface.",
                                 "Deploy or correct the attachment.", blocking=True),
    "NAT_RULE_EXPECTED_PRESENT": _c(SV, "A NAT rule is present on the device.", "None."),
    "NAT_RULE_MISSING": _c(SV, "A NAT rule is not present on the device.", "Deploy or correct the NAT rule.", blocking=True),
    # -- Remove Configuration (running-config presence of the statements selected for removal) ------------------------
    "CONFIG_REMOVED_CONFIRMED": _c(VER, "The configuration selected for removal is absent from the running configuration.", "None."),
    "CONFIG_STILL_PRESENT": _c(VER, "Configuration selected for removal is still present after execution.",
                               "Inspect the device; the removal was not applied or was re-added.", blocking=True),
    "MGMT_CONFIG_PRESENT": _c(VER, "Management VRF running configuration matches the plan.", "None."),
    "MGMT_CONFIG_MISSING": _c(VER, "Management VRF running configuration differs from the plan.",
                               "Inspect the device and the approved management path before compensation.", blocking=True),
    "REMOVAL_TARGET_PRESENT": _c(VER, "The configuration selected for removal is present before execution.", "None."),
    "REMOVAL_TARGET_ALREADY_ABSENT": _c(VER, "The configuration selected for removal is already absent before execution.",
                                        "Nothing will be sent for it; refresh the snapshot if this is unexpected."),
    "REMOVAL_TARGET_DRIFTED": _c(VER, "Only part of the configuration selected for removal is present.",
                                 "Refresh the running configuration and rebuild the removal.", blocking=True),
    "DHCP_SERVICE_UNHEALTHY": _c(SV, "The DHCP servers report an inactive service.", "Restore the DHCP service before changing relays.", blocking=True, unknown_blocks=True),
    # -- monitoring / fleet conditions ---------------------------------------------------------------------------
    "MONITORING_PIPELINE_UNHEALTHY": _c(MON, "The monitoring backend or telemetry collection is unhealthy.",
                                        "Restore InfluxDB / the topology service / the collectors.", blocking=True, unknown_blocks=True),
    "TOPOLOGY_SERVICE_UNAVAILABLE": _c(MON, "The topology service cannot be read.", "Start the topology service."),
    "NETBOX_SOURCE_UNAVAILABLE": _c(MON, "NetBox (a read-only source) cannot be read.", "Restore NetBox; health itself does not depend on it."),
    "GRAFANA_UNAVAILABLE": _c(MON, "Grafana cannot be read.", "Restore Grafana; it only renders dashboards."),
    "TELEMETRY_COLLECTOR_SILENT": _c(MON, "No monitored device has fresh telemetry although the backend is reachable.",
                                     "Check the gNMI collector service."),
    # -- change / plan preconditions ----------------------------------------------------------------------------
    "PLAN_VALIDATION_CURRENT": _c(PL, "The pinned validation is current and passing.", "None."),
    "PLAN_CURRENT": _c(PL, "The plan is current and pinned to the current validation.", "None."),
    "PLAN_VALIDATION_STALE": _c(PL, "The pinned validation is no longer current.", "Re-run Change Validation, then rebuild the plan.", blocking=True),
    "PLAN_STALE": _c(PL, "The plan is no longer current.", "Re-run Change Validation, then rebuild the plan.", blocking=True),
    "PLAN_MISSING": _c(PL, "No plan has been built for the Change.", "Build the plan from a CURRENT passing validation.", blocking=True, unknown_blocks=True),
    "VALIDATION_NOT_PASSING": _c(PL, "The latest validation is not PASS / PASS_WITH_WARNINGS.", "Resolve the validation findings.", blocking=True, unknown_blocks=True),
    "PLAN_HEALTH_PRECONDITION_FAILED": _c(PL, "One or more blocking health preconditions failed.", "Resolve the blocking checks and re-run the precheck.", blocking=True),
    # -- verification (pre/postcheck) --------------------------------------------------------------------------------
    "POSTCHECK_REQUIREMENT_FAILED": _c(VER, "One or more plan verification requirements failed.", "Review the failed requirements.", blocking=True),
    "PRECHECK_DATA_UNAVAILABLE": _c(VER, "Evidence needed to evaluate a prerequisite is unavailable.", "Collect fresh evidence and re-run the precheck.", blocking=True, unknown_blocks=True),
    "POSTCHECK_DATA_UNAVAILABLE": _c(VER, "Evidence needed to evaluate a requirement is unavailable.", "Collect fresh evidence and re-evaluate.", blocking=True, unknown_blocks=True),
    "REQUIREMENT_NOT_IMPLEMENTED": _c(VER, "No evaluator exists for this requirement; it is NOT verified.", "Verify manually or extend the health engine."),
    "REQUIREMENT_UNKNOWN_TYPE": _c(VER, "The requirement type is not known to the health engine.", "Rebuild the plan with a current planner."),
    "REQUIREMENT_DESCRIPTOR_INCOMPLETE": _c(VER, "The plan's requirement descriptor carries no expected facts (older plan).", "Rebuild the plan.", unknown_blocks=True),
    "EVIDENCE_CONFLICT": _c(VER, "Live evidence contradicts older telemetry; the live value was used.", "None; live evidence takes precedence."),
    # -- IP connectivity (Phase 22): a read-only ping FROM a managed device TO an inventory-known destination -----
    "CONNECTIVITY_REACHABLE": _c(CONN, "A read-only ping from the device to the destination succeeded with no packet loss.", "None."),
    "CONNECTIVITY_DEGRADED": _c(CONN, "A read-only ping from the device to the destination showed partial packet loss.",
                               "Investigate the path for congestion or an intermittent failure."),
    "CONNECTIVITY_UNREACHABLE": _c(CONN, "A read-only ping from the device to the destination failed (no replies).",
                                   "Verify the destination is up and the path between the two devices.", blocking=True),
    "CONNECTIVITY_CHECK_UNAVAILABLE": _c(CONN, "The connectivity check could not be attempted.",
                                        "Verify platform capability, device reachability and the destination address.", unknown_blocks=True),
})

# Codes that mean "the health engine could not decide"; only ever paired with UNKNOWN.
UNKNOWN_CODES = frozenset({
    "DEVICE_TELEMETRY_UNAVAILABLE", "PRECHECK_DATA_UNAVAILABLE", "POSTCHECK_DATA_UNAVAILABLE", "REQUIREMENT_NOT_IMPLEMENTED",
    "REQUIREMENT_UNKNOWN_TYPE", "REQUIREMENT_DESCRIPTOR_INCOMPLETE",
})


def spec(code: str) -> CodeSpec:
    """The catalogue entry for ``code`` (an unknown code is a programming error, never silently accepted)."""
    return CODES[code]
