"""
Service boundary for Automation.

Originally (Phase 3) every section here was an explicit not-implemented navigation shell. Phase 8-21 built the real
config-change lifecycle (DeviceIntent/Change -> Validate -> Plan -> Render -> Execute -> Verify, under Device
Builder) and Phase 15/22 built the real health-check automation (under Health); this module now points each
section that has a genuine operator-usable page at it, and leaves every section that does not honestly
``not_integrated`` -- never a fabricated capability. Real implementations must keep calling through this module
rather than putting Netmiko/subprocess/reconciliation logic in a view.
"""

from __future__ import annotations

from .base import not_integrated

# slug -> (label, description). Order matches the Phase 3 spec's list.
AUTOMATION_SECTIONS = [
    ("fleet-health", "Fleet Health", "Aggregate health across all managed devices."),
    ("per-device-health", "Per-Device Health", "Detailed health for a single device."),
    ("configuration-changes", "Configuration Changes", "Small incremental CREATE / ATTACH changes to a running device: direct CLI or capability-driven widgets, previewed as an exact patch beside the live running configuration."),
    ("template-library", "Template Library", "Intent-based configuration templates: baseline role templates, templates extracted from running devices, portable export / import, and Use Template (clone into a Device Builder working intent)."),
    ("new-device-provisioning", "New Device Provisioning", "Staged, capability-gated workflow that brings a new device under management: identity, bootstrap, IPAM reservation, candidate, validation, approval, provision, postcheck, NSOT sync and Golden probation."),
    ("traffic-test-workbench", "Traffic / Test Workbench", "Controlled, bounded network tests between lab endpoints: ICMP, traceroute, TCP / UDP probes and iperf3 throughput, each stored as an immutable evidence run."),
    ("remove-configuration", "Remove Configuration", "Intentional, dependency-aware removal of selected configuration (line range or smart object selection) from a running device -- not rollback."),
    ("maintenance-mode", "Maintenance Mode", "Take a device out of service only when its active traffic can be moved away losslessly over redundancy that already exists (or is proven quiesced): per-family, per-direction readiness, an immutable approved plan, a verified drain, a 7-day safety deadline and a verified restore."),
    ("unit-test-matrix", "Unit Test Matrix", "Lab 7 test governance: every deployed automation artifact with its required negative and positive test cases, Pylint status and the latest Tier-3 evidence (read-only)."),
    ("code-coverage", "Code Coverage", "Lab 7 test governance: platform x feature test coverage for every currently implemented capability cell, plus generic control-plane coverage (statements, branches, functions, cases)."),
    ("rollback-recovery", "Rollback / Recovery", "Revert a device to a prior known-good state."),
    ("soak-management", "Soak Management", "Probationary/soak period tracking before a change is accepted."),
    ("initial-golden-bootstrap", "Initial Golden Bootstrap", "ONE-TIME adoption of the pre-existing traditionally configured network as the initial Golden baseline."),
    ("credential-management", "Device Credentials", "Safe managed-device account metadata, rotation policy, and non-secret audit status."),
    ("change-history", "Change History", "Chronological record of configuration changes."),
    ("troubleshooting", "Troubleshooting", "Guided diagnostics for a device or link."),
]


def get_automation_summary() -> dict:
    return not_integrated(
        "This page is a navigation shell: each section below links to its real page where one exists "
        "(Health, Configuration Changes, Remove Configuration, Device Builder Changes, Soak Management, Initial Golden "
        "Bootstrap). Standalone rollback/recovery and troubleshooting have no dedicated operator page yet -- see "
        "docs/AUTOMATION_CONFIGURATION_WORKFLOWS.md and docs/PHASE_22_NETWORK_AUTOMATION.md.",
    )


# Sections that graduated out of the shell state; slug -> URL name of the real page.
IMPLEMENTED_SECTIONS = {
    "fleet-health": "core:health_fleet",                  # Phase 15
    "per-device-health": "core:health_fleet",              # Phase 15 (+ Phase 22 IP connectivity)
    "configuration-changes": "core:workbench_changes",       # incremental patch workbench (NOT Device Builder's full build)
    "template-library": "core:template_library",              # V2 Phase 3 intent templates (clone -> ordinary Change lifecycle)
    "new-device-provisioning": "core:provisioning_list",      # V2 Phase 5A staged provisioning (drives the ordinary Change lifecycle)
    "traffic-test-workbench": "core:traffic_workbench",        # V2 Phase 5B structured tests (never a command box)
    "remove-configuration": "core:workbench_remove",          # first-class, dependency-aware removal workbench
    "change-history": "core:device_builder_changes",         # each Change's detail page carries its full lifecycle history
    "soak-management": "core:soaks_list",                  # Phase 20
    "maintenance-mode": "core:maintenance_list",            # V2 Maintenance Mode (entry / restore are queued for the worker)
    "initial-golden-bootstrap": "core:bootstrap_home",      # one-time legacy baseline bootstrap
    "credential-management": "core:credential_status",     # Phase 23 metadata/status only; scheduler performs due rotations
    "unit-test-matrix": "core:quality_unit_tests",          # Lab 7 test governance (persisted Tier-3 evidence)
    "code-coverage": "core:quality_coverage",               # Lab 7 test governance (persisted Tier-3 evidence)
}

# Sections whose real page performs ONLY read-only actions.  A section absent here but present in
# IMPLEMENTED_SECTIONS has real write actions of its own (each individually gated by its own explicit approval
# step -- e.g. Change execution, a soak decision) -- never a live network mutation reachable from THIS shell page.
READ_ONLY_SECTIONS = {"fleet-health", "per-device-health", "credential-management", "unit-test-matrix", "code-coverage"}


def get_automation_sections() -> list[dict]:
    return [
        {
            "slug": slug,
            "label": label,
            "description": description,
            "implemented": slug in IMPLEMENTED_SECTIONS,
            "url_name": IMPLEMENTED_SECTIONS.get(slug, ""),
            "read_only": slug in READ_ONLY_SECTIONS,
        }
        for slug, label, description in AUTOMATION_SECTIONS
    ]


def get_automation_section(slug: str) -> dict | None:
    for section in get_automation_sections():
        if section["slug"] == slug:
            return section
    return None
