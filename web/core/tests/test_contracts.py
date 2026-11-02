"""Central architecture / security / side-effect contracts for the Device Builder.

Every invariant that previously lived as a copy in a per-phase architecture test
(Phase 3, 9, 10, 11, 12) is asserted here ONCE, over the whole module set, with
a labelled ``subTest`` per (module, rule).  A new Device Builder module joins
``DEVICE_BUILDER_MODULES``; it does NOT get a new architecture test file.

Phase-13 validation has its own stricter boundary (``test_phase13_architecture``)
because it must additionally never touch Configlets/lifecycle/notifications.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

from django.test import SimpleTestCase, TestCase

from core import models, views
from core.services import (
    candidate_renderer,
    feature_template_renderer,
    field_commit_service,
    field_registry,
    field_validators,
    interface_intent_service,
    platform_drivers,
    routing_intent_service,
    service_policy_intent_service,
)
from core.services import change_plan_service, health_service
from core.services.health import (
    codes as health_codes, device as health_device, evaluators as health_evaluators, evidence as health_evidence, fleet as health_fleet,
    inventory as health_inventory, live as health_live, persistence as health_persistence, postchecks as health_postchecks,
    prechecks as health_prechecks, requirements as health_requirements, results as health_results, scope as health_scope,
    telemetry as health_telemetry, thresholds as health_thresholds,
)
from core.services.planning import (
    builder as plan_builder,
    configlet_factory,
    dependency_mapping,
    errors as plan_errors,
    ordering,
    priorities as plan_priorities,
    serialization as plan_serialization,
    snippets,
)
from core.services import change_service, configlet_service, device_builder_ipam_service, intent_service, lifecycle_service, secret_policy
from core.tests.helpers.candidates import add_acl, add_bgp_neighbor, add_fhrp, add_instance, add_interface, add_static_route, commit, make_candidate

WEB_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = WEB_ROOT.parent

DEVICE_BUILDER_MODULES = (
    candidate_renderer,
    feature_template_renderer,
    field_commit_service,
    field_registry,
    field_validators,
    interface_intent_service,
    platform_drivers,
    routing_intent_service,
    service_policy_intent_service,
)
# The Phase-8 control-plane models/services are held to the same rule.
CONTROL_PLANE_MODULES = (models, change_service, configlet_service, intent_service, lifecycle_service, secret_policy)
# The Phase-14 plan builder: pure planning + one atomic persistence step, never an execution path.
PLANNING_MODULES = (
    change_plan_service, plan_builder, configlet_factory, dependency_mapping, plan_errors, ordering, plan_priorities,
    plan_serialization, snippets,
)
# views.py is held to the same "no direct automation" rule as the services.
IMPORT_BOUNDARY_MODULES = (*DEVICE_BUILDER_MODULES, *CONTROL_PLANE_MODULES, *PLANNING_MODULES, views)

FORBIDDEN_IMPORTS = ("netmiko", "paramiko", "pynetbox", "subprocess", "requests", "github", "git", "influxdb")
LIVE_ADAPTERS = ("nsot_live", "nsot_netbox", "netbox_ipam")
LIFECYCLE_TEXT = ("containerlab deploy", "containerlab destroy", "containerlab cleanup")
# The plan builder must not even contain the words of deployment or persistence (Phase 17 owns execution).
DEPLOYMENT_TEXT = ("configure terminal", "write memory", "copy running", "commit confirmed", "netmiko", "vtysh", "send_config")
# Vendor syntax lives ONLY in platform_drivers + the Jinja feature templates.
VENDOR_SYNTAX = (
    "router bgp", "router ospf", "ip route", "ipv6 route", "switchport", "ip access-list", "ip access-group", "ip address",
    "address-family ipv", "masquerade", "helper-address", "ip virtual-router", "remote-as", "table ip", "no shutdown",
)
EXECUTION_TOKENS = ("send_config", "push_", "execute", "deploy")


def imported_names(module) -> set[str]:
    """Every top-level package AND last module segment AND imported alias (so ``from . import x`` is seen)."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(module))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
                names.add(node.module.split(".")[-1])
            names.update(alias.name for alias in node.names)
    return names


class ImportBoundaryContractTests(SimpleTestCase):
    def test_no_device_netbox_git_or_network_library_is_imported(self):
        for module in IMPORT_BOUNDARY_MODULES:
            imports = imported_names(module)
            for forbidden in FORBIDDEN_IMPORTS:
                with self.subTest(module=module.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, imports)

    def test_editing_modules_do_not_import_live_device_or_netbox_adapters(self):
        # views are excluded: the IPAM-prefix and NSOT pages legitimately read NetBox through their own service.
        for module in (*DEVICE_BUILDER_MODULES, *PLANNING_MODULES):
            imports = imported_names(module)
            for forbidden in LIVE_ADAPTERS:
                with self.subTest(module=module.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, imports)

    def test_commit_and_render_paths_touch_no_http_module(self):
        for module in (field_commit_service, candidate_renderer):
            imports = imported_names(module)
            for forbidden in ("urllib", "http"):
                with self.subTest(module=module.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, imports)

    def test_no_dynamic_execution_or_shell_call_in_device_builder_code(self):
        banned_names = {"eval", "exec", "__import__"}
        banned_attrs = {"system", "popen", "check_output"}
        for module in IMPORT_BOUNDARY_MODULES:
            offenders = []
            for node in ast.walk(ast.parse(inspect.getsource(module))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned_names:
                    offenders.append(f"call {node.func.id}() at line {node.lineno}")
                if isinstance(node, ast.Attribute) and node.attr in banned_attrs:
                    offenders.append(f"attribute .{node.attr} at line {node.lineno}")
            with self.subTest(module=module.__name__):
                self.assertEqual(offenders, [])


class NoDeploymentOrNetBoxWriteContractTests(SimpleTestCase):
    def test_no_containerlab_lifecycle_command_in_device_builder_modules(self):
        for module in (*DEVICE_BUILDER_MODULES, *PLANNING_MODULES):
            source = inspect.getsource(module).lower()
            for forbidden in (*LIFECYCLE_TEXT, *(DEPLOYMENT_TEXT if module in PLANNING_MODULES else ())):
                with self.subTest(module=module.__name__, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)

    def test_no_netbox_write_call_in_device_builder_modules(self):
        # a NetBox client/endpoint write, or one of the repository's NetBox write helpers
        writes = re.compile(
            r"(\b(client|nb|netbox|pynetbox|endpoint|api)\b[\w\.\[\]\"']*\.(create|update|delete|save|post|put|patch)\("
            r"|\bnb\.(dcim|ipam)\b|\b(reconcile_object|ensure_tag|ensure_custom_field|ensure_interface_mac)\()"
        )
        for module in (*DEVICE_BUILDER_MODULES, *PLANNING_MODULES, device_builder_ipam_service):
            with self.subTest(module=module.__name__):
                self.assertIsNone(writes.search(inspect.getsource(module)))
        source = inspect.getsource(device_builder_ipam_service)  # explicit read-only lookup: no ORM/client writes either
        for forbidden in (".create(", ".update(", ".save(", ".delete(", "reconcile_object"):
            with self.subTest(module="device_builder_ipam_service", forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_mutation_views_expose_no_execution_surface(self):
        mutation_views = (
            "device_builder_field_commit", "device_builder_static_route_add", "device_builder_routing_instance_add",
            "device_builder_routing_binding_add", "device_builder_bgp_neighbor_add", "device_builder_bgp_network_add",
            "device_builder_phase12_add",
        )
        for name in mutation_views:
            source = inspect.getsource(getattr(views, name))
            for forbidden in EXECUTION_TOKENS:
                with self.subTest(view=name, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)


class SourceOfTruthContractTests(SimpleTestCase):
    """The single-renderer, stable-ID, allowlisted-path and secret-reference rules."""

    def test_exactly_one_authoritative_candidate_renderer(self):
        services = WEB_ROOT / "core/services"
        self.assertEqual([p.name for p in services.glob("*candidate_renderer*.py")], ["candidate_renderer.py"])

    def test_no_raw_cli_field_exists_in_the_service_policy_schema(self):
        source = inspect.getsource(service_policy_intent_service)
        for bad in ("nat_cli", "security_cli", "pbr_cli", "services_config"):
            with self.subTest(field=bad):
                self.assertNotIn(bad, source)

    def test_ids_are_stable_opaque_ids_not_array_indexes(self):
        interface_source = inspect.getsource(interface_intent_service)
        for token in ('_new_id("if")', '_new_id("addr")', 'sections["interfaces"]'):
            with self.subTest(module="interface_intent_service", token=token):
                self.assertIn(token, interface_source)
        routing_source = inspect.getsource(routing_intent_service)
        for prefix in ("route", "bind", "peer", "net"):
            with self.subTest(module="routing_intent_service", prefix=prefix):
                self.assertIn(f'_new_id("{prefix}")', routing_source)
        self.assertIn("_new_id(ID_PREFIX[family])", routing_source)
        self.assertIn('sections["routing"]', routing_source)
        self.assertEqual(
            routing_intent_service.ID_PREFIX,
            {"static_routes": "route", "rip": "rip", "ospf": "ospf", "isis": "isis", "eigrp": "eigrp", "bgp": "bgp"},
        )

    def test_field_registry_is_an_allowlist_not_generic_json_path_mutation(self):
        source = inspect.getsource(field_registry)
        for token in ("_INTERFACE_PATH_RE", "_ROUTE_PATH_RE", "_BGP_NEIGHBOR_PATH_RE", "get_interface(revision", "get_static_route(revision"):
            with self.subTest(token=token):
                self.assertIn(token, source)
        for token in ("eval(", "setattr(intent, path"):
            with self.subTest(forbidden=token):
                self.assertNotIn(token, source)

    def test_bgp_neighbor_authentication_is_reference_only(self):
        source = inspect.getsource(routing_intent_service)
        self.assertNotIn('"password"', source)
        self.assertIn('"password_ref"', source)

    def test_feature_templates_are_additive_and_never_copies_of_frozen_lab1_templates(self):
        feature_templates = sorted((REPO_ROOT / "templates" / "features").rglob("*.j2"))
        self.assertGreaterEqual(len(feature_templates), 12)
        self.assertTrue(all("features" in path.parts for path in feature_templates))
        self.assertGreaterEqual(len([p for p in feature_templates if p.name.startswith("routing_")]), 8)
        lab1 = list(REPO_ROOT.glob("templates/R*.cfg.j2")) + list(REPO_ROOT.glob("templates/S*.cfg.j2"))
        self.assertGreater(len(lab1), 0)
        self.assertFalse({p.name for p in feature_templates} & {"R1.cfg.j2", "R2.cfg.j2", "R3.cfg.j2", "S1.cfg.j2"})


class PlanBuilderContractTests(SimpleTestCase):
    def test_planning_code_contains_no_vendor_syntax_and_no_hostname_conditionals(self):
        """Snippets come from the platform drivers via slices; the planner never spells CLI or branches on a device name."""
        hostnames = {"R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4"}
        for module in PLANNING_MODULES:
            tree = ast.parse(inspect.getsource(module))
            docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                          if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body
                          and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)}
            literals = [n.value for n in ast.walk(tree)
                        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings]
            offenders = sorted({lit for lit in literals for token in VENDOR_SYNTAX if token in lit.lower()} | (hostnames & set(literals)))
            with self.subTest(module=module.__name__):
                self.assertEqual(offenders, [])

    def test_the_plan_views_are_thin_adapters_over_the_service(self):
        source = inspect.getsource(views)
        section = source[source.index("Phase 14 -- unified priority"):]
        for forbidden in ("core.services.planning", "topological", "compute_plan", "added_lines", "configlet_factory", "ordering."):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, section)
        self.assertIn("change_plan_service.build_change_plan", section)

    def test_plans_do_not_import_validation_internals_or_create_a_second_validator(self):
        """Phase 14 consumes Phase 13's stored results; it may hash the snapshot but never re-derive semantics."""
        for module in PLANNING_MODULES:
            names = {n.name for n in ast.walk(ast.parse(inspect.getsource(module))) if isinstance(n, ast.FunctionDef)}
            with self.subTest(module=module.__name__):
                self.assertFalse(names & {"validate_change", "run_validation", "validate_dependencies", "find_cycles", "build_graph"})


class EditingHasNoSideEffectsTests(TestCase):
    """Building intent (interfaces, routing, services, policy) must stay a pure DRAFT operation."""

    def test_editing_never_advances_lifecycle_creates_configlets_or_records_deployment(self):
        change, intent, revision = make_candidate()
        lifecycle_events_before = change.lifecycle_events.count()
        interface = add_interface(revision, kind="SVI", name="Vlan10")
        commit(change, intent, revision, f"interfaces.{interface['id']}.description", "safe")
        add_static_route(revision)
        bgp = add_instance(revision, family="bgp", local_asn=65000)
        add_bgp_neighbor(revision, instance_id=bgp["id"], peer_address="192.0.2.1", remote_asn=65001)
        add_fhrp(revision, interface["id"])
        add_acl(revision)
        change.refresh_from_db()
        self.assertEqual(change.lifecycle_state, models.ChangeLifecycleState.DRAFT)
        self.assertEqual(models.Configlet.objects.filter(change=change).count(), 0)
        self.assertEqual(change.lifecycle_events.count(), lifecycle_events_before)
        self.assertFalse(
            change.audit_events.filter(
                event_type__in=(models.AuditEventType.DEPLOYMENT_RECORDED, models.AuditEventType.ROLLBACK_RECORDED)
            ).exists()
        )


# --- Phase 15: health / precheck / postcheck ----------------------------------------------------------------------------
HEALTH_MODULES = (
    health_codes, health_device, health_evaluators, health_evidence, health_fleet, health_inventory, health_live, health_persistence,
    health_postchecks, health_prechecks, health_requirements, health_results, health_scope, health_telemetry, health_thresholds,
    health_service,
)
# The ONE module that may open a device session or spawn a process; everything else is evidence in, results out.
HEALTH_LIVE_MODULE = health_live
HEALTH_VIEW_NAMES = ("health_fleet", "health_fleet_snapshot", "health_device", "health_device_deep", "health_run", "health_run_report",
                     "change_precheck", "change_precheck_run", "change_precheck_detail")
# Anything that would change a device, clear state, persist a config, or restart a service.
MUTATION_TOKENS = (  # command-shaped only: bare words like "shutdown" are also legitimate fact keys / prose
    "configure terminal", "conf t", "write memory", "copy running", "commit confirmed", "no shutdown", "reload", "reboot",
    "clear ip", "clear bgp", "clear ipv6", "systemctl", "ip link set", "ip route replace", "ip addr add", "nft add", "nft delete", "nft flush",
    "service restart", "iptables",
)
MUTATION_ATTRIBUTES = {"send_config_set", "send_config_from_file", "config_mode", "save_config", "commit", "exit_config_mode", "send_command_timing",
                       "system", "popen", "check_output", "check_call"}


def code_strings(module, *, skip_assignments=()):
    """String constants that are CODE (not docstrings), so prose describing what is forbidden is not mistaken for a command."""
    tree = ast.parse(inspect.getsource(module))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
    skipped = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in skip_assignments for t in node.targets):
            skipped.update(id(n) for n in ast.walk(node))
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings and id(n) not in skipped]


class HealthReadOnlyContractTests(SimpleTestCase):
    def test_only_the_live_adapter_opens_sessions_or_spawns_processes(self):
        io_libraries = ("netmiko", "paramiko", "subprocess", "socket", "urllib", "http", "requests", "pynetbox", "git", "github", "influxdb", "influxdb_client")
        for module in HEALTH_MODULES:
            imports = imported_names(module)
            allowed = {"netmiko", "subprocess"} if module is HEALTH_LIVE_MODULE else set()
            for library in io_libraries:
                with self.subTest(module=module.__name__, library=library):
                    if library in allowed:
                        continue
                    self.assertNotIn(library, imports)
        # Fleet Quick's adapter builds no Flux query and has no InfluxDB client: it consumes the existing topology service
        telemetry_source = inspect.getsource(health_telemetry)
        for forbidden in ("from(bucket", "range(start", "|> filter", "InfluxDBClient", "/api/v2/query"):
            with self.subTest(fleet_quick_source=forbidden):
                self.assertNotIn(forbidden, telemetry_source)

    def test_health_code_contains_no_mutation_command_config_method_shell_or_dynamic_execution(self):
        for module in HEALTH_MODULES:
            tree = ast.parse(inspect.getsource(module))
            offenders = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "__import__", "compile"}:
                    offenders.append(f"{node.func.id}() line {node.lineno}")
                if isinstance(node, ast.Attribute) and node.attr in MUTATION_ATTRIBUTES:
                    offenders.append(f".{node.attr} line {node.lineno}")
                if isinstance(node, ast.keyword) and node.arg == "shell" and not (isinstance(node.value, ast.Constant) and node.value.value is False):
                    offenders.append(f"shell= line {node.value.lineno}")
                if isinstance(node, ast.Import) and any(a.name in ("importlib", "runpy") for a in node.names):
                    offenders.append(f"dynamic import line {node.lineno}")
            with self.subTest(module=module.__name__, check="ast"):
                self.assertEqual(offenders, [])
            strings = code_strings(module, skip_assignments=("FORBIDDEN_COMMAND_TOKENS",) if module is HEALTH_LIVE_MODULE else ())
            for token in MUTATION_TOKENS:
                with self.subTest(module=module.__name__, token=token):
                    self.assertEqual([s for s in strings if token in s.lower()], [])
        # the single process spawn is docker exec of a list, never a shell string
        spawns = [n for n in ast.walk(ast.parse(inspect.getsource(health_live))) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr == "run" and getattr(n.func.value, "id", "") == "subprocess"]
        self.assertEqual(len(spawns), 1)
        self.assertIsInstance(spawns[0].args[0], ast.List)
        self.assertEqual(spawns[0].args[0].elts[0].value, "docker")

    def test_live_command_allowlists_are_fixed_server_owned_and_read_only(self):
        for key, command in health_live.CEOS_COMMANDS.items():
            with self.subTest(platform="ceos", key=key):
                head, _, tail = command.partition(" | ")
                self.assertTrue(head.startswith("show "))
                self.assertIn(tail, ("", "json"))
                self.assertFalse(any(ch in command for ch in "{}%;&`$<>"), "no interpolation or shell metacharacter")
        for key, argv in health_live.LINUX_COMMANDS.items():
            with self.subTest(platform="linux", key=key):
                self.assertIsInstance(argv, tuple)
                self.assertIn(argv[0], {"ip", "vtysh", "nft"})
                self.assertTrue((argv[0] == "ip" and argv[-1] == "show") or (argv[0] == "vtysh" and argv[2].startswith("show ")) or argv == ("nft", "list", "ruleset"))
        for key, command in health_live.IOSXE_COMMANDS.items():
            with self.subTest(platform="cisco_c8000v_iosxe", key=key):
                self.assertTrue(command.startswith("show "))
                self.assertFalse(any(ch in command for ch in "|{}%;&`$<>"), "no pipe, interpolation or shell metacharacter")
        for key, query in health_live.SRLINUX_QUERIES.items():
            with self.subTest(platform="nokia_srlinux", key=key):          # gNMI Get (read-only) of state, or of config for routing facts
                path, datastore = query
                self.assertTrue(path.startswith("/"))
                self.assertIn(datastore, {"state", "config"})
                self.assertEqual(datastore == "config", key == "running_config")
                self.assertFalse(any(ch in path for ch in "{}%;&`$<>| "))
        self.assertEqual(set(health_live.PROBE_KEY), {"ceos", "linux", "nokia_srlinux", "cisco_c8000v_iosxe"})
        self.assertEqual(set(health_live.ALLOWLISTS), set(health_live.PROBE_KEY))
        for table in health_live.ALLOWLISTS.values():
            with self.assertRaises(TypeError):
                table["evil"] = "configure terminal"
        self.assertTrue(all(key in health_live.ALLOWLISTS[p] for p, key in health_live.PROBE_KEY.items()))
        with self.assertRaises(TypeError):  # an immutable mapping: nothing can add a command at runtime
            health_live.CEOS_COMMANDS["evil"] = "configure terminal"
        # the browser can influence neither a command nor a target: the read API takes an inventory entry and an optional fake factory
        self.assertEqual(list(inspect.signature(health_live.read_device).parameters), ["device", "session_factory", "now"])

    def test_health_views_take_no_command_source_url_or_query_from_the_browser(self):
        allowed_get = {"check_sources", "recorded"}
        for name in HEALTH_VIEW_NAMES:
            source = inspect.getsource(getattr(views, name))
            with self.subTest(view=name):
                self.assertNotIn("request.POST", source)
                self.assertNotIn("request.body", source)
                self.assertEqual({k for k in re.findall(r"request\.GET\.get\(\"([a-z_]+)\"", source)} - allowed_get, set())
                for forbidden in ("subprocess", "netmiko", "socket", "urllib", "influx", "eval(", "exec("):
                    self.assertNotIn(forbidden, source)
        self.assertNotIn("health_service.live", inspect.getsource(views), "views call the service API, never the live adapter")

    def test_health_writes_only_its_own_run_history_and_audit_and_never_touches_other_subsystems(self):
        # ORM-shaped writes only (``dict.update`` is not a database write)
        writers = re.compile(r"\.(save|delete|bulk_create|bulk_update|get_or_create|update_or_create)\(|objects(\.\w+\([^)]*\))*\.(create|update)\(")
        for module in HEALTH_MODULES:
            if module is health_persistence:
                continue
            with self.subTest(module=module.__name__):
                self.assertIsNone(writers.search(inspect.getsource(module)), "only persistence.py may write")
        creates = re.findall(r"models\.(\w+)\.objects\.create\(", inspect.getsource(health_persistence))
        self.assertEqual(sorted(creates), ["AuditEvent", "OperationalCheckRun"])
        untouched = {"notification_service", "slack_service", "lifecycle_service", "configlet_service", "nsot_git", "candidate_renderer", "platform_drivers",
                     "device_builder_service", "change_service", "automation_service", "netbox_ipam", "ipam_context"}
        for module in HEALTH_MODULES:
            with self.subTest(module=module.__name__, check="subsystems"):
                self.assertEqual(imported_names(module) & untouched, set())
        # NetBox / Grafana are only ever READ, and only through the existing read-only adapters, from the Fleet-Quick telemetry adapter
        adapters = {m.__name__ for m in HEALTH_MODULES if imported_names(m) & {"nsot_netbox", "monitoring_service", "topology_service"}}
        self.assertEqual(adapters, {health_telemetry.__name__})
        for token in (*LIFECYCLE_TEXT, "git commit", "git push", "gh pr ", "gh workflow", "gh run "):
            for module in HEALTH_MODULES:
                with self.subTest(module=module.__name__, forbidden=token):
                    self.assertNotIn(token, inspect.getsource(module).lower())


# =============================================================================
# Phase 17 -- structured execution boundary
# =============================================================================
EXECUTION_DIR = WEB_ROOT / "core" / "services" / "execution"
EXECUTION_IO_LIBRARIES = ("netmiko", "paramiko", "pygnmi", "subprocess", "socket", "urllib", "http", "requests", "pynetbox", "git", "github", "influxdb", "influxdb_client")
# the modules that legitimately talk to a device, and the ONLY library each may import (SR Linux: the gNMI session
# lives in its writer module; the executor itself imports no device library at all)
EXECUTION_ALLOWED_IO = {"ceos": {"netmiko"}, "linux": {"subprocess"}, "iosxe": {"netmiko"}, "srlinux_gnmi": {"pygnmi"}}
EXECUTION_FORBIDDEN_IMPORTS = {"lifecycle_service", "configlet_service", "netbox_ipam", "ipam_context", "slack_service", "nsot_git", "ci_service"}
EXECUTION_FORBIDDEN_TEXT = (
    "write memory", "copy running", "startup-config", "reload", "reboot", "systemctl", "iptables", "vtysh", "containerlab", "git commit",
    "git push", "gh pr", "gh workflow",
)


STARTUP_PERSISTENCE_COMMANDS = ("copy running-config startup-config", "show startup-config")
STARTUP_PERSISTENCE_METHODS = {"save_startup", "startup_config_text", "startup_state_digest"}


def execution_modules():
    import importlib

    names = ["core.services.execution_service"] + sorted(
        "core.services.execution." + ".".join(path.relative_to(EXECUTION_DIR).with_suffix("").parts).removesuffix(".__init__")
        for path in EXECUTION_DIR.rglob("*.py")
    )
    return [importlib.import_module(name.removesuffix(".")) for name in names]


class ExecutionBoundaryContractTests(SimpleTestCase):
    def test_only_the_two_executors_touch_a_device_library_and_each_only_its_own(self):
        for module in execution_modules():
            short = module.__name__.rsplit(".", 1)[-1]
            imports = imported_names(module)
            for library in EXECUTION_IO_LIBRARIES:
                with self.subTest(module=module.__name__, library=library):
                    if library in EXECUTION_ALLOWED_IO.get(short, set()) and (
                            ".executors." in module.__name__ or module.__name__.endswith(".writers.srlinux_gnmi")):
                        continue
                    self.assertNotIn(library, imports)
            with self.subTest(module=module.__name__, check="other subsystems"):
                self.assertEqual(imports & EXECUTION_FORBIDDEN_IMPORTS, set(), "execution never touches lifecycle, NetBox writers, Slack, Git or CI")

    def test_no_dynamic_execution_shell_or_os_command_anywhere_in_the_engine(self):
        for module in execution_modules():
            offenders = []
            for node in ast.walk(ast.parse(inspect.getsource(module))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile", "__import__"}:
                    offenders.append(f"{node.func.id}() line {node.lineno}")
                if isinstance(node, ast.Attribute) and node.attr in {"system", "popen", "check_output", "check_call", "Popen"}:
                    offenders.append(f".{node.attr} line {node.lineno}")
                if isinstance(node, ast.keyword) and node.arg == "shell" and not (isinstance(node.value, ast.Constant) and node.value.value is False):
                    offenders.append(f"shell= line {node.value.lineno}")
            with self.subTest(module=module.__name__):
                self.assertEqual(offenders, [])
        spawns = [n for n in ast.walk(ast.parse(inspect.getsource(sys_module("linux")))) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and n.func.attr == "run" and getattr(n.func.value, "id", "") == "subprocess"]
        self.assertEqual(len(spawns), 1, "exactly one process spawn in the whole engine")
        self.assertIsInstance(spawns[0].args[0], ast.List)
        self.assertEqual(spawns[0].args[0].elts[0].value, "docker")

    def test_no_persistence_reload_lifecycle_or_repository_command_is_ever_sent(self):
        for module in execution_modules():
            strings = [s.lower() for s in code_strings(module)]
            for token in EXECUTION_FORBIDDEN_TEXT:
                with self.subTest(module=module.__name__, token=token):
                    # Phase-4's bounded FRR static-route executor is the only
                    # intentional vtysh writer. Its exact command grammar,
                    # inverse and no-shell argv are covered in executor tests.
                    if token == "vtysh" and module.__name__ == "core.services.execution.executors.linux":
                        continue
                    # The baseline IS-IS transition persists R1/R2/S1/S2 after its final validation. The cEOS
                    # executor holds exactly these two commands for it; the test below proves that nothing in
                    # the general engine can send them.
                    allowed = STARTUP_PERSISTENCE_COMMANDS if module.__name__ == "core.services.execution.executors.ceos" else ()
                    self.assertEqual([s for s in strings if token in s and not s.startswith("no ") and s not in allowed], [])

    def test_startup_persistence_is_never_reached_from_the_general_engine(self):
        for module in execution_modules():
            tree = ast.parse(inspect.getsource(module))
            used = sorted({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in STARTUP_PERSISTENCE_METHODS and isinstance(n.ctx, ast.Load)}
                          | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id in STARTUP_PERSISTENCE_METHODS}
                          | {s for s in code_strings(module) if s in STARTUP_PERSISTENCE_METHODS})
            with self.subTest(module=module.__name__):
                # Inside the executor the digest reads the text through ``self``; no other reference exists.
                self.assertEqual(used, ["startup_config_text"] if module.__name__ == "core.services.execution.executors.ceos" else [])
        # Everywhere in the application (views, commands, services, modules), not only next to the engine: the callers are
        # the two shielded transactions that own a verified final state -- the baseline IS-IS transition lifecycle and the
        # Maintenance Mode executor (the drained state, and the restored one, must survive a reload) -- and the one other
        # mention is the dry run's list of calls it refuses.
        callers, mentions = set(), set()
        for path in WEB_ROOT.rglob("*.py"):
            relative = path.relative_to(WEB_ROOT).as_posix()
            if "/tests/" in f"/{relative}" or "/migrations/" in f"/{relative}":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if any(isinstance(n, ast.Attribute) and n.attr == "save_startup" for n in ast.walk(tree)):
                callers.add(relative)
            if any(isinstance(n, ast.Constant) and n.value == "save_startup" for n in ast.walk(tree)):
                mentions.add(relative)
        self.assertEqual(callers, {"core/services/route_shield/lifecycle.py", "core/services/maintenance_mode/executor.py"},
                         "only the baseline IS-IS transition and the Maintenance Mode executor write a startup configuration")
        self.assertEqual(mentions, {"core/services/route_shield/dry_run.py"}, "the name is used as text only where the dry run refuses it")

    def test_the_engine_writes_no_netbox_object_and_only_its_own_history(self):
        writes = re.compile(r"(\b(client|nb|netbox|pynetbox|endpoint|api)\b[\w\.\[\]\"']*\.(create|update|delete|save|post|put|patch)\("
                            r"|\bnb\.(dcim|ipam)\b|\b(reconcile_object|ensure_tag|ensure_custom_field|ensure_interface_mac)\()")
        created = set()
        for module in execution_modules():
            source = inspect.getsource(module)
            with self.subTest(module=module.__name__):
                self.assertIsNone(writes.search(source))
            created.update(re.findall(r"models\.(\w+)\.objects\.(?:create|get_or_create)\(", source))
        self.assertEqual(created, {"AuditEvent", "ChangeExecutionRun", "ConfigletExecutionResult", "ExecutionDeviceLock"})

    def test_the_mutating_engine_has_exactly_one_caller_the_explicit_post_view(self):
        callers = set()
        for path in (WEB_ROOT / "core").rglob("*.py"):
            rel = path.relative_to(WEB_ROOT).as_posix()
            if "/tests/" in rel or "/migrations/" in rel:
                continue
            if "execute_change(" in path.read_text() or ".execute_change" in path.read_text():
                callers.add(rel)
        self.assertEqual(callers, {"core/services/execution/engine.py", "core/services/execution_service.py", "core/views.py"})
        # V2 Phase 5A: provisioning adds NO caller.  Its package never names the engine entry point, never spawns an executor of its own,
        # and contributes policy only through the three hooks the engine itself calls.
        from core.services.provisioning import gate as provisioning_gate

        for path in (WEB_ROOT / "core" / "services" / "provisioning").glob("*.py"):
            text = path.read_text()
            for forbidden in ("execute_change", "executor_for", "locking.acquire", ".apply(", ".compensate("):
                self.assertNotIn(forbidden, text, f"{path.name}: {forbidden}")
        self.assertEqual({name for name in vars(provisioning_gate) if not name.startswith("_") and name != "annotations"},
                         {"blockers", "before_first_mutation", "after_execution"})
        engine_source = (WEB_ROOT / "core/services/execution/engine.py").read_text()
        gate_source = (WEB_ROOT / "core/services/execution/eligibility.py").read_text()
        self.assertEqual(gate_source.count("provisioning_gate.blockers(change)"), 1)
        self.assertEqual(engine_source.count("provisioning_gate.before_first_mutation(change)"), 1)
        self.assertLess(engine_source.index("provisioning_gate.before_first_mutation(change)"), engine_source.index("failed_spec = _apply_all(run, attempt)"))
        self.assertFalse([name for name in dir(views) if name.startswith("provisioning_") and "execute_change" in inspect.getsource(getattr(views, name))])
        self.assertIn("execute_change", inspect.getsource(views.change_execute_run))
        self.assertEqual(inspect.getsource(views).count("execution_service.execute_change("), 1)
        for name in ("change_execute", "change_executions", "change_execution_detail", "change_execution_report"):
            source = inspect.getsource(getattr(views, name))
            with self.subTest(view=name):
                self.assertNotIn("execute_change", source)
                self.assertNotIn("request.POST", source)
                self.assertEqual(set(re.findall(r"request\.GET\.get\(\"([a-z_]+)\"", source)) - {"check_sources"}, set())

    def test_the_post_view_reads_only_the_documented_fields_and_supplies_no_command_path(self):
        source = inspect.getsource(views.change_execute_run)
        self.assertEqual(set(re.findall(r"request\.POST\.get\(\"?([A-Za-z_]+)", source)) - {"name"}, {"through_cfg_id", "confirm_mode"})
        for forbidden in ("subprocess", "netmiko", "socket", "eval(", "exec(", "rendered_config", "command"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(list(inspect.signature(engine_module().execute_change).parameters)[:2], ["change", "actor"])

    def test_every_executor_call_site_is_reached_only_through_the_engine(self):
        executors_dir = EXECUTION_DIR / "executors"
        callers = {p.name for p in EXECUTION_DIR.glob("*.py") if re.search(r"\.(apply|compensate|assess)\(", p.read_text())}
        self.assertEqual(callers, {"engine.py"})
        self.assertTrue((executors_dir / "registry.py").exists())


def sys_module(short):
    import importlib

    return importlib.import_module(f"core.services.execution.executors.{short}")


def engine_module():
    import importlib

    return importlib.import_module("core.services.execution.engine")


# --- Phase 19: immutable configuration bundles ---------------------------------------------------------------------------------
BUNDLES_DIR = WEB_ROOT / "core" / "services" / "bundles"
BUNDLE_IO_LIBRARIES = ("netmiko", "paramiko", "subprocess", "socket", "urllib", "http", "requests", "pynetbox", "git", "github", "influxdb", "influxdb_client", "docker")
# A bundle is evidence: it never reaches the engine, a device, NetBox, the lifecycle, notifications, credentials, Git or CI.
BUNDLE_FORBIDDEN_IMPORTS = {
    "execution", "execution_service", "engine", "executors", "health_service", "lifecycle_service", "configlet_service", "netbox_ipam", "ipam_context",
    "nsot_live", "nsot_netbox", "nsot_git", "notification_service", "slack_service", "ci_service", "change_plan_service", "change_validation_service",
    "raw_configlet_service", "sandbox", "verifier", "verification",
}
BUNDLE_FORBIDDEN_TEXT = ("configure terminal", "write memory", "copy running", "containerlab", "git commit", "git push", "git tag", "vtysh", "send_config", "docker")


def bundle_modules():
    import importlib

    names = ["core.services.bundle_service"] + sorted(f"core.services.bundles.{path.stem}" for path in BUNDLES_DIR.glob("*.py"))
    return [importlib.import_module(name.removesuffix(".__init__")) for name in names]


class BundleBoundaryContractTests(SimpleTestCase):
    def test_bundle_code_imports_no_device_network_shell_engine_lifecycle_notification_or_git_module(self):
        for module in bundle_modules():
            imports = imported_names(module)
            with self.subTest(module=module.__name__):
                self.assertEqual(imports & set(BUNDLE_IO_LIBRARIES), set())
                self.assertEqual(imports & BUNDLE_FORBIDDEN_IMPORTS, set())

    def test_no_dynamic_execution_shell_or_os_command_and_no_deployment_text(self):
        for module in bundle_modules():
            offenders = []
            for node in ast.walk(ast.parse(inspect.getsource(module))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile", "__import__"}:
                    offenders.append(f"{node.func.id}() line {node.lineno}")
                if isinstance(node, ast.Attribute) and node.attr in {"system", "popen", "check_output", "check_call", "Popen", "run"} \
                        and getattr(node.value, "id", "") in {"os", "subprocess"}:
                    offenders.append(f".{node.attr} line {node.lineno}")
                if isinstance(node, ast.keyword) and node.arg == "shell":
                    offenders.append(f"shell= line {node.value.lineno}")
            with self.subTest(module=module.__name__, check="calls"):
                self.assertEqual(offenders, [])
            strings = [s.lower() for s in code_strings(module)]
            for token in BUNDLE_FORBIDDEN_TEXT:
                with self.subTest(module=module.__name__, token=token):
                    self.assertEqual([s for s in strings if token in s], [])
            with self.subTest(module=module.__name__, check="never names the engine entry point"):
                self.assertNotIn("execute_" + "change", inspect.getsource(module))

    def test_bundle_code_only_creates_its_own_rows_and_an_audit_event_and_never_updates_or_deletes(self):
        created, offenders = set(), []
        for module in bundle_modules():
            source = inspect.getsource(module)
            created.update(re.findall(r"models\.(\w+)\.objects\.(?:create|get_or_create|update_or_create|bulk_create)\(", source))
            created.update(re.findall(r"\bmodels\.(ConfigurationBundle)\(", source))
            offenders += [f"{module.__name__}: {m}" for m in re.findall(r"\.(?:update|delete|bulk_update|update_or_create|get_or_create)\(", source)]
            writes = re.compile(r"(\b(client|nb|netbox|pynetbox|endpoint|api)\b[\w\.\[\]\"']*\.(create|update|delete|save|post|put|patch)\("
                                r"|\bnb\.(dcim|ipam)\b|\b(reconcile_object|ensure_tag|ensure_custom_field|ensure_interface_mac)\()")
            with self.subTest(module=module.__name__, check="no NetBox write"):
                self.assertIsNone(writes.search(source))
        # Phase 20: golden.py records the APPROVE atomically with the bundle.  One-time legacy bootstrap: legacy.py records ITS single approval the same way.
        self.assertEqual(created, {"AuditEvent", "ConfigurationBundle", "ConfigurationBundleItem", "GoldenDecision", "LegacyBootstrapDecision"})
        self.assertEqual(offenders, [], "a bundle is only ever created: nothing is updated, repaired or deleted")

    def test_golden_bundles_are_created_only_by_the_evidence_checked_service_reached_only_from_the_decision_route(self):
        kinds, referers, golden_sites = set(), set(), set()
        for path in (WEB_ROOT / "core").rglob("*.py"):
            rel = path.relative_to(WEB_ROOT).as_posix()
            if "/tests/" in rel or "/migrations/" in rel:
                continue
            text = path.read_text()
            for kind in re.findall(r"seal_bundle\(\s*kind=([\w\.]+)", text):
                kinds.add(kind)
                if kind.endswith("GOLDEN"):
                    golden_sites.add(rel)
            if "create_golden_bundle" in text or "seal_bundle" in text:
                referers.add(rel)
        # V2 Phase 5 added ONE root kind (DEPLOYED: a verified Complete provisioning run), sealed in persistence.py only.  The Golden seal
        # sites and their referers below are unchanged: a new root kind is not a new way to reach Golden.
        self.assertEqual(kinds, {"models.BundleKind.UAT", "models.BundleKind.DEPLOYED", "models.BundleKind.PROBATION", "models.BundleKind.GOLDEN",
                                 "models.BundleKind.LEGACY_BASELINE"})
        # Exactly TWO places seal a Golden bundle, and each is reachable from exactly one explicit operator route: the normal soak-backed promotion
        # (golden.py, via soak.decision) and the ONE-TIME legacy bootstrap (legacy.py, via bootstrap.decision; it refuses forever once used).
        self.assertEqual(golden_sites, {"core/services/bundles/golden.py", "core/services/bundles/legacy.py"}, "the ONLY places that seal a Golden bundle")
        self.assertEqual(referers, {"core/services/bundle_service.py", "core/services/bundles/golden.py", "core/services/bundles/legacy.py",
                                    "core/services/bundles/persistence.py", "core/services/soak/decision.py"},
                         "nothing else -- not the collector, not a view -- can reach Golden creation")
        from core import urls

        for pattern in urls.urlpatterns:
            with self.subTest(route=str(pattern.pattern)):
                self.assertNotIn("golden", f"{pattern.name} {pattern.pattern}".lower())   # the decision route is named for the soak, not for an artifact
        views_source = inspect.getsource(views)
        for token in ("create_golden_bundle", "seal_bundle", "golden_from"):
            with self.subTest(view_token=token):
                self.assertNotIn(token, views_source)
        self.assertEqual(views_source.count("bundle_service.derive_probation_bundle("), 1)
        self.assertEqual(views_source.count("bundle_service.create_uat_bundle("), 1)
        self.assertEqual(views_source.count("bundle_service.create_deployed_bundle("), 1)   # the one explicit root-sealing POST, by the run's own mode
        self.assertEqual(views_source.count("soak_service.decide("), 1, "exactly one view (the explicit decision POST) can lead to Golden")

    def test_bundle_views_are_thin_and_read_only_fields_from_the_browser(self):
        allowed = {"bundles_list": {"kind", "change"}, "bundle_detail": {"notice"}, "bundle_manifest": set(), "change_execution_bundle_create": set(),
                   "bundle_derive_probation": {"confirm"}}
        for name, fields in allowed.items():
            source = inspect.getsource(getattr(views, name))
            with self.subTest(view=name):
                self.assertEqual(set(re.findall(r"request\.(?:GET|POST)\.get\(\"([a-z_]+)\"", source)), fields)
                for forbidden in ("subprocess", "netmiko", "socket", "eval(", "exec(", "payload", "manifest=", "digest=", "kind=request", "parent="):
                    self.assertNotIn(forbidden, source.replace("bundle_manifest", "").replace("export_json", ""))
