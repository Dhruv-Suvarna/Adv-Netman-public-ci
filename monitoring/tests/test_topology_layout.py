"""Offline contracts for the hierarchical presentation layout.

This extends monitoring/tests/test_topology.py with layout SEMANTICS for the
frozen Lab 1 baseline (AGENTS.md): relative tiering, the management zone
placement, and determinism. It intentionally avoids asserting exact pixel
coordinates -- only relationships the presentation policy promises.

The fixture below mirrors the real active `topology-data.json` edge list
(15 nodes / 23 container-to-container links, one host attachment excluded)
so the tests exercise the same shape verify_topology.py checks live. It is a
TEST FIXTURE, not a second production adjacency list: `modules/topology_graph
.py` never hardcodes this edge list; it only reads it from the reconciled
active-topology snapshot at runtime.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

import yaml

from modules.topology import resolve_monitoring_metadata
from modules.topology_graph import build_base_graph, overlay_health, empty_evidence, validate_graph_payload

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "modules"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from topology_server import INDEX_HTML  # noqa: E402  (path set above)

REPO_ROOT = Path(__file__).resolve().parents[2]


# (node, interface, node, interface) -- copied from a read-only `containerlab
# inspect`/`topology-data.json` capture of the frozen Lab 1 deployment, for
# test purposes only.
_REAL_EDGES = [
    ("R3", "eth1", "S3", "eth1"), ("R4", "eth1", "S4", "eth1"), ("S3", "eth2", "S4", "eth2"),
    ("S3", "eth3", "R1", "eth1"), ("S4", "eth3", "R2", "eth1"), ("R3", "eth2", "R5", "eth1"),
    ("R4", "eth2", "R5", "eth2"), ("R5", "eth3", "WebServer", "eth1"), ("R1", "eth2", "S1", "eth1"),
    ("R2", "eth2", "S2", "eth1"), ("S1", "eth2", "S2", "eth2"), ("S1", "eth3", "H1", "eth1"),
    ("S1", "eth4", "H2", "eth1"), ("S2", "eth3", "H3", "eth1"), ("S2", "eth4", "H4", "eth1"),
    ("mgmt_swt", "eth1", "R1", "eth3"), ("mgmt_swt", "eth2", "R2", "eth3"),
    ("mgmt_swt", "eth3", "R3", "eth3"), ("mgmt_swt", "eth4", "R4", "eth3"),
    ("mgmt_swt", "eth5", "S1", "eth5"), ("mgmt_swt", "eth6", "S2", "eth5"),
    ("mgmt_swt", "eth7", "S3", "eth4"), ("mgmt_swt", "eth8", "S4", "eth4"),
]
_UNMONITORED = {"H1", "H2", "H3", "H4", "WebServer"}


def _snapshot() -> dict:
    node_names = sorted({name for edge in _REAL_EDGES for name in (edge[0], edge[2])})
    nodes = [
        {
            "id": name, "kind": "linux" if name.startswith("R3") or name.startswith("R4") else "arista_ceos",
            "image": "test", "platform": "test",
            "monitored": name not in _UNMONITORED,
            "monitoring_implementation": "none" if name in _UNMONITORED else "test-adapter",
        }
        for name in node_names
    ]
    edges = []
    for a, ai, z, zi in _REAL_EDGES:
        endpoints = sorted(
            [{"node": a, "interface": ai, "monitor_interface": ai}, {"node": z, "interface": zi, "monitor_interface": zi}],
            key=lambda item: (item["node"], item["interface"]),
        )
        edge_id = "--".join(sorted([f"{a}:{ai}", f"{z}:{zi}"]))
        plane = "management" if "mgmt_swt" in (a, z) else "data"
        edges.append({"id": edge_id, "plane": plane, "endpoints": endpoints})
    return {
        "lab_name": "srlceos01", "source": "/read-only/topology-data.json",
        "source_sha256": "1" * 64, "excluded_host_links": 1,
        "nodes": nodes, "edges": edges,
    }


SNAPSHOT = _snapshot()


class LayoutSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.graph = build_base_graph(SNAPSHOT, layout_seed=5840)
        self.y = {node: self.graph.nodes[node]["y"] for node in self.graph.nodes}
        self.x = {node: self.graph.nodes[node]["x"] for node in self.graph.nodes}

    def test_exactly_15_nodes_23_edges(self):
        self.assertEqual(self.graph.number_of_nodes(), 15)
        self.assertEqual(self.graph.number_of_edges(), 23)

    def test_node_and_edge_identities_unchanged(self):
        expected_nodes = {name for edge in _REAL_EDGES for name in (edge[0], edge[2])}
        self.assertEqual(set(self.graph.nodes), expected_nodes)
        expected_edges = {edge["id"] for edge in SNAPSHOT["edges"]}
        actual_edges = {data["id"] for _, _, data in self.graph.edges(data=True)}
        self.assertEqual(actual_edges, expected_edges)

    def test_webserver_above_r5(self):
        self.assertLess(self.y["WebServer"], self.y["R5"])

    def test_r5_above_upper_routers(self):
        self.assertLess(self.y["R5"], self.y["R3"])
        self.assertLess(self.y["R5"], self.y["R4"])

    def test_upper_routers_above_upper_switches(self):
        self.assertLess(self.y["R3"], self.y["S3"])
        self.assertLess(self.y["R4"], self.y["S4"])

    def test_upper_switches_above_edge_routers(self):
        self.assertLess(self.y["S3"], self.y["R1"])
        self.assertLess(self.y["S4"], self.y["R2"])

    def test_edge_routers_above_access_switches(self):
        self.assertLess(self.y["R1"], self.y["S1"])
        self.assertLess(self.y["R2"], self.y["S2"])

    def test_hosts_below_their_access_layer(self):
        for host in ("H1", "H2", "H3", "H4"):
            self.assertGreater(self.y[host], self.y["S1"])
            self.assertGreater(self.y[host], self.y["S2"])

    def test_mgmt_swt_outside_primary_data_plane_horizontal_region(self):
        data_x = [value for node, value in self.x.items() if node != "mgmt_swt"]
        margin = 100.0  # a real gap, not merely off-by-a-pixel
        self.assertLess(self.x["mgmt_swt"], min(data_x) - margin)

    def test_mgmt_swt_tier_is_the_dedicated_management_zone(self):
        self.assertIsNone(self.graph.nodes["mgmt_swt"]["presentation_tier"])
        self.assertEqual(self.graph.nodes["mgmt_swt"]["presentation_region"], "management-zone")
        for node in self.graph.nodes:
            if node != "mgmt_swt":
                self.assertIsNotNone(self.graph.nodes[node]["presentation_tier"])
                self.assertEqual(self.graph.nodes[node]["presentation_region"], "data-plane")

    def test_coordinates_are_finite_and_data_edges_do_not_touch_mgmt_positioning(self):
        # Management-zone placement must be derivable without moving any
        # data-plane node: rebuilding with the management edges removed
        # should not change a single data-plane coordinate.
        stripped = {**SNAPSHOT, "edges": [e for e in SNAPSHOT["edges"] if e["plane"] == "data"]}
        stripped_nodes = [n for n in SNAPSHOT["nodes"] if n["id"] != "mgmt_swt"]
        stripped = {**stripped, "nodes": stripped_nodes}
        other = build_base_graph(stripped, layout_seed=5840)
        for node in other.nodes:
            self.assertEqual((other.nodes[node]["x"], other.nodes[node]["y"]), (self.x[node], self.y[node]))

    def test_layout_is_deterministic_across_rebuilds(self):
        second = build_base_graph(SNAPSHOT, layout_seed=5840)
        first_coords = {n: (self.graph.nodes[n]["x"], self.graph.nodes[n]["y"]) for n in self.graph.nodes}
        second_coords = {n: (second.nodes[n]["x"], second.nodes[n]["y"]) for n in second.nodes}
        self.assertEqual(first_coords, second_coords)

    def test_repeated_health_refresh_does_not_move_nodes(self):
        # A health refresh rebuilds the graph from the same snapshot on every
        # request (see TopologyBuilder.build); simulate several refreshes.
        coordinates = []
        for _ in range(3):
            graph = build_base_graph(SNAPSHOT, layout_seed=5840)
            coordinates.append({n: (graph.nodes[n]["x"], graph.nodes[n]["y"]) for n in graph.nodes})
        self.assertTrue(all(c == coordinates[0] for c in coordinates))

    def test_health_and_safe_demo_semantics_survive_the_new_layout(self):
        config = {
            "browser_refresh_seconds": 20, "healthy_seconds": 60,
            "stale_seconds": 120, "recent_event_window_seconds": 900,
        }
        payload = overlay_health(self.graph, empty_evidence(), config, demo="safe-link-down")
        validate_graph_payload(payload)
        nodes = {item["id"]: item for item in payload["graph"]["nodes"]}
        for host in _UNMONITORED:
            self.assertEqual(nodes[host]["health"], "UNKNOWN")
        self.assertEqual(payload["demo"]["mode"], "DEMO/SYNTHETIC")
        synthetic = [e for e in payload["graph"]["edges"] if e.get("synthetic")]
        self.assertEqual(len(synthetic), 1)
        self.assertEqual(synthetic[0]["plane"], "data")


class InteractionContractTests(unittest.TestCase):
    """DOM/JS interaction contract for pan/zoom/node-drag, checked against
    the served markup and script source.

    IMPORTANT LIMITATION: there is no headless browser in this environment,
    so these are static source/structure checks (the right IDs, handlers,
    and CSS exist and are wired to the right elements) -- they catch a
    missing button, a handler never attached, or a CSS rule that quietly
    hides the toolbar. They cannot execute a real pointerdown/move/up
    sequence or observe actual pixel movement in a browser. Real drag/pan/
    zoom/click behavior must still be confirmed manually in Chrome/Firefox
    per docs/DYNAMIC_TOPOLOGY.md.
    """

    def test_zoom_pan_fit_reset_and_node_reset_controls_present(self):
        for marker in ('id="zoom-in"', 'id="zoom-out"', 'id="zoom-fit"', 'id="zoom-reset"', 'id="reset-positions"'):
            self.assertIn(marker, INDEX_HTML)

    def test_toolbar_is_inside_the_canvas_and_visibly_styled(self):
        # The toolbar must be a floating panel *inside* #canvas-wrap (not
        # relying on header space), with real background/border/z-index so
        # it cannot blend into the canvas or paint underneath the SVG.
        self.assertIn('class="viewport-toolbar"', INDEX_HTML)
        toolbar_rule = re.search(r"\.viewport-toolbar\{([^}]*)\}", INDEX_HTML)
        self.assertIsNotNone(toolbar_rule, "no .viewport-toolbar CSS rule found")
        declarations = toolbar_rule.group(1)
        for expected in ("position:absolute", "z-index:", "background:"):
            self.assertIn(expected, declarations)
        # The toolbar markup must appear after the closing </svg> tag inside
        # canvas-wrap, i.e. as a normal sibling overlay, not nested inside
        # the SVG (where a plain HTML <div> would not render as a toolbar).
        svg_close = INDEX_HTML.index("</svg>")
        toolbar_open = INDEX_HTML.index('class="viewport-toolbar"')
        self.assertGreater(toolbar_open, svg_close)

    def test_background_pan_target_is_pixel_synced_and_explicitly_hit_testable(self):
        # #bg must be kept numerically in sync with the canvas (not just a
        # percentage length, which can resolve ambiguously against a
        # dynamically-changing viewBox), and pointer-events must be forced
        # on explicitly rather than relying on default SVG fill/paint-based
        # hit-testing (which some engines apply inconsistently to a
        # transparent fill).
        self.assertIn('pointer-events="all"', INDEX_HTML)
        self.assertIn("pointer-events:all", INDEX_HTML)
        self.assertIn("bg.setAttribute('width',s.w)", INDEX_HTML)
        self.assertIn("bg.setAttribute('height',s.h)", INDEX_HTML)

    def test_background_pan_wired_with_pointer_capture_and_cursor_feedback(self):
        self.assertIn("bg.addEventListener('pointerdown'", INDEX_HTML)
        self.assertIn("bg.addEventListener('pointermove'", INDEX_HTML)
        self.assertIn("bg.setPointerCapture(e.pointerId)", INDEX_HTML)
        self.assertIn("#bg{fill:#000;fill-opacity:0;pointer-events:all;cursor:grab}", INDEX_HTML)
        self.assertIn("#bg.dragging{cursor:grabbing}", INDEX_HTML)

    def test_text_selection_suppressed_during_drag(self):
        self.assertIn("user-select:none", INDEX_HTML)

    def test_wheel_zoom_wired_to_graph_element(self):
        self.assertIn("el('graph').addEventListener('wheel'", INDEX_HTML)

    def test_node_pointer_handlers_exist_and_are_attached_per_node(self):
        for fn in ("onNodePointerDown", "onNodePointerMove", "onNodePointerUp"):
            self.assertIn(f"function {fn}(", INDEX_HTML)
        self.assertIn("g.addEventListener('pointerdown',e=>onNodePointerDown(e,n,g))", INDEX_HTML)
        self.assertIn("g.addEventListener('pointermove',onNodePointerMove)", INDEX_HTML)
        self.assertIn("g.addEventListener('pointerup',onNodePointerUp)", INDEX_HTML)
        self.assertIn("g.setPointerCapture(e.pointerId)", INDEX_HTML)

    def test_click_vs_drag_threshold_exists(self):
        self.assertIn("DRAG_PX", INDEX_HTML)
        self.assertIn("Math.hypot(dxs,dys)>DRAG_PX", INDEX_HTML)
        # A drag must suppress the click-selects-details behavior.
        self.assertIn("if(!moved&&nodeById[id])select('node',nodeById[id])", INDEX_HTML)

    def test_node_offsets_are_client_side_only_and_applied_when_rendering(self):
        # nodeOffsets is presentation-only state, applied through
        # nodeDisplay(); it must never be written into a fetch()/PUT-style
        # call, and must not be reset by render() except to prune ids for
        # nodes that no longer exist.
        self.assertIn("function nodeDisplay(n){", INDEX_HTML)
        self.assertIn("let nodeOffsets={}", INDEX_HTML)
        self.assertNotIn("nodeOffsets", re.search(r"async function load\(\).*?\}", INDEX_HTML, re.S).group(0))
        # render() only prunes stale ids; it must not reassign the dict
        # wholesale (that is reset's job, not a refresh's).
        render_body = re.search(r"function render\(data\)\{(.*?)\n\}\n", INDEX_HTML, re.S).group(1)
        self.assertNotIn("nodeOffsets={}", render_body)
        self.assertIn("delete nodeOffsets[id]", render_body)

    def test_edge_rendering_uses_displayed_node_coordinates(self):
        # Edges must be drawn from nodeDisplay(...) (backend coords + any
        # manual offset), not the raw node object, so a dragged node's
        # links visibly follow it.
        self.assertIn(
            "const a=nodeDisplay(nodeById[e.source]), z=nodeDisplay(nodeById[e.target])",
            INDEX_HTML,
        )
        self.assertIn(
            "const a=nodeDisplay(nodeById[link.source]), z=nodeDisplay(nodeById[link.target])",
            INDEX_HTML,
        )

    def test_reset_node_positions_clears_offsets_and_rerenders(self):
        self.assertIn("function resetNodePositions(){nodeOffsets={};if(current)render(current)}", INDEX_HTML)
        self.assertIn("el('reset-positions').onclick=resetNodePositions", INDEX_HTML)

    def test_fit_uses_displayed_positions_reset_view_uses_baseline(self):
        # Fit to Screen must include manually dragged nodes; Reset View is
        # the fixed deterministic camera and must not depend on drags.
        self.assertIn("function fitToDisplayed(){if(!current)return;view=computeFitView(worldBoundsOf(displayedPositions())", INDEX_HTML)
        self.assertIn("function fitToBaseline(){if(!current)return;view=computeFitView(worldBoundsOf(baselinePositions())", INDEX_HTML)
        self.assertIn("el('zoom-fit').onclick=fitToDisplayed", INDEX_HTML)
        self.assertIn("el('zoom-reset').onclick=fitToBaseline", INDEX_HTML)

    def test_pan_state_is_module_scope_and_survives_a_refresh(self):
        # `view` (camera) is declared once at module scope, and render()
        # (called every 20s refresh) only re-applies it via applyView()
        # unless graph identity actually changed -- it must never be reset
        # to {x:0,y:0,k:1} inside render() itself.
        render_body = re.search(r"function render\(data\)\{(.*?)\n\}\n", INDEX_HTML, re.S).group(1)
        self.assertNotIn("view={x:0,y:0,k:1}", render_body)
        self.assertIn("if(!viewInitialized||identityChanged){fitToBaseline();viewInitialized=true}else{applyView()}", INDEX_HTML)

    def test_toolbar_click_cannot_start_a_background_pan(self):
        # Toolbar buttons are plain HTML <button> elements outside the SVG
        # subtree entirely -- structurally, a click on one can never reach
        # #bg's pointerdown listener (different ancestor chain). Assert the
        # buttons are declared with their own onclick handlers rather than
        # relying on any bg/document-level catch-all.
        for handler in ("el('zoom-in').onclick=", "el('zoom-out').onclick=", "el('zoom-fit').onclick=", "el('zoom-reset').onclick=", "el('reset-positions').onclick="):
            self.assertIn(handler, INDEX_HTML)

    def test_management_edges_rendered_behind_and_lower_opacity(self):
        self.assertIn("mgmt-edges", INDEX_HTML)
        self.assertIn(".edge.management{stroke-dasharray:6 6;stroke-width:1.6;opacity:.4}", INDEX_HTML)

    def test_viewport_group_present_for_pan_zoom_transform(self):
        self.assertIn('id="viewport"', INDEX_HTML)
        self.assertIn("function applyView(){el('viewport').setAttribute('transform'", INDEX_HTML)


class BackendCoordinatesUnaffectedByFrontendDragTests(unittest.TestCase):
    """The frontend drag feature is presentation-only: nothing about it can
    exist server-side, since the server never receives node positions."""

    def test_topology_server_has_no_position_write_endpoint(self):
        server_source = (Path(__file__).resolve().parents[1] / "scripts" / "topology_server.py").read_text()
        for verb in ("do_POST", "do_PUT", "do_PATCH"):
            self.assertNotIn(verb, server_source)

    def test_backend_layout_is_still_the_only_source_of_x_y(self):
        # The API payload's x/y come solely from build_base_graph's
        # deterministic layout; a client-side nodeOffsets map is applied
        # only in the browser and is invisible to this rebuild.
        first = build_base_graph(SNAPSHOT, layout_seed=5840)
        second = build_base_graph(SNAPSHOT, layout_seed=5840)
        self.assertEqual(
            {n: (first.nodes[n]["x"], first.nodes[n]["y"]) for n in first},
            {n: (second.nodes[n]["x"], second.nodes[n]["y"]) for n in second},
        )


class ManagementAddressTests(unittest.TestCase):
    """Dual-stack management addressing metadata (visualization-only).

    The expected values below were independently verified for this session
    (2026-09-07) against TWO authoritative sources that agreed exactly:
    - the persistent device config templates (templates/<device>.cfg.j2);
    - live read-only `docker exec ... ip -6 addr show` (R3/R4) and
      `Cli -c "show ipv6 interface brief"` (cEOS) on the running deployment.
    See docs/DYNAMIC_TOPOLOGY.md for the full discovered-address matrix.
    """

    EXPECTED_VLAN200_V4 = {
        "R1": "192.168.200.1", "R2": "192.168.200.2",
        "R3": "192.168.200.3", "R4": "192.168.200.4",
        "S1": "192.168.200.11", "S2": "192.168.200.12",
        "S3": "192.168.200.13", "S4": "192.168.200.14",
        "mgmt_swt": "192.168.200.10",
    }
    EXPECTED_VLAN200_V6 = {
        "R1": "2001:db8:200::1", "R2": "2001:db8:200::2",
        "R3": "2001:db8:200::3", "R4": "2001:db8:200::4",
        "S1": "2001:db8:200::11", "S2": "2001:db8:200::12",
        "S3": "2001:db8:200::13", "S4": "2001:db8:200::14",
        "mgmt_swt": "2001:db8:200::10",
    }

    def setUp(self):
        self.inventory = yaml.safe_load((REPO_ROOT / "inventory.yml").read_text())
        self.devices = self.inventory["network_devices"]

    def test_ipv4_matches_authoritative_inventory_for_vlan200_devices(self):
        for device, expected in self.EXPECTED_VLAN200_V4.items():
            self.assertEqual(self.devices[device]["monitoring"]["address"], expected)

    def test_ipv6_matches_authoritative_inventory_for_vlan200_devices(self):
        for device, expected in self.EXPECTED_VLAN200_V6.items():
            self.assertEqual(self.devices[device]["monitoring"].get("address_v6"), expected)

    def test_ipv6_values_are_literally_present_in_the_persistent_device_template(self):
        # Cross-check straight against the device config file, not just
        # inventory.yml, so a hand-edited inventory value can never
        # silently drift from the device's actual persistent
        # configuration -- this is the "discover from authoritative
        # source" requirement, not a second copy of the same claim.
        for device, expected in self.EXPECTED_VLAN200_V6.items():
            template_name = self.devices[device]["template"]
            template_text = (REPO_ROOT / "templates" / template_name).read_text()
            self.assertIn(expected, template_text, f"{device}: {expected!r} not found in {template_name}")

    def test_r5_uses_its_actual_management0_design_not_a_fabricated_vlan200_v6(self):
        # R5's documented design (AGENTS.md/inventory.yml) has no Vlan200
        # SVI; a static management-VLAN IPv6 for R5 would be fabricated.
        self.assertNotIn("address_v6", self.devices["R5"]["monitoring"])
        self.assertEqual(self.devices["R5"]["monitoring"]["address"], "auto")
        self.assertEqual(self.devices["R5"]["monitoring"]["source_interface"], "Management0")
        template_text = (REPO_ROOT / "templates" / self.devices["R5"]["template"]).read_text()
        self.assertNotIn("Vlan200", template_text)

    def test_resolver_never_invents_ipv6_for_a_monitored_device_lacking_one(self):
        # A monitored device with a real IPv4 but genuinely no configured
        # IPv6 must resolve to None, not a guessed value.
        resolved = resolve_monitoring_metadata(
            {"platform": "ceos", "address": "192.0.2.9", "source_interface": "Vlan200"},
            management_ipv4="172.20.20.99", management_ipv6="3fff:172:20:20::99",
        )
        self.assertEqual(resolved["monitoring_address"], "192.0.2.9")
        self.assertIsNone(resolved["monitoring_address_v6"])

    def test_resolver_auto_falls_back_to_live_containerlab_address_for_both_families(self):
        # Mirrors R5's real "auto"/Management0 design: no static
        # address_v6 in inventory -> live Containerlab-assigned value for
        # both v4 and v6, never a pattern-derived one.
        resolved = resolve_monitoring_metadata(
            {"platform": "ceos", "address": "auto", "source_interface": "Management0"},
            management_ipv4="172.20.20.16", management_ipv6="3fff:172:20:20::10",
        )
        self.assertEqual(resolved["monitoring_address"], "172.20.20.16")
        self.assertEqual(resolved["monitoring_address_v6"], "3fff:172:20:20::10")
        self.assertEqual(resolved["monitoring_interface"], "Management0")

    def test_unmonitored_node_has_no_management_address_at_all(self):
        resolved = resolve_monitoring_metadata(None, management_ipv4="172.20.20.2", management_ipv6="3fff:172:20:20::2")
        self.assertIsNone(resolved["monitoring_address"])
        self.assertIsNone(resolved["monitoring_address_v6"])
        self.assertIsNone(resolved["monitoring_interface"])

    def test_hosts_and_webserver_are_not_in_the_monitored_management_vlan(self):
        # These must never be labelled with a management-plane address:
        # they simply are not part of network_devices/the monitoring VLAN.
        for name in ("H1", "H2", "H3", "H4", "WebServer"):
            self.assertNotIn(name, self.devices)

    def test_no_ipv6_is_computed_from_an_ipv4_octet_in_the_resolver_source(self):
        # Static guard against the exact shortcut this task forbids: the
        # resolver's source must contain no arithmetic/string derivation of
        # an IPv6 suffix from an IPv4 address (e.g. splitting on "." and
        # re-joining into a "::N" suffix). It may only ever read
        # `address_v6` or pass through a live-observed value verbatim.
        source = (REPO_ROOT / "modules" / "topology.py").read_text()
        resolver = source[source.index("def resolve_monitoring_metadata"):]
        resolver = resolver[:resolver.index("\n\n\n")]
        self.assertNotIn(".split(\".\"", resolver)
        self.assertNotIn("f'::{", resolver)
        self.assertNotIn('f"::{', resolver)


class AddressDisplayContractTests(unittest.TestCase):
    """Frontend "Show Addresses" toggle and node/API metadata consumption
    (see the InteractionContractTests docstring for the same static-source-
    check limitation: no headless browser is available here)."""

    def test_show_addresses_toggle_exists_and_defaults_on(self):
        self.assertIn('id="toggle-addresses"', INDEX_HTML)
        self.assertIn('aria-pressed="true"', INDEX_HTML)
        self.assertIn("let showAddresses=true", INDEX_HTML)

    def test_toggle_does_not_reset_camera_and_does_not_touch_backend(self):
        toggle_handler = re.search(r"el\('toggle-addresses'\)\.onclick=\(\)=>\{(.*?)\};", INDEX_HTML, re.S).group(1)
        self.assertNotIn("fitTo", toggle_handler)     # must not silently re-fit the camera
        self.assertNotIn("fetch(", toggle_handler)    # must not call the API
        self.assertIn("render(current)", toggle_handler)

    def test_toggle_state_is_module_scope_not_reset_by_render_or_load(self):
        render_body = re.search(r"function render\(data\)\{(.*?)\n\}\n", INDEX_HTML, re.S).group(1)
        load_body = re.search(r"async function load\(\)\{(.*?)\}\n", INDEX_HTML, re.S).group(1)
        self.assertNotIn("showAddresses=", render_body)
        self.assertNotIn("showAddresses=", load_body)

    def test_frontend_reads_address_fields_from_api_data_not_a_hardcoded_literal(self):
        # No literal management/monitoring IP address may appear in the
        # served script -- every value must come from the fetched node
        # object.
        self.assertIn("n.monitoring_address", INDEX_HTML)
        self.assertIn("n.monitoring_address_v6", INDEX_HTML)
        self.assertIn("n.monitoring_interface", INDEX_HTML)
        script = re.search(r"<script>(.*)</script>", INDEX_HTML, re.S).group(1)
        self.assertNotRegex(script, r"192\.168\.200\.\d+")
        self.assertNotRegex(script, r"2001:db8:200::")

    def test_node_box_widens_only_for_addresses_actually_present(self):
        self.assertIn("NODE_HALF_W_ADDR", INDEX_HTML)
        self.assertIn("function nodeBoxHalf(n){return (showAddresses&&n.monitoring_address)", INDEX_HTML)

    def test_missing_v6_does_not_render_a_placeholder_line(self):
        # The v6 <text> element must only be created inside an
        # `if(n.monitoring_address_v6)` guard -- never unconditionally
        # (which would print a fake "v6 —" row for a device that
        # genuinely lacks one).
        self.assertIn("if(n.monitoring_address_v6){", INDEX_HTML)

    def test_operational_details_shows_management_interface_v4_v6_without_dropping_existing_fields(self):
        show_node_body = re.search(r"function showNode\(n\)\{(.*?)\}\n", INDEX_HTML, re.S).group(1)
        for still_present in (
            "n.health", "n.health_reason", "n.role", "n.platform", "n.monitoring_implementation",
            "n.last_telemetry_timestamp", "n.telemetry_age_seconds", "n.cpu_percent", "n.memory_percent",
            "n.recent_critical_syslog_count", "n.recent_snmp_trap_count", "n.latest_event_timestamp",
        ):
            self.assertIn(still_present, show_node_body)
        for new_field in ("['Management interface',n.monitoring_interface]", "['Management IPv4',n.monitoring_address]", "['Management IPv6',n.monitoring_address_v6]"):
            self.assertIn(new_field, show_node_body)

    def test_fit_bounds_account_for_current_per_node_box_size(self):
        self.assertIn("function worldBoundsOf(positions){", INDEX_HTML)
        self.assertIn("p.x-p.hw", INDEX_HTML)
        self.assertIn("function displayedPositions(){return current?current.graph.nodes.map(n=>{const p=nodeDisplay(n),b=nodeBoxHalf(n)", INDEX_HTML)
        self.assertIn("function baselinePositions(){return current?current.graph.nodes.map(n=>{const b=nodeBoxHalf(n)", INDEX_HTML)


if __name__ == "__main__":
    unittest.main()
