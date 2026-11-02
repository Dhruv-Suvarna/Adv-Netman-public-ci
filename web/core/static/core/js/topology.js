/* Phase 5 read-only SVG topology renderer.
 *
 * The API payload remains authoritative.  Pan, zoom, address visibility and
 * nodeOffsets are presentation state held only in this closure.  This file
 * issues GET requests only and has no topology mutation endpoint.
 */
(function () {
  "use strict";

  var root = document.getElementById("topology-root");
  if (!root) return;

  var NS = "http://www.w3.org/2000/svg";
  var COLORS = {
    HEALTHY: "var(--topology-healthy)", STALE: "var(--topology-stale)",
    OFFLINE: "var(--topology-offline)", UNKNOWN: "var(--topology-unknown)",
    UP: "var(--topology-up)", DOWN: "var(--topology-down)",
    DEGRADED: "var(--topology-degraded)"
  };
  var MIN_ZOOM = 0.2, MAX_ZOOM = 4, NODE_W = 39, NODE_H = 25;
  var NODE_W_ADDRESSES = 68, NODE_H_ADDRESSES = 38, WORLD_PAD = 90, DRAG_PX = 4;
  var current = null, selected = null, lastSignature = null;
  var view = { x: 0, y: 0, k: 1 }, viewInitialized = false, manuallyAdjusted = false;
  var panDrag = null, nodeDrag = null;
  var nodeOffsets = {}; // Presentation-only; never serialized or sent anywhere.
  var showAddresses = true;
  var nodeById = {}, nodeElementsById = {}, edgeLinksByNode = {};

  function el(id) { return document.getElementById(id); }
  function svgEl(name) { return document.createElementNS(NS, name); }
  function fmt(value) { return value === null || value === undefined || value === "" ? "—" : String(value); }
  function age(value) { return value === null || value === undefined ? "—" : Number(value).toFixed(1) + " s"; }
  function add(parent, name, text) {
    var child = document.createElement(name);
    child.textContent = text;
    parent.appendChild(child);
    return child;
  }
  function detailGrid(rows) {
    var list = document.createElement("dl");
    list.className = "topology-detail-grid";
    rows.forEach(function (row) {
      add(list, "dt", row[0]);
      add(list, "dd", fmt(row[1]));
    });
    return list;
  }

  function connectedNeighbors(nodeId) {
    if (!current) return "—";
    return current.graph.edges.filter(function (edge) {
      return edge.source === nodeId || edge.target === nodeId;
    }).map(function (edge) {
      return edge.source === nodeId ? edge.target : edge.source;
    }).sort().join(", ") || "—";
  }

  function showNode(node) {
    var details = el("topology-details");
    details.textContent = "";
    details.className = "";
    add(details, "h4", node.canonical_name || node.id);
    details.appendChild(detailGrid([
      ["Health", node.health], ["Reason", node.health_reason], ["Role", node.role],
      ["Platform", node.platform], ["Image", node.image], ["Runtime", node.runtime_state],
      ["Mgmt interface", node.monitoring_interface], ["Monitoring IPv4", node.monitoring_address],
      ["Monitoring IPv6", node.monitoring_address_v6], ["Container IPv4", node.management_ipv4],
      ["Container IPv6", node.management_ipv6], ["Monitoring", node.monitoring_implementation],
      ["Telemetry time", node.last_telemetry_timestamp], ["Telemetry age", age(node.telemetry_age_seconds)],
      ["CPU", node.cpu_percent === null ? "—" : node.cpu_percent + "%"],
      ["Memory", node.memory_percent === null ? "—" : node.memory_percent + "%"],
      ["Critical syslog", node.recent_critical_syslog_count], ["SNMP traps", node.recent_snmp_trap_count],
      ["Latest event", node.latest_event_timestamp], ["Neighbors", connectedNeighbors(node.id)]
    ]));
  }

  function showEdge(edge) {
    var details = el("topology-details");
    details.textContent = "";
    details.className = "";
    add(details, "h4", edge.id);
    details.appendChild(detailGrid([
      ["State", edge.status], ["Reason", edge.health_reason], ["Evidence", edge.status_source],
      ["Plane", edge.plane], ["Endpoints", edge.source + " ↔ " + edge.target],
      ["State updated", edge.last_state_update], ["Link events", edge.recent_link_event_count],
      ["Latest event", edge.latest_link_event]
    ]));
    (edge.endpoint_state || edge.endpoints || []).forEach(function (endpoint) {
      var box = document.createElement("div");
      box.className = "topology-endpoint";
      add(box, "strong", fmt(endpoint.node) + " · " + fmt(endpoint.monitor_interface));
      box.appendChild(detailGrid([
        ["Container iface", endpoint.interface], ["Admin", endpoint.admin_status],
        ["Oper", endpoint.oper_status], ["Evidence age", age(endpoint.age_seconds)],
        ["Fresh evidence", endpoint.evidence_fresh], ["Errors", endpoint.errors],
        ["Discards", endpoint.discards]
      ]));
      details.appendChild(box);
    });
  }

  function select(kind, item) {
    selected = { kind: kind, id: item.id };
    document.querySelectorAll(".topology-selected").forEach(function (target) {
      target.classList.remove("topology-selected");
    });
    var target = document.querySelector('[data-topology-kind="' + kind + '"][data-topology-id="' + CSS.escape(item.id) + '"]');
    if (target) target.classList.add("topology-selected");
    if (kind === "node") showNode(item); else showEdge(item);
  }

  function containerSize() {
    var bounds = el("topology-graph").getBoundingClientRect();
    return { w: Math.max(bounds.width, 300), h: Math.max(bounds.height, 300) };
  }
  function updateViewBox() {
    var size = containerSize(), svg = el("topology-graph"), bg = el("topology-bg");
    svg.setAttribute("viewBox", "0 0 " + size.w + " " + size.h);
    bg.setAttribute("x", 0); bg.setAttribute("y", 0);
    bg.setAttribute("width", size.w); bg.setAttribute("height", size.h);
  }
  function worldBounds(positions) {
    return {
      xmin: Math.min.apply(null, positions.map(function (p) { return p.x - p.hw; })) - WORLD_PAD,
      xmax: Math.max.apply(null, positions.map(function (p) { return p.x + p.hw; })) + WORLD_PAD,
      ymin: Math.min.apply(null, positions.map(function (p) { return p.y - p.hh; })) - WORLD_PAD,
      ymax: Math.max.apply(null, positions.map(function (p) { return p.y + p.hh; })) + WORLD_PAD
    };
  }
  function computeFit(bounds, size) {
    var width = Math.max(bounds.xmax - bounds.xmin, 1);
    var height = Math.max(bounds.ymax - bounds.ymin, 1);
    var scale = Math.min(size.w / width, size.h / height, MAX_ZOOM) || 1;
    var centerX = (bounds.xmin + bounds.xmax) / 2, centerY = (bounds.ymin + bounds.ymax) / 2;
    scale = Math.max(scale, MIN_ZOOM);
    return { x: size.w / 2 - centerX * scale, y: size.h / 2 - centerY * scale, k: scale };
  }
  function applyView() {
    el("topology-viewport").setAttribute("transform", "translate(" + view.x + "," + view.y + ") scale(" + view.k + ")");
  }
  function nodeDisplay(node) {
    var offset = nodeOffsets[node.id];
    return offset ? { x: node.x + offset.dx, y: node.y + offset.dy } : { x: node.x, y: node.y };
  }
  function nodeHalfBox(node) {
    return showAddresses && node.monitoring_address ? { hw: NODE_W_ADDRESSES, hh: NODE_H_ADDRESSES } : { hw: NODE_W, hh: NODE_H };
  }
  function positions(useOffsets) {
    return current.graph.nodes.map(function (node) {
      var point = useOffsets ? nodeDisplay(node) : { x: node.x, y: node.y };
      var box = nodeHalfBox(node);
      return { x: point.x, y: point.y, hw: box.hw, hh: box.hh };
    });
  }
  function fitDisplayed() {
    if (!current) return;
    view = computeFit(worldBounds(positions(true)), containerSize());
    manuallyAdjusted = false; applyView();
  }
  function resetView() {
    if (!current) return;
    view = computeFit(worldBounds(positions(false)), containerSize());
    manuallyAdjusted = false; applyView();
  }
  function zoomBy(factor, cx, cy) {
    var next = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, view.k * factor));
    var worldX = (cx - view.x) / view.k, worldY = (cy - view.y) / view.k;
    view.k = next; view.x = cx - worldX * next; view.y = cy - worldY * next;
    manuallyAdjusted = true; applyView();
  }
  function zoomCenter(factor) {
    var size = containerSize(); zoomBy(factor, size.w / 2, size.h / 2);
  }

  function updateNodeAndEdges(nodeId) {
    var entry = nodeElementsById[nodeId];
    if (!entry) return;
    var point = nodeDisplay(entry.data);
    entry.group.setAttribute("transform", "translate(" + point.x + "," + point.y + ")");
    (edgeLinksByNode[nodeId] || []).forEach(function (link) {
      var a = nodeDisplay(nodeById[link.source]), z = nodeDisplay(nodeById[link.target]);
      [link.line, link.hit].forEach(function (line) {
        line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
        line.setAttribute("x2", z.x); line.setAttribute("y2", z.y);
      });
    });
  }

  function resetNodePositions() {
    nodeOffsets = {};
    if (current) render(current);
  }

  function accessibleSelect(group, kind, item) {
    group.setAttribute("tabindex", "0");
    group.setAttribute("role", "button");
    group.setAttribute("aria-label", (kind === "node" ? "Device " : "Link ") + item.id + ", " + (item.health || item.status));
    group.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(kind, item); }
    });
  }

  function render(data) {
    nodeDrag = null; panDrag = null; current = data;
    var nodes = data.graph.nodes, edges = data.graph.edges;
    Object.keys(nodeOffsets).forEach(function (id) {
      if (!nodes.some(function (node) { return node.id === id; })) delete nodeOffsets[id];
    });
    var signature = JSON.stringify({
      nodes: nodes.map(function (node) { return [node.id, node.x, node.y]; }).sort(),
      edges: edges.map(function (edge) { return [edge.id, edge.source, edge.target]; }).sort()
    });
    var identityChanged = signature !== lastSignature;
    lastSignature = signature;
    updateViewBox();
    var mgmt = el("topology-mgmt-edges"), dataLayer = el("topology-data-edges"), nodeLayer = el("topology-nodes");
    mgmt.textContent = ""; dataLayer.textContent = ""; nodeLayer.textContent = "";
    nodeById = {}; nodeElementsById = {}; edgeLinksByNode = {};
    nodes.forEach(function (node) { nodeById[node.id] = node; });

    edges.slice().sort(function (a, b) { return (a.plane === "management") - (b.plane === "management"); }).forEach(function (edge) {
      var a = nodeDisplay(nodeById[edge.source]), z = nodeDisplay(nodeById[edge.target]);
      var layer = edge.plane === "management" ? mgmt : dataLayer;
      var line = svgEl("line");
      line.setAttribute("x1", a.x); line.setAttribute("y1", a.y); line.setAttribute("x2", z.x); line.setAttribute("y2", z.y);
      line.setAttribute("stroke", COLORS[edge.status] || COLORS.UNKNOWN);
      line.classList.add("topology-edge"); if (edge.plane === "management") line.classList.add("management");
      line.dataset.topologyKind = "edge"; line.dataset.topologyId = edge.id;
      line.addEventListener("click", function () { select("edge", edge); });
      accessibleSelect(line, "edge", edge);
      var title = svgEl("title"); title.textContent = edge.id + " · " + edge.status + " · click for interface evidence"; line.appendChild(title);
      layer.appendChild(line);
      var hit = line.cloneNode(false); hit.classList.remove("topology-edge", "management"); hit.classList.add("topology-edge-hit");
      hit.removeAttribute("tabindex"); hit.removeAttribute("role"); hit.removeAttribute("aria-label");
      hit.addEventListener("click", function () { select("edge", edge); }); layer.appendChild(hit);
      var link = { source: edge.source, target: edge.target, line: line, hit: hit };
      (edgeLinksByNode[edge.source] || (edgeLinksByNode[edge.source] = [])).push(link);
      (edgeLinksByNode[edge.target] || (edgeLinksByNode[edge.target] = [])).push(link);
    });

    nodes.forEach(function (node) {
      var point = nodeDisplay(node), box = nodeHalfBox(node), displayAddress = showAddresses && !!node.monitoring_address;
      var group = svgEl("g"); group.classList.add("topology-node");
      group.dataset.topologyKind = "node"; group.dataset.topologyId = node.id;
      group.setAttribute("transform", "translate(" + point.x + "," + point.y + ")");
      accessibleSelect(group, "node", node);
      var rect = svgEl("rect"); rect.setAttribute("x", -box.hw); rect.setAttribute("y", -box.hh);
      rect.setAttribute("width", box.hw * 2); rect.setAttribute("height", box.hh * 2); rect.setAttribute("rx", 10);
      rect.setAttribute("fill", "#10243a"); rect.setAttribute("stroke", COLORS[node.health] || COLORS.UNKNOWN); group.appendChild(rect);
      var label = svgEl("text"); label.setAttribute("y", displayAddress ? -21 : -2); label.textContent = node.id; group.appendChild(label);
      var role = svgEl("text"); role.classList.add("topology-role"); role.setAttribute("y", displayAddress ? -7 : 14); role.textContent = node.role; group.appendChild(role);
      if (displayAddress) {
        var v4 = svgEl("text"); v4.classList.add("topology-address"); v4.setAttribute("y", 7); v4.textContent = "v4 " + node.monitoring_address; group.appendChild(v4);
        if (node.monitoring_address_v6) {
          var v6 = svgEl("text"); v6.classList.add("topology-address"); v6.setAttribute("y", 21); v6.textContent = "v6 " + node.monitoring_address_v6; group.appendChild(v6);
        }
      }
      var nodeTitle = svgEl("title"); nodeTitle.textContent = node.id + " · " + node.health + " · " + node.health_reason; group.appendChild(nodeTitle);
      group.addEventListener("pointerdown", function (event) {
        event.stopPropagation();
        var offset = nodeOffsets[node.id] || { dx: 0, dy: 0 };
        nodeDrag = { id: node.id, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, startDx: offset.dx, startDy: offset.dy, moved: false };
        group.setPointerCapture(event.pointerId); group.classList.add("dragging");
      });
      group.addEventListener("pointermove", onNodePointerMove);
      group.addEventListener("pointerup", onNodePointerUp);
      group.addEventListener("pointercancel", onNodePointerUp);
      nodeLayer.appendChild(group); nodeElementsById[node.id] = { group: group, data: node };
    });

    if (!viewInitialized || identityChanged) { resetView(); viewInitialized = true; } else { applyView(); }
    root.classList.remove("is-unavailable"); el("topology-unavailable").hidden = true;
    var backendStatus = data.backend && data.backend.status ? data.backend.status : "UNKNOWN";
    el("topology-status").textContent = "Last refreshed " + data.generated_at + " · backend " + backendStatus + " · " + nodes.length + " nodes / " + edges.length + " links · auto " + data.refresh_interval_seconds + "s";
    el("topology-status").classList.toggle("is-error", backendStatus !== "OK");
    el("topology-mode").textContent = "LIVE / READ-ONLY";
    el("topology-mode").className = "badge " + (backendStatus === "OK" ? "badge--success" : "badge--warning");
    if (selected) {
      var list = selected.kind === "node" ? nodes : edges;
      var selectedItem = list.find(function (item) { return item.id === selected.id; });
      if (selectedItem) select(selected.kind, selectedItem);
    }
  }

  function onNodePointerMove(event) {
    if (!nodeDrag || event.pointerId !== nodeDrag.pointerId) return;
    var dx = event.clientX - nodeDrag.startX, dy = event.clientY - nodeDrag.startY;
    if (!nodeDrag.moved && Math.hypot(dx, dy) > DRAG_PX) nodeDrag.moved = true;
    if (!nodeDrag.moved) return;
    nodeOffsets[nodeDrag.id] = { dx: nodeDrag.startDx + dx / view.k, dy: nodeDrag.startDy + dy / view.k };
    updateNodeAndEdges(nodeDrag.id);
  }
  function onNodePointerUp(event) {
    if (!nodeDrag || event.pointerId !== nodeDrag.pointerId) return;
    var id = nodeDrag.id, moved = nodeDrag.moved;
    if (nodeElementsById[id]) nodeElementsById[id].group.classList.remove("dragging");
    nodeDrag = null;
    if (!moved && nodeById[id]) select("node", nodeById[id]);
  }

  function markUnavailable() {
    root.classList.add("is-unavailable");
    el("topology-unavailable").hidden = false;
    el("topology-status").textContent = "Topology service temporarily unavailable." + (current ? " Displayed data is stale." : "");
    el("topology-status").classList.add("is-error");
    el("topology-mode").textContent = current ? "STALE / READ-ONLY" : "UNAVAILABLE";
    el("topology-mode").className = "badge badge--warning";
  }

  function load() {
    return window.fetch(root.dataset.topologyEndpoint, {
      method: "GET", credentials: "same-origin", cache: "no-store",
      headers: { "Accept": "application/json" }
    }).then(function (response) {
      if (!response.ok) throw new Error("topology unavailable");
      return response.json();
    }).then(render).catch(markUnavailable);
  }

  el("topology-reload").addEventListener("click", load);
  el("topology-zoom-in").addEventListener("click", function () { zoomCenter(1.3); });
  el("topology-zoom-out").addEventListener("click", function () { zoomCenter(1 / 1.3); });
  el("topology-fit").addEventListener("click", fitDisplayed);
  el("topology-reset-view").addEventListener("click", resetView);
  el("topology-reset-positions").addEventListener("click", resetNodePositions);
  el("topology-toggle-addresses").addEventListener("click", function () {
    showAddresses = !showAddresses;
    this.setAttribute("aria-pressed", String(showAddresses));
    this.setAttribute("aria-label", showAddresses ? "Hide addresses" : "Show addresses");
    this.textContent = showAddresses ? "Hide Addresses" : "Show Addresses";
    if (current) render(current);
  });
  el("topology-graph").addEventListener("wheel", function (event) {
    event.preventDefault();
    var bounds = el("topology-graph").getBoundingClientRect();
    zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.clientX - bounds.left, event.clientY - bounds.top);
  }, { passive: false });

  var background = el("topology-bg");
  background.addEventListener("pointerdown", function (event) {
    if (event.button !== 0) return;
    panDrag = { pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, startViewX: view.x, startViewY: view.y };
    background.classList.add("dragging"); background.setPointerCapture(event.pointerId); event.preventDefault();
  });
  background.addEventListener("pointermove", function (event) {
    if (!panDrag || event.pointerId !== panDrag.pointerId) return;
    view.x = panDrag.startViewX + event.clientX - panDrag.startX;
    view.y = panDrag.startViewY + event.clientY - panDrag.startY;
    manuallyAdjusted = true; applyView();
  });
  function endPan(event) {
    if (panDrag && (!event || event.pointerId === panDrag.pointerId)) { panDrag = null; background.classList.remove("dragging"); }
  }
  background.addEventListener("pointerup", endPan);
  background.addEventListener("pointercancel", endPan);
  window.addEventListener("resize", function () { updateViewBox(); if (current && !manuallyAdjusted) fitDisplayed(); });

  var initialScript = el("topology-initial-data"), initial = null;
  try { initial = initialScript ? JSON.parse(initialScript.textContent) : null; } catch (error) { initial = null; }
  if (initial) render(initial); else markUnavailable();
  var refreshSeconds = Number(root.dataset.refreshSeconds);
  if (!Number.isFinite(refreshSeconds) || refreshSeconds < 10 || refreshSeconds > 300) refreshSeconds = 20;
  window.setInterval(load, refreshSeconds * 1000);
}());
