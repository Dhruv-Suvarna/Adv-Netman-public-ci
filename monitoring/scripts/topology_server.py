#!/usr/bin/env python3
"""Localhost-only HTTP/API presentation for the NMAS NetworkX graph."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
from urllib.parse import parse_qs, urlparse

from topology_graph import DEMO_MODE, InfluxEvidence, TopologyBuilder  # pylint: disable=import-error  # resolved through the sys.path the script sets up for modules/

ETC = Path("/etc/nmas-topology")

INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NMAS Dynamic Network Topology</title>
<style>
:root{color-scheme:dark;--bg:#07111f;--panel:#0d1b2d;--line:#263a52;--text:#e7eef8;--muted:#92a7bf;--healthy:#36d399;--stale:#fbbf24;--offline:#fb5b5b;--unknown:#8090a3;--up:#4cc9f0;--down:#ff5d73;--degraded:#ffb454}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#102743 0,#07111f 50%);color:var(--text);font:14px system-ui,sans-serif;height:100vh;overflow:hidden}
header{height:72px;display:flex;align-items:center;gap:22px;padding:12px 20px;border-bottom:1px solid var(--line);background:#091525e8;flex:none}h1{font-size:19px;margin:0;letter-spacing:.03em}.sub{color:var(--muted);font-size:12px;margin-top:5px}.badge{padding:6px 10px;border-radius:999px;background:#15283e;color:#b9d5ef;font-weight:700;font-size:11px;letter-spacing:.08em}.badge.demo{background:#8a3b0c;color:#fff}.spacer{flex:1}button,a.button{border:1px solid #35506d;background:#13253a;color:var(--text);border-radius:7px;padding:7px 10px;text-decoration:none;cursor:pointer;font:inherit}button:hover,a.button:hover{background:#1b3552}
main{display:grid;grid-template-columns:minmax(0,1fr) 330px;height:calc(100vh - 72px)}#canvas-wrap{position:relative;min-width:0;overflow:hidden;user-select:none;-webkit-user-select:none}svg{width:100%;height:100%;display:block;touch-action:none}
#bg{fill:#000;fill-opacity:0;pointer-events:all;cursor:grab}#bg.dragging{cursor:grabbing}
.edge{stroke-width:3;cursor:pointer;pointer-events:stroke}.edge.management{stroke-dasharray:6 6;stroke-width:1.6;opacity:.4}.edge-hit{stroke:transparent;stroke-width:16;cursor:pointer;pointer-events:stroke}.node{cursor:grab}.node.dragging{cursor:grabbing}.node rect{stroke-width:3;filter:drop-shadow(0 4px 7px #0008)}.node text{fill:white;text-anchor:middle;font-weight:700;font-size:12.5px;pointer-events:none}.node .role{fill:#9fb4cb;font-size:8px;font-weight:500;letter-spacing:.03em;text-transform:uppercase}.node .addr{fill:#8fa6bf;font-size:7.5px;font-weight:500;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:0}.selected rect,.selected.edge{stroke:#fff!important;stroke-width:5}.selected.edge{opacity:1}
.viewport-toolbar{position:absolute;left:14px;top:14px;z-index:6;display:flex;flex-direction:column;gap:6px;background:#091525e8;border:1px solid var(--line);border-radius:10px;padding:8px;box-shadow:0 6px 18px #0009}.viewport-toolbar button{width:36px;height:34px;padding:0;font-size:17px;line-height:1;border-radius:8px}.viewport-toolbar button.wide{width:auto;min-width:36px;font-size:11px;padding:0 9px;white-space:nowrap}.viewport-toolbar .sep{height:1px;background:var(--line);margin:2px 0}.viewport-toolbar button[aria-pressed="true"]{background:#1f4d78;border-color:#4c86b8}
aside{border-left:1px solid var(--line);background:#0a1727;padding:17px;overflow:auto}aside h2{font-size:15px;margin:0 0 14px}.detail-grid{display:grid;grid-template-columns:110px 1fr;gap:8px 10px}.detail-grid dt{color:var(--muted)}.detail-grid dd{margin:0;overflow-wrap:anywhere}.endpoint{margin-top:13px;padding:10px;background:#101f32;border:1px solid #263c55;border-radius:8px}.endpoint b{display:block;margin-bottom:7px}.legend{position:absolute;left:16px;bottom:16px;padding:10px 12px;background:#091525e8;border:1px solid var(--line);border-radius:9px;display:grid;grid-template-columns:auto auto;gap:6px 14px;font-size:11px;z-index:2}.legend-title{grid-column:1/-1;color:#b9cce0;font-weight:800}.dot{width:10px;height:10px;border-radius:50%;display:inline-block;margin-right:6px}.swatch{width:21px;height:3px;display:inline-block;margin:0 6px 3px 0}.mgmt-swatch{width:21px;height:0;border-top:1.6px dashed #9fb4cb;display:inline-block;margin:0 6px 5px 0;opacity:.6}.notice{position:absolute;top:15px;left:50%;transform:translateX(-50%);padding:8px 13px;background:#7c2d12;color:white;border-radius:6px;font-weight:800;display:none;z-index:2}.error{color:#ff8b9a}.healthy{color:var(--healthy)}.stale{color:var(--stale)}.offline,.down{color:var(--offline)}.unknown{color:var(--unknown)}.up{color:var(--up)}.degraded{color:var(--degraded)}
@media(max-width:850px){main{grid-template-columns:1fr}aside{display:none}}
</style></head><body>
<header><div><h1>NMAS Dynamic Network Topology</h1><div class="sub" id="refresh">Loading real monitoring state…</div></div><span class="badge" id="mode">REAL</span><div class="spacer"></div><label><input id="demo" type="checkbox"> Safe synthetic link-down demo</label><a class="button" id="grafana" href="http://127.0.0.1:3000" target="_blank" rel="noopener">Grafana</a><button id="reload">Refresh now</button></header>
<main><section id="canvas-wrap"><div class="notice" id="notice"></div><svg id="graph" role="img" aria-label="Live network topology">
<rect id="bg" x="0" y="0" width="100%" height="100%" fill="#000000" fill-opacity="0" pointer-events="all"></rect>
<g id="viewport"><g id="mgmt-edges"></g><g id="data-edges"></g><g id="nodes"></g></g>
</svg>
<div class="viewport-toolbar" role="toolbar" aria-label="Graph view controls">
<button id="zoom-in" type="button" title="Zoom in" aria-label="Zoom in">+</button>
<button id="zoom-out" type="button" title="Zoom out" aria-label="Zoom out">&minus;</button>
<button id="zoom-fit" type="button" class="wide" title="Fit to screen (includes manually moved nodes)" aria-label="Fit to screen">Fit</button>
<button id="zoom-reset" type="button" class="wide" title="Reset camera to the deterministic initial view" aria-label="Reset view">Reset View</button>
<button id="reset-positions" type="button" class="wide" title="Clear manually dragged node positions and restore the layout" aria-label="Reset node positions">Reset Node Positions</button>
<div class="sep"></div>
<button id="toggle-addresses" type="button" class="wide" title="Show/hide management IPv4/IPv6 on each device" aria-label="Show addresses" aria-pressed="true">Show Addresses</button>
</div>
<div class="legend"><div class="legend-title">Device state</div><span><i class="dot" style="background:var(--healthy)"></i>Healthy</span><span><i class="dot" style="background:var(--stale)"></i>Stale</span><span><i class="dot" style="background:var(--offline)"></i>Offline</span><span><i class="dot" style="background:var(--unknown)"></i>Unknown</span><div class="legend-title">Link state</div><span><i class="swatch" style="background:var(--up)"></i>Up</span><span><i class="swatch" style="background:var(--down)"></i>Down</span><span><i class="swatch" style="background:var(--degraded)"></i>Degraded</span><span><i class="swatch" style="background:var(--unknown)"></i>Unknown</span><div class="legend-title">Plane</div><span><i class="swatch" style="background:#8da5bd"></i>Data</span><span><i class="mgmt-swatch"></i>Management</span></div></section>
<aside><h2>Operational details</h2><div id="details" class="sub">Select a device or link. Interface names and evidence timestamps appear here. Drag a node to reposition it (presentation only); drag empty canvas to pan.</div></aside></main>
<script>
const NS='http://www.w3.org/2000/svg', colors={HEALTHY:'#36d399',STALE:'#fbbf24',OFFLINE:'#fb5b5b',UNKNOWN:'#8090a3',UP:'#4cc9f0',DOWN:'#ff5d73',DEGRADED:'#ffb454'};
const MIN_ZOOM=0.2, MAX_ZOOM=4, NODE_HALF_W=39, NODE_HALF_H=25, NODE_HALF_W_ADDR=68, NODE_HALF_H_ADDR=38, WORLD_PAD=90, DRAG_PX=4;
let current=null, selected=null, timer=null;
let view={x:0,y:0,k:1}, viewInitialized=false, manuallyAdjusted=false, lastSignature=null;
let panDrag=null;                     // background-canvas pan in progress
let nodeOffsets={};                   // id -> {dx,dy}; PRESENTATION-ONLY manual drag offsets, never sent to the backend
let nodeDrag=null;                    // node drag in progress
let showAddresses=true;               // PRESENTATION-ONLY toggle; survives refreshes/drags, never sent to the backend
let nodeById={}, nodeElementsById={}, edgeLinksByNode={};
const el=id=>document.getElementById(id), svgEl=name=>document.createElementNS(NS,name), fmt=v=>v===null||v===undefined?'—':String(v), age=v=>v===null||v===undefined?'—':Number(v).toFixed(1)+' s';
function add(parent,name,text){const n=document.createElement(name);n.textContent=text;parent.appendChild(n);return n}
function grid(rows){const dl=document.createElement('dl');dl.className='detail-grid';for(const [k,v] of rows){add(dl,'dt',k);add(dl,'dd',fmt(v))}return dl}
function showNode(n){const d=el('details');d.textContent='';add(d,'h2',n.canonical_name);d.appendChild(grid([['Health',n.health],['Reason',n.health_reason],['Role',n.role],['Platform',n.platform],['Image',n.image],['Management interface',n.monitoring_interface],['Management IPv4',n.monitoring_address],['Management IPv6',n.monitoring_address_v6],['Monitoring',n.monitoring_implementation],['Telemetry time',n.last_telemetry_timestamp],['Telemetry age',age(n.telemetry_age_seconds)],['CPU',n.cpu_percent===null?'—':n.cpu_percent+'%'],['Memory',n.memory_percent===null?'—':n.memory_percent+'%'],['Critical syslog (window)',n.recent_critical_syslog_count],['SNMP traps (window)',n.recent_snmp_trap_count],['Latest event',n.latest_event_timestamp]]))}
function showEdge(e){const d=el('details');d.textContent='';add(d,'h2',e.id);d.appendChild(grid([['State',e.status],['Reason',e.health_reason],['Evidence source',e.status_source],['Plane',e.plane],['Last state update',e.last_state_update],['Recent link events',e.recent_link_event_count],['Latest link event',e.latest_link_event],['Real state',e.real_status]]));for(const p of e.endpoint_state){const box=document.createElement('div');box.className='endpoint';add(box,'b',p.node+' · '+p.monitor_interface);box.appendChild(grid([['Containerlab iface',p.interface],['Admin',p.admin_status],['Oper',p.oper_status],['Evidence age',age(p.age_seconds)],['Fresh',p.evidence_fresh],['Errors total',p.errors],['Discards total',p.discards]]));d.appendChild(box)}}
function select(kind,item){selected={kind,id:item.id};document.querySelectorAll('.selected').forEach(x=>x.classList.remove('selected'));const target=document.querySelector(`[data-kind="${kind}"][data-id="${CSS.escape(item.id)}"]`);if(target)target.classList.add('selected');kind==='node'?showNode(item):showEdge(item)}

// --- Graph viewport -----------------------------------------------------
// Pan/zoom apply only to <g id="viewport">; the page, header, and sidebar
// never move. The SVG viewBox and the #bg pan-catcher rect are both kept in
// exact pixel sync with the canvas (see updateViewBox), so mouse
// coordinates map 1:1 to viewport user-space, and #bg's hit area never
// depends on how a browser resolves a percentage length.
function containerSize(){const r=el('graph').getBoundingClientRect();return {w:Math.max(r.width,300),h:Math.max(r.height,300)}}
function updateViewBox(){
  const s=containerSize(), svg=el('graph'), bg=el('bg');
  svg.setAttribute('viewBox',`0 0 ${s.w} ${s.h}`);
  bg.setAttribute('x',0); bg.setAttribute('y',0); bg.setAttribute('width',s.w); bg.setAttribute('height',s.h);
}
function worldBoundsOf(positions){
  // positions: [{x,y,hw,hh}] -- each node's own current half-extents, so
  // Fit/Reset account for the wider "Show Addresses" boxes and any manual
  // drag, never a single global node size.
  const left=positions.map(p=>p.x-p.hw), right=positions.map(p=>p.x+p.hw), top=positions.map(p=>p.y-p.hh), bottom=positions.map(p=>p.y+p.hh);
  return {xmin:Math.min(...left)-WORLD_PAD,xmax:Math.max(...right)+WORLD_PAD,ymin:Math.min(...top)-WORLD_PAD,ymax:Math.max(...bottom)+WORLD_PAD};
}
function computeFitView(bounds,size){const bw=Math.max(bounds.xmax-bounds.xmin,1),bh=Math.max(bounds.ymax-bounds.ymin,1);const k=Math.min(size.w/bw,size.h/bh,MAX_ZOOM)||1;const cx=(bounds.xmin+bounds.xmax)/2,cy=(bounds.ymin+bounds.ymax)/2;return {x:size.w/2-cx*k,y:size.h/2-cy*k,k:Math.max(k,MIN_ZOOM)}}
function applyView(){el('viewport').setAttribute('transform',`translate(${view.x},${view.y}) scale(${view.k})`)}

// Manual per-node presentation offsets. These never touch the backend
// x/y (the deterministic hierarchical layout) and are never sent to the
// server -- purely a client-side nodeOffsets[id] = {dx, dy} map applied
// only while rendering/displaying.
function nodeDisplay(n){const o=nodeOffsets[n.id];return o?{x:n.x+o.dx,y:n.y+o.dy}:{x:n.x,y:n.y}}
// "Show Addresses" widens/heightens only a monitored device's own box
// (nodes with no real monitoring_address, e.g. hosts/WebServer, stay
// compact even when the toggle is on) -- also presentation-only, applied
// solely at render/measure time.
function nodeBoxHalf(n){return (showAddresses&&n.monitoring_address)?{hw:NODE_HALF_W_ADDR,hh:NODE_HALF_H_ADDR}:{hw:NODE_HALF_W,hh:NODE_HALF_H}}
function displayedPositions(){return current?current.graph.nodes.map(n=>{const p=nodeDisplay(n),b=nodeBoxHalf(n);return {x:p.x,y:p.y,hw:b.hw,hh:b.hh}}):[]}
function baselinePositions(){return current?current.graph.nodes.map(n=>{const b=nodeBoxHalf(n);return {x:n.x,y:n.y,hw:b.hw,hh:b.hh}}):[]}
function fitToDisplayed(){if(!current)return;view=computeFitView(worldBoundsOf(displayedPositions()),containerSize());manuallyAdjusted=false;applyView()}
function fitToBaseline(){if(!current)return;view=computeFitView(worldBoundsOf(baselinePositions()),containerSize());manuallyAdjusted=false;applyView()}
function zoomBy(factor,cx,cy){const newK=Math.min(MAX_ZOOM,Math.max(MIN_ZOOM,view.k*factor));const wx=(cx-view.x)/view.k,wy=(cy-view.y)/view.k;view.k=newK;view.x=cx-wx*newK;view.y=cy-wy*newK;manuallyAdjusted=true;applyView()}
function zoomAtCenter(factor){const s=containerSize();zoomBy(factor,s.w/2,s.h/2)}

// Directly patch one node's <g> transform and its incident edge endpoints
// while dragging, instead of a full render() on every pointermove: keeps
// dragging smooth and never touches backend coordinates or selection.
function updateNodeAndEdgesPosition(id){
  const entry=nodeElementsById[id]; if(!entry)return;
  const p=nodeDisplay(entry.data);
  entry.g.setAttribute('transform',`translate(${p.x},${p.y})`);
  for(const link of edgeLinksByNode[id]||[]){
    const a=nodeDisplay(nodeById[link.source]), z=nodeDisplay(nodeById[link.target]);
    link.line.setAttribute('x1',a.x); link.line.setAttribute('y1',a.y); link.line.setAttribute('x2',z.x); link.line.setAttribute('y2',z.y);
    link.hit.setAttribute('x1',a.x); link.hit.setAttribute('y1',a.y); link.hit.setAttribute('x2',z.x); link.hit.setAttribute('y2',z.y);
  }
}
function resetNodePositions(){nodeOffsets={};if(current)render(current)}

function render(data){
  // A drag in progress targets DOM elements this rebuild is about to
  // discard; its offset (if any) is already committed into nodeOffsets on
  // every pointermove, so dropping the in-flight pointer-capture
  // bookkeeping here is safe and avoids touching a detached element.
  nodeDrag=null; panDrag=null;
  current=data;
  const nodes=data.graph.nodes, edges=data.graph.edges;
  for(const id of Object.keys(nodeOffsets)){if(!nodes.some(n=>n.id===id))delete nodeOffsets[id]}
  const signature=JSON.stringify({n:nodes.map(n=>[n.id,n.x,n.y]).sort(),e:edges.map(e=>[e.id,e.source,e.target]).sort()});
  const identityChanged=signature!==lastSignature; lastSignature=signature;
  updateViewBox();
  const mgmtLayer=el('mgmt-edges'),dataLayer=el('data-edges'),nodeLayer=el('nodes');
  mgmtLayer.textContent=''; dataLayer.textContent=''; nodeLayer.textContent='';
  nodeById=Object.fromEntries(nodes.map(n=>[n.id,n]));
  nodeElementsById={}; edgeLinksByNode={};
  const orderedEdges=[...edges].sort((a,b)=>(a.plane==='management')-(b.plane==='management'));
  for(const e of orderedEdges){
    const a=nodeDisplay(nodeById[e.source]), z=nodeDisplay(nodeById[e.target]), layer=e.plane==='management'?mgmtLayer:dataLayer;
    const line=svgEl('line');line.setAttribute('x1',a.x);line.setAttribute('y1',a.y);line.setAttribute('x2',z.x);line.setAttribute('y2',z.y);line.setAttribute('stroke',colors[e.status]);line.classList.add('edge',e.plane);line.dataset.kind='edge';line.dataset.id=e.id;line.onclick=()=>select('edge',e);
    const title=svgEl('title');title.textContent=e.id+' · '+e.status+' · '+e.plane+' · click for interface evidence';line.appendChild(title);layer.appendChild(line);
    const hit=line.cloneNode(false);hit.classList.remove('edge','management');hit.classList.add('edge-hit');hit.onclick=line.onclick;layer.appendChild(hit);
    const link={source:e.source,target:e.target,line,hit};
    (edgeLinksByNode[e.source]||(edgeLinksByNode[e.source]=[])).push(link);
    (edgeLinksByNode[e.target]||(edgeLinksByNode[e.target]=[])).push(link);
  }
  for(const n of nodes){
    const p=nodeDisplay(n), box=nodeBoxHalf(n), showAddr=showAddresses&&!!n.monitoring_address;
    const g=svgEl('g');g.classList.add('node');g.dataset.kind='node';g.dataset.id=n.id;g.setAttribute('transform',`translate(${p.x},${p.y})`);
    const r=svgEl('rect');r.setAttribute('x',-box.hw);r.setAttribute('y',-box.hh);r.setAttribute('width',box.hw*2);r.setAttribute('height',box.hh*2);r.setAttribute('rx',10);r.setAttribute('fill','#10243a');r.setAttribute('stroke',colors[n.health]);g.appendChild(r);
    const t=svgEl('text');t.setAttribute('y',showAddr?-21:-2);t.textContent=n.id;g.appendChild(t);
    const role=svgEl('text');role.classList.add('role');role.setAttribute('y',showAddr?-7:14);role.textContent=n.role;g.appendChild(role);
    if(showAddr){
      const v4=svgEl('text');v4.classList.add('addr');v4.setAttribute('y',7);v4.textContent='v4 '+n.monitoring_address;g.appendChild(v4);
      if(n.monitoring_address_v6){
        const v6=svgEl('text');v6.classList.add('addr');v6.setAttribute('y',21);v6.textContent='v6 '+n.monitoring_address_v6;g.appendChild(v6);
      }
    }
    const title=svgEl('title');
    let tip=n.id+' · '+n.health+' · '+n.health_reason;
    if(n.monitoring_interface)tip+='\nManagement interface: '+n.monitoring_interface;
    if(n.monitoring_address)tip+='\nIPv4: '+n.monitoring_address;
    if(n.monitoring_address_v6)tip+='\nIPv6: '+n.monitoring_address_v6;
    title.textContent=tip;g.appendChild(title);
    g.addEventListener('pointerdown',e=>onNodePointerDown(e,n,g));
    g.addEventListener('pointermove',onNodePointerMove);
    g.addEventListener('pointerup',onNodePointerUp);
    g.addEventListener('pointercancel',onNodePointerUp);
    nodeLayer.appendChild(g);
    nodeElementsById[n.id]={g,data:n};
  }
  if(!viewInitialized||identityChanged){fitToBaseline();viewInitialized=true}else{applyView()}
  el('refresh').textContent=`Last refreshed ${data.generated_at} · backend ${data.backend.status} · ${nodes.length} nodes / ${edges.length} links · auto ${data.refresh_interval_seconds}s`;el('refresh').className='sub '+(data.backend.status==='OK'?'':'error');el('mode').textContent=data.demo.mode;el('mode').className='badge '+(data.demo.active?'demo':'');el('notice').style.display=data.demo.active?'block':'none';el('notice').textContent=data.demo.label+(data.demo.target_edge?' · '+data.demo.target_edge:'');if(data.grafana_url)el('grafana').href=data.grafana_url;
  if(selected){const list=selected.kind==='node'?nodes:edges,item=list.find(x=>x.id===selected.id);if(item)select(selected.kind,item)}
}

// --- Node drag ------------------------------------------------------------
// Pointer events are owned entirely by the node's own <g> (pointer
// capture keeps them there for the whole gesture). A small screen-pixel
// movement threshold distinguishes a click (Operational Details) from a
// drag (reposition); the offset is divided by the current zoom scale `k`
// so the node tracks the cursor 1:1 regardless of zoom level.
function onNodePointerDown(e,n,g){
  e.stopPropagation();
  const off=nodeOffsets[n.id]||{dx:0,dy:0};
  nodeDrag={id:n.id,pointerId:e.pointerId,startX:e.clientX,startY:e.clientY,startDx:off.dx,startDy:off.dy,moved:false};
  g.setPointerCapture(e.pointerId);
  g.classList.add('dragging');
}
function onNodePointerMove(e){
  if(!nodeDrag||e.pointerId!==nodeDrag.pointerId)return;
  const dxs=e.clientX-nodeDrag.startX, dys=e.clientY-nodeDrag.startY;
  if(!nodeDrag.moved&&Math.hypot(dxs,dys)>DRAG_PX)nodeDrag.moved=true;
  if(!nodeDrag.moved)return;
  nodeOffsets[nodeDrag.id]={dx:nodeDrag.startDx+dxs/view.k, dy:nodeDrag.startDy+dys/view.k};
  updateNodeAndEdgesPosition(nodeDrag.id);
}
function onNodePointerUp(e){
  if(!nodeDrag||e.pointerId!==nodeDrag.pointerId)return;
  const {id,moved}=nodeDrag;
  nodeElementsById[id]?.g.classList.remove('dragging');
  nodeDrag=null;
  if(!moved&&nodeById[id])select('node',nodeById[id]);
}

async function load(){const q=el('demo').checked?'?demo=safe-link-down':'';try{const r=await fetch('/api/topology'+q,{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);render(await r.json())}catch(e){el('refresh').textContent='Refresh failed: '+e.message;el('refresh').className='sub error'}}
el('reload').onclick=load;el('demo').onchange=load;
el('zoom-in').onclick=()=>zoomAtCenter(1.3);
el('zoom-out').onclick=()=>zoomAtCenter(1/1.3);
el('zoom-fit').onclick=fitToDisplayed;
el('zoom-reset').onclick=fitToBaseline;
el('reset-positions').onclick=resetNodePositions;
el('toggle-addresses').onclick=()=>{
  showAddresses=!showAddresses;
  el('toggle-addresses').setAttribute('aria-pressed',String(showAddresses));
  if(current)render(current); // node dimensions change; camera/pan/zoom is left exactly as-is
};
el('graph').addEventListener('wheel',e=>{e.preventDefault();const r=el('graph').getBoundingClientRect();zoomBy(e.deltaY<0?1.12:1/1.12,e.clientX-r.left,e.clientY-r.top)},{passive:false});

// --- Background pan --------------------------------------------------------
// Owned entirely by the dedicated #bg rect, which updateViewBox() keeps
// pixel-exact with the visible canvas and which is explicitly marked
// pointer-events:all (both as an SVG presentation attribute and in the
// stylesheet) so hit-testing never silently depends on how a given
// browser treats a transparent/none fill on an SVG shape.
const bg=el('bg');
bg.addEventListener('pointerdown',e=>{
  if(e.button!==0)return;                 // left mouse button / primary touch only
  panDrag={pointerId:e.pointerId,startX:e.clientX,startY:e.clientY,startViewX:view.x,startViewY:view.y};
  bg.classList.add('dragging');
  bg.setPointerCapture(e.pointerId);
  e.preventDefault();
});
bg.addEventListener('pointermove',e=>{
  if(!panDrag||e.pointerId!==panDrag.pointerId)return;
  view.x=panDrag.startViewX+(e.clientX-panDrag.startX);
  view.y=panDrag.startViewY+(e.clientY-panDrag.startY);
  manuallyAdjusted=true;
  applyView();
});
function endPan(e){if(panDrag&&(!e||e.pointerId===panDrag.pointerId)){panDrag=null;bg.classList.remove('dragging')}}
bg.addEventListener('pointerup',endPan);
bg.addEventListener('pointercancel',endPan);

window.addEventListener('resize',()=>{updateViewBox();if(current&&!manuallyAdjusted)fitToDisplayed()});
load();timer=setInterval(load,20000);
</script></body></html>'''


class SnapshotCache:
    def __init__(self, builder: TopologyBuilder, max_age: int):
        self.builder = builder
        self.max_age = max_age
        self.values: dict[str, tuple[float, dict]] = {}
        self.lock = threading.Lock()

    def get(self, demo: str | None = None) -> dict:
        key = demo or "real"
        with self.lock:
            cached = self.values.get(key)
            if cached and time.monotonic() - cached[0] < self.max_age:
                return cached[1]
            value = self.builder.build(demo=demo)
            self.values[key] = (time.monotonic(), value)
            return value


class Handler(BaseHTTPRequestHandler):
    server_version = "NMAS-Topology/1"

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'")
        self.end_headers()

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self._headers(status, content_type, len(body))
        self.wfile.write(body)

    def _json(self, status: int, value: dict) -> None:
        self._send(status, "application/json; charset=utf-8", json.dumps(value, separators=(",", ":")).encode())

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._send(200, "text/html; charset=utf-8", INDEX_HTML.encode())
        if parsed.path == "/api/topology":
            params = parse_qs(parsed.query)
            demo = params.get("demo", [None])[0]
            if demo not in {None, DEMO_MODE}:
                return self._json(400, {"error": "unsupported demo mode"})
            return self._json(200, self.server.cache.get(demo))
        if parsed.path == "/healthz":
            value = self.server.cache.get()
            ok = value["backend"]["status"] == "OK" and bool(value["graph"]["nodes"])
            return self._json(200 if ok else 503, {
                "status": "ok" if ok else "degraded",
                "backend": value["backend"]["status"],
                "generated_at": value["generated_at"],
                "nodes": len(value["graph"]["nodes"]),
                "edges": len(value["graph"]["edges"]),
            })
        return self._json(404, {"error": "not found"})

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> None:
    config = json.loads((ETC / "config.json").read_text())
    topology = json.loads((ETC / "topology.json").read_text())
    required = ("INFLUXDB_ORG", "INFLUXDB_BUCKET", "INFLUXDB_TOKEN")
    if not all(os.environ.get(key) for key in required):
        raise SystemExit("InfluxDB runtime environment is incomplete")
    influx = InfluxEvidence(
        org=os.environ["INFLUXDB_ORG"], bucket=os.environ["INFLUXDB_BUCKET"],
        token=os.environ["INFLUXDB_TOKEN"],
    )
    cache = SnapshotCache(TopologyBuilder(topology, config, influx), int(config["backend_cache_seconds"]))
    cache.get()  # fail-safe graph construction and initial backend query before listen
    server = ThreadingHTTPServer((config["bind_address"], int(config["port"])), Handler)
    server.cache = cache
    server.serve_forever()


if __name__ == "__main__":
    main()
