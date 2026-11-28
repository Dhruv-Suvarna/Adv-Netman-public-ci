# ACL source and safe HC18 causality (ACLSRC)

Read-only, explicitly version-gated cEOS source for HC18 (`acl.counters`). **Status: SIMULATED only.** No gateway-recorded cEOS ACL output is pinned and no fixture
was started; the JSON shapes below are hand-written to the EOS `| json` layout and must be pinned against a live gateway run before anything is called LIVE.
`adapters/acl.py::describe_source` labels `LIVE_GATEWAY_PINNED` only when a gateway run reports `live: true`; otherwise `RECORDED` or `SIMULATED`.

## Pipeline
`collectors.CliCollector` keys `acl_rules` (`show ip access-lists | json`) and `acl_attach` (`show ip access-lists summary | json`)
→ `normalization.normalize_acl_rules` / `normalize_acl_attachment` (parsers `acl.rules`, `acl.attachment`, `eos-json-1.0`, **EOS 4.28 ≤ v < 5.0**)
→ `runtime.join_acl_observations` → engine key `acl.counters@<interface>-<direction>` → `runbooks.hc.hc18`.
Unsupported platform/version is refused before any contact (`PARSER_UNAVAILABLE`); iosxe/linux have no ACL command in the catalogue. No write verb is possible
(`validate_read_only`). Counter history is `adapters.acl.AclContext` (`RuntimeDeps.acl_context`, in memory; **not wired into `deployment.py`** — outside this subtask's scope, so deployments without a context never get counter deltas).

## Semantics
* **Attachment** (interface, direction) comes only from `acl.attachment`; it is never inferred from rule content. Unattached ACLs produce no observation; attached-but-uncollected rules produce an explicit gap.
* **Ordered first match**: rules are evaluated by sequence; an *unsupported* rule ahead of any proven match makes HC18 INCONCLUSIVE (it might match first). An unsupported rule after the proven match does not matter.
* **Counter history**: `prev_hits` exists only from two consecutive complete samples (10 s ≤ span ≤ 900 s) of an unchanged rule. Statuses: `no_history`, `short_history`, `stale_history`, `counter_reset`, `rule_changed`, `no_counter`, `ok`.
* **HC18 causal denial** requires all of: attachment known and complete, flow traverses the attachment *in the filtering direction* (`in` = flow enters the device via that interface, `out` = leaves via it; path interfaces from `path_fwd`), supported first match = deny, `history == ok` and hits incremented. Otherwise: wrong direction / other interface / other AF → recorded in `not_traversed`, not causal; ambiguous attachment, partial collection, unknown path interfaces, VRF not proven (non-default flow VRF with unknown ACL VRF), unsupported earlier rule, missing/stale/reset/flat counters → INCONCLUSIVE. `direction_matches_flow` is now always True on a FAULT (it used to be merely recorded).
* TCP healthy with ICMP denied: the flow's own first match decides; ICMP denies are recorded as `icmp_denies` for HC23 and do not fail HC18. Shadowed denies never match.

## Supported rule grammar
`(permit|deny) (ip|tcp|udp|icmp) <any | host A.B.C.D | A.B.C.D/len> <same> [eq <1-65535>] [log]`; `remark` lines are skipped. IPv4 only.

## Unsupported (kept in order as `unsupported`, never guessed)
IPv6 ACLs; standard ACLs; wildcard-mask addresses; source-port operators; `range`/`neq`/`gt`/`lt`; named ports and ICMP types; tcp flags/`established`/`fragments`/`tracked`; object groups; VRF-aware attachment (VRF stays unknown); dynamic/PBR/zone-based firewall policy; non-cEOS platforms. Legacy fixtures that carry `acl.counters` with subject `<if>-<dir>` keep working.

## Tests
Master validation added ACLSRC-017: no explicit rule match is INCONCLUSIVE because implicit/default deny cannot be excluded without default-action and counter evidence. HC18 must never report PASS merely because the explicit rule list contains no matching deny.

`core/tests/test_troubleshooting_acl_source.py`, IDs ACLSRC-001..016:
`cd web && DJANGO_DEBUG=1 DJANGO_SECRET_KEY=test /opt/ai-orchestrator/nmas-env/bin/python manage.py test core.tests.test_troubleshooting_acl_source` (16 OK) plus regression `core.tests.test_troubleshooting_engine core.tests.test_troubleshooting_runbooks core.tests.test_troubleshooting_runtime core.tests.test_troubleshooting_l2_source core.tests.test_troubleshooting_deployment`.
Source pin: HEAD cbb9c96 plus working-tree edits (not committed).
