# RB05 v1.0.0 -- DNS resolution and zone-propagation failures

Separate client configuration, DNS policy/transport, authoritative inconsistency, replication lag, cache/TTL and DNSSEC causes for a name-specific failure.

> Stage 1 is deterministic and read-only. Unavailable evidence is UNKNOWN. Results in this document come from SIMULATED replay fixtures unless stated otherwise (see `deterministic-engine.md`).

## Symptoms
A name does not resolve, resolves to the wrong address, or a zone change has not reached all clients.

## Triggering signals
Probe failure by name, application errors, zone-change events.

## Production contracts
The name, the zone, the resolvers and authoritative servers that must answer, the intended answer.

## Worked before / what changed
Zone serials, SOA history and DNS-related approved changes.

## Scope
One client, its resolvers, the authoritative servers of the zone.

## Collectors and permissions
Read-only bounded queries per resolver and per authoritative server, SOA, transfer status, delegation, DNSSEC and time sync.

## Baselines
Intent = NetBox DNS names; historical = answer TTLs; contract = the service name.

## Hypothesis tree and tests
The tables below are generated from the executable DAG (`python -m core.services.troubleshooting.runbooks write`); edit the code, not the table.

## Hypothesis tree
Each hypothesis lists the tests that confirm or eliminate it; counter-evidence from passing tests is kept in the report.

<!-- DAG:BEGIN -->
Runbook-Id: RB05
Runbook-Version: 1.1.0
Strategies: divide-and-conquer, top-down

| Step | Test | Title | Layer | Hypothesis | Class | Hard prerequisite | Expected (healthy) |
|---|---|---|---|---|---|---|---|
| 1 | DN10 v1 | Time synchronisation and recent DNS changes | CTRL | H-change | CONTEXT | - | clock sane, no unapproved DNS change |
| 2 | DN03 v1 | Recursive answers per resolver | L7 | H-cache | CONTEXT | - | all resolvers answer the intended record |
| 3 | DN04 v1 | Authoritative answers per NS | L7 | H-auth | DISCRIMINATING | - | every NS serves the same data (AA) |
| 4 | DN05 v1 | SOA serial, NS delegation, zone transfer | L7 | H-auth | DISCRIMINATING | - | identical serials, healthy transfers |
| 5 | DN06 v1 | Cache and negative TTL vs authoritative | L7 | H-cache | DISCRIMINATING | - | no stale cache |
| 6 | DN01 v1 | Client resolv.conf and search paths | L7 | H-client | DISCRIMINATING | - | client resolvers as intended |
| 7 | DN02 v1 | UDP/TCP 53 reachability and source-specific policy | L4 | H-policy | DISCRIMINATING | - | both transports reachable |
| 8 | DN07 v1 | A/AAAA/CNAME/PTR consistency | L7 | H-auth | DISCRIMINATING | - | records coherent |
| 9 | DN08 v1 | Split-horizon views | L7 | H-auth | DISCRIMINATING | - | each view returns its intended answer |
| 10 | DN09 v1 | DNSSEC validation | L7 | H-auth | DISCRIMINATING | - | validated, signatures fresh |

| Hypothesis | Statement | Domain | Tests |
|---|---|---|---|
| H-auth | Authoritative inconsistency, replication failure, record or view error | dns | DN04, DN05, DN07, DN08, DN09 |
| H-client | Client resolver configuration or clock | dns | DN01 |
| H-policy | DNS ACL / source-specific forwarding policy or transport | policy | DN02 |
| H-cache | Stale cache / negative caching within TTL | dns | DN03, DN06 |
| H-change | A recent DNS/zone change | change | DN10 |

<!-- DAG:END -->

## Tests and expected outcomes
Every test states its healthy expectation before execution, records the actual output with evidence ids, interpretation and next action. PASS = expectation held; FAIL = fault condition present; INCONCLUSIVE/UNAVAILABLE carry a specific reason; SKIPPED rows carry NOT_APPLICABLE / UNSAFE_TO_EXECUTE / SKIPPED_AFTER_CONFIRMED_ISOLATION with the exact reason.

## DNS rules (v1.1.0)
Details in `../dns-rules.md`. DN03 fails any NXDOMAIN/NODATA/non-success answer unless the name is intended absent; DN05 orders SOA serials by RFC 1982 (never numeric max), registers `dns.delegation` as a source and reports missing delegation/transfer evidence as INCONCLUSIVE; DN06 also detects stale negative cache against an AA reference.

## Platform adaptations
Clients without dig/resolvectl produce UNAVAILABLE for the affected tests.

## Causal isolation
Compare recursive with authoritative answers to split resolver/cache causes from zone-side causes.

## Alternative explanations
Client resolver config, UDP/TCP 53 policy, resolver REFUSED/SERVFAIL, stale cache within TTL, authoritative inconsistency, split horizon, DNSSEC, time skew.

## Safe stopping criteria
Stop after a proven causal finding; a stale-cache finding is an expected self-healing condition.

## AI handoff gate
Only when authoritative and recursive evidence is contradictory or unavailable.

## Proposed remediations
Proposals only; nothing here is executed. Each is Tier 2 or higher unless it is explicitly 'none', requires operator approval and is subject to NMAS governance.

* **F-cache-ttl** (tier 2): wait for TTL expiry; optional single-name cache flush on one resolver with approval. Approvals: operator approval for flush. Never: flush all caches, zone edits.
* **F-dns-transport** (tier 2): narrow ACL correction permitting the client subnet to the resolver on UDP/TCP 53. Approvals: operator approval, dry-run. Never: open DNS to any.
* **F-resolver-refused** (tier 2): see DN02: confirm policy before change. Approvals: operator approval. Never: n/a.
* **F-zone-propagation** (tier 2): repair transfer/notify on the stale secondary (ACL/TSIG); verify serial convergence. Approvals: DNS owner approval. Never: editing records on the secondary, serial manipulation.

## Pre- and post-tests
* F-cache-ttl: before DN06, DN04; after DN03, DN06.
* F-dns-transport: before DN02; after DN02, DN03.
* F-resolver-refused: before DN02; after DN03.
* F-zone-propagation: before DN04, DN05; after DN05, DN04, DN03.

## Rollback
Zone data is corrected at its source; caches are never flushed blindly.

## Soak
DNS changes inside the soak window are correlated, not blamed.

## Documentation example
ns2 serial behind with TSIG-refused transfers -> F-zone-propagation; resolver 10.0.0.54 holding the old answer for 240 s with consistent authoritative data -> F-cache-ttl.
