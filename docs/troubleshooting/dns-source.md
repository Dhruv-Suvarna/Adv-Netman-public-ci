# DNS runtime evidence source (RB05)

Task JOB-8A8D46BFB7D5 (subtask of JOB-9AA10B4E7CA7). Source HEAD cbb9c96 plus existing uncommitted troubleshooting implementation. Changed files: `normalization.py`, `collectors.py`, `runtime.py`, `adapters/dns.py`, `tests/test_troubleshooting_dns_source.py`, this document. No production, gateway policy, topology, compatibility ledger, remote repository or credentials were touched; no DNS query was made by this work.

## Path

`runtime.CollectorProvider.collect` -> `adapters.dns.requests_for_device` (typed request set from the case target `{client,name,zone,resolvers,authoritative,dnssec?}`) -> `collectors.DnsCollector` (source type `DNS_QUERY`, admission, budget, validation, injected runner) -> `normalization.normalize_dns` (parser `dns.response` / `dns-json-1.0`, vantage-OS independent) -> `runtime.map_observations` -> RB05 keys `dns.resolver_config`, `dns.transport`, `dns.query`, `dns.soa`, `dns.xfr`, `dns.delegation`, `dns.records`, `dns.dnssec`, `time.sync` (subject carried in `target.dns`). No new database/collector service.

## Runner contract (injected, authorized, read-only)

`RuntimeDeps.dns_runner(admission) -> runner`; `runner.execute(request_dict) -> JSON text (nmas.dns.response/1)`; optional `provenance()` (gateway dict stored verbatim; only `live: true` is LIVE). Request: `{schema: nmas.dns.request/1, op, server, name, zone, qtype, role, transport, timeout_s, read_only: true}`. The module never opens a socket. No runner (or factory returning None) => every DNS key is a `NOT_CONFIGURED` missing-data record; RB05 returns INCONCLUSIVE, never PASS.

## Validation and budgets

Names: <=253 chars, labels 1-63 of `[a-z0-9_-]` (no wildcard/whitespace/leading-trailing hyphen); servers: IP literal (canonical form; multicast/unspecified/broadcast refused) or hostname, and must be in the case's authorized set (resolvers + authoritative + `DnsContext` extras). Query types limited to A/AAAA/CNAME/PTR/SOA/NS; AXFR/IXFR/ANY/TXT/MX/SRV/DNSSEC RR types are refused (zone transfer state comes from a `zone_status` read, not a transfer). Invalid requests never reach the runner (`COMMAND_NOT_ALLOWED`). Budget: shared collector `Budget` (commands, seconds, bytes, records), 64 KiB per response, <=64 rows, retry on timeout/transient error only, remaining requests become `BUDGET_EXCEEDED`. RB05 full set is 13-14 requests (runtime default 16).

## Evidence semantics

* Document must answer the asked question (op/name/qtype/server/transport/role); otherwise `PARSE_FAILED` (never attributed). Bad IPs, TTLs, SOA fields, non-boolean flags, duplicate CNAMEs => no observation.
* Authoritative vs recursive: `role` from the request, `aa` from the flag; an authoritative reply lacking `aa` is UNTRUSTED. Answers = RRset at the end of the CNAME chain; CNAME loops flagged.
* TTL/cache: positive TTL = min answer TTL (remaining TTL for resolvers), `expires_at`, optional `original_ttl`/`cache_age_s`/`cache` hit|miss|unknown. Negative caching TTL = min(SOA TTL, SOA minimum) (RFC 2308); NODATA without SOA is UNTRUSTED (TTL never invented). `adapters.dns.ttl_recovery` reports WAITING_TTL / RECHECK_DUE for a stale answer.
* UDP truncation: UDP raw evidence is kept, one TCP retry is made (counted), only the TCP answer becomes an observation.
* Transport: UDP/TCP result per resolver; a transport never tried => UNTRUSTED; REFUSED => `acl_refused`.
* SOA serial parsed as unsigned 32-bit; `zone_status` supplies transfer result (device = authoritative server); delegation lame = answered without AA/NOERROR; unanswered servers are "unknown", not lame.
* DNSSEC: observation only when the runner supplies AD (and, for AD=true, RRSIG expiry and DS match); otherwise `EMPTY` gap. Time sync unsynchronised/offset unknown => `EMPTY` gap.
* Timeouts/unreachable => `TIMEOUT`/`TRANSPORT_ERROR` gaps carrying the exact engine key.

## Validation

All fixtures are **SIMULATED** hand-written documents; no gateway-recorded DNS output exists, so nothing is claimed live. Stable tests `DNSSRC-001..024` (supports UT-050, simulated IT-08): authoritative mismatch + zone propagation, stale cache then TTL-aware recovery (fresh case after TTL), policy (REFUSED/ACL) and TCP failure, malformed/mismatched/timeout responses, unavailable runner, DNSSEC unavailable/fail/valid, client config, lame delegation, time skew, budget/validation/no-contact, truncation retry, provenance labelling.

Commands (from `clab_dualstack_lab`):
- `DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_dns_source`: 24 tests PASS.
- Same with `test_troubleshooting_runbooks test_troubleshooting_collectors test_troubleshooting_runtime test_troubleshooting_stp_source`: 182 run, 3 failures, none DNS: `test_troubleshooting_collectors.py:903` and runtime `RT003` (stale STP assertions from the STP subtask) and one DNS test fixed afterwards.
- `python3 -I -m py_compile` on all scoped files: PASS.
- Gateway attested test not run (STP subtask found it blocked at the source pin); no live evidence.

## INCOMPLETE_WORK / limits

* No live DNS evidence or real runner adapter (gateway/NetmikoAdapter-style DNS runner) exists; integration owner must supply `dns_runner`.
* RB05 lists no `dns.delegation` source; the adapter requests delegation whenever `dns.soa` is wanted. RB05's `max()` over serials ignores RFC 1982 wraparound; NXDOMAIN-only resolver answers are not flagged by DN03. RB05 is out of scope here.
* Split-horizon queries need `DnsContext.vantage_servers`; absent => DN08 stays INCONCLUSIVE/SKIPPED per intent.
* Stale `test_troubleshooting_collectors.py:903` / `RT003` STP assertions remain for the integration owner.

## Source pins (SHA-256, before this document)

```text
11a217bac4165acc06b7e2f3ce3424a832988dee881be07738e6ecb1126c143a  web/core/services/troubleshooting/normalization.py
002c84b88f0f69eb2828ddb81e1116318a34b611abe35c7011387aff0581d7e5  web/core/services/troubleshooting/collectors.py
858a92762c23bec72af586a0b829855f43fe1887484b339b5099a679576cee64  web/core/services/troubleshooting/runtime.py
c31c022a0ba7cb025dfb34d519306045179da35fb797e830d3806eeab1dcc333  web/core/services/troubleshooting/adapters/dns.py
91132364f8be389b675e0af89066da5129bd52956a074474adfa43f87ec2eca4  web/core/tests/test_troubleshooting_dns_source.py
```
