# RB05 DNS rules: negative cache and serial order

Subtask f3-f3_dns_rules (RB05 v1.1.0). Changed: `runbooks/rb05_dns.py`, `tests/test_troubleshooting_dns_rules.py`, this file, `runbooks/RB05-dns.md` (DAG block regenerated via `render_dag_block`; only RB05 touched). No network, gateway or production action; all fixtures SIMULATED, nothing claimed live.

## DN03 (recursive answers)
* Per resolver the answer is classified ANSWER / NODATA (NOERROR, no data) / NXDOMAIN / REFUSED / SERVFAIL / other.
* Intent: `services.dns_names[name]` (value or list), or intended-absent via `services.dns_absent` list or an explicit null/empty `dns_names` entry. No intent => INCONCLUSIVE (no guess).
* REFUSED/SERVFAIL -> `F-resolver-refused` (policy, non-causal); other rcodes -> `F-resolver-nonsuccess`; NXDOMAIN/NODATA for a name that should resolve -> `F-resolver-negative` (H-cache, non-causal: DN04/DN06 attribute it); wrong answer -> `F-resolver-stale`. Intended-absent: negative = PASS, positive answer -> `F-resolver-unexpected-answer`.

## DN06 (cache vs authoritative)
Reference must be an AA NOERROR answer, else INCONCLUSIVE. A resolver holding a different positive answer, or NXDOMAIN/NODATA with TTL>0 while the AA answer exists, is `F-cache-ttl` (causal, self-heals after TTL). When the authoritative side is also negative, it is not called cache. Recovery = fresh run after TTL where DN03/DN05/DN06 pass.

## DN05 (zone propagation)
* RFC 1982, 32-bit: a<b iff (b-a) mod 2^32 in (0, 2^31); distance exactly 2^31 is undefined. `analyse_serials` returns EQUAL / ORDERED (newest + lagging) / AMBIGUOUS (undefined pair or cyclic, no single newest) / INVALID (not an unsigned 32-bit int). `max()` is never used (rollover: 2 is newer than 4294967293).
* SOA with `aa == false` is not authoritative serial evidence (uncertainty).
* Lag => FAIL `F-zone-propagation`; causal only when transfer evidence (`dns.xfr`) shows a non-ok result for the lagging server, otherwise non-causal ("cause not attributed").
* Lame delegation or an empty NS set => FAIL `F-lame-delegation`.
* `dns.delegation` is now a declared DN05 source. Missing delegation, delegated servers that did not answer, unknown transfer status (with lag or equal serials), ambiguous/invalid serials => INCONCLUSIVE (never PASS) unless a fault is already proven (then listed as unresolved).

## Validation
`DJANGO_DEBUG=1 /home/student/Scripts/.venv-ci/bin/python web/manage.py test core.tests.test_troubleshooting_dns_rules core.tests.test_troubleshooting_runbooks core.tests.test_troubleshooting_dns_source` -> 71 tests OK. IDs DNSRULE-001..021 cover rollover, equality, half-range, cyclic, stale negative cache, authoritative NXDOMAIN, intended absent, no intent, recovery, REFUSED, missing/lame delegation, transfer unknown, DAG source. Gateway attested run not performed.

## Limits
Other RB05 consumers (reporting/remediation) have no new remediation entries for the added findings (proposals only via existing ones). The adapter comment in `adapters/dns.py` about delegation being undeclared is now stale (outside this scope).
