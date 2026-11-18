# Sandbox guardrail test report

Date: 2026-11-14  
Environment: authoritative public development worktree; `DJANGO_DEBUG=1`, test-only Django secret, `/opt/ai-orchestrator/nmas-env/bin/python`; local fakes/fixtures unless explicitly identified. No live unauthorized destination was contacted.

## New adversarial coverage

| Area | Cases | Result |
|---|---|---|
| Target authorization | approved exact target; unknown; R5; unverified/withdrawn/revoked; expired; cross-topology; cross-tenant; management-path mismatch; address substitution; VM1 protected address; mapped IPv4; unknown/raw operation; agent apply; proposal no connection; grant tamper/expiry/revision; discovery non-expansion | PASS |
| Research | approved bounded textual document; HTTP/IP literal/unlisted/userinfo/non-443; private/loopback/link-local/metadata/ULA; mapped IPv4; DNS answer change; unlisted redirect; credential query; POST; binary/oversize; audit privacy | PASS |
| AI/research | unavailable by default; typed broker use; prompt-injected content remains untrusted; no plan/execution authorization | PASS |
| Staged isolation | exact IPv4 `/32` and IPv6 `/128`; cgroup default deny; no Docker reference; namespace private/metadata/mapped denial; R5/unverified/protected/empty manifest refusal; production direct-provider refusal | PASS |

## Executed commands and stable results

| Suite | Result |
|---|---|
| New target+research modules | 21 tests, PASS, 0.009 s |
| Combined new guardrail, AI/AI-runtime, deployment and binding suite | 97 tests, PASS, 8.675 s |
| Full `test_troubleshooting_*.py` regression | 756 tests, PASS, 284.202 s, 0 failures/errors |
| Final changed-boundary focus (target policy/provider, AI, research, artifacts) | 62 tests, PASS, 2.581 s |
| Final target-policy revalidation module after live-authorization test | 14 tests, PASS, 0.004 s |
| Preservation suite: commissioning, isolation, ZTP/DHCP, identity, maintenance, credential rotation, management paths, traffic and observations | 779 tests, PASS, 1 skipped, 403.994 s |
| Compatibility builder self-tests | 18 tests, PASS, 1.789 s |
| New candidate pre/post hash verification | 190/190 paths PASS; zero builder problems |
| Staged-copy migrations | fresh DB migrated 0001 through core 0039, PASS |
| Staged-copy guardrail/AI/provider/deployment suite | 102 tests, PASS, 4.394 s |
| Python byte compilation and `git diff --check` | PASS for changed Python/source set at execution time |
| Rendered nftables syntax (`sudo nft -c`, check-only) | PASS; no rules loaded |
| Rendered systemd unit syntax (`systemd-analyze verify`, ExecStart substituted with `/usr/bin/true` for syntax-only validation) | PASS; no unit installed |

The first 96-test combined attempt produced five failures and two errors because sandbox enforcement correctly refused legacy simulated provider paths used by deployment tests. No product control was weakened. The test runner now explicitly disables the production-only provider gate inside automated tests, while real settings keep it true; a dedicated test proves real-settings refusal. The corrected 97-test run passed.

## Existing regression basis

Before these guardrails, the accepted overlay's final evidence reported:

- 707 Troubleshooter tests PASS in 294 seconds at the earlier checkpoint;
- later phase-readiness evidence: 719 Troubleshooter tests PASS;
- full `core` regression: 8,746 tests PASS, 44 skipped, 0 failures/errors;
- an earlier accepted full `core` run: 8,733 tests PASS, 44 skipped.

Those are historical baseline identities, not rerun claims. This report preserves rather than hides the earlier transient/stale failures described in the referenced validation records. A new production candidate must rerun full core and domain suites under its own identity.

## Requirements mapping

- Commissioning, isolation, ZTP, DHCP, maintenance, credential rotation and traffic monitoring were not invoked against live devices. Existing services/topology were checked read-only and left running/unmodified.
- Device identity/admission/path behavior is covered by the new pure policy tests and existing NMAS provider/deployment tests in the broad Troubleshooter suite.
- Troubleshooting, observations, lifecycle authorization, Change Engine and AI gateway behavior are covered by existing Troubleshooter/AI/governance modules included in regression.
- Host namespace/privilege bypass is assessed statically and with renderer fixtures only. No root namespace or live firewall activation was authorized, so production kernel containment remains unverified.

## Limitations

Tests prove code decisions and safe rendering, not live production containment. The staged units refer to worker commands that must still be implemented and packaged. Root/Docker-capable current components remain outside the proof. Public access was simulated; approved live research connectivity must be validated only after namespace activation. These limitations are deployment blockers, not skipped successes.

The new candidate identifiers are entries `955faa118060c3b7694fdd3d3453976eafdb9b5b4f5f7b3be5ac663d0e1df97a` and manifest `acca183adca00a39a4067cadb17f11f39e302a55eddef825c69172f2c26ba82d`. They identify an unreviewed evidence candidate, not an approval.

## Standalone-worker completion evidence (2026-11-14)

### Application and adversarial suites

- Broad public Troubleshooter checkpoint: **770/770 PASS**, 273.187 s. Subsequent worker/DB-boundary deltas are covered by the focused runs below.
- Preservation suite spanning commissioning, isolation, FRR, ZTP/DHCP, identity/lifecycle, maintenance, management paths/VRF, credential rotation, traffic and Change Engine: **805 PASS, 1 skipped, 0 failed**, 410.495 s (806 discovered).
- Final worker/security focused suite: **17/17 PASS**; worker IPC suite repeated three times: **12/12 PASS** each.
- Final staged-package worker/artifact suite: **17/17 PASS**.
- Full staged immediately preceding candidate: **771/771 PASS**, 284.059 s. The final candidate differs only in bounded socket-start retry and audit-before-response ordering; those exact final files passed the staged 17-test suite and three repeated 12-test IPC suites.
- Existing research, target-policy, NMAS-provider, AI-runtime and deployment cases are included in the passing full 770-test suite. An earlier 84-case subset had one test-assertion failure because the assertion rejected the word `docker` even in `InaccessiblePaths`; the assertion was corrected to reject Docker group membership/execution while requiring socket denial.

Adversarial coverage includes HMAC tampering, peer-UID impersonation, durable replay, expiry, operation/rendered-command substitution, arbitrary destination/command/config fields, lost socket, principal substitution, private/mapped/redirect/proxy-like research paths, executable downloads, DB writes to identity/path tables and untyped transport calls. Existing policy suites cover R5, unknown/unverified/cross-tenant/cross-topology, host address, grant/path/inventory revision changes and prompt-injected tool output.

One final-package staged run initially exposed a real startup/audit ordering race: the socket path could exist before `listen()`, and a response could arrive before its audit append. The client now performs only bounded ENOENT/ECONNREFUSED startup retries, and the worker durably appends audit before returning the signed response. The initial failing run is retained here; three repeated worker suites and the final staged 17-test run passed after the fix.

### Kernel and service artifacts

- `systemd-analyze verify`: all three rendered units syntactically valid (only the expected absent future `/opt/nmas/venv/bin/python` warning before installation).
- `systemd-analyze security --offline`: diagnostic **1.4 OK**, research **1.5 OK**, runtime **0.6 SAFE**.
- `nft -c`: diagnostic and research policies PASS.
- Disposable runtime namespace: diagnostic allowed exact `192.0.2.6:8443` and `2001:db8::6:8443`; denied adjacent v4/v6 addresses and the same approved IP on port 22. Research allowed public-shaped v4/v6 on 443 and denied RFC1918/ULA peers. No live VM interface/firewall was changed.
- Kernel inventory: Linux 7.0, systemd 255, cgroup v2 and nftables 1.0.9 available; unprivileged `SO_BINDTODEVICE` succeeded. Cgroup `IPAddressAllow` was rendered/verified but not live-activated.

### Final compatibility candidate

Final candidate: `/home/student/Scripts/nmas-sandbox-workers-release-20261114T212024Z/package`, 203 entries (194 ADD, 8 REPLACE, 1 MERGE), entries identity `cab1ac29d8be78b11dc9ecfa130843634a754049afe6c7dd012fef3e25d091d1`, manifest SHA-256 `75010e99e83b49a9a562caa8305cf363214490bd298251f473913f6492b7d596`, `problems: []`.

- Build/stage/post-verify: **203/203 PASS**.
- Disposable production DB copy: migration 0035→0039 PASS; `integrity_check=ok`, zero FK violations.
- Scratch apply: preverify PASS, 203-entry apply PASS; rollback removed 194 additions/restored nine shared files; post-rollback preverify PASS.
- Production preverify remains PASS for the immutable 179-path package, the unapproved 190-path package and the final 203-path package. Production remains at core migration 0035.

### Live preservation checks

`/healthz` returned `ok`, login returned 200, Troubleshooter route remained 404, the original 15 `clab-srlceos01-*` containers remained up (six separate long-running capability-test containers also existed), NMAS web/gNMI/topology/traffic and AI control services were active, production HEAD remained `129d3f...`, and production status remained its historical 16 entries (13 modified + 3 untracked). No production source, DB migration, service, topology, route, firewall or interface was changed by this work.

The tests prove implemented code and disposable namespace enforcement. They do not claim live worker activation, institutional address ownership, production deployment approval or containment of the existing root/Docker-capable services.
