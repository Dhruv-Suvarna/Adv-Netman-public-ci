# V2 Phase 3 — cEOS native ZTP, live and NMAS-driven (isolated fixture)

Date: 2026-10-24 (UTC). Worktree branch `v2-lifecycle-phase3-ztp` (base `c9ab840`); the run used the uncommitted working tree that this change commits.
Result: **PASS**. Arista cEOSLab 4.36.2F, driven by NMAS's native ZTP over an isolated, relayed bootstrap network, went from
factory default to `BOOTSTRAPPED`. Its management was verified by key-only, host-key-pinned SSH, and it stayed `NOT_ADMITTED`.

This is the evidence behind `AristaEosAdapter.evidence_status = SUPPORTED_AND_LIVE_VERIFIED`. The scope is that image, this
fixture and the HTTP transport. TFTP and HTTPS were not exercised live (see Limitations).

## Fixture (disposable, isolated)

`labs/ztp-isolated/fixture.sh up` (plain Docker, not Containerlab):

```
[ZTPNEW1 cEOS, factory default] Eth1 --- Eth1 [ZTPUP1 cEOS relay] Eth2 --- eth1 [nmas-ztp-p3-svc: ISC dhcpd 4.4.3 + NMAS delivery]
  serial ZTPP3NEW0001                10.254.30.1/24, ip helper,   10.254.31.1/30    10.254.31.2/30
  system MAC 02:5a:70:00:00:01       option 82 (circuit-id)
```

* Every container runs on Docker network `none`. The links are point-to-point veths. There is no Containerlab management
  bridge, no docker0, no VLAN 200, and no route to the production lab or to the host's production dhcpd, which was never
  touched.
* ZTPNEW1 has no startup-config, no user and no key, and ZTP is enabled. Its "hardware identity" (serial and system MAC) is
  written as cEOS flash documents, the container equivalent of a burned-in identity.
* ZTPUP1 is fixture infrastructure, the trusted relay. It is pre-configured (`labs/ztp-isolated/upstream-startup-config`)
  and is not the device under test.
* NMAS ran with a scratch settings module: its own SQLite DB, a scratch `inventory.yml` that lists only ZTPUP1, the
  enrollment-key store in scratch, and DHCP validate/status commands pointing at the fixture's container. The production
  database, inventory and services were not used.
* NMAS reached the device only through the bootstrap service network. The delivery server and the management commands ran
  in the service container's network namespace (`nsenter -n`), which is the only route to 10.254.30.0/24. NMAS never used
  `docker exec` into the device.

## Sequence (every step is an NMAS command or service; actors are scratch users with real roles)

| # | Step | Actor (role) | Result |
|---|------|--------------|--------|
| 1 | Adopt ZTPUP1 (IN_SERVICE / ADMITTED upstream) | arthur (Approver) | ok |
| 2 | Register ZTPNEW1: arista_ceos, expected serial ZTPP3NEW0001, base MAC 02:5a:70:00:00:01 | olivia (Operator) | DEV-000002 REGISTERED |
| 3 | Attachment ZTPUP1:Ethernet1 → local Ethernet1, routed; approval | olivia / arthur | approved |
| 4 | Bootstrap authorization (scope DHCP_DISCOVERY + BOOTSTRAP_FETCH, max_uses 1, 3 h) | olivia / arthur | BAUTH-000001 APPROVED |
| 5 | `nmas_ztp network-create ztp-lab-a` (10.254.30.0/24, relay 10.254.30.1=ZTPUP1) | arthur | recorded |
| 6 | `nmas_ztp session-open` | olivia | ZTP-000001: adapter arista_eos, transport HTTP, address 10.254.30.10, Ed25519 enrollment key (private half to the protected provider only) |
| 7 | `nmas_ztp dhcp-validate`, then `dhcp-apply` | olivia / erin (Executor) | `dhcpd -t` ok; applied sha256 `85ade836…`; class `nmas-ZTP-000001` |
| 8 | `fixture.sh reset-new` (fixture action: device to factory default) | — | ZTP active |
| 9 | Native DHCP through the relay; `serve --follow-ingest` folds the lease | system:ztp-dhcp-ingest | lease CORRELATED; REGISTERED → DISCOVERED; ztp_state ENABLED |
| 10 | Native ZTP HTTP fetch of the option-67 URL | system:ztp-artifact-service | SERVED 877 bytes to 10.254.30.10; the authorization's single use consumed (CONSUMED 1/1) |
| 11 | `nmas_ztp contact` (key exchange only) | olivia (Validate) | first-seen host key `SHA256:IRtqIasmvRhU6RvcRYzVCrlFw91+DEqH4M/7nNL8bTQ`, recorded untrusted |
| 12 | `verify` before enrollment | erin | **refused** HOST_KEY_NOT_ENROLLED |
| 13 | `enroll-host-key` by the session opener | olivia | **refused**: the actor lacks the Approve permission |
| 14 | `enroll-host-key` with a wrong fingerprint | arthur | **refused** HOST_KEY_MISMATCH |
| 15 | Out-of-band confirmation on the device console: `show management ssh hostkey ed25519 public` → fingerprint computed `SHA256:IRtq…bTQ` (equal) | arthur | basis recorded |
| 16 | `enroll-host-key` | arthur | enrolled |
| 17 | `verify` (SSH as `nmas-enroll` with the session key; pinned host key; no password) | erin | 11/11 checks passed → DISCOVERED → BOOTSTRAPPED (automation actor "system:ztp-workflow (requested by erin)") |

Verification checks (`ceos-session-status.json`): platform Arista cEOSLab · version supported · native ZTP completed
(`show zerotouch` mode disabled) · hostname ZTPNEW1 · bootstrap address 10.254.30.10/24 · only Ethernet1 addressed · IP
routing disabled · only bootstrap routes (connected /24 plus static service /30) · no production services · enrollment key
installed · management ACL applied. `ztp_state` = DISABLED_VERIFIED; `production_services` = [].

After the run:

* session BOOTSTRAPPED (closed)
* artifact EXPIRED (1 delivery)
* authorization CONSUMED
* identity_state PENDING_VERIFICATION (promotion stays the operator's Phase 2 action)
* admission_state **NOT_ADMITTED**
* `lifecycle.transition(COMMISSIONING | IN_SERVICE)` → TRANSITION_INVALID
* device event chain `verify_chain` = True (23 events: `ceos-lifecycle-events.json`)

## Delivery refusals (live, against the running NMAS server, from 10.254.31.2)

| Request | HTTP | Recorded code |
|---------|------|---------------|
| GET the real artifact after bootstrap | 404 | ARTIFACT_EXPIRED |
| GET `/ztp/v1/../../web/db.sqlite3` | 404 | PATH_INVALID |
| GET an unknown artifact id | 404 | ARTIFACT_UNKNOWN |
| GET `/` | 404 | PATH_INVALID |
| PUT on the artifact path | 405 | (not recorded: no write method exists) |

The server log contains no request path (`grep -c ztp/v1 serve.log` = 0).

## Files

* `ceos-delivered-startup-config.txt`: the delivered artifact. The locked password hash is redacted here; it is a
  sha512-crypt of random bytes that were discarded at render time. No plaintext secret was delivered: login is key-only, and
  the SSH key's private half never left the protected provider.
* `ceos-isolated-dhcpd.conf`: the NMAS-rendered ISC policy as applied (class match on giaddr + circuit-id + vendor prefix;
  one single-address pool; no dynamic pool).
* `ceos-dhcpd-leases.txt`: the provider's lease database: the relayed binding, then the device's release.
* `ceos-session-status.json`, `ceos-lifecycle-events.json`: the NMAS evidence.

## Defects found by this run (fixed in the same change)

1. **A released lease was classified as UNTRUSTED_RELAY.** About 20 s after applying its static configuration, cEOS
   releases its DHCP lease. ISC appends a `binding state free` block with no relay data. The ingester treated that block as
   a new binding without relay evidence and audited a false UNTRUSTED_RELAY (lease observation #2 in the scratch DB). Fix
   (`discovery.fold`): an inactive block without relay data now only ends the existing binding. It is never classified, and
   it is counted as `inactive` when no binding was seen. Unit-tested.
2. **Apply read-back sampled the service mid-restart.** The read-back reported `running: false` because it ran before the
   fixture's supervisor had restarted dhcpd. Fix: apply and rollback now poll the status command for up to 10 s, and an
   apply whose service is not running is FAILED, not APPLIED.

Found after the live run, while writing the unit tests (also fixed):

3. **HEAD consumed an authorization use.** An HTTP HEAD went through the same delivery decision as GET, so it would have
   consumed the authorization's use and marked the session DELIVERED with 0 bytes sent. The delivery server now answers 405
   to every method except GET.
4. **Two evidence keys were blanked by the audit redactor.** `secret_in_bootstrap` and `authorization_use_counted` contain
   redactor key substrings, so their `False`/`True` values were stored as `[REDACTED]` (this is visible in the scratch DB's
   ZTP_SESSION_OPEN and ZTP_ARTIFACT_DELIVERED events). They were renamed `bootstrap_plaintext_material` and
   `bootstrap_use_counted`.

A hand-configured prototype (written before the NMAS code existed) established the facts the adapter relies on:

* the option 60/61/77 formats
* the relay circuit-id `Ethernet1`
* the need for `aaa authorization exec default local`
* veth TX checksum offload must be off through cEOS ETBA (`fixture.sh` now does this)

None of the prototype's state was used as evidence. Its leases were archived and cleared, and the device was reset to factory
default before the NMAS-driven run.

## Limitations

* HTTP only. The isolated delivery service does not serve HTTPS, and the adapter's transport decision records that HTTPS is
  not served; with policy `INTEGRITY_REQUIRED` it refuses rather than downgrading. TFTP delivery is covered by unit tests over
  real UDP on localhost only; binding UDP/69 needs privileges the run did not use.
* One image (cEOSLab 4.36.2F) on one fixture. Physical EOS and other versions are not covered.
* The out-of-band host-key confirmation used the fixture container's console CLI, standing in for a physical console. NMAS
  itself never uses that path.
* The fixture's dhcpd restart is the fixture supervisor's job (a marker file). It is not an NMAS production DHCP integration.

## Finalization review (2026-10-24)

This review re-read the saved artifacts and the live run's scratch database, using a read-only copy. The cEOS run was
not repeated, because the saved evidence covers every acceptance claim below.

### What each claim rests on

| Claim | Basis | Class |
|-------|-------|-------|
| Native DHCP exchange through the relay | `ceos-dhcpd-leases.txt`: provider-written binding with the cEOS vendor class `Arista;cEOSLab;ZTPP3NEW0001`, user class `Arista;cEOSLab;4.36.2F…`, giaddr 10.254.30.1 and circuit-id `Ethernet1` | saved live evidence |
| DHCPDISCOVER cadence (~30 s) and the parameter-request list | prototype packet observation; no capture was saved | not independently verified |
| Trusted relay correlation | lease observation #1 CORRELATED, `relay_trusted`, upstream ZTPUP1:Ethernet1 (`ceos-session-status.json`, scratch DB) | saved live evidence |
| Correct bootstrap option | `ceos-isolated-dhcpd.conf`: option 67 carries the artifact URL inside the giaddr + circuit-id + vendor-prefix class | saved live evidence |
| Native fetch and delivery | delivery #1 SERVED, 877 bytes, HTTP, to 10.254.30.10; authorization CONSUMED 1/1 | saved live evidence |
| Native application | the authenticated read-back: hostname, address, ACL, enrollment key, `show zerotouch` mode disabled (`ceos-session-status.json`; `web/core/tests/fixtures/ztp/ceos_4.36.2F_verification.json`) | saved live evidence |
| Host-key enrollment | first-seen key `SHA256:IRtq…bTQ`. The saved console read-back of `show management ssh hostkey ed25519 public` hashes to the same fingerprint (recomputed with `ssh-keygen -lf`). Enrolled by arthur; the session opener was olivia | saved live evidence |
| Pinned-key, key-only SSH | verification as `nmas-enroll` with the session key, presented key equal to the enrolled key | saved live evidence |
| 11 operational postchecks | `verification.checks` (11/11 ok), digest `17cda0e3…` | saved live evidence |
| NOT_ADMITTED; no premature IN_SERVICE | device `admission_state` NOT_ADMITTED. COMMISSIONING and IN_SERVICE were refused with TRANSITION_INVALID | saved live evidence |
| Hash chain | `verify_chain` = True, recomputed on the scratch DB copy. The DB holds 25 events: the 23 exported in `ceos-lifecycle-events.json` plus the 2 refused COMMISSIONING / IN_SERVICE probes recorded after the export | saved live evidence |
| Delivery refusals | deliveries #2–#5 REFUSED (ARTIFACT_EXPIRED, PATH_INVALID ×2, ARTIFACT_UNKNOWN). PUT returned 405 and wrote no row. The server log holds no request path | saved live evidence |
| Self-approval refusal of host-key enrollment | live: the CLI refused the opener (missing Approve permission). The workflow's own APPROVAL_SELF rule is unit-tested | live (RBAC) + unit test |
| Wrong-fingerprint refusal | live: refused HOST_KEY_MISMATCH | saved live evidence |
| TFTP delivery | localhost UDP in unit tests only | unit-test evidence |
| Kea, IOS XE, SR Linux, SONiC, Junos, Ubuntu cloud-init, IOS XR | the classifications in `adapters/` (none is live) | unit test / mock / documented vendor capability |

The scratch DB also shows that, in the live run itself, the DHCP apply was recorded APPLIED while the read-back said
`running: false`, and that a false UNTRUSTED_RELAY row was written. These are live defects 1 and 2 above: both records
predate their fixes.

### Trust boundary: network isolation is a prerequisite

The relay evidence is trusted because of the network, not because of a protocol check. ISC dhcpd cannot see a packet's
source address, so it accepts any packet carrying giaddr 10.254.30.1 and a circuit-id. The bootstrap subnet is routed to
the service (ZTPUP1 has `ip routing`; that is how the device reaches the HTTP service). A host on a **shared** bootstrap
segment could therefore unicast a forged "relayed" DISCOVER to 10.254.31.2:67 with another port's circuit-id, and receive
that port's reservation and artifact.

* In this fixture the boundary holds: the bootstrap subnet is a single point-to-point veth, so the only possible client is
  the device on the authorized port.
* If the boundary is crossed, the impact is bounded. The artifact is secret-free (a public key, a locked password hash and
  an ACL). Nothing is trusted until an approver enrolls the host key read **out of band** from the authorized device's
  console. Bootstrap also requires an authenticated session whose serial / system MAC match the authorization.
* Enforcing the boundary is a Phase 5 isolation concern, not provided here: the relay-to-service path must accept UDP/67
  only from the relay itself (relay egress address / ACL on the service link). TFTP (UDP) requester binding also assumes
  that source addresses on the bootstrap segment cannot be spoofed. HTTP requester binding rests on the TCP handshake.

### Defects corrected in this review (each with a regression test)

5. **A failed DHCP read-back left the unverified candidate live.** Apply/rollback recorded FAILED ("previous configuration
   kept"), but the new file stayed in place. An apply with no status command was reported APPLIED without the service ever
   being seen running. Now any read-back failure restores the previous file (or removes the candidate) and requests a
   restart, and APPLIED requires a positive service status (`test_ztp_dhcp.ApplyTests`).
6. **The provider directory was not confined.** Any absolute non-system directory was accepted as `config_root` /
   `lease_file`, for example a checkout or a home directory. It must now lie under the `NMAS_ZTP_PROVIDER_ROOTS` setting
   (default `labs/ztp-isolated/runtime` and `web/var/ztp`) (`NetworkPolicyTests`, `SafeRootTests`). A future live run must
   list its isolated directory there.
7. **A revoked authorization did not stop bootstrap completion.** A multi-use authorization stays APPROVED after its first
   delivery. Revoking it stopped further deliveries, but verification could still take the device to BOOTSTRAPPED.
   Verification now refuses before contacting the device. The BOOTSTRAP lifecycle edge itself also refuses unless the
   authorization is APPROVED or CONSUMED (`test_ztp_workflow.RevocationTests`).
8. **A refused session-open could orphan an enrollment private key.** The key was written to the protected provider
   before the session records. It is now written as the last step of the same transaction (`OpenSessionTests`).
9. **A DHCP identity mismatch left the session open.** It was marked non-retryable, yet a later lease on the port could
   resume the onboarding. It now closes the session FAILED through `workflow.record_failure`, which revokes the artifact
   and drops the reservation (`DiscoveryTests`).

### Remaining limitations (unchanged by this review)

* The enrollment private key stays in the protected provider after the session closes. Retiring or replacing it belongs
  to Phase 4 credential onboarding; its reference (`ztp-enroll-…`) is distinct from operational credentials.
* Some human-requested automation events (DHCP policy, management contact, management verification) record the human
  username with `actor_kind` AUTOMATION. Attribution is complete (the username is present) but the kind is mixed. Left as
  is: the hash-chained live evidence uses this form.
