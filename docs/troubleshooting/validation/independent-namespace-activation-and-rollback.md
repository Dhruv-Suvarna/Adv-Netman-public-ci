# Independent namespace activation and rollback evidence

Date: 2026-11-14/15 (America/Denver)

> **Superseded attachment.** The lifecycle guarantees recorded here still hold,
> but the `ipvlan` attachment and its parent/source/gateway/return-route/
> upstream-ACL inputs are replaced by the VM-local veth design. Current
> evidence and inputs: `vm-local-veth-networking.md`.

## Decision

The coupled-namespace implementation gap is technically closed in a new,
unapproved successor candidate. Diagnostic and research now have independent
preflight, activation, validation, deactivation and rollback operations with
activation-scoped ownership state. The frozen 205-operation package was not
modified and remains conditionally accepted only for its previously stated
application/inactive-staging scope.

This evidence is **not** university authorization, production activation,
independent security acceptance or live containment proof. Gate B/Stage C
remains NO-GO pending the external inputs, review and change authorization below.

## Implementation

- `namespace-activate.sh` is a thin launcher for `namespace_activation.py`.
- Every command selects exactly one of `diagnostic` or `research` and reads only
  that namespace's config/state. The old combined template is explicitly retired;
  separate unresolved templates are provided.
- `preflight` is mutation-free and refuses missing CIDR, parent, return-route,
  DNS, firewall, source-uniqueness, upstream-ACL, egress or authorization data.
  It validates an exact nft SHA-256 and does not call `ip route get` or infer a
  network from host reachability.
- IPv4 and IPv6 are independently enabled/disabled and validated. Namespace
  IPv4/IPv6 forwarding is forced off. Nftables has separate default-drop input,
  forward and output chains; only IPv6 neighbor solicitation/advertisement is
  added for static on-link operation.
- Activation writes a root-only per-namespace journal before each command,
  labels ownership in the namespace, records completed steps atomically and
  validates the resulting interface, addresses, exact default routes, forwarding,
  nft table/chains and resolver content.
- Handled failure/interruption performs ownership-scoped compensation. Rollback
  treats an already absent namespace/state as an idempotent no-op, but refuses an
  unowned existing namespace or mismatched activation ID, config digest, marker
  or resolver ownership proof. Repeated activation, deactivation and
  rollback are deterministic/idempotent for the same reviewed activation.
- No code path edits the parent interface, host addresses/routes/rules, global
  nftables, SSH, Docker networks or Containerlab links.

## Disposable test evidence

Command, run both from source and from the staged successor:

```text
python3 deploy/sandbox/test_namespace_activation.py
```

Result: **PASS**, 10 groups:

1. Mutation-free diagnostic and research preflight.
2. Missing CIDR, parent, return route, DNS, firewall approval and authorization
   all refuse before namespace creation.
3. Independent activation/validation and repeat-activation idempotency.
4. Synthetic local IPv4/IPv6 endpoints: diagnostic exact TCP/2222 allow and
   wrong-port deny; research TCP/443 allow and TCP/2222 deny.
5. Research rollback leaves diagnostic links/routes/state byte-identical and
   diagnostic validation still passes.
6. Diagnostic rollback leaves research links/routes/state byte-identical and
   research validation still passes.
7. Diagnostic injected failure after every applicable creation step (12 points)
   cleans diagnostic and preserves/validates research.
8. Research injected failure after every applicable creation step (13 points,
   including resolver creation) cleans research and preserves/validates diagnostic.
9. Repeated deactivate and repeated rollback are no-op successes after cleanup.
10. Host parent addresses, complete route tables and policy rules match the
    captured disposable-test baseline after both namespaces are removed.

The test created only temporary `nmas-test-*` namespaces, one synthetic veth
pair, synthetic addresses and local Python socket endpoints. Final inspection
found no `nmas-test-*` namespace/link or `/tmp/nmas-namespace-test-*` directory.
No external endpoint, device, production service, database, systemd unit,
Containerlab container or active topology link was contacted or changed.

Additional results:

| Check | Result |
|---|---|
| Python compile / shell syntax / diff whitespace | PASS |
| Focused sandbox artifact suite | PASS, 5/5 source and 5/5 staged |
| Deployment/binding/sandbox regression | PASS, 44/44 |
| Package production pre-verification | PASS, 210/210 |
| Package staged post-verification | PASS, 210/210 |
| New payload SHA-256 audit | PASS, 210/210 |
| Frozen package manifest SHA-256 | unchanged: `dfbe2f5e8b589c63853ee8f823b6adf08a682da3126d923b3091f856b2330352` |
| Disposable artifacts after tests | none found |

## New candidate identity

- path: `/home/student/Scripts/nmas-independent-namespaces-release-20261115T050919Z/package`
- operations: 210 (201 ADD, 8 REPLACE, 1 MERGE)
- entries identity: `5dab9de7e6af5d29fcfb23bb194ae65bde944c276f72cb8b3afe2c6bc0bd520f`
- manifest SHA-256: `47c98c1a0952bf0cd52e2271685dfa1d2e3891409d1e3989072702efa8da6242`
- builder problems: none

This candidate is immutable evidence awaiting independent diff/security/QA
review. It does not inherit the frozen package's conditional acceptance.
An earlier `050438Z` build was superseded before handoff by the true no-mutation
repeat-rollback receipt check; it is not the candidate for review.

## Remaining blockers

1. Independent acceptance of the new 210-operation identity and exact diff.
2. All infrastructure-owner values in the missing-input matrix: dedicated
   diagnostic/research sources, parents/VLANs, per-family gateways and return
   routes, upstream ACLs, complete protected networks, approved resolvers and
   proxy/public-egress decisions.
3. Attributable university authorization for namespaces, nftables, cgroup/systemd
   containment and public research; exact research hostname/privacy approval.
4. Approved production users/UIDs/GIDs, install paths/modes, secret lifecycle,
   model broker ownership and completion-provider controls.
5. Approved `ManagementPath` records, host-key pins, credentials, lifecycle and
   per-device diagnostic authorization; production currently has no approved paths.
6. Application/DB backup, restore test, writer quiescence, migration authorization,
   maintenance window, named operators/reviewers and tested console/OOB recovery.
7. Authorized production activation followed by live dual-stack containment and
   baseline evidence. Until then, no operational or live-containment claim is valid.
