# Authoritative development repository

`Dhruv-Suvarna/Adv-Netman-public-ci` is the authoritative NMAS V2 development
repository. All new commits, branches, pull requests, merges, hosted CI runs and
capability-ledger changes happen here.

`Dhruv-Suvarna/Adv-Netman` is a private legacy and security-remediation archive.
Its Git history once exposed credentials, so none of it may be imported: no
mirror push, no repository import, no merge or cherry-pick of its commits. Work
that still exists only there is ported as reviewed source-level changes on a
branch of this repository.

## History

The repository started as a CI-only mirror of sanitized snapshots:

| Commit | Role |
| --- | --- |
| `e0e85e6` | published root: first sanitized snapshot |
| `cf0d79e` | appended sanitized snapshot |
| `321db58` | last sanitized snapshot: the **import boundary** |

Each snapshot commit was built by `scripts/ci/build_public_ci_snapshot.py` from
one reviewed legacy commit. Only tracked blobs were exported; the legacy `.git`
directory, untracked files, runtime credentials, databases and local deployment
state were not. Generated device session logs and `address_report.csv` were
excluded; their paths, modes, sizes, hashes and exclusion reasons remain in
`PUBLIC_CI_SNAPSHOT.json`, their content is not published.

`PUBLIC_CI_SNAPSHOT.json` is now the immutable record of that import. It binds
the boundary tree to the legacy source commit, source tree and canonical SHA-256
file manifest. It is never edited.

After the boundary, `main` takes ordinary reviewed squash merges. The snapshot
builder remains only as the tool that produced the import; it is not part of
the development workflow.

## Integrity checks

`.github/workflows/repository-integrity.yml` runs
`scripts/ci/verify_public_ci_snapshot.py` on every pull request and every push
to `main`:

- `--history --import-boundary 321db58`: the history is one strictly linear,
  single-parent chain from the published root. Every commit up to the boundary
  is a builder-identity snapshot whose trailers, path set and (for the boundary)
  every blob's mode, size and SHA-256 agree with its manifest. Every later commit
  keeps the import manifest byte-identical and contains no excluded legacy path
  and no submodule, symlink or special mode. A pull request checks its base.
- `--roots`: every commit reachable from all refs (push) or from the pull
  request head has the published root as its only root, so imported legacy
  history is refused on any branch. Feature branches themselves are allowed.
- `--tree-policy`: the checked-out tree descends from the boundary, keeps the
  import manifest unchanged and contains no excluded path or special mode.
- the offline NMAS tracked-file credential scan.

`Secret scanning` runs the same tracked scan plus pinned, SHA-256-verified
Gitleaks over the current tree and the new commit range with redacted output.
`Tier-3 validation` runs the targeted gate on pull requests and the full gate,
including test governance, on pushes to `main`.

All workflows use `permissions: contents: read`, GitHub-hosted `ubuntu-24.04`
runners, actions pinned to full commit SHAs, `persist-credentials: false`, no
`secrets.*`, and no `pull_request_target`, `workflow_run` or `id-token`.

## Development workflow

1. Branch from the latest `main`.
2. Implement, or port reviewed legacy source changes.
3. Run focused tests; prove live capability evidence on an isolated fixture.
4. Scan the staged files for credentials; stage only reviewed files.
5. Push the branch normally and open a pull request against `main`.
6. Merge by squash only after Repository integrity, Secret scanning and
   Tier-3 validation pass. Never force-push or rewrite published history.

The `Configuration Validation` workflow (`repository_dispatch`) carries
sanitized payloads only, with a read-only token.

## Not covered by hosted CI

Live Containerlab/NOS verification, production NMAS health, live
NetBox/DHCP/Grafana checks, credential-provider tests with real material and
device authentication run only on the private lab host. The seven lab-backed
Tier-3 checks are `NOT_RUN` on hosted runners and are never reported as passed.
