# Sanitized public CI mirror

The proposed `Adv-Netman-public-ci` repository is a CI-only, linear
snapshot history. It is not a replacement source repository and its checks are not
native required checks on private PR #86.

## Security boundary

`build_public_ci_snapshot.py` exports only blobs tracked by one reviewed source
commit. It cannot copy the source `.git` directory, untracked files, ignored
runtime credentials, databases, protected audit material, or local deployment
state. It refuses submodules, symlinks, special Git modes, and an existing
output directory.

The generated snapshot intentionally excludes root-level generated device
session logs and `address_report.csv`. Their paths, modes, sizes, hashes, and
exclusion reasons remain in `PUBLIC_CI_SNAPSHOT.json`; their contents are not
published. Documentation evidence remains included because it is required by
the governance tests and has passed both the NMAS scanner and Gitleaks. Its
addresses describe the intentionally published lab/simulation environment, not
production credentials.

The first snapshot is one root commit. Each later snapshot is appended as one
single-parent commit on top of the last approved public snapshot
(`--parent-mirror <local clone> --parent-commit <full SHA>`); only that sanitized
mirror chain is fetched, never source-repository history. The history is
append-only: no force push, no merge commits, no second root.

Every commit message and manifest bind the snapshot to the original repository,
full source commit, source tree object, and canonical SHA-256 file manifest;
appended manifests also name `mirror_root_commit` and `mirror_parent_commit`.
The mirror-only integrity workflow runs `verify_public_ci_snapshot.py --history
--expected-root <published root>`, which rejects a different root, a merge, a
commit not made by the snapshot builder identity, provenance trailers that
disagree with that commit's manifest, a commit path set that differs from its
manifest, special modes, and any ref outside the chain. It then verifies every
tracked path, mode, size, and digest of the current tree before running the
offline scanner. Any source edit requires a newly reviewed snapshot and
manifest.

## Workflow coverage

Public-safe workflows included from the source snapshot:

- Public CI snapshot integrity: immutable source linkage and offline NMAS scan.
- Secret scanning: tracked-file scanner and pinned Gitleaks current/history
  scan with no source upload.
- Tier-3: static checks, Django checks/tests, monitoring tests, governance,
  Pylint, coverage, and Grafana drift on a standard Ubuntu runner.
- Configuration Validation: code is present for source parity, but the
  `repository_dispatch` workflow must not be used by production NMAS against
  the public mirror. It carries sanitized payloads only and has read-only token
  permissions.

Not covered by the public runner: live Containerlab/NOS verification, production
NMAS health, live NetBox/DHCP/Grafana checks, credential-provider tests using
real material, and device authentication. These remain private/local evidence
and must never be represented as public-CI PASS.

## Publication gate

Before creating the GitHub repository:

1. Build from the reviewed full source commit (appending to the last approved
   snapshot after the first publication), run the tree and history verifiers,
   and scan the tree, the new commit range, and the full mirror history.
2. Confirm no submodule, LFS pointer, release asset, database, private key, or
   credential artifact is present.
3. Create the public repository only after explicit approval. Disable issues,
   discussions, wiki, projects, merge commits, squash/rebase merging, branch
   deletion, and unnecessary workflow token writes for the CI-only mirror.
4. Permit only selected GitHub-owned, full-SHA-pinned actions; set workflow
   permissions to read-only and prevent Actions from approving PRs.
5. Push the single root commit, run Public CI snapshot integrity first, then
   Secret scanning, then Tier-3. Record actual GitHub conclusions and artifact
   IDs. Do not report these as native checks on PR #86.
