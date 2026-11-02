# Credential incident remediation

This document records the source-side controls for the 2026 public-history
credential incident. It intentionally contains no credential values, password
hashes, private keys, or authentication responses.

## cEOS replacement privilege

The dedicated cEOS service accounts declare privilege 15 and the
`network-admin` role. Live read-only diagnosis found that an authenticated SSH
session nevertheless started at privilege 1 because the candidate did not
configure local EXEC authorization. EOS applies a local username's configured
initial privilege through local EXEC authorization.

The reviewed candidate now includes:

```text
aaa authorization exec default local none
```

`local` applies the configured privilege to local service and break-glass
accounts. The `none` fallback preserves the existing shell path for an already
authenticated non-local RADIUS user; command authorization continues to use
the RADIUS-supplied role through `aaa authorization commands all default
local`. Rollback removes the explicit EXEC list.

The login verifier now parses the exact numeric result of `show privilege`.
Level 1 is a failure, not merely a different success banner, and raw command
output is no longer retained in evidence.

## Deployment boundary

These source changes do not modify a live device. Applying the candidate to a
managed device still requires the existing checkpoint, automatic rollback,
recovery-access, fresh-login, human-MFA, health, and persistence gates. The
legacy shared cEOS account and Linux root-password retirement remain separate
operator-approved production changes.

## Shared-credential path removal

Managed cEOS inventory entries now require a dedicated username and protected
credential reference. The shared fleet fallback has been removed from the
credential resolver, NSOT live reads, workbench captures, and the core
orchestrator. A missing device profile fails closed. R5 remains outside NMAS
managed scope and is reached only through the explicit host-side container
console for repository-owned bootstrap and read-only commands.

The Linux plaintext was also reused by H1-H4 and WebServer in addition to the
two managed Ubuntu/FRR routers. Current source no longer imports or consumes a
shared Linux root-password reference. Lab Linux orchestration and reporting use
fixed container-console targets, while the prepared bootstrap candidate denies
remote root/password login and locks the root password. Those candidate
effects are not applied to running containers by this source-only change.

## Preventive controls

The repository uses a tracked-file scanner for NMAS-specific low-entropy
assignments, redacted Gitleaks scans for the current tree and new commits,
immutable GitHub Action pins, read-only workflow permissions, and local
pre-commit/pre-push hooks. Runtime credentials remain in the protected local
provider and are referenced from source only by opaque identifiers.
