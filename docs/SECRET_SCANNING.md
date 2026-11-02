# Secret scanning

NMAS uses two complementary repository gates because common token and entropy
rules do not reliably detect short lab passwords.

`python scripts/ci/scan_tracked_secrets.py` scans every Git-tracked current
file, including gzip evidence, and reports only a rule name and location.  It
also rejects credential-store filenames and the legacy literal assignment
names that caused the public-history incident.  Matched values are never
printed.

Gitleaks 8.30.1 supplies the broader credential-format scan.  CI downloads the
versioned release archive, verifies its pinned SHA-256 digest, and scans both
the current tree and the new commit range.  The commit-range check catches a
secret added and then deleted within one pull request.  `.gitleaks.toml`
extends the default rules with NMAS low-entropy assignments.

`.gitleaksignore` contains exact path/rule/line fingerprints reviewed during
the 2026-10-30 audit.  It contains no credential values.  A changed line gets a
new fingerprint and must be reviewed again rather than inheriting an old
exception.

Local verification:

```text
python scripts/ci/scan_tracked_secrets.py
gitleaks dir --redact=100 --max-archive-depth=2 .
python scripts/ci/run_gitleaks_range.py --gitleaks /path/to/gitleaks
```

Developers can install the repository-local hooks after installing
`pre-commit` and Gitleaks:

```text
pre-commit install
pre-commit install --hook-type pre-push
```

The pre-commit hook runs the tracked-tree scanner. The pre-push hook repeats
that scan and runs the redacted Gitleaks commit-range wrapper. Both hooks are
local-only: they do not upload repository content or findings.

The Gitleaks wrapper validates commit identifiers from the GitHub event before
passing a fixed argument vector to the scanner.  CI uses read-only repository
permissions, a non-persisted checkout credential, and no secret-bearing report
artifact.
