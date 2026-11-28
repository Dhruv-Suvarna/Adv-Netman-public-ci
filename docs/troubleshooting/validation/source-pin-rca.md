# Root cause: gateway source pin `PermissionError: monitoring/runtime/influxdb2-engine`

Investigated 2026-11-10 by a standalone engineering agent on VM 1 (read-only against the gateway; no permission, policy or
service change).

## Symptom

Every attested run requested by JOB-9AA10B4E7CA7 (`aiorch_gw.py pin|test clab_dualstack_lab …`, e.g. runs `ptdbf812013e3e`,
`ptd226f8fb5671`) ended in state `error` with
`source pin failed: PermissionError: [Errno 13] Permission denied: '/home/student/Scripts/clab_dualstack_lab/monitoring/runtime/influxdb2-engine'`.

## What touches the path

`/opt/ai-orchestrator/gateway/sandbox_pin.py` (sha256 prefix `163a7767…`, identical to `~/ai-orchestrator/gateway/sandbox_pin.py`)
runs inside the gateway sandbox as the project owner with **no supplementary groups** and walks the worktree with `os.scandir`.
Its `walk()` hashes, and in `copy` mode copies, **every** regular file except `.git`, `__pycache__`, `*.pyc` and test caches. It
does not consult `.gitignore`.

## What the path is

| Path | Owner / mode | Git status | Nature |
|---|---|---|---|
| `monitoring/runtime/influxdb2-engine` | `vmware:student 0700` | ignored (`.gitignore:1 monitoring/runtime/*`) | live InfluxDB engine data of the running monitoring stack |
| `monitoring/runtime/influxdb2` | `vmware:student 0700` | ignored | InfluxDB state |
| `monitoring/runtime/grafana` | `472:root 0750` | ignored | Grafana state |
| `monitoring/runtime/{monitoring.env,snmp-secrets.json,telemetry-secrets.json}` | `student 0600` | ignored | runtime secrets |

It is runtime state, not tracked source. The legacy checkout is the directory the live monitoring stack runs from, so its
ignored runtime tree is populated.

## Reproduction (read-only, same helper, same uid)

```
python3 -I -S -B /opt/ai-orchestrator/gateway/sandbox_pin.py hash /home/student/Scripts/clab_dualstack_lab
  -> PermissionError: [Errno 13] Permission denied: '.../monitoring/runtime/influxdb2-engine'
python3 -I -S -B /opt/ai-orchestrator/gateway/sandbox_pin.py hash /home/student/Scripts/nmas-public-dev
  -> {"head": "4f950b36…", "origin": "https://github.com/Dhruv-Suvarna/Adv-Netman-public-ci.git", "tree_sha256": …}
```

## The actual root cause: wrong repository

Even with the directory readable, the pin would still be refused. `_pin()` in `aiorch_gateway.py` checks
`result["origin"] in cfg["repository"]["origin_urls"]`; the installed policy (`POLICY_SHA256 412ef58e…`, pinned by
`privileged/deploy/GATEWAY_MANIFEST`) authorizes only `Dhruv-Suvarna/Adv-Netman-public-ci`. `clab_dualstack_lab` has origin
`Dhruv-Suvarna/Adv-Netman`, the private legacy archive. Per `AGENTS.md` and `docs/AUTHORITATIVE_REPOSITORY.md`, no feature
development may happen there and its work must be ported as reviewed source. The PermissionError only surfaced first because
`walk()` runs before the origin check.

Contributing cause: `LAB_REQUIREMENTS.md`, `IMPLEMENTATION_PLAN.md` and `GAP_ANALYSIS.md` (which `CLAUDE.md` tells every agent to
read) still say new artifacts belong in `/home/student/Scripts/clab_dualstack_lab`. That text predates the authoritative-repository
policy and steered the job's agents into the archive.

## Correction (smallest change consistent with the trust model)

No gateway change. Granting the sandbox access to `vmware`-owned data, adding a skip-on-error, or adding the legacy origin to the
allowlist would each weaken provenance or isolation. Instead the troubleshooting work was ported as reviewed source into a
worktree of the authorized repository: `/home/student/Scripts/nmas-public-dev-troubleshooting`, branch
`troubleshooting/job-9aa10b4e7ca7-port` from `origin/main` `4f950b3`. The installed helper pins it without error (see the
continuation report for the exact pin).

## Optional hardening (not required; separate approval)

`walk()` copying gitignored runtime secrets into the test sandbox is a latent exposure if an authorized worktree ever holds a
populated `monitoring/runtime/`. `_vm_pin` already uses "tracked + untracked, `.gitignore` honoured". Aligning `sandbox_pin.py`
with that (enumerate with `git ls-files -c -o --exclude-standard -z`, `lstat` each entry, fail closed on an unreadable *listed*
file) keeps the attestation equal to exactly what the test sandbox executes. It changes `tree_sha256` semantics, so it needs a
gateway re-pin (`GATEWAY_MANIFEST`, `SHA256SUMS`, deploy pins) and an operator deploy. It is recommended, not staged.
