# AGENTS.md

## Project Context

- Authoritative Git repository (all NMAS V2 development, PRs, merges, CI and
  capability-ledger changes): `https://github.com/Dhruv-Suvarna/Adv-Netman-public-ci`,
  default branch `main`. See `docs/AUTHORITATIVE_REPOSITORY.md`.
- Legacy repository `Dhruv-Suvarna/Adv-Netman` (local checkout
  `/home/student/Scripts/clab_dualstack_lab`) is a private legacy and
  security-remediation archive: no new feature commits, branches or development
  PRs there, and none of its Git history may be imported here.
- Active Containerlab runtime directory:
  `/home/student/clab-quickstart`
- The runtime directory is NOT the source of truth.
- Continue from the current repository state; do not restart completed work.

Before making changes, read:
- `AGENTS.md`
- `LAB_REQUIREMENTS.md`
- `IMPLEMENTATION_PLAN.md`
- `GAP_ANALYSIS.md`
- relevant documentation under `docs/`

Also inspect:
- `git status`
- `git log --oneline -5`

## Frozen Lab 1 Baseline

The deployed Lab 1 topology is authoritative for Labs 2 and 3.

Live platforms:

### Arista cEOS 4.36.2F
- R1
- R2
- R5
- S1
- S2
- S3
- S4
- mgmt_swt

### Ubuntu 24.04 + FRRouting 8.4.4
- R3
- R4

There is NO live Nokia SR Linux in the approved Labs 2/3 baseline.

Do NOT change unless explicitly instructed:
- Containerlab topology
- node kinds
- images
- links
- IPv4/IPv6 addressing
- VLANs
- RIP
- OSPF
- BGP
- NAT
- DHCP
- application connectivity
- management addressing

The known H1 -> WebServer connectivity issue is pre-existing and out of scope.

## Containerlab Safety

Do NOT run:
- containerlab deploy
- containerlab destroy
- redeploy
- cleanup
- equivalent topology lifecycle commands

unless explicitly instructed.

Assume the topology is already deployed and management connectivity exists.

Do not recreate containers simply to apply monitoring configuration.

## Infrastructure as Code

Persistent desired state must live in Git.

Prefer:
- modules
- Jinja2 templates
- configuration files
- provisioning scripts
- verification tests
- documentation

`master.py` must remain a thin orchestrator.

Do not place large platform-specific implementations directly inside `master.py`.

Automation must be idempotent and safe to rerun.

## Monitoring Baseline

NMAS:
`192.168.200.100`

Existing monitoring infrastructure includes:
- rsyslog
- SNMP polling
- SNMPv3
- SNMP trap reception
- SNMP trap ingestion
- Syslog collection
- InfluxDB
- Grafana
- logrotate / retention
- Python monitoring environment

Determine completed phases from Git history and documentation.

Do not redo committed phases except for regression verification.

Reuse existing infrastructure instead of creating duplicate:
- collectors
- databases
- InfluxDB buckets
- Grafana instances
- receivers

## Platform Rules

Do not mix configuration syntax between platforms.

- cEOS configuration must use commands supported by the live EOS image.
- R3/R4 must use Ubuntu/FRR-compatible mechanisms.
- R3/R4 do not have normal systemd as PID 1; do not assume systemd is available there.
- Do not introduce Nokia SR Linux configuration into the current Labs 2/3 implementation.

## Operational Safety

Prefer read-only inspection before live modification.

Do NOT:
- shut real topology interfaces
- flap real links
- alter routes for monitoring tests
- break routing adjacencies
- restart routing daemons unnecessarily
- reboot network containers
- alter VLAN or forwarding behavior for monitoring verification

Prefer:
- synthetic test events
- native test commands
- deterministic markers
- disposable dummy interfaces where appropriate

Remove temporary test artifacts afterward.

## Secrets

Never commit:
- runtime credentials
- SNMP authentication/privacy passwords
- InfluxDB tokens
- API keys
- generated secret files

Use the existing ignored:
`monitoring/runtime/`

for runtime secrets.

Before finishing a phase, inspect:
- `git status`
- `git diff`
- `git grep`

for accidental credentials.

## Validation

Before declaring a phase complete:

- validate modified Python/Bash/configuration syntax
- verify live device configuration
- verify the complete end-to-end monitoring path
- run phase-specific verification
- run relevant regression tests
- verify NMAS health
- verify monitoring services remain healthy
- verify topology remains unchanged
- verify lab containers remain running
- prove idempotency where appropriate

Do not report PASS unless it was actually observed.

## Git Workflow

Work one subsystem at a time:

1. inspect
2. implement
3. verify
4. review diff
5. human review
6. commit separately

Do NOT stage or commit implementation changes unless explicitly instructed by the user.

Repository rules (`docs/AUTHORITATIVE_REPOSITORY.md`):
- branch from the latest `main` and open the PR against this repository;
- merge by squash only, so `main` stays a strictly linear chain;
- never force-push or rewrite published history; never push, merge or
  cherry-pick legacy-repository commits -- port legacy work as reviewed source
  changes;
- stage only reviewed files and scan them for credentials before every push;
  no credentials, runtime secrets or private runtime artifacts in commits.

Keep functional phase commits separate where practical.

## Agent Handoff

This file is the authoritative cross-agent project policy.

Only one coding agent should edit this working tree at a time.

When switching between Claude Code and Codex:
- continue from the current Git state
- read this file first
- inspect Git history and working tree
- do not discard another agent's work
- do not restart completed phases
