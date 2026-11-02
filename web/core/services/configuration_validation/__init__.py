"""Configuration Validation: the external (GitHub Actions) test of one validated Configuration Change candidate.

    bundle.py    the sanitized, hash-bound validation bundle and its transport encoding (pure)
    checks.py    what the workflow tests on a bundle (pure: no database, no device, no network)
    github.py    the one module that talks to the GitHub REST API (dispatch, run lookup)
    service.py   dispatch after a passing Tier-2 run, status tracking, staleness and the execution gate

GitHub Actions validates only.  Nothing in this package, and nothing the workflow runs, opens a device session, sends
configuration, executes a Configlet or writes NetBox.
"""
