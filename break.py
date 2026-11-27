#!/usr/bin/env python3
"""NMAS controlled fault-injection harness.  Live transport is fail-closed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "web"))

from core.services.troubleshooting import fault_injection as fi  # noqa: E402


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Prepare, simulate, watch, or independently roll back an allowlisted NMAS fault campaign")
    p.add_argument("action", choices=("digest", "simulate", "run", "rollback", "status"))
    p.add_argument("--flow-map", help="live only: JSON file mapping each protected-flow selector_ref to {source, destination}")
    p.add_argument("--live-state-dir", default=str(Path.home() / "nmas-evidence" / "fault-campaigns"))
    p.add_argument("--poll-seconds", type=int, default=5)
    p.add_argument("--policy", required=True)
    p.add_argument("--fault-id")
    p.add_argument("--authorization-id")
    p.add_argument("--confirm")
    p.add_argument("--state-dir", default="/tmp/nmas-fault-fixture", help="fixture state only; live state is not implemented")
    return p


def main() -> int:
    args = parser().parse_args()
    policy = fi.load_policy(args.policy)
    digest = fi.policy_digest(policy)
    if args.action == "digest":
        print(json.dumps({"policy_sha256": digest}, sort_keys=True))
        return 0
    if args.action in {"run", "rollback", "status"}:
        return live(args, policy)
    if not policy["campaign"]["fixture_only"]:
        raise fi.FaultRefused("LIVE_DRIVER_UNCONFIGURED", "use the 'run' action with --flow-map for an authorized live campaign")
    if not args.fault_id or not args.authorization_id or not args.confirm:
        raise fi.FaultRefused("CAMPAIGN_ARGUMENTS_REQUIRED")
    driver = fi.FixtureDriver()
    store = fi.StateStore(args.state_dir, policy["campaign"]["id"])
    controller = fi.CampaignController(policy, args.fault_id, store, driver)
    results = [controller.prepare(authorization_id=args.authorization_id, confirm=args.confirm),
               controller.inject(authorization_id=args.authorization_id, confirm=args.confirm),
               controller.watchdog(), controller.rollback(reason="fixture simulation complete")]
    print(json.dumps(results, sort_keys=True))
    return 0


def live(args, policy: dict) -> int:
    """One authorized, bounded, reversible fault in the operator's own Containerlab topology.

    ``run`` arms (healthy dual-stack baseline + saved original state), injects, verifies the fault is present, then
    watches until the fault is repaired, a protected flow degrades, or the deadline passes, and restores the original
    state itself if nothing else did.  It prints campaign state only; the injected fault stays in the 0600 state file,
    so the Troubleshooter is never told the ground truth.
    """
    import time

    if policy["campaign"]["fixture_only"] or policy["topology"] != "srlceos01":
        raise fi.FaultRefused("LIVE_POLICY_REQUIRED")
    if not args.fault_id or not args.flow_map:
        raise fi.FaultRefused("CAMPAIGN_ARGUMENTS_REQUIRED", "--fault-id and --flow-map are required")
    flow_map = json.loads(Path(args.flow_map).read_text(encoding="utf-8"))
    driver = fi.ContainerlabCeosDriver(policy["topology"], flow_map)
    store = fi.StateStore(args.live_state_dir, policy["campaign"]["id"])
    controller = fi.CampaignController(policy, args.fault_id, store, driver)
    if args.action == "status":
        print(json.dumps(controller.summary(store.load()), sort_keys=True))
        return 0
    if args.action == "rollback":
        print(json.dumps(controller.rollback(reason="operator emergency rollback"), sort_keys=True))
        return 0
    if not args.authorization_id or not args.confirm:
        raise fi.FaultRefused("CAMPAIGN_ARGUMENTS_REQUIRED")
    print(json.dumps(controller.prepare(authorization_id=args.authorization_id, confirm=args.confirm), sort_keys=True), flush=True)
    result = controller.inject(authorization_id=args.authorization_id, confirm=args.confirm)
    print(json.dumps(result, sort_keys=True), flush=True)
    try:
        while result.get("status") == "ACTIVE":
            time.sleep(max(1, min(int(args.poll_seconds), 30)))
            state = store.load()
            if driver.matches_baseline(controller.fault, state["baseline"]):
                kind = controller.fault["fault_type"]
                receipt = state.get("injection_receipt") or {}
                if kind == "link_flap":
                    reason = "bounded flap sequence completed; link verified up with unchanged configuration"
                elif kind == "peer_carrier_loss":
                    reason = "peer link restored before the deadline by something other than the harness; baseline verified"
                elif kind == "carrier_loss" and receipt.get("verified_link_down") is False:
                    reason = "INJECTION_NOT_HELD: the node reasserted the link before verification; baseline verified (no NMAS action)"
                elif kind == "carrier_loss":
                    reason = "link restored before the deadline without a configuration change; baseline verified"
                else:
                    reason = "original state already restored by remediation; verified"
                result = controller.rollback(reason=reason)
            else:
                result = controller.watchdog()
    except KeyboardInterrupt:
        result = controller.rollback(reason="operator interrupt")
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result.get("status") == "RESTORED" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except fi.FaultRefused as exc:
        print(json.dumps({"status": "REFUSED", "code": exc.code, "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc

