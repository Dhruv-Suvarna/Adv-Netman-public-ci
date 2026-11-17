#!/usr/bin/env python3
"""Schema/digest checks for the non-installable Stage B review files."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import tempfile


HERE = Path(__file__).resolve().parent
PROPOSALS = HERE / "stage-b"
SPEC = importlib.util.spec_from_file_location("namespace_activation", HERE / "namespace_activation.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def configured(path: Path, policy: Path, *, authorize: bool, targets: str | None = None) -> str:
    text = path.read_text(encoding="utf-8")
    text = text.replace("AUTHORIZATION_APPROVED=no", f"AUTHORIZATION_APPROVED={'yes' if authorize else 'no'}")
    text = text.replace("NFT_POLICY=/etc/nmas/research-egress.nft", f"NFT_POLICY={policy}")
    text = text.replace("NFT_POLICY=/etc/nmas/diagnostic-egress.nft", f"NFT_POLICY={policy}")
    if targets is not None:
        text = text.replace("TARGETS=", f"TARGETS={targets}")
    return text + "TEST_NAMESPACE_NAME=nmas-test-proposal-worker\nTEST_HOST_NAMESPACE=nmas-test-proposal-host\n"


def main() -> int:
    research_policy = PROPOSALS / "research-egress.nft.proposed"
    diagnostic_policy = PROPOSALS / "diagnostic-egress.nft.blocked"
    diagnostic_candidate_policy = PROPOSALS / "diagnostic-egress.nft.proposed"
    assert hashlib.sha256(research_policy.read_bytes()).hexdigest() == "49e1f29de49a3a0a9bfc1b1c6a7cea9c855d8b119d241f2fae1a71379fb26970"
    assert hashlib.sha256(diagnostic_policy.read_bytes()).hexdigest() == "c8e26909224d1e7e84040c307aeca9dde2e204c5bd465f8a20902c75cab70137"
    assert hashlib.sha256(diagnostic_candidate_policy.read_bytes()).hexdigest() == \
           "b166c4d7554750c0894ddc3d741cf8925d3f47e51f18302bff8739ce11d978ee"
    with tempfile.TemporaryDirectory(prefix="nmas-stage-b-proposal-") as temporary:
        root = Path(temporary)
        research = root / "research.env"
        research.write_text(configured(PROPOSALS / "research-namespace.env.proposed", research_policy, authorize=True),
                            encoding="utf-8")
        research.chmod(0o600)
        value = MODULE.normalized_config(research, "research", test_mode=True)
        assert value["egress"] == "ens33" and value["ipv6"] is None
        assert value["https_targets"] == [["104.16.253.120", 443], ["104.16.254.120", 443],
                                           ["104.18.20.81", 443], ["104.18.21.81", 443],
                                           ["199.232.66.132", 443]]
        blocked = root / "diagnostic-blocked.env"
        blocked.write_text(configured(PROPOSALS / "diagnostic-namespace.env.blocked", diagnostic_policy, authorize=False),
                           encoding="utf-8")
        blocked.chmod(0o600)
        try:
            MODULE.normalized_config(blocked, "diagnostic", test_mode=True)
        except MODULE.Refused as exc:
            assert "AUTHORIZATION_APPROVED" in str(exc)
        else:
            raise AssertionError("blocked diagnostic proposal became activatable")
        proposed = root / "diagnostic-proposed.env"
        proposed.write_text(configured(PROPOSALS / "diagnostic-namespace.env.proposed",
                                       diagnostic_candidate_policy, authorize=True), encoding="utf-8")
        proposed.chmod(0o600)
        value = MODULE.normalized_config(proposed, "diagnostic", test_mode=True)
        assert value["targets"] == [["192.168.200.1", 22], ["192.168.200.11", 22],
                                    ["192.168.200.12", 22], ["192.168.200.13", 22],
                                    ["192.168.200.14", 22], ["192.168.200.2", 22]]
        synthetic = root / "diagnostic-synthetic.env"
        synthetic.write_text(configured(PROPOSALS / "diagnostic-namespace.env.blocked", diagnostic_policy, authorize=True,
                                         targets="tcp:192.0.2.10:22"), encoding="utf-8")
        synthetic.chmod(0o600)
        value = MODULE.normalized_config(synthetic, "diagnostic", test_mode=True)
        assert value["targets"] == [["192.0.2.10", 22]]
    print("PASS: research proposal schema/digests and diagnostic fail-closed proposal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
