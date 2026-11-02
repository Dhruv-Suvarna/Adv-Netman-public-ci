#!/usr/bin/env python3
"""Thin launcher for the Tier-3 change-effect / regression validator (Phase 16).

All logic lives in web/core/services/ci (pure Python, no Django configuration needed):

    python tier3.py --base <sha> --head <sha>          targeted validation of a comparison
    python tier3.py --mode full                        the whole regression surface
    python tier3.py --base origin/main --working-tree  validate uncommitted work before committing
    python tier3.py --from-github                      inside GitHub Actions (derives base/head from the event)

Validation only: nothing is deployed, no device or NetBox write, no Containerlab lifecycle command.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "web"))

from core.services.ci.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
