"""Launcher: ``python -m challenge_console`` (or ``scripts/run_challenge_console.sh``).

    python -m challenge_console                 the Tkinter console
    python -m challenge_console --headless 60   run the collectors without a display for 60 s, print a summary, save the session
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import APP_TITLE, VERSION
from .config import ConsoleConfig
from .runtime import DISCARD, SAVE, ConsoleRuntime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="challenge_console", description=f"{APP_TITLE} {VERSION} (read-only)")
    parser.add_argument("--headless", type=float, metavar="SECONDS", help="collect without a display for this long, then exit")
    parser.add_argument("--no-save", action="store_true", help="with --headless: discard the session log instead of saving it")
    parser.add_argument("--save-dir", help="where a saved session goes (default: the user data directory)")
    parser.add_argument("--print-config", action="store_true", help="print the effective configuration and exit")
    args = parser.parse_args(argv)

    config = ConsoleConfig.from_env(**({"save_dir": Path(args.save_dir).expanduser()} if args.save_dir else {}))
    if args.print_config:
        print(json.dumps(config.public_dict(), indent=2))
        return 0

    if args.headless is not None:
        runtime = ConsoleRuntime(config)
        runtime.start()
        try:
            time.sleep(max(0.0, args.headless))
        except KeyboardInterrupt:
            pass
        saved = runtime.finish(DISCARD if args.no_save else SAVE)
        print(json.dumps({"summary": runtime.store.summary(), "saved": str(saved) if saved else None,
                          "leftover_workers": runtime.leftover_workers}, indent=2))
        return 1 if runtime.leftover_workers else 0

    try:
        from .ui.app import run
    except ImportError as exc:
        if "tkinter" in str(exc).lower():
            print("Tkinter is not available to this Python. Install it with:  sudo apt install python3-tk\n"
                  "(the collectors can still be run without a display:  python -m challenge_console --headless 60)", file=sys.stderr)
            return 2
        raise
    return run(config)


if __name__ == "__main__":
    sys.exit(main())
