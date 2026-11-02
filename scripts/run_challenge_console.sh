#!/usr/bin/env bash
# Launch the standalone NMAS challenge console (read-only; needs neither the NMAS website nor a browser).
#   scripts/run_challenge_console.sh                 the Tkinter console
#   scripts/run_challenge_console.sh --headless 60   collectors only, no display
# Python: NMAS_CONSOLE_PYTHON, else the shared project environment, else python3.  Tkinter itself comes from the
# distribution package python3-tk (sudo apt install python3-tk); this script never elevates privileges.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python="${NMAS_CONSOLE_PYTHON:-/home/student/Scripts/.venv/bin/python}"
[ -x "$python" ] || python="$(command -v python3)"
cd "$repo_root"
exec "$python" -m challenge_console "$@"
