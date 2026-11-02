#!/usr/bin/env bash
# Run the FRR isolation live harness (web/core/tests/live_frr_isolation_fixture.py) against the disposable fixture with the
# fixture settings (runtime/ database), INSIDE the network namespace of the fixture's service host (nmasfrrfx-svc,
# 10.254.92.2 -- the NMAS source the fixture models).  NMAS reaches the trusted upstream only over SSH (management.linux_ssh);
# `docker exec nmasfrrfx-*` is used by the harness only as the fixture's out-of-band observer and traffic generator.
#
# Usage: run-harness.sh migrate | <stage> [<stage> ...]     (stages: see the harness module docstring)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${NMAS_PYTHON:-/home/student/Scripts/.venv-ci/bin/python}"
mkdir -p "$HERE/runtime"
cd "$REPO/web"
if [ "${1:-}" = "migrate" ]; then
  exec env DJANGO_DEBUG=1 PYTHONPATH="$HERE" DJANGO_SETTINGS_MODULE=settings_fixture "$PY" manage.py migrate --noinput
fi
PID="$("$HERE/fixture.sh" svc-pid)"
exec sudo -n nsenter -t "$PID" -n sudo -n -u "$(id -un)" env HOME="$HOME" PATH="$PATH" DJANGO_DEBUG=1 PYTHONPATH="$HERE" \
  DJANGO_SETTINGS_MODULE=settings_fixture NMAS_FRR_LIVE_STAGES="$*" NMAS_FRR_LIVE_EVIDENCE="${NMAS_FRR_LIVE_EVIDENCE:-$HERE/runtime/evidence}" \
  "$PY" manage.py shell -c "from core.tests.live_frr_isolation_fixture import main; main()"
