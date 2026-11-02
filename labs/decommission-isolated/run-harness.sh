#!/usr/bin/env bash
# Run the V2 Phase 7 live harness (web/core/tests/live_decommission_fixture.py) INSIDE the fixture's NMAS network namespace -- the
# only route to the fixture routers -- with the fixture settings (runtime/ database).  Nothing on the host is routed or reconfigured.
#
# Usage: run-harness.sh migrate | <stage> [<stage> ...]     (stages: see the harness module docstring)
# NMAS_LIVE_MODULE selects another live harness module run in the same namespace (default: the Phase 7 decommission harness).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${NMAS_PYTHON:-/home/student/Scripts/.venv-ci/bin/python}"
PID="$("$HERE/fixture.sh" nmas-pid)"
EVIDENCE="${NMAS_P7_LIVE_EVIDENCE:-$HERE/runtime/evidence}"
cd "$REPO/web"
if [ "${1:-}" = "migrate" ]; then
  exec env DJANGO_DEBUG=1 PYTHONPATH="$HERE" DJANGO_SETTINGS_MODULE=settings_fixture "$PY" manage.py migrate --noinput
fi
exec sudo -n nsenter -t "$PID" -n sudo -n -u "$(id -un)" env HOME="$HOME" PATH="$PATH" DJANGO_DEBUG=1 PYTHONPATH="$HERE" \
  DJANGO_SETTINGS_MODULE=settings_fixture NMAS_P7_LIVE_EVIDENCE="$EVIDENCE" NMAS_P7_LIVE_STAGES="$*" NMAS_RIP_LIVE_EVIDENCE="${NMAS_RIP_LIVE_EVIDENCE:-$HERE/runtime/evidence-rip}" \
  "$PY" manage.py shell -c "from ${NMAS_LIVE_MODULE:-core.tests.live_decommission_fixture} import main; main()"
