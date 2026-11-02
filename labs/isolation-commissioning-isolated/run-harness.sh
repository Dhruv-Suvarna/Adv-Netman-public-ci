#!/usr/bin/env bash
# Run the V2 Phases 5 + 6 live harness (web/core/tests/live_isolation_commissioning_fixture.py) INSIDE the fixture's
# bootstrap-service network namespace -- the only route to the fixture -- with the fixture settings (runtime/ database,
# enrollment store and DHCP provider root).  Nothing on the host is mounted, routed or reconfigured.
#
# Usage: run-harness.sh migrate | <stage> [<stage> ...]     (stages: see the harness module docstring)
#        NMAS_ISO_LIVE_NETBOX_ENV=<labs/managed-scope-isolated/runtime/fixture-client.env> selects the real NetBox gateway
#        against the disposable NetBox (labs/managed-scope-isolated/netbox.sh) instead of the in-memory one.
#        NMAS_LIVE_MODULE selects another harness run the same way (V2 Phase 9: core.tests.live_option82_ztp_fixture,
#        core.tests.live_ipv6_admission_fixture).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${NMAS_PYTHON:-/home/student/Scripts/.venv-ci/bin/python}"
PID="$("$HERE/fixture.sh" svc-pid)"
EVIDENCE="${NMAS_ISO_LIVE_EVIDENCE:-$HERE/runtime/evidence}"
cd "$REPO/web"
if [ "${1:-}" = "migrate" ]; then
  exec env DJANGO_DEBUG=1 PYTHONPATH="$HERE" DJANGO_SETTINGS_MODULE=settings_fixture "$PY" manage.py migrate --noinput
fi
exec sudo -n nsenter -t "$PID" -n sudo -n -u "$(id -un)" env HOME="$HOME" PATH="$PATH" DJANGO_DEBUG=1 PYTHONPATH="$HERE" \
  DJANGO_SETTINGS_MODULE=settings_fixture NMAS_ISO_LIVE_EVIDENCE="$EVIDENCE" NMAS_ISO_LIVE_STAGES="$*" \
  NMAS_ISO_LIVE_NETBOX_ENV="${NMAS_ISO_LIVE_NETBOX_ENV:-}" \
  "$PY" manage.py shell -c "from ${NMAS_LIVE_MODULE:-core.tests.live_isolation_commissioning_fixture} import main; main()"
