#!/usr/bin/env bash
# Run the Phase 4 live harness (web/core/tests/live_management_fixture.py) INSIDE the fixture's NMAS network namespace.
# A private mount namespace remounts sysfs so /sys/class/net shows the namespace's own interfaces (nmas_side reads it);
# nothing on the host is mounted, routed or reconfigured.  Usage: run-harness.sh <evidence dir> [test label suffix]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# NMAS_MGMT_LIVE_MODULE selects another harness module on the same fixture (V2 Phase 8: core.tests.live_dynamic_telemetry_fixture).
EVIDENCE="${1:?evidence directory}"; LABEL="${NMAS_MGMT_LIVE_MODULE:-core.tests.live_management_fixture}${2:+.$2}"
PY="${NMAS_PYTHON:-/home/student/Scripts/.venv-ci/bin/python}"
PID="$("$HERE/fixture.sh" nmas-pid)"
USER_NAME="$(id -un)"
cd "$REPO/web"
exec sudo -n nsenter -t "$PID" -n unshare --mount --propagation private sh -c \
  'mount -t sysfs nmas-fixture-sysfs /sys && exec sudo -n -u "$0" env HOME="$1" PATH="$2" DJANGO_DEBUG=1 NMAS_MGMT_LIVE_FIXTURE=1 NMAS_MGMT_LIVE_EVIDENCE="$3" NMAS_P8_TSDB_RUNTIME="$6" "$4" manage.py test "$5"' \
  "$USER_NAME" "$HOME" "$PATH" "$EVIDENCE" "$PY" "$LABEL" "${NMAS_P8_TSDB_RUNTIME:-}"
