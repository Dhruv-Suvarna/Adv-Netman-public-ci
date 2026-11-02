#!/usr/bin/env bash
# Shared paths and Docker privilege handling. No host configuration occurs here.
BASE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REPO_DIR=$(dirname "$BASE_DIR")
export NMAS_VENV=${NMAS_VENV:-"$(dirname "$REPO_DIR")/.venv"}
PYTHON="$NMAS_VENV/bin/python"
if ! command docker info >/dev/null 2>&1; then
    docker() { sudo -n docker "$@"; }
fi
