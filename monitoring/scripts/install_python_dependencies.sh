#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
if [[ ! -x "$PYTHON" ]]; then
    [[ ! -e "$NMAS_VENV" ]] || { echo "Existing virtual environment is incomplete: $NMAS_VENV" >&2; exit 1; }
    python3 -m venv "$NMAS_VENV"
fi
PIP_DISABLE_PIP_VERSION_CHECK=1 "$PYTHON" -m pip install -r "$REPO_DIR/requirements.txt" -r "$BASE_DIR/requirements.txt"
"$PYTHON" -m pip check
"$PYTHON" -c 'import yaml, paramiko, netmiko, jinja2, requests, pynetbox; from ncclient import manager; from pygnmi.client import gNMIclient; import grpc'
