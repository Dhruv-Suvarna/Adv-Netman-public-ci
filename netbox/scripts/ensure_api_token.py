#!/usr/bin/env python3
"""Idempotent bootstrap of the NetBox API token used by modules/netbox_ipam.py.

Why this exists instead of the SUPERUSER_API_TOKEN/SUPERUSER_API_KEY
environment variables netbox-docker's own docker/super_user.py accepts:
NetBox 4.7 stores API tokens as v2 "hashed" tokens -- the (key, token) pair
is generated together by NetBox itself and only an HMAC digest is persisted
(see users/models/tokens.py in the pinned netbox-community/netbox v4.7.0
release). Pre-supplying our own key/token pair through environment variables
would mean reproducing that generation scheme outside NetBox to guarantee it
validates; asking NetBox's own Django ORM to generate the token is the
supported mechanism and is what this script does, via `manage.py shell -c`
(the exact approach netbox-docker's own super_user.py uses for the initial
superuser, just invoked here for a second, later step).

This script is:
  * idempotent: it never creates a second token if one is already recorded
    in netbox/.env, and it never overwrites an existing NETBOX_TOKEN value.
  * safe to rerun: running it again after a successful run is a fast no-op.
  * explicit: it distinguishes "token already present", "token already
    exists in NetBox but its plaintext is unknown to us" (requires a human
    decision -- NetBox cannot reveal a v2 token's plaintext after creation),
    and genuine failures (container not running, manage.py error, ORM
    exception) -- it never silently swallows any of them.
  * non-destructive: it never deletes or rotates an existing token.

Never hacks the NetBox database directly -- every NetBox-side operation goes
through `manage.py shell`, i.e. NetBox's own Django ORM.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

NETBOX_DIR = Path(__file__).resolve().parents[1]
ENV_FILE = NETBOX_DIR / ".env"
COMPOSE_FILE = NETBOX_DIR / "docker-compose.yml"

# Executed inside the netbox container via `manage.py shell -c`. Emits
# exactly one JSON line on stdout so the wrapper below can parse it reliably
# regardless of any other Django/shell banner output.
TOKEN_SCRIPT = """
import json
from django.contrib.auth import get_user_model
from users.models import Token

User = get_user_model()
username = {username!r}

try:
    user = User.objects.get(username=username)
except User.DoesNotExist:
    print("NETBOX_TOKEN_RESULT " + json.dumps({{"status": "error", "message": f"No such user: {{username}}"}}))
else:
    existing = Token.objects.filter(user=user).count()
    if existing:
        print("NETBOX_TOKEN_RESULT " + json.dumps({{"status": "exists", "count": existing}}))
    else:
        token = Token.objects.create(user=user)
        value = f"nbt_{{token.key}}.{{token.token}}" if token.v2 else token.token
        print("NETBOX_TOKEN_RESULT " + json.dumps({{"status": "created", "token": value}}))
"""


def read_env(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise SystemExit(f"ERROR: {path} does not exist. Run bootstrap_netbox.sh first.")
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip()
    return values


def write_token(path: Path, token_value: str) -> None:
    lines = path.read_text().splitlines()
    pattern = re.compile(r"^NETBOX_TOKEN=")
    replaced = False
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = f"NETBOX_TOKEN={token_value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"NETBOX_TOKEN={token_value}")
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)


def run_in_netbox(python_code: str) -> str:
    cmd = [
        "docker", "compose", "-f", str(COMPOSE_FILE), "exec", "-T", "netbox",
        "/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py", "shell", "-c", python_code,
    ]
    result = subprocess.run(cmd, cwd=NETBOX_DIR, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise SystemExit(
            "ERROR: manage.py shell failed while ensuring the API token exists "
            f"(exit {result.returncode}).\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result.stdout


def extract_result(stdout: str) -> dict:
    for line in stdout.splitlines():
        if line.startswith("NETBOX_TOKEN_RESULT "):
            return json.loads(line[len("NETBOX_TOKEN_RESULT "):])
    raise SystemExit(
        "ERROR: manage.py shell ran but did not emit a parseable result line. "
        f"Full output:\n{stdout}"
    )


def main() -> int:
    env = read_env(ENV_FILE)
    if env.get("NETBOX_TOKEN"):
        print("API token already present in netbox/.env; skipping (idempotent).")
        return 0

    username = env.get("SUPERUSER_NAME")
    if not username:
        raise SystemExit("ERROR: SUPERUSER_NAME is not set in netbox/.env")

    stdout = run_in_netbox(TOKEN_SCRIPT.format(username=username))
    result = extract_result(stdout)

    if result["status"] == "error":
        raise SystemExit(f"ERROR: {result['message']}")

    if result["status"] == "exists":
        print(
            f"NetBox already has {result['count']} API token(s) for user {username!r}, "
            "but netbox/.env has no NETBOX_TOKEN value. NetBox's v2 tokens cannot be "
            "read back after creation, so this script will NOT create a duplicate "
            "silently. Resolve manually: either recover the token value you recorded "
            "elsewhere, or delete the existing token for this user via the NetBox UI/"
            "API and rerun this script to have a fresh one generated.",
            file=sys.stderr,
        )
        return 2

    # result["status"] == "created"
    write_token(ENV_FILE, result["token"])
    print(f"API token created for user {username!r} and stored in netbox/.env (not displayed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
