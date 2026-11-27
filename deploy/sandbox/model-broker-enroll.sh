#!/bin/bash
# Enroll or replace the provider credential (and optionally the model id) of one NMAS model broker.
# Run in your own terminal:  sudo sh deploy/sandbox/model-broker-enroll.sh <codex|claude-a|claude-b> [model-id]
# The key is read without echo, written only to the root-owned broker environment file, and never printed.
set -eu
instance=${1:-}; model=${2:-}
case "$instance" in codex|claude-a|claude-b) ;; *) echo "usage: $0 <codex|claude-a|claude-b> [model-id]" >&2; exit 64;; esac
file=/etc/nmas/model-broker-$instance.env
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 77; }
[ -f "$file" ] && [ ! -L "$file" ] || { echo "missing $file" >&2; exit 66; }
case "$model" in *[!A-Za-z0-9._:-]*) echo "invalid model id" >&2; exit 65;; esac
[ -t 0 ] || { echo "a terminal is required so the key is not echoed or logged" >&2; exit 65; }
printf 'Provider API key for %s (input hidden): ' "$instance" >&2
stty -echo; trap 'stty echo' EXIT INT TERM; IFS= read -r key; stty echo; trap - EXIT INT TERM; printf '\n' >&2
case "$key" in ''|*[!A-Za-z0-9._-]*) echo "empty or malformed key; nothing changed" >&2; exit 65;; esac
umask 077; tmp=$(mktemp "$file.XXXXXX")
grep -v '^NMAS_TS_MODEL_PROVIDER_CREDENTIAL=' "$file" | { if [ -n "$model" ]; then sed "s|^NMAS_TS_MODEL_ID=.*|NMAS_TS_MODEL_ID=$model|"; else cat; fi; } > "$tmp"
printf 'NMAS_TS_MODEL_PROVIDER_CREDENTIAL=%s\n' "$key" >> "$tmp"; key=
chown root:"nmas-ts-model-$instance" "$tmp"; chmod 0640 "$tmp"; mv "$tmp" "$file"
echo "credential stored in $file; restart with: systemctl restart nmas-ts-model-broker@$instance" >&2
