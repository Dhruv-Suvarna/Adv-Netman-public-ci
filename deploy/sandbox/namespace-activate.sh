#!/bin/sh
# Independent NMAS namespace lifecycle launcher. Production mutations still
# require the separately approved configuration and change window documented in
# docs/troubleshooting/validation/staged-production-rollout-and-rollback.md.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec /usr/bin/python3 -I "$script_dir/namespace_activation.py" "$@"
