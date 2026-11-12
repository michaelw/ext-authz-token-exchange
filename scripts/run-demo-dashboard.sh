#!/usr/bin/env bash

set -euo pipefail

if [ "${1:-}" = "--" ]; then
  shift
fi

exec python3 scripts/developer.py dashboard "$@"
