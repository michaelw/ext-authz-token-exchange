#!/usr/bin/env bash

set -euo pipefail

if [ "${1:-}" = "--" ]; then
  shift
fi

exec go run ./cmd/demo-dashboard "$@"
