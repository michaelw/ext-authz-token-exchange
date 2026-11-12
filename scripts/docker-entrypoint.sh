#! /bin/sh
set -e

if [ ! -w /go-cache ]; then
  sudo chown devuser:devuser /go-cache
fi
exec "$@"
