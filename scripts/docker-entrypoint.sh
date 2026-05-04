#! /bin/sh
set -e

sudo chown devuser:devuser /go-cache
devspace run setup
devspace run generate

exec "$@"
