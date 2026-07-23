#!/bin/sh
set -eu

cd /app/strike
alembic upgrade head

if [ "$#" -eq 0 ]; then
  echo "Strike is run on demand. Supply a command, for example: python -m strike.run_campaign ..." >&2
  exit 64
fi

cd /app
exec "$@"
