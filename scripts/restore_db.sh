#!/bin/sh
# Restore a strike+gate schema dump produced by backup_db.sh.
#
# Usage: scripts/restore_db.sh backups/bastion-<timestamp>.dump [target-db]
#
# Restores into POSTGRES_DB (from .env) by default. Pass a second argument
# to restore into a different database instead (e.g. a scratch database for
# verifying a backup without touching live data) — that database must
# already exist and be reachable by the same postgres container.
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 <dump-file> [target-db]" >&2
  exit 2
fi
dump="$1"

cd "$(dirname "$0")/.."
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

target_db="${2:-${POSTGRES_DB:-bastion}}"

docker compose exec -T postgres \
  pg_restore -U "${POSTGRES_USER:-bastion}" -d "$target_db" --clean --if-exists --no-owner \
  < "$dump"

echo "restored '$dump' into database '$target_db'"
