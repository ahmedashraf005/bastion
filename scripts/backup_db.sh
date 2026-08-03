#!/bin/sh
# Back up the strike and gate schemas — the source-of-truth data — to a
# local, timestamped custom-format pg_dump file. control's schema is a
# read-only projection over the same data and is not backed up separately.
#
# There is no backup scheduler here; run this manually before anything that
# could disrupt the Postgres volume (e.g. changing COMPOSE_PROJECT_NAME,
# experimenting with a second checkout, or any raw `docker compose down -v`).
set -eu

cd "$(dirname "$0")/.."
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

mkdir -p backups
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
out="backups/bastion-${timestamp}.dump"

docker compose exec -T postgres \
  pg_dump -U "${POSTGRES_USER:-bastion}" -d "${POSTGRES_DB:-bastion}" -n strike -n gate -Fc \
  > "$out"

echo "backup written: $out"
