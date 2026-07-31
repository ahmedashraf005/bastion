#!/bin/sh
set -eu

alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${GATE_PORT:-8000}"
