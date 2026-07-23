#!/bin/sh
set -eu

if [ -z "${HF_TOKEN:-}" ]; then
  echo "HF_TOKEN is required to download the gated Prompt Guard 2 model; set it in .env" >&2
  exit 1
fi

echo "gate_prompt_guard_warmup_started"
python -c 'from detectors.prompt_guard import PromptGuardDetector; PromptGuardDetector.load()'
echo "gate_prompt_guard_warmup_completed"

alembic upgrade head
exec uvicorn app.main:app --host 0.0.0.0 --port "${GATE_PORT:-8000}"
