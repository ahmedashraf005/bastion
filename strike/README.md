# Bastion.Strike

Bastion.Strike is the safety-limited red-team campaign runner. It can target
only the bundled SampleBank Copilot through the reviewed hardcoded allowlist.

Run Strike commands from the repository root with Strike's dedicated virtual
environment; do not use `gate/.venv` for campaign or review commands.

```bash
python3.14 -m venv strike/.venv
strike/.venv/bin/pip install -r strike/requirements.txt
cd strike && ../.venv/bin/alembic upgrade head && cd ..
```

Run a reviewed campaign with explicit safety limits:

```bash
strike/.venv/bin/python -m strike.run_campaign \
  --target sample-bank \
  --attempts strike/attempts/canary_leak.yaml \
  --max-queries 50 \
  --max-wall-clock-seconds 300
```

Review synthesized defensive-rule proposals with the same interpreter:

```bash
strike/.venv/bin/python -m strike.synthesizer.review_cli list
strike/.venv/bin/python -m strike.synthesizer.review_cli show <proposal-id>
```

Gate and SampleBank Copilot must be running before a campaign is invoked.
