# Bastion.Strike

Bastion.Strike is the safety-limited red-team campaign runner. It can target
only the bundled SampleBank Copilot through the reviewed hardcoded allowlist.
The supported operator command is `bastion strike run --config <campaign.yaml>`;
the direct module command below remains useful for development and diagnostics.

Run Strike commands from the repository root with Strike's dedicated virtual
environment; do not use `gate/.venv` for campaign or review commands.

```bash
python3.14 -m venv strike/.venv
strike/.venv/bin/pip install -r strike/requirements.txt
strike/.venv/bin/alembic -c strike/alembic.ini upgrade head
```

Run a reviewed campaign:

```bash
strike/.venv/bin/python -m strike.run_campaign \
  --target sample-bank \
  --attempts strike/attempts/canary_leak.yaml
```

`--max-queries`/`--max-wall-clock-seconds` override the campaign YAML's own
limits (or the 50/300 fallback if the YAML sets neither) — the fallback is
sized for a worst-case adaptive campaign and is far more than a static
attempts list like `canary_leak.yaml` ever uses; do not pass it as an
example for an adaptive or branching campaign. `canary_leak_branching.yaml`
sets its own calibrated 20-query/600-second budget in the YAML instead of
relying on the fallback.

Render a campaign's evidence:

```bash
strike/.venv/bin/python -m strike.report --campaign <campaign-id>
strike/.venv/bin/python -m strike.report --campaign <campaign-id> --format json
```

`bastion report` is the supported operator command for this; the direct
module command is for development.

Review synthesized defensive-rule proposals with the same interpreter:

```bash
strike/.venv/bin/python -m strike.synthesizer.review_cli list
strike/.venv/bin/python -m strike.synthesizer.review_cli show <proposal-id>
```

Gate and SampleBank Copilot must be running before a campaign is invoked. The
Compose-backed quickstart starts them with `bastion gate up`.
