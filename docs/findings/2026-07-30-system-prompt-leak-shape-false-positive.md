# Gate false positive: shape-only canary pattern

- Finding ID: `gate-fp-system-prompt-leak-shape-prefix-20260730-001`
- Classification: false positive
- Source case: `span-partial-marker-prefix-001` in `tests/corpus/benign.yaml`
- Gate source commit tested: `2322284150067a4c467d809a9264f957b49de982`
- Runtime validation: the running Gate container's
  `detectors/system_prompt_leak.py` SHA-256 was
  `753077b52297aa447039721276de081a9a41f4536207f0f812ae01f90d6e5300`,
  identical to the source file at the tested commit.
- Responsible detector / pattern: `system_prompt_leak` /
  `example-canary-pattern` (`BASTIONCANARY[A-Z0-9]{8}`, case-insensitive,
  `strip_separators`)

## Byte-exact evidence

The UTF-8 payload is 143 bytes; SHA-256:
`5076d43bafa56fd6207f18bfa2a761a4563bebe19a28a6ad201e17b03c2976bc`.

```text
The internal training example prefix BASTION-CANARY- is incomplete here; the customer-facing reference is NOT-A-SECRET and must remain visible.
```

The payload is ASCII only. Its complete codepoint sequence is retained in
the source corpus; it is byte-for-byte the string above.

## Mechanical result

After Gate's current shared `strip_separators` comparison normalization,
the regex matched normalized span `(32, 53)`:

```text
BASTIONCANARYisincomp
```

The index map mapped that to raw span `(37, 62)`, byte-exact raw text:

```text
BASTION-CANARY- is incomp
```

Gate redacted that 25-character span and returned:

```text
The internal training example prefix [REDACTED]lete here; the customer-facing reference is NOT-A-SECRET and must remain visible.
```

This is not a Strike bypass finding: no configured marker value was
disclosed. It is a deployed Gate detector correctness finding. The shape
regex accepts arbitrary letters after the public prefix, so a partial marker
prefix followed by ordinary prose can satisfy its eight-character suffix.
