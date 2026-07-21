# ADR-003: Interim policy storage as YAML

- Status: Accepted
- Date: 2026-07-21

## Context

ADR-001 assigns policy CRUD to Bastion.Control. That control-plane service
does not exist yet, while Bastion.Gate now needs policy rules to evaluate in
the live request path.

## Decision

Store Gate policy rules in the version-controlled
`gate/policy/rules.yaml` file. Gate loads this file once at service startup
and retains the resulting policy engine for its process lifetime.

This phase deliberately has no policy hot-reload. Changing a rule requires a
Gate restart; that limitation is intentional while Control is not available
to own policy management.

## Consequences

When Bastion.Control is built, a future ADR must decide how policy reaches
Gate at runtime, such as an internal API push, polling, or a shared table.
This YAML file is not that permanent mechanism and must not be treated as
one.

The rule shape defined in this file is the interim policy contract. Control's
future policy model should produce the same shape, even though nothing in this
phase enforces that alignment yet.
