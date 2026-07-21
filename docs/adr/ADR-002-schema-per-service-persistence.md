# ADR-002: Schema-per-service persistence

- Status: Accepted
- Date: 2026-07-21

## Context

Bastion.Gate now needs durable request logging in Postgres. Bastion.Control
will later use the same physical Postgres instance for policies, findings,
RBAC, and audit data. The services use different ecosystems and migration
tooling: Gate uses Python with SQLAlchemy and Alembic, while Control will
choose its .NET tooling, most likely EF Core, when that service is built.

Allowing both migration systems to own one flat database namespace would risk
migration collisions and would couple the data plane and control plane in a
way that conflicts with the architectural split recorded in ADR-001.

## Decision

Use a schema-per-service model within the shared Postgres database. Gate owns
the `gate` schema and exclusively migrates objects in that schema. Control
will own the `control` schema when it exists and will exclusively migrate its
own objects. Each future service follows the same ownership rule.

If one service needs to reference a record owned by another, it stores the
identifier as a plain UUID column. Bastion will not create database-enforced
foreign keys across service schema boundaries. Schema creation is part of the
owning service's versioned migration history rather than an out-of-band
initialization step.

## Consequences

There is no database-level referential integrity across planes. If cross-schema
consistency is needed later, it is an application-level concern that must be
designed, monitored, and tested explicitly.

Each service's migration tool touches only its owned schema. Gate's Alembic
migrations and Control's future EF Core migrations therefore cannot collide or
require coordinated migration histories, while both services can still use the
same physical Postgres instance.
