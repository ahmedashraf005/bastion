# ADR-011: Control-plane v1 read-only observability

- Status: Accepted
- Date: 2026-07-22

## Context

ADR-001 assigns management APIs, policies, findings, RBAC, audit access, and
job orchestration to Bastion.Control. None of those responsibilities justify
displacing the working Gate YAML policy flow or Strike review CLI before the
first .NET service has proven it can read shared operational data reliably.
The forthcoming dashboard also needs a real API rather than direct operator SQL.

The services share one physical Postgres instance but own separate schemas and
migration histories. Gate and Strike already own their schemas through
Alembic. Control needs its own schema and EF Core history without taking over
their tables or migrations.

## Decision

Control v1 is a read-only observability API over Strike campaigns, findings,
and proposed rules, plus recent Gate traffic. It deliberately does not add
policy CRUD, RBAC, authentication, job control, or any write endpoint. This
proves a real .NET API against real shared data without displacing flows that
already work, and provides the dashboard's first API surface.

Control owns schema `control` and migrates it exclusively through EF Core. In
v1 the schema contains no domain tables: the initial migration creates only
the schema, ready for a future real Control-owned concern such as RBAC. EF
Core's service-prefixed migration ledger lives in `public` so `control` stays
empty; this internal tooling metadata is the same necessary exception already
documented for service migration ledgers. EF Core is used only for this
Control-owned schema.

Read-only queries into `gate.requests`, `strike.campaigns`,
`strike.findings`, and `strike.proposed_rules` use Dapper with explicit,
parameterized `SELECT` statements. Force-mapping tables owned by another
service's migration history into EF Core is an anti-pattern: it creates a
false ownership boundary and can silently break when that service evolves its
own schema. Cross-schema references remain plain identifiers; Control adds no
cross-schema foreign keys.

Control v1 has no authentication or RBAC. Those are substantial capabilities
in their own right and are intentionally deferred rather than bolted onto the
first .NET service alongside data access.

The repository uses `control/global.json` to pin the required .NET 10 SDK and
a project-local `control/dotnet10` wrapper to select the installed .NET 10
host on this machine. This avoids shell-profile or PATH changes while keeping
the intended SDK version explicit and portable for contributors and CI.

## Consequences

Control v1 is an internal observability tool, not a security boundary. Until
authentication and RBAC exist, it must not be exposed as a production
management interface.

The Gate YAML policy and Strike review CLI remain authoritative for their
existing write workflows. Future Control work must deliberately replace or
integrate those workflows rather than accidentally duplicating them.

Control's Dapper reads expose only selected summary fields and remain
mechanically separate from its EF Core ownership boundary. If a source schema
changes, the explicit query and DTO must be reviewed rather than being
implicitly inferred through an ORM mapping.
