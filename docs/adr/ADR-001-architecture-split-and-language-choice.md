# ADR-001: Architecture split and language choice

- Status: Accepted
- Date: 2026-07-21

## Context

Bastion has two distinct operational concerns. Its data plane sits in the
request path and must proxy OpenAI-compatible traffic, inspect streaming
responses, and apply policy decisions with low overhead. Its control plane
manages durable state and operator workflows: policies, findings, audit data,
RBAC, and job control.

The detector ecosystem needed by the data plane is strongest in Python.
Prompt Guard 2, Presidio, and the surrounding Hugging Face tooling are native
to that ecosystem. Management APIs and stateful operator workflows benefit
from ASP.NET's strengths and also make the project's .NET design judgment
visible.

The project is intended to be self-hostable and open source. Its infrastructure
choice must therefore avoid adding unnecessary licensing constraints for
people who run, modify, and distribute their own deployment.

## Decision

Use a Python FastAPI service, Bastion.Gate, as the data plane. It will be a
hand-built OpenAI-compatible reverse proxy with asynchronous streaming
inspection and thin local scanner interfaces around supported Python tools.

Use an ASP.NET Web API, Bastion.Control, as the control plane. It will own
management APIs, policy CRUD, findings, RBAC, audit log access, and job
orchestration. Future .NET projects in this repository must target `net10.0`.
The project chooses .NET 10 because it is the current LTS release and is
supported through November 2028. .NET 8 and .NET 9 reach end of support on
November 10, 2026, so neither is an appropriate starting point for this new
project.

Use Valkey, rather than Redis, for pub/sub, job queueing, and the future
embedding-indexed cache and attack-memory workloads. Valkey is a
BSD-licensed, permissively licensed Redis fork. That avoids copyleft licensing
implications for a self-hostable OSS product while retaining the required
data-structure and vector-search direction.

## Consequences

The service boundary makes the latency-sensitive proxy independently scalable
and keeps management concerns out of the request path. It also introduces a
cross-language boundary that must be specified and tested deliberately through
versioned APIs, shared event contracts, and end-to-end observability.

The split is not a license to duplicate domain logic. Policy semantics must
remain explicit and consistent between the control plane, which authors and
approves policy, and the gate, which evaluates it. The control plane and gate
will therefore need a stable policy representation and an auditable rollout
path.

Valkey is the default for this repository. Replacing it with Redis requires a
new explicit decision because licensing and self-hosting expectations are part
of the product design, not an incidental implementation detail.
