# Specification quality profile

Use this profile for product, architecture, UX, workflow, policy, test-strategy, governance, API, data, operational, or other design specifications.

## Full-context framing

- Review the prompt, visible history, repository, current docs, contracts, constraints and implementation reality.
- State the problem, users, value, current behavior and desired outcome.
- Separate current scope, future options and non-goals.
- Record authoritative sources, facts, assumptions, hypotheses, risks and unknowns.
- Preserve legitimate ambiguity until evidence or specialist input resolves it.

## Concept and alternatives

- Present the smallest viable concept before detail.
- Research authoritative standards and relevant proven case studies where claims could have changed or are uncertain.
- Compare credible alternatives, including retaining current behavior.
- Record each material decision, rationale, rejected alternatives, consequences and reversal path.

## Three Amigos review

### Business

- Validate user value, outcomes, scope, policy, ownership, priority and acceptable risk.

### Engineering

- Validate feasibility, architecture, contracts, dependency direction, failure semantics, performance, operability and migration.

### QA

- Validate testability, observable outcomes, ambiguity, acceptance criteria, negative paths, data needs and evidence quality.

Resolve disagreements explicitly. Do not average incompatible positions into vague prose.

## Specialist review

Use every perspective materially touched:

- architecture and domain boundaries;
- application and infrastructure security;
- performance, capacity and resilience;
- data modeling, lifecycle, privacy and migration;
- operations, observability, support, rollback and incident response;
- UX, accessibility, content and learnability;
- agentic-AI authority, prompt injection, context, tool use, evaluation and human control.

Record which perspectives are not applicable and why.

## Rapid Software Testing review

- Create a risk inventory and rank product/implementation risks.
- Identify oracles and where each is weak.
- Apply consistency, boundary, interruption, concurrency, history, authority, data and platform heuristics.
- Write focused exploratory charters with setup, mission, evidence and stop conditions.
- Zoom out to lifecycle/system effects and look in corners: empty, huge, stale, malformed, degraded, cancelled and unauthorized states.
- Debrief observations, surprises, coverage gaps and next tests.

## Required specification output

- rationale and alternatives;
- functional and non-functional requirements;
- boundaries, contracts and data/state models;
- success, failure, degraded and recovery behavior;
- security, performance, data, operations, UX and agentic-AI concerns where relevant;
- acceptance criteria and test strategy;
- evidence plan and traceability;
- assumptions, risks, concerns, unknowns, deferrals and recommendations.

Do not claim design correctness from review consensus. Identify what is proven, supported, unverified, assumed or unknown.
