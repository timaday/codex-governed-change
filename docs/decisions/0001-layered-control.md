# ADR-0001: Use layered guidance, evidence and authority

Status: accepted

## Context

Neither prompt instructions nor model self-review provides deterministic enforcement. Repository teams still need convenient author guidance.

## Decision

Separate the system into:

1. global/repository `AGENTS.md` invariants;
2. a reusable governed-change skill;
3. deterministic gate evidence;
4. fresh read-only review;
5. deterministic aggregation;
6. protected CI and human authority.

## Alternatives

- **One large global prompt**: rejected because it is costly, conflicts with repository context, and remains probabilistic.
- **Skill only**: rejected because a skill is workflow guidance, not an authority boundary.
- **Reviewer only**: rejected because another LLM cannot replace executable proof.
- **CI only**: insufficient for semantic/specification review and a disciplined local correction loop.

## Consequences

The architecture has more components than a prompt-only approach but each boundary has a single responsibility and can be tested independently.
