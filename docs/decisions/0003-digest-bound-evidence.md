# ADR-0003: Bind every result to an exact candidate and policy

Status: accepted

## Context

Passing evidence can become stale after even a small file or policy change. Head SHA alone does not describe uncommitted local changes.

## Decision

Every task, gate, reviewer result, manifest and disposition references an exact candidate identity and effective governance-policy digest. Working-tree observations compare pre/post identities. CI uses immutable commit mode.

## Alternatives

- **Branch name**: mutable and ambiguous.
- **Head commit only**: omits working-tree changes and effective policy.
- **Patch digest only**: can omit base-dependent behavior, submodules or policy.
- **Timestamps**: not content identity.

## Consequences

Evidence becomes reconstructable and stale use is detectable. Canonicalization and Git edge cases become security-critical code requiring extensive tests.
