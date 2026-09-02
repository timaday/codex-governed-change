# ADR-0012: Authenticate and reconstruct reviewer qualification

Status: accepted

## Context

A qualification summary and content-addressed case table can repeat claims about
human labels or executions without proving either. Required qualification fields
also cannot be added silently to existing version `1.0.0` public artifacts.

## Decision

Use typed, content-addressed corpus, label-decision and case-evidence documents.
The protected decision source must authenticate the exact label-decision ID.
Each case references stored normalized stdout and stderr captures, reviewer output and a
content-addressed reviewer-execution statement. Admission re-hashes those bytes,
validates the mode-specific output and execution schemas, checks exact case and
reviewer-identity bindings, then recomputes all qualification metrics.
The trusted launcher replaces only supervisor runtime paths and allowlisted
parent-environment values with `<REVIEWER_RUNTIME>` before parsing, hashing or
retention so public evidence remains machine-neutral.

Version `effective-policy`, `evidence-manifest`, and `reviewer-qualification` as
`2.0.0`. Migration from `1.0.0` is explicit and cannot synthesize missing
authority or execution evidence.

## Consequences

Qualification evidence is larger and requires durable normalized capture artifacts, but a
candidate cannot gain reviewer authority from digest-shaped strings,
self-reported flags, or issuer prose. Existing version `1.0.0` artifacts remain
recognizable only as inputs to an explicit migration and never satisfy the new
admission contract directly.
