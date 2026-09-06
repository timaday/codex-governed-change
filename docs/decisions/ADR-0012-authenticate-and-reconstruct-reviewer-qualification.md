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
reviewer-identity bindings, then recomputes all qualification metrics. Every
critical corpus case also carries a human-labelled defect ID and concrete
requirement/path/line target. Critical recall counts only a blocking finding
whose requirement, path and line match that target and its corpus-derived
evidence; rapid-review findings additionally match the protected defect ID
through their typed finding ID. A disposition alone does not detect a defect.
The trusted launcher replaces only supervisor runtime paths and allowlisted
parent-environment values with `<REVIEWER_RUNTIME>` before parsing, hashing or
retention so public evidence remains machine-neutral.

Version `effective-policy`, `evidence-manifest`, and `reviewer-qualification` as
`2.0.0`. Migration from `1.0.0` is explicit and cannot synthesize missing
authority or execution evidence.

Version `reviewer-qualification-corpus` as `3.0.0` when critical expected-
finding labels become mandatory. Migration from `2.0.0` requires those labels
from a separately protected human source and rebuilds the corpus content
address; they cannot be inferred from an old `BLOCK` label.

Version `reviewer-qualification` as `4.0.0` and
`reviewer-qualification-cases` as `6.0.0` when the protected timeout and maximum
output bytes become part of reviewer identity. Migration from their immediate
predecessors requires both positive limits from a separately protected source
and rebuilds the content address. Qualification independently derives every
execution's elapsed milliseconds from its RFC 3339 interval with integer
millisecond flooring, rejects reversed or over-timeout intervals, and requires
the execution, post-run context and aggregate latency values to match that
derivation. Self-consistent readdressing cannot turn unbounded or impossible
timing into qualified evidence.

Version `rapid-review-session` as `2.0.0` when typed finding path and line become
mandatory. Migration from `1.0.0` requires those targets from a separately
protected source; they cannot be inferred from finding prose or a file-only
evidence reference.

Version `context-qualification` as `2.0.0` when `evidence_class` becomes
mandatory. Migration from `1.0.0` requires `empirical` or
`synthetic_bootstrap` from a separately protected source. A synthetic migration
sets `qualified` false and records a limitation; changing its content address
cannot turn it into empirical qualification.

## Consequences

Qualification evidence is larger and requires durable normalized capture artifacts, but a
candidate cannot gain reviewer authority from digest-shaped strings,
self-reported flags, or issuer prose. Existing version `1.0.0` artifacts remain
recognizable only as inputs to an explicit migration and never satisfy the new
admission contract directly.
