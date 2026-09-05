# ADR-0014: Reconstruct empirical context qualification

Status: accepted

## Context

Context qualification version `2.0.0` distinguishes empirical evidence from a
synthetic bootstrap, but its empirical shape contains only aggregate metrics.
A content address proves those aggregate bytes did not change; it does not prove
that a protected labelled corpus, reviewer executions, or raw measurements
produced them.

## Decision

Version `context-qualification` as `3.0.0`. An empirical record binds:

- the exact retained corpus bytes and authenticated label-decision ID;
- one DEEP baseline and one candidate-profile measurement set;
- conformance and rapid-review qualification records plus their per-case
  evidence for each set; and
- the normalized raw output and execution artifacts transitively referenced by
  those case-evidence documents.

Preparation, review and admission descriptor-resolve every typed reference,
reconstruct every labelled case using the protected reviewer-qualification
oracle, recompute critical recall, false passes, false blocks, unknowns,
traceability and tokens, then compare those results with the record's aggregate
fields. Missing usage, raw artifacts, labels, cases or mode evidence is
`UNKNOWN`. A second self-reported aggregate never substitutes for raw proof.

`synthetic_bootstrap` remains permitted only while constructing deterministic
qualification cases. Its version `3.0.0` record has no empirical measurement
references, remains `qualified=false`, and carries a limitation.

Migration from `2.0.0` requires separately protected corpus, label and
measurement references for an empirical record. Those facts cannot be inferred
from the legacy aggregates. Synthetic migration preserves the explicit
unqualified boundary. Every migrated content address is rebuilt.

## Consequences

Qualification artifacts are larger and must be retained as one exact package.
The protected producer and admission kernel share the same case reconstruction
implementation, so context efficiency can be promoted only from independently
replayable evidence. Existing `2.0.0` records are migration inputs only and do
not satisfy current production admission.
