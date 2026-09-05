# ADR-0011: Compile model context deterministically

Status: accepted

## Context

Inlining a whole repository and complete logs into every model request wastes
tokens and can reduce salience. Ad-hoc summarization can instead omit a failure,
unknown, authority constraint or affected dependency and create false assurance.

## Decision

Every governed model invocation receives a deterministic context projection with
one of `COMPACT`, `STANDARD` or `DEEP`. All retain a non-droppable assurance
kernel: authenticated authority and policy, repository/candidate/policy/evidence
digests, complete changed-file inventory, independently derived affected/test
closure, deterministic results, all unresolved failures/risks/conflicts/survivors/
limitations/unknowns, fixed rubric/disposition contract and retrievable typed
references.

Progressive disclosure is:

```text
manifest -> typed result summary -> relevant excerpt -> complete artifact
```

The candidate repository and unabridged artifacts remain read-only retrievable;
they are not all inlined. Each projection emits a context receipt with versions,
source/projection digests, inclusions, exclusions with deterministic reasons,
token/byte metrics, truncation state, retrieval expansions, model and effort.
Mandatory information is never silently truncated. The compiler escalates to
`DEEP` or returns `CONTEXT_BUDGET_INSUFFICIENT` and `UNKNOWN/BLOCK`.

One protected artifact closure is derived from gate-manifest and mutation-record
references plus recursively typed path/digest materials. Effective profile
selection precedes profile-specific budget and qualification checks.
Preparation, the isolated reviewer and admission independently reconstruct the
same closure, profile, index, projection and disclosed bytes. A lower requested
profile cannot pin a lower qualification after protected signals escalate it.

Context qualification distinguishes protected empirical measurements from an
explicitly unqualified synthetic bootstrap used only while constructing
qualification cases. Production preparation, review and admission accept only
the empirical class.

Context variants are promotable only when a labelled defect/governance corpus
shows no material regression in critical recall, evidence traceability or
disposition correctness. Caching is recorded only when the active interface
reports it and never reduces the logical input claim. No vector database is part
of the MVP.

## Alternatives

- **Always inline everything**: rejected for cost and salience.
- **Model-selected context without a receipt**: rejected because selection is
  non-reconstructable and can inherit author framing.
- **Optimize token count alone**: rejected because assurance quality is the hard
  constraint.

## Consequences

The compiler, affected-closure algorithm and receipt schema join the protected
TCB. Context-selector uncertainty escalates or blocks. Stable rubric prefixes and
content-addressed deltas may improve cacheability without changing assurance work.
