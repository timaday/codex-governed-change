# ADR-0006: Review affected closure with full repository access

Status: accepted

## Context

Reviewing only changed lines misses callers, contracts, configuration and operational effects. Loading an entire large repository into one prompt can reduce relevance and exceed context budgets.

## Decision

Give the reviewer read-only access to the full repository. Seed it with the exact task and diff, then require traversal of affected callers, dependencies, schemas, tests, configuration, trust boundaries and documentation. Run whole-repository audits separately.

## Alternatives

- **Changed lines only**: too narrow for multi-file semantic effects.
- **Author-selected file list**: allows accidental or strategic omission.
- **Whole repository pasted into the prompt**: high cost and poor salience.

## Consequences

Review remains repository-aware and bounded. The reviewer may still miss an affected edge; deterministic dependency checks and periodic audits remain valuable.
