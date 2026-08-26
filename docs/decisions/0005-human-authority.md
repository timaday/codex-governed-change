# ADR-0005: Reserve approval and waiver authority for humans

Status: accepted

## Context

Models can generate valuable findings but cannot own organizational risk or be held accountable for merge and deployment decisions.

## Decision

The strongest automated disposition is `READY_FOR_HUMAN`. Reviewer `PASS`, aggregator success and CI success are prerequisites, not approval. Only a human may approve merge, deployment, governance change or waiver.

## Alternatives

- **Automatic merge after reviewer PASS**: rejected because the reviewer is probabilistic and lacks risk authority.
- **Automatic merge after all tests**: rejected because tests are incomplete models of requirements and may be candidate-controlled.
- **Model-generated waiver**: rejected because it collapses the control boundary.

## Consequences

The system improves evidence and review discipline without pretending to remove human accountability.
