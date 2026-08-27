# Code quality profile

Use this profile for any change that can affect executable behavior, build output, persistence, deployment, authority, security, tests, or runtime operations.

## Design review

- State the domain behavior and acceptance oracle before implementation.
- Identify public contracts, invariants, state transitions, error semantics and trust boundaries.
- Preserve SOLID and domain-first/hexagonal boundaries where proportionate.
- Keep framework, filesystem, network, Git, subprocess, clock and model concerns outside pure policy.
- Prefer the smallest coherent change; record broader refactors as future options.
- Reject silent fallback, cascading defaults and generic exception mapping that changes authority semantics.

## Risk selection

Select every relevant gate. Do not mark a gate `N/A` without a reason in the task contract.

| Risk | Minimum additional evidence |
|---|---|
| Public/API contract | contract tests, consumer impact search, compatibility decision |
| Persistence/schema | migration forward/backward tests, data integrity and recovery |
| Authentication/authorization | abuse cases, least privilege, bypass search, secret handling |
| Concurrency | deterministic race fixtures, ownership/lifecycle review, interruption tests |
| Subprocess/tool execution | argument-injection, timeout, signal, output-bound and path tests |
| Performance path | representative workload, bounds, resource and regression measurements |
| Deployment/operations | configuration, health, rollback, observability and degraded-mode tests |
| Evidence/governance | stale/replay/self-modification/malformed/unknown mutation tests |

## Mandatory sequence

1. Establish a focused red test or observable failing oracle.
2. Implement the minimum behavior that satisfies the intended contract.
3. Run formatting/generated consistency, compilation/type, unit, integration and contract gates.
4. Run architecture/dependency checks.
5. Run security/static/dependency checks.
6. Run risk-selected property, fuzz, mutation, concurrency, adversarial and runtime gates.
7. Inspect every changed test for assertion weakening or implementation mirroring.
8. Review docs, migration and operational behavior for drift.
9. Preserve raw bounded evidence and exact candidate binding.
10. After cheap deterministic gates pass, execute the risk-selected RST-inspired rapid-review charters in a fresh read-only context and debrief product, testing, and quality-of-testing stories.

## Review heuristics

- Trace success, known failure, unknown observation, cancellation and cleanup paths.
- Search all call sites, not just changed lines.
- Look for default branches that widen authority or hide unsupported states.
- Check idempotency, retry semantics, ownership, lifecycle and partial failure.
- Check boundary values, empty inputs, oversized inputs, invalid encoding, path/symlink cases and concurrent mutation.
- Treat a stronger test suite with a poor architecture as technical debt, not success; verify maintainability and dependency direction explicitly.
- Use HTSM and FEW HICCUPPS only as fallible inquiry prompts. Require direct observations, explicit oracles, evidence linkage, coverage/omission reporting, counter-hypotheses, and residual-risk disposition.
