# Implementation plan

The tasks are ordered by proof dependency. Each task ends with focused red-to-green evidence and a full regression run. Do not start a dependent task while its prerequisite remains `UNKNOWN`.

## T01 — Domain vocabulary and fail-closed policy

Requirements: GOV-008, GOV-012, GOV-017, GOV-018, GOV-026, GOV-030

- Implement immutable domain value objects and enums.
- Implement aggregation and waiver policies as pure functions.
- Prove that reviewer `PASS` alone cannot create readiness.
- Prove that all absent/unknown mandatory evidence blocks.

Exit: domain tests and relevant acceptance tests pass; no adapter exists yet.

## T02 — Schema and representation adapters

Requirements: GOV-004, GOV-007, GOV-023

- Parse and serialize every JSON Schema representation.
- Reject additional properties, unsupported schema versions, non-finite values, malformed hashes and invalid references.
- Preserve domain/JSON separation.

Exit: all valid examples round-trip; malformed fixture matrix fails closed.

## T03 — Candidate identity

Requirements: GOV-003, GOV-009, GOV-019, GOV-028, GOV-029

- Implement Git and SHA-256 adapters.
- Support commit and working-tree modes.
- Cover tracked, staged, unstaged, renamed, deleted, executable-mode, symlink, untracked and submodule states.
- Recompute identity around observations.

Exit: identity is deterministic and every mutation fixture invalidates evidence.

## T04 — Artifact store

Requirements: GOV-004, GOV-021, GOV-023, GOV-028

- Implement atomic bounded artifact writes and hash verification.
- Reject traversal, unsafe symlinks and overwrite races.
- Add deterministic redaction metadata without hiding incomplete evidence.

Exit: crash/race/path/security tests pass.

## T05 — Deterministic gate runner

Requirements: GOV-004, GOV-008, GOV-014, GOV-019, GOV-026, GOV-027

- Execute argument arrays with timeout and bounded output capture.
- Distinguish failure from observation uncertainty.
- Bind results to pre/post candidate identity.
- Support configured gate profiles and explicit shell-risk mode.

Exit: exit, signal, timeout, truncation, encoding, launch-error and drift decision tables pass.

## T06 — Fresh reviewer launcher

Requirements: GOV-005, GOV-006, GOV-007, GOV-016, GOV-020, GOV-021, GOV-025

- Build the exact `codex exec` argument array.
- Generate reviewer stdin from an allowlist.
- Create a sanitized harness Git root and nest the immutable candidate as read-only evidence so candidate-owned Codex configuration is not active.
- Disable reviewer hooks, subagents and execpolicy loading in addition to ignoring user config.
- Validate output schema and candidate binding.
- Record a sanitized invocation descriptor and prompt digest.
- Never use resume, subagent fallback or author transcript.

Exit: fake-Codex integration tests prove command, input and fail-closed behavior without requiring a live model.

## T07 — Evidence aggregation and CLI

Requirements: GOV-002, GOV-008, GOV-017, GOV-018, GOV-023, GOV-029, GOV-030

- Implement `scope`, `identify`, `run-gates`, `prepare-review`, `review`, `import-reviewer-result`, `evaluate`, `status`, and `verify` commands.
- Make `evaluate` deterministic and side-effect-free apart from writing its result.
- Use stable process exits for automation.

Exit: end-to-end fixture pipelines produce expected dispositions.

## T08 — Stop-hook adapter

Requirements: GOV-010, GOV-025

- Parse Codex Stop-hook stdin.
- Recompute current identity and inspect disposition.
- Continue once with the smallest correction instruction.
- On the second stop, surface `UNKNOWN/BLOCK` without looping.
- Avoid nested reviewer execution.

Exit: first/continued/error path tests pass and stdout is valid hook JSON.

## T09 — Governance integrity and CI reference

Requirements: GOV-011, GOV-013, GOV-021, GOV-024, GOV-030

- Detect governance-asset changes and require governance authorization.
- Validate workflow permissions, immutable policy source and secret separation.
- Implement the reference GitHub Action integration.
- Add governance mutation cases.

Exit: candidate-owned policy cannot approve itself in the reference deployment.

## T10 — Adoption, evaluation and release candidate

Requirements: all

- Make examples match implemented commands.
- Run the complete deterministic suite.
- Run seeded defect and mutation corpus repeatedly.
- Run a new live GPT-5.6 reviewer only after fake-adapter tests are green.
- Aggregate exact evidence and update status no further than `READY_FOR_HUMAN`.

Exit: one immutable candidate has reconstructable evidence, independent review and a human-readable debrief. Human merge remains separate.

## Task controls

- A task may refine implementation detail but may not weaken its mapped requirement.
- New production dependencies require a recorded decision and security review.
- Governance schema changes require backward-compatibility or explicit version migration tests.
- A failed external reviewer never authorizes an in-session substitute.
- Each task report must state facts, assumptions, risks, unknowns and evidence.
