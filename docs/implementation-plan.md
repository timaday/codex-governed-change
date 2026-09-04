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
- Run a new live ChatGPT-authenticated Codex `gpt-5.6-sol` reviewer only after
  fake-adapter tests are green.
- Aggregate exact evidence and update status no further than `READY_FOR_HUMAN`.

Exit: one immutable candidate has reconstructable evidence, qualified
fresh-context review and a human-readable debrief. Human merge remains separate.

## T11 — RST-inspired rapid-review contracts and policy

Requirements: GOV-031 through GOV-037, GOV-039, GOV-040

- Add candidate-bound risk assessment, charter, session, debrief, and risk-disposition schemas and examples.
- Implement risk escalation, charter selection, session/debrief completeness, oracle/evidence linkage, finding severity, residual-risk authority, and candidate freshness as pure policy.
- Support both specification/design and code/change investigations.
- Preserve the distinction between checking, conformance review, investigation, and human decision.

Exit: rapid-review decision tables and malformed/stale/adversarial artifact tests pass.

## T12 — Rapid-review reviewer, CLI, CI, and qualification integration

Requirements: GOV-031 through GOV-040

- Extend task profiles, evidence manifests, reviewer allowlist/prompt, CLI, Stop hook, and reference CI with the new lifecycle.
- Run chartered sessions only in a fresh sanitized read-only reviewer process.
- Add three-story debrief and actionable finding/remediation loops; repeat candidate-bound evidence after repairs.
- Update adoption, evaluation, skill, threat model, traceability, examples, and status evidence.

Exit: deterministic tests, a final exact-candidate fresh rapid review, debrief, reconciliation, evidence regeneration, and human-owned disposition are reconstructable.

## Architecture-hardening sequence

T13–T24 supersede the remaining execution order for T05–T12. Earlier work is
preserved but cannot qualify until the applicable hardening task is green.

## T13 — Architecture, TCB and hardened contracts

Requirements: GOV-041 through GOV-062, GOV-TOKEN-001 through GOV-TOKEN-004

- Record the TCB, trust boundaries, owners, untrusted inputs, lineage and bypasses.
- Update normative requirements, decisions, schemas, examples, traceability and
  acceptance oracles before production changes.
- Reconcile mutation, reviewer terminology, evidence-store and status conflicts.

Exit: blueprint validation passes and all newly executable behavior oracles are
present and red for the intended missing behavior.

## T14 — Admission, authenticated authority and assurance domain

Requirements: GOV-041, GOV-048 through GOV-053

- Implement the sole deterministic admission kernel as a pure domain policy.
- Implement authenticated decision applicability, protected risk/gate floors,
  LKG promotion and rollback rules.
- Implement fixed assurance arguments, defeaters and monotonic disposition.
- Replace unbounded correctness labels with bounded observation vocabulary.

Exit: exhaustive decision, forgery, downgrade, LKG and monotonicity tests pass.

## T15 — Schema lifecycle and typed evidence

Requirements: GOV-052, GOV-057, GOV-059 through GOV-061, GOV-TOKEN-003

- Implement typed, digest-bound artifact and excerpt locators.
- Add the authority, assurance, attestation, RST, mutation and context contracts.
- Validate complete RFC 3339 values, lifecycle ordering and supported migrations.

Exit: every example round-trips, incompatibility fails closed and hallucinated
locations cannot satisfy a claim.

## T16 — Repository identity, provenance and write-once storage

Requirements: GOV-045 through GOV-047, GOV-061, GOV-062

- Bind candidates and all evidence to protected `repository_id`.
- Package trusted in-toto-shaped provenance only after untrusted execution ends.
- Make content-addressed evidence idempotent for identical bytes and blocking for
  conflicting replacement; reconstruct all self-identifiers deterministically.

Exit: replay, overwrite, cross-repository, source/environment and portability
tests pass.

## T17 — Disposable gate sandbox and trusted supervisor

Requirements: GOV-004, GOV-026 through GOV-028, GOV-044, GOV-046, GOV-061

- Replace direct host candidate execution with a disposable sandbox provider.
- Default to no network and no secrets; bound time, process tree, resources and
  output; expose a deterministic capability report.
- Start one absolute per-gate deadline before candidate reconstruction, pass the
  unchanged applicable absolute deadline to every Git/container/execution helper and retain an
  `UNKNOWN` gate record when preparation is incomplete.
- Keep protected governance, supervisor, reviewer harness and authoritative
  evidence unwritable and package observations in a later trusted phase.

Exit: capability-unavailable, escape/write, network, secret, process-tree,
timeout, cancellation and truncation tests fail closed.

## T18 — Operational RST feedback loop

Requirements: GOV-031 through GOV-040, GOV-057

- Implement risk register, fallible oracle, coverage and follow-up contracts.
- Bind all artifacts to task and candidate and update risks/charters from
  observations, mutation survivors and reviewer findings.
- Preserve investigation, checking, conformance and human authority distinctions.

Exit: complete lifecycle, stale artifact, weak oracle and bidirectional feedback
tests pass without treating completed paperwork as correctness.

## T19 — Governed mutation

Requirements: GOV-024, GOV-040, GOV-058, GOV-059

- Run the mandatory curated semantic corpus in a disposable candidate only after
  the baseline suite is green and before final review.
- Implement bounded optional generated-tool adapters and complete mutant records.
- Classify causal kills separately from invalid, timeout, survivor, unknown and
  human-triaged equivalent outcomes.

Exit: every mandatory valid non-equivalent mutant is causally killed and no
unresolved corpus outcome exists.

## T20 — Qualified fresh-context review

Requirements: GOV-005 through GOV-007, GOV-016, GOV-020, GOV-021, GOV-025,
GOV-038, GOV-052, GOV-054 through GOV-056

- Retain the fresh ephemeral read-only lane and remove independence overclaims.
- Enforce tool/config/credential/context isolation and verified evidence locators.
- Share complete host-path and named-endpoint recognition with gate streams;
  deny asynchronous descriptor signalling through both `fcntl` and `ioctl`.
- Qualify each mode-specific prompt, schema, model, Codex CLI version and launcher identity against
  the labelled defect/injection corpus; expose disagreement and high-risk escalation.
- Emit a reconstructable reviewer-execution statement and reject a stored result
  that is not linked to its fresh process, prepared/final context and termination.

Exit: fake-adapter, canary, affected-closure, tool-boundary, qualification and
version-invalidation tests pass without a fallback reviewer.

## T21 — Deterministic context compiler

Requirements: GOV-TOKEN-001 through GOV-TOKEN-004, GOV-052, GOV-054, GOV-055

- Implement COMPACT, STANDARD and DEEP projections with a non-droppable assurance
  kernel and deterministic automatic DEEP escalation.
- Derive the exact changed-file inventory from the verified candidate and reject
  caller aggregation or mismatch.
- Persist separate prepared and post-run context receipts, including Codex JSONL
  usage and all retrieval expansions, and reconcile them during admission.
- Project `manifest -> typed summary -> relevant excerpt -> full artifact`, keep
  full repository/artifact retrieval available, and record every expansion.
- Deduplicate by content address, preserve stable/dynamic prompt sections and emit
  context receipts with separate quality and efficiency metrics.
- Block or escalate when mandatory context cannot fit; never silently truncate.

Exit: determinism, retrievability, closure, compression-preservation, budget,
isolation and quality-non-regression tests pass.

## T22 — Orchestration, CLI and bounded Stop hook

Requirements: GOV-002, GOV-008 through GOV-010, GOV-017, GOV-019, GOV-023,
GOV-025, GOV-029, GOV-030, GOV-041, GOV-051

- Wire trusted phase ordering: identify, sandbox gates, package, mutate, compile
  context, review, assure, admit and report.
- Complete the public CLI and stable fail-closed exit contract.
- Make the Stop hook recompute identity and consult only the admission result.

Exit: clean fixture pipelines and first/continued/error hook tests pass.

## T23 — Always-running protected CI admission

Requirements: GOV-011, GOV-013, GOV-041 through GOV-043, GOV-050, GOV-062,
GOV-063

- Make the final job use `if: always()` and inspect each direct dependency result
  plus every required artifact before running the admission kernel.
- Keep actions SHA-pinned, credentials out of untrusted jobs and the expected
  required-check source/no-bypass/current-candidate deployment explicit.
- Support the GitHub Free topology with a protected public authority ref and a
  separate private manual/scheduled broker pinned to that exact authority SHA.
- Derive called-job authority from GitHub's resolved workflow SHA, reject every
  caller-selected authority/source identity, and verify the completed broker
  run's exact referenced workflow before post-completion success.
- Keep mirrored authority workflows outside the private broker's active
  workflow directory.
- Keep the authenticated reviewer JIT runner private-broker scoped and prevent
  every public or candidate event from scheduling it.
- Add static and executable simulations for skipped, cancelled, absent, neutral,
  failed and malformed prerequisites.

Exit: no upstream outcome or candidate-owned authority mutation can yield a
successful required disposition check.

## T24 — Exact-candidate qualification and debrief

Requirements: all

- Run all deterministic, integration, sandbox, security, curated mutation, RST,
  schema-lifecycle, assurance and context-optimization gates without skips.
- Reconstruct the live public-authority ruleset, private-broker caller pins,
  trigger allowlist and target App check source without claiming paid private
  protection.
- Reconstruct the called-job workflow SHA and completed-run referenced-workflow
  binding, and prove no reusable mirror remains active in the broker.
- Qualify token variants and the final reviewer identity on the labelled corpus.
- Only then run one fresh live ChatGPT-authenticated Codex `gpt-5.6-sol`
  exact-candidate review and reconstruct the
  content-addressed evidence chain.
- Update status no further than the deterministic result; human disposition is
  separate.
- Re-observe authoritative JSON and untracked candidate inputs through retained
  no-follow descriptors and keep one exact byte observation per command.

Exit: the immutable candidate has reconstructable evidence or remains honestly
`UNKNOWN/BLOCK` with exact missing proof.

## Task controls

- A task may refine implementation detail but may not weaken its mapped requirement.
- New production dependencies require a recorded decision and security review.
- Governance schema changes require backward-compatibility or explicit version migration tests.
- A failed external reviewer never authorizes an in-session substitute.
- Each task report must state facts, assumptions, risks, unknowns and evidence.
