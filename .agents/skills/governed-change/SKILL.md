---
name: governed-change
description: Govern code, test, configuration, infrastructure, documentation, and specification changes with an explicit task contract, risk-selected quality profile, deterministic evidence, fresh-context read-only review, fail-closed disposition, and human approval. Use whenever Codex designs or implements a material repository change, fixes findings, claims readiness, or changes an acceptance oracle. Do not use for read-only explanation that makes no repository change.
---

# Governed change

Treat guidance as workflow and deterministic evidence as proof. Never let an author or reviewer model own final acceptance.

## Establish context

1. Read `IMPLEMENTATION_STATUS.md`, `docs/specification.md`, `docs/requirements.md`, applicable decisions, and `docs/traceability.md`.
2. Inspect Git state and identify the current base, changed/untracked surfaces, governance assets, and conflicting authority.
3. Classify the change as `code`, `specification`, `mixed`, or `governance`.
4. Create or update a schema-valid task contract using `schemas/task-contract.schema.json`.
5. Separate facts, assumptions, hypotheses, risks, unknowns, deferrals, and non-goals.
6. Stop on an unresolved source conflict; do not select the easiest interpretation.

## Load the applicable profile

- For code, tests, configuration, infrastructure, generated artifacts, migrations, or runtime behavior, read `references/code-profile.md`.
- For requirements, architecture, UX, workflow, policy, acceptance criteria, test strategy, or other design specifications, read `references/spec-profile.md`.
- For a mixed or governance change, read both.
- Before reporting status or launching independent review, always read `references/evidence-policy.md`.

## Follow Context -> Decide -> Act -> Verify -> Learn

### Context

- Reconstruct intent from repository authority and the approved task contract.
- Identify affected contracts, callers, dependencies, schemas, tests, configuration, trust boundaries, documentation and operations.
- Record the initial candidate identity. If the governance CLI is not implemented yet, mark candidate-bound enforcement `UNKNOWN`; do not fabricate it.

### Decide

- Define acceptance oracles and mandatory gate IDs before production edits.
- For executable behavior, establish a focused failing test or other explicit red oracle first.
- If a red oracle is unsafe or infeasible, record the proof gap and obtain a human decision before substituting another oracle.
- Choose the smallest coherent implementation slice and state non-goals.
- Treat any gate, schema, reviewer prompt, hook, workflow, CODEOWNERS, waiver policy, or disposition-policy change as governance work.

### Act

- Implement the bounded slice through explicit domain and adapter boundaries.
- Do not weaken, skip, delete, quarantine, retry-away, relabel, or reduce an oracle that the candidate must satisfy.
- Do not add silent fallbacks. Preserve `FAIL`, `UNKNOWN`, `BLOCK`, and `READY_FOR_HUMAN` distinctions.
- Do not publish, merge, deploy, change repository settings, create credentials, or grant waivers without separate user authority.

### Verify

1. Run focused deterministic checks.
2. Run the complete applicable profile.
3. Recompute the candidate after every relevant command; discard stale evidence.
4. Self-review the exact diff for scope, contracts, architecture, security, data, performance, operations, UX, tests and documentation.
5. Run the strict independent reviewer only as a new ephemeral read-only `codex exec` process. Start it in a sanitized harness Git root with the immutable candidate nested as evidence so candidate-owned Codex configuration is not active. Never use `/review`, a subagent, or `resume` as the isolation boundary.
6. Give the reviewer only permitted repository artifacts, the normalized task contract, exact candidate identifiers, and raw evidence. Do not pass author chat, plan, self-review, conclusions, hidden reasoning, or unrelated connectors.
7. Validate reviewer schema, candidate binding and limitations deterministically.
8. If any repair changes the candidate, invalidate all affected proof and launch another fresh reviewer after rerunning gates.

Treat reviewer unavailability, timeout, non-zero exit, malformed/truncated output, missing evidence, candidate mismatch, or unresolved uncertainty as `UNKNOWN/BLOCK`. Do not silently substitute a weaker reviewer path.

### Learn

- Debrief observed defects, false assumptions, residual risks, unknowns and future options.
- Update repository decisions only when evidence reveals a real contract gap and a human authorizes the governance change.
- Keep current scope, future options and non-goals separate.

## Report status

Lead with `READY_FOR_HUMAN`, `BLOCK`, or `UNKNOWN` and include:

- exact candidate identity and tree state;
- completed requirement/task IDs;
- deterministic commands, exits, counts and artifact hashes;
- fresh reviewer invocation identity, verdict and findings;
- aggregator result;
- facts, assumptions, risks, unknowns, deferrals and limitations;
- confirmation that no gates were weakened and no unauthorized external action occurred.

Never use `complete`, `approved`, `correct`, `safe`, or equivalent language when mandatory proof is absent. `READY_FOR_HUMAN` is not merge approval.
