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
- Before reporting status or launching fresh-context review, always read `references/evidence-policy.md`.

## Follow Context -> Decide -> Act -> Verify -> Learn

### Context

- Reconstruct intent from repository authority and the approved task contract.
- Identify affected contracts, callers, dependencies, schemas, tests, configuration, trust boundaries, documentation and operations.
- Record the initial candidate identity with the governance CLI. If identity observation is unavailable, mark candidate-bound enforcement `UNKNOWN`; do not fabricate it.

### Decide

- Define acceptance oracles and mandatory gate IDs before production edits.
- Resolve protected minimum risk/gates from changed paths and affected surfaces;
  candidate/task input may increase but never reduce them without an applicable
  authenticated decision.
- For executable behavior, establish a focused failing test or other explicit red oracle first.
- If a red oracle is unsafe or infeasible, record the proof gap and obtain a human decision before substituting another oracle.
- Choose the smallest coherent implementation slice and state non-goals.
- Treat any gate, schema, reviewer prompt, hook, workflow, CODEOWNERS, waiver policy, or disposition-policy change as governance work.
- Build a candidate-bound risk assessment and select `low`, `standard`, or `elevated` RST-inspired rapid-review effort. Low-risk skips need a protected recorded rationale; hazardous work cannot be low.
- Write focused charters with missions, risks, stakeholders, value, coverage, techniques, fallible oracles, evidence, timeboxes, constraints, and stopping heuristics.

### Act

- Implement the bounded slice through explicit domain and adapter boundaries.
- Do not weaken, skip, delete, quarantine, retry-away, relabel, or reduce an oracle that the candidate must satisfy.
- Do not add silent fallbacks. Preserve `FAIL`, `UNKNOWN`, `BLOCK`, and `READY_FOR_HUMAN` distinctions.
- Do not publish, merge, deploy, change repository settings, create credentials, or grant waivers without separate user authority.

### Verify

1. Run focused and complete deterministic checks only in the protected disposable
   gate sandbox; never give candidate code a writable governance/evidence path.
2. Run the mandatory curated governance mutation corpus after the green baseline.
3. Recompute the candidate after every relevant command; discard stale evidence.
4. Package output/provenance in a fresh trusted phase after candidate execution ends.
5. Self-review the exact diff for scope, contracts, architecture, security, data, performance, operations, UX, tests and documentation.
6. Conduct required rapid-review charters and feedback updates in a fresh
   sanitized read-only process; capture observations, fallible oracles, coverage,
   omissions, obstacles, follow-ups and residual risks.
7. Compile `COMPACT`, `STANDARD` or `DEEP` context deterministically. Preserve the
   non-droppable assurance kernel, full retrieval access and context receipt.
   Budget insufficiency escalates or blocks; it never truncates mandatory facts.
8. Run the strict fresh-context reviewer only as a new ephemeral read-only
   `codex exec` process. Start in a sanitized harness with the immutable candidate
   nested as evidence. Never use `/review`, a subagent, or `resume` as the boundary.
9. Give the reviewer only authenticated task facts, repository-derived evidence,
   the context receipt and typed retrievable references. Do not pass author chat,
   persisted reasoning, plan, self-review, conclusions or unrelated connectors.
10. Validate reviewer qualification, schema, repository/candidate binding,
    evidence locators, retrieval expansions and limitations deterministically.
11. Build the fixed assurance case and let only the protected admission kernel
    evaluate it. If any repair changes the candidate, invalidate the lineage.
12. Debrief the product, testing and quality-of-testing stories separately and
    require authenticated human decisions for critical/high risk acceptance.

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
- fresh-context reviewer/context-receipt/qualification identities, bounded verdict and findings;
- sandbox capability, provenance and curated mutation outcomes;
- risk profile, charters, rapid-review session status, three-story debrief, findings, and residual-risk dispositions;
- aggregator result;
- facts, assumptions, risks, unknowns, deferrals and limitations;
- confirmation that no gates were weakened and no unauthorized external action occurred.

Never use `complete`, `approved`, `correct`, `safe`, or equivalent language when mandatory proof is absent. `READY_FOR_HUMAN` is not merge approval.
