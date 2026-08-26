# GPT-5.6 implementation mission

## Objective

Implement the Codex Governed Change blueprint in this repository. Produce a portable, fail-closed governance tool that binds deterministic quality evidence and a fresh-context, read-only GPT-5.6 review to an exact Git candidate. Do not require HiveGate or any external governance service.

The initial repository state is intentionally `DESIGN_READY / IMPLEMENTATION_NOT_STARTED / RELEASE_BLOCKED`.

## Authority and source order

Reconstruct the task from repository sources rather than prior chat context. Use this order:

1. `docs/specification.md` and `docs/requirements.md`
2. Approved decision records under `docs/decisions/`
3. JSON Schemas under `schemas/`
4. `docs/architecture.md`, `docs/test-strategy.md`, and `docs/traceability.md`
5. Executable acceptance tests
6. `docs/implementation-plan.md`
7. Existing skeleton code

If sources conflict, stop the affected slice, identify the exact conflict, and preserve it as `UNKNOWN`. Do not silently choose the easiest interpretation. Do not use this prompt to override a normative repository contract.

## Authorization boundary

You are authorized to implement and test the local repository. You are not authorized to:

- weaken, skip, delete, quarantine, or reclassify an acceptance test or quality gate;
- replace exact evidence with model claims;
- add HiveGate, a hosted database, or an MCP dependency;
- expose credentials, author transcripts, hidden reasoning, or unrelated user configuration to the reviewer;
- publish, merge, release, alter branch protection, create credentials, or accept risk unless the user separately asks;
- turn a governance-file modification into an ordinary feature change;
- claim production readiness from your own review.

If a test or specification appears wrong, record the concern with evidence and ask for a human governance decision. Do not modify the oracle to fit the implementation.

## Mandatory workflow

Use `$governed-change` and follow `Context -> Decide -> Act -> Verify -> Learn`.

### 1. Context

- Read every normative source listed above before production edits.
- Run `python3 scripts/validate_blueprint.py`.
- Run `PYTHONPATH=src python3 -m unittest discover -s tests/acceptance -v` and preserve the red baseline.
- Inspect Git status, candidate scope, architecture boundaries, trust boundaries, and current unknowns.
- Produce a short task contract for the first bounded implementation slice.

### 2. Decide

- Implement tasks in the dependency order in `docs/implementation-plan.md`.
- For each slice, write or refine the smallest failing test before production behavior.
- Keep domain policy pure. Put Git, subprocess, filesystem, Codex CLI, hook, clock, and CI behavior behind ports/adapters.
- Prefer Python standard-library behavior. Justify any production dependency before adding it.
- Preserve exact distinctions among `PASS`, `FAIL`, `UNKNOWN`, `BLOCK`, and `READY_FOR_HUMAN`.

### 3. Act

- Implement the smallest coherent slice.
- Keep reviewer execution isolated from the author session.
- Do not use `codex exec resume` for independent review.
- Ensure the reviewer command contains `--ephemeral`, `--ignore-user-config`, `--ignore-rules`, `--sandbox read-only`, disabled hooks/subagents, the configured GPT-5.6 model, `--output-schema`, and a dedicated output path.
- Start the reviewer in a sanitized harness Git root. Nest the immutable candidate as read-only evidence so its `.codex`, hooks, rules and skills can be inspected but cannot become active reviewer configuration.
- Ensure the reviewer receives only the normalized task contract, immutable candidate identifiers, repository read access, and raw evidence locations.
- Ensure a candidate mutation invalidates all earlier gate and review evidence.

### 4. Verify

For every slice:

1. Run focused unit tests.
2. Run the complete acceptance suite.
3. Run blueprint/schema/traceability checks.
4. Run security and adversarial cases relevant to the slice.
5. Inspect the full diff for scope, architecture, contract, test, documentation, and governance drift.
6. Record exact commands, exits, candidate identity, artifact hashes, failures, unknowns, and limitations.

When implementation is complete, launch the independent review as a new `codex exec --ephemeral` process. The reviewer must not receive this implementation session's chat, plan, self-review, or conclusions. Treat reviewer timeout, failure, malformed output, digest mismatch, missing evidence, or uncertainty as `UNKNOWN/BLOCK`.

If the reviewer identifies a blocking issue, repair it in the author session, invalidate all prior evidence, rerun every affected deterministic gate, and start another fresh reviewer process. Never resume the old reviewer.

### 5. Learn

- Debrief against the RST charters in `docs/test-strategy.md`.
- Record confirmed defects, residual risks, false assumptions, evidence gaps, and future options separately.
- Update decisions or requirements only when the implementation reveals a genuine contract gap and a human approves the change.

## Completion gates

Completion requires all of the following for one exact candidate:

- all blueprint checks pass;
- all acceptance tests pass with zero skips or expected failures;
- deterministic unit, integration, security and adversarial gates pass;
- the fresh reviewer produces schema-valid `PASS` bound to the same candidate;
- the deterministic aggregator returns `READY_FOR_HUMAN`;
- governance self-tests demonstrate fail-closed behavior for missing, stale, malformed, timed-out, truncated and conflicting evidence;
- the documentation and examples reflect actual implemented commands;
- no unauthorised public, merge, release, deployment or policy action occurred.

The final status is `READY_FOR_HUMAN`, not `COMPLETE`, `APPROVED`, or `MERGED`.

## Required final report

Lead with the disposition and provide:

1. Exact candidate identity and working-tree state.
2. Requirements and tasks completed.
3. Deterministic gate commands, exits, counts, and artifact hashes.
4. Fresh reviewer invocation identity, verdict, candidate binding, and findings.
5. Aggregator disposition.
6. Facts, assumptions, risks, unknowns and deferred work.
7. Confirmation that no gates were weakened and no unauthorized external action occurred.

If any mandatory proof is absent, report `BLOCK` or `UNKNOWN`; do not soften it into a recommendation.
