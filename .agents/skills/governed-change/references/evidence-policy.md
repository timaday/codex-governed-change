# Evidence and disposition policy

Use this policy before claiming readiness or running independent review.

## Evidence classifications

- `PROVEN`: reproduced by deterministic evidence bound to the exact candidate and effective policy.
- `SUPPORTED`: backed by inspected repository artifacts but not fully executed.
- `UNVERIFIED`: plausible or specified, but not independently demonstrated.
- `UNKNOWN`: missing, stale, conflicting, timed-out, truncated, malformed, unavailable, or otherwise incomplete.

Only `PROVEN` satisfies a mandatory executable gate. `UNKNOWN` blocks.

## Integrity checks

For every artifact, verify:

- schema and producer version;
- exact candidate and effective policy identity;
- creation order and pre/post candidate stability;
- command identity, exit or termination cause;
- raw output size, digest and truncation state;
- required causal observations;
- reference path containment and artifact digest;
- authorization for any governance change or waiver.

Never infer an absent field, reuse evidence by timestamp/branch name, or treat a summary as a raw artifact.

## Disposition

Emit `READY_FOR_HUMAN` only when every mandatory deterministic gate is `PASS`, the fresh reviewer is valid and `PASS`, every artifact matches one candidate, governance integrity holds, and no mandatory unknown remains.

Emit `BLOCK` for confirmed failure, reviewer block, unauthorized governance change, or unsatisfied mandatory condition.

Emit `UNKNOWN` when a required fact cannot be established. `UNKNOWN` is a blocking disposition even though it is not a confirmed product failure.

The reviewer can veto but cannot certify. The aggregator can establish readiness for human review but cannot merge, waive, deploy, or approve risk.

## Fresh review contract

- Start a new `codex exec --ephemeral` process; never resume.
- Start from a sanitized harness Git root with the immutable candidate nested as read-only evidence, preventing candidate-owned Codex configuration from becoming active.
- Use ignored user config/rules, disabled hooks/subagents, a read-only sandbox, fixed reviewer prompt and schema output.
- Do not expose author chat, plan, self-review, conclusions, hidden reasoning, unrelated connectors or write credentials.
- Allow full repository read access and require independent affected-closure search.
- Treat any process/schema/identity/evidence error as `UNKNOWN/BLOCK`.
- After a repair, invalidate prior results and start another new reviewer.

## Human waiver

Do not create or infer a waiver. Accept only a schema-valid, protected, human-attributed, scoped, candidate-bound, non-expired waiver. Report the waived requirement and compensating control prominently. A waiver never changes historical evidence from failed/unknown to passed.
