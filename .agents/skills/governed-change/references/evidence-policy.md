# Evidence and disposition policy

Use this policy before claiming readiness or running fresh-context review.

## Evidence classifications

- `DIRECTLY_OBSERVED`: directly reproduced by evidence bound to the exact repository, candidate, policy, producer and execution identity.
- `VERIFIED_WITHIN_SCOPE`: a fixed deterministic rule validated the bounded claim from resolved evidence.
- `UNVERIFIED`: plausible or specified, but not independently demonstrated.
- `UNKNOWN`: missing, stale, conflicting, timed-out, truncated, malformed, unavailable, or otherwise incomplete.

Only an applicable `DIRECTLY_OBSERVED` or `VERIFIED_WITHIN_SCOPE` result can
satisfy a mandatory claim. Neither implies overall product correctness.
`UNKNOWN` blocks.

## Integrity checks

For every artifact, verify:

- schema and producer version;
- exact candidate and effective policy identity;
- creation order and pre/post candidate stability;
- command identity, exit or termination cause;
- raw output size, digest and truncation state;
- required causal observations;
- reference path containment and artifact digest;
- protected `repository_id`, source identity and execution identity;
- authenticated decision references for task, governance, risk or waiver authority;
- context receipt inclusion/exclusion and retrieval-expansion lineage;
- authorization for any governance change or waiver.

Never infer an absent field, reuse evidence by timestamp/branch name, or treat a summary as a raw artifact.

## Disposition

Emit `READY_FOR_HUMAN` only when the single admission kernel validates every
fixed assurance claim, every mandatory deterministic/mutation gate is `PASS`,
the qualified reviewer has `NO_BLOCKING_FINDING_OBSERVED`, every artifact matches
one repository/candidate/source/execution lineage, context is complete,
governance integrity holds, and no mandatory unknown or defeater remains.

Where rapid review is required, also require the exact candidate-bound risk assessment, minimum charters, completed fresh-context session reports, direct oracle/evidence links, explicit coverage and omissions, three-story debrief, and disposition of every finding and residual risk. Block unresolved critical/high findings or material residual risks unless an authorized human accepts them for the exact candidate. Low-risk skips require a protected non-empty rationale and are forbidden for hazardous surfaces.

Emit `BLOCK` for confirmed failure, reviewer block, unauthorized governance change, or unsatisfied mandatory condition.

Emit `UNKNOWN` when a required fact cannot be established. `UNKNOWN` is a blocking disposition even though it is not a confirmed product failure.

The reviewer can veto but cannot certify. The aggregator can establish readiness for human review but cannot merge, waive, deploy, or approve risk.

Heuristic/checklist completion, elapsed time, session count, or absence of findings cannot establish rapid-review success. Blocked/inconclusive sessions, unclear coverage, unavailable material oracles/environments, or unsupported success claims are `UNKNOWN`.

## Fresh review contract

- Start a new `codex exec --ephemeral` process; never resume.
- Start from a sanitized harness Git root with the immutable candidate nested as read-only evidence, preventing candidate-owned Codex configuration from becoming active.
- Use ignored user config/rules, disabled hooks/subagents, the root-denying
  custom read-only permission profile with tool network off and a synthetic
  tool home, fixed reviewer prompt and schema output.
- Do not expose author chat, plan, self-review, conclusions, hidden reasoning, unrelated connectors or write credentials.
- Allow full repository read access and require independent affected-closure search.
- Treat any process/schema/identity/evidence error as `UNKNOWN/BLOCK`.
- After a repair, invalidate prior results and start another new reviewer.

## Human waiver

Do not create or infer a waiver. Accept only schema-valid protected issuance and
consumption decisions bound to repository, task, candidate, policy, scope,
authenticated issuer and validity period. Report the waived requirement and
compensating control prominently. A waiver never changes historical evidence
from failed/unknown to passed.
