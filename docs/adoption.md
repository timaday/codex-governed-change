# Adoption guide

This guide describes adoption of the implementation candidate. Local commands
are covered by the repository suite; enforcement still requires protected
policy inputs, a real sandbox, reviewer qualification, hosted CI and human
approval in the adopting repository.

## 1. Prerequisites

- Git.
- Python 3.11 or newer.
- A current ChatGPT-authenticated Codex CLI with `gpt-5.6-sol` access.
- A repository with deterministic build/test commands.
- CI and branch/ruleset administration for hard enforcement.

The deterministic suite must work without a live model. Live fresh-context review
uses normal ChatGPT/Codex authentication outside the sanitized harness. The MVP
reviewer identity does not use an OpenAI API key, and no authentication value or
machine-specific credential-store location belongs in repository content or
evidence.

## 2. Install global guidance

Copy `examples/global-AGENTS.md` to `~/.codex/AGENTS.md`, or merge its invariant kernel into an existing global file. Keep repository commands out of the global file.

Verify from a new Codex run:

```bash
codex --ask-for-approval never "Summarize the current instructions."
```

## 3. Adopt repository files

Copy or adapt:

```text
AGENTS.md
.agents/skills/governed-change/
.codex/agents/independent-reviewer.toml
.codex/review/reviewer.prompt.md
.codex/hooks.json.example -> .codex/hooks.json
schemas/
```

Repository `AGENTS.md` must define exact deterministic commands and authority order. Avoid copying technology-specific commands that do not apply.

## 4. Configure profiles and gates

Create a protected governance policy declaring:

- evidence root;
- governance asset paths;
- reviewer model and reasoning effort;
- code/spec/mixed profiles;
- required gates per risk class;
- time and output bounds;
- allowed executables and whether shell mode is prohibited;
- redaction patterns;
- human waiver authority.

Do not permit candidate-owned environment variables to silently override this policy.

## 5. Trust the local hook

Codex project hooks require repository trust. Inspect `.codex/hooks.json` and its script before trusting it. The Stop hook improves the local author loop but is not the merge boundary because a developer can disable a non-managed project hook.

An organization with managed Codex configuration may deploy a managed hook separately. Local adoption must still use protected CI.

## 6. Configure GitHub protection

Recommended controls:

- require pull requests;
- require the governed disposition status check;
- require code-owner review for governance assets;
- prevent bypass where organizational policy permits;
- use a protected, SHA-pinned reusable governance workflow;
- give deterministic/reviewer jobs only `contents: read`;
- do not persist checkout credentials in the reviewer job;
- keep any PR-comment/write step separate from the credentialed model job;
- pin third-party actions to audited full commit SHAs in hardened deployments.

The example workflow is illustrative. A repository administrator must map it to the organization's runner, secret, workflow and ruleset policy.

The reference deliberately calls a target-branch-owned `.governance/ci/`
deployment adapter. That adapter is repository-specific and must materialize
the authenticated task, policy, RST/context inputs, reviewer allowlist and
manifest input after the candidate identity is known. It must never be loaded
from PR code. The reference uses the portable repository-relative evidence root
`artifacts/governance`; an adopter may select another protected relative root,
but the policy, adapter and workflow must agree exactly. Missing adapter scripts,
qualification records or generated inputs block the workflow.
Decision JSON is never self-authenticating: the protected adapter must return
the exact decision IDs it verified through the configured authenticated source.
The evaluator accepts only those explicitly verified IDs; an omitted adapter
observation, content-address alone, issuer string or model assertion has no
authority.

## 7. Per-change operation

1. Create a schema-valid task contract.
2. Create an exact-candidate risk assessment and select proportionate RST-inspired rapid-review charters.
3. Run cheap local deterministic gates.
4. Run the fresh conformance reviewer and required chartered rapid-review sessions.
5. Debrief the product, testing, and quality-of-testing stories; disposition every finding and residual risk without model-owned acceptance.
6. Evaluate the evidence.
7. If any file changes, discard prior evidence and repeat the affected checks and focused charters.
8. Push the candidate and let CI reconstruct proof.
9. Human reviews `READY_FOR_HUMAN` and owns material risk acceptance; neither is automatic approval.

The installed CLI exposes `scope`, `identify`, `run-gates`, `mutate`,
`prepare-review`, `assemble-manifest`, `review`, `import-reviewer-result`,
`evaluate`, `status`, `verify` and `hook`. Every command returns `0` only for a
valid/ready bounded outcome, `1` for a confirmed block and `2` for unknown or
incomplete evidence. Use `codex-governance COMMAND --help` for the portable
argument contract. Evidence paths are repository-relative; do not place user,
home-directory, host or local endpoint values in policy or committed artifacts.
`prepare-review` requires `--repository`, `--policy` and `--candidate`; it
re-identifies the exact candidate and derives a conservative Git-visible
dependency/caller/contract/test closure. Callers cannot supply an aggregate or
restricted replacement for the changed-file inventory or closure. Each `review` call also requires a
portable workflow run ID and writes three linked outputs: the schema-bound model
result, reviewer-execution statement, and post-run context-execution receipt.
The reference CI runs conformance and every protected rapid-review input, then
passes all three artifact families to the final reconstruction job.

## 8. Reviewer isolation verification

Before relying on the reviewer lane:

- inspect the actual argv and stdin created by a fake Codex executable;
- verify no `resume`, author transcript, self-review, unrelated connector or writable token appears;
- verify Codex starts in a sanitized harness Git root and candidate-owned `.codex`, hooks, rules and skills are not active configuration;
- verify every copied review artifact is beneath the policy-selected evidence root, rather than a hard-coded host or user path;
- place a random canary only in author context and prove its bytes are absent from reviewer-accessible inputs;
- verify candidate filesystem and repository token are read-only;
- force timeout, non-zero and malformed output and confirm `UNKNOWN/BLOCK`;
- mutate the candidate during local review and confirm invalidation.

## 9. Rollout stages

### Observe

Run locally and in non-required CI. Measure misses, false blocks, cost and latency. Do not claim enforcement.

### Warn

Publish a non-required status with explicit `BLOCK/UNKNOWN` findings. Tune repository gates and reviewer prompt under human review.

### Enforce

Make the deterministic disposition a required check. Protect governance assets and effective policy source.

### Harden

The curated governance mutation corpus is mandatory for MVP admission. Add
generated language mutation, specialist lanes, organization-managed controls,
signed attestations or model diversity according to protected risk policy.

## 10. Removal and rollback

Removing enforcement is a governance change. Preserve the previous required check until an equal or stronger replacement is protected and evidenced. If the reviewer service is unavailable, the valid fallback is `UNKNOWN/BLOCK`, not local `/review` or a same-session subagent.
