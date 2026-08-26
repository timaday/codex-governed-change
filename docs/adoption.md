# Adoption guide

This guide describes the intended post-implementation adoption. Commands referring to `codex-governance` remain unverified until the implementation is complete.

## 1. Prerequisites

- Git.
- Python 3.11 or newer.
- A current Codex CLI with GPT-5.6 access.
- A repository with deterministic build/test commands.
- CI and branch/ruleset administration for hard enforcement.

The deterministic suite must work without a live model. Live independent review requires normal Codex authentication locally or a carefully isolated CI credential.

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

## 7. Per-change operation

1. Create a schema-valid task contract.
2. Run local deterministic gates.
3. Run the fresh reviewer.
4. Evaluate the evidence.
5. If any file changes, discard prior evidence and repeat.
6. Push the candidate and let CI reconstruct proof.
7. Human reviews `READY_FOR_HUMAN`; it is not automatic approval.

## 8. Reviewer isolation verification

Before relying on the reviewer lane:

- inspect the actual argv and stdin created by a fake Codex executable;
- verify no `resume`, author transcript, self-review, unrelated connector or writable token appears;
- verify Codex starts in a sanitized harness Git root and candidate-owned `.codex`, hooks, rules and skills are not active configuration;
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

Add mutation evaluation, specialist lanes, organization-managed controls, signed attestations or model diversity according to risk.

## 10. Removal and rollback

Removing enforcement is a governance change. Preserve the previous required check until an equal or stronger replacement is protected and evidenced. If the reviewer service is unavailable, the valid fallback is `UNKNOWN/BLOCK`, not local `/review` or a same-session subagent.
