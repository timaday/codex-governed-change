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
- CI and branch/ruleset administration for hard enforcement. A personal
  GitHub Free account is sufficient when topology B is used.

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

Choose exactly one authority topology:

- Topology A is for organizations or accounts with a separately protected
  authority repository or managed required workflow.
- Topology B is the personal-account GitHub Free profile. Create a dedicated
  public authority ref in the public target, protect it with its own ruleset,
  and use a separate private repository only as a manual/scheduled execution
  broker. The broker caller pins the public reusable workflow by a full commit
  SHA; the called workflow derives authority from that resolved workflow SHA,
  not caller inputs, and accepts calls only from the configured private broker.
  Keep only broker callers in the private repository's active workflow
  directory. Do not register its authenticated reviewer runner to the public
  target. Keep recurring producer execution disabled until the protected
  receipt commit is live and every broker caller is repinned; disable it again
  before every authority transition or recovery operation.

Topology B requires no organization and makes no private-repository protection
claim. Store the target-only GitHub App private key as a private-broker Actions
secret. Keep ChatGPT-managed Codex authentication only on the clean single-job
JIT runner registered to that broker. The broker must have no pull-request,
push, issue, comment, repository-dispatch or public-webhook trigger. The App is
installed only on the public target and publishes only the fixed `disposition`
check. Its finalizer must verify the completed broker run and exact resolved
authority-workflow reference through GitHub before publishing success.
The generic pull-request workflow is private-repository-only for authenticated
review; on a public repository its reviewer job stays unscheduled and topology B
provides the private execution boundary.

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

The example workflow is illustrative. A repository administrator must map it to
the selected topology's runner, secret, workflow and ruleset policy.

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
`evaluate`, `status`, `verify` and `hook`. Evidence-producing commands return
`0` only for a valid/ready bounded outcome, `1` for a confirmed block and `2`
for unknown or incomplete evidence. `status` is deliberately display-only: it
always emits `state: UNKNOWN`, places the untrusted input under
`reported_state`, and exits 2. Use `codex-governance COMMAND --help` for the portable
argument contract. Evidence paths are repository-relative; do not place user,
home-directory, host or local endpoint values in policy or committed artifacts.
`prepare-review` reports the non-authoritative component state `CONTEXT_READY`;
only `evaluate` may report or successfully return `READY_FOR_HUMAN`.
`prepare-review` requires the repository, policy, task, candidate, complete gate
and mutation summaries, protected context qualification repository and prompt,
both separately protected mode-specific reviewer qualification records, the
separately adapter-verified qualification label-decision ID, protected observation
time, profile/model/effort and exact policy-selected budget. It re-identifies the
candidate, derives and hashes the complete conservative Git-visible closure, and
writes separate source-bundle, projection and prepared-receipt artifacts. Any
optional caller source document must equal that protected reconstruction exactly;
it cannot replace the inventory, closure or adverse evidence. Each `review` call
requires all three context references plus the protected context-qualification
reference, the separately adapter-verified qualification label-decision ID, a
portable workflow run ID, and writes the schema-bound model result,
reviewer-execution statement, and post-run context-execution receipt.
In a split checkout, pass `--authority-root` for the protected governance
checkout, make `--schema-root`, `--prompt`, and `--output-schema` relative to
that root, and make policy, candidate, permitted-input and output paths relative
to `--repository`. Derive `--timeout-seconds` and `--max-output-bytes` from the
protected effective policy; CLI defaults are not deployment policy.
Pass that protected `--timeout-seconds` to `prepare-review`, every `review`, and
`evaluate`; each command verifies the value after protected policy
reconstruction while using its single absolute deadline from command entry.
The reference CI runs conformance and every protected rapid-review input, then
passes all three artifact families to the final reconstruction job.
For a candidate touching a path in the previous LKG policy's
`governance_paths`, the manifest input must also carry separate proposed-policy,
authenticated LKG-promotion-decision and rollback-evidence references. The
promotion decision must also appear in the verified authenticated-decision set.
Every manifest also carries the protected-source-authenticated LKG-policy
decision that binds the effective policy to the exact task, candidate and base.
Rollback evidence uses nested gate-result, capability and provenance references;
all must be retained and reconstructable, and any limitation blocks promotion.
For a governance candidate, `run-gates` additionally requires
`--proposed-policy`. It runs the protected policy's `rollback-rehearsal`
separately from the task gate manifest, requires its command target to equal the
candidate base, and publishes the typed rollback-evidence reference in its
summary. The rollback command imports the implementation from a read-only
materialization containing exactly the producer-digested previous-LKG Python
package closure; ignored, untracked and candidate-local files are not executed
as rollback authority. The proposed policy must bind its LKG commit to the
candidate head.

`mutate` additionally requires `--governance-repository` naming the protected
governance checkout and `--mutation-corpus` naming the repository-relative exact
corpus file within it. The file's complete byte digest must equal
`mutation.corpus_sha256` in effective policy. The producer copies those validated
bytes into candidate-bound evidence; the evaluated repository's file at the same
relative path has no authority.

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

The protected, policy-digested curated governance mutation corpus is mandatory
for MVP admission. Add
generated language mutation, specialist lanes, organization-managed controls,
signed attestations or model diversity according to protected risk policy.

## 10. Removal and rollback

Removing enforcement is a governance change. Preserve the previous required check until an equal or stronger replacement is protected and evidenced. If the reviewer service is unavailable, the valid fallback is `UNKNOWN/BLOCK`, not local `/review` or a same-session subagent.
