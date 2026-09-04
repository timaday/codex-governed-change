# Codex governed-change authority

This bundle is the protected topology-B authority for
`timaday/codex-governed-change` when its exact commit is installed on the
public target ref `refs/heads/governance-authority` and that ref is protected by
the supplied GitHub Free-compatible ruleset. Its workflows are reusable-only.
A separate private repository invokes them through explicit manual or scheduled
broker callers and publishes one GitHub App check named `disposition`. An
internal broker `workflow_run` finalizer may publish success only after the
source producer is already recorded as completed successfully. There is no
public webhook.

The target candidate cannot change the protected authority ref, its policy, its
adapters, or its reviewer inputs. The private broker holds the GitHub App
credential but is not an authority source. The governance kernel is
copied beneath `kernel/` and becomes authority-owned code; `kernel/SOURCE.json`
binds the exact source commit, a complete source-file digest manifest, and every
authority-owned override. Target code is never used as the reviewer or admission
launcher. Candidate commands and fresh reviewers never receive the App private
key or installation token.

The curated mutation corpus is copied into the protected release directory and
the policy binds its exact raw bytes; the candidate-local corpus is never the
mutation authority. Protected context-qualification records are stored under
`.governance/context-qualifications/` and bind every profile/version identity.
For v0.1.0 they establish quality parity without claiming token savings.

The target registry separately binds the kernel source commit, the one-time
initial-LKG transition, exact bootstrap and proposed policy digests, exact task
digest, current target ref, and candidate ID. The current kernel's gate contract
uses candidate comparison base `5393338` as the bootstrap-policy LKG field. The
distinct authority-transition and rollback basis `a0a0b01` is a pre-implementation
blueprint and has no executable LKG evaluator, so this release cannot honestly
claim an old-policy execution. It instead requires a distinct protected
initial-bootstrap decision.
This exception is non-reusable; every later governance upgrade must execute its
actual previous LKG. The evidence manifest has two exclusive admission modes:
this exact initial-bootstrap mode carries its protected bootstrap verification,
proposed policy, promotion decision, and rollback evidence; the normal mode
requires a protected previous-LKG policy decision. Every job reconstructs
`MANIFEST.json` before use. Upstream evidence and the final publication cross
jobs only through immutable artifact IDs emitted by the protected upload steps.

## GitHub Free bootstrap order

1. Push this reviewed bundle to `refs/heads/governance-authority` in the public
   target as the one-time bootstrap commit.
2. Protect that exact ref with exactly one authority profile. A sole user owner
   with no second eligible reviewer uses
   `rulesets/authority-ref.ruleset.json`: every change still requires a pull
   request, thread resolution, stale-review dismissal, and no bypass, but it
   does not make a false second-human claim or deadlock the repository. An
   account with another eligible reviewer uses
   `rulesets/authority-ref-reviewed.ruleset.json`, which also requires one
   eligible approval from someone other than the last pusher. It deliberately
   does not require code-owner review because a sole-user repository would
   deadlock. Adding an eligible reviewer requires upgrading to the reviewed
   profile.
3. Create or reuse the separate private execution-broker repository. Render its
   three caller workflows from `.governance/broker-templates/`, replacing the
   authority placeholders with this exact public authority commit. The broker
   default branch is not authority and must accept no public or candidate event.
4. Open the prefilled URL in `.governance/github-app-registration.json`, review
   the settings, and create the private GitHub App.
5. Install the App only on `timaday/codex-governed-change`.
6. Store the App ID as private-broker repository variable
   `DISPOSITION_APP_ID`, and create repository variable
   `GOVERNED_SCHEDULE_ENABLED` with exact value `false`. Upload the App's PEM
   private key directly as the
   private-broker repository Actions secret `DISPOSITION_APP_PRIVATE_KEY`. Never
   paste the key into a file, issue, command line, log, or chat.
   The App requests `statuses:write` only so GitHub can bind the App as the
   expected source of the required status check. Authority code publishes only
   the fixed Checks API run and must never call the commit-status API.
7. Verify the authority-owned mutation corpus, all three protected context
   qualifications, the exact bootstrap policy, the proposed policy whose LKG is
   the release candidate, and their target-registry digests.
8. Provision a clean, single-job JIT runner labelled
   `governed-reviewer-jit` on Linux x64 and register it only to the private
   broker. Pre-authenticate it through
   ChatGPT/Codex with qualified `gpt-5.6-sol` access, isolate it from all other
   credentials and workloads, and destroy it after the job. No OpenAI API key
   is permitted. The authority ref is public, but its reusable job executes in
   the private caller context; saved ChatGPT-managed Codex authentication never
   enters the public target.
9. The protected human-label decision records the owner's approval of all eight
   labels. Manually run `Qualify protected Codex reviewer broker` from the
   private broker on that clean JIT runner; it executes the exact conformance
   and rapid-review prompt/schema/model/launcher/CLI identities against every
   approved seeded case. Replace both blocking draft records and both
   content-addressed per-case documents with the measured results, update the
   protected policy with their exact IDs and corpus digest, and commit those
   qualification files as the authority basis. The qualified identity includes
   the exact `chatgpt` authentication mode as well as the prompt, schema, model,
   reasoning, launcher, and CLI identities. Then add human decisions in one
   child commit containing only decision files plus `MANIFEST.json`; bootstrap
   scope binds the basis parent, avoiding any self-referential commit claim.
   Regenerate the protected candidate binding. Until then the producer
   intentionally returns a non-successful check.
10. Add a protected `.governance/releases/v0.1.0/bootstrap-decision.json` that
   exactly authorizes the authority basis commit, bootstrap policy, kernel source, and
   blueprint basis. Separately add the distinct proposed policy and exact
   protected `lkg_promotion` decision.
11. Exercise `.governance/releases/v0.1.0/rollback-plan.json` against a clean
    checkout of the blueprint base in a disposable sandbox. The protected
    workflow packages five reconstructing JSON records plus bounded
    `stdout.bin` and `stderr.bin` into its immutable rollback artifact; these
    runtime records are not precommitted claims. Admission re-hashes both
    streams and validates every source, task, candidate, policy, command,
    timing, sandbox, provenance, material, subject, and cross-document binding.
12. After the qualification basis and decision-only child commits are protected,
    set `GOVERNED_SCHEDULE_ENABLED` to `false` and do not run any broker
    workflow. Repin all three private broker callers to the
    exact decision commit at the live authority ref and verify every resolved
    reusable-workflow SHA equals that commit. A stale or mixed pin is a blocking
    installation state. The required transitions are machine-readable in
    `.governance/bootstrap-sequence.json`. Its permitted-run sets include both
    manually dispatched workflows and automatically triggered finalizers; a
    completed producer may therefore trigger the finalizer before the receipt
    commit exists, while its protected guards still determine the outcome.
13. Dispatch `Governed disposition broker` on the private broker's default
   branch for target `release-v0.1.0`, selecting the complete protected decision set. The
   run emits a content-addressed `authorization-receipt-proposal.json` that
   preserves the authenticated actor, immutable decision commit, basis commit,
   selected decision IDs, and original dispatch assertion. Commit that exact
   proposal as `.governance/releases/v0.1.0/authorization-receipt.json` in the
   sole permitted receipt-only child commit, together with regenerated
   `MANIFEST.json`.
14. Commit the receipt-only child, immediately confirm
   `GOVERNED_SCHEDULE_ENABLED` is `false`, then again stop all broker runs until
   all three callers are repinned to and verified against that exact receipt
   commit. Only after that verification set the variable to exact value `true`
   and run the producer. A scheduled run accepts no decision
   inputs and may inherit only the exact authenticated set in that protected
   receipt. A manual run may still make a fresh authenticated selection.
   Before every later authority transition, recovery, or caller repin, set the
   variable back to `false`; do not re-enable it until the new protected receipt
   commit is the verified pin for all three callers.
15. After the App has submitted the `disposition` check for the current
   authority and target commits, render the target
   ruleset with the App integration ID, apply it disabled, verify its source
   binding, and then enable it.

## Expected outcomes

- `READY_FOR_HUMAN` lets the protected finalizer update only that source run's
  exact initialized failure sentinel after GitHub records the producer as
  completed successfully. It never creates a free-standing success and rejects
  finalization if a newer governed check has initialized. It is not merge,
  release, waiver, or risk-acceptance authority.
- `BLOCK`, `UNKNOWN`, missing evidence, a skipped or cancelled job, an invalid
  candidate, absent qualification, or any adapter failure creates or preserves
  a non-successful check. The first credentialed job creates a completed failure
  check for the one immutable protected target before any checkout, bundle read,
  target resolution, or admission work. The source producer may update that
  exact check only to failure. It defers every success publication until its
  internal `workflow_run` completion event proves that GitHub recorded the
  whole source run as successful; only then may the finalizer create the
  App-bound success. Source-run failure or cancellation after initialization
  therefore cannot preserve or create success. Cancellation of the finalizer
  after GitHub accepts its final success write cannot invalidate the already
  completed successful source run; before that write, the sentinel remains
  failure. Once
  protected target resolution succeeds, it also uploads an immutable failure
  payload before downstream work; the publisher uses that payload whenever
  admission cannot upload its own. A failed reevaluation enumerates every check
  suite for the exact commit and App and then every `disposition` run in each
  suite, changing every earlier successful governed-change run to failure.
  Pagination must agree with GitHub's reported totals and fail closed on any
  incomplete, changing, or repeated result set. Stale success cannot remain
  authoritative. No state other than the final validated success permits
  progression. If GitHub cannot mint the App token or create the initial failure
  check, the producer has not started its protected publication boundary and
  must not be represented as a completed reevaluation.
- Scheduled runs re-evaluate only protected entries in
  `.governance/targets.json` and only the decision set inherited from the
  protected authorization receipt; they cannot supply or infer decisions from
  a scheduler actor. Adding a candidate requires a protected authority
  repository change and a new, non-bootstrap workflow version. This v0.1.0
  adapter accepts exactly one registry entry and cannot reuse the initial-LKG
  transition for a later target; arbitrary dispatch inputs cannot select
  another commit.
- Before protected target resolution and again immediately before check
  creation, the workflow verifies that the live protected authority ref equals
  GitHub's resolved `job.workflow_sha`. The reusable workflows accept no
  caller-selected authority repository, ref, SHA, target, trigger, actor, or
  source-run identity. Publication evidence binds that authority SHA. Before
  post-completion success, the finalizer also verifies the completed private
  broker run's repository, commit, workflow, attempt, event, result, and sole
  `referenced_workflows` entry against the same authority SHA. The publisher
  also reloads the target and verifies that target
  `refs/heads/main` still resolves to the evaluated commit. A stale authority or
  target ref cannot publish success.
- Each candidate job verifies the actual clean checkout `HEAD` before use and
  again after candidate-executing or reviewer steps. Pre-use checks reject every
  tracked, ordinary-untracked, or ignored-untracked change. Post-execution checks
  reject every tracked change and every ordinary or ignored untracked path outside the fixed
  `artifacts/governance/completion/evidence/` root. This is a protected
  compensating control for the immutable v0.1.0 kernel adapter, whose commit
  mode resolves its requested head but does not itself compare it with checkout
  `HEAD`. The authority workflow does not rely on that behavior alone.
- Deterministic, reviewer, and admission target checkouts fetch complete history
  so the fixed blueprint base and release head are both locally resolvable for
  exact diff and candidate reconstruction.
- Protected JSON inputs are validated without reserialization: the exact bytes
  whose digests appear in the target and rollback plan are copied into evidence.
  Both protected task contracts are stored as canonical JSON bytes, so their raw
  protected digests are identical to the kernel's parsed-task digests.
- A reviewer result is usable only after both bounded stdout and stderr capture
  threads reach EOF. If either stream remains open after the reviewer parent
  exits, the authority terminates the isolated process group, closes and rejoins
  the streams, records incomplete observation, and forces `UNKNOWN` even when a
  schema-valid result file and zero parent exit code exist.
- Production and qualification observe the combined stdout/stderr from
  `codex login status` under the same sanitized reviewer environment and require
  the exact ChatGPT-authenticated mode immediately before every invocation. The
  combined capture is required because the CLI may emit status on stderr. That
  authentication mode is part of protected qualification and execution identity;
  API-key mode, missing output, and additional output are rejected.
- Every authority JSON, decision, receipt, policy, evidence file, rollback raw
  stream, and publication input is consumed from one cached, descriptor-bound,
  no-follow byte observation under a monotonic deadline. Parsing, hashing,
  validation, copying, and reference construction reuse those exact bytes;
  pathname check-then-reopen sequences are forbidden. Protected qualification
  stores the exact reviewer-output bytes returned by the launcher observation;
  it never reopens that output pathname.

## Local verification

The verification suite is self-contained. Immutable candidate and rollback-source
inputs live under `tests/fixtures/` and are included in `MANIFEST.json`; tests do
not read a sibling release pack, an ancestor checkout, or machine-local state.
The source-provenance test also requires every kernel file to match either the
source-commit manifest or one explicit base-plus-authority override.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

No credential is required for this command.
