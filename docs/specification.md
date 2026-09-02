# Governed Change System Specification

Status: `DESIGN_READY`

Normative terms `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` indicate requirement strength.

## 1. Problem framing

LLM instruction following is probabilistic. Long conversations dilute important constraints; rules may conflict; and a model assessing its own output can accept unsupported conclusions. A larger prompt cannot create a durable authority boundary.

The system therefore separates:

1. **Guidance**: `AGENTS.md`, a repository skill, and task contracts help an author model work consistently.
2. **Evidence production**: deterministic commands produce exact candidate-bound results.
3. **Fresh-context review**: a separate read-only model process searches for defects and missing evidence without receiving the author conversation.
4. **Disposition**: deterministic aggregation rejects incomplete or stale proof.
5. **Authority**: protected CI and a human decide whether the candidate may be merged.

## 2. Scope

### 2.1 MVP scope

- Git repositories used with Codex CLI or an IDE-attached Codex session.
- Code, test, configuration, infrastructure, documentation, and specification changes.
- A repository skill with code and specification profiles.
- Commit candidates in CI and working-tree candidates locally.
- Deterministic gate execution with bounded output capture and artifact hashing.
- Fresh ChatGPT-authenticated Codex GPT-5.6 Sol (`gpt-5.6-sol`) review through
  a new `codex exec` invocation.
- JSON evidence contracts and a deterministic fail-closed aggregator.
- A bounded Codex Stop-hook adapter.
- Local operation without HiveGate, MCP, a database, or a hosted service.
- A GitHub Actions reference integration and branch-protection guidance.

### 2.2 Future options

- GitLab and other CI adapters.
- Organization-managed Codex hook policy.
- Model-diverse review lanes.
- Signed attestations and transparency logs.
- Remote evidence storage and workload identity.
- Language-aware dependency graph adapters.
- Policy-as-code engines such as OPA, if justified by adoption needs.

### 2.3 Non-goals

- Replacing deterministic testing, static analysis, security scanning, code owners, or human review.
- Proving that two instances of the same model are statistically independent.
- Allowing an LLM to grant waivers, merge, deploy, rotate credentials, or change policy.
- Treating a reviewer `PASS` as proof that the candidate is correct.
- Loading the whole repository or author conversation into one reviewer prompt.
- Providing a universal build/test command set for every technology stack.

## 3. Actors and authority

| Actor | May | Must not |
|---|---|---|
| Human task owner | Approve scope, requirements, waivers and merge | Rely on a model claim as sole evidence |
| Author model | Design, edit, test, self-review, repair | Declare final acceptance or modify gates to benefit its candidate |
| Deterministic gate runner | Execute configured commands and capture evidence | Interpret missing evidence as success |
| Fresh-context reviewer | Read the candidate, repository and verified evidence; emit bounded findings | Edit candidate, access author chat/reasoning, accept risk or certify merge |
| Evidence aggregator | Validate contracts, identities and required results | Infer absent results or override a failure |
| CI authority | Reproduce gates on an immutable commit | Trust mutable candidate-owned policy without protection |

The reviewer has asymmetric authority: `BLOCK` and `UNKNOWN` prevent automated progression; `PASS` only satisfies one prerequisite.

## 4. Trust boundaries

- Repository content, task text, diffs, commit messages, issue content and tool output are untrusted data.
- The author model and reviewer model are untrusted decision makers.
- The reviewer process MUST have read-only candidate access and no write credential.
- The evidence directory MUST be outside candidate identity inputs to avoid a self-referential digest, but its exclusion MUST be fixed and narrow.
- Gate definitions, schemas, aggregation policy, reviewer prompt and workflow files are governance assets. A normal candidate MUST NOT be able to alter the effective versions used to approve itself.
- CI SHOULD obtain effective governance policy from the protected base branch or a separately protected SHA-pinned workflow.
- Secrets MUST NOT be exposed to pull-request code, model prompts, model-readable logs, or committed evidence.

## 5. Domain vocabulary

### 5.1 Task contract

A normalized, schema-valid declaration of:

- task ID and profile;
- authoritative sources;
- base candidate;
- scope and non-goals;
- facts, assumptions and unknowns;
- acceptance oracles;
- risks and affected surfaces;
- mandatory gate IDs;
- required specialist perspectives;
- governance-file change authorization, if any.

The task contract is an input assertion, not automatic truth. The reviewer MUST compare it with repository authority.

A decision object is likewise an assertion until the configured protected
decision-source adapter verifies it. Content addressing proves only byte
identity. Every decision-consuming rule MUST receive a separate exact set of
adapter-verified `decision_id` values; the default is empty. Missing source
verification is `UNKNOWN/BLOCK` even when repository, candidate, scope, issuer,
time and decision content all appear valid.

### 5.2 Candidate identity

A candidate identity binds evidence to one repository state. It includes:

- mode: `commit` or `working_tree`;
- base commit;
- head commit when present;
- canonical tracked diff digest;
- the independently observed, sorted repository-relative paths changed by that
  tracked diff plus non-ignored untracked additions;
- ordered non-ignored untracked path/content/mode digests for working-tree mode;
- ordered submodule states when submodules are present;
- effective governance policy digest;
- final aggregate SHA-256 digest.

Paths MUST be repository-relative and normalized. Collections MUST be sorted. Hashing MUST use raw bytes where content identity matters and canonical JSON for aggregate structures.

The admission kernel MUST use this candidate-bound changed-path set, not the
task author's affected-surface declaration, when selecting protected governance
rules and deciding whether governance authorization is required. The task's
affected surfaces remain an additional assertion used for closure checks.

`.git/` and the configured evidence output root are excluded. No other tracked candidate path may be excluded. Ignored files are outside the candidate contract and MUST NOT be needed for correctness; required generated inputs must be represented by a declared gate artifact digest.

Working-tree mode is advisory because the tree can change concurrently. The runner MUST compute the identity before and after each gate and reviewer run. Every gate, mutation baseline and mutant probe MUST independently re-identify its exact executed copy both before and after execution; observing the untouched source repository cannot establish copy stability. A mutant source identity additionally binds a complete concrete Git-visible tree manifest after the protected patch is applied. That manifest recursively binds each submodule's exact commit and its own tracked plus non-ignored untracked bytes; a gitlink commit alone is insufficient because submodule worktree bytes can drift without moving `HEAD`. A mismatch makes the result `UNKNOWN`. Submodules copied for gates MUST be reconstructed from their bound commits rather than copied from working directories, so ignored and machine-local files remain absent. CI MUST use immutable commit mode. Each observation-through-publication command MUST hold a non-blocking OS-backed lock on the retained no-follow evidence-root directory descriptor itself for its complete lifetime, and the output store MUST verify that same root device/inode through publication. A writable, hardlinkable or replaceable lock leaf is not an authority boundary. Replacement, unavailable safe binding or contention is `UNKNOWN/BLOCK`.

In commit mode, resolving the caller-requested head is not proof of the checked
out repository state. The repository adapter MUST independently resolve actual
checkout `HEAD`, require it to equal the resolved requested head, and perform
that comparison before candidate construction, snapshot copying, or execution.
A clean checkout at another locally resolvable commit is a candidate mismatch,
not valid evidence for the requested head.

### 5.3 Gate result

Each gate result records:

- gate ID, command descriptor and profile;
- candidate identity;
- start/end timestamps and bounded duration;
- exit status or termination cause;
- stdout/stderr artifact locations, byte lengths, truncation state and SHA-256 hashes;
- status: `PASS`, `FAIL`, or `UNKNOWN`;
- limitations and producer version.

`PASS` requires exit zero, complete required observations, no timeout, matching pre/post candidate identity, and schema-valid artifacts. Non-zero is `FAIL` unless the command could not be observed reliably, in which case it is `UNKNOWN`. Timeout, launch error, signal ambiguity, missing output, invalid encoding where required, truncation of required causal evidence, or identity drift is `UNKNOWN`.

A gate manifest is constructed only after every referenced gate result exists.
Its `created_at` MUST be at or after the maximum referenced result `ended_at`;
a caller-supplied observation time cannot serve as manifest creation time.

### 5.4 Reviewer result

The fresh reviewer emits only schema-valid JSON containing:

- candidate binding;
- verdict: `NO_BLOCKING_FINDING_OBSERVED`, `BLOCK`, or `UNKNOWN`;
- reviewed surfaces;
- findings with severity, location, claim, violated oracle, evidence and remediation;
- missing evidence;
- the exact protected mandatory claim-ID set from the context assurance kernel,
  each present once with non-empty resolved evidence references;
- claim classifications: `DIRECTLY_OBSERVED`, `VERIFIED_WITHIN_SCOPE`,
  `UNVERIFIED`, or `UNKNOWN`;
- limitations.

The reviewer result is invalid if it does not exactly match the repository,
candidate, task contract, context receipt, reviewer prompt/launcher/model/schema
qualification, and required gate manifest supplied by the runner. Every cited
evidence locator is resolved and digest-verified before it can support a claim.

### 5.5 Evidence manifest and disposition

The evidence manifest references immutable, hashed task, candidate, gate and reviewer artifacts. The aggregator validates references rather than trusting embedded summaries.

The only automated final states are:

- `READY_FOR_HUMAN`: all mandatory prerequisites are valid for the exact candidate.
- `BLOCK`: a confirmed failure, blocking reviewer finding, unauthorized governance change, or unsatisfied mandatory condition exists.
- `UNKNOWN`: the system cannot establish a required fact. `UNKNOWN` blocks progression.

## 6. Required workflow

### 6.1 Context

The author MUST inspect repository authority, current Git state, affected contracts and risks before editing. It MUST identify conflicts rather than inventing an override.

### 6.2 Decide

For executable behavior, the author MUST establish a failing test or other explicit red oracle before production implementation. If this is infeasible, the task remains blocked until a human accepts a documented alternative oracle.

For specification work, the author MUST produce traceable requirements, alternatives, decisions, acceptance criteria and a verification strategy before finalizing prose.

### 6.3 Act

The author MUST make bounded, coherent changes. It MUST NOT modify acceptance authority to make the same candidate pass unless the task is explicitly classified as a governance change.

### 6.4 Verify

The author runs required deterministic gates, self-reviews the diff, and starts
the fresh-context reviewer only after sandbox, mutation, RST, context and other
deterministic prerequisites pass. A candidate modification invalidates all
earlier affected results.

### 6.5 Learn

The author records defects, false assumptions, residual risks, unknowns and future options. Learning does not silently change approved requirements.

## 7. Quality profiles

### 7.1 Code profile

The task contract selects applicable gates from:

- formatting and generated-file consistency;
- compilation and type checking;
- unit, integration and contract tests;
- architecture and dependency-boundary tests;
- static security and dependency analysis;
- property, fuzz, mutation, concurrency and adversarial tests for risk-bearing surfaces;
- runtime evidence for operational claims;
- documentation and migration consistency.

A mandatory gate cannot be marked `N/A` without an explicit task-contract reason and human authority where risk is reduced.

### 7.2 Specification profile

A specification change requires:

- problem, users, value, scope, non-goals and constraints;
- authoritative sources and traceability;
- alternatives and decisions with rationale;
- functional and non-functional requirements;
- Business, Engineering and QA review;
- relevant architecture, security, performance, data, operations, UX, accessibility and agentic-AI perspectives;
- acceptance criteria, test strategy and evidence plan;
- Rapid Software Testing risks, heuristics, oracles, charters, edge cases and debrief;
- contradictions, assumptions, unknowns and deferrals kept explicit.

### 7.3 Mixed profile

Mixed changes MUST satisfy both profiles. Documentation-only labeling does not remove code-profile obligations if behavior or authority changes.

## 8. Fresh-context reviewer isolation

The strict reviewer MUST be a new process and MUST NOT use `codex exec resume` or an in-session subagent. This establishes fresh context, not statistical or organizational independence.

The launcher MUST:

- use a new `codex exec --ephemeral` invocation;
- use `--ignore-user-config` while preserving normal authentication;
- use `--ignore-rules` and explicit overrides that disable hooks and subagents for the reviewer process;
- select a strict custom Codex permission profile that extends `:read-only`,
  denies the host root, re-allows only the sanitized workspace and minimum
  detected Codex/tool runtime installation roots, and disables tool network
  access; runtime roots are derived at launch, never accepted from candidate
  input, and persist only through the argv digest; the legacy broad-read
  `--sandbox read-only` mode is insufficient for this boundary and MUST NOT be
  combined with the custom profile;
- set approval policy to `never`, require strict config parsing, and restrict
  model-generated tool environments to non-secret runtime keys; parent `HOME`,
  `CODEX_HOME`, proxy values and authentication material remain available only
  where needed by the parent Codex process and MUST NOT reach tool processes;
  tools receive a fixed synthetic home value so shells cannot reconstruct the
  parent credential location;
- select the configured ChatGPT-authenticated Codex GPT-5.6 Sol model
  (`gpt-5.6-sol`) and reasoning effort; API-key authentication is outside the
  MVP reviewer identity;
- require `--output-schema`, `--json` event output and a dedicated final-output path;
- start Codex in a sanitized harness Git root, with the immutable candidate checkout nested beneath it as read-only evidence, so candidate-owned `.codex` configuration, hooks, skills and execpolicy are inspectable files but not active reviewer configuration;
- expose no author chat, plan, self-review, persisted/hidden reasoning,
  connector, unrelated MCP tool, host filesystem outside the bounded read
  roots, tool network, or tool-visible credential;
- pass only a fixed reviewer prompt, normalized task contract, exact candidate identifiers, required gate manifest and raw evidence locations;
- copy only explicitly allowlisted, digest-matched, bounded regular evidence
  files into the sanitized harness; caller-selected harness roots, absolute
  paths, symlinks, path traversal and undeclared evidence are forbidden;
- record digest-only argv/stdin identities and the exact sanitized invocation
  configuration in a content-addressed reviewer-execution statement that also
  binds the Codex thread and CLI versions, workflow run/attempt, limits,
  materials, prompt/schema/model/qualification/launcher identities,
  termination, primitive supervisor/capture observations, direct write-once
  normalized stdout/stderr references, output, candidate pre/post identity and
  CLI-reported token usage;
- classify non-zero exit, timeout, malformed output, missing output or identity mismatch as `UNKNOWN`.

A zero-exit reviewer parent is not complete process observation. Stdin delivery
MUST run in a bounded writer and share one absolute launcher deadline with
process waiting, stream closure, capture joins and forced cleanup. Process
execution reserves part of that same bound for cleanup; no phase receives a
fresh timeout after the deadline. A reviewer that retains but does not read
stdin forces bounded termination and `UNKNOWN`. Both bounded
stdout and stderr capture threads MUST reach EOF and a trusted descendant
boundary MUST prove that no live descendant remains before reviewer output can
be valid. Changing process group or session, closing every standard stream, or
signalling a same-UID supervisor MUST NOT escape that boundary. On Linux the
reference adapter prefers placing the reviewer behind trusted PID 1 in a fresh
user, PID and mount namespace whose trusted parent remains outside the
reviewer-visible PID namespace; PID-1 exit or parent death tears down the
complete namespace. Where nested namespaces are kernel-blocked, a
`no_new_privs` seccomp guard MUST instead deny every process-signal,
cross-process-write, and cross-process resource-limit mutation syscall for the
reviewer and all descendants before exec, making the same-UID outer
child-subreaper non-signalable and preventing `prlimit64` from terminating or
crippling it indirectly. The subreaper proves and performs bounded descendant
cleanup on that fallback. If neither exact
kernel boundary is available, the result is `UNKNOWN` before the reviewer is
admitted. On x86_64 the guard MUST reject the complete x32-tagged syscall
number space before native syscall dispatch; checking only native x86_64
numbers is not containment because an x32-enabled kernel could otherwise admit
alternate-ABI signal or cross-process-write calls. Initial success MUST NOT be
inferred from a racy zombie-only process-group scan. Cleanup, stream closure and
capture joins MUST remain time-bounded. Any live descendant, missing containment
handshake or incomplete capture permanently forces `UNKNOWN`; later cleanup
completion cannot promote it.

Before retained reviewer streams are hashed or persisted, the trusted launcher
MUST replace harness, executable-runtime, home, authentication-home, temporary,
proxy and other allowlisted parent-environment values with a fixed portable
token. Parsing and execution-statement digests use those normalized captured
bytes. An endpoint- or generic host-path-shaped value in a Codex command-
execution event whose exact decoded bytes already occur in the immutable
candidate or protected reviewer inputs is a portable source literal and is
replaced by a distinct fixed token. An exact immutable assignment-shaped source
expression whose right-hand side starts a same-name method call is syntax, not a
credential value, and receives the same treatment; nested actual credential
tokens remain ambiguous. The exception does not apply to credential values or
the final agent message. Other recognized shaped values are replaced before
persistence, and that ambiguous transformation permanently forces `UNKNOWN`.
JSONL normalization MUST parse and re-serialize complete events so replacement
cannot corrupt escaping. Truncation, retained machine values or malformed JSONL
block.

The reviewer MUST compute the diff and affected closure independently. The author MUST NOT select a restricted file list that prevents repository search.

The prompt, output schema, model, Codex CLI version and material launcher configuration form one
qualified reviewer identity per review mode. Conformance and rapid review use
distinct output schemas and therefore MUST have distinct protected qualification
IDs even when their prompt, model and launcher are otherwise identical. A
protected human-labelled defect and prompt-injection corpus records critical
recall, false pass/block, unknown, latency and cost for each identity. A material
identity change invalidates only that exact qualification and cannot fall back to
the identity for another mode. Qualification acceptance MUST bind the exact
approved corpus and the authenticated label-decision ID, and that decision ID
MUST be present in the protected decision-source result. Corpus, label-decision
and case-evidence representations are typed and content-addressed. Each case
MUST deterministically reconstruct its full candidate identity from the exact
corpus paths, modes and UTF-8 file bytes; resolve and re-hash its stored
normalized stdout/stderr capture streams; parse the final Codex JSONL agent
message, thread and usage; schema-validate that message against the retained
reviewer output; derive capture, cleanup, binding and execution validity from
primitive supervisor observations; bind the execution to the exact case plus
prompt/schema/model/launcher/Codex identity; and independently recompute every
aggregate. Self-reported execution booleans, supplied digest-shaped candidate
IDs or unverified issuer prose are not execution or human authority.
A typed coverage-class field identifies seeded-defect, prompt-injection and
clean-control cases. Every exact identity and review mode MUST exercise all three
classes; one deliberately injected seeded-defect case may cover both of the first
two classes, but a corpus missing any class cannot qualify.
A content-addressed summary is not sufficient evidence of its own claims.
High/critical policy may require a human specialist or genuinely diverse lane;
disagreement is a defeater, not a majority vote. Whole-repository architecture
and security audit is a separate scheduled/major-change workflow.

The trusted launcher creates and owns the temporary harness; callers do not
select it. The sanitized harness contains only the fixed protected reviewer
prompt, output schema, permitted-input manifest, explicitly digest-matched
evidence, and the nested candidate. It MUST NOT copy global or candidate Codex
configuration into an active layer. Authentication may remain in the normal
Codex home, but no authentication file or value enters the harness, prompt,
result, or evidence manifest. The launcher MUST re-observe the live candidate
before and after the reviewer process. A trusted post-run phase MUST persist the
reviewer result, normalized stdout and stderr bytes, reviewer-execution statement
and a context-execution receipt linked to the immutable prepared receipt. The
execution statement binds both receipts, both direct stream references and the
output without creating a circular content address. Admission MUST resolve the
raw streams, reconstruct their JSONL result/usage and primitive observation
facts, and then reconstruct those links;
a schema-valid reviewer document or ambient workflow success is insufficient.

## 9. Affected closure and repository audit

Per-change review begins with the exact diff and traverses:

- callers and callees;
- imports and dependency edges;
- public contracts and schemas;
- tests and fixtures;
- configuration, deployment and migration paths;
- authorization and trust boundaries;
- documentation and operational procedures.

The reviewer has full repository read access but MUST prefer targeted search over indiscriminate context loading. A periodic full-repository architecture/security audit is a separate workflow and does not replace per-change review.

## 10. Stop-hook behavior

The Stop hook is a local continuation guard, not final enforcement.

It MUST read the hook event from stdin, recompute current candidate identity, and inspect the latest valid disposition:

| Condition | First Stop (`stop_hook_active=false`) | Continued Stop (`stop_hook_active=true`) |
|---|---|---|
| Exact `READY_FOR_HUMAN` evidence | Return `continue: true` | Return `continue: true` |
| Missing/stale/failed/unknown evidence | Return `decision: block` with the smallest next action | Return `continue: false` with a visible stop reason |
| Hook internal failure | Fail closed with a blocking reason | Stop with `UNKNOWN`, not an infinite loop |

The hook MUST NOT launch nested reviewers recursively. It verifies state and instructs the author to run the explicit governance command.

Non-managed project hooks require trust and can be disabled. CI remains the hard authority.

## 11. CI and governance integrity

CI MUST run on the immutable pull-request candidate and use read-only repository permissions for model review. Deterministic setup and tests MUST run before any job receives a model credential.

The effective gate policy MUST come from a protected source. The reference
workflow in this repository is an installation template for a separately
protected authority repository or organization ruleset; copying it into the
evaluated repository cannot establish authority. Recommended controls:

- required status checks or repository rulesets;
- code-owner review for governance assets;
- a SHA-pinned reusable workflow in a separately protected repository, or an equivalent organization-managed required workflow;
- `contents: read`, no persisted checkout credentials, and no write token in the reviewer job;
- separate jobs for untrusted tests/model review and any later PR comment or publication action;
- explicit human approval for governance changes and waivers.

Removing or renaming the required workflow MUST leave the required check absent and therefore blocking; it must not create a silent pass.

## 12. Waivers

A waiver is a protected human decision, not a fallback. It records:

- waiver ID and human approver;
- exact candidate and requirement/gate;
- rationale and compensating controls;
- creation and expiry;
- scope and whether reuse is forbidden.

An LLM cannot create, approve, extend or infer a waiver. Expired, mismatched, missing or malformed waivers are `UNKNOWN/BLOCK`.

## 13. Privacy, security and observability

- Artifact logs MUST be bounded, hashed and redacted before model exposure.
- Redaction MUST be deterministic and reported; it MUST NOT conceal required causal evidence.
- Protected normalization MUST remove exact supervisor/host values and
  secret-shaped credentials before persistence. A secret-shaped replacement is
  evidence ambiguity and forces `UNKNOWN`; exact proxy-environment values are
  credential-class values even when their syntax is not independently
  recognized. Known supervisor-path replacement may remain usable when its
  category and count are recorded.
- Reviewer prompts and outputs MUST NOT request or store hidden chain-of-thought.
- Authentication files, API keys and environment secrets MUST never be committed or included in evidence.
- Audit records SHOULD contain versions, hashes, times, exit states and limitations, not unnecessary source copies or personal data.
- The CLI MUST use argument arrays without a shell by default. Shell commands require explicit configuration and risk classification.
- Symlinks, path traversal, submodules, large files, invalid encodings, concurrent edits and subprocess termination MUST have explicit tests.

## 14. RST-inspired rapid review

RST-inspired rapid review is a distinct investigative layer for specification/design review before approval and code/change review after cheap deterministic gates. Deterministic checks evaluate known assertions; conformance review compares the candidate with its contract; rapid review investigates important risks, failures, assumptions, stakeholders, and value that those mechanisms may have omitted. It is not official or fully automated Rapid Software Testing, and it never replaces deterministic evidence, conformance review, or human authority.

For each exact candidate, the workflow MUST:

1. create or update a candidate-bound risk assessment;
2. select risk-proportionate, time-boxed charters;
3. run cheap deterministic checks first when useful;
4. conduct each required charter in a fresh-context read-only harness with the approved contract, risk assessment, charter, and allowlisted evidence, never the implementer's conversation;
5. record experiments, direct observations, fallible oracles, evidence, findings, counter-hypotheses, coverage, omissions, obstacles, follow-up charters, and residual risks;
6. debrief the product story, testing story, and quality-of-testing story separately;
7. return actionable findings for remediation; and
8. invalidate all affected evidence and repeat after any candidate mutation.

Risk effort is configurable rather than duration-driven:

- `low`: rapid review may be skipped only with a non-empty policy-valid rationale; hazardous surfaces in GOV-034 cannot select this profile;
- `standard`: at least one completed focused charter and debrief;
- `elevated`: multiple relevant completed charters or explicit justified coverage,
  qualified fresh-context review, human debrief, and human ownership of material
  residual-risk acceptance.

HTSM and FEW HICCUPPS are fallible guidewords for inquiry, not rules or proof. Useful oracles include purpose and stakeholder value, claims and requirements, internal consistency, history, comparable systems, user desires, standards and law, feasibility, testability, observability, invariants, schemas, differential/metamorphic relationships, error states, privilege boundaries, concurrency, compatibility, recovery, operability, and diagnostics. Every finding must explain why an observation threatens value and cite direct evidence.

The deterministic governor validates artifact presence, schema, provenance, exact candidate binding, required charter count/status, evidence references, finding disposition, and residual-risk disposition. It MUST return `UNKNOWN/BLOCK` for missing or stale artifacts, unavailable material oracles/environments, unclear coverage, missing debrief, blocked/inconclusive sessions, unsupported success claims, or unresolved high-impact risk. Completed checklists, elapsed time, session count, or no findings never establish safety.

The adaptation is informed by the [Rapid Software Testing introduction](https://rapid-software-testing.com/a-ridiculously-rapid-introduction-to-rapid-software-testing/), [Heuristic Test Strategy Model](https://rapid-software-testing.com/heuristic-test-strategy-model/), [FEW HICCUPPS](https://developsense.com/blog/2012/07/few-hiccupps), [session report checklist](https://rapid-software-testing.com/session-based-test-management-report-checklist/), and [testing/checking distinction](https://rapid-software-testing.com/testing-and-checking-refined/). The repository defines an independent MIT-licensed adaptation and does not copy or vendor course worksheets.

## 15. Protected admission and trusted authority

The admission kernel is the only component that may emit
`READY_FOR_HUMAN`. It is a pure, deterministic reference monitor evaluated from
the previous LKG governance source. It validates a compact assurance case with
fixed argument rules for authorized scope, exact/current repository and
candidate, protected governance, complete gates, required RST and mutation,
qualified fresh-context review, and visible residual risks, waivers and unknowns.
Each claim contains supporting and refuting typed evidence, limitations and
unresolved defeaters. Model prose is never an argument rule.

Prerequisite components use component-specific success vocabulary. In
particular, deterministic context preparation emits `CONTEXT_READY` or
`UNKNOWN`; it never emits `READY_FOR_HUMAN` and cannot be mistaken for the
admission decision.

For a fixed authenticated authority set, the policy is monotonic: adding a
failure, unknown or defeater; removing required evidence; changing repository,
candidate, policy, producer or environment; or making evidence stale can never
improve disposition.

Protected decisions are external verified facts, not booleans or names supplied
by the candidate. Task approval, governance authorization, risk reduction,
waiver issuance/consumption and LKG promotion bind repository ID, task digest,
candidate/base where applicable, policy digest, exact scope, authenticated
issuer, issued/expiry times and single-use consumption where applicable.
Protected changed-surface policy computes a minimum risk profile and gate set.
Task input may add scrutiny; reducing the floor requires an applicable decision.
The previous LKG policy supplies the exact TCB path set used for classification.
Admission first requires a protected-source-authenticated LKG-policy decision
binding that policy digest to the exact task, candidate and candidate base, and
requires the policy's LKG commit to equal that base. When any changed path
intersects that authenticated set, the evidence manifest must separately
reference the proposed policy, authenticated LKG-promotion decision and rollback
evidence. Rollback evidence contains typed references to a policy-defined
rollback gate result, sandbox capability and provenance statement. Admission
descriptor-resolves and fully reconstructs those nested artifacts, raw streams,
producer identity and chronology, rejects limitations, and requires the policy
argv, executed gate argv, provenance material and exact machine-readable success
line to agree on the authenticated base target. A protected producer runs this
rehearsal separately from the ordinary task-selected gate set using executable
rollback code from a read-only materialization containing exactly the paths and
verified bytes in the previous-LKG package's producer manifest. The materialized
import root contains that package and no broader source-tree siblings, Python
site initialization is disabled, and a missing, mismatched or extra file blocks;
ignored, untracked and candidate-relative rollback code is never an authority
source. It emits the
nested typed rollback evidence before the
previous-LKG promotion predicate runs;
ordinary governance authorization or digest-shaped proof alone is insufficient.

## 16. Sandboxed execution and provenance

Candidate commands are untrusted. They run in a disposable candidate/build
sandbox with no secrets, network disabled by default, declared process/resource/
time/output limits, and no writable protected governance, supervisor, reviewer
harness or authoritative evidence path. The supervisor records its capability
report. If that boundary cannot be established, the gate is `UNKNOWN` and
admission blocks. A separate directory or path validation alone is not a sandbox.
For a container provider, the trusted supervisor MUST allocate a runtime-only
name and ID file outside the candidate, finish a bounded `create` transaction,
and validate the immutable container ID and reserved name before starting the
timed attached command. The capability explicitly records the pinned image and
canonical candidate command; admission independently reconstructs its execution
identity from protected provider/version/image/command and every process, memory,
CPU, timeout and output bound. After every exit path it MUST resolve any identity that
appears after a client timeout, forcibly remove only exact immutable IDs, and
quarantine the reserved name until repeated successful all-container listing
queries prove both the ID and exact name stably absent. A non-zero or malformed
provider response is ambiguous, never proof of absence. Killing only the local
provider CLI, accepting a missing ID, ignoring a failed remove, or relying on
one pre-completion name query is not container cleanup. Delayed creation,
failed removal, missing identity or an inconclusive absence check makes process
observation incomplete and therefore `UNKNOWN`. Any observed rename of the
original ID or same-name substitution permanently taints the transaction; later
removal or absence cannot restore certainty.
Every gate receives a newly reconstructed candidate copy. A writable copy is
never reused by a later gate, so an earlier command cannot replace the source,
tests or configuration observed by a sibling gate. Before launch, the trusted
supervisor independently identifies the copy and requires it to match the exact
candidate; mismatch is `UNKNOWN/BLOCK`.

The sandbox capability observation MUST be produced before the execution it
authorizes. Production rejects a capability whose `verified_at` is later than
the gate start, and reconstruction independently requires
`capability.verified_at <= result.started_at <= result.ended_at <=
gate-manifest.created_at`. The provenance predicate start/end times MUST equal
the gate result. A caller-supplied, future-dated or conflicting clock value is
`UNKNOWN`; digest integrity cannot repair invalid chronology.

Only after untrusted execution ends may a fresh trusted phase package output. It
emits an in-toto-shaped Statement v1 whose subjects bind the protected
`repository_id` and exact candidate/source digest. The predicate binds task,
effective policy, gate/reviewer prompt, producer/builder implementation, workflow
run and attempt, tools, sandbox/environment, resolved materials, start/end time,
result, limits, limitations and artifact digests. Source identity and execution
identity are distinct replay boundaries. The MVP statement is unsigned
provenance; it MUST NOT be described as authenticated until a signature envelope
is actually verified.

Authoritative storage is content-addressed and write-once. Writing identical
bytes to the same address is idempotent; any conflicting replacement blocks. A
content-addressed document ID is SHA-256 of canonical JSON with exactly that
top-level ID field omitted. Cross-repository substitution and unresolved typed
artifact/excerpt locators are `UNKNOWN/BLOCK`.

The same no-replacement/idempotent-identical rule applies to CLI output files;
atomic replacement is not an authority-output mechanism. During admission, each
gate result's stdout/stderr references are resolved beneath the repository,
re-hashed, byte-counted and reconciled with provenance. `PASS` additionally
requires exited-zero, complete observation, no truncation and exact candidate
pre/post identity. Gate, mutation and reviewer producers retain distinct
workflow/run identities; causal artifact links, not identical run IDs, relate
them.

Every output-producing CLI command MUST publish through the configured
repository evidence root. A caller-selected output is accepted only as a
repository-relative path that resolves beneath that root. Absolute paths,
traversal, evidence-root escapes, and symlinks in the evidence root, parent
chain, or leaf MUST be rejected before directory creation or publication.
If the runtime cannot provide directory-bound no-follow traversal, creation,
publication and readback, authoritative artifact I/O is unavailable and MUST
return `UNKNOWN/BLOCK`; it MUST NOT fall back to race-prone pathname I/O.
Existing leaves MUST be opened nonblocking where the platform supports special
files and rejected after descriptor-bound type inspection unless they are
regular files.

## 17. Governed mutation and operational RST

The mandatory mutation gate is a curated semantic corpus for fail-closed
governance invariants. The previous-LKG policy binds the complete corpus byte
digest, and the producer reads those exact bytes from the protected governance
checkout, copies them into write-once evidence, and rejects a candidate-local or
digest-mismatched substitute. It runs in a disposable candidate after a green
baseline and before final review. Only a protected structured probe showing that
the exact selected unittest command ran at least one test and terminated solely
with an assertion failure kills a valid non-equivalent mutant. The trusted probe
emits an exact machine-readable terminal marker and distinct exit code; admission
re-reads the bounded raw stream and reconstructs both rather than trusting the
mutant-record label. `SURVIVED`, `TIMEOUT`, `INVALID`, unresolved
`EQUIVALENT_CLAIMED`, launch/import/discovery/harness/crash/signal, malformed
probe, unexecuted and mixed error/failure outcomes never count as killed and
block or remain unknown. Generated language mutation is a bounded optional
adapter; aggregate percentage alone is not an oracle.

Every admitted mutant record MUST bind the protected corpus, repository, task,
policy and original candidate; a distinct mutated-source identity that includes
the complete concrete Git-visible mutated tree; the exact
selected command and execution identity; a validated disposable-sandbox
capability; the corresponding in-toto-shaped provenance statement; the bounded
execution result; and resolvable causal evidence. Mutation commands MUST use the
same protected container boundary as deterministic gates. A host subprocess or
summary-only corpus run is diagnostic evidence only and cannot satisfy the
mutation claim.

Operational RST maintains separate candidate/task-bound risk-register,
fallible-oracle/reference, charter, session observation, coverage, debrief and
follow-up artifacts. Requirements and changes create risks; observations update
them; surviving mutants refine charters; reviewer findings create follow-up
risks. Completed paperwork or no findings never proves correctness.

## 18. Deterministic context compilation

Every model call receives a protected deterministic projection:

- `COMPACT` for routine bounded low-risk work;
- `STANDARD` for normal implementation/review; or
- `DEEP` for governance, security, authentication/authorization, architecture,
  release/evidence/reviewer changes, large or uncertain closure, gate failure or
  absence, mutation survivor, oracle conflict, injection risk, incomplete
  authority/provenance, reviewer/selector uncertainty, or unsafe budget pressure.

All profiles contain a non-droppable assurance kernel: authenticated task and
authority; applicable policy; repository/candidate/policy/evidence identities;
complete changed-file inventory; a conservative dependency, caller, contract
and test closure independently derived by the trusted compiler from the
re-identified exact repository and policy; deterministic results; every
unresolved risk, failure, conflict,
survivor, limitation and unknown; the fixed reviewer rubric and disposition
contract; and typed references that can retrieve exact underlying evidence.

For the MVP, the conservative closure is the complete Git-visible candidate
repository inventory plus changed paths (including deletions), excluding only
the policy-declared evidence root. This safely includes unchanged callers,
contracts and tests without trusting language-specific or caller-provided
selection. A supplied closure that is missing, extra or differently ordered
MUST block. `prepare-review` therefore requires the exact repository and
effective policy in addition to the candidate descriptor.

The candidate-bound rapid-review assessment may increase but MUST NOT reduce the
effective protected/task risk profile, task-required review flag, or the larger
of the profile/task minimum charter counts. A downgrade is a confirmed block,
not a valid low-risk skip.

Progressive disclosure is `manifest -> typed summary -> relevant excerpt ->
complete artifact`. The complete repository and unabridged artifacts remain
read-only accessible without being inlined wholesale. Every expansion is added
to a context receipt. Stable rubric content precedes candidate-specific deltas;
unchanged content is referenced by digest. Prompt caching is recorded only when
reported by the active interface and never reduces logical assurance input.

Caller input is never aggregation authority. The protected compiler resolves
typed digest-bound task, policy, gate, mutation, risk, limitation, unknown and
rubric artifacts; independently re-identifies repository inventory and affected
closure; derives adverse profile signals; and rejects any supplied summary or
flag that differs. Every projection-version/profile combination binds a
protected content-addressed context-qualification artifact and the exact
qualification ID declared by effective policy.

The source bundle, projection and prepared receipt are separate immutable
referenced artifacts. The receipt binds projection/profile version,
context-qualification identity, source/projection digests,
included sources, excluded sources with deterministic reasons, estimated and
actual tokens where available, bytes, truncation, retrieval expansions, model,
effort, latency and cost when available. Mandatory information is never silently
truncated. The compiler escalates or returns
`CONTEXT_BUDGET_INSUFFICIENT` with `UNKNOWN/BLOCK`.

Admission descriptor-reads those artifacts and independently reconstructs their
source inventory, closure, signal/profile decision, inclusion choices, digests
and metrics. A self-consistent or content-addressed summary alone is not proof.

Context variants require representative seeded-defect/governance qualification.
They are promoted only if critical recall, evidence traceability and disposition
correctness do not materially regress; efficiency metrics are secondary. The MVP
uses Git metadata, repository search, import/test mapping and content-addressed
manifests, not embeddings or a vector database.

## 19. Schema lifecycle and portability

Schemas define supported versions and migration behavior. The qualification
evidence additions are breaking: `effective-policy` is `3.0.0` with the
protected mutation-corpus digest; `reviewer-qualification`, `context-receipt`,
`sandbox-capability`, and `provenance-statement` are `2.0.0`;
`evidence-manifest` is `3.0.0`; `reviewer-qualification-cases` is `3.0.0`
with full candidate and per-case context evidence; `reviewer-qualification-corpus` is `2.0.0` with
mandatory typed case classes; and `reviewer-execution` is `3.0.0` with primitive
observation plus direct stream references. Every transition advertised by the
lifecycle policy has an executable explicit migration; missing legacy facts must
come from separately protected inputs and every content address is rebuilt.
An old document is accepted only
as migration input and never as current admission evidence. Syntax validation is
followed by semantic validation including complete RFC 3339 parsing, time
ordering, digest/reference relationships and lifecycle constraints. Unsupported
or ambiguous versions block. The domain remains independent of JSON, Git,
subprocess, Codex, clocks and filesystems.

The package remains standalone on Python 3.11+ with standard-library production
code plus declared Git/Codex and an optional local sandbox executable. No HiveGate
code, service or schema is a runtime dependency. Repository files and committed
examples MUST NOT contain a developer path, username, hostname, local endpoint,
credential or machine-derived configuration/evidence.

Every authoritative repository/evidence read opens the resolved repository
directory and each child relative to a retained directory descriptor. Leaf opens
use no-follow and nonblocking flags, then `fstat` proves a bounded regular file
before bytes are read through that descriptor. Pathname validation followed by a
later pathname read is not an admissible fallback; unavailable descriptor-bound
access is `UNKNOWN`. The same retained-descriptor reader is mandatory while
materializing permitted evidence into the reviewer harness. The reviewer CLI
reads each permitted artifact once, validates and hashes those retained bytes,
and passes those same bytes to harness materialization; it must not reopen the
pathname between validation and copy.

Gate and mutation implementation identities hash a canonical manifest containing
the repository-relative filename, byte length and SHA-256 digest of every Python
file in the trusted package closure. The producer kind is framed separately.
Where that closure is materialized for protected execution, the manifest is the
exclusive copy allowlist: every source and destination digest is verified and no
additional importable file may appear under the materialized root. Changing or
injecting any shared producer dependency changes the asserted identity or blocks
materialization and makes earlier evidence incompatible.

## 20. Acceptance rule

The system may emit `READY_FOR_HUMAN` only when every required artifact is
schema-valid, semantically valid, complete, current, provenance-bearing,
authorized and bound to one repository and exact candidate; every mandatory
deterministic and mutation gate is `PASS`; the qualified fresh-context reviewer
reports `NO_BLOCKING_FINDING_OBSERVED`; its reviewer-execution statement and
post-run context-execution receipt reconstruct; required separately qualified
rapid-review sessions and the
three-story debrief are complete; every finding and material residual risk has a
valid authenticated disposition; both prepared and post-run context receipts are complete; governance
integrity remains protected by the LKG policy; and no unresolved defeater or
mandatory `UNKNOWN` remains.

Every reviewer-qualification case is itself a governed model invocation. Its
case evidence therefore contains separate typed references for the reconstructed
source bundle, projection, context qualification, prepared receipt and post-run
receipt in addition to output, execution and normalized streams. Digest-shaped
self-report without those exact artifacts cannot qualify a reviewer identity.

Nothing in this specification authorizes automatic merge or deployment.
