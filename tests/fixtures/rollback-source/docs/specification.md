# Governed Change System Specification

Status: `DESIGN_READY`

Normative terms `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` indicate requirement strength.

## 1. Problem framing

LLM instruction following is probabilistic. Long conversations dilute important constraints; rules may conflict; and a model assessing its own output can accept unsupported conclusions. A larger prompt cannot create a durable authority boundary.

The system therefore separates:

1. **Guidance**: `AGENTS.md`, a repository skill, and task contracts help an author model work consistently.
2. **Evidence production**: deterministic commands produce exact candidate-bound results.
3. **Independent review**: a fresh read-only model process searches for defects and missing evidence.
4. **Disposition**: deterministic aggregation rejects incomplete or stale proof.
5. **Authority**: protected CI and a human decide whether the candidate may be merged.

## 2. Scope

### 2.1 MVP scope

- Git repositories used with Codex CLI or an IDE-attached Codex session.
- Code, test, configuration, infrastructure, documentation, and specification changes.
- A repository skill with code and specification profiles.
- Commit candidates in CI and working-tree candidates locally.
- Deterministic gate execution with bounded output capture and artifact hashing.
- Fresh GPT-5.6 review through a new `codex exec` invocation.
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
| Independent reviewer | Read the candidate, repository and raw evidence; emit findings | Edit candidate, access author chat, accept risk or certify merge |
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

### 5.2 Candidate identity

A candidate identity binds evidence to one repository state. It includes:

- mode: `commit` or `working_tree`;
- base commit;
- head commit when present;
- canonical tracked diff digest;
- ordered non-ignored untracked path/content/mode digests for working-tree mode;
- ordered submodule states when submodules are present;
- effective governance policy digest;
- final aggregate SHA-256 digest.

Paths MUST be repository-relative and normalized. Collections MUST be sorted. Hashing MUST use raw bytes where content identity matters and canonical JSON for aggregate structures.

`.git/` and the configured evidence output root are excluded. No other tracked candidate path may be excluded. Ignored files are outside the candidate contract and MUST NOT be needed for correctness; required generated inputs must be represented by a declared gate artifact digest.

Working-tree mode is advisory because the tree can change concurrently. The runner MUST compute the identity before and after each gate and reviewer run. A mismatch makes the result `UNKNOWN`. CI MUST use immutable commit mode.

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

### 5.4 Reviewer result

The fresh reviewer emits only schema-valid JSON containing:

- candidate binding;
- verdict: `PASS`, `BLOCK`, or `UNKNOWN`;
- reviewed surfaces;
- findings with severity, location, claim, violated oracle, evidence and remediation;
- missing evidence;
- claim classifications: `PROVEN`, `SUPPORTED`, `UNVERIFIED`, or `UNKNOWN`;
- limitations.

The reviewer result is invalid if it does not exactly match the candidate, task contract, reviewer prompt version, and required gate manifest supplied by the runner.

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

The author runs required deterministic gates, self-reviews the diff, and starts the independent reviewer only after deterministic prerequisites pass. A candidate modification invalidates all earlier affected results.

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

## 8. Independent reviewer isolation

The strict reviewer MUST be a new process and MUST NOT use `codex exec resume` or an in-session subagent.

The launcher MUST:

- use a new `codex exec --ephemeral` invocation;
- use `--ignore-user-config` while preserving normal authentication;
- use `--ignore-rules` and explicit overrides that disable hooks and subagents for the reviewer process;
- set `--sandbox read-only`;
- select the configured GPT-5.6 model and reasoning effort;
- require `--output-schema` and a dedicated final-output path;
- start Codex in a sanitized harness Git root, with the immutable candidate checkout nested beneath it as read-only evidence, so candidate-owned `.codex` configuration, hooks, skills and execpolicy are inspectable files but not active reviewer configuration;
- expose no author chat, plan, self-review, hidden reasoning, unrelated connector, or writable credential;
- pass only a fixed reviewer prompt, normalized task contract, exact candidate identifiers, required gate manifest and raw evidence locations;
- record the exact sanitized invocation configuration and prompt digest;
- classify non-zero exit, timeout, malformed output, missing output or identity mismatch as `UNKNOWN`.

The reviewer MUST compute the diff and affected closure independently. The author MUST NOT select a restricted file list that prevents repository search.

The sanitized harness contains only the fixed protected reviewer prompt, output schema, permitted-input manifest, and nested candidate/evidence paths. It MUST NOT copy global or candidate Codex configuration into an active layer. Authentication may remain in the normal Codex home, but no authentication file or value enters the harness, prompt, result, or evidence manifest.

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

The effective gate policy MUST come from a protected source. Recommended controls:

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
- Reviewer prompts and outputs MUST NOT request or store hidden chain-of-thought.
- Authentication files, API keys and environment secrets MUST never be committed or included in evidence.
- Audit records SHOULD contain versions, hashes, times, exit states and limitations, not unnecessary source copies or personal data.
- The CLI MUST use argument arrays without a shell by default. Shell commands require explicit configuration and risk classification.
- Symlinks, path traversal, submodules, large files, invalid encodings, concurrent edits and subprocess termination MUST have explicit tests.

## 14. Acceptance rule

The system may emit `READY_FOR_HUMAN` only when every required artifact is schema-valid, complete, current, authorized and bound to one exact candidate; every mandatory deterministic gate is `PASS`; the fresh reviewer is valid and `PASS`; no unauthorized governance change exists; and no unresolved mandatory `UNKNOWN` remains.

Nothing in this specification authorizes automatic merge or deployment.
