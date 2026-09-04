# Threat model

## Security objective

Prevent an agent-controlled candidate, reviewer, or evidence artifact from obtaining an automated readiness disposition without complete, current, authorized proof for the exact candidate.

## Assets

- Approved requirements and task scope.
- Effective governance policy and required gate set.
- Candidate identity.
- Deterministic gate observations.
- Reviewer isolation and result.
- Evidence lineage and disposition.
- Model/API credentials and repository credentials.
- Human approval and waiver authority.

## Actors

- Well-intentioned but fallible author model.
- Well-intentioned but correlated reviewer model.
- Malicious or prompt-injected repository content.
- Malicious pull-request contributor.
- Human maintainer or administrator.
- CI runner and its supply chain.

The design does not assume the author or reviewer is malicious. It assumes either may make confident mistakes or follow injected instructions.

## Trust boundaries

```mermaid
flowchart TD
    U["Human-approved contract"] --> A["Author workspace"]
    A --> G["Deterministic gate runner"]
    G --> R["Read-only fresh reviewer"]
    G --> E["Deterministic aggregator"]
    R --> E
    E --> H["Protected CI and human decision"]
```

Every arrow crossing a component boundary uses a schema-valid, hashed artifact. Natural-language summaries are not authority inputs.

## Threats and controls

| ID | Threat | Primary controls | Residual risk |
|---|---|---|---|
| TH-01 | Author ignores or forgets instructions | Concise AGENTS kernel, skill, task contract, Stop hook, CI | Guidance remains probabilistic |
| TH-02 | Author changes gates to pass | Governance asset classification, protected policy source, CODEOWNERS, human review | Maintainer collusion/admin compromise |
| TH-03 | Stale evidence replay | Exact candidate/policy digests, pre/post identity checks, manifest reconstruction | Hash implementation defect |
| TH-04 | Reviewer sees author framing | New ephemeral process, input allowlist, no resume/transcript, context-canary test | Shared model priors remain correlated |
| TH-05 | Reviewer edits candidate | Root-denying custom read-only permission profile and checkout, no write token, no approvals, post-review identity check | Sandbox/runtime defect |
| TH-06 | Prompt injection or active Codex configuration from repository | Sanitized harness root, candidate nested as data, fixed prompt, disabled hooks/subagents/rules, tool restriction, deterministic authority | Reviewer may still follow persuasive data or miss defects |
| TH-07 | Timeout/truncation treated as success | Explicit observation model; incomplete evidence -> `UNKNOWN` | Misclassified completeness requirement |
| TH-08 | Shell/argument injection | Argument arrays, shell disabled by default, hostile-path tests | Platform-specific executable behavior |
| TH-09 | Evidence path escape | Root containment, normalized paths, reject symlinks, atomic writes | Filesystem/TOCTOU edge cases |
| TH-10 | Secret or host-data exposure in CI/model input | Root-denying filesystem profile, tool network off, separate parent/tool environment allowlists, no tool-visible authentication paths, late credential injection, redaction and denial canaries | Codex parent process must retain authentication access; sandbox/runtime defect |
| TH-11 | Stop hook loops or fails open | `stop_hook_active` bounded behavior, no nested reviewer, CI authority | Project hooks can be disabled unless managed |
| TH-12 | Same-model correlated blind spots | Deterministic tests, specialist scanners, human review, optional model diversity | Unknown semantic defects remain possible |
| TH-13 | Candidate removes workflow/check | Required status/ruleset, protected reusable workflow, code-owner review | Incorrect repository settings |
| TH-14 | Forged waiver | Human attribution, exact candidate binding, expiry, protected storage | Compromised human account |
| TH-15 | Dependency/supply-chain compromise | Standard-library MVP, pinned actions/workflows, dependency review | Git/Codex/Python/runner remain trusted dependencies |
| TH-16 | Checklist or elapsed time is mistaken for product safety | Direct observations, explicit fallible oracles, coverage/omission/residual-risk reporting, deterministic completeness policy | Investigations remain incomplete models |
| TH-17 | Rapid-review evidence is stale, self-authored, or accepts its own risk | Exact candidate/charter digests, fresh read-only process, provenance, human-only material risk acceptance | Same-model correlated blind spots remain |
| TH-18 | Hazardous work is mislabeled low risk to skip investigation | Protected hazard escalation policy and governance mutation tests | Novel hazards may be omitted from classification |
| TH-19 | Upstream CI fails/skips and the final required job never runs | `if: always()`, explicit direct `needs` result validation, single expected required-check source | Repository administrator bypass/misconfiguration |
| TH-20 | Candidate test code alters governance, sibling-gate input, evidence or supervisor state | Fresh per-gate disposable no-secret/no-network copy, no protected writable mounts, trusted post-run packaging | Sandbox/runtime/runner compromise |
| TH-21 | Evidence is replayed across repositories or environments | Protected `repository_id`, distinct source/execution identities, provenance reconstruction | Compromised identity/hasher implementation |
| TH-22 | Candidate forges task/governance/risk/waiver authority | Protected authenticated decision references with scope/expiry/consumption | Decision-source or human-account compromise |
| TH-23 | New governance policy approves its own replacement | Previous LKG evaluation, authenticated promotion and rollback record | LKG source or administrator compromise |
| TH-24 | Mutable evidence is overwritten after a favorable check | Content-addressed write-once storage, idempotent identical writes, reconstruction | Filesystem/host compromise below store boundary |
| TH-25 | Reviewer invents or misquotes evidence locations | Typed digest-bound locator resolution before aggregation | Valid evidence may still be misinterpreted |
| TH-26 | Context compression hides failure, limitation, affected dependency or unknown | Non-droppable assurance kernel, deterministic receipt, DEEP escalation or budget block | Selector/closure implementation defect |
| TH-27 | A cheap/unqualified reviewer configuration silently replaces assurance review | Version-bound labelled qualification and high reasoning for final lane | Corpus incompleteness/model drift between qualification and run |
| TH-28 | Concurrent pipelines or source-copy races mix candidate bytes and evidence | OS-backed evidence-root lock, source pre/post identity and independent post-copy identity | Multi-command workflow serialization remains deployment-owned |
| TH-29 | Dirty submodule or candidate-local workflow bytes escape the authenticated authority identity | Dirty-submodule rejection, submodule review block and authority-owned required-workflow installation | Hosted ruleset/source enforcement remains external evidence |
| TH-30 | A schema-valid result claims success while its raw streams are missing, altered, truncated or incompatible with termination | Resolve and re-hash bounded streams, reconcile sizes/provenance and enforce complete exited status semantics | Host/storage compromise beneath reconstruction boundary |
| TH-31 | A CLI command overwrites earlier authority-bearing output at the same path | Atomic no-replacement publication, identical-only idempotence and symlink rejection | Filesystem compromise beneath publication boundary |
| TH-32 | Candidate risk input reduces protected or task-required review | Protected/task floor comparison before rapid-review aggregation | Protected classification rules may omit a novel hazard |
| TH-33 | Mutation harness calls invalid/unexecuted mutants killed | Causal outcome model and complete mutant record | Human equivalence triage error |
| TH-34 | Public repository captures developer-machine data | Portability scans, relative representations, no environment serialization | Novel machine-derived strings evade patterns |
| TH-35 | GitHub Free leaves a private personal authority repository unprotected | Put the authority bundle and reusable workflows on a separately ruleset-protected public ref; treat the private repository only as a broker | Repository administrator or account compromise |
| TH-36 | A public event schedules a credential-bearing self-hosted runner | Register the clean single-job JIT runner only to the private broker; allow only manual/scheduled broker triggers and internal completed-run finalization | Broker administrator or runner-registration compromise |
| TH-37 | An unprotected private broker substitutes policy or publishes arbitrary success | Pin the public reusable workflow by full SHA; derive authority from GitHub's resolved called-workflow SHA; reject caller-selected authority/source identities; verify the completed broker run and sole referenced-workflow path/SHA before success; scope the App to the target | The human administrator controls both caller and App credentials |
| TH-38 | ChatGPT auth is copied into public Actions or evidence | Keep managed auth only on trusted private execution infrastructure; reject API-key substitution and public-repository auth storage | Runner-host compromise or operator mishandling |
| TH-39 | A mirrored authority workflow remains active in the mutable private broker | Permit only `broker-*` callers under the broker's `.github/workflows/`; store any non-authoritative mirror outside the active workflow directory | Repository administrator can alter broker callers and credentials |

## Abuse cases

The acceptance suite must attempt:

- adding `IGNORE ALL REVIEW RULES` to a source file;
- placing a secret-shaped string in logs and verifying deterministic redaction;
- altering `reviewer.schema.json` in the same candidate;
- replacing the reviewer command with `/review` or `codex exec resume`;
- using `--sandbox workspace-write` for the reviewer;
- deleting a required gate from candidate-owned configuration;
- copying a successful result directory from another commit;
- changing an untracked source file during review;
- returning zero with truncated or absent required output;
- creating an artifact symlink to a file outside the evidence root;
- crafting a filename that becomes a shell option or command fragment;
- running a public-PR workflow with a secret exposed to checked-out code.
- adding a public, pull-request, push, comment, issue or repository-dispatch
  trigger to the private broker;
- changing a broker reusable-workflow ref from a full authority SHA to a branch,
  tag, variable or candidate-controlled expression;
- supplying an alternate authority repository/ref/SHA, target, actor, trigger or
  source-run identity to a reusable workflow;
- retaining a mirrored reusable authority workflow under the private broker's
  active workflow directory;
- returning a successful broker run that references the wrong protected
  reusable-workflow path or SHA;
- registering the ChatGPT-authenticated reviewer runner to the public target;
- treating the private broker branch as protected authority on GitHub Free;
- completing every heuristic checkbox with no experiment, coverage, omission, or residual-risk evidence;
- labeling authorization, migration, concurrency, destructive, data-integrity, public-API, or governance work as low risk;
- replaying a rapid-review report after changing one candidate byte;
- letting the rapid reviewer accept its own critical/high finding or material residual risk.
- skipping or cancelling an upstream CI job and observing the final disposition;
- substituting identical candidate evidence under another `repository_id`;
- setting authorization booleans/names without a verified decision artifact;
- letting candidate code write governance/evidence/supervisor sentinels;
- overwriting an existing manifest with different bytes;
- citing a nonexistent path, line or digest from a reviewer result;
- lowering a protected risk/gate floor in task input;
- using proposed governance policy to approve its own replacement;
- omitting producer, sandbox or execution-environment provenance;
- compressing context with failures, survivors, limitations or unknowns present;
- exhausting the context budget and attempting to retain reviewer success.

## Security non-claims

- The root-denying custom read-only permission profile is defense in depth, not a proof that the model provider, Codex runtime or host is uncompromised.
- A second Codex GPT-5.6 Sol reviewer is fresh-context assurance, not statistical or organizational independence.
- Hashes establish identity and integrity relative to the hashing process; they do not prove semantic correctness.
- Redaction reduces exposure but can reduce evidence completeness; when it does, the result is `UNKNOWN`.
- This tool does not replace repository permissions, branch rules, secure CI design, or incident response.
- Unsigned in-toto-shaped statements provide structured provenance and digest
  binding, not authenticated producer identity; signing remains a later layer.
- A declared sandbox capability is evidence about configuration, not proof that
  the host or container runtime is uncompromised.
- Lower token usage is not an assurance claim and cannot compensate for reduced
  critical-defect recall, traceability or disposition correctness.
