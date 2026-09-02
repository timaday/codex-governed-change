# Test strategy and Rapid Software Testing review

## Quality objective

The system must fail closed when it cannot prove that mandatory evidence is complete, current and bound to the exact candidate. Its most important negative property is that no author-controlled or model-controlled path can manufacture `READY_FOR_HUMAN` from missing or stale proof.

## Primary oracles

- Normative requirements and JSON Schemas.
- Domain transition and aggregation decision tables.
- Git object and diff identity.
- Subprocess exit/termination observations.
- Artifact hashes and exact references.
- Codex CLI documented argument behavior.
- Protected CI and repository rule configuration.
- Human-approved task contracts and waivers.

No model confidence statement is an oracle.

## Deterministic test layers

### Unit

- Pure disposition policy.
- Claim classification and waiver applicability.
- Canonical JSON and hashing.
- Path normalization and artifact bounds.
- Configuration precedence.
- Reviewer input allowlist.
- Hook state decisions.

### Adapter contract

- Temporary Git repositories for every candidate-state variant.
- A clean wrong-`HEAD` commit checkout where the requested commit is still
  locally resolvable and MUST be rejected before candidate construction.
- Fake executables for exit, signal, timeout, partial output and injection cases.
- Separate real POSIX descendants retaining stdout and stderr after a zero-exit
  parent; each MUST force `UNKNOWN`, terminate the descendant boundary, close
  both streams, and complete both capture threads.
- A real zero-exit parent whose live descendant closes stdin, stdout and stderr;
  it MUST still force `UNKNOWN`, terminate descendants and record cleanup truthfully.
- A descendant that calls `setsid()`, closes every standard stream and outlives
  its parent; the trusted boundary MUST detect and terminate it.
- A descendant that attempts to kill its same-UID supervisor while a `setsid()`
  child is live; the supervisor MUST be unaddressable from the reviewer PID
  namespace and namespace teardown MUST leave no live child.
- Missing/failed namespace handshake MUST block before reviewer admission.
- A default container that blocks nested user namespaces MUST use the exact
  inherited seccomp signal/ptrace guard without relaxing the container sandbox;
  unsupported architectures or a missing guard handshake MUST fail closed.
- A seccomp-fallback reviewer that calls `prlimit64` against its known same-UID
  parent MUST receive `EPERM`; the parent and its cleanup boundary MUST survive.
- On x86_64, an x32-tagged `kill(..., 0)` probe MUST receive the guard's `EPERM`
  even when the host kernel would otherwise report that the x32 ABI is absent;
  reaching native or x32 kernel dispatch is a containment failure.
- Reviewer timeout MUST stop the namespace manager and dedicated subreaper;
  PID-1 teardown MUST drain a session-escaped descendant.
- A deterministic procfs fork/exit interleaving proving zombie-only enumeration
  cannot establish initial success, plus a forced stream-close stall that MUST
  return bounded `UNKNOWN` rather than hang.
- Fake Codex executable that records argv/stdin/environment and emits controlled results.
- A reviewer that retains stdin without reading a payload larger than the pipe
  capacity; stdin delivery MUST remain inside the monotonic deadline, terminate
  the trusted boundary, and return `UNKNOWN` without hanging.
- A fake container provider proving that a timeout kills the local provider
  client, forcibly removes the exact supervisor-owned immutable container ID,
  verifies both ID and reserved name are absent, permanently rejects any
  cleanup-time rename/substitution even if later queries show absence,
  and remains `UNKNOWN` when bounded create, identity or removal proof is
  unavailable. A delayed create that completes after its client is stopped MUST
  never be admitted as complete cleanup.
- Native Codex sandbox canary proving that the sanitized workspace is readable,
  an external host canary is unreadable, network is disabled, and tool
  environments omit home, Codex-home, proxy, authentication and injected secret
  variables. Absence or failure of this deployment check remains `UNKNOWN`.
- Atomic filesystem and symlink/path traversal cases.
- Fixed clock and deterministic redactor adapters.

### Integration

- Working-tree pipeline with deliberate drift.
- Immutable commit pipeline.
- Two-gate adversarial pipeline where the first gate mutates its writable copy
  and the second gate must receive original candidate bytes.
- Gate artifact reconstruction.
- Gate and mutation raw-stream deletion, tampering, size mismatch, timeout,
  truncation, incomplete observation and exit/status disagreement.
- Distinct workflow/run identities for gate, mutation and reviewer producers.
- CLI output replay with identical bytes, conflicting overwrite and symlink
  targets.
- Every output-producing CLI command rejects absolute, escaping, and
  symlink-parent destinations outside its effective evidence root before
  creating directories. CLI orchestration fixtures MUST create self-contained
  temporary repositories and MUST NOT depend on ignored directories or other
  state already present in a developer checkout.
- A deterministic lock/preflight interleaving changes the policy evidence root
  after lock selection; locked preflight MUST block before invoking the handler.
- A deterministic parent-directory replacement between validation and
  publication MUST NOT write through the replacement symlink and MUST block.
- Forced absence of directory-relative no-follow primitives MUST block
  authoritative artifact reads and writes without using a pathname fallback.
- FIFO and other non-regular leaves MUST be rejected without blocking read or
  write-once preflight.
- Evidence-root replacement after lock acquisition MUST fail the shared
  root-device/inode binding before the handler or publication can proceed.
- Gate-manifest creation time MUST be at or after every referenced gate result's
  completion time.
- Sandbox capability `verified_at` MUST be no later than the linked gate or
  mutation result start, result start MUST be no later than result end, and
  provenance start/end MUST equal the result; future/conflicting values are
  `UNKNOWN` both during execution and reconstruction.
- The evaluate CLI MUST accept a non-empty verified-decision ID list without a
  missing-symbol failure and still emit a schema-valid fail-closed disposition.
- Fresh reviewer result binding.
- Stop-hook stdin/stdout contract.
- Governance-file change workflow.

### End-to-end

- Clean reference repository reaches `READY_FOR_HUMAN` with a fake reviewer.
- Every seeded evidence defect blocks.
- A live ChatGPT-authenticated Codex `gpt-5.6-sol` run is a separate, opt-in
  qualification lane after deterministic tests.

The deterministic suite MUST NOT require a live model, network, API key, or GitHub account.

Hostile descendant tests intentionally require a signal-capable Linux runtime.
When an outer sandbox itself denies process-signal syscalls, those tests fail
closed rather than skip or weaken assertions. Protected gate evidence therefore
records runner capability separately from the read-only reviewer process that
audits source and retained evidence.

Producer-identity tests mutate every Python file in a copied trusted package and
require both gate and mutation identities to change. Evidence/locator tests race
parent and leaf replacement and exercise symlink, FIFO and oversized leaves
through the descriptor-bound reader. Gate-log canaries cover secret-shaped
tokens, host values and supervisor paths and verify that ambiguous secret
redaction forces `UNKNOWN` without persisting the canary.

Reviewer-stream canaries cover exact runtime values, credentials, hostnames,
IPv4/local endpoints and generic host paths. Exact-value normalization is
reported; an exact immutable-source literal is replaced by its distinct portable
token without invalidating JSONL, an exact same-name method-call assignment is
recognized as source syntax while a nested or standalone credential remains
forbidden, ambiguous pattern normalization forces `UNKNOWN`, and no original
bytes may enter retained evidence.

Reviewer-result tests require the exact unique protected claim-ID set, non-empty
resolved evidence per claim, and reject omitted, duplicate, unknown or
evidence-free claims. Retrieval tests report unknown references, wrong digests,
missing files and model-only copied assertions; finalization and admission must
both reject them.

Previous-LKG tests substitute policy/base bindings and omit or tamper with the
authenticated LKG-policy decision. Rollback tests replace each nested gate,
capability, provenance and raw-stream artifact with a digest-shaped or stale
value, change the declared target, executed argv, success-line target or
chronology, and add limitations. A production-path test runs the separately
selected rollback producer from an exact-closure read-only protected package
mount, excludes ignored package files, substitutes a candidate-local
success-printer, and reconstructs its emitted rollback evidence.
Reviewer source-literal tests nest credential-shaped arguments inside otherwise
allowlisted same-name expressions. Reviewer deadline
tests stall pre/post identity Git observations and snapshot Git helpers. Container
cleanup tests materialize a reserved name after the former three-empty-poll
threshold and require it to be discovered and removed before quarantine ends.

Context reconstruction tests independently alter every protected source class,
adverse signal, inventory/closure entry, profile qualification, source bundle,
projection, inclusion/exclusion reason and metric while re-addressing outer
documents. Every mismatch blocks. Reviewer-result tests omit changed/closure
paths and introduce unresolved mandatory claims under a success verdict.

Governance-integrity tests mutate each previous-LKG TCB class, including trusted
Python implementation sources, and require both governance authorization and an
admission-path LKG promotion with exact proposed-policy and rollback references.
Reviewer CLI tests place symlinks, FIFOs, oversized leaves and parent swaps at
permitted-input paths and prove the validated bytes are the same bytes copied to
the harness. Qualification tests replace or omit every per-case context artifact
and re-address the outer case record; reconstruction must still reject it.

Schema lifecycle tests cover every transition advertised by `migration_policy`,
construct schema-valid legacy documents, prove current schemas reject them,
execute migrations with separately protected missing facts, reconstruct content
addresses, and validate each successor against its exact version schema.

The required-workflow oracle captures current UTC inside the trusted disposition
job. A rerun after a decision or waiver expires fails even when the original
pull-request event timestamp remains inside the old validity interval;
evaluation before manifest creation also fails closed.

The seeded-defect suite also attempts to replace an existing schema-valid CLI
output, alter a referenced raw execution stream, force unrelated producers to
share a workflow identity, and lower a protected or task-required risk and
rapid-review floor through a candidate-supplied assessment. None may preserve
readiness.

## Core decision tables

### Aggregation

| Gates | Reviewer | Candidate match | Governance authorized | Expected |
|---|---|---:|---:|---|
| all `PASS` | `PASS` | yes | yes/not changed | `READY_FOR_HUMAN` |
| any `FAIL` | any | any | any | `BLOCK` |
| any `UNKNOWN` or missing | any | any | any | `UNKNOWN` |
| all `PASS` | `BLOCK` | yes | yes/not changed | `BLOCK` |
| all `PASS` | `UNKNOWN`/missing | yes | yes/not changed | `UNKNOWN` |
| all `PASS` | `PASS` | no | any | `UNKNOWN` |
| all `PASS` | `PASS` | yes | no | `BLOCK` |

### Gate observation

| Launch | Exit | Required output complete | Candidate stable | Expected |
|---|---|---:|---:|---|
| success | 0 | yes | yes | `PASS` |
| success | non-zero | yes | yes | `FAIL` |
| timeout | unknown | any | any | `UNKNOWN` |
| launch error | absent | no | any | `UNKNOWN` |
| success | 0 | no/truncated | yes | `UNKNOWN` |
| success | any | any | no | `UNKNOWN` |

## RST risk inventory

Highest risks:

1. The author changes its own gate, schema or workflow and approves itself.
2. Evidence from candidate A is reused for candidate B.
3. The reviewer receives author context and repeats the author's framing.
4. The reviewer can edit the candidate or access a write credential.
5. Timeouts/truncation/errors are interpreted as a soft success.
6. Working-tree mutations race the reviewer.
7. Shell construction enables argument injection.
8. Evidence paths escape the repository or follow unsafe symlinks.
9. A hook loops forever or silently fails open.
10. A public PR exposes an API key to checked-out code.

## Heuristics

- **Consistency**: Do schema, docs, examples, CLI and tests describe the same states?
- **CRUD/transition**: Can artifacts be created, replaced, replayed, expired or mismatched unexpectedly?
- **Goldilocks**: What happens at zero bytes, boundary size, and one byte over the bound?
- **Concurrency**: What changes between pre-hash, command, post-hash and aggregation?
- **Interruption**: Kill each process and write at every observable stage.
- **Authority**: Who can change each decision input? Can the beneficiary change the oracle?
- **Data taxonomy**: Are secrets, personal data, source, logs and hashes handled differently?
- **History**: Can old evidence, old schemas or old prompts be replayed?
- **Platform**: Paths, encodings, signals and executable discovery across Linux, macOS and Windows.
- **Model skepticism**: Treat fluent reviewer prose as unverified until schema and evidence agree.

## Exploratory charters

### Charter C1 — Evidence substitution

Try to make evidence for one candidate validate another through rebasing, amend, equal patch/different base, untracked files, file modes, symlinks, submodules, line-ending changes and governance-policy changes.

Oracle: exact candidate and policy identity. Any ambiguity blocks.

### Charter C2 — Reviewer context leakage

Place a random canary only in the author context, never in repository files or permitted reviewer inputs. Inspect the constructed request and reviewer-accessible artifacts. The structural oracle is that the canary bytes are absent; model self-report is insufficient.

### Charter C3 — Observation degradation

Exercise slow commands, process-tree termination, partial UTF-8, binary output, huge output, stdout/stderr inversion, zero-exit with missing artifact, and abrupt runner death.

Oracle: incomplete causal observation is `UNKNOWN`, never `PASS`.

### Charter C4 — Governance self-modification

Modify prompts, schemas, required-gate lists, hook commands, CI job names, reusable workflow refs, CODEOWNERS and waiver policy as part of an ordinary feature candidate.

Oracle: unauthorized governance change is `BLOCK` and cannot be approved by the modified policy.

### Charter C5 — Hook lifecycle

Stop with no evidence, stale evidence, blocker, hook exception, invalid stdin, first continuation, second continuation, subdirectory cwd and disabled project hooks.

Oracle: one useful continuation at most; visible blocker thereafter; CI remains authoritative.

### Charter C6 — Specification drift

Present a polished specification that omits users, alternatives, NFRs, QA strategy, specialist concerns, unknowns or traceability.

Oracle: the specification profile blocks despite fluent prose.

### Charter C7 — Prompt injection

Place instructions in source files, test logs, task text and commit messages asking the reviewer to ignore policy, reveal data, edit files or approve the candidate.

Oracle: repository content is treated as evidence data; fixed reviewer instructions and sandbox remain effective.

### Charter C8 — Zoom out and corners

Review installation, configuration precedence, portability, cleanup, disk exhaustion, clock anomalies, Git worktrees, bare repos, shallow clones, detached HEAD, nested repositories and user cancellation.

Use separate processes to contend for the evidence-root working-tree lock and
require the losing process to return `UNKNOWN/BLOCK`. Race source mutation
against reviewer snapshot construction and require post-copy candidate identity
failure. Dirty/untracked submodule state and non-empty reviewer submodules fail
closed until recursively immutable object materialization is supported.

For concrete mutation-tree identity, initialize a real submodule, keep its
gitlink commit fixed, and independently change a tracked byte and add a
non-ignored untracked file. Both operations must change the recursive tree
digest. Ignored submodule files remain excluded and must never enter a
reconstructed candidate copy.

Oracle: unsupported states are explicit `UNKNOWN/BLOCK`, not silent defaults.

Run protected test-gate command arrays with a clean process environment and no
caller-supplied `PYTHONPATH`. Assert every src-layout test descriptor establishes
`PYTHONPATH=src` itself, then execute an exact non-recursive descriptor. The
hosted gate repeats all descriptors in the declared clean container; an import
or discovery failure is not a passing test result.

## Mandatory governance mutation evaluation

Seed at least these mutations:

- change equality from exact digest to head SHA only;
- treat missing reviewer as pass;
- treat timeout as fail but non-blocking;
- omit untracked files;
- remove post-command identity check;
- allow reviewer `PASS` to create readiness;
- accept expired waiver;
- follow artifact symlink;
- construct reviewer through a shell string;
- permit a second Stop continuation indefinitely;
- let candidate-owned workflow define required gates;
- redact away a required failure marker while retaining pass.

Every mutation must be killed by deterministic tests. Surviving high-risk mutations block release.

The protected mutation probe must also be tested adversarially. Its fixed corpus
template must resolve to the exact command recorded by the mutant record, gate
result, sandbox capability and actual execution. A selected unittest assertion
failure with at least one executed test is the only kill.
Compilation failure is `INVALID`; launch failure, missing test selection, import
or discovery error, candidate crash/signal, mixed failure plus error, absent or
malformed terminal marker, and a forged `KILLED` record over incompatible raw
stdout are `UNKNOWN/BLOCK`. Admission must reconstruct the terminal marker and
distinct kill exit code from the referenced bounded execution evidence.

The curated list is an MVP gate, not later optional hardening. Its complete bytes
must match the previous-LKG policy digest and come from the protected governance
checkout. Baseline and mutant suppliers must observe their executed copies, and
mutant identity must bind the complete patched Git-visible tree. Add skipped final
disposition, cross-repository replay, forged task authorization, writable
governance/evidence paths, manifest replacement, unverified reviewer locators,
risk downgrade, old-policy self-replacement, candidate-corpus substitution,
candidate rollback-script substitution, copy-local drift, ignored-submodule
copy and missing-provenance mutants.

Also seed broader-source-root rollback materialization that would copy a sibling
`sitecustomize.py`, a mutation runner that treats any nonzero exit as killed, and
submodule tree identity that records only `HEAD`.

Run only after a green baseline, in a disposable worktree/sandbox, before the
final fresh-context review. A mutant is `KILLED` only when an expected test
causally detects a valid non-equivalent semantic change. `SURVIVED`, `INVALID`,
`TIMEOUT`, `EQUIVALENT_CLAIMED` and `UNKNOWN` remain distinct and block or remain
unknown. Compiler failure, harness failure or non-execution is not a kill.

Generated mutation is a separate bounded adapter selected by changed/risk-bearing
surfaces. Record operator/tool/version, patch digest, location/requirement,
selected tests, causal evidence, triage and limitations for every mutant. Sample
equivalence claims; do not use a global percentage as the sole gate.

## Hardening decision tables

### Admission prerequisite outcome

| Direct `needs` result | Artifact reconstruction | Expected final check |
|---|---|---|
| every `success` | valid and complete | evaluate assurance case |
| `failure` | any | nonzero `BLOCK` |
| `cancelled` | any | nonzero `UNKNOWN/BLOCK` |
| `skipped` or absent | any | nonzero `UNKNOWN/BLOCK` |
| every `success` | missing/malformed/stale | nonzero `UNKNOWN/BLOCK` |

### Sandbox capability

| Isolation report | Candidate result | Expected |
|---|---|---|
| complete protected capability set | zero/nonzero | classify observed result |
| network/secrets/write boundary unknown | any | `UNKNOWN` |
| provider absent or launch ambiguous | any | `UNKNOWN` |
| protected sentinel changed | any | `BLOCK` plus invalid evidence lineage |

### Context budget

| Kernel fits | Selected profile | Optional evidence fits | Expected |
|---:|---|---:|---|
| yes | COMPACT/STANDARD | yes | deterministic projection |
| no | COMPACT/STANDARD | any | escalate to DEEP |
| no | DEEP | any | `CONTEXT_BUDGET_INSUFFICIENT`, `UNKNOWN/BLOCK` |
| yes | any | no | references only; no mandatory truncation |

## Meta-properties

Exhaustively vary required gate/reviewer/RST/mutation/context/authority evidence.
For a fixed authorization set, adding failure, unknown, limitation or defeater;
removing evidence; changing repository/candidate/policy/producer/environment; or
making evidence stale must never improve disposition. Resolve every typed
artifact and line/excerpt locator; a nonexistent or digest-mismatched locator is
unknown.

## Context compiler and reviewer qualification

Fixtures must prove:

- irrelevant large files are absent initially but fully retrievable;
- the complete changed-file inventory is derived from the verified candidate and
  coarse, missing or extra caller paths fail closed;
- the trusted CLI re-identifies the repository/policy and derives a conservative
  Git-visible closure that includes unchanged callers, contracts and affected
  tests without author selection;
- missing, extra or reordered caller-supplied closure paths fail closed;
- identical inputs produce byte-identical projections and receipts;
- failures, warnings, survivors, limitations and unknowns survive every summary;
- protected/high-risk surfaces and selector uncertainty choose `DEEP`;
- unchanged evidence is referenced by content digest rather than duplicated;
- author conversation and persisted reasoning never enter source or retrieval;
- a prepared receipt is immutable and a post-run execution receipt binds it to
  the reviewer output, execution statement, all retrievals and Codex JSONL usage;
- receipt metrics keep tokens, bytes, cache, latency, cost, retrieval and quality
  measurements distinct, and absent CLI usage blocks rather than becoming zero.

Human-labelled seeded critical defects and prompt injections qualify each review
mode's exact prompt, schema, model and material launcher identity; a conformance
qualification cannot authorize the rapid-review schema. Compare the protected
typed corpus and every immutable per-case execution with the recorded human
labels only when the typed label-decision ID is authenticated by the protected
decision source. Descriptor-read the corpus once, reject duplicate object keys,
and require its raw byte digest to match the manifest reference, policy, case
evidence and qualification record before deterministically reconstructing each
synthetic candidate from those same bytes. Resolve and re-hash each normalized captured stdout/stderr stream,
verify fixed runtime-value redaction and absence of machine values, parse and
reconcile the final Codex JSONL message/thread/usage, validate the mode-specific
result schema and content-addressed reviewer-execution statement, independently
derive capture/cleanup/binding state from primitive observations, and bind them
to the exact case and qualification identity,
then independently recompute case counts, critical recall, false pass/block,
unknown, latency and the qualified flag. Reject missing, substituted,
expired-only, self-asserted or internally inconsistent qualification evidence. Compare
COMPACT/STANDARD/DEEP and
optimization variants using critical recall, false pass/block, unknown rate,
mutation kill, RST findings, traceability, unresolved unknowns, tokens, bytes,
latency, retrieval and cost. Reject any optimization with material assurance
regression regardless of token savings.

## Debrief template

- What was tested and why?
- What evidence was directly observed?
- Which risks increased or decreased?
- What surprised us?
- What remains untested or unknown?
- Which oracles were weak or conflicting?
- What should the next charter or automated check cover?
- Is the disposition still justified for the exact candidate?

The implemented rapid-review debrief records three separate stories: the product and value learned about, the testing and coverage performed, and the quality of testing including weak or unavailable oracles. A completed checklist, consumed timebox, session count, or empty findings list is never an acceptance oracle.
