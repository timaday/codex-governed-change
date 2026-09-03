# Implementation status

Status date: 2026-09-03

## Current disposition

`IMPLEMENTED_CANDIDATE / FINAL_QUALIFICATION_UNKNOWN / RELEASE_BLOCKED`

T01–T23 implementation surfaces are present and the complete local deterministic
suite is green. T24 remains incomplete because no protected real-container
evidence chain, human-labelled live reviewer qualification, exact-candidate live
review, hosted CI reconstruction or human disposition exists. This is not a
release or enforcement claim.

| Claim | Classification | Evidence |
|---|---|---|
| The blueprint files are structurally complete | `VERIFIED_WITHIN_SCOPE` | Local blueprint validator passed; immutable public-commit CI remains pending |
| The normative JSON examples match the protected schema subset | `VERIFIED_WITHIN_SCOPE` | Thirty-five mapped schema/example pairs pass syntax, semantic lifecycle and content-address checks |
| The governed-change skill has valid frontmatter and metadata | `VERIFIED_WITHIN_SCOPE` | The skill-creator structural validator passed locally |
| The skill and strict-review workflow work in a fresh live Codex GPT-5.6 Sol run | `UNKNOWN` | Fake-process isolation is verified and an isolated ChatGPT-authenticated `gpt-5.6-sol` access probe succeeded; exact-candidate corpus qualification and strict review remain pending, so no qualifying review result exists yet |
| The standalone governance CLI works | `VERIFIED_WITHIN_SCOPE` | Scope, identity, gates, mutation, context, manifest assembly, review, import, evaluation, status, verification and hook boundaries are implemented and locally tested |
| Fresh-context reviewer isolation is enforced | `VERIFIED_WITHIN_SCOPE` | Fake-process tests plus native and ChatGPT-authenticated Codex canaries prove the root-denying custom read-only profile, sanitized tool environment, disabled tool network, sanitized snapshot, digest-matched evidence, schema binding and fail-closed timeout/malformed/drift behavior; on the tested Linux runtime a fresh user/PID/mount namespace keeps trusted parents outside reviewer visibility, retained-stream/session-escaped descendants and supervisor-assassination attempts force `UNKNOWN`, and PID-1 plus outer-subreaper cleanup is bounded |
| Stop-hook enforcement works | `VERIFIED_WITHIN_SCOPE` | Pure hook lifecycle tests pass and the wrapper recomputes the live candidate or fails closed |
| CI can make a release decision | `UNKNOWN` | The always-running prerequisite matrix and reference workflow invariants are tested; no hosted protected deployment was run |
| A declared container produced admission evidence | `UNKNOWN` | Sandbox command/capability and no-host-fallback tests pass, but no protected Docker/Podman evidence chain was executed for this candidate |
| The system is ready for production adoption | `BLOCK` | Mandatory T24 external and human evidence is absent |

## Status vocabulary

- `DIRECTLY_OBSERVED`: directly reproduced within the stated evidence boundary.
- `VERIFIED_WITHIN_SCOPE`: a fixed deterministic rule validated the bounded claim.
- `UNVERIFIED`: plausible or specified, but not independently demonstrated.
- `UNKNOWN`: missing, stale, conflicting, timed-out, truncated, malformed, or unavailable evidence.
- `BLOCK`: a disposition. Required evidence is not sufficient to proceed.

`UNVERIFIED` does not satisfy mandatory executable gates. `UNKNOWN` always blocks.

## Promotion conditions

Do not change the disposition to `READY_FOR_HUMAN` until all of the following are true for the same immutable candidate:

1. Every requirement in `docs/requirements.md` is implemented or explicitly deferred outside MVP.
2. `scripts/validate_blueprint.py` passes.
3. Every acceptance test passes without skips, expected failures, retries that hide failure, or reduced assertions.
4. Deterministic unit, integration, security and adversarial gates pass.
5. A qualified fresh-context read-only reviewer returns schema-valid
   `NO_BLOCKING_FINDING_OBSERVED` for the same repository/candidate/context.
6. The protected admission kernel reconstructs the assurance case and returns
   `READY_FOR_HUMAN`.
7. A human reviews the change and any explicit waivers.

No model may edit this file to claim readiness from its own assessment alone.

## Recorded baselines

The local design qualification on 2026-08-26 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 30 requirement mappings, seven schemas, seven examples, links, syntax, traceability and anti-skip checks.
- `PYTHONPATH=src python3 -m unittest discover -s tests/acceptance -v`: 37 test methods discovered; three blueprint-contract tests passed and the implementation surfaces remained red with 44 error events rooted in explicit `NotImplementedError` task boundaries T01, T03, T05, T06, T07, T08 and T09.

These observations are historical working-copy evidence, not immutable release evidence.

The architecture-hardening checkpoint on 2026-08-26 then observed:

- `python3 scripts/validate_blueprint.py`: exit zero for 66 requirement
  mappings and 26 schema/example pairs.
- `PYTHONPATH=src python3 -m unittest discover -s tests/acceptance -v`: 98
  tests discovered; 44 passed, four assertions failed on the intentionally stale
  CI reference/portability checkpoint, and 50 implementation errors identified
  missing admission, authority, assurance, attestation, sandbox, mutation, RST,
  qualification, schema-lifecycle and context-compiler behavior.

The portability assertion was corrected to accept an explicitly empty dependency
list while still rejecting any runtime dependency. All earlier executable results
are invalidated by subsequent candidate changes and must be rerun.

The successor working-copy checkpoint on 2026-09-02 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs.
- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 235 tests passed
  (168 acceptance and 67 unit tests);
  no skips or expected failures were reported.
- `PYTHONPATH=src python3 scripts/run_mutation_corpus.py`: baseline `PASS` and
  all 23 curated mutants `KILLED` for corpus
  `sha256:ea59494b38c57876fd2b4b828c740f24ac1c25c28667ceebcf313abacb35a515`.
  The runner labels this local proof as
  non-admission evidence.

A fresh read-only Codex audit of an earlier working-copy candidate returned a
schema-valid blocking assessment, but its retained stream was truncated and its
usage evidence unavailable. The attempt is therefore `UNKNOWN`, not qualifying
review evidence. Its nine reported risks were nevertheless treated as findings
and remediated in the current successor candidate. A new exact-candidate review
is required.

A later fresh read-only audit of immutable commit `13197d0` reported five
additional blocking implementation findings: incomplete previous-LKG TCB
classification, missing admission-path LKG promotion, reviewer CLI pathname
reopens, self-reported qualification context digests, and a second externally
visible readiness producer. Its process evidence was `UNKNOWN` because usage and
capture completion were unavailable, but the concrete findings were retained and
remediated with adversarial tests in the current successor candidate. That audit
is stale after these changes; another exact-candidate review is required.
The audit also exposed JSONL escape corruption when a retained command output
contained a host-path-shaped literal from the source under review. The trusted
normalizer now re-serializes parsed JSONL and replaces only exact literals proven
to occur in the immutable candidate or protected inputs with a distinct portable
source token; unproven shaped output still redacts and forces `UNKNOWN`.

A subsequent fresh read-only audit of immutable commit `db46cc4` reported six
blocking implementation findings: rollback promotion trusted nested proof
summaries; previous-LKG policy identity was self-selected; reviewer claims had
no protected exact set; retrieval expansion was model-self-reported; repository
observation and snapshot Git work were outside the reviewer deadline; and an
unresolved container create could outlive three empty cleanup polls. The audit's
formal process disposition was `UNKNOWN` because one immutable Python source
expression matched the credential-shape filter. All six findings now have
contract-first remediations and adversarial tests in this working-copy successor.
Exact same-name method-call source syntax is distinguished from credential
values without permitting nested or standalone credentials. The `db46cc4`
review and the 235-test checkpoint are stale after these changes; deterministic
gates, mutation and a new exact-candidate fresh review must be rerun.

A further fresh read-only audit of immutable commit `d5075db` was bound to the
correct candidate, but its formal process disposition was `UNKNOWN` because the
normalized retained stream still contained an ambiguous machine- or
credential-shaped value. Its five concrete findings were retained: a nested
credential could enter the source-expression exception; rollback success was
not bound to the executed argv and stdout target; the protected producer had no
production rollback-evidence path; three breaking public representations still
used version `1.0.0`; and the local review task understated affected surfaces.
The current successor narrows the source-expression grammar, binds rollback
policy/command/output to the authenticated base, produces separate typed
rollback evidence, versions and migrates the three representations, and expands
the exact local review scope. The `d5075db` audit and every earlier deterministic
result are stale for this successor; exact-candidate gates, curated mutation and
a new fresh review remain required.

A subsequent fresh read-only audit of immutable commit `c55cee2` was bound to
the exact candidate and declared `BLOCK`, but its formal process evidence was
`UNKNOWN` because process observation and stream capture were incomplete. Its
six concrete findings were retained: ordinary gates observed the untouched
repository instead of the executed copy; mutation probes did the same and did
not bind a concrete mutated tree; a re-addressed candidate corpus could replace
the curated corpus; rollback executed candidate-relative code outside the
producer closure; the lifecycle policy advertised migrations with no executable
implementation; and submodule copying could include ignored machine-local
files. This successor observes each exact gate/baseline/mutant copy, binds the
complete Git-visible mutant tree, policy-digests and evidence-copies the corpus
from the protected governance checkout, imports rollback from an exact-closure
read-only producer-digested package mount, implements and schema-tests every
advertised migration, and reconstructs submodules at their bound commits. Seven corresponding
curated mutants enforce those closures. The `c55cee2` audit is stale after these
changes and cannot qualify this successor.

The immutable `f7037ae` successor checkpoint on 2026-09-02 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs.
- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 243 tests passed;
  no skips or expected failures were reported.
- `PYTHONPATH=src python3 scripts/run_mutation_corpus.py`: baseline `PASS` and
  all 33 curated mutants `KILLED` for corpus
  `sha256:d0395bf74f016b84fe3287663f1572342755ce2195c6a6cf94a63f29044ed97b`.
  The runner labels this local proof as non-admission evidence.
- `PYTHONPATH=src python3 scripts/rehearse_rollback.py 5393338571f8ed5de5192613dcdd6131044932dc`:
  `PASS`.

These observations were local post-commit proof, not protected T24 evidence, and
the audit below prevents them from qualifying the release.

The fresh read-only Codex audit of immutable commit `f7037ae` was bound to the
correct candidate and declared `BLOCK`, but its formal process evidence was
`UNKNOWN` because the retained stream contained an ambiguous machine- or
credential-shaped value and process/capture completion could not be established.
Its three concrete findings were retained: the rollback materializer received
the broader `src/` tree while producer identity covered only the package;
mutation admission counted arbitrary nonzero exits, including launch and harness
failures, as kills; and concrete mutation-tree identity recorded only submodule
`HEAD`, not dirty Git-visible submodule bytes.

The current working-copy successor materializes and verifies only exact producer
manifest paths beneath the package import root, launches rollback through an
isolated no-site interpreter, requires a terminal structured unittest probe plus
a distinct causal-kill exit reconstructed from raw evidence, and recursively
binds tracked and non-ignored untracked submodule bytes. Three new curated mutants
cover these repairs, and six older corpus selections were narrowed or given
explicit assertion oracles so harness errors remain `UNKNOWN` rather than being
mislabelled. Every result for `f7037ae` is stale for this successor; complete
deterministic gates, the expanded curated corpus, rollback rehearsal, portability
checks and a new exact-candidate fresh review must be rerun.

The subsequent fresh read-only audit of immutable commit `dfd55cb` completed its
bounded process observation but was formally `UNKNOWN`: the local review output
schema still constrained the result to the preceding candidate ID, so the model's
otherwise schema-valid `BLOCK` result could not bind this candidate. Its four
concrete findings are nevertheless retained. The reference split-checkout review
arguments resolved candidate and authority inputs beneath the wrong roots and
omitted the policy's non-default output bound; the mutation record named the
unexecuted corpus unittest selection rather than its actual protected probe argv;
and qualification admission hashed a canonical corpus reserialization instead
of the single-read retained bytes. The current working-copy successor defines
separate candidate/authority review roots and policy-derived limits, binds the
expanded protected mutation-probe argv everywhere, and requires raw corpus-byte
digest equality plus duplicate-key rejection. All `dfd55cb` evidence is stale
after these changes and cannot qualify this successor.

The resulting working-copy checkpoint on 2026-09-02 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 250 tests passed
  with no skips or expected failures, including the public-portability checks;
- `PYTHONPATH=src python3 scripts/run_mutation_corpus.py`: baseline `PASS` and
  all 36 curated mutants `KILLED` for corpus
  `sha256:135f386af061062fcb6ec2eb3c6c5b553361326302b741ecc75df663a92a4b95`;
- `PYTHONPATH=src python3 scripts/rehearse_rollback.py 5393338571f8ed5de5192613dcdd6131044932dc`:
  `PASS`.

These are local deterministic observations, not protected T24 admission
evidence. This status update changes the candidate, so the final immutable
successor still requires rebinding gates and a new exact-candidate review.

The fresh read-only audit of immutable commit `fdf0f58` was exactly candidate
bound and produced an otherwise schema-valid `BLOCK` result, but its formal
process disposition was `UNKNOWN`: an invented machine-shaped tool argument was
redacted, so process/capture completeness could not be established. Its one
concrete finding is retained. Three protected src-layout test commands in the
public effective policy omitted `PYTHONPATH=src`; the reviewer reproduced the
exact unit command in a clean environment and all discovered modules failed to
import `codex_governance`. The current working-copy successor requires
self-contained protected gate argv and repository-relative reviewer tool
arguments. Every `fdf0f58` result is stale after this repair begins.

The working-copy remediation checkpoint on 2026-09-02 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 252 tests passed,
  including an exact protected unit-gate argv in a clean environment with no
  caller-supplied Python import path;
- `PYTHONPATH=src python3 scripts/run_mutation_corpus.py`: baseline `PASS` and
  all 36 curated mutants `KILLED` for corpus
  `sha256:135f386af061062fcb6ec2eb3c6c5b553361326302b741ecc75df663a92a4b95`;
- `PYTHONPATH=src python3 scripts/rehearse_rollback.py 5393338571f8ed5de5192613dcdd6131044932dc`:
  `PASS`.

These are local deterministic observations, not protected T24 admission
evidence. This status mutation requires one final gate rebind before the
successor is committed and independently reviewed.

The fresh read-only audit of immutable commit `16d1df4` was bound to the exact
candidate and declared `BLOCK`, but its formal process disposition was
`UNKNOWN`: an ambiguous shaped stream value was redacted and capture-thread
completion was not established. Its two concrete findings are retained. Raw
reviewer stderr incorrectly received the parsed command-event source-literal
allowlist, and conformance qualification accepted model output without
reconstructing its gate/context bindings, exact closure, required surfaces,
mandatory claims or evidence references. The current working-copy successor
confines the source-literal exception to successfully parsed command events and
reconstructs deterministic qualification gate manifests plus corpus-file
locators before validating those output semantics. Two new curated mutants
cover the reported bypasses. Every result for `16d1df4`, including its otherwise
valid model findings, is stale after these changes; all deterministic gates,
mutation, rollback, portability and a new exact-candidate review must be rerun.

The reviewer sandbox deliberately denies cross-process signalling. When a test
runner is itself nested inside that sandbox, descendant-cleanup tests that need
to signal their fixtures fail closed because the outer boundary removes that
capability; they are never skipped or converted to success. Protected
deterministic qualification must run those tests in its declared signal-capable
runner before the separate read-only model lane begins.

The fresh read-only audit of immutable commit `7d6b4d3` was candidate-bound and
emitted a `BLOCK` payload, but its formal process disposition was `UNKNOWN`:
reviewer-initiated test execution exposed a machine-shaped temporary path that
required ambiguous redaction, so capture completeness was not established. Its
six concrete source findings are retained. Mutation evidence confused the
original repository candidate with the distinct mutated execution subject;
critical qualification recall counted any blocking disposition rather than the
human-labelled defect; the seccomp fallback allowed asynchronous `fcntl`
configuration capable of signalling the supervisor; gate provenance did not
require the exact protected prompt and ordered material set; an artifact leaf
was not re-stated after descriptor read; and authenticated decisions remained
valid at their nominal expiration instant. Every `7d6b4d3` result is stale for
the current successor.

The remediation working-copy checkpoint on 2026-09-02 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- `PYTHONPATH=src python3 -m unittest discover -s tests -v`: 260 tests passed
  with no skips or expected failures, including focused regressions for all six
  retained findings and the public-portability checks;
- `PYTHONPATH=src python3 scripts/run_mutation_corpus.py`: baseline `PASS` and
  all 44 curated mutants `KILLED` for corpus
  `sha256:9c2fc3a47064da3d7618f861b1c791a6e68272f12fed4742e20f7ecdf69c709e`;
- `PYTHONPATH=src python3 scripts/rehearse_rollback.py 5393338571f8ed5de5192613dcdd6131044932dc`:
  `PASS`;
- `git diff --check` and the focused public-portability suite: `PASS`.

These are local deterministic observations, not protected T24 admission
evidence. This status mutation changes the candidate, so the final immutable
successor requires a complete gate rebind and a new exact-candidate fresh
review.

The fresh read-only audit of immutable commit `6655ed6` declared `BLOCK`, but
its formal result was `UNKNOWN` and is not admissible: the ignored local output
schema still constrained the result to the preceding candidate, and source-test
canaries appeared in the reviewer's captured stream and required ambiguous
redaction. Four concrete findings are nevertheless retained. Rapid-review
qualification matched only requirement/file evidence rather than the protected
defect ID and exact line; reviewer output was reopened and canonically
reserialized after validation rather than retaining one exact descriptor-read
representation; the seccomp fallback denied every `F_SETFL`, including benign
`O_NONBLOCK`; and gate normalization omitted short exact host values plus
address-shaped endpoints. Every result for `6655ed6` is stale for this
successor.

The current working-copy remediation makes rapid-review defect ID/path/line
matching exact, versions the typed rapid-review finding representation with an
explicit migration, retains the reviewer output parent descriptor and one raw
output representation through validation/hash/publication, limits `F_SETFL`
denial to flags containing `O_ASYNC`, and fails closed after replacing short
host values or address-shaped gate output. Seven new semantic mutants cover
those boundaries. Before this status mutation, the working-copy checkpoint on
2026-09-02 observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- the exact acceptance suite: 191 tests passed;
- the unit suite: 76 tests passed;
- `PYTHONPATH=src python3 scripts/run_mutation_corpus.py --timeout 180`:
  baseline `PASS` and all 51 curated mutants `KILLED` for corpus
  `sha256:562ddc6705fde76368283de901ea7d1d78935c96c1737a147e65294eb4ff1fc4`;
- `git diff --check`: `PASS`.

These are local deterministic observations, not protected T24 admission
evidence. This status mutation invalidates the checkpoint and requires the
complete gates, rollback rehearsal, portability checks and exact-candidate
fresh review to be rebound to the immutable successor.

The fresh read-only audit of immutable commit `bfe44b9` declared `BLOCK` but is
formally `UNKNOWN` and cannot qualify the release. Its stdout and stderr readers
did reach EOF, but shaped values inside three transient command-output events
required ambiguous redaction under the preceding stream contract. Five concrete
findings were independently reproduced in source and retained: exact host-value
gate replacement did not force `UNKNOWN`; reviewer pre/post identity observed
only the source repository rather than the copied snapshot; assurance admission
allowed an incomplete or substituted claim/rule set; `status` could echo a
caller-supplied schema-valid readiness state and return success; and reviewer
findings did not bind their path and line to a matching repository locator.

The current working-copy successor makes every exact host-value gate replacement
ambiguous, projects parsed command-execution command and aggregated-output
payloads to fixed omission tokens, reidentifies both source and snapshot, admits
exactly one of each of the nine fixed assurance claim/rule pairs, makes `status`
display-only, and requires every finding to bind an existing canonical path and
in-bounds line through a digest-valid same-path repository locator. Six curated
semantic mutants cover those boundaries. Before this status mutation:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- the exact acceptance suite passed 195 tests and the unit suite passed 76 tests,
  with no skips or expected failures;
- the first expanded mutation run killed 54 of 55 mutants and correctly returned
  `BLOCK` for one equivalent proposed operator; that operator was replaced with
  a direct fixed-rule bypass and all candidate-bound gates remain to be rebound.

These observations are local working-copy proof, not protected T24 admission
evidence. This status mutation and the mutation-operator correction invalidate
the checkpoint; complete deterministic gates, mutation, rollback, portability
and a new exact-candidate fresh review are required for the immutable successor.

The fresh read-only audit of immutable commit `a404cb8` was exactly
candidate-bound, completed every process/capture observation, retained portable
untruncated streams and produced a formally admissible `BLOCK`. It reported five
source-level findings: gate portability recognition consumed only partial host
paths and omitted named endpoints; the Linux seccomp fallback left equivalent
asynchronous `ioctl` signal controls available; general authoritative JSON used
race-prone pathname reads; untracked candidate entries separated `lstat` from
pathname content reads; and candidate-copy Git work occurred outside the gate
timeout and could fail without retained gate evidence.

The current working-copy successor centralizes complete host-path and named-
endpoint recognition for gate and reviewer streams, filters asynchronous
descriptor controls through both `fcntl` and architecture-correct Linux
`ioctl`, reads authoritative JSON and untracked file/link identity through
retained no-follow descriptors with post-read binding checks, caches one exact
JSON observation per command, and starts one absolute gate deadline before
candidate preparation while retaining incomplete preparation as `UNKNOWN`.
Eight new curated semantic mutants cover those boundaries. Before this status
mutation:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- the complete suite passed 279 tests with no skips or expected failures,
  including public-portability checks;
- after narrowing one timeout-removal operator so its existing assertion oracle
  measures only the removed timeout, the repeated expanded mutation run
  established a `PASS` baseline and causally killed all 63 operators for corpus
  `sha256:73701b1a19aaf810189bf4c3ffea9a9a843208d0d6bf9058081aa0ef112528a8`.

The mutation-operator correction, final source-quality cleanup and this status
update change the candidate. They require complete deterministic gates, all 63
causal mutation kills, rollback rehearsal, portability and a new exact-candidate
fresh review before any release qualification claim.

The immutable `8ec2b44` successor then passed its local blueprint, 279-test,
compile, rollback, portability and 63-operator mutation checkpoints. Its fresh
ChatGPT-authenticated `gpt-5.6-sol` review completed with admissible process
evidence and returned `BLOCK`. Seven concrete findings were retained:

- candidate and reviewer pathname copies could block or consume a replaced
  special leaf;
- reviewer snapshot/evidence copying and permission traversal did not all share
  a stop-capable absolute deadline;
- each mutant copy was not re-identified against the source immediately before
  patching and expected mutation trees could observe the live source;
- mutation Git/file/tree observations lacked one absolute deadline;
- admission trusted claimed reviewer argv/stdin and omitted exact
  permitted-input, risk and charter material reconstruction;
- portability recognition assumed a small POSIX root set and omitted bare
  non-loopback IPv6; and
- evidence evaluation could reopen a referenced policy within one command.

The current working-copy successor addresses those findings with retained
descriptor copies in killable bounded helpers, deadline-bound permission and
mutation observations, pre-patch source/copy/source identity checks, portable
argv plus exact protected-prompt/permitted-input stdin reconstruction, exact
rapid-review materials and one-to-one execution/charter binding, arbitrary-root
path plus bare IPv6 recognition, and a command-scoped digest-bound evidence
reference cache. A follow-on split-checkout audit also found and repaired an
admission path that rebuilt stdin from the candidate prompt rather than the
protected authority prompt. That repair is covered by an explicit
`--authority-root`, a dedicated semantic mutant, and the breaking
`reviewer-qualification-cases` v4 migration for newly retained invocation
references. The curated corpus now contains 76 operators with content ID
`sha256:5c5d1c0c9f74ace0815394e9ba5a3baa65459e892e734d820a34ab0fcb94b74e`.

Before this status mutation, the working-copy checkpoint on 2026-09-02
observed:

- `python3 scripts/validate_blueprint.py`: `PASS` for 66 requirements and 35
  schema/example pairs;
- the acceptance suite: 200 tests passed;
- the unit suite: 86 tests passed;
- `python3 -m compileall -q src tests` and `git diff --check`: `PASS`;
- the public-portability acceptance tests passed; and
- the 76-operator mutation run, rollback rehearsal and exact-candidate fresh
  review remain pending for the immutable successor.

These observations are local working-copy proof, not protected T24 admission
evidence. This status update invalidates them. Complete deterministic gates,
all 76 causal mutation kills, rollback rehearsal, portability and a new exact-
candidate fresh review must be rebound after the successor commit. Any later
candidate mutation invalidates that evidence again.

The immutable `541f50d` successor passed blueprint integrity, the 200-test
acceptance suite, the 86-test unit suite, compilation, rollback rehearsal and
public-portability checks. Its first complete 76-operator diagnostic mutation
run established a green baseline but correctly returned `BLOCK` for corpus
`sha256:5c5d1c0c9f74ace0815394e9ba5a3baa65459e892e734d820a34ab0fcb94b74e`:
69 operators were killed, five survived and two remained `UNKNOWN`.

The seven outcomes exposed mutation-oracle defects rather than release-ready
evidence. A selected evidence-reconstruction test copied its active mutant into
the synthetic candidate, making the fixture invalid before five targeted
assertions ran. The ignored-submodule operator caused a harness error instead
of performing its declared unsafe copy, and the protected-prompt test omitted a
candidate-controlled prompt that could prove protected authority won.

The current working-copy successor preserves the committed pre-mutation target
only inside a protected selected-test fixture, makes the submodule operator
copy the unsafe working tree it declares, and adds the candidate-prompt
substitution case before manifest construction. Focused protected-probe
execution causally killed all seven corrected operators. The 76-operator corpus
now has content ID
`sha256:0f2d063b3bcfb6393d227b8a786ebcfbd716bb43afea6e49cc4ec03480eda191`.
This remediation and status record invalidate the preceding evidence; complete
deterministic gates, all 76 mutation kills, rollback, portability and a fresh
exact-candidate review remain required after the successor is committed.

The immutable `be91b6f` successor subsequently passed blueprint integrity,
the 200-test acceptance suite, the 86-test unit suite, compilation, rollback,
public-portability checks and all 76 protected semantic mutants. Its exact
fresh-context `gpt-5.6-sol` review reconstructed successfully but returned
`BLOCK` with eight admissible findings: mutation probes disclosed target
metadata and lacked an unmodified paired control; gate suppliers did not
recheck the live source; the reviewer deadline began after lock/policy work and
did not cover untracked input, CLI-version or final-output reads; complete
multi-token authorization fields and colon-delimited absolute POSIX paths could
survive normalization; and stale or unqualified findings could be promoted to
a confirmed block instead of remaining `UNKNOWN`.

The current working-copy remediation updates the authoritative contracts first,
then requires separately verified unmodified control and mutant copies with the
same structured-probe command and sandbox execution identity, retains both
results through causal locators, reconstructs control survival and chronological
execution before granting kill credit, and exposes no target metadata. Gate
suppliers now bind live source plus executed copy. The absolute review deadline
now begins before lock selection and is passed through policy, authority,
candidate, schema, prompt, evidence, CLI-version and final-output observations.
Shared stream normalization removes complete authorization fields and ordinary
colon-delimited POSIX paths, then rescans. Unqualified findings remain
`UNKNOWN`. The documented local mutation runner also uses the policy-sized
300-second acceptance bound after its obsolete 120-second default timed out the
green 205-test baseline. The protected corpus now contains 86 exact semantic operators with
content ID
`sha256:afacbf64980643b719f35f254e0599a7aae2ffe607d657a179205f732ee66d70`
and protected byte digest
`sha256:6153e5c45c46a7e5a667cecfb904f410e2f2c64e895e10e478f55b132e2a0b2b`.

Working-copy checks after this remediation observed blueprint integrity, 206
acceptance tests, 91 unit tests, compilation and diff hygiene passing. These are
local development observations only and this status mutation invalidates their
candidate binding. The successor must be committed and rerun through all
deterministic gates, the complete paired-control 86-operator corpus, rollback,
portability and a new exact-candidate fresh review before release readiness can
be claimed.

The first exact 86-operator paired-control run on `c12d31e` retained a surviving
control for every operator and killed 85 mutants. It correctly returned `BLOCK`
because `reviewer-final-output-deadline-omitted` survived: the existing test
proved the descriptor reader honored a supplied deadline but did not exercise
the launcher-to-reader handoff. The current test remediation launches the
isolated reviewer under a known absolute deadline and observes that exact value
at final output materialization. This test/status mutation invalidates all
`c12d31e` evidence; the successor requires complete rebinding.

The immutable `448fa4f` successor then passed blueprint integrity, 206
acceptance tests, 91 unit tests, compilation, rollback rehearsal, public
portability and the complete 86-operator paired-control corpus: every clean
control survived and every mutant was killed. Its exact fresh
ChatGPT-authenticated `gpt-5.6-sol` review was fully observed and candidate-bound
but returned `BLOCK` with five admissible findings. Admission omitted an
allowlisted provenance input when reconstructing reviewer stdin and materials;
admission schemas could be caller-selected outside the protected authority
root; qualification reopened a result schema between identity and validation;
launcher-closure hashing used unbounded pathname reads; and permission-profile
normalization allowed security-distinct argv to share one portable digest.

This working-copy successor rejects permitted-input keys that protected
qualification and admission cannot reconstruct, resolves every admission schema
only beneath the distinct protected authority root, retains each qualification
schema's one descriptor-read representation, and binds launcher-closure reads
and verification to the shared reviewer deadline. Reviewer execution schema
`4.0.0` separately binds the exact executed argv digest while preserving a
reconstructable portable digest, and portable normalization now requires exact
semantic equality with the generated root-denying, network-disabled permission
profile. These candidate changes invalidate all `448fa4f` evidence. The next
immutable successor requires complete deterministic, rollback, portability,
paired-control mutation and fresh-review qualification before release work can
continue.

Eight protected semantic operators cover those five findings, bringing the
paired-control corpus to 94 operators with content ID
`sha256:d8e321f6a655316e5902d61003a92f26bb70e0edf0e76b3f2083e10f23151843`
and protected byte digest
`sha256:14f3fcf4759ed03583bfb19da1b4be09147eee9dd3bdcf2a3692cf3477307aac`.

Immutable candidate `344c2d4` passed its deterministic, portability and
rollback checks, but its first complete 94-operator paired-control run returned
`BLOCK`: 93 mutants were killed and
`launcher-closure-deadline-omitted` survived. The production deadline was
present; the acceptance oracle allowed the deadline-bound verification pass to
mask a missing deadline on the initial closure reads. This successor asserts
that every initial and verification read receives the same absolute deadline.
All evidence for `344c2d4` is non-qualifying and the successor requires complete
rebinding.

Immutable candidate `09eba32` then passed blueprint integrity, 209 acceptance
tests, 92 unit tests, compilation, rollback rehearsal, public portability and
the complete 94-operator paired-control corpus: every clean control survived and
every mutant was killed. Its exact fresh ChatGPT-authenticated `gpt-5.6-sol`
review was fully observed and candidate-bound but returned `BLOCK` with six
admissible findings: reviewer permitted-input shapes were not mode-exact;
evaluate output preflight did not share protected schema authority; the
reference workflow passed a checkout-prefixed evaluate schema root;
qualification did not reconcile both exact executed-argv occurrences; final
reviewer output validation reopened its schema path; and container ID files
were read through replaceable pathnames without the transaction deadline.

This working-copy successor requires `evidence_root` and one exact input key set
per review mode, independently reconstructs the full qualification input
document, shares one protected manifest/policy/schema cache across evaluate lock
selection, output preflight and execution, and uses the unprefixed split-root
workflow contract. Qualification reconciles the top-level and primitive
supervisor exact-argv digests. The reviewer validates final output against the
schema object retained under its absolute deadline, and container creation and
cleanup read the ID file through the deadline-bound no-follow descriptor helper.
Nine protected semantic operators cover these bypasses, bringing the corpus to
103 operators with content ID
`sha256:675e71533ad799d5d47449312be222d13e15b15a6c6bfc09d42675f8a15af347`
and protected byte digest
`sha256:2e12c428e2b8a227b6c85ddcd55f5e66900ad5f9b958a6b2f748a643282e00ed`.
All evidence for `09eba32` is non-qualifying; this successor requires complete
candidate-bound deterministic, rollback, portability, paired-control mutation
and fresh-review qualification before release work can continue.
