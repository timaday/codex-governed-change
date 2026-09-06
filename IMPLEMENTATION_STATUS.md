# Implementation status

Status date: 2026-09-05

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

Immutable candidate `b3015e6` passed blueprint integrity, 211 acceptance tests,
92 unit tests, compilation, rollback rehearsal and public portability. Its
complete 103-operator paired-control run returned `BLOCK`: all 103 controls
survived and 102 mutants were killed, but
`unreconstructable-reviewer-input-accepted` survived. Exact mode-specific input
sets made that older transformation equivalent because adding keys only to the
legacy broad allowlist no longer changed admission. The successor replaces it
with an optional-provenance-pair bypass at the active exact-set comparison. All
evidence for `b3015e6` is non-qualifying and complete candidate rebinding is
required. The revised 103-operator corpus has content ID
`sha256:d313dc236a62da0151cd767c32640f1de927e880481887f1ae64099f338ee4af`
and protected byte digest
`sha256:8e6adae43cc628d6674e35387cbfb1bf761fc4e369627a6f5f7e1d740efd9977`.

Immutable candidate `676833d` then passed blueprint integrity, 211 acceptance
tests, 92 unit tests, compilation, rollback rehearsal, public portability and
the complete 103-operator paired-control corpus: every clean control survived
and every mutant was killed. Its exact fresh ChatGPT-authenticated
`gpt-5.6-sol` source review emitted a schema-valid `BLOCK` result, but the
launcher conservatively admitted only `UNKNOWN` because stream observation was
incomplete after ambiguous machine- or credential-shaped bytes were redacted.
The retained diagnostic finding was independently confirmed: `run_gate`
converted its execution and cleanup deadlines to remaining durations, while
the container helpers rebased those durations from later clock observations.
A scheduler pause could therefore extend the protected GOV-044 budget.

This working-copy successor passes the unchanged absolute execution deadline
to container creation and the unchanged gate deadline to cleanup, derives
subprocess timeouts only from those received deadlines, refuses expired helper
entry, and rechecks the execution deadline immediately before candidate launch.
Direct helper-expiry and adversarial caller-to-callee scheduling-gap tests cover
the boundary. A dedicated semantic operator restores deadline rebasing, bringing
the corpus to 104 entries with content ID
`sha256:371315008833d73d149efb744c7e0d44161a604d066e0aaf4c03277221d6ac67`
and protected byte digest
`sha256:0d33d00c13ff93a733956b7130e9970783df5041c3a507a5d623bf45d59eb2aa`.
All evidence for `676833d` is non-qualifying; complete deterministic, rollback,
portability, paired-control mutation and fresh-review rebinding is required for
the immutable successor.

Immutable candidate `0df7df3` passed blueprint integrity, 212 acceptance tests,
92 unit tests, compilation, rollback rehearsal, public portability and the
complete 104-operator paired-control corpus: every clean control survived and
every mutant was killed. Its exact fresh ChatGPT-authenticated `gpt-5.6-sol`
review again emitted a schema-valid `BLOCK` result but was conservatively
admitted as `UNKNOWN` after ambiguous shaped stream bytes made observation
incomplete. Both retained diagnostic findings were independently confirmed.
The shared portability recognizer excluded multi-leading-separator POSIX paths
and UNC share roots, while permission finalization calculated its child timeout
before strict parent-side path resolution and could reuse that stale duration
after a scheduler gap.

This working-copy successor recognizes every such POSIX and UNC boundary form
through the shared gate/reviewer normalization path. Permission finalization
performs real-path resolution inside its bounded child, receives the unchanged
absolute deadline, validates it at entry and again immediately before launch,
and derives the subprocess timeout only from the latter observation. Gate,
reviewer and direct scheduler-gap tests cover both closures. Three dedicated
semantic operators restore the two path-recognition gaps and the stale
permission budget, bringing the corpus to 107 entries with content ID
`sha256:7fa92b1cf5dcf164e13434168af7734f2f8b12905f22de08242f0c222382d8a7`
and protected byte digest
`sha256:c63534ec76d0f37f3a29ba7dc4c6b9981148d9d4c14a569c6d63b93ce9f584ce`.
All evidence for `0df7df3` is non-qualifying; the immutable successor requires
complete deterministic, rollback, portability, paired-control mutation and
fresh-review rebinding.

Immutable candidate `b75c3f9` passed blueprint integrity, 212 acceptance tests,
93 unit tests, compilation, rollback rehearsal and public portability, but its
complete local mutation run correctly returned `UNKNOWN` before any operator.
The corpus baseline inherited the documented 300-second acceptance timeout while
the same exact green suite required more than 360 seconds on this runner. An
ad-hoc machine-specific timeout would not repair the protected policy binding.
This working-copy successor therefore raises both the protected acceptance gate
and documented local runner default to the same bounded 600 seconds and
re-addresses the existing timeout-regression mutant. The 107-entry corpus now
has content ID
`sha256:e23044f9b17dd89c7597a7b201a8deaec94a967f3cadde319ad854db282a2f24`
and protected byte digest
`sha256:28fd15c3f823ddc3e2d5a8a084ff4d30a2ba14485507d4e907270175fb45c9fa`.
All evidence for `b75c3f9` is non-qualifying; deterministic gates, paired
controls, fresh review and candidate identity must be regenerated.

Immutable candidate `901793b` passed blueprint integrity, 212 acceptance tests,
93 unit tests, compilation, rollback rehearsal and public portability. Its
600-second corpus baseline passed and 106 paired operators were killed, but the
complete 107-operator aggregate correctly returned `BLOCK` because
`named-endpoint-unredacted` survived. Multi-leading POSIX recognition consumed
the URL authority portion after the endpoint mutant removed HTTP support, so the
combined oracle still observed ambiguity without proving the named-endpoint
family worked. This working-copy successor excludes scheme-qualified URL
authority separators from generic POSIX matching, adds an endpoint-specific
classification oracle, and re-addresses the affected path and endpoint mutants.
The 107-entry corpus now has content ID
`sha256:1f5f337c576950373c2535adfd87f5b52bbf67520d06495d648a21eeee379b30`
and protected byte digest
`sha256:0126171816204fcd19d68d5bd2fced690b4b3e1465fc245aa930f04623ead4d4`.
All `901793b` evidence is non-qualifying; deterministic gates, paired controls,
fresh review and candidate identity must be regenerated.

Immutable candidate `e71cde4` passed blueprint integrity, 212 acceptance tests,
94 unit tests, compilation, rollback rehearsal, public portability and the
complete 107-operator paired-control corpus. Its fresh ChatGPT-authenticated
`gpt-5.6-sol` source review completed with valid bounded execution and declared
`BLOCK` on one high-severity finding: the generic POSIX pattern excluded every
colon before multiple separators, so an ordinary label followed by a colon and
two or three leading separators could survive both shared normalizers. This
working-copy successor limits the exception to the endpoint family's listed
word-boundary schemes, adds gate and reviewer adversarial cases for ordinary
colon-delimited multi-separator paths, and adds a dedicated semantic mutant for
the overbroad exception. The 108-entry corpus now has content ID
`sha256:23964762357b071d85f59962c85cecd83101be1bc92b8e25e251938bb7c5b494`
and protected byte digest
`sha256:7fde4633c995ba9a47a2b3d9da1eff702b87284e596351607e62d607fb376590`.
All `e71cde4` evidence is non-qualifying; deterministic gates, paired controls,
fresh review and candidate identity must be regenerated.

Immutable candidate `3bee288` passed the complete local 108-operator
paired-control corpus and its release authority passed its deterministic suite,
but the exact fresh ChatGPT-authenticated `gpt-5.6-sol` release audit declared
`BLOCK`. A listed endpoint scheme followed by three or more separators could
avoid both endpoint and generic-host-path recognition. This working-copy
successor treats that malformed form as endpoint ambiguity in the shared
gate/reviewer recognizer and adds gate, reviewer and semantic-mutation canaries.
The 109-entry corpus now has content ID
`sha256:765ac3acb571fc67ffb1eb55d6c3e25b5ec72b9ac92b1d6e925632008528fd22`
and protected byte digest
`sha256:f41359f6899fc8e9dc1d126157f9977dd3d003ccd84f5355e0dcc3edb2bb4704`.
All `3bee288` evidence is non-qualifying; deterministic gates, paired controls,
fresh review and candidate identity must be regenerated.

Immutable candidate `eb5c79f` later passed its local blueprint, unit,
acceptance, full-suite, portability, packaging and complete 124-operator
paired-control mutation checks. Its exact fresh ChatGPT-authenticated
`gpt-5.6-sol` review nevertheless declared `BLOCK` with five material findings:
initial-bootstrap admission still required a previous-LKG decision, duplicate
risk-to-charter edges could preserve operational RST readiness, protected
context qualification schema and artifact reads did not receive the review
deadline, finding validation reopened a repository pathname after locator
resolution, and Python-only regular-expression syntax could be accepted as a
Draft 2020-12 `pattern`. All `eb5c79f` evidence is therefore non-qualifying.

This working-copy successor reconstructs the mutually exclusive one-off
initial-bootstrap decision, verification, authority manifest, rollback plan,
rollback task, rollback candidate, promotion, capability, provenance and raw
streams without repository-specific constants. It also requires target-bearing
rollback command/stdout and bounded exact chronology; rejects duplicate
risk-to-charter relationships; carries the unchanged review deadline through
repository inventory and empirical qualification reads; validates finding
lines from the already retained locator bytes; and restricts `pattern` to the
protected portable ECMA-262/Python intersection. Five targeted semantic
operators cover those reviewed fail-open or unusable paths, bringing the corpus
to 129 entries with content ID
`sha256:56bd8694f2b6f60743eb317f5e728e2e1c8b162ed0646409938bf43b4f12dbd5`
and protected byte digest
`sha256:251cbf4b8971287bf568f1cc8de254e0a2f05524b4e966ad1f4dfb875209285f`.
Diagnostic focused, unit, blueprint and 235-test acceptance runs, including
the deeper bootstrap artifact-substitution and stale-plan controls, are green
but stale by construction after the final documentation mutations. The
successor still requires exact-candidate deterministic and mutation gates, fresh review,
protected authority/kernel/broker rebinding, hosted real-isolation and labelled
qualification evidence, paired governed-versus-ordinary measurement, protected
admission reconstruction and separate human release approval. Release remains
blocked.

Immutable candidate `5a7766b` subsequently passed blueprint integrity, 105 unit
tests, 235 acceptance tests and its then-current 129-entry corpus. Its strict
fresh ChatGPT-authenticated `gpt-5.6-sol` review returned `BLOCK` with six
material findings. Preparation and review manufactured a qualification-label
verification set from policy; initial bootstrap did not bind the exact hosted
authority ref, active ruleset and commit-resident manifest; initial rollback
accepted limited plans and capabilities; reviewer runtime isolation trusted
mutable home environment variables; portable schema validation admitted
Unicode-divergent shorthand expressions; and operational RST collapsed
requirement and change update identities into one untyped locator set. All
evidence for `5a7766b` is non-qualifying.

This working-copy successor moves qualification-label verification to a
separate adapter-supplied decision boundary; reconstructs the exact dispatch,
live authority ref and no-bypass protected ruleset, authority commit and
commit-resident manifest; requires limitation-free initial rollback plan,
evidence, gate, capability, provenance and verification layers plus empty
stderr; derives the account home from operating-system identity while treating
environment homes as additional denied roots; rejects Unicode-divergent regular
expression shorthands; and derives separate exact requirement and change update
sets. Eight targeted paired-control operators cover the findings, bringing the
corpus to 137 entries with content ID
`sha256:ea08fda439f8345fbc9d3e1bef27c287808d9617b7c501419a478d91cfba1350`
and protected byte digest
`sha256:acef9b470bab854b4807ef8f2a7fc5f60f1650fe630f4ce5d653b592944d52b5`.
Blueprint integrity, 107 unit tests and 237 acceptance tests are green locally;
all eight new mutants have surviving controls and causal kills. This status
mutation invalidates those working-copy observations for release admission.
The immutable successor still requires exact-candidate deterministic and full
137-entry mutation evidence, a new strict fresh review, protected authority and
broker rebinding, hosted qualification/admission evidence, the pre-approved
held-out governed-versus-ordinary measurement decision, and separate human
release approval. Operational qualification, measured benefit and human
approval remain `UNKNOWN`; release remains blocked.

Immutable candidate `23ad49d` passed blueprint integrity, 107 unit tests and
237 acceptance tests. Its complete corpus run then correctly stopped before the
first operator with baseline `UNKNOWN`: expanding the protected reconstruction
suite raised the observed baseline duration beyond the policy-bound 600-second
limit. No mutant received credit and all `23ad49d` observations are
non-qualifying. This successor raises the documented local runner and protected
acceptance-gate limit together to the repository-portable bounded value of 900
seconds and re-addresses the existing timeout-regression operator. The
137-entry corpus now has content ID
`sha256:364c52e1176c9b13283cd404c813b56a49dd4ff5014d878c2b0b29be37f4427c`
and protected byte digest
`sha256:bddfcf21e8360f8df82843e6a9a9a7529294ecbc130f3c757f342c4f72c253b4`.
This mutation invalidates earlier evidence. Exact-candidate deterministic,
complete paired-control mutation, fresh review, protected authority and broker,
hosted qualification/admission, measured comparison and human approval states
must all be regenerated; release remains blocked.

Immutable candidate `25de1ee` passed post-commit blueprint integrity and 107
unit tests; its exact 237-test acceptance run passed in 655.935 seconds. The
complete mutation run was stopped after a live read-only ruleset observation
showed that GitHub's hosted pull-request rule includes three protected fields
not represented by that candidate's exact-shape validator: allowed merge
methods, unattributed-change approval and required reviewers. The live state is
the intended squash/rebase-only, extra-approval, empty-reviewer-list profile,
but `25de1ee` would reject it as shape drift. Its incomplete mutation run and
all earlier observations are non-qualifying. This successor binds that exact
hosted parameter shape in the contract, reference rulesets, reconstruction and
adversarial tests. A dedicated semantic operator brings the corpus to 138
entries with content ID
`sha256:0ed4abbc83a477e2abf348572570358172382f698c04308adcfcfc3ab55a2fc3`
and protected byte digest
`sha256:acf7cb7e380b9eb8bc741f414d6ead283f551807c0900d22f958547f8894adce`.
Complete deterministic, paired-control mutation and strict
fresh review evidence must be rebound to the next immutable candidate; release
remains blocked.

Immutable candidate `44ca182` passed blueprint integrity, 107 unit tests and
237 acceptance tests. Its complete 138-entry corpus had surviving controls for
every operator and killed 136 mutants, but correctly returned `BLOCK`: the
deadline-propagation operator produced an assertion-fixture error and therefore
remained `UNKNOWN`, while the limited-bootstrap-plan operator survived because
its selected case also limited the outer verification and did not isolate the
plan check. This successor makes absence of the propagated deadline an ordinary
assertion failure and keeps the limited-plan verification otherwise complete,
so both controls pass and both exact mutants are now causally `KILLED` in
focused rechecks. Those focused observations are not complete qualification;
all exact-candidate gates, the full corpus and fresh review must be rebound to
the next immutable successor. Release remains blocked.

Immutable candidate `5d3baef` then passed blueprint integrity, 107 unit tests,
237 acceptance tests, the 344-test full suite, rollback rehearsal, public
portability and the complete 138-operator paired-control corpus. Every clean
control survived and every mutant was killed. Its exact fresh
ChatGPT-authenticated `gpt-5.6-sol` review completed with valid bounded process,
capture, cleanup, candidate and model bindings and returned `BLOCK` with four
material findings. Coverage validation accepted uncovered or multiply covered
RST nodes; the risk register accepted a type-valid subset instead of the exact
protected update set; preparation and admission did not inherit a command-entry
deadline through all protected reconstruction; and numeric regular-expression
backreferences used Python semantics despite an advertised portable ECMA-262
subset. All evidence for `5d3baef` is non-qualifying.

This working-copy successor requires exactly one coverage note per session and
every protected oracle exactly once, and derives the exact protected
requirement, changed-path, observation, surviving-mutant and reviewer-finding
risk-update identities. Preparation, review and admission now establish one
protected-policy-matched deadline before lock selection and pass it through Git,
schema, evidence, retrieval, context qualification and admission reconstruction;
cached observations recheck expiry. Numeric backreferences are rejected from
the supported portable pattern subset. Seven targeted paired-control operators
cover these repairs, bringing the corpus to 145 entries with content ID
`sha256:702032a9006796782110336557127859f01c038fba46c4217a8ee77ddd4d11da`
and protected byte digest
`sha256:93c5aff6aa00df3c641fda29c032504fb7a2e67c16ee87fcd758a5fe90ab926b`.
The seven new controls survived and their mutants were causally killed; the
243-test acceptance suite passed locally. This status mutation invalidates
those observations for release admission. Exact-candidate deterministic and
complete paired-control mutation evidence, a new strict fresh review, protected
authority/kernel/broker rebinding, hosted real-isolation and human-labelled
qualification evidence, the approved held-out governed-versus-ordinary
measurement, protected admission reconstruction and separate human release
approval are still required. Operational qualification, measured benefit and
human approval remain `UNKNOWN`; release remains blocked.

Immutable candidate `ba705a9` passed blueprint integrity, 109 unit tests, 243
acceptance tests, the 352-test combined suite, packaging compilation, rollback
rehearsal and public-portability checks. Its complete 145-entry local corpus had
surviving controls for every operator and killed 144 mutants, but correctly
returned `BLOCK`: `review-deadline-start-delayed` made the selected acceptance
fixture dereference an absent command deadline, which raised a harness error and
therefore reconstructed as `UNKNOWN` rather than a causal kill. This
working-copy successor records a missing deadline value and fails through an
ordinary assertion, preserving the same GOV-025 oracle while ensuring that
import, discovery, fixture and runtime errors remain `UNKNOWN`. The candidate
mutation invalidates every `ba705a9` observation. Exact-candidate deterministic
and complete paired-control mutation evidence, a new strict fresh review,
protected authority/kernel/broker rebinding, hosted real-isolation and
human-labelled qualification evidence, the approved held-out
governed-versus-ordinary measurement, protected admission reconstruction and
separate human release approval remain required. Operational qualification,
measured benefit and human approval remain `UNKNOWN`; release remains blocked.

Immutable candidate `deebb31` passed blueprint integrity, 109 unit tests, 243
acceptance tests, the 352-test combined suite, packaging compilation, rollback
rehearsal, public portability and the complete 145-operator paired-control
corpus. Every clean control survived and every mutant was killed. Its exact
fresh ChatGPT-authenticated `gpt-5.6-sol` source review completed with valid
bounded process, capture, cleanup, candidate and model bindings and reported no
blocking source finding. The subsequently frozen public-authority candidate
`3ef59c8` passed all 79 authority tests and bundle reconstruction, but its fresh
review was correctly classified `UNKNOWN` after ambiguous machine-shaped stream
normalization made process observation incomplete. Its structured advisory
output nevertheless identified four hypotheses, all of which were reproduced
before repair except one subclaim: the existing rapid-retrieval mutant
precondition occurs exactly once and had applied successfully.

This working-copy source successor closes the three reproduced kernel defects.
Admission retrieval now resolves model-requested expansion paths only through
the protected digest index and unchanged command deadline; RST feedback graphs
must contain the exact independently derived typed set, including every required
relationship while remaining order-insensitive; and empirical context
qualification counts input plus output tokens without double-counting reasoning
tokens while validating cached-input and reasoning-output subset invariants.
Four targeted paired-control operators cover digest/deadline retrieval, missing
required RST edges, token aggregation and token subsets, bringing the corpus to
149 entries with content ID
`sha256:e91e96d6eac1838e1bb8761d38ba135675d0fb8f7f8c5b7ebe43d46d314a68df`
and protected byte digest
`sha256:2af138c4f2e1ab4dcfc54df7ef14e5c85d6b2c6b7f7bcfdb5ac0a109cd84102f`.
All four focused controls survived and their mutants were causally killed. The
separate authority-only live-ruleset applicability defect remains to be closed
when the kernel is rebound into the next authority successor. This status
mutation invalidates all working-copy observations. Exact-candidate gates, the
complete 149-entry corpus, fresh review, authority/kernel/broker rebinding,
hosted real-isolation and empirical qualification, paired comparison, protected
admission reconstruction and separate human release approval remain required.
Operational qualification, measured benefit and human approval remain
`UNKNOWN`; release remains blocked.

The source candidate `e370eeb` subsequently passed blueprint integrity, 109
unit tests, 245 acceptance tests, packaging compilation, rollback rehearsal and
public-portability checks. Its complete mutation run was superseded before
completion after the exact public-authority candidate `93c3750` passed 82 local
authority tests and bundle reconstruction but returned a valid fresh
ChatGPT-authenticated `gpt-5.6-sol` `BLOCK`. Four findings concern the
authority-only paired-comparison producer: governed finding-shape mismatch,
incomplete ordinary primitive reconstruction, omitted ordinary launcher
model/effort validation, and an asserted rather than reconstructed governed
`STANDARD` context. A fifth finding reaches the source admission kernel: the
live public-authority observation did not bind repository visibility, so an
accessible private repository could satisfy the ref/ruleset/manifest checks.

This working-copy source successor now requires the retained authority state to
bind `visibility` exactly to `public`, with a private-visibility bootstrap
regression and a causal semantic operator. The 150-entry corpus has content ID
`sha256:e9ea0ef8b47ce58295ed6c463c1a50b4fb2d6e7712723b6f57c938842c66d395`
and protected byte digest
`sha256:ffb541f5d2d8bba279a665313e464818de1cfdcb69b3576a141f1559b64938af`.
The focused control survived and the visibility-check mutant was killed. The
four comparison findings remain authority work and cannot be repaired or
reviewed until this source successor is frozen and rebound. Exact-candidate
deterministic and complete paired-control mutation evidence, fresh source and
authority reviews, protected authority/broker advancement, hosted
real-isolation and empirical qualification, paired comparison, admission
reconstruction and separate human release approval remain required. Operational
qualification, measured benefit and human approval remain `UNKNOWN`; release
remains blocked.

A subsequent strict fresh-context review of the authority successor reproduced
a critical defect in public source candidate `ab14b9f`: qualification could
trust a fully readdressed retained latency chain without independently deriving
the RFC 3339 interval or enforcing the protected timeout. The obsolete
candidate-bound mutation run was stopped and is not evidence. This working-copy
successor versions reviewer qualification as `4.0.0` and its case evidence as
`6.0.0`, binds protected timeout/output limits into identity, derives exact
millisecond-floor wall intervals, rejects reversed and over-timeout evidence,
requires execution/context/aggregate equality, and brings the authority's
wall-derived launcher latency fix into public source. Two targeted semantic
operators bring the curated corpus to 152 entries with content ID
`sha256:c5630b640af80cea39d6da96fe4a70aaccd1af47dec1f22f1d70f74457c827b7`
and protected byte digest
`sha256:57f6eb3cbbcc45075b67645ffad062e2361396f6ac72bc1f9da59fb47558f026`.
Both targeted controls survived and their mutants were causally killed.
Blueprint validation and all 356 deterministic tests pass locally;
exact-candidate freeze, the complete mutation corpus, fresh source and authority
reviews, authority/kernel/broker rebinding, hosted real isolation and empirical
qualification, paired comparison, protected admission reconstruction and
separate human release approval remain required. Operational qualification,
measured benefit and human approval remain `UNKNOWN`; release remains blocked.

Immutable source candidate `d2d1288` passed blueprint validation and all 356
deterministic tests. Its exact fresh ChatGPT-authenticated `gpt-5.6-sol` review
returned a valid `BLOCK`: the accepted RFC 3339 grammar allowed fractional
precision that Python silently truncated to microseconds, so a fully readdressed
sub-microsecond timeout overrun could appear exactly on the protected boundary.
The corresponding authority candidate `c10c7e5` passed all 87 authority tests
and exact manifest reconstruction, but its fresh review also returned a valid
`BLOCK`. Empirical context packages could use internally consistent nested
reviewer identities without matching the separately protected production
identities, and the authority-only paired comparison enforced its timeout only
after millisecond flooring. All three findings were reproduced before repair;
the d2/c10-bound reviews and bindings are obsolete and non-qualifying.

This working-copy successor restricts the supported RFC 3339 profile to exactly
representable zero-to-six-digit fractional seconds and rejects precision loss
before interval reconstruction. Every nested empirical context record must now
match both externally derived conformance and rapid-review identities:
credential-free preparation and admission use the separately protected
qualification records plus independently protected prompt/schema/launcher and
policy fields, while live review derives the identity from its observed Codex
runtime. Two new paired-control semantic operators cover the timestamp and
context-identity defects, bringing the source corpus to 154 entries with content
ID `sha256:a570d926fe271f472bfb791a660e0c3e8b98f1e1a64cf2873fead1673b1b38cb`
and protected byte digest
`sha256:634b3578c6e517f11d595ff59673bd80894799a5b210feb6ee89dc9ee69ad20f`.
Both clean controls survived and both mutants were causally killed in focused
checks. The authority successor separately compares exact integer microseconds
against the paired-arm timeout before flooring and has fully readdressed
governed and ordinary regressions plus a distinct clean-control semantic mutant.
Exact-candidate gates, the complete mutation corpus, fresh source and authority
reviews, authority/kernel/broker advancement, hosted real isolation and
empirical qualification, the approved paired comparison, protected admission
reconstruction and separate human release approval remain required. Operational
qualification, measured benefit and human approval remain `UNKNOWN`; release
remains blocked.

Immutable source candidate `7f851e3` passed blueprint validation and all 357
deterministic tests, but its strict ChatGPT-authenticated Codex review correctly
remained `UNKNOWN` before model execution: the protected Codex runtime rejected
`uniqueItems` in the model-facing conformance output schema. No reviewer result
or token usage was available, so that attempt is not qualification evidence and
all candidate and authority bindings to `7f851e3` are obsolete.

This working-copy successor removes only the unsupported transport keyword from
the model-facing schema and retains JSON-equality uniqueness for reviewed
surfaces, affected closure and claims in deterministic semantic validation
before qualification or admission. A focused Codex transport probe accepts the
successor schema. A new clean-control semantic operator kills omission of that
post-validator, bringing the source corpus to 155 entries with content ID
`sha256:d9ae2724db2cd25e21a0ba7e8778dd95ca6cfaedd54fe36f135d749ca64f348d`
and protected byte digest
`sha256:6e3bc18e592caf24ae1b553882c447d35eb51770d69f790a1718f835cd5ce8a0`.
The focused 49-test schema, reviewer-isolation, lifecycle, mutation-governance
and public-portability set passes. This status mutation invalidates those
working-copy observations. Exact-candidate gates, the complete mutation corpus,
fresh source and authority reviews, authority/kernel/broker advancement, hosted
real isolation and empirical qualification, the approved paired comparison,
protected admission reconstruction and separate human release approval remain
required. Operational qualification, measured benefit and human approval remain
`UNKNOWN`; release remains blocked.
