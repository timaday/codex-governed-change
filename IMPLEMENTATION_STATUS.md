# Implementation status

Status date: 2026-09-02

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

The reviewer sandbox deliberately denies cross-process signalling. When a test
runner is itself nested inside that sandbox, descendant-cleanup tests that need
to signal their fixtures fail closed because the outer boundary removes that
capability; they are never skipped or converted to success. Protected
deterministic qualification must run those tests in its declared signal-capable
runner before the separate read-only model lane begins.

These observations are invalidated by any later candidate mutation and remain
working-copy evidence until protected T24 reconstruction is complete.
