# Traceability

Every MVP requirement maps to an implementation task and at least one deterministic acceptance surface. Test module names are stable contracts for the implementation run.

| Requirement | Task | Acceptance surface |
|---|---|---|
| GOV-001 | T09, T10 | `test_blueprint_contract.py`, skill fixtures |
| GOV-002 | T01, T07 | `test_workflow_profiles.py` |
| GOV-003 | T03, T24 | `test_candidate_identity.py`, deadline-bound untracked regular/symlink retained-descriptor and leaf-race tests, reviewer/gate composite source-plus-snapshot and mutation copy-local drift, recursive-submodule and concrete-mutant-tree tests, `test_reviewer_isolation.py` |
| GOV-004 | T02, T04, T05 | `test_gate_evidence.py` |
| GOV-005 | T06, T24 | `test_reviewer_isolation.py`, unit stderr-only success plus missing/duplicate/additional combined-stream rejection, exact hosted authentication-check regression |
| GOV-006 | T06, T09, T24 | `test_reviewer_isolation.py`, runtime-root coalescing plus bidirectional harness and user-home permission-overlap canaries, CI static checks |
| GOV-007 | T02, T06 | `test_reviewer_isolation.py`, exact-five claim schema/admission fixtures, incomplete-closure and unresolved-claim reconstruction tests |
| GOV-008 | T01, T05, T07 | `test_disposition_policy.py`, `test_gate_evidence.py` |
| GOV-009 | T03, T05, T06, T17, T19, T24 | `test_candidate_identity.py`, `test_disposition_policy.py`, `test_gate_sandbox.py`, copy-bound mutation runner tests, `test_reviewer_isolation.py` |
| GOV-010 | T08 | `test_stop_hook.py` |
| GOV-011 | T09, T23 | `test_governance_integrity.py`, workflow validation, exact protected command clean-environment execution |
| GOV-012 | T01, T07 | `test_disposition_policy.py` |
| GOV-013 | T09 | `test_governance_integrity.py` |
| GOV-014 | T05, T07 | `test_workflow_profiles.py`, `test_gate_evidence.py`, protected src-layout import-path tests |
| GOV-015 | T07 | `test_workflow_profiles.py` |
| GOV-016 | T06, T21 | `test_reviewer_isolation.py`, protected reviewer-closure admission tests |
| GOV-017 | T01, T07 | `test_disposition_policy.py` |
| GOV-018 | T01, T07 | `test_disposition_policy.py` |
| GOV-019 | T03, T05, T09 | `test_candidate_identity.py`, CI static checks |
| GOV-020 | T06 | `test_reviewer_isolation.py` |
| GOV-021 | T04, T06, T09 | `test_gate_evidence.py`, shared gate/reviewer complete multi-token authorization, arbitrary-root and single-/multi-leading-separator colon-delimited POSIX/Windows/UNC-share-root host-path, word-boundary scheme exception, malformed listed-scheme separator canaries, independently classified named-endpoint and bare IPv4/IPv6 canaries, post-normalization rescan, benign RFC3339 clock-value regression, unit gate-runner short-host/address endpoint canaries, `test_reviewer_isolation.py`, deterministic command-event omission plus final-message/raw-stream credential/endpoint/host-path canaries, permission-profile environment canary, `test_governance_integrity.py` |
| GOV-022 | T01-T10 | Blueprint clean-environment gate |
| GOV-023 | T02, T04, T07, T24 | Complete producer-closure, exact prompt/material omission/substitution/ordering, descriptor-bound raw-stream, distinct-producer-workflow and schema/example tests |
| GOV-024 | T09, T10, T19 | Protected full-corpus digest/substitution tests and governance mutation corpus |
| GOV-025 | T06, T08, T24 | `test_reviewer_isolation.py`, pre-launch procfs PID/PPID/exactly-one fully parsed `NSpid`/child-enumeration zero-launch tests, deadline-before-lock review CLI input/version/launcher-closure tests, shared-deadline pre/post candidate observation, descriptor-bound snapshot/evidence/final-output/output-schema/launcher-source read, retained-schema validation, explicit pre-launch execution-budget timeout, unchanged permission-finalization deadline with scheduler-gap no-launch and bounded child resolution, snapshot-Git tests, unit unread-full-stdin, namespace/direct/`fcntl`/`ioctl` supervisor-assassination, benign descriptor-operation, `prlimit64`-denial and x32-ABI-denial process tests, `test_stop_hook.py` |
| GOV-026 | T01, T05, T24 | `test_gate_evidence.py`, raw-stream reconstruction and stale/unqualified-finding uncertainty tests |
| GOV-027 | T05, T06 | `test_gate_evidence.py`, `test_reviewer_isolation.py` |
| GOV-028 | T03, T04, T24 | `test_candidate_identity.py`, `test_cli_orchestration.py`, artifact-store security tests |
| GOV-029 | T03, T07 | `test_candidate_identity.py`, configuration tests |
| GOV-030 | T01, T07, T09 | `test_disposition_policy.py`, capability-boundary tests |
| GOV-031 | T11, T12 | `test_rapid_review.py`, `test_workflow_profiles.py` |
| GOV-032 | T11 | `test_rapid_review.py`, schema/example checks |
| GOV-033 | T11, T24 | `test_rapid_review.py`, protected risk-floor reconstruction tests |
| GOV-034 | T11 | `test_rapid_review.py` |
| GOV-035 | T11 | `test_rapid_review.py` |
| GOV-036 | T11 | `test_rapid_review.py` |
| GOV-037 | T11 | `test_rapid_review.py` |
| GOV-038 | T12 | `test_rapid_review.py`, `test_reviewer_isolation.py`, exact retained permitted-input/risk/charter materials and one-session/one-execution/one-charter reconstruction tests |
| GOV-039 | T11, T12 | `test_rapid_review.py`, `test_disposition_policy.py` |
| GOV-040 | T11, T12 | `test_rapid_review.py`, `test_candidate_identity.py` |
| GOV-041 | T14, T21, T22, T23 | `test_reference_monitor.py`, forged-ready display-only status and context `CONTEXT_READY` terminology oracles, `test_ci_admission.py` |
| GOV-042 | T23 | `test_ci_admission.py`, executable unprefixed split-root evaluate reference, `test_governance_integrity.py` |
| GOV-043 | T13, T23, T24 | `test_trusted_authority.py`, protected authority-root admission-schema reuse across lock/preflight/evaluation and split-root rejection tests, authenticated previous-LKG policy/base/policy-substitution tests, complete-TCB source mutation coverage in `test_governance_integrity.py` and admission reconstruction |
| GOV-044 | T17 | `test_gate_sandbox.py`, unchanged absolute-deadline propagation across container helper boundaries, adversarial scheduler-gap no-launch, retained preparation-`UNKNOWN`, descriptor-bound deadline-sharing container-ID reads, reconstructed image/command/limit identity, ignored-submodule exclusion, copy-local drift, bounded-create, post-empty-threshold delayed-create quarantine, exact-ID timeout/removal and cleanup-time rename/substitution tests |
| GOV-045 | T16 | `test_attestation.py`, `test_candidate_identity.py` |
| GOV-046 | T16, T17, T20 | `test_attestation.py`, complete producer-closure identity, exact/portable reviewer argv separation, `test_gate_sandbox.py`, `test_reviewer_isolation.py`, `test_evidence_reconstruction.py` |
| GOV-047 | T16, T24 | `test_attestation.py`, `test_gate_evidence.py`, `test_pipeline_lock.py`, deterministic existing-leaf/publication/readback replacement, directory-lock hardlink/leaf-replacement and CLI no-replacement tests |
| GOV-048 | T14, T24 | `test_trusted_authority.py`, `test_disposition_policy.py`, authenticated qualification-label decision, trusted-current-time, exact-expiration boundary and rerun-after-expiry tests |
| GOV-049 | T14, T24 | `test_trusted_authority.py`, `test_workflow_profiles.py`, protected risk-floor reconstruction tests |
| GOV-050 | T14, T23, T24 | `test_trusted_authority.py`, exact-manifest read-only protected-package rollback producer, sibling `sitecustomize`/extra-file exclusion, disabled site loading, candidate-script substitution, exact argv/stdout target binding, admission-path proposed-policy/promotion/rollback reconstruction including initial bootstrap plus missing/dummy/re-addressed nested-proof and verification-digest tests, `test_ci_admission.py` |
| GOV-051 | T14, T22 | `test_assurance_case.py`, exact-nine claim omission/duplication/rule-substitution admission tests, `test_reference_monitor.py` |
| GOV-052 | T15, T20, T23 | `test_assurance_case.py` descriptor-bound parent/leaf swap/symlink/FIFO/oversize tests, general authoritative-JSON/schema symlink/FIFO/oversize and command-session single-observation/conflicting-digest tests, exact mode-specific permitted-input sets and full-document reconstruction, both conformance and rapid-review finding missing-path/out-of-range-line/swapped-locator tests, artifact and reviewer-output retained-parent/leaf re-stat barriers, raw noncanonical output preservation, split-checkout reviewer/admission schema and evidence command tests, protected-authority prompt reconstruction, end-to-end reviewer CLI protected-authority/candidate-root materialization and single-read race/special-file tests, `test_reviewer_isolation.py` |
| GOV-053 | T14 | `test_assurance_case.py`, `test_disposition_policy.py` |
| GOV-054 | T20 | `test_reviewer_isolation.py`, protected repository-relative command instruction, permission-profile canary, unit x32-ABI, asynchronous-`fcntl` and equivalent-`ioctl` denial plus benign descriptor-operation process tests, `test_context_compiler.py` |
| GOV-055 | T20, T24 | `test_reviewer_qualification.py`, mandatory seeded-defect/prompt-injection/control classes and critical expected-finding labels, both-mode blanket-`BLOCK`/empty/wrong-ID/wrong-line/unrelated-finding rejection, single-read raw-corpus and protected-schema digests plus duplicate-key rejection, deterministic synthetic-candidate plus per-case source/projection/qualification/prepared/post-run context and typed corpus/case/normalized-stream/JSONL-result/primitive-observation/execution reconstruction, equality of both exact executed-argv occurrences, portable argv, stdin/full permitted-input/risk/charter, gate/context, closure, reviewed-surface, mandatory-claim and corpus-derived reference tampering, command-event omission plus raw-stderr/final-message ambiguity tests, portability and protected exact-corpus label-decision tests |
| GOV-056 | T20 | `test_reviewer_qualification.py`, `test_workflow_profiles.py` |
| GOV-057 | T18, T24 | `test_rapid_review.py` protected evidence-locator substitution matrix, `test_rst_operations.py` complete exact relationship-graph, duplicate-reference, empty/extra feedback-edge and presence-only red controls, admission reconstruction |
| GOV-058 | T19 | `test_mutation_governance.py`, identical unmodified-control command/environment and metadata-branch tests, exact 600-second protected-policy/local-runner timeout binding, per-mutant source-before/copy/source-after identity and shared Git/tree deadline tests, producer-to-admission control/original-candidate/mutated-execution subject tests, protected-corpus bytes, recursive concrete mutated-tree identity, selected-fixture pre-mutation target isolation, exact template/record/gate/sandbox/executed command identity, structured selected-unittest causal proof and post-probe drift tests |
| GOV-059 | T19 | `test_mutation_governance.py`, compile/launch/import/discovery/crash/malformed-probe classification, raw-evidence reconstruction and schema/example checks |
| GOV-060 | T15, T24 | `test_schema_lifecycle.py`, complete executable advertised-transition matrix including effective-policy v3, evidence-manifest v4, context-qualification v3, rapid-review-session v2, reviewer-qualification v3, reviewer-qualification-cases v5 and reviewer-execution v5, protected missing-field inputs, legacy/current schema rejection and re-addressing, unit schema-adapter tests for portable ECMA-262 pattern and advertised Draft 2020-12 definition/instance semantics, capability/provenance chronology and schema/example checks |
| GOV-061 | T15, T16, T17 | Complete framed producer-package drift and exact-manifest materialization tests in `test_attestation.py`, `test_gate_sandbox.py` |
| GOV-062 | T13, T16, T17, T23 | `test_public_portability.py`, ignored-submodule sandbox exclusion, clean-environment gate |
| GOV-063 | T23, T24 | `test_github_free_topology.py`, authority-bundle called-job SHA/caller guard/completed-run referenced-workflow tests, caller/callee finalizer concurrency non-contention, required-linear-history ruleset reconstruction, real two-parent decision/receipt rejection, broker active-workflow isolation, hosted ruleset verification and exact-candidate release pack |
| GOV-TOKEN-001 | T21, T24 | `test_context_compiler.py`, `test_cli_orchestration.py`, protected-source and forged-signal tests |
| GOV-TOKEN-002 | T21, T24 | `test_context_qualification.py`, `test_reviewer_qualification.py`, empirical/synthetic-bootstrap boundary, profile/version identity, exact corpus/label/mode/case/raw-measurement reconstruction, aggregate-recomputation and missing-usage tests |
| GOV-TOKEN-003 | T15, T20, T21, T24 | `test_context_compiler.py` protected artifact-closure/profile-escalation/index/exact-byte retrieval tests, `test_reviewer_isolation.py`, source/projection/retrieval reconstruction and tampering tests in `test_evidence_reconstruction.py`, rapid-review retrieval-expansion protected-index reconstruction, qualification-case dummy-digest/context-artifact tests, schema/example checks |
| GOV-TOKEN-004 | T21 | `test_context_compiler.py`, `test_reference_monitor.py` |

## Coverage rules

- `scripts/validate_blueprint.py` MUST fail if a requirement lacks a task or acceptance surface.
- New requirements MUST update this table, the implementation plan, and an executable test before being considered design-ready.
- Renaming a test does not remove the requirement; traceability must be updated in the same governance change.
- A mapped test that is skipped, expected-failed, non-discovered, or not executed provides no acceptance evidence.
- Named requirement families such as `GOV-TOKEN-*` are normative and receive the
  same task, traceability and no-skip treatment as numbered requirements.
