# ADR-0008: Protect one admission kernel with LKG policy

Status: accepted

## Context

Candidate-owned tests, workflow conditions, schemas and task assertions can be
changed by the beneficiary of admission. Several individually reasonable checks
do not create an authority boundary if a skipped or replaced final job can appear
successful.

## Decision

One small deterministic admission kernel evaluates fixed assurance arguments and
is the only readiness-producing required check. It uses the previous protected
last-known-good (LKG) governance version, authenticated human decisions and
verified attestations. It is invoked with `if: always()` after every direct CI
prerequisite and rejects any outcome other than explicit `success` plus valid
artifacts. It cannot merge, deploy, issue authority, create credentials or modify
repository settings.

The protected deployment binds the check name to its expected GitHub App/source,
requires current or merge-queue candidates, disallows bypass where supported and
uses full-SHA action references. A governance replacement is evaluated by the
old LKG and becomes LKG only through authenticated promotion with rollback
evidence.

The old LKG policy's explicit `governance_paths` are the classifier input and
cover the complete trusted implementation and deployment closure. Admission—not
a standalone test helper—descriptor-resolves the proposed policy, promotion
decision and rollback evidence and invokes the LKG-promotion predicate whenever
the candidate touches that closure. Other prerequisites use their own success
vocabulary; they cannot emit `READY_FOR_HUMAN`.

The effective policy is not trusted merely because the candidate and manifest
repeat its digest. Before any classification, a protected decision-source result
must authenticate that exact policy for the exact task, candidate and base
commit, and the policy's LKG commit must equal that base. Rollback evidence uses
typed gate-result, capability and provenance references whose bytes and execution
semantics are reconstructed; naked digest-shaped fields cannot promote policy.

## Alternatives

- **Trust the candidate workflow's last successful job**: rejected because a
  dependency failure or rename can skip the decision.
- **Let every gate decide independently**: rejected because there is no single
  fail-closed completeness decision.
- **Let the reviewer authorize governance changes**: rejected because advice is
  not accountable authority.

## Consequences

Deployment configuration remains part of the TCB and cannot be proven solely by
repository files. Missing source/ruleset/up-to-date evidence is `UNKNOWN/BLOCK`.
