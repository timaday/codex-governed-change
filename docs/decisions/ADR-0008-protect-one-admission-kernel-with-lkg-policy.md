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
