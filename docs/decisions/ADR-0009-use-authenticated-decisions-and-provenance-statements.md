# ADR-0009: Use authenticated decisions and provenance statements

Status: accepted

## Context

A boolean authorization or free-text approver name is an assertion. Hashes bind
bytes but do not establish who authorized an action, which repository produced
evidence or which execution environment observed it.

## Decision

Task approval, governance authorization, risk reduction, waiver issuance,
waiver consumption and LKG promotion use protected decision references. Each is
bound to repository, task digest, candidate/base as applicable, policy, scope,
authenticated issuer and validity period. Models may request decisions but may
not create them.

Content addressing does not authenticate the issuer. The protected
decision-source adapter returns the exact set of decision IDs it authenticated,
and every pure decision policy requires membership in that set in addition to
content, binding, scope and time checks. The default set is empty. A deployment
that cannot verify its configured source therefore cannot authorize from
self-declared issuer fields.

Evidence uses a standalone in-toto-shaped Statement v1 representation. Its
subjects bind `repository_id` and candidate/source digests; its predicate records
task, policy, gate/prompt, producer implementation, workflow attempt, tool,
sandbox/environment, material, time, limit, result, limitation and artifact
identities. Signing is deferred, so the MVP calls these provenance statements,
not cryptographically authenticated attestations.

Artifacts are content-addressed and write-once. An identifier is SHA-256 over
canonical JSON after removing exactly its own top-level identifier field. A
same-path identical-byte write is idempotent; different bytes at that path block.

## Alternatives

- **Repository/commit digest only**: rejected because identical Git states can
  exist under different authority and environment contexts.
- **Free-text identity**: rejected because it is forgeable candidate data.
- **Require an external attestation service**: rejected to preserve standalone
  operation.

## Consequences

Repository operators must provide a protected decision-verification adapter. If
it is absent, applicable authority remains unknown. Cryptographic signing can
wrap the same statement later without changing its bounded claim semantics.
