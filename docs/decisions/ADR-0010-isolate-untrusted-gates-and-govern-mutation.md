# ADR-0010: Isolate untrusted gates and govern mutation

Status: accepted

## Context

Tests execute candidate-controlled code. Running them in the governance checkout
can alter the supervisor, policy or evidence that later judges the run. Merely
using a different directory is not a security boundary. Mutation is mandatory
for fail-closed controls but was previously described as optional adoption
hardening.

## Decision

Candidate commands run only through a disposable sandbox provider whose verified
capability report declares no secrets, network disabled by default, process/time/
resource/output limits, and no writable governance, authoritative evidence,
reviewer-harness or supervisor paths. The candidate/build copy may be writable.
No authoritative evidence path is mounted. After the sandbox terminates, a fresh
trusted phase packages captured outputs and provenance. An unavailable safe
provider is `UNKNOWN/BLOCK`.

The mandatory MVP mutation layer is a finite curated semantic corpus executed in
a disposable candidate after baseline success and before final review. A valid
mutant is killed only when protected structured evidence proves the selected
unittest command ran at least one test and ended solely in an assertion failure;
compile, launch, import, discovery, harness, crash, signal, malformed-probe and
unexecuted outcomes never count. A valid non-equivalent survivor blocks; timeout,
invalid mutation and unresolved equivalence remain unknown. Optional
language-specific generation is a bounded adapter and does not enter the pure
domain or mandatory dependency set.

## Alternatives

- **Host subprocess plus path validation**: rejected because candidate code keeps
  host capabilities.
- **Mount authoritative evidence read/write for convenience**: rejected because
  the subject could manufacture its evidence.
- **Treat compilation failure as a killed mutant**: rejected because it does not
  show an oracle detected the semantic fault.

## Consequences

Some platforms cannot safely run gates without an external local sandbox runtime;
they receive an honest blocked result. The Python package remains standard-library
only and discovers the provider through a protected adapter.
