# Contributing

This project treats governance changes as changes to the acceptance authority, not ordinary refactors.

## Before proposing a change

1. Read `IMPLEMENTATION_STATUS.md`, `docs/specification.md`, `docs/requirements.md`, and `docs/traceability.md`.
2. Classify the change as implementation, test, documentation, schema, governance, or mixed.
3. State scope, non-goals, affected requirements, risks, acceptance oracles, and expected evidence.
4. For behavior changes, establish a failing test before production code.
5. For specification changes, provide Business, Engineering, QA, relevant specialist, and RST review evidence.

## Integrity rules

- Do not combine a governance-oracle change with the implementation that benefits from it unless the dependency is unavoidable and explicitly reviewed.
- Do not turn a mandatory failure into a skip, warning, retry-only result, or undocumented exception.
- Do not accept stale evidence after any candidate mutation.
- Do not place credentials, Codex authentication files, author transcripts, private repository data, or model reasoning traces in artifacts.
- Human waivers must be explicit, scoped, justified, attributable, and time-bounded. A model cannot issue a waiver.

## Pull request evidence

A pull request should include:

- requirement and task identifiers;
- exact base/head candidate identity;
- deterministic gate commands and results;
- fresh reviewer result and digest binding when the implementation supports it;
- residual risks and unknowns;
- confirmation that governance controls were not weakened.

No contribution is considered production-ready until protected CI and a human approve it.
