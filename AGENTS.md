# Repository operating agreement

## Current phase

This repository is `IMPLEMENTED_CANDIDATE / FINAL_QUALIFICATION_UNKNOWN / RELEASE_BLOCKED`. Read `IMPLEMENTATION_STATUS.md` before making claims.

## Mandatory workflow

- For every code, test, configuration, hook, CI, schema, or specification change, invoke `$governed-change` before editing.
- Read `docs/specification.md`, `docs/requirements.md`, applicable decisions, and `docs/traceability.md` before production changes.
- Treat approved repository contracts as authoritative. Report conflicts; do not silently resolve them from chat assumptions.
- Separate facts, assumptions, hypotheses, risks, unknowns, deferrals, and non-goals.
- Any candidate mutation invalidates evidence and reviews bound to the earlier candidate.
- Missing, failed, stale, timed-out, truncated, malformed, conflicting, or unavailable evidence is `UNKNOWN` and blocks.
- Never weaken, skip, delete, quarantine, relabel, or reduce a test, gate, schema, threshold, or governance control to obtain `PASS` unless a human explicitly authorizes a governance change.
- A reviewer may veto but cannot edit the candidate, accept risk, authorize merge, or certify correctness.
- Do not use an in-session subagent as the strict independent reviewer. The strict review boundary is a new ephemeral read-only `codex exec` process.
- Do not publish, merge, release, change repository settings, or create credentials unless the user explicitly asks.

## Required commands

Blueprint integrity:

```bash
python3 scripts/validate_blueprint.py
```

Implementation acceptance:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/acceptance -v
```

Until implementation is complete, acceptance failures are expected red evidence. They are not permission to weaken the contract.

## Code Review Rules

- Findings must identify the violated requirement or oracle and cite a concrete path and location.
- Prioritize correctness, authority bypass, stale evidence, digest confusion, reviewer leakage, unsafe subprocess behavior, secret exposure, race conditions, portability, and missing tests.
- Flag any fallback that turns a required `BLOCK` or `UNKNOWN` into success.
- Flag any path by which the author, reviewer, PR code, or mutable workflow can modify its own acceptance authority.
- Ignore style-only issues unless they obscure a real defect or violate an executable repository check.
