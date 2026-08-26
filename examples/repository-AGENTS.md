# Repository governed-change agreement

- Invoke `$governed-change` before any material repository edit.
- Read the current implementation status, normative specification, requirements, decisions, and traceability before production changes.
- Repository contracts win over chat assumptions; report conflicts.
- Define a task contract and exact required gates before editing.
- Use the repository's documented build, unit, integration, contract, architecture, security, adversarial and specification gates.
- Run the strict reviewer as a fresh read-only `codex exec --ephemeral` process; `/review` and subagents are additional signals only.
- Recompute candidate identity after every change and discard stale evidence.
- Do not change governance assets in an ordinary feature or fix task.
- Report only `READY_FOR_HUMAN`, `BLOCK`, or `UNKNOWN`; human approval remains separate.

## Code Review Rules

- Findings require a concrete path/location, violated oracle and evidence.
- Flag correctness, authority, stale evidence, unsafe fallback, test weakening, security, architecture, data, performance and operational risks.
- Ignore style-only findings that deterministic formatting or linting should own.
