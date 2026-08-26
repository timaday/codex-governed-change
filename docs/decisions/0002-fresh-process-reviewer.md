# ADR-0002: Use a fresh Codex process for strict review

Status: accepted

## Context

The strict reviewer must not receive the author conversation. Documented custom subagent settings do not establish that isolation boundary.

## Decision

Launch strict review with a new `codex exec --ephemeral` process, never `resume`. Start it in a sanitized harness Git root and place the immutable candidate beneath that root as read-only evidence. Use ignored user config/rules, disabled hooks/subagents, read-only sandboxing, schema-constrained output, and an input allowlist. Candidate-owned `.codex`, hook, skill and rule files remain inspectable data but never become active reviewer configuration.

Keep `.codex/agents/independent-reviewer.toml` only as an interactive convenience.

## Alternatives

- **Built-in `/review`**: useful for fast feedback but not the strict no-author-context boundary.
- **In-session subagent**: read-only configuration is useful, but context isolation is not a documented guarantee.
- **Different prompt in the same session**: rejected because prior conversation remains available.

## Consequences

Each repair cycle incurs a new reviewer call. Cost and latency increase, while author-context leakage and stale reviewer assumptions decrease. Same-model correlated blind spots remain.
