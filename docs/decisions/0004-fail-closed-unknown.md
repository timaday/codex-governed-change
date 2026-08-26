# ADR-0004: Treat incomplete proof as UNKNOWN and block

Status: accepted

## Context

Timeouts, missing output and truncated observations do not establish that a candidate failed, but they also cannot establish that it passed.

## Decision

Keep `FAIL` distinct from `UNKNOWN`. Any mandatory `UNKNOWN` blocks automated progression. No silent fallback may turn reviewer or gate unavailability into a pass.

## Alternatives

- **Treat every infrastructure error as FAIL**: loses diagnostic truth and can hide observation defects.
- **Warn and continue**: allows the system to approve without required proof.
- **Retry until success**: can hide flakiness and consume unbounded resources.

## Consequences

Availability problems can block delivery. This is intentional for mandatory proof; operators must repair the evidence path or use an explicit protected human waiver.
