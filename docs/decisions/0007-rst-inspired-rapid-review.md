# ADR-0007: Add candidate-bound RST-inspired rapid review

## Context

Deterministic checks can evaluate known assertions and a fresh conformance reviewer can compare a candidate with its contract, yet both can miss important stakeholders, assumptions, failure modes, and value threats that were never framed.

## Decision

Add an RST-inspired rapid-review layer for specification/design and code/change work. Each investigation starts from an exact candidate-bound risk assessment and focused time-boxed charter, runs in the existing fresh read-only reviewer boundary, captures direct observations with fallible oracles and evidence, and ends with a three-story debrief plus explicit finding and residual-risk disposition.

Risk profiles select minimum work, not a universal duration. Low risk may skip only with a recorded policy-valid rationale and cannot include designated hazardous surfaces. Standard risk requires one charter. Elevated risk requires multiple relevant charters or explicit justified coverage and retains human ownership of material residual-risk acceptance.

Checklists, HTSM, FEW HICCUPPS, elapsed time, session count, and absence of findings are guidewords or observations, never certificates. Missing, stale, obstructed, inconclusive, weakly linked, or unclear evidence remains `UNKNOWN/BLOCK`.

Non-empty reference text is not linkage. Every rapid-review evidence reference
must resolve through the protected content-addressed locator set, and admission
must reconstruct the operational relationship graph across risks, charters,
sessions, oracles, coverage, debrief, follow-ups and disposition. Missing,
dangling, wrong-kind or digest-mismatched edges are `UNKNOWN`; a complete list of
artifact kinds has no readiness authority.

The new fields in `task-contract.schema.json` and `evidence-manifest.schema.json` are representation-compatible additions, so both remain at `1.0.0`. Existing artifacts remain parseable. Policy provides the fail-closed migration boundary: a task selecting rapid review cannot become ready without constructing and validating the new candidate-bound artifacts; omitted fields are never defaulted into success.

## Consequences

Readiness now requires more candidate-bound artifacts and may take additional fresh-review calls. The benefit is explicit inquiry into omitted risks and honest reporting of investigative limits. AI may assist experiments and reporting but cannot accept residual risk, grant waivers, or approve a candidate.

## Attribution

This independent MIT-licensed adaptation uses concepts described by the [Rapid Software Testing introduction](https://rapid-software-testing.com/a-ridiculously-rapid-introduction-to-rapid-software-testing/), [HTSM](https://rapid-software-testing.com/heuristic-test-strategy-model/), [FEW HICCUPPS](https://developsense.com/blog/2012/07/few-hiccupps), [session report checklist](https://rapid-software-testing.com/session-based-test-management-report-checklist/), and [testing/checking distinction](https://rapid-software-testing.com/testing-and-checking-refined/). No course material or worksheet is copied or vendored.
