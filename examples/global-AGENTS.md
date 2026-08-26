# Governed change invariant

- For every material code, test, configuration, infrastructure, documentation, or specification change, use the repository's governed-change workflow when present.
- Before editing, establish authoritative sources, scope, non-goals, assumptions, risks, affected surfaces, acceptance oracles, and required gates.
- A goal stated in chat does not silently alter repository requirements. Report conflicts before proceeding.
- Completion cannot be established by model self-assessment. Require fresh deterministic evidence and independent read-only review bound to the exact candidate.
- Missing, failed, timed-out, truncated, malformed, conflicting, unavailable, or stale mandatory evidence is `UNKNOWN` and blocks.
- Any candidate mutation invalidates evidence and reviews for the earlier candidate.
- Never weaken, skip, delete, relabel, or reduce a test, gate, threshold, schema, or authority control to obtain `PASS` unless a human explicitly authorizes a governance change.
- Reviewers advise and may veto; they do not edit, accept risk, grant waivers, merge, or deploy.
- Human approval remains required.
