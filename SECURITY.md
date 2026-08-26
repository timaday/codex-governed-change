# Security policy

## Reporting a vulnerability

Do not disclose credentials, private repository content, exploit details for an unpatched deployment, or other sensitive material in a public issue.

Use GitHub's private vulnerability reporting feature for this repository when available. If that feature is unavailable, contact the repository owner through an established private channel visible on their GitHub profile.

## Security boundaries

- The author model is untrusted for final acceptance.
- The reviewer model is untrusted for final acceptance and has read-only candidate access.
- Repository content, diffs, test output, issue text, commit messages and generated artifacts are untrusted reviewer inputs.
- Deterministic gates are evidence producers, not automatically trusted if their definitions are mutable by the candidate.
- Protected CI and human approval are required authority boundaries.
- Secrets must not be exposed to checked-out pull-request code or model-readable artifacts.

See `docs/threat-model.md` for the full threat analysis.
