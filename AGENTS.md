# Public authority-ref operating agreement

- Treat `.github/`, `.governance/`, `kernel/`, `rulesets/`, `AGENTS.md`, and `tests/` as
  protected authority surfaces.
- Update contracts and tests before changing workflow or publication behavior.
- Never weaken or bypass a failing, missing, unknown, stale, cancelled,
  malformed, timed-out, skipped, or unqualified prerequisite.
- Never place private keys, installation tokens, user tokens, authentication
  files, machine paths, hostnames, private endpoints, or local configuration in
  repository content or evidence.
- This bundle is authority only when its exact commit is reachable from the
  configured ruleset-protected public authority ref. A private broker checkout
  or mutable branch is not authority.
- Every workflow in this bundle must be reusable-only (`workflow_call`). Public,
  candidate, pull-request, push, comment, issue, dispatch and schedule triggers
  are forbidden here.
- Candidate and reviewer jobs must remain credential-free and read-only with
  respect to authority. Only a final publisher invoked by the separate private
  broker may receive the GitHub App credential.
- The App may publish only the fixed Checks API run. Its `statuses:write`
  permission exists solely for GitHub expected-source eligibility; authority
  code must not call the commit-status API. It may not merge, release, modify
  settings, issue waivers, accept risk, promote policy, or write contents.
- The only successful check condition is an exact protected
  `READY_FOR_HUMAN` disposition for the selected candidate.
- Use ChatGPT-authenticated `gpt-5.6-sol`; an OpenAI API key is not an allowed
  reviewer identity.
- The authenticated JIT runner must be registered only to the private broker,
  never to the public target containing this authority ref.
- A model may report or veto but may not approve, create a protected human
  decision, or certify release.
- Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`
  after every change.
