# ADR-0013: Support GitHub Free with public authority and a private execution broker

Status: accepted

## Context

The topology-B release design placed governance authority, the Codex reviewer
workflow, and the GitHub App credential in one private personal repository. A
personal GitHub Free account cannot enforce a ruleset or classic branch
protection on that repository. GitHub also limits private-repository environment
secrets to paid plans.

Making the authority repository public would make protection available, but it
would put ChatGPT-managed Codex automation in a public/open-source workflow.
Official Codex authentication guidance explicitly reserves that advanced
`auth.json` pattern for trusted private automation and says not to use it for
public or open-source repositories. The official Codex GitHub Action uses an
OpenAI API key, which is not an allowed reviewer identity for this project.

The target may be owned by one personal account. The design cannot require an
organization, a paid GitHub plan, or a second eligible reviewer that does not
exist.

## Decision

Topology B uses three distinct roles across two repositories:

1. The public target repository holds candidate branches and one dedicated
   authority ref. Separate active rulesets protect the target default branch and
   the authority ref. The authority ref contains the governance bundle,
   reusable workflow implementation, policy, schemas, decisions, target
   registry, and release records. Runtime always selects it by a full commit
   SHA and verifies that the configured live authority ref still equals that
   SHA.
2. A separate private personal-account repository is an execution broker, not
   an authority source. Its active trigger surface contains only
   manual/scheduled caller workflows, internal completed-run finalization,
   repository-scoped Actions configuration, and credentials. A non-authoritative
   mirror of the public bundle MAY remain for reconstruction, but no caller may
   select it as authority. Each caller pins a reusable workflow from the public
   authority ref by full commit SHA. It has no pull-request, push, issue,
   comment, repository-dispatch, or public-webhook trigger.
3. A private GitHub App installed only on the public target publishes the fixed
   `disposition` check. Its private key is a private-broker Actions secret. The
   candidate, deterministic gates, admission kernel, and reviewer tools never
   receive that key or its installation token.

ChatGPT-authenticated `gpt-5.6-sol` runs only on a clean, single-job, Linux x64
JIT runner registered to the private broker. The runner is isolated from other
credentials and workloads and destroyed after the job. Saved ChatGPT-managed
authentication never enters the public repository, its Actions secrets,
artifacts, or logs. An OpenAI API key is forbidden.

The private broker's default branch is not represented as protected authority.
Its callers are transport and credential activation only. The protected target
registry, candidate identity, decisions, reviewer identity, admission logic,
and publication payload all come from the exact public authority commit. A
broker caller cannot select an arbitrary candidate, authority ref, workflow, or
check name. A changed caller requires the same human owner who already controls
the App installation and target rulesets; administrative account compromise
remains an explicit residual risk rather than a false branch-protection claim.

For a sole-user repository, the authority-ref ruleset requires pull requests,
thread resolution, stale-review dismissal, and no bypass, but zero approving
reviews. This prevents direct accidental updates without inventing a second
human. If another eligible reviewer exists, the reviewed profile requiring one
approval is mandatory.

The initial authority-ref creation and ruleset installation are a one-time
bootstrap. Their exact commits and live settings require human review and
post-installation verification. The exception is non-reusable.

## Consequences

- A personal GitHub Free account can enforce both required rulesets because the
  governed refs are public.
- ChatGPT authentication and the App private key remain in trusted private
  execution infrastructure.
- Candidate-controlled code cannot modify the authority ref or trigger the
  broker.
- Public evidence can name and reconstruct the exact authority commit even
  though broker run details may be private.
- The operator must provision a separate private broker and an ephemeral
  self-hosted reviewer runner. These are deployment prerequisites, not runtime
  dependencies of the package.
- No claim is made that an unprotected private broker branch is protected. The
  broker is outside the acceptance-authority set and cannot replace the pinned
  public reusable workflow without an observable caller change by the human
  administrator.

## Rejected alternatives

- Upgrade to GitHub Pro: rejected because the portable MVP must work on GitHub
  Free personal accounts.
- Put ChatGPT `auth.json` in public-repository Actions secrets: rejected by
  official Codex guidance and the public-runner threat model.
- Use `openai/codex-action` with an OpenAI API key: rejected because the
  qualified identity is ChatGPT-authenticated Codex.
- Keep unprotected governance authority in the private broker: rejected because
  it would preserve the original authority-substitution blocker.
- Register the authenticated self-hosted runner to the public target: rejected
  because public contribution paths must not be able to schedule work on a
  credential-bearing runner.
- Require an organization or a second approver: rejected as a universal
  prerequisite; adopters that have them should use the stronger topology-A or
  reviewed-authority profile.
