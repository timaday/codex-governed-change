# Research basis and limitations

## Official Codex behavior

- Codex loads global and layered repository `AGENTS.md` guidance, with more specific project files later in the instruction chain. Keep guidance concise and put deterministic formatting/lint enforcement in CI. [Official AGENTS.md documentation](https://learn.chatgpt.com/docs/agent-configuration/agents-md)
- Repository skills live under `.agents/skills` and use progressive disclosure. A focused `SKILL.md` can route to detailed references and deterministic scripts. [Official skills documentation](https://learn.chatgpt.com/docs/build-skills)
- Custom subagents can be configured with a model, effort, tools and a read-only sandbox, but the documented configuration does not provide a strict parent-conversation exclusion control. This is why the design treats a subagent as a convenience reviewer, not its audit boundary. [Official subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- `codex exec` supports ephemeral sessions, ignored user config, a read-only sandbox, JSON Schema output and a separate final-output file. [Official non-interactive documentation](https://learn.chatgpt.com/docs/non-interactive-mode), [CLI command reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli#cli-codex-exec)
- A synchronous Stop hook can request another model continuation. Non-managed project hooks require trust and can be disabled, so the design keeps CI as the hard boundary. [Official hooks documentation](https://learn.chatgpt.com/docs/hooks)
- The Codex GitHub Action supports read-only review and schema-constrained outputs, but credential isolation and trusted triggers remain deployment responsibilities. [Official GitHub Action documentation](https://learn.chatgpt.com/docs/github-action)
- The official GitHub Action is API-key based. Official Codex authentication
  guidance separately documents ChatGPT-managed `auth.json` for trusted private
  CI, requires persistent or securely round-tripped refreshed credentials, and
  explicitly says not to use that advanced pattern for public or open-source
  repositories. This is why topology B separates its public authority ref from
  its private execution broker and private-broker-scoped JIT runner. [Official
  authentication documentation](https://learn.chatgpt.com/docs/auth), [advanced
  private CI authentication](https://learn.chatgpt.com/docs/auth/ci-cd-auth)
- GitHub documents branch protection and rulesets for private repositories as
  paid-plan features, while public repositories can use them on GitHub Free.
  GitHub also restricts environment secrets in private repositories by plan.
  The Free topology therefore protects public refs and uses ordinary private
  repository Actions secrets only in the non-authoritative broker. [Protected
  branches](https://docs.github.com/en/repositories/configuring-branches-and-merges/managing-protected-branches/about-protected-branches),
  [ruleset availability](https://docs.github.com/en/repositories/configuring-branches-and-merges/managing-rulesets/available-rules-for-rulesets),
  [environments and secrets](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- Codex `.rules`/execpolicy controls command execution decisions; it is not a replacement for behavioral quality governance. [Official rules documentation](https://developers.openai.com/codex/rules)

## Empirical rationale

### Fresh context

Research on self-attribution bias reports that LLM monitors can become more permissive when reviewing their own preceding work than when equivalent content is presented freshly. This supports a separate reviewer invocation that receives artifacts rather than the author conversation. [Self-Attribution Bias](https://arxiv.org/html/2603.04582v1)

Inference: a fresh process reduces one bias mechanism; it does not prove independence because author and reviewer may still share training, architecture and failure modes.

### Context management

Long-context research shows that retrieval quality can degrade depending on where relevant information appears. The reviewer therefore gets full repository read access but begins with an exact diff and traverses affected surfaces rather than receiving an indiscriminate repository dump. [Lost in the Middle](https://aclanthology.org/2024.tacl-1.9/)

### Multiple review sources

Real-world code-review benchmarks suggest that synthesizing multiple review sources can improve detection. The MVP uses one fresh general reviewer plus deterministic tools; specialist or model-diverse lanes are a future risk-based option. [SWR-Bench](https://arxiv.org/html/2509.01494v1)

### Deterministic and generative testing

Property-based testing driven by agent-inferred properties has found defects in mature software, supporting the use of property, fuzz and mutation testing as external verification rather than relying on review prose. [Property-based testing for code](https://www.anthropic.com/research/property-based-testing)

### Independent evaluation and lifecycle oversight

The NIST Generative AI Profile emphasizes measurement, red-teaming, documented limitations and independent evaluation across the lifecycle. This design encodes those ideas as explicit evidence states, adversarial charters and human authority. [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

## What the evidence does not establish

- No cited study proves this implementation will prevent every Codex GPT-5.6 Sol drift or defect.
- A reviewer `PASS` is not proof of correctness or security.
- Same-model review retains correlated blind spots and possible self-preference.
- Local hook behavior is not durable enforcement unless delivered through managed policy; CI and repository controls remain necessary.
- Full repository read access does not mean every relevant file will be inspected on every run.
- Evaluation results from this repository will apply only to the tested versions, configurations, fixtures and risk classes.

## Design conclusion

The supported conclusion is layered: concise instructions and a skill improve process consistency; a fresh reviewer reduces author-context coupling; deterministic gates supply repeatable evidence; exact digests prevent stale proof; protected CI prevents easy self-approval; and a human retains risk authority. None of these layers is sufficient alone.
