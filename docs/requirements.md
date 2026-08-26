# Requirements

Status: normative MVP contract

| ID | Requirement | Acceptance evidence |
|---|---|---|
| GOV-001 | The repository MUST provide concise global/repository instruction examples and a repo-scoped governed-change skill. | Blueprint validation; skill activation tests |
| GOV-002 | Every material change profile MUST follow Context, Decide, Act, Verify, Learn. | Task-contract and workflow tests |
| GOV-003 | Evidence MUST bind to a deterministic candidate identity including relevant working-tree additions. | Candidate identity unit/acceptance tests |
| GOV-004 | Gate results MUST include command identity, candidate identity, exit/termination state, bounded raw artifacts, hashes, timing, truncation and limitations. | Gate runner contract tests |
| GOV-005 | Strict independent review MUST run in a new ephemeral process without author conversation context. | Reviewer command and prompt-allowlist tests |
| GOV-006 | The independent reviewer MUST have read-only candidate access and no repository write credential. | Command construction and CI policy tests |
| GOV-007 | Reviewer output MUST conform to the repository schema and contain evidence-backed findings and limitations. | Schema and malformed-output tests |
| GOV-008 | Missing, stale, timed-out, truncated, malformed, conflicting or unavailable mandatory evidence MUST become `UNKNOWN/BLOCK`. | Aggregation decision-table tests |
| GOV-009 | Any candidate mutation MUST invalidate prior gate and reviewer evidence. | Pre/post identity drift tests |
| GOV-010 | The Stop hook MUST force at most one continuation and then expose a blocker without looping. | Stop-hook first/continued-call tests |
| GOV-011 | CI MUST reproduce mandatory gates on an immutable commit and expose a required disposition check. | CI static policy tests and integration evidence |
| GOV-012 | Only a human MAY approve merge, deployment, risk acceptance or waiver. | Domain-policy tests and documented branch controls |
| GOV-013 | A normal candidate MUST NOT approve itself by modifying governance policy, schemas, prompts, workflows or gate definitions. | Governance-integrity and protected-policy tests |
| GOV-014 | Code changes MUST support deterministic build, test, architecture, security and risk-selected advanced gates. | Code-profile validation tests |
| GOV-015 | Specification changes MUST require traceability, alternatives, Three Amigos, relevant specialists, acceptance criteria, test strategy and RST review. | Specification-profile validation tests |
| GOV-016 | The reviewer MUST inspect the exact diff and affected closure while retaining full repository read access. | Reviewer prompt contract and fixture tests |
| GOV-017 | Reviewer `PASS` MUST NOT independently create `READY_FOR_HUMAN`. | Aggregator authority tests |
| GOV-018 | Waivers MUST be explicit, human-approved, scoped, candidate-bound and expiring. | Waiver validation tests |
| GOV-019 | Working-tree mode MUST compare pre/post identities; CI MUST use immutable commit mode. | Race/drift and CI mode tests |
| GOV-020 | The reviewer launcher MUST never use `resume` and MUST record a sanitized invocation/prompt digest. | Reviewer-launcher tests |
| GOV-021 | Secrets, authentication files, author transcripts and hidden reasoning MUST NOT enter reviewer inputs or evidence. | Redaction/allowlist/security tests |
| GOV-022 | MVP code MUST run on Python 3.11+ with no mandatory production dependency outside the standard library and Codex/Git executables. | Packaging and clean-environment tests |
| GOV-023 | Every disposition MUST be reconstructable from immutable referenced artifacts and producer versions. | Manifest reconstruction tests |
| GOV-024 | The governance system MUST include mutation/adversarial evaluation for its own fail-closed controls. | Evaluation corpus and mutation gate evidence |
| GOV-025 | An unavailable independent reviewer MUST block; the system MUST NOT silently fall back to `/review` or a subagent. | Reviewer-unavailable tests |
| GOV-026 | The implementation MUST distinguish confirmed failure from observation uncertainty. | Exit/timeout/truncation decision tests |
| GOV-027 | Commands MUST use argument arrays without shell expansion by default; shell mode MUST be explicit and risk-labelled. | Subprocess-injection tests |
| GOV-028 | Governance outputs MUST be written under a configured evidence root that cannot escape the repository or follow unsafe symlinks. | Path traversal and symlink tests |
| GOV-029 | Configuration precedence and effective policy MUST be observable and digestible. | Configuration resolution tests |
| GOV-030 | The implementation MUST never perform merge, deployment, repository-setting changes, credential creation, or waiver approval. | Capability-boundary tests |

## MVP completion rule

Every requirement above is mandatory. A proposed deferral changes the MVP contract and therefore requires an explicit human-reviewed specification change, traceability update, and rationale. An implementation model may not unilaterally defer a requirement.
