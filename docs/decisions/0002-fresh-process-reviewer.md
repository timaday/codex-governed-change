# ADR-0002: Use a fresh Codex process for strict review

Status: accepted

## Context

The strict reviewer must not receive the author conversation. Documented custom subagent settings do not establish that isolation boundary.

## Decision

Launch strict review with a new `codex exec --ephemeral` process, never `resume`. Start it in a sanitized harness Git root and place the immutable candidate beneath that root as read-only evidence. Use ignored user config/rules, disabled hooks/subagents, schema-constrained output, and an input allowlist. Apply a strict custom Codex permission profile that extends read-only behavior, denies the host root, re-allows only the sanitized harness and minimum detected Codex/tool runtime installation roots, disables tool network, forbids approval escalation, and limits tool environments to fixed non-secret keys. Runtime roots are derived from the protected parent executable environment at launch, never candidate input, and persist only through the argv digest. Candidate-owned `.codex`, hook, skill and rule files remain inspectable data but never become active reviewer configuration.

Select the explicit ChatGPT-authenticated Codex model `gpt-5.6-sol`. Do not use
the unsuffixed `gpt-5.6` alias for the protected identity and do not substitute
OpenAI API-key authentication. Authentication may exist in the trusted runner's
normal Codex credential store for the parent process only. Model-generated tool
processes cannot inherit the credential environment or read the credential
store or host filesystem outside the harness/minimum runtime roots. No
credential value enters reviewer inputs, the sanitized harness, model-readable
evidence, or committed configuration.

Keep `.codex/agents/independent-reviewer.toml` only as an interactive convenience.

Reviewer completion requires EOF on both bounded stdout and stderr capture
streams plus a trusted descendant boundary, not only termination of the parent
or disappearance of its original process group. A descendant that changes
session/process group, closes every standard stream, or signals a same-UID
supervisor remains in scope. The preferred Linux adapter places a trusted PID 1
and reviewer in a fresh user/PID/mount namespace, keeps the namespace manager
and child-subreaper outside the reviewer-visible PID namespace, and requires a
bounded handshake before admission. Namespace/PID-1 teardown supplies the
non-escapable cleanup unit. Where nested namespaces are blocked, a
supported-architecture `no_new_privs` seccomp guard denies all reviewer-tree
signal and cross-process-write syscalls before exec, making the outer subreaper
non-signalable while it performs bounded cleanup. On x86_64 it rejects every
x32-tagged syscall before native dispatch rather than assuming the host kernel
has disabled that alternate ABI. An unavailable equivalent
kernel capability forces `UNKNOWN`. A racy zombie-only scan cannot establish
initial success, and cleanup completion remains separate from execution validity.
Before any boundary child launches, the outer supervisor must also prove that
its procfs view reports the same self PID and parent PID as the process API,
that any namespace PID list ends in that self PID, and that direct-child
enumeration succeeds. This preflight is distinct from the inner namespace
handshake; failure returns `UNKNOWN` without launching candidate-controlled code.

Runtime read grants are canonical and pairwise non-overlapping after redundant
descendant installation roots are coalesced. They cannot equal or contain a
user home, filesystem root or sanitized harness, and cannot be nested beneath
the harness. This is required because a more-specific Codex
filesystem grant can reopen a path beneath the root deny.

## Alternatives

- **Built-in `/review`**: useful for fast feedback but not the strict no-author-context boundary.
- **In-session subagent**: read-only configuration is useful, but context isolation is not a documented guarantee.
- **Different prompt in the same session**: rejected because prior conversation remains available.

## Consequences

Each repair cycle incurs a new reviewer call. Cost and latency increase, while author-context leakage and stale reviewer assumptions decrease. Same-model correlated blind spots remain.
