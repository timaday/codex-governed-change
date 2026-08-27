"""Protected governance asset integrity policy."""

from collections.abc import Sequence

from codex_governance.domain.model import DispositionState


GOVERNANCE_PATHS = frozenset(
    {
        "AGENTS.md",
        "IMPLEMENTATION_STATUS.md",
        "IMPLEMENT_WITH_GPT_5_6.md",
        ".github/CODEOWNERS",
    }
)
GOVERNANCE_PREFIXES = (
    ".agents/",
    ".codex/",
    ".github/workflows/",
    "schemas/",
    "scripts/",
    "tests/acceptance/",
    "docs/requirements.md",
    "docs/specification.md",
    "docs/decisions/",
)


def is_governance_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized in GOVERNANCE_PATHS or any(
        normalized.startswith(prefix) for prefix in GOVERNANCE_PREFIXES
    )


def classify_governance_change(
    *,
    changed_paths: Sequence[str],
    task_profile: str,
    governance_change_authorized: bool,
) -> DispositionState | None:
    """Legacy classifier: booleans never authorize protected governance edits."""
    del task_profile, governance_change_authorized
    governed = any(is_governance_path(path) for path in changed_paths)
    if not governed:
        return None
    return DispositionState.BLOCK


def validate_ci_policy(workflow_text: str) -> list[str]:
    """Perform conservative static checks on a reference deployment workflow."""
    checks = {
        "workflow must be an authority-owned required-workflow template": "AUTHORITY-OWNED REQUIRED-WORKFLOW TEMPLATE",
        "candidate-local workflow must be explicitly non-authoritative": "candidate-local code with the same workflow, job or check name has no authority",
        "workflow must declare read-only contents": "contents: read",
        "checkout credentials must not persist": "persist-credentials: false",
        "candidate mode must be immutable commit": "--mode commit",
        "reviewer must use the protected launcher": "governance/schemas review",
        "reviewer identity must be qualification matched": "qualification-matched",
        "decision source must be explicitly verified": "--verified-decision-id",
        "deployment adapter must come from target-branch authority": "target-branch `.governance/ci/` adapter",
        "final disposition must run after failures": "if: ${{ always() }}",
        "final disposition must name every prerequisite": "needs: [deterministic_evidence, fresh_context_review]",
        "deterministic prerequisite must be exactly successful": '[[ "$DETERMINISTIC_RESULT" == "success" ]]',
        "review prerequisite must be exactly successful": '[[ "$REVIEW_RESULT" == "success" ]]',
        "governance source must use a full SHA": "GOVERNANCE_REF",
    }
    return sorted(message for message, token in checks.items() if token not in workflow_text)
