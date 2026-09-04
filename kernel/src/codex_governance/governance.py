"""Protected governance asset integrity policy."""

from collections.abc import Sequence

from codex_governance.canonical import normalize_repo_path
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
    "tests/unit/",
    "src/codex_governance/",
    "docs/requirements.md",
    "docs/specification.md",
    "docs/decisions/",
)
DEFAULT_GOVERNANCE_PATHS = tuple(sorted((*GOVERNANCE_PATHS, *GOVERNANCE_PREFIXES)))


def is_governance_path(
    path: str, *, governance_paths: Sequence[str] = DEFAULT_GOVERNANCE_PATHS
) -> bool:
    """Classify one path against the exact previous-LKG protected path set."""
    normalized = normalize_repo_path(path)
    for raw_protected in governance_paths:
        prefix = raw_protected.endswith("/")
        protected = normalize_repo_path(raw_protected[:-1] if prefix else raw_protected)
        if prefix:
            if normalized.startswith(protected + "/"):
                return True
        elif normalized == protected:
            return True
    return False


def classify_governance_change(
    *,
    changed_paths: Sequence[str],
    task_profile: str,
    governance_change_authorized: bool,
    governance_paths: Sequence[str] = DEFAULT_GOVERNANCE_PATHS,
) -> DispositionState | None:
    """Legacy classifier: booleans never authorize protected governance edits."""
    del task_profile, governance_change_authorized
    governed = any(
        is_governance_path(path, governance_paths=governance_paths)
        for path in changed_paths
    )
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
        "reviewer must use the protected launcher": "--schema-root schemas review",
        "reviewer must declare the protected authority root": "--authority-root governance",
        "reviewer identity must be qualification matched": "qualification-matched",
        "decision source must be explicitly verified": "--verified-decision-id",
        "deployment adapter must come from target-branch authority": "target-branch `.governance/ci/` adapter",
        "final disposition must run after failures": "if: ${{ always() }}",
        "final disposition must name every prerequisite": "needs: [deterministic_evidence, fresh_context_review]",
        "protected runner must capture current UTC": "date -u '+%Y-%m-%dT%H:%M:%SZ'",
        "deterministic prerequisite must be exactly successful": '[[ "$DETERMINISTIC_RESULT" == "success" ]]',
        "review prerequisite must be exactly successful": '[[ "$REVIEW_RESULT" == "success" ]]',
        "governance source must use a full SHA": "GOVERNANCE_REF",
    }
    errors = [message for message, token in checks.items() if token not in workflow_text]
    if "pull_request.updated_at" in workflow_text:
        errors.append("replayable event time must not be used for validity evaluation")
    return sorted(errors)
