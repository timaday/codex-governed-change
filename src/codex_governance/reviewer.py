"""Fresh reviewer process boundary skeleton."""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_governance.domain.model import ReviewerVerdict


def build_reviewer_command(
    *,
    codex_executable: str,
    model: str,
    schema_path: Path,
    output_path: Path,
    review_root: Path,
    reasoning_effort: str = "xhigh",
) -> list[str]:
    """Build a shell-free strict reviewer argv for a sanitized harness root."""
    del codex_executable, model, schema_path, output_path, review_root, reasoning_effort
    raise NotImplementedError("T06: implement strict reviewer argv")


def build_reviewer_stdin(
    *, fixed_prompt: str, permitted_inputs: Mapping[str, Any]
) -> str:
    """Serialize only the reviewer input allowlist after the fixed prompt."""
    del fixed_prompt, permitted_inputs
    raise NotImplementedError("T06: implement reviewer input allowlist")


def classify_reviewer_execution(
    *,
    return_code: int | None,
    timed_out: bool,
    output_present: bool,
    output_valid: bool,
    candidate_matches: bool,
    output_truncated: bool,
    declared_verdict: str | None,
) -> ReviewerVerdict:
    """Classify reviewer process evidence."""
    del return_code, timed_out, output_present, output_valid
    del candidate_matches, output_truncated, declared_verdict
    raise NotImplementedError("T06: implement reviewer process classification")
