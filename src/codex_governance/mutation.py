"""Pure governance mutation selection and outcome policy."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_governance.canonical import (
    content_address,
    normalize_repo_path,
    require_sha256,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.domain.model import DispositionState


REQUIRED_CURATED_MUTANTS = frozenset(
    {
        "missing-reviewer-pass",
        "timeout-soft-success",
        "omit-untracked",
        "omit-post-identity",
        "reviewer-pass-authorizes",
        "expired-waiver",
        "artifact-symlink",
        "reviewer-shell",
        "stop-loop",
        "candidate-gates",
        "redaction-hides-failure",
        "skipped-final",
        "cross-repository-replay",
        "forged-task-authorization",
        "writable-protected-paths",
        "manifest-overwrite",
        "cli-output-overwrite",
        "raw-stream-success",
        "unverified-reviewer-reference",
        "risk-downgrade",
        "protected-risk-floor-downgrade",
        "old-policy-self-replacement",
        "missing-provenance",
    }
)

MUTATION_PROBE_SOURCE = """import py_compile, subprocess, sys
path, command = sys.argv[1], sys.argv[2:]
if path.endswith('.py'):
    try:
        py_compile.compile(path, doraise=True)
    except py_compile.PyCompileError:
        raise SystemExit(120)
try:
    result = subprocess.run(command, stdin=subprocess.DEVNULL, check=False)
except OSError:
    raise SystemExit(121)
raise SystemExit(result.returncode if 0 <= result.returncode < 120 else 119)
"""


def build_mutation_probe_command(
    path: str, selected_command: Sequence[str]
) -> list[str]:
    relative = normalize_repo_path(path)
    if not selected_command or not all(
        isinstance(item, str) and item for item in selected_command
    ):
        raise ValueError("selected mutation command is required")
    return [
        "/usr/bin/env", "PYTHONPATH=src", "python3", "-c",
        MUTATION_PROBE_SOURCE, relative, *selected_command,
    ]


def evaluate_mutation_record(record: Mapping[str, Any]) -> DispositionState:
    outcome = record.get("outcome")
    if outcome == "SURVIVED":
        return DispositionState.BLOCK
    if outcome == "KILLED":
        evidence = record.get("causal_evidence")
        tests = record.get("selected_tests")
        references = (
            record.get("sandbox_capability"),
            record.get("provenance_statement"),
            record.get("execution_result"),
        )
        if (
            verify_content_address(record, "mutant_record_id")
            and isinstance(evidence, Sequence)
            and evidence
            and isinstance(tests, Sequence)
            and tests
            and all(isinstance(item, Mapping) for item in references)
        ):
            return DispositionState.READY_FOR_HUMAN
    return DispositionState.UNKNOWN


def mutated_source_identity(
    *, candidate_id: str, corpus_id: str, mutant_id: str, patch_sha256: str
) -> str:
    """Identify one protected mutation of an exact original candidate."""
    if not isinstance(mutant_id, str) or not mutant_id:
        raise ValueError("mutant identity is required")
    return sha256_canonical(
        {
            "candidate_id": require_sha256(candidate_id, name="candidate_id"),
            "corpus_id": require_sha256(corpus_id, name="corpus_id"),
            "mutant_id": mutant_id,
            "patch_sha256": require_sha256(patch_sha256, name="patch_sha256"),
        }
    )


def select_generated_mutants(
    *, candidates: Sequence[Mapping[str, Any]], budget: int
) -> list[dict[str, Any]]:
    if budget < 0:
        raise ValueError("mutation budget cannot be negative")
    relevant = [
        dict(item)
        for item in candidates
        if item.get("changed_line") is True or item.get("risk") in {"high", "critical"}
    ]
    return sorted(relevant, key=lambda item: str(item.get("id", "")))[:budget]


def parse_curated_corpus(data: bytes) -> dict[str, Any]:
    """Parse exact protected corpus bytes without a second pathname read."""
    import json

    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("curated mutation corpus is unavailable or malformed") from exc
    if not isinstance(document, dict) or document.get("schema_version") != "1.0.0":
        raise ValueError("unsupported curated mutation corpus")
    if not verify_content_address(document, "corpus_id"):
        raise ValueError("curated mutation corpus identity does not reconstruct")
    baseline = document.get("baseline_command")
    mutants = document.get("mutants")
    if (
        not isinstance(baseline, list)
        or not baseline
        or not all(isinstance(item, str) and item for item in baseline)
        or not isinstance(mutants, list)
    ):
        raise ValueError("curated mutation corpus commands are malformed")
    ids: set[str] = set()
    required_fields = {
        "mutant_id", "path", "old", "new", "operator",
        "requirement_id", "selected_command",
    }
    for mutant in mutants:
        if not isinstance(mutant, dict) or set(mutant) != required_fields:
            raise ValueError("curated mutant has unexpected fields")
        mutant_id = mutant["mutant_id"]
        if not isinstance(mutant_id, str) or mutant_id in ids:
            raise ValueError("curated mutant ID is invalid or duplicated")
        ids.add(mutant_id)
        normalize_repo_path(mutant["path"])
        if not all(
            isinstance(mutant.get(field), str) and mutant[field]
            for field in ("old", "new", "operator", "requirement_id")
        ):
            raise ValueError("curated mutant transformation is incomplete")
        command = mutant["selected_command"]
        if not isinstance(command, list) or not command or not all(
            isinstance(item, str) and item for item in command
        ):
            raise ValueError("curated mutant command is malformed")
    if ids != REQUIRED_CURATED_MUTANTS:
        raise ValueError("curated mutation corpus does not exactly match protected IDs")
    return document


def load_curated_corpus(path: Path) -> dict[str, Any]:
    """Load the protected finite corpus without accepting unknown operations."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError("curated mutation corpus is unavailable or malformed") from exc
    return parse_curated_corpus(data)


def apply_curated_mutant(candidate_copy: Path, mutant: Mapping[str, Any]) -> str:
    """Apply one exact protected text mutation to a disposable candidate copy."""
    root = candidate_copy.resolve(strict=True)
    relative = normalize_repo_path(mutant.get("path"))
    target = root.joinpath(*relative.split("/"))
    if target.is_symlink() or not target.is_file():
        raise ValueError("mutant target must be a regular candidate file")
    target.resolve(strict=True).relative_to(root)
    try:
        text = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("mutant target must be UTF-8 text") from exc
    old = mutant.get("old")
    new = mutant.get("new")
    if not isinstance(old, str) or not isinstance(new, str) or text.count(old) != 1:
        raise ValueError("curated mutant precondition did not match exactly once")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")
    return sha256_canonical(
        {"path": relative, "old": old, "new": new, "operator": mutant.get("operator")}
    )


def mutation_record_id(record: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a fully packaged mutant observation to all fields except its own ID."""
    return content_address(dict(record), "mutant_record_id")
