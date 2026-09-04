"""Standalone in-toto-shaped unsigned provenance statements."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_governance.canonical import (
    content_address,
    require_sha256,
    sha256_bytes,
    sha256_canonical,
    verify_content_address,
)
from codex_governance.lifecycle import validate_time_order


STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://timaday.github.io/codex-governed-change/"
    "attestation/governance-provenance/v1"
)


def producer_implementation_manifest(
    producer_kind: str, package_root: Path | None = None
) -> dict[str, Any]:
    """Frame the complete trusted Python package closure for one producer."""
    if producer_kind not in {"gate", "mutation"}:
        raise ValueError("unknown producer kind")
    root = (package_root or Path(__file__).resolve().parent).resolve(strict=True)
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.py"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError("producer implementation closure contains an unsafe file")
        data = path.read_bytes()
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": len(data),
                "sha256": sha256_bytes(data),
            }
        )
    if not files:
        raise ValueError("producer implementation closure is empty")
    return {
        "schema_version": "1.0.0",
        "producer_kind": producer_kind,
        "files": files,
    }


def gate_implementation_sha256(package_root: Path | None = None) -> str:
    """Identify the complete protected gate producer closure."""
    return sha256_canonical(
        producer_implementation_manifest("gate", package_root)
    )


def mutation_implementation_sha256(package_root: Path | None = None) -> str:
    """Identify the complete protected mutation producer closure."""
    return sha256_canonical(
        producer_implementation_manifest("mutation", package_root)
    )


def _hex_digest(value: str) -> str:
    return require_sha256(value).split(":", 1)[1]


def build_provenance_statement(
    *,
    repository_id: str,
    candidate_id: str,
    repository_digest: str,
    task_contract_sha256: str,
    effective_policy_sha256: str,
    gate_definition_sha256: str,
    reviewer_prompt_sha256: str,
    producer: Mapping[str, Any],
    workflow: Mapping[str, Any],
    tools: Sequence[Mapping[str, Any]],
    environment: Mapping[str, Any],
    materials: Sequence[Mapping[str, Any]],
    started_at: str,
    ended_at: str,
    result: str,
    limits: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
    limitations: Sequence[str],
) -> dict[str, Any]:
    if not repository_id.startswith("repo:") or not validate_time_order(started_at, ended_at):
        raise ValueError("invalid repository identity or provenance time order")
    require_sha256(candidate_id, name="candidate_id")
    document: dict[str, Any] = {
        "schema_version": "2.0.0",
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": repository_id, "digest": {"sha256": _hex_digest(repository_digest)}},
            {"name": "candidate", "digest": {"sha256": _hex_digest(candidate_id)}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "repository_id": repository_id,
            "candidate_id": candidate_id,
            "task_contract_sha256": require_sha256(task_contract_sha256),
            "effective_policy_sha256": require_sha256(effective_policy_sha256),
            "gate_definition_sha256": require_sha256(gate_definition_sha256),
            "reviewer_prompt_sha256": require_sha256(reviewer_prompt_sha256),
            "producer": dict(producer),
            "workflow": dict(workflow),
            "tools": [dict(item) for item in tools],
            "environment": dict(environment),
            "materials": [dict(item) for item in materials],
            "started_at": started_at,
            "ended_at": ended_at,
            "result": result,
            "limits": dict(limits),
            "artifacts": [dict(item) for item in artifacts],
            "limitations": list(limitations),
            "signed": False,
        },
    }
    return content_address(document, "statement_id")


def verify_provenance_statement(
    statement: Mapping[str, Any], repository_id: str, candidate_id: str,
    repository_digest: str | None = None,
) -> bool:
    if not verify_content_address(statement, "statement_id"):
        return False
    if statement.get("schema_version") != "2.0.0":
        return False
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        return False
    predicate = statement.get("predicate")
    if not isinstance(predicate, Mapping):
        return False
    if predicate.get("repository_id") != repository_id or predicate.get("candidate_id") != candidate_id:
        return False
    if predicate.get("signed") is not False:
        return False
    if not validate_time_order(str(predicate.get("started_at")), str(predicate.get("ended_at"))):
        return False
    expected_repository_digest = (
        _hex_digest(repository_digest) if repository_digest is not None else None
    )
    expected = {
        repository_id: expected_repository_digest,
        "candidate": _hex_digest(candidate_id),
    }
    observed: dict[str, Any] = {repository_id: None, "candidate": None}
    for subject in statement.get("subject", ()):
        if not isinstance(subject, Mapping):
            return False
        name = subject.get("name")
        digest = subject.get("digest")
        if name in observed and isinstance(digest, Mapping):
            if observed[str(name)] is not None:
                return False
            observed[str(name)] = digest.get("sha256")
    repository_matches = observed[repository_id] is not None and (
        expected_repository_digest is None
        or observed[repository_id] == expected_repository_digest
    )
    return repository_matches and observed["candidate"] == expected["candidate"]
