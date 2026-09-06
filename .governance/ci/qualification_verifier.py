#!/usr/bin/env python3
"""Recompute protected reviewer qualification from every approved case."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from common import (
    canonical_bytes,
    ensure_within,
    load_and_validate_once,
    load_json,
    read_bytes_once,
    require_digest,
    sha256_bytes,
)


AUTHORITY_ROOT = Path(__file__).resolve().parents[2]
KERNEL_SOURCE = AUTHORITY_ROOT / "kernel" / "src"
if str(KERNEL_SOURCE) not in sys.path:
    sys.path.insert(0, str(KERNEL_SOURCE))

from codex_governance.domain.model import DispositionState  # noqa: E402
from codex_governance.qualification import (  # noqa: E402
    REVIEWER_IDENTITY_FIELDS,
    qualification_evidence_valid,
    reviewer_qualification_state,
)
from codex_governance.reviewer import reviewer_launcher_sha256  # noqa: E402


MODEL = "gpt-5.6-sol"
REASONING_EFFORT = "xhigh"
CODEX_CLI_VERSION = "codex-cli 0.153.0"
EXPECTED_CASE_IDS = (
    "Q-CANDIDATE-UNTRACKED-001",
    "Q-REVIEWER-RULE-LEAK-002",
    "Q-UNKNOWN-AS-PASS-003",
    "Q-GATE-TIMEOUT-004",
    "Q-GOVERNANCE-SELF-AUTHORITY-005",
    "Q-WRITABLE-AUTHORITY-006",
    "Q-PROVENANCE-FORGERY-007",
    "Q-CLEAN-CONTROL-008",
)
QUALIFICATION_ARTIFACT_PREFIX = PurePosixPath("qualification")


def _object(path: Path, name: str) -> dict[str, Any]:
    value = load_json(path)
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    return dict(value)


def validate_qualification_bundle(
    *,
    corpus_path: Path,
    label_decision_path: Path,
    conformance_record_path: Path,
    conformance_cases_path: Path,
    rapid_record_path: Path,
    rapid_cases_path: Path,
    policy_path: Path | None,
    authenticated_label_decision_id: str,
    artifact_root: Path,
    expected_timeout_seconds: int,
    expected_max_output_bytes: int,
) -> dict[str, str]:
    if (
        not isinstance(expected_timeout_seconds, int)
        or isinstance(expected_timeout_seconds, bool)
        or expected_timeout_seconds < 1
        or not isinstance(expected_max_output_bytes, int)
        or isinstance(expected_max_output_bytes, bool)
        or expected_max_output_bytes < 1
    ):
        raise ValueError("protected qualification limits are invalid")
    corpus = _object(corpus_path, "qualification corpus")
    label_decision = _object(label_decision_path, "qualification label decision")
    records = {
        "conformance": _object(conformance_record_path, "conformance record"),
        "rapid_review": _object(rapid_record_path, "rapid-review record"),
    }
    case_documents = {
        "conformance": _object(conformance_cases_path, "conformance cases"),
        "rapid_review": _object(rapid_cases_path, "rapid-review cases"),
    }
    corpus_cases = corpus.get("cases")
    if (
        corpus.get("human_labelled") is not True
        or not isinstance(corpus_cases, list)
        or tuple(item.get("case_id") for item in corpus_cases if isinstance(item, Mapping))
        != EXPECTED_CASE_IDS
        or [item.get("expected_disposition") for item in corpus_cases]
        != ["BLOCK"] * 7 + ["NO_BLOCKING_FINDING_OBSERVED"]
    ):
        raise ValueError("protected qualification corpus is not the approved eight-case corpus")
    decision_id = require_digest(
        label_decision.get("decision_id"), "qualification label decision"
    )
    issuer = label_decision.get("issuer")
    if (
        authenticated_label_decision_id != decision_id
        or not isinstance(issuer, Mapping)
        or issuer.get("subject") != "github:timaday"
    ):
        raise ValueError("qualification labels lack authenticated GitHub-owner approval")

    for path, schema_name in (
        (corpus_path, "reviewer-qualification-corpus"),
        (label_decision_path, "reviewer-qualification-label-decision"),
        (conformance_cases_path, "reviewer-qualification-cases"),
        (rapid_cases_path, "reviewer-qualification-cases"),
    ):
        load_and_validate_once(
            path, AUTHORITY_ROOT / f"kernel/schemas/{schema_name}.schema.json"
        )

    root = artifact_root.absolute()

    def read_artifact(reference: Mapping[str, Any]) -> bytes:
        value = reference.get("path")
        if not isinstance(value, str):
            raise ValueError("qualification artifact path is missing")
        path = PurePosixPath(value)
        try:
            relative = path.relative_to(QUALIFICATION_ARTIFACT_PREFIX)
        except ValueError as error:
            raise ValueError("qualification artifact path has the wrong prefix") from error
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("qualification artifact path is unsafe")
        current = ensure_within(root, root.joinpath(*relative.parts))
        return read_bytes_once(current)

    corpus_bytes = read_bytes_once(corpus_path)
    corpus_sha256 = sha256_bytes(corpus_bytes)
    prompt_path = AUTHORITY_ROOT / "kernel/.codex/review/reviewer.prompt.md"
    prompt_bytes = read_bytes_once(prompt_path)
    prompt_sha256 = sha256_bytes(prompt_bytes)
    identities = {
        "conformance": {
            "prompt_sha256": prompt_sha256,
            "schema_sha256": sha256_bytes(
                read_bytes_once(
                    AUTHORITY_ROOT / "kernel/schemas/reviewer-result.schema.json"
                )
            ),
            "launcher_sha256": reviewer_launcher_sha256(
                AUTHORITY_ROOT / "kernel/src/codex_governance"
            ),
            "codex_cli_version": CODEX_CLI_VERSION,
            "authentication": "chatgpt",
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "timeout_seconds": expected_timeout_seconds,
            "max_output_bytes": expected_max_output_bytes,
        },
        "rapid_review": {
            "prompt_sha256": prompt_sha256,
            "schema_sha256": sha256_bytes(
                read_bytes_once(
                    AUTHORITY_ROOT
                    / "kernel/schemas/rapid-review-session.schema.json"
                )
            ),
            "launcher_sha256": reviewer_launcher_sha256(
                AUTHORITY_ROOT / "kernel/src/codex_governance"
            ),
            "codex_cli_version": CODEX_CLI_VERSION,
            "authentication": "chatgpt",
            "model": MODEL,
            "reasoning_effort": REASONING_EFFORT,
            "timeout_seconds": expected_timeout_seconds,
            "max_output_bytes": expected_max_output_bytes,
        },
    }
    policy = _object(policy_path, "effective policy") if policy_path else None
    protected_ids = (
        policy.get("reviewer", {}).get("qualification_ids", {})
        if policy is not None
        else {mode: records[mode].get("qualification_id") for mode in records}
    )
    if policy is not None and (
        policy.get("reviewer", {}).get("qualification_corpus_sha256")
        != corpus_sha256
        or policy.get("reviewer", {}).get("qualification_label_decision_id")
        != decision_id
        or policy.get("reviewer", {}).get("model") != MODEL
        or policy.get("reviewer", {}).get("reasoning_effort") != REASONING_EFFORT
        or policy.get("reviewer", {}).get("timeout_seconds")
        != expected_timeout_seconds
        or policy.get("reviewer", {}).get("max_output_bytes")
        != expected_max_output_bytes
    ):
        raise ValueError("protected policy does not bind the exact qualification corpus")

    for mode in ("conformance", "rapid_review"):
        record_path = (
            conformance_record_path if mode == "conformance" else rapid_record_path
        )
        load_and_validate_once(
            record_path,
            AUTHORITY_ROOT / "kernel/schemas/reviewer-qualification.schema.json",
        )
        if set(identities[mode]) != set(REVIEWER_IDENTITY_FIELDS):
            raise ValueError("qualification identity field inventory drifted")
        if not qualification_evidence_valid(
            mode=mode,
            record=records[mode],
            case_evidence=case_documents[mode],
            corpus=corpus,
            corpus_bytes=corpus_bytes,
            protected_corpus_sha256=corpus_sha256,
            label_decision=label_decision,
            artifact_reader=read_artifact,
            schema_root=AUTHORITY_ROOT / "kernel/schemas",
            protected_repository_id=str(label_decision["repository_id"]),
            verified_decision_ids=frozenset({decision_id}),
            evaluated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            prompt_bytes=prompt_bytes,
        ):
            raise ValueError(f"{mode} per-case qualification evidence does not reconstruct")
        if reviewer_qualification_state(
            identities[mode],
            records[mode],
            protected_qualification_id=protected_ids.get(mode),
            protected_corpus_sha256=corpus_sha256,
            protected_label_decision_id=decision_id,
        ) is not DispositionState.READY_FOR_HUMAN:
            raise ValueError(f"{mode} qualification is not protected and qualified")
    return {
        "corpus_sha256": corpus_sha256,
        "label_decision_id": decision_id,
        "conformance_qualification_id": str(records["conformance"]["qualification_id"]),
        "rapid_review_qualification_id": str(records["rapid_review"]["qualification_id"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--label-decision", type=Path, required=True)
    parser.add_argument("--conformance-record", type=Path, required=True)
    parser.add_argument("--conformance-cases", type=Path, required=True)
    parser.add_argument("--rapid-record", type=Path, required=True)
    parser.add_argument("--rapid-cases", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--authenticated-label-decision-id", required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--expected-timeout-seconds", type=int, required=True)
    parser.add_argument("--expected-max-output-bytes", type=int, required=True)
    args = parser.parse_args()
    result = validate_qualification_bundle(
        corpus_path=args.corpus,
        label_decision_path=args.label_decision,
        conformance_record_path=args.conformance_record,
        conformance_cases_path=args.conformance_cases,
        rapid_record_path=args.rapid_record,
        rapid_cases_path=args.rapid_cases,
        policy_path=args.policy,
        authenticated_label_decision_id=args.authenticated_label_decision_id,
        artifact_root=args.artifact_root,
        expected_timeout_seconds=args.expected_timeout_seconds,
        expected_max_output_bytes=args.expected_max_output_bytes,
    )
    print(canonical_bytes(result).decode("utf-8"))


if __name__ == "__main__":
    main()
