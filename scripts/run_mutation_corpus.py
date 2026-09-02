#!/usr/bin/env python3
"""Run the protected semantic corpus in one disposable copy per mutant.

This runner produces deterministic local proof. Admission additionally requires
the same runner to be invoked by the protected disposable-container supervisor
and packaged with sandbox/provenance evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from codex_governance.canonical import canonical_json_bytes
from codex_governance.mutation import (
    apply_curated_mutant,
    build_mutation_probe_command,
    causal_mutation_pair_outcome,
    classify_mutation_execution,
    load_curated_corpus,
)
from codex_governance.sandbox import prepare_candidate_copy


def run(
    command: list[str], cwd: Path, timeout: int
) -> tuple[str, int | None, bytes, str]:
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": "src",
        "LANG": "C.UTF-8",
    }
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "UNKNOWN", None, b"", "timeout"
    except OSError:
        return "UNKNOWN", None, b"", "not_launched"
    return (
        "PASS" if completed.returncode == 0 else "FAIL",
        completed.returncode,
        completed.stdout,
        "exited",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--corpus", type=Path, default=Path("tests/mutation/corpus.json"))
    parser.add_argument("--evidence-root", default="artifacts/governance")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    corpus = load_curated_corpus(args.corpus)
    baseline, baseline_exit, _, _ = run(
        corpus["baseline_command"], repository, args.timeout
    )
    if baseline != "PASS":
        sys.stdout.buffer.write(canonical_json_bytes(
            {"state": "UNKNOWN", "baseline": baseline, "baseline_exit": baseline_exit, "mutants": []}
        ) + b"\n")
        return 2
    results = []
    with tempfile.TemporaryDirectory(prefix="codex-governance-mutation-") as directory:
        root = Path(directory).resolve()
        for index, mutant in enumerate(corpus["mutants"], 1):
            command = build_mutation_probe_command(
                mutant["path"], mutant["selected_command"]
            )
            control = prepare_candidate_copy(
                repository=repository,
                destination=root / f"control-{index}",
                evidence_root=args.evidence_root,
            )
            control_observed, control_exit, control_stdout, control_termination = run(
                command, control, args.timeout
            )
            control_outcome = classify_mutation_execution(
                status=control_observed,
                termination_kind=control_termination,
                exit_code=control_exit,
                stdout=control_stdout,
            )
            if control_outcome != "SURVIVED":
                results.append(
                    {
                        "mutant_id": mutant["mutant_id"],
                        "outcome": "UNKNOWN",
                        "control_outcome": control_outcome,
                        "control_exit": control_exit,
                    }
                )
                continue
            candidate = prepare_candidate_copy(
                repository=repository,
                destination=root / f"mutant-{index}",
                evidence_root=args.evidence_root,
            )
            try:
                patch_sha256 = apply_curated_mutant(candidate, mutant)
            except (OSError, ValueError):
                results.append({"mutant_id": mutant["mutant_id"], "outcome": "INVALID"})
                continue
            observed, exit_code, stdout, termination = run(
                command, candidate, args.timeout
            )
            outcome = causal_mutation_pair_outcome(
                control_outcome,
                classify_mutation_execution(
                    status=observed,
                    termination_kind=termination,
                    exit_code=exit_code,
                    stdout=stdout,
                ),
            )
            results.append({
                "mutant_id": mutant["mutant_id"],
                "outcome": outcome,
                "control_outcome": control_outcome,
                "control_exit": control_exit,
                "patch_sha256": patch_sha256,
                "selected_exit": exit_code,
            })
    complete = all(item["outcome"] == "KILLED" for item in results)
    summary = {
        "state": "PASS" if complete else "BLOCK",
        "baseline": baseline,
        "corpus_id": corpus["corpus_id"],
        "mutants": results,
        "limitations": ["local proof is not sandbox provenance or admission evidence"],
    }
    sys.stdout.buffer.write(canonical_json_bytes(summary) + b"\n")
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
