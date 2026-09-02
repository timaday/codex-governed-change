"""Pure governance mutation selection and outcome policy."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    normalize_repo_path,
    require_git_object,
    require_sha256,
    sha256_bytes,
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
        "nested-source-credential",
        "rollback-output-unbound",
        "legacy-context-schema",
        "gate-copy-source-identity",
        "mutation-copy-source-identity",
        "candidate-owned-corpus",
        "candidate-owned-rollback",
        "incomplete-migration-registry",
        "ignored-submodule-copy",
        "unframed-rollback-package",
        "rollback-sibling-sitecustomize",
        "noncausal-mutation-kill",
        "submodule-head-only",
        "raw-stderr-source-literal",
        "qualification-output-unchecked",
        "artifact-leaf-rebind",
        "fcntl-signal-escape",
        "qualification-blanket-block",
        "mutant-subject-confusion",
        "provenance-prompt-unchecked",
        "provenance-materials-unchecked",
    }
)

MUTATION_KILLED_EXIT = 100
MUTATION_UNKNOWN_EXIT = 119
MUTATION_INVALID_EXIT = 120
MUTATION_PROBE_PREFIX = b"CODEX_MUTATION_PROBE="
MUTATION_PROBE_SENTINEL = "<PROTECTED_MUTATION_PROBE>"
MUTATION_PATH_SENTINEL = "<MUTATED_PATH>"
UNITTEST_SELECTION_RE = re.compile(r"^tests(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
MUTATION_PROBE_FIELDS = frozenset(
    {
        "schema_version", "outcome", "tests_run", "failures", "errors",
        "skipped", "expected_failures", "unexpected_successes",
    }
)

MUTATION_PROBE_SOURCE = """import json, os, py_compile, sys, unittest
PREFIX = 'CODEX_MUTATION_PROBE='
FIELDS = ('tests_run', 'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes')
def emit(outcome, counts=None):
    values = {name: 0 for name in FIELDS}
    if counts is not None:
        values.update(counts)
    payload = {'schema_version': '1.0.0', 'outcome': outcome, **values}
    print(PREFIX + json.dumps(payload, sort_keys=True, separators=(',', ':')), flush=True)
path, names = sys.argv[1], sys.argv[2:]
if path.endswith('.py'):
    try:
        py_compile.compile(path, doraise=True)
    except py_compile.PyCompileError:
        emit('INVALID')
        raise SystemExit(120)
try:
    sys.path[:0] = [os.path.join(os.getcwd(), 'src'), os.getcwd()]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    counts = {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'skipped': len(result.skipped),
        'expected_failures': len(result.expectedFailures),
        'unexpected_successes': len(result.unexpectedSuccesses),
    }
except BaseException:
    emit('UNKNOWN')
    raise SystemExit(119)
if counts['tests_run'] > 0 and counts['failures'] > 0 and all(
    counts[name] == 0
    for name in ('errors', 'skipped', 'expected_failures', 'unexpected_successes')
):
    emit('KILLED', counts)
    raise SystemExit(100)
if counts['tests_run'] > 0 and all(counts[name] == 0 for name in FIELDS[1:]):
    emit('SURVIVED', counts)
    raise SystemExit(0)
emit('UNKNOWN', counts)
raise SystemExit(119)
"""


def selected_mutation_tests(selected_command: Sequence[str]) -> list[str]:
    if (
        len(selected_command) < 7
        or list(selected_command[:6])
        != [
            "python3", "-I", "-S", "-c",
            MUTATION_PROBE_SENTINEL, MUTATION_PATH_SENTINEL,
        ]
    ):
        raise ValueError(
            "selected mutation command must be the protected unittest probe template"
        )
    names = list(selected_command[6:])
    if not names or any(
        not isinstance(name, str) or UNITTEST_SELECTION_RE.fullmatch(name) is None
        for name in names
    ):
        raise ValueError("selected mutation unittest names are malformed")
    return names


def build_mutation_probe_command(
    path: str, selected_command: Sequence[str]
) -> list[str]:
    relative = normalize_repo_path(path)
    names = selected_mutation_tests(selected_command)
    return [
        "python3", "-I", "-S", "-c", MUTATION_PROBE_SOURCE, relative, *names,
    ]


def mutation_probe_outcome(stdout: bytes, exit_code: int | None) -> str:
    """Reconstruct one exact terminal probe observation from bounded raw stdout."""
    if not isinstance(stdout, bytes) or not stdout.endswith(b"\n"):
        return "UNKNOWN"
    if stdout.count(MUTATION_PROBE_PREFIX) != 1:
        return "UNKNOWN"
    lines = stdout.splitlines()
    if not lines or not lines[-1].startswith(MUTATION_PROBE_PREFIX):
        return "UNKNOWN"
    raw = lines[-1][len(MUTATION_PROBE_PREFIX):]
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "UNKNOWN"
    if (
        not isinstance(payload, dict)
        or set(payload) != MUTATION_PROBE_FIELDS
        or payload.get("schema_version") != "1.0.0"
        or raw != canonical_json_bytes(payload)
    ):
        return "UNKNOWN"
    counts = [
        payload.get(name)
        for name in (
            "tests_run", "failures", "errors", "skipped",
            "expected_failures", "unexpected_successes",
        )
    ]
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in counts
    ):
        return "UNKNOWN"
    tests_run, failures, errors, skipped, expected_failures, unexpected = counts
    outcome = payload.get("outcome")
    if (
        outcome == "KILLED"
        and exit_code == MUTATION_KILLED_EXIT
        and tests_run > 0
        and failures > 0
        and errors == skipped == expected_failures == unexpected == 0
    ):
        return "KILLED"
    if (
        outcome == "SURVIVED"
        and exit_code == 0
        and tests_run > 0
        and failures == errors == skipped == expected_failures == unexpected == 0
    ):
        return "SURVIVED"
    if outcome == "INVALID" and exit_code == MUTATION_INVALID_EXIT and not any(counts):
        return "INVALID"
    return "UNKNOWN"


def classify_mutation_execution(
    *, status: str, termination_kind: str, exit_code: int | None, stdout: bytes
) -> str:
    """Map only matching gate state and protected probe proof to an outcome."""
    if termination_kind == "timeout":
        return "TIMEOUT"
    observed = mutation_probe_outcome(stdout, exit_code)
    if status == "PASS" and observed == "SURVIVED":
        return "SURVIVED"
    if status == "FAIL" and observed in {"KILLED", "INVALID"}:
        return observed
    return "UNKNOWN"


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


def _git(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", os.fspath(repository), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("Git-visible mutation source observation failed")
    return completed.stdout


def git_visible_tree_sha256(
    repository: Path,
    *,
    evidence_root: str,
    replacements: Mapping[str, bytes] | None = None,
) -> str:
    """Hash every Git-visible source byte in one concrete candidate tree."""
    root = repository.resolve(strict=True)
    evidence = normalize_repo_path(evidence_root)
    replacement_bytes = {
        normalize_repo_path(path): bytes(data)
        for path, data in (replacements or {}).items()
    }
    return _git_visible_tree_sha256(
        root,
        evidence_root=evidence,
        replacements=replacement_bytes,
        ancestors=frozenset(),
    )


def _git_visible_tree_sha256(
    root: Path,
    *,
    evidence_root: str | None,
    replacements: Mapping[str, bytes],
    ancestors: frozenset[Path],
) -> str:
    """Recursively frame one repository and all initialized submodule trees."""
    root = root.resolve(strict=True)
    if root in ancestors:
        raise ValueError("recursive submodule cycle is not admissible")
    nested_ancestors = ancestors | {root}
    modes: dict[str, str] = {}
    for raw in _git(root, "ls-files", "--stage", "-z").split(b"\x00"):
        if not raw:
            continue
        metadata, raw_path = raw.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        modes[normalize_repo_path(raw_path.decode("utf-8"))] = mode
    entries: list[dict[str, Any]] = []
    names = _git(
        root, "ls-files", "-z", "--cached", "--others", "--exclude-standard"
    )
    seen: set[str] = set()
    for raw in names.split(b"\x00"):
        if not raw:
            continue
        path = normalize_repo_path(raw.decode("utf-8"))
        if path in seen or (
            evidence_root is not None
            and (path == evidence_root or path.startswith(evidence_root + "/"))
        ):
            continue
        seen.add(path)
        absolute = root.joinpath(*path.split("/"))
        mode = modes.get(path)
        if mode == "160000":
            nested_root = absolute.resolve(strict=True)
            try:
                nested_root.relative_to(root)
            except ValueError as exc:
                raise ValueError("Git-visible submodule escapes its repository") from exc
            commit = require_git_object(
                _git(nested_root, "rev-parse", "HEAD").decode("ascii").strip(),
                name="submodule commit",
            )
            entries.append(
                {
                    "path": path,
                    "mode": mode,
                    "submodule_commit": commit,
                    "submodule_tree_sha256": _git_visible_tree_sha256(
                        nested_root,
                        evidence_root=None,
                        replacements={},
                        ancestors=nested_ancestors,
                    ),
                }
            )
            continue
        if path in replacements:
            data = replacements[path]
            if mode is None:
                info = absolute.lstat()
                mode = "100755" if info.st_mode & 0o111 else "100644"
        elif not absolute.exists() and not absolute.is_symlink():
            entries.append({"path": path, "mode": mode or "missing", "missing": True})
            continue
        else:
            info = absolute.lstat()
            if stat.S_ISLNK(info.st_mode):
                data = os.fsencode(os.readlink(absolute))
                mode = "120000"
            elif stat.S_ISREG(info.st_mode):
                data = absolute.read_bytes()
                mode = "100755" if info.st_mode & 0o111 else "100644"
            else:
                raise ValueError("Git-visible mutation source contains an unsafe type")
        entries.append(
            {"path": path, "mode": mode, "bytes": len(data), "sha256": sha256_bytes(data)}
        )
    if set(replacements) - seen:
        raise ValueError("mutation replacement path is not Git-visible")
    return sha256_canonical({"schema_version": "1.0.0", "entries": entries})


def expected_mutated_tree_sha256(
    *, repository: Path, evidence_root: str, mutant: Mapping[str, Any]
) -> str:
    """Compute the concrete tree identity after one protected virtual patch."""
    root = repository.resolve(strict=True)
    relative = normalize_repo_path(mutant.get("path"))
    target = root.joinpath(*relative.split("/"))
    if target.is_symlink() or not target.is_file():
        raise ValueError("mutant target must be a regular candidate file")
    text = target.read_text(encoding="utf-8")
    old = mutant.get("old")
    new = mutant.get("new")
    if not isinstance(old, str) or not isinstance(new, str) or text.count(old) != 1:
        raise ValueError("curated mutant precondition did not match exactly once")
    replaced = text.replace(old, new, 1).encode("utf-8")
    return git_visible_tree_sha256(
        root, evidence_root=evidence_root, replacements={relative: replaced}
    )


def mutated_source_identity(
    *,
    candidate_id: str,
    corpus_id: str,
    mutant_id: str,
    patch_sha256: str,
    tree_sha256: str,
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
            "tree_sha256": require_sha256(tree_sha256, name="tree_sha256"),
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
        selected_mutation_tests(command)
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
