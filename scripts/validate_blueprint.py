#!/usr/bin/env python3
"""Validate the implementation blueprint without third-party dependencies."""

from __future__ import annotations

import hashlib
import json
import py_compile
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []

REQUIRED_PATHS = [
    "README.md",
    "IMPLEMENTATION_STATUS.md",
    "IMPLEMENT_WITH_GPT_5_6.md",
    "AGENTS.md",
    "docs/specification.md",
    "docs/requirements.md",
    "docs/architecture.md",
    "docs/architecture-hardening-delta.md",
    "docs/implementation-plan.md",
    "docs/test-strategy.md",
    "docs/threat-model.md",
    "docs/traceability.md",
    "docs/adoption.md",
    "docs/research.md",
    ".agents/skills/governed-change/SKILL.md",
    ".agents/skills/governed-change/agents/openai.yaml",
    ".agents/skills/governed-change/references/code-profile.md",
    ".agents/skills/governed-change/references/spec-profile.md",
    ".agents/skills/governed-change/references/evidence-policy.md",
    ".codex/agents/independent-reviewer.toml",
    ".codex/review/reviewer.prompt.md",
    ".codex/hooks.json.example",
    "scripts/stop_hook.py",
    ".github/CODEOWNERS",
    ".github/workflows/blueprint-quality.yml",
]

EXAMPLE_SCHEMAS = {
    "examples/task-contract.json": "schemas/task-contract.schema.json",
    "examples/candidate.json": "schemas/candidate.schema.json",
    "examples/gate-result.json": "schemas/gate-result.schema.json",
    "examples/reviewer-result.json": "schemas/reviewer-result.schema.json",
    "examples/evidence-manifest.json": "schemas/evidence-manifest.schema.json",
    "examples/disposition.json": "schemas/disposition.schema.json",
    "examples/waiver.json": "schemas/waiver.schema.json",
    "examples/risk-assessment.json": "schemas/risk-assessment.schema.json",
    "examples/review-charter.json": "schemas/review-charter.schema.json",
    "examples/rapid-review-session.json": "schemas/rapid-review-session.schema.json",
    "examples/rapid-review-debrief.json": "schemas/rapid-review-debrief.schema.json",
    "examples/risk-disposition.json": "schemas/risk-disposition.schema.json",
    "examples/effective-policy.json": "schemas/effective-policy.schema.json",
    "examples/gate-manifest.json": "schemas/gate-manifest.schema.json",
    "examples/authenticated-decision.json": "schemas/authenticated-decision.schema.json",
    "examples/evidence-locator.json": "schemas/evidence-locator.schema.json",
    "examples/assurance-case.json": "schemas/assurance-case.schema.json",
    "examples/sandbox-capability.json": "schemas/sandbox-capability.schema.json",
    "examples/provenance-statement.json": "schemas/provenance-statement.schema.json",
    "examples/mutant-record.json": "schemas/mutant-record.schema.json",
    "examples/context-receipt.json": "schemas/context-receipt.schema.json",
    "examples/context-qualification.json": "schemas/context-qualification.schema.json",
    "examples/context-source-bundle.json": "schemas/context-source-bundle.schema.json",
    "examples/context-projection.json": "schemas/context-projection.schema.json",
    "examples/context-execution-receipt.json": "schemas/context-execution-receipt.schema.json",
    "examples/reviewer-execution.json": "schemas/reviewer-execution.schema.json",
    "examples/risk-register.json": "schemas/risk-register.schema.json",
    "examples/oracle-reference.json": "schemas/oracle-reference.schema.json",
    "examples/coverage-note.json": "schemas/coverage-note.schema.json",
    "examples/follow-up.json": "schemas/follow-up.schema.json",
    "examples/reviewer-qualification.json": "schemas/reviewer-qualification.schema.json",
    "examples/reviewer-qualification-cases.json": "schemas/reviewer-qualification-cases.schema.json",
    "examples/reviewer-qualification-corpus.json": "schemas/reviewer-qualification-corpus.schema.json",
    "examples/reviewer-qualification-label-decision.json": "schemas/reviewer-qualification-label-decision.schema.json",
    "examples/rollback-evidence.json": "schemas/rollback-evidence.schema.json",
}


def fail(message: str) -> None:
    ERRORS.append(message)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read UTF-8 text {path.relative_to(ROOT)}: {exc}")
        return ""


def load_json(path: Path) -> Any:
    try:
        return json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
        return None


def resolve_local_ref(root_schema: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise ValueError(f"only local refs are supported by blueprint validation: {ref}")
    current: Any = root_schema
    for raw_part in ref[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        current = current[part]
    return current


def type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ValueError(f"unsupported schema type: {expected}")


def validate_instance(
    value: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    location: str,
) -> None:
    if "$ref" in schema:
        try:
            target = resolve_local_ref(root_schema, schema["$ref"])
        except (KeyError, TypeError, ValueError) as exc:
            fail(f"{location}: unresolved schema ref {schema['$ref']}: {exc}")
            return
        validate_instance(value, target, root_schema, location)
        return

    if "const" in schema and value != schema["const"]:
        fail(f"{location}: expected const {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        fail(f"{location}: value {value!r} not in enum {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
        if not any(type_matches(value, item) for item in expected_types):
            fail(f"{location}: expected type {expected_types!r}, got {type(value).__name__}")
            return

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                fail(f"{location}: missing required property {key!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    fail(f"{location}: unexpected property {key!r}")
        for key, child in value.items():
            if key in properties:
                validate_instance(child, properties[key], root_schema, f"{location}.{key}")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            fail(f"{location}: expected at least {schema['minItems']} items")
        if schema.get("uniqueItems"):
            rendered = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(rendered) != len(set(rendered)):
                fail(f"{location}: array items must be unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_instance(item, item_schema, root_schema, f"{location}[{index}]")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            fail(f"{location}: string shorter than {schema['minLength']}")
        pattern = schema.get("pattern")
        if pattern and re.search(pattern, value) is None:
            fail(f"{location}: value {value!r} does not match {pattern!r}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            fail(f"{location}: value {value} is below minimum {schema['minimum']}")


def validate_required_paths() -> None:
    for relative in REQUIRED_PATHS:
        if not (ROOT / relative).is_file():
            fail(f"missing required file: {relative}")


def validate_text_hygiene() -> None:
    ignored_parts = {".git", "__pycache__", "artifacts", "build", "dist"}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in ignored_parts for part in path.parts):
            continue
        if path.suffix.lower() not in {".md", ".py", ".json", ".toml", ".yaml", ".yml", ".txt", ".example"} and path.name not in {"AGENTS.md", "LICENSE", "CODEOWNERS", ".gitignore", ".editorconfig"}:
            continue
        text = read_text(path)
        if text and not text.endswith("\n"):
            fail(f"missing final newline: {path.relative_to(ROOT)}")
        for number, line in enumerate(text.splitlines(), start=1):
            if line.rstrip() != line:
                fail(f"trailing whitespace: {path.relative_to(ROOT)}:{number}")
            if "\t" in line and path.suffix.lower() != ".py":
                fail(f"tab in text file: {path.relative_to(ROOT)}:{number}")


def validate_json_contracts() -> None:
    schemas: dict[str, dict[str, Any]] = {}
    for schema_path in sorted((ROOT / "schemas").glob("*.schema.json")):
        document = load_json(schema_path)
        if not isinstance(document, dict):
            continue
        schemas[str(schema_path.relative_to(ROOT))] = document
        if document.get("type") != "object":
            fail(f"root schema must be object: {schema_path.relative_to(ROOT)}")
        properties = document.get("properties", {})
        for required in document.get("required", []):
            if required not in properties:
                fail(f"schema required property not defined: {schema_path.name}:{required}")

    expected_schema_paths = set(EXAMPLE_SCHEMAS.values())
    missing_schemas = expected_schema_paths - set(schemas)
    for path in sorted(missing_schemas):
        fail(f"missing mapped schema: {path}")

    for example_relative, schema_relative in EXAMPLE_SCHEMAS.items():
        example = load_json(ROOT / example_relative)
        schema = schemas.get(schema_relative)
        if example is not None and schema is not None:
            validate_instance(example, schema, schema, example_relative)


def validate_toml() -> None:
    for relative in ["pyproject.toml", ".codex/config.toml"]:
        path = ROOT / relative
        try:
            tomllib.loads(read_text(path))
        except tomllib.TOMLDecodeError as exc:
            fail(f"invalid TOML {relative}: {exc}")


def validate_skill() -> None:
    skill = read_text(ROOT / ".agents/skills/governed-change/SKILL.md")
    match = re.match(r"\A---\n(.*?)\n---\n", skill, flags=re.DOTALL)
    if not match:
        fail("skill frontmatter is missing or malformed")
        return
    keys = []
    for line in match.group(1).splitlines():
        if ":" in line:
            keys.append(line.split(":", 1)[0].strip())
    if keys != ["name", "description"]:
        fail(f"skill frontmatter must contain only name and description, found {keys}")
    if "name: governed-change" not in match.group(0):
        fail("skill name must be governed-change")
    if len(skill.splitlines()) > 500:
        fail("SKILL.md exceeds 500 lines")

    metadata = read_text(ROOT / ".agents/skills/governed-change/agents/openai.yaml")
    for required in ["display_name: \"Governed Change\"", "short_description:", "$governed-change"]:
        if required not in metadata:
            fail(f"skill UI metadata missing {required!r}")


def validate_traceability() -> None:
    requirements_text = read_text(ROOT / "docs/requirements.md")
    requirements = sorted(set(re.findall(r"\bGOV-(?:[0-9]{3}|TOKEN-[0-9]{3})\b", requirements_text)))
    expected_numbered = [f"GOV-{number:03d}" for number in range(1, 63)]
    expected_named = [f"GOV-TOKEN-{number:03d}" for number in range(1, 5)]
    expected = sorted(expected_numbered + expected_named)
    if requirements != expected:
        fail("requirements must contain contiguous GOV-001..GOV-062 and GOV-TOKEN-001..004")

    traceability = read_text(ROOT / "docs/traceability.md")
    for requirement in expected:
        if re.search(rf"^\| {re.escape(requirement)} \|", traceability, flags=re.MULTILINE) is None:
            fail(f"requirement missing from traceability table: {requirement}")

    referenced_tests = set(re.findall(r"`(test_[a-z0-9_]+\.py)`", traceability))
    actual_tests = {path.name for path in (ROOT / "tests/acceptance").glob("test_*.py")}
    for name in sorted(referenced_tests - actual_tests):
        fail(f"traceability references missing test module: {name}")

    if len(actual_tests) < 7:
        fail(f"expected at least seven acceptance modules, found {len(actual_tests)}")


def validate_no_hidden_acceptance() -> None:
    forbidden = ["@unittest.skip", "@pytest.mark.skip", "expectedFailure", "skipTest(", "xfail("]
    for path in sorted((ROOT / "tests/acceptance").glob("test_*.py")):
        text = read_text(path)
        for marker in forbidden:
            if marker in text:
                fail(f"acceptance test contains forbidden skip/expected-failure marker {marker!r}: {path.name}")


def validate_python_syntax() -> None:
    for base in [ROOT / "src", ROOT / "tests", ROOT / "scripts"]:
        for path in sorted(base.rglob("*.py")):
            try:
                py_compile.compile(str(path), doraise=True)
            except py_compile.PyCompileError as exc:
                fail(f"Python syntax failure {path.relative_to(ROOT)}: {exc.msg}")


def validate_internal_links() -> None:
    markdown_paths = [path for path in ROOT.rglob("*.md") if ".git" not in path.parts]
    pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in markdown_paths:
        text = read_text(path)
        for target in pattern.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean = target.split("#", 1)[0]
            if not clean:
                continue
            resolved = (path.parent / clean).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                fail(f"internal link escapes repository: {path.relative_to(ROOT)} -> {target}")
                continue
            if not resolved.exists():
                fail(f"broken internal link: {path.relative_to(ROOT)} -> {target}")


def validate_status_honesty() -> None:
    status = read_text(ROOT / "IMPLEMENTATION_STATUS.md")
    for required in [
        "IMPLEMENTED_CANDIDATE",
        "FINAL_QUALIFICATION_UNKNOWN",
        "RELEASE_BLOCKED",
        "UNKNOWN",
        "BLOCK",
    ]:
        if required not in status:
            fail(f"implementation status missing {required}")
    pyproject = tomllib.loads(read_text(ROOT / "pyproject.toml"))
    project_status = pyproject.get("tool", {}).get("codex-governed-change", {})
    if project_status.get("implementation_status") != "IMPLEMENTED_CANDIDATE":
        fail("pyproject must declare implementation_status=IMPLEMENTED_CANDIDATE")
    if project_status.get("release_disposition") != "BLOCK":
        fail("pyproject must declare release_disposition=BLOCK until qualification")


def blueprint_digest() -> str:
    digest = hashlib.sha256()
    excluded = {".git", "__pycache__", "artifacts", "build", "dist"}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in excluded for part in path.parts):
            continue
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return "sha256:" + digest.hexdigest()


def main() -> int:
    validate_required_paths()
    validate_text_hygiene()
    validate_json_contracts()
    validate_toml()
    validate_skill()
    validate_traceability()
    validate_no_hidden_acceptance()
    validate_python_syntax()
    validate_internal_links()
    validate_status_honesty()

    if ERRORS:
        for error in ERRORS:
            print(f"BLUEPRINT_ERROR: {error}", file=sys.stderr)
        print(f"BLUEPRINT_QUALITY=FAIL errors={len(ERRORS)}", file=sys.stderr)
        return 1

    print(
        "BLUEPRINT_QUALITY=PASS "
        f"requirements=66 schemas={len(EXAMPLE_SCHEMAS)} examples={len(EXAMPLE_SCHEMAS)} "
        f"blueprint_sha256={blueprint_digest()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
