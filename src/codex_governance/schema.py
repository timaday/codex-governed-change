"""Fail-closed standard-library adapter for the protected schema subset."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from codex_governance.canonical import canonical_json_bytes, verify_content_address
from codex_governance.lifecycle import parse_rfc3339


CONTENT_ADDRESS_FIELDS = {
    "assurance-case": "assurance_case_id",
    "authenticated-decision": "decision_id",
    "context-receipt": "receipt_id",
    "context-execution-receipt": "execution_receipt_id",
    "coverage-note": "coverage_note_id",
    "evidence-locator": "locator_id",
    "evidence-manifest": "manifest_id",
    "follow-up": "follow_up_id",
    "gate-manifest": "gate_manifest_id",
    "mutant-record": "mutant_record_id",
    "oracle-reference": "oracle_id",
    "provenance-statement": "statement_id",
    "reviewer-qualification": "qualification_id",
    "reviewer-execution": "execution_id",
    "risk-assessment": "assessment_id",
    "risk-register": "risk_register_id",
    "rollback-evidence": "rollback_evidence_id",
    "sandbox-capability": "capability_id",
    "waiver": "waiver_id",
}


DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
JSON_TYPES = frozenset(
    {"object", "array", "string", "boolean", "integer", "number", "null"}
)
SUPPORTED_KEYWORDS = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type",
    "const", "enum", "required", "properties", "additionalProperties",
    "items", "minItems", "uniqueItems", "minLength", "pattern", "minimum",
}


class SchemaValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = tuple(errors)


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _resolve_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ValueError(f"unsupported non-local schema reference: {reference}")
    current: Any = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            raise ValueError(f"unresolved schema reference: {reference}")
        current = current[token]
    if not isinstance(current, dict):
        raise ValueError(f"schema reference does not target an object: {reference}")
    return current


def validate_schema_definition(schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if schema.get("$schema") != DRAFT_2020_12:
        errors.append("$schema: unsupported schema version")

    def walk(node: Any, location: str) -> None:
        if not isinstance(node, dict):
            errors.append(f"{location}: schema node must be an object")
            return
        for key in node:
            if key not in SUPPORTED_KEYWORDS:
                errors.append(f"{location}: unsupported keyword {key!r}")
        declared_type = node.get("type")
        if declared_type is not None:
            declared_types = (
                [declared_type]
                if isinstance(declared_type, str)
                else declared_type
            )
            if (
                not isinstance(declared_types, list)
                or not declared_types
                or any(
                    not isinstance(item, str) or item not in JSON_TYPES
                    for item in declared_types
                )
                or len(declared_types) != len(set(declared_types))
            ):
                errors.append(f"{location}: invalid type declaration")
        if "$ref" in node:
            try:
                _resolve_ref(schema, node["$ref"])
            except (TypeError, ValueError) as exc:
                errors.append(f"{location}: {exc}")
        for name, child in node.get("properties", {}).items():
            walk(child, f"{location}/properties/{name}")
        for name, child in node.get("$defs", {}).items():
            walk(child, f"{location}/$defs/{name}")
        if isinstance(node.get("items"), dict):
            walk(node["items"], f"{location}/items")

    walk(schema, "$")
    return sorted(set(errors))


def validate_instance(instance: Any, schema: dict[str, Any]) -> list[str]:
    definition_errors = validate_schema_definition(schema)
    if definition_errors:
        return definition_errors
    errors: list[str] = []

    def check(value: Any, node: dict[str, Any], location: str) -> None:
        if "$ref" in node:
            check(value, _resolve_ref(schema, node["$ref"]), location)
            return
        expected = node.get("type")
        if expected is not None:
            expected_types = [expected] if isinstance(expected, str) else expected
            if not any(_json_type_matches(value, item) for item in expected_types):
                errors.append(f"{location}: expected {expected}")
                return
        if "const" in node and value != node["const"]:
            errors.append(f"{location}: value must equal {node['const']!r}")
        if "enum" in node and value not in node["enum"]:
            errors.append(f"{location}: value is not in the permitted enum")
        if isinstance(value, dict):
            for name in node.get("required", []):
                if name not in value:
                    errors.append(f"{location}: missing required property {name!r}")
            properties = node.get("properties", {})
            if node.get("additionalProperties") is False:
                for name in value:
                    if name not in properties:
                        errors.append(f"{location}: additional property {name!r}")
            for name, child in properties.items():
                if name in value:
                    check(value[name], child, f"{location}/{name}")
        elif isinstance(value, list):
            minimum = node.get("minItems")
            if isinstance(minimum, int) and len(value) < minimum:
                errors.append(f"{location}: requires at least {minimum} items")
            if node.get("uniqueItems") is True:
                encoded = [canonical_json_bytes(item) for item in value]
                if len(encoded) != len(set(encoded)):
                    errors.append(f"{location}: items must be unique")
            child = node.get("items")
            if isinstance(child, dict):
                for index, item in enumerate(value):
                    check(item, child, f"{location}/{index}")
        elif isinstance(value, str):
            minimum = node.get("minLength")
            if isinstance(minimum, int) and len(value) < minimum:
                errors.append(f"{location}: string is shorter than {minimum}")
            pattern = node.get("pattern")
            if isinstance(pattern, str) and re.search(pattern, value) is None:
                errors.append(f"{location}: string does not match {pattern!r}")
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            minimum = node.get("minimum")
            if minimum is not None and value < minimum:
                errors.append(f"{location}: number is below {minimum}")

    try:
        canonical_json_bytes(instance)
        check(instance, schema, "$")
    except (TypeError, ValueError) as exc:
        errors.append(f"$: {exc}")
    return sorted(set(errors))


def validate_semantics(instance: Any, schema_name: str) -> list[str]:
    """Validate lifecycle and identity invariants that JSON Schema cannot express."""
    errors: list[str] = []

    def walk(value: Any, location: str) -> None:
        if isinstance(value, dict):
            parsed: dict[str, Any] = {}
            for key, child in value.items():
                if key.endswith("_at"):
                    try:
                        parsed[key] = parse_rfc3339(child)
                    except (TypeError, ValueError):
                        errors.append(f"{location}/{key}: invalid RFC 3339 timestamp")
                walk(child, f"{location}/{key}")
            for start, end in (
                ("started_at", "ended_at"),
                ("issued_at", "expires_at"),
                ("created_at", "expires_at"),
            ):
                if start in parsed and end in parsed and parsed[start] >= parsed[end]:
                    errors.append(f"{location}: {end} must follow {start}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{location}/{index}")

    walk(instance, "$")
    if isinstance(instance, dict):
        field = CONTENT_ADDRESS_FIELDS.get(schema_name)
        if field and not verify_content_address(instance, field):
            errors.append(f"$/{field}: content address does not reconstruct")
        if schema_name == "candidate":
            from codex_governance.candidate import verify_candidate_identity

            if not verify_candidate_identity(instance):
                errors.append("$/candidate_id: candidate identity does not reconstruct")
    return sorted(set(errors))


def load_json(path: Path, *, max_bytes: int = 2_000_000) -> Any:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError("JSON input exceeds configured size bound")
    try:
        return json.loads(
            data.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite number {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid UTF-8 JSON: {exc}") from exc


def load_and_validate(instance_path: Path, schema_path: Path) -> Any:
    schema = load_json(schema_path)
    instance = load_json(instance_path)
    if not isinstance(schema, dict):
        raise SchemaValidationError(["$: schema must be an object"])
    errors = validate_instance(instance, schema)
    errors.extend(
        validate_semantics(instance, schema_path.name.removesuffix(".schema.json"))
    )
    if errors:
        raise SchemaValidationError(errors)
    return instance


class JsonRepresentationAdapter:
    def __init__(self, schema_path: Path):
        self.schema_path = schema_path

    def parse(self, data: bytes) -> Any:
        try:
            value = json.loads(
                data.decode("utf-8"),
                parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise SchemaValidationError([f"$: invalid UTF-8 JSON: {exc}"]) from exc
        schema = load_json(self.schema_path)
        if not isinstance(schema, dict):
            raise SchemaValidationError(["$: schema must be an object"])
        errors = validate_instance(value, schema)
        errors.extend(
            validate_semantics(
                value, self.schema_path.name.removesuffix(".schema.json")
            )
        )
        if errors:
            raise SchemaValidationError(errors)
        return value

    def serialize(self, value: Any) -> bytes:
        schema = load_json(self.schema_path)
        if not isinstance(schema, dict):
            raise SchemaValidationError(["$: schema must be an object"])
        errors = validate_instance(value, schema)
        errors.extend(
            validate_semantics(
                value, self.schema_path.name.removesuffix(".schema.json")
            )
        )
        if errors:
            raise SchemaValidationError(errors)
        return canonical_json_bytes(value)
