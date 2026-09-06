"""Fail-closed standard-library adapter for the protected schema subset."""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from codex_governance.artifacts import read_bounded_path_file
from codex_governance.canonical import canonical_json_bytes, verify_content_address
from codex_governance.lifecycle import parse_rfc3339


CONTENT_ADDRESS_FIELDS = {
    "assurance-case": "assurance_case_id",
    "authenticated-decision": "decision_id",
    "context-receipt": "receipt_id",
    "context-qualification": "qualification_id",
    "context-source-bundle": "source_bundle_id",
    "context-projection": "projection_id",
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
    "reviewer-qualification-cases": "case_evidence_id",
    "reviewer-qualification-corpus": "corpus_id",
    "reviewer-qualification-label-decision": "decision_id",
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
    "items", "minItems", "maxItems", "uniqueItems", "minLength", "pattern", "minimum",
}

_AUTHORITATIVE_JSON_BYTES: ContextVar[dict[str, bytes] | None] = ContextVar(
    "authoritative_json_bytes", default=None
)


@contextmanager
def authoritative_json_session() -> Iterator[None]:
    """Cache each authoritative pathname's exact bytes for one bounded command."""
    token = _AUTHORITATIVE_JSON_BYTES.set({})
    try:
        yield
    finally:
        _AUTHORITATIVE_JSON_BYTES.reset(token)


class SchemaValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = tuple(errors)


_PORTABLE_SIMPLE_ESCAPES = frozenset(r".^$*+?{}[]()|/\-fnrtv")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _compile_portable_pattern(pattern: str) -> re.Pattern[str]:
    """Compile only the schema repository's proven ECMA-262/Python subset."""
    in_class = False
    previous_quantifier = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 >= len(pattern):
                raise re.error("trailing pattern escape")
            escaped = pattern[index + 1]
            if escaped in {"x", "u"}:
                width = 2 if escaped == "x" else 4
                digits = pattern[index + 2 : index + 2 + width]
                if len(digits) != width or any(
                    digit not in _HEX_DIGITS for digit in digits
                ):
                    raise re.error("malformed portable hexadecimal escape")
                index += width + 2
            elif escaped in "123456789":
                raise re.error("backreferences are outside the portable subset")
            elif escaped == "0":
                if index + 2 < len(pattern) and pattern[index + 2].isdigit():
                    raise re.error("octal escapes are not portable")
                index += 2
            elif escaped in _PORTABLE_SIMPLE_ESCAPES:
                index += 2
            else:
                raise re.error("escape is outside the portable pattern subset")
            previous_quantifier = False
            continue
        if (
            not in_class
            and character == "("
            and index + 1 < len(pattern)
            and pattern[index + 1] == "?"
        ):
            raise re.error("extended groups are outside the portable subset")
        if character == "[":
            if in_class:
                raise re.error("nested character classes are not portable")
            in_class = True
            previous_quantifier = False
        elif character == "]":
            in_class = False
            previous_quantifier = False
        elif in_class and pattern[index : index + 2] in {"&&", "--", "~~", "||"}:
            raise re.error("character-class operators are outside the portable subset")
        elif not in_class and character in "*+?":
            if previous_quantifier:
                raise re.error("nested quantifiers are outside the portable subset")
            previous_quantifier = True
        elif not in_class and character == "}":
            previous_quantifier = True
        else:
            previous_quantifier = False
        index += 1
    if in_class:
        raise re.error("unterminated character class")
    return re.compile(pattern)


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": (
            isinstance(value, int)
            and not isinstance(value, bool)
        ) or (
            isinstance(value, float)
            and value.is_integer()
        ),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _json_equal(left: Any, right: Any) -> bool:
    """Compare values using JSON Schema's mathematical/type-aware equality."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if (
        isinstance(left, (int, float))
        and isinstance(right, (int, float))
        and not isinstance(left, bool)
        and not isinstance(right, bool)
    ):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _resolve_ref(root: dict[str, Any], reference: str) -> dict[str, Any] | bool:
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ValueError(f"unsupported non-local schema reference: {reference}")
    current: Any = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            raise ValueError(f"unresolved schema reference: {reference}")
        current = current[token]
    if not isinstance(current, (dict, bool)):
        raise ValueError(f"schema reference does not target a schema: {reference}")
    return current


def validate_schema_definition(schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        canonical_json_bytes(schema)
    except (TypeError, ValueError) as exc:
        return [f"$: {exc}"]
    if not isinstance(schema, dict):
        return ["$: schema root must be an object"]
    if schema.get("$schema") != DRAFT_2020_12:
        errors.append("$schema: unsupported schema version")

    def walk(node: Any, location: str) -> None:
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            errors.append(f"{location}: schema node must be an object or boolean")
            return
        for key in node:
            if key not in SUPPORTED_KEYWORDS:
                errors.append(f"{location}: unsupported keyword {key!r}")
        if "$schema" in node and node["$schema"] != DRAFT_2020_12:
            errors.append(f"{location}: unsupported schema version")
        for keyword in ("$id", "title", "description"):
            if keyword in node and not isinstance(node[keyword], str):
                errors.append(f"{location}: {keyword} must be a string")
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
        definitions = node.get("$defs", {})
        if not isinstance(definitions, dict):
            errors.append(f"{location}: $defs must be an object")
            definitions = {}
        properties = node.get("properties", {})
        if not isinstance(properties, dict):
            errors.append(f"{location}: properties must be an object")
            properties = {}
        required = node.get("required")
        if required is not None and (
            not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or len(required) != len(set(required))
        ):
            errors.append(f"{location}: required must be a unique string array")
        if "enum" in node:
            enum = node["enum"]
            if not isinstance(enum, list) or not enum:
                errors.append(f"{location}: enum must be a non-empty array")
            elif any(
                _json_equal(left, right)
                for index, left in enumerate(enum)
                for right in enum[index + 1 :]
            ):
                errors.append(f"{location}: enum values must be unique")
        for keyword in ("additionalProperties", "items"):
            if keyword in node and not isinstance(node[keyword], (dict, bool)):
                errors.append(f"{location}: {keyword} must be a schema")
        for keyword in ("minItems", "maxItems", "minLength"):
            value = node.get(keyword)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                errors.append(
                    f"{location}: {keyword} must be a non-negative integer"
                )
        if (
            isinstance(node.get("minItems"), int)
            and not isinstance(node.get("minItems"), bool)
            and isinstance(node.get("maxItems"), int)
            and not isinstance(node.get("maxItems"), bool)
            and node["minItems"] > node["maxItems"]
        ):
            errors.append(f"{location}: minItems must not exceed maxItems")
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            errors.append(f"{location}: uniqueItems must be a boolean")
        if "minimum" in node and (
            not isinstance(node["minimum"], (int, float))
            or isinstance(node["minimum"], bool)
        ):
            errors.append(f"{location}: minimum must be a number")
        if "pattern" in node:
            pattern = node["pattern"]
            if not isinstance(pattern, str):
                errors.append(f"{location}: pattern must be a string")
            else:
                try:
                    _compile_portable_pattern(pattern)
                except re.error:
                    errors.append(
                        f"{location}: pattern must be a portable ECMA-262 expression"
                    )
        if "$ref" in node:
            try:
                _resolve_ref(schema, node["$ref"])
            except (TypeError, ValueError) as exc:
                errors.append(f"{location}: {exc}")
        for name, child in properties.items():
            walk(child, f"{location}/properties/{name}")
        for name, child in definitions.items():
            walk(child, f"{location}/$defs/{name}")
        if isinstance(node.get("items"), (dict, bool)):
            walk(node["items"], f"{location}/items")
        if isinstance(node.get("additionalProperties"), (dict, bool)):
            walk(node["additionalProperties"], f"{location}/additionalProperties")

    walk(schema, "$")
    return sorted(set(errors))


def validate_instance(instance: Any, schema: dict[str, Any]) -> list[str]:
    definition_errors = validate_schema_definition(schema)
    if definition_errors:
        return definition_errors
    errors: list[str] = []

    active: set[tuple[int, int]] = set()

    def check(value: Any, node: dict[str, Any] | bool, location: str) -> None:
        if node is True:
            return
        if node is False:
            errors.append(f"{location}: false schema rejects the value")
            return
        marker = (id(value), id(node))
        if marker in active:
            return
        active.add(marker)
        if "$ref" in node:
            check(value, _resolve_ref(schema, node["$ref"]), location)
        try:
            expected = node.get("type")
            if expected is not None:
                expected_types = [expected] if isinstance(expected, str) else expected
                if not any(_json_type_matches(value, item) for item in expected_types):
                    errors.append(f"{location}: expected {expected}")
                    return
            if "const" in node and not _json_equal(value, node["const"]):
                errors.append(f"{location}: value must equal {node['const']!r}")
            if "enum" in node and not any(
                _json_equal(value, permitted) for permitted in node["enum"]
            ):
                errors.append(f"{location}: value is not in the permitted enum")
            if isinstance(value, dict):
                for name in node.get("required", []):
                    if name not in value:
                        errors.append(f"{location}: missing required property {name!r}")
                properties = node.get("properties", {})
                additional = node.get("additionalProperties", True)
                for name, child in properties.items():
                    if name in value:
                        check(value[name], child, f"{location}/{name}")
                for name in value:
                    if name not in properties:
                        if additional is False:
                            errors.append(f"{location}: additional property {name!r}")
                        elif isinstance(additional, (dict, bool)):
                            check(value[name], additional, f"{location}/{name}")
            elif isinstance(value, list):
                minimum = node.get("minItems")
                if isinstance(minimum, int) and len(value) < minimum:
                    errors.append(f"{location}: requires at least {minimum} items")
                maximum = node.get("maxItems")
                if isinstance(maximum, int) and len(value) > maximum:
                    errors.append(f"{location}: permits at most {maximum} items")
                if node.get("uniqueItems") is True and any(
                    _json_equal(left, right)
                    for index, left in enumerate(value)
                    for right in value[index + 1 :]
                ):
                    errors.append(f"{location}: items must be unique")
                child = node.get("items", True)
                if isinstance(child, (dict, bool)):
                    for index, item in enumerate(value):
                        check(item, child, f"{location}/{index}")
            elif isinstance(value, str):
                minimum = node.get("minLength")
                if isinstance(minimum, int) and len(value) < minimum:
                    errors.append(f"{location}: string is shorter than {minimum}")
                pattern = node.get("pattern")
                if (
                    isinstance(pattern, str)
                    and _compile_portable_pattern(pattern).search(value) is None
                ):
                    errors.append(f"{location}: string does not match {pattern!r}")
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                minimum = node.get("minimum")
                if minimum is not None and value < minimum:
                    errors.append(f"{location}: number is below {minimum}")
        finally:
            active.discard(marker)

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
        if schema_name == "reviewer-result":
            for name in ("reviewed_surfaces", "affected_closure", "claims"):
                values = instance.get(name)
                if isinstance(values, list) and any(
                    _json_equal(left, right)
                    for index, left in enumerate(values)
                    for right in values[index + 1 :]
                ):
                    errors.append(f"$/{name}: items must be unique")
        if schema_name == "context-qualification":
            empirical_fields = {
                "corpus_sha256", "label_decision_id", "measurement_evidence"
            }
            if instance.get("evidence_class") == "synthetic_bootstrap":
                if instance.get("qualified") is not False or not instance.get(
                    "limitations"
                ):
                    errors.append(
                        "$: synthetic bootstrap context must be unqualified and limited"
                    )
                if empirical_fields & set(instance):
                    errors.append(
                        "$: synthetic bootstrap context cannot claim empirical evidence"
                    )
            elif instance.get("evidence_class") == "empirical":
                for name in sorted(empirical_fields - set(instance)):
                    errors.append(f"$: missing required empirical property {name!r}")
        if schema_name == "assurance-case":
            from codex_governance.assurance import assurance_claim_set_is_fixed

            if not assurance_claim_set_is_fixed(instance.get("claims")):
                errors.append("$/claims: fixed assurance claim set does not reconstruct")
        if schema_name == "evidence-manifest":
            bootstrap_fields = {
                "initial_bootstrap_decision",
                "initial_bootstrap_verification",
            }
            present_bootstrap_fields = bootstrap_fields.intersection(instance)
            if present_bootstrap_fields:
                missing = bootstrap_fields.difference(instance)
                for name in sorted(missing):
                    errors.append(f"$: missing required initial-bootstrap property {name!r}")
                for name in (
                    "proposed_policy",
                    "lkg_promotion_decision",
                    "rollback_evidence",
                ):
                    if name not in instance:
                        errors.append(
                            f"$: missing required initial-bootstrap property {name!r}"
                        )
                if "lkg_policy_decision" in instance:
                    errors.append(
                        "$: initial-bootstrap manifests must not contain "
                        "'lkg_policy_decision'"
                    )
            elif "lkg_policy_decision" not in instance:
                errors.append("$: missing required property 'lkg_policy_decision'")
    return sorted(set(errors))


def parse_json_bytes(data: bytes) -> Any:
    """Parse one already-observed UTF-8 JSON representation."""
    try:
        return json.loads(
            data.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite number {value}")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid UTF-8 JSON: {exc}") from exc


def load_json(
    path: Path,
    *,
    max_bytes: int = 2_000_000,
    deadline: float | None = None,
) -> Any:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if deadline is not None and (
        not isinstance(deadline, (int, float))
        or isinstance(deadline, bool)
        or not math.isfinite(deadline)
        or time.monotonic() >= deadline
    ):
        raise TimeoutError("authoritative JSON deadline expired")
    cache = _AUTHORITATIVE_JSON_BYTES.get()
    key = str(path.absolute())
    data = cache.get(key) if cache is not None else None
    if data is None:
        data = read_bounded_path_file(
            path, max_bytes=max_bytes, deadline=deadline
        )
        if cache is not None:
            cache[key] = data
    elif len(data) > max_bytes:
        raise ValueError("JSON input exceeds configured size bound")
    return parse_json_bytes(data)


def validate_loaded_instance(
    instance: Any,
    schema_path: Path,
    *,
    deadline: float | None = None,
) -> Any:
    """Validate an already-parsed instance without reopening its representation."""
    schema = load_json(schema_path, deadline=deadline)
    if not isinstance(schema, dict):
        raise SchemaValidationError(["$: schema must be an object"])
    errors = validate_instance(instance, schema)
    errors.extend(
        validate_semantics(instance, schema_path.name.removesuffix(".schema.json"))
    )
    if errors:
        raise SchemaValidationError(errors)
    return instance


def load_and_validate(
    instance_path: Path,
    schema_path: Path,
    *,
    deadline: float | None = None,
) -> Any:
    return validate_loaded_instance(
        load_json(instance_path, deadline=deadline),
        schema_path,
        deadline=deadline,
    )


class JsonRepresentationAdapter:
    def __init__(self, schema_path: Path):
        self.schema_path = schema_path

    def parse(self, data: bytes) -> Any:
        try:
            value = parse_json_bytes(data)
        except ValueError as exc:
            raise SchemaValidationError([f"$: {exc}"]) from exc
        return validate_loaded_instance(value, self.schema_path)

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
