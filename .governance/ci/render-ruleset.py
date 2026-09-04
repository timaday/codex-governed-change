#!/usr/bin/env python3
"""Render a disabled App-bound target ruleset after the integration is known."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from common import load_json, write_once


PLACEHOLDER = "__GITHUB_APP_INTEGRATION_ID__"


def replace(value: object, integration_id: int) -> object:
    if value == PLACEHOLDER:
        return integration_id
    if isinstance(value, list):
        return [replace(item, integration_id) for item in value]
    if isinstance(value, dict):
        return {key: replace(item, integration_id) for key, item in value.items()}
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--integration-id", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.integration_id < 1:
        raise ValueError("integration ID must be a positive integer")
    rendered = replace(load_json(args.template), args.integration_id)
    encoded = json.dumps(rendered, sort_keys=True)
    if PLACEHOLDER in encoded or rendered.get("enforcement") != "disabled":
        raise ValueError("ruleset must remain disabled until separately verified")
    checks = [
        rule
        for rule in rendered.get("rules", [])
        if rule.get("type") == "required_status_checks"
    ]
    required = checks[0]["parameters"]["required_status_checks"] if len(checks) == 1 else []
    if required != [{"context": "disposition", "integration_id": args.integration_id}]:
        raise ValueError("ruleset check source is not exact")
    if rendered.get("bypass_actors") != []:
        raise ValueError("ruleset bypass actors are forbidden")
    write_once(args.output, rendered)


if __name__ == "__main__":
    main()
