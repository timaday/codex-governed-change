#!/usr/bin/env python3
"""Require the live protected authority ref to equal this workflow commit."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from common import read_bytes_once, require_repository, require_sha, sha256_bytes, write_once


API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "codex-governed-change-authority/0.1.0",
}


def _request_json(url: str, *, token: str) -> object:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={**API_HEADERS, "Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(1_000_001)
            if response.status != 200 or len(data) > 1_000_000:
                raise RuntimeError("GitHub did not return one bounded observation")
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"GitHub authority lookup failed with HTTP {error.code}"
        ) from None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("GitHub returned malformed authority state") from error


def observe_live_ref(
    *,
    repository: str,
    ref: str,
    expected_sha: str,
    token: str,
    api_url: str,
    require_private: bool = False,
) -> dict[str, object]:
    owner, name = require_repository(repository).split("/", 1)
    expected = require_sha(expected_sha, "expected_sha")
    if not ref.startswith("refs/heads/") or not ref.removeprefix("refs/heads/"):
        raise ValueError("authority ref must be a branch ref")
    url = (
        api_url.rstrip("/")
        + "/repos/"
        + urllib.parse.quote(owner, safe="")
        + "/"
        + urllib.parse.quote(name, safe="")
        + "/git/ref/"
        + urllib.parse.quote(ref.removeprefix("refs/"), safe="/")
    )
    document = _request_json(url, token=token)
    if not isinstance(document, dict):
        raise RuntimeError("GitHub authority-ref response is malformed")
    if (
        document.get("ref") != ref
        or document.get("object", {}).get("type") != "commit"
        or document.get("object", {}).get("sha") != expected
    ):
        raise ValueError("workflow authority commit is stale")
    if require_private:
        repository_url = (
            api_url.rstrip("/")
            + "/repos/"
            + urllib.parse.quote(owner, safe="")
            + "/"
            + urllib.parse.quote(name, safe="")
        )
        repository_document = _request_json(repository_url, token=token)
        if not isinstance(repository_document, dict):
            raise RuntimeError("GitHub authority-repository response is malformed")
        if (
            repository_document.get("full_name") != repository
            or repository_document.get("private") is not True
        ):
            raise ValueError("reviewer authority repository is not private")
    return {
        "repository": repository,
        "ref": ref,
        "sha": expected,
        "current": True,
        "private": True if require_private else None,
    }


def observe_live_authority(
    *,
    repository: str,
    ref: str,
    expected_sha: str,
    token: str,
    api_url: str,
    authority_root: Path,
    observed_at: str,
) -> dict[str, object]:
    """Bind the live public ref, exact active ruleset, and commit manifest."""
    current = observe_live_ref(
        repository=repository,
        ref=ref,
        expected_sha=expected_sha,
        token=token,
        api_url=api_url,
    )
    if ref != "refs/heads/governance-authority":
        raise ValueError("bootstrap authority observation requires the protected ref")
    owner, name = require_repository(repository).split("/", 1)
    rulesets_url = (
        api_url.rstrip("/")
        + "/repos/"
        + urllib.parse.quote(owner, safe="")
        + "/"
        + urllib.parse.quote(name, safe="")
        + "/rulesets?includes_parents=false&targets=branch&per_page=100"
    )
    summaries = _request_json(rulesets_url, token=token)
    if not isinstance(summaries, list):
        raise RuntimeError("GitHub ruleset response is malformed")
    matching_ids = [
        item.get("id")
        for item in summaries
        if isinstance(item, dict)
        and item.get("target") == "branch"
        and item.get("enforcement") == "active"
    ]
    if len(matching_ids) != 1:
        raise ValueError("exactly one active branch ruleset is required")
    rulesets: list[dict[str, object]] = []
    for ruleset_id in matching_ids:
        if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
            raise ValueError("GitHub returned an invalid ruleset identity")
        detail = _request_json(
            rulesets_url.split("?", 1)[0] + "/" + str(ruleset_id), token=token
        )
        if not isinstance(detail, dict):
            raise RuntimeError("GitHub ruleset detail is malformed")
        if detail.get("conditions") == {
            "ref_name": {"include": [ref], "exclude": []}
        }:
            rulesets.append(detail)
    if len(rulesets) != 1:
        raise ValueError("exactly one active authority ruleset is required")
    detail = rulesets[0]
    rules = detail.get("rules")
    if (
        detail.get("target") != "branch"
        or detail.get("enforcement") != "active"
        or detail.get("bypass_actors") != []
        or not isinstance(rules, list)
        or any(not isinstance(item, dict) for item in rules)
    ):
        raise ValueError("authority ruleset is not active and bypass-free")
    rules_by_type = {item.get("type"): item for item in rules}
    if len(rules_by_type) != len(rules) or set(rules_by_type) != {
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "pull_request",
    }:
        raise ValueError("authority ruleset has an unexpected rule set")
    for kind in ("deletion", "non_fast_forward", "required_linear_history"):
        if rules_by_type[kind] != {"type": kind}:
            raise ValueError("authority ruleset rule is malformed")
    pull_request = rules_by_type["pull_request"]
    parameters = pull_request.get("parameters")
    expected_parameter_keys = {
        "allowed_merge_methods",
        "dismiss_stale_reviews_on_push",
        "require_code_owner_review",
        "require_extra_approval_for_unattributed_changes",
        "require_last_push_approval",
        "required_approving_review_count",
        "required_review_thread_resolution",
        "required_reviewers",
    }
    if (
        set(pull_request) != {"type", "parameters"}
        or not isinstance(parameters, dict)
        or set(parameters) != expected_parameter_keys
        or parameters.get("allowed_merge_methods") != ["squash", "rebase"]
        or parameters.get("dismiss_stale_reviews_on_push") is not True
        or parameters.get("require_code_owner_review") is not False
        or parameters.get("require_extra_approval_for_unattributed_changes")
        is not True
        or parameters.get("required_reviewers") != []
        or parameters.get("required_review_thread_resolution") is not True
        or parameters.get("required_approving_review_count") not in {0, 1}
        or parameters.get("require_last_push_approval")
        != (parameters.get("required_approving_review_count") == 1)
    ):
        raise ValueError("authority pull-request rule is not an approved profile")

    root = authority_root.resolve(strict=True)
    manifest = read_bytes_once(root / "MANIFEST.json")
    completed = subprocess.run(
        ["git", "-C", str(root), "show", expected_sha + ":MANIFEST.json"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr or completed.stdout != manifest:
        raise ValueError("authority manifest is not the exact commit-resident file")
    try:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ValueError("authority observation timestamp is invalid") from error
    return {
        "schema_version": "1.0.0",
        "repository": repository,
        "ref": ref,
        "commit": current["sha"],
        "manifest_commit": expected_sha,
        "manifest_sha256": sha256_bytes(manifest),
        "ruleset": {
            "id": detail["id"],
            "target": detail["target"],
            "enforcement": detail["enforcement"],
            "bypass_actors": detail["bypass_actors"],
            "conditions": detail["conditions"],
            "rules": rules,
        },
        "observed_at": observed_at,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--api-url", default="https://api.github.com")
    parser.add_argument("--token-env", default="GH_API_TOKEN")
    parser.add_argument("--require-private", action="store_true")
    parser.add_argument("--authority-root", type=Path)
    parser.add_argument("--observed-at")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise ValueError("protected GitHub authority token is unavailable")
    if args.output is not None:
        if args.require_private or args.authority_root is None or not args.observed_at:
            raise ValueError("complete public authority observation inputs are required")
        write_once(
            args.output,
            observe_live_authority(
                repository=args.repository,
                ref=args.ref,
                expected_sha=args.expected_sha,
                token=token,
                api_url=args.api_url,
                authority_root=args.authority_root,
                observed_at=args.observed_at,
            ),
        )
    else:
        print(
            json.dumps(
                observe_live_ref(
                    repository=args.repository,
                    ref=args.ref,
                    expected_sha=args.expected_sha,
                    token=token,
                    api_url=args.api_url,
                    require_private=args.require_private,
                ),
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
