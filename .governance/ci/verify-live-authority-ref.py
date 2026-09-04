#!/usr/bin/env python3
"""Require the live protected authority ref to equal this workflow commit."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from common import require_repository, require_sha


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
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codex-governed-change-authority/0.1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.loads(response.read(1_000_000).decode("utf-8"))
            if response.status != 200:
                raise RuntimeError("GitHub did not return the authority ref")
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"GitHub authority-ref lookup failed with HTTP {error.code}"
        ) from None
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
        repository_request = urllib.request.Request(
            repository_url,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "codex-governed-change-authority/0.1.0",
            },
        )
        try:
            with urllib.request.urlopen(repository_request, timeout=30) as response:
                repository_document = json.loads(
                    response.read(1_000_000).decode("utf-8")
                )
                if response.status != 200:
                    raise RuntimeError("GitHub did not return the authority repository")
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"GitHub authority-repository lookup failed with HTTP {error.code}"
            ) from None
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--api-url", default="https://api.github.com")
    parser.add_argument("--token-env", default="GH_API_TOKEN")
    parser.add_argument("--require-private", action="store_true")
    args = parser.parse_args()
    token = os.environ.get(args.token_env)
    if not token:
        raise ValueError("protected GitHub authority token is unavailable")
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
