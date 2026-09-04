#!/usr/bin/env python3
"""Bind a downloaded immutable artifact ID to its protected upload digest."""

from __future__ import annotations

import argparse
import json
import os
import urllib.request

from common import require_digest, require_repository


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--artifact-id", required=True, type=int)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    args = parser.parse_args()

    if args.artifact_id < 1 or args.workflow_run_id < 1:
        raise ValueError("artifact and workflow run identifiers must be positive")
    repository = require_repository(args.repository)
    expected_digest = args.artifact_digest
    if not expected_digest.startswith("sha256:"):
        expected_digest = "sha256:" + expected_digest
    require_digest(expected_digest, "artifact_digest")
    token = os.environ.get("GH_API_TOKEN")
    if not token:
        raise ValueError("protected GitHub metadata token is unavailable")
    request = urllib.request.Request(
        "https://api.github.com/repos/"
        + repository
        + "/actions/artifacts/"
        + str(args.artifact_id),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codex-governed-change-authority/0.1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise ValueError("GitHub artifact metadata lookup failed")
        body = response.read(1_000_001)
    if len(body) > 1_000_000:
        raise ValueError("GitHub artifact metadata exceeded the size bound")
    metadata = json.loads(body.decode("utf-8"))
    workflow = metadata.get("workflow_run")
    if (
        metadata.get("id") != args.artifact_id
        or metadata.get("name") != args.artifact_name
        or metadata.get("expired") is not False
        or metadata.get("digest") != expected_digest
        or not isinstance(workflow, dict)
        or workflow.get("id") != args.workflow_run_id
    ):
        raise ValueError("GitHub artifact ID, digest, name, or workflow binding disagrees")


if __name__ == "__main__":
    main()
