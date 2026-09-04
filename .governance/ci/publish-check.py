#!/usr/bin/env python3
"""Publish one completed check using an installation token from the environment."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from common import load_json, require_digest, require_repository, require_sha


REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,127}$")
WORKFLOW_RUN_RE = re.compile(r"^([1-9][0-9]*)-([1-9][0-9]*)$")
PUBLICATION_FIELDS = {
    "schema_version",
    "target_id",
    "target_ref",
    "authority_repository",
    "authority_ref",
    "authority_sha",
    "source_repository",
    "source_head_sha",
    "repository",
    "repository_id",
    "head_sha",
    "candidate_id",
    "task_contract_sha256",
    "effective_policy_sha256",
    "manifest_id",
    "manifest_sha256",
    "disposition_sha256",
    "check_name",
    "status",
    "conclusion",
    "title",
    "summary",
    "details_url",
    "workflow_run",
    "external_id",
    "reason_codes",
}


def _paginated_collection(
    base_url: str,
    *,
    query: dict[str, object],
    collection_name: str,
    headers: dict[str, str],
) -> list[object]:
    """Read one complete GitHub collection or fail closed on pagination drift."""
    results: list[object] = []
    expected_total: int | None = None
    page = 1
    while True:
        url = base_url + "?" + urllib.parse.urlencode(
            {**query, "per_page": 100, "page": page}
        )
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, method="GET", headers=headers),
                timeout=30,
            ) as response:
                payload = json.loads(response.read(4_000_000).decode("utf-8"))
                page_results = payload.get(collection_name)
                total_count = payload.get("total_count")
                if (
                    response.status != 200
                    or not isinstance(page_results, list)
                    or len(page_results) > 100
                    or not isinstance(total_count, int)
                    or isinstance(total_count, bool)
                    or total_count < 0
                ):
                    raise RuntimeError("GitHub returned an invalid paginated result")
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"GitHub pagination failed with HTTP {error.code}"
            ) from None
        if expected_total is None:
            expected_total = total_count
        elif total_count != expected_total:
            raise RuntimeError("GitHub result set changed during pagination")
        results.extend(page_results)
        if len(results) >= expected_total:
            if len(results) != expected_total:
                raise RuntimeError("GitHub pagination was inconsistent")
            return results
        if not page_results or len(page_results) < 100:
            raise RuntimeError("GitHub pagination was incomplete")
        page += 1


def discover_app_check_runs(
    repository_url: str,
    *,
    head: str,
    app_id: int,
    headers: dict[str, str],
) -> list[dict[str, object]]:
    """Enumerate all runs via suites, avoiding the ref-runs 1,000-suite ceiling."""
    suites = _paginated_collection(
        repository_url
        + "/commits/"
        + urllib.parse.quote(head, safe="")
        + "/check-suites",
        query={"app_id": app_id, "check_name": "disposition"},
        collection_name="check_suites",
        headers=headers,
    )
    suite_ids: list[int] = []
    for suite in suites:
        suite_id = suite.get("id") if isinstance(suite, dict) else None
        suite_app = suite.get("app") if isinstance(suite, dict) else None
        if (
            not isinstance(suite_id, int)
            or isinstance(suite_id, bool)
            or not isinstance(suite_app, dict)
            or suite_app.get("id") != app_id
        ):
            raise RuntimeError("GitHub returned an invalid check suite")
        suite_ids.append(suite_id)
    if len(suite_ids) != len(set(suite_ids)):
        raise RuntimeError("GitHub suite pagination repeated a result")

    check_runs: list[dict[str, object]] = []
    for suite_id in sorted(suite_ids):
        runs = _paginated_collection(
            repository_url + "/check-suites/" + str(suite_id) + "/check-runs",
            query={"check_name": "disposition", "filter": "all"},
            collection_name="check_runs",
            headers=headers,
        )
        for run in runs:
            run_id = run.get("id") if isinstance(run, dict) else None
            run_app = run.get("app") if isinstance(run, dict) else None
            run_suite = run.get("check_suite") if isinstance(run, dict) else None
            if (
                not isinstance(run_id, int)
                or isinstance(run_id, bool)
                or run.get("name") != "disposition"
                or not isinstance(run_app, dict)
                or run_app.get("id") != app_id
                or not isinstance(run_suite, dict)
                or run_suite.get("id") != suite_id
                or run.get("head_sha") != head
            ):
                raise RuntimeError("GitHub returned an invalid check run")
            check_runs.append(run)
    check_ids = [run["id"] for run in check_runs]
    if len(check_ids) != len(set(check_ids)):
        raise RuntimeError("GitHub check-run pagination repeated a result")
    return check_runs


def validate_publication(
    publication: object,
    target: object,
    *,
    workflow_run: str,
    authority_repository: str,
    authority_sha: str,
    source_repository: str,
    source_head_sha: str,
    admission_result: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if admission_result not in {"success", "failure"}:
        raise ValueError("publisher requires a completed admission job")
    if not isinstance(publication, dict) or set(publication) != PUBLICATION_FIELDS:
        raise ValueError("publication fields do not match the fixed contract")
    if not isinstance(target, dict) or publication.get("schema_version") != "1.0.0":
        raise ValueError("publication or target schema is invalid")
    repository = require_repository(publication.get("repository"))
    authority = require_repository(authority_repository)
    expected_authority_sha = require_sha(authority_sha, "authority_sha")
    source = require_repository(source_repository)
    expected_source_head_sha = require_sha(source_head_sha, "source_head_sha")
    head = require_sha(publication.get("head_sha"), "head_sha")
    for field in (
        "candidate_id",
        "task_contract_sha256",
        "effective_policy_sha256",
        "manifest_id",
        "manifest_sha256",
        "disposition_sha256",
    ):
        require_digest(publication.get(field), field)
    match = WORKFLOW_RUN_RE.fullmatch(workflow_run)
    reason_codes = publication.get("reason_codes")
    if (
        match is None
        or not isinstance(reason_codes, list)
        or not reason_codes
        or reason_codes != sorted(set(reason_codes))
        or any(not isinstance(code, str) or REASON_RE.fullmatch(code) is None for code in reason_codes)
    ):
        raise ValueError("publication run or reason binding is invalid")
    expected_details = f"https://github.com/{source}/actions/runs/{match.group(1)}"
    expected_external = (
        "governed-change:" + workflow_run + ":" + str(publication["candidate_id"])
    )
    expected = {
        "target_id": target.get("target_id"),
        "target_ref": target.get("target_ref"),
        "repository": target.get("repository"),
        "repository_id": target.get("repository_id"),
        "head_sha": target.get("head_sha"),
        "candidate_id": target.get("expected_candidate_id"),
        "task_contract_sha256": target.get("expected_task_contract_sha256"),
        "effective_policy_sha256": target.get("expected_policy_sha256"),
        "workflow_run": workflow_run,
        "external_id": expected_external,
        "details_url": expected_details,
        "authority_repository": authority,
        "authority_ref": "refs/heads/governance-authority",
        "authority_sha": expected_authority_sha,
        "source_repository": source,
        "source_head_sha": expected_source_head_sha,
    }
    if any(publication.get(field) != value for field, value in expected.items()):
        raise ValueError("publication does not match the protected target and run")
    if (
        publication.get("check_name") != "disposition"
        or publication.get("status") != "completed"
        or publication.get("conclusion") not in {"success", "failure"}
        or not isinstance(publication.get("title"), str)
        or not publication["title"]
        or not isinstance(publication.get("summary"), str)
        or not publication["summary"]
        or len(publication["title"]) > 255
        or len(publication["summary"]) > 65_535
    ):
        raise ValueError("publication payload is not the fixed disposition contract")
    if (
        (admission_result == "success" and publication.get("conclusion") != "success")
        or (admission_result == "failure" and publication.get("conclusion") != "failure")
    ):
        raise ValueError("publication conclusion contradicts the admission result")
    zero = "sha256:" + "0" * 64
    if publication.get("conclusion") == "success" and any(
        publication.get(field) == zero
        for field in ("manifest_id", "manifest_sha256", "disposition_sha256")
    ):
        raise ValueError("successful publication lacks reconstructed evidence")
    if repository != target.get("repository") or head != target.get("head_sha"):
        raise ValueError("publication repository binding is invalid")
    return publication, target


def verify_completed_source_run(
    *,
    api_url: str,
    source_repository: str,
    source_head_sha: str,
    authority_repository: str,
    authority_sha: str,
    workflow_run: str,
    headers: dict[str, str],
) -> None:
    """Require GitHub to have completed the exact protected producer successfully."""
    match = WORKFLOW_RUN_RE.fullmatch(workflow_run)
    if match is None:
        raise ValueError("completed source workflow binding is invalid")
    source = require_repository(source_repository)
    expected_source_head_sha = require_sha(source_head_sha, "source_head_sha")
    source_owner, source_name = source.split("/", 1)
    run_url = (
        api_url.rstrip("/")
        + "/repos/"
        + urllib.parse.quote(source_owner, safe="")
        + "/"
        + urllib.parse.quote(source_name, safe="")
        + "/actions/runs/"
        + match.group(1)
        + "/attempts/"
        + match.group(2)
    )
    try:
        with urllib.request.urlopen(
            urllib.request.Request(run_url, method="GET", headers=headers),
            timeout=30,
        ) as response:
            source_run = json.loads(response.read(1_000_000).decode("utf-8"))
            if response.status != 200:
                raise RuntimeError("GitHub did not return the source workflow run")
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"GitHub source-workflow lookup failed with HTTP {error.code}"
        ) from None
    referenced_workflows = source_run.get("referenced_workflows")
    expected_workflow_path = (
        authority_repository
        + "/.github/workflows/disposition.yml@"
        + authority_sha
    )
    if (
        source_run.get("id") != int(match.group(1))
        or source_run.get("run_attempt") != int(match.group(2))
        or source_run.get("status") != "completed"
        or source_run.get("conclusion") != "success"
        or source_run.get("event") not in {"workflow_dispatch", "schedule"}
        or source_run.get("head_branch") != "main"
        or source_run.get("head_sha") != expected_source_head_sha
        or source_run.get("name") != "Governed disposition broker"
        or source_run.get("path") != ".github/workflows/broker-disposition.yml"
        or source_run.get("repository", {}).get("full_name")
        != source
        or not isinstance(referenced_workflows, list)
        or len(referenced_workflows) != 1
        or not isinstance(referenced_workflows[0], dict)
        or referenced_workflows[0].get("path") != expected_workflow_path
        or referenced_workflows[0].get("sha") != authority_sha
    ):
        raise ValueError(
            "source broker run did not complete with the exact protected authority workflow"
        )


def resolve_generation_sentinel(
    check_runs: list[dict[str, object]], publication: dict[str, object]
) -> int:
    """Select one exact source-generation sentinel and reject newer work."""
    expected_external = "governed-change:" + str(publication["workflow_run"]) + ":initialized"
    expected_details = str(publication["details_url"])
    matches = [
        run
        for run in check_runs
        if run.get("external_id") == expected_external
        and run.get("details_url") == expected_details
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
    ]
    if len(matches) != 1:
        raise ValueError("source generation has no unique initialized failure sentinel")
    sentinel_id = int(matches[0]["id"])
    if any(int(run["id"]) > sentinel_id for run in check_runs):
        raise ValueError("a newer governed reevaluation has already initialized")
    return sentinel_id


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--workflow-run", required=True)
    parser.add_argument("--authority-repository", required=True)
    parser.add_argument("--authority-sha", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--admission-result", required=True)
    parser.add_argument("--app-id", type=int, required=True)
    parser.add_argument("--check-run-id", type=int)
    parser.add_argument("--api-url", default="https://api.github.com")
    parser.add_argument("--token-env", default="GITHUB_APP_TOKEN")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--finalize-completed-success", action="store_true")
    args = parser.parse_args()

    publication, target = validate_publication(
        load_json(args.publication),
        load_json(args.target),
        workflow_run=args.workflow_run,
        authority_repository=args.authority_repository,
        authority_sha=args.authority_sha,
        source_repository=args.source_repository,
        source_head_sha=args.source_head_sha,
        admission_result=args.admission_result,
    )
    if args.app_id < 1:
        raise ValueError("publishing GitHub App ID must be positive")
    if args.finalize_completed_success:
        if args.check_run_id is not None:
            raise ValueError("success finalization resolves its source-generation sentinel")
    elif not isinstance(args.check_run_id, int) or args.check_run_id < 1:
        raise ValueError("initialized check ID must be positive")
    if args.validate_only:
        print(json.dumps({"validated": True}, sort_keys=True))
        return
    if not args.finalize_completed_success and publication["conclusion"] == "success":
        raise ValueError("success publication is deferred until source-workflow completion")
    token = os.environ.get(args.token_env)
    if not token:
        raise ValueError("GitHub App installation token is unavailable")
    authority_token = os.environ.get("GH_API_TOKEN")
    if not authority_token:
        raise ValueError("protected GitHub authority token is unavailable")
    authority_owner, authority_name = str(publication["authority_repository"]).split(
        "/", 1
    )
    authority_ref = str(publication["authority_ref"])
    authority_url = (
        args.api_url.rstrip("/")
        + "/repos/"
        + urllib.parse.quote(authority_owner, safe="")
        + "/"
        + urllib.parse.quote(authority_name, safe="")
        + "/git/ref/"
        + urllib.parse.quote(authority_ref.removeprefix("refs/"), safe="/")
    )
    authority_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + authority_token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "codex-governed-change-authority/0.1.0",
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(
                authority_url, method="GET", headers=authority_headers
            ),
            timeout=30,
        ) as response:
            observed_authority = json.loads(response.read(1_000_000).decode("utf-8"))
            if response.status != 200:
                raise RuntimeError("GitHub did not return the authority ref")
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"GitHub authority-ref lookup failed with HTTP {error.code}"
        ) from None
    if (
        observed_authority.get("ref") != authority_ref
        or observed_authority.get("object", {}).get("type") != "commit"
        or observed_authority.get("object", {}).get("sha")
        != publication["authority_sha"]
    ):
        raise ValueError("workflow authority commit is stale")
    repository = str(publication["repository"])
    head = str(publication["head_sha"])
    owner, name = repository.split("/", 1)
    repository_url = (
        args.api_url.rstrip("/")
        + "/repos/"
        + urllib.parse.quote(owner, safe="")
        + "/"
        + urllib.parse.quote(name, safe="")
    )
    target_ref = str(target["target_ref"])
    ref_url = repository_url + "/git/ref/" + urllib.parse.quote(
        target_ref.removeprefix("refs/"), safe="/"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "codex-governed-change-authority/0.1.0",
    }
    try:
        with urllib.request.urlopen(
            urllib.request.Request(ref_url, method="GET", headers=headers), timeout=30
        ) as response:
            observed_ref = json.loads(response.read(1_000_000).decode("utf-8"))
            if response.status != 200:
                raise RuntimeError("GitHub did not return the target ref")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            observed_ref = {}
        else:
            raise RuntimeError(
                f"GitHub target-ref lookup failed with HTTP {error.code}"
            ) from None
    ref_current = (
        observed_ref.get("ref") == target_ref
        and observed_ref.get("object", {}).get("sha") == head
    )
    if args.finalize_completed_success:
        if publication["conclusion"] != "success" or not ref_current:
            raise ValueError("post-completion success is not current and admissible")
        verify_completed_source_run(
            api_url=args.api_url,
            source_repository=str(publication["source_repository"]),
            source_head_sha=str(publication["source_head_sha"]),
            authority_repository=str(publication["authority_repository"]),
            authority_sha=str(publication["authority_sha"]),
            workflow_run=str(publication["workflow_run"]),
            headers=authority_headers,
        )
        check_runs = discover_app_check_runs(
            repository_url, head=head, app_id=args.app_id, headers=headers
        )
        sentinel_id = resolve_generation_sentinel(check_runs, publication)
        body = {
            "name": "disposition",
            "status": "completed",
            "conclusion": "success",
            "external_id": publication["external_id"],
            "details_url": publication["details_url"],
            "output": {
                "title": publication["title"],
                "summary": publication["summary"],
            },
        }
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    repository_url + "/check-runs/" + str(sentinel_id),
                    data=json.dumps(body, sort_keys=True).encode("utf-8"),
                    method="PATCH",
                    headers={**headers, "Content-Type": "application/json"},
                ),
                timeout=30,
            ) as response:
                result = json.loads(response.read(1_000_000).decode("utf-8"))
                if (
                    response.status != 200
                    or result.get("id") != sentinel_id
                    or result.get("name") != "disposition"
                    or result.get("head_sha") != head
                    or result.get("conclusion") != "success"
                    or result.get("app", {}).get("id") != args.app_id
                ):
                    raise RuntimeError("GitHub did not finalize the source-generation sentinel")
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"GitHub sentinel finalization failed with HTTP {error.code}"
            ) from None
        later_runs = discover_app_check_runs(
            repository_url, head=head, app_id=args.app_id, headers=headers
        )
        if any(int(run["id"]) > sentinel_id for run in later_runs):
            raise RuntimeError("success finalization was superseded by a newer reevaluation")
        print(json.dumps({"check_run_id": result["id"], "conclusion": "success"}, sort_keys=True))
        return
    if not ref_current:
        publication["conclusion"] = "failure"
        publication["title"] = "Governed admission blocked"
        publication["summary"] = "The protected target ref no longer resolves to the evaluated commit."
    if publication["conclusion"] == "success":
        raise ValueError("success publication is deferred until source-workflow completion")
    url = repository_url + "/check-runs/" + str(args.check_run_id)
    body = {
        "name": "disposition",
        "status": "completed",
        "conclusion": publication["conclusion"],
        "external_id": publication["external_id"],
        "details_url": publication["details_url"],
        "output": {
            "title": publication["title"],
            "summary": publication["summary"],
        },
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(body, sort_keys=True).encode("utf-8"),
        method="PATCH",
        headers={
            **headers,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read(1_000_000).decode("utf-8"))
            if (
                response.status != 200
                or result.get("id") != args.check_run_id
                or result.get("name") != "disposition"
                or result.get("head_sha") != head
                or result.get("conclusion") != publication["conclusion"]
                or result.get("app", {}).get("id") != args.app_id
            ):
                raise RuntimeError("GitHub did not update the initialized check run")
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"GitHub check update failed with HTTP {error.code}"
        ) from None
    if publication["conclusion"] == "failure":
        check_runs = discover_app_check_runs(
            repository_url, head=head, app_id=args.app_id, headers=headers
        )
        prior_successes = sorted(
            (
                check
                for check in check_runs
                if check.get("conclusion") == "success"
                and str(check.get("external_id", "")).startswith(
                    "governed-change:"
                )
            ),
            key=lambda check: check["id"],
        )
        for prior in prior_successes:
            revoke_url = repository_url + "/check-runs/" + str(prior["id"])
            revoke_body = {
                "name": "disposition",
                "status": "completed",
                "conclusion": "failure",
                "output": {
                    "title": "Governed admission superseded",
                    "summary": (
                        "A later protected re-evaluation did not establish readiness. "
                        "The previous success is revoked."
                    ),
                },
            }
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(
                        revoke_url,
                        data=json.dumps(revoke_body, sort_keys=True).encode("utf-8"),
                        method="PATCH",
                        headers={**headers, "Content-Type": "application/json"},
                    ),
                    timeout=30,
                ) as response:
                    revoked = json.loads(response.read(1_000_000).decode("utf-8"))
                    if response.status != 200 or revoked.get("conclusion") != "failure":
                        raise RuntimeError("GitHub did not revoke a prior success")
            except urllib.error.HTTPError as error:
                raise RuntimeError(
                    f"GitHub prior-check revocation failed with HTTP {error.code}"
                ) from None
    print(json.dumps({"check_run_id": result["id"], "conclusion": publication["conclusion"]}, sort_keys=True))


if __name__ == "__main__":
    main()
