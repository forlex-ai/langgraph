"""Behavioral tests for the secret gate; no live credential is used."""

import hashlib
import importlib.util
import io
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import patch


def gate():
    """Load the actual implementation or report the missing feature."""
    source = Path(__file__).with_name("secret_scan.py")
    if not source.exists():
        raise AssertionError("The approved fail-closed TruffleHog gate is not implemented")
    spec = importlib.util.spec_from_file_location("secret_scan", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def finding(raw="unit-only-value", *, verified=False, error=None, path="tests/unit/example.py"):
    """Build synthetic scanner output for protocol tests."""
    row = {
        "SourceMetadata": {"Data": {"Git": {"commit": "a" * 40, "file": path, "line": 7}}},
        "DetectorName": "Postgres",
        "Raw": raw,
        "RawV2": "",
        "Verified": verified,
    }
    if error is not None:
        row["VerificationError"] = error
    return row


def exception(row):
    """Build one exact exception for a synthetic finding."""
    result = {
        "id": "unit-fixture-1",
        "repository": "forlex-ai/unit",
        "detector": row["DetectorName"],
        "path": row["SourceMetadata"]["Data"]["Git"]["file"],
        "commit": "a" * 40,
        "fingerprint": hashlib.sha256(row["Raw"].encode()).hexdigest(),
        "owner": "danielbichuetti",
        "rationale": "Reviewed synthetic fixture, no live credential.",
        "expires": "2099-01-01",
    }
    result["proof"] = proof_url(result)
    return result


def proof_url(row):
    """Reference the exact inert fixture source, without a live proof fetch."""
    return (
        "https://github.com/"
        + row["repository"]
        + "/blob/"
        + row["commit"]
        + "/"
        + urllib.parse.quote(row["path"], safe="/")
    )


def pr_api_fixture(module):
    """Provide independently defined live GitHub facts and inspect every check write."""
    repository = "forlex-ai/unit"
    head = "a" * 40
    base = "b" * 40
    merge = "c" * 40
    responses = {
        "": {"full_name": repository, "default_branch": "main"},
        "pulls/1": {
            "state": "open",
            "head": {"sha": head},
            "base": {"ref": "test", "sha": "d" * 40, "repo": {"full_name": repository}},
            "merge_commit_sha": merge,
            "mergeable": True,
        },
        "git/ref/heads/test": {"ref": "refs/heads/test", "object": {"type": "commit", "sha": base}},
        "git/commits/" + merge: {"sha": merge, "parents": [{"sha": base}, {"sha": head}]},
    }
    checks = {}
    calls = []

    def api(repo, suffix, *, method="GET", body=None):
        calls.append((method, suffix, body))
        assert repo == repository
        if method == "POST":
            number = 3 + len(checks)
            result = {
                "id": number,
                "head_sha": body["head_sha"],
                "name": body["name"],
                "app": {"id": 15368},
                "status": body["status"],
            }
            checks["check-runs/" + str(number)] = result
            return result
        if suffix in checks:
            if method == "PATCH":
                checks[suffix] = {**checks[suffix], **body}
            return checks[suffix]
        if suffix not in responses:
            raise module.SecretScanRefusal("Unavailable synthetic API fact")
        return responses[suffix]

    module.github = api
    event = {
        "number": 1,
        "repository": {"full_name": repository},
        "pull_request": {"head": {"sha": head}, "base": {"ref": "test", "sha": "d" * 40}},
    }
    return event, responses, checks, calls


class GateTests(unittest.TestCase):
    """Exercise redaction, exception boundaries and scanner failure behavior."""

    def test_branch_deletion_scans_retained_before_tip_instead_of_default_sha(self):
            """Deleted branches bind a full scan to the retained deleted tip, never the default head."""
            module = gate()
            event, _responses, checks, _calls = pr_api_fixture(module)
            event.update(ref="refs/heads/deleted", before="b" * 40, after="0" * 40, deleted=True)
            with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
                source = module.context(event, "push", "forlex-ai/unit")
            self.assertEqual((source["head"], source["base"]), ("b" * 40, None))
            self.assertEqual([check["head_sha"] for check in checks.values()], ["b" * 40])
            self.assertEqual([check["name"] for check in checks.values()], ["TruffleHog history scan"])

    def test_branch_deletion_without_a_valid_retained_tip_creates_no_check(self):
            """Missing, zero and malformed deleted tips refuse before any default-head check exists."""
            for before in (None, "0" * 40, "B" * 40, "b" * 39):
                with self.subTest(before=before):
                    module = gate()
                    event, _responses, _checks, calls = pr_api_fixture(module)
                    event.update(ref="refs/heads/deleted", after="0" * 40, deleted=True)
                    if before is not None:
                        event["before"] = before
                    with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}), self.assertRaises(ValueError):
                        module.context(event, "push", "forlex-ai/unit")
                    self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_head_changing_during_merge_polling_refuses_the_stale_event(self):
            """A ready prospective merge for a newer head cannot reuse an older PR event."""
            module = gate()
            event, _responses, _checks, calls = pr_api_fixture(module)
            api = module.github
            reads = 0

            def moving(repo, suffix, *, method="GET", body=None):
                nonlocal reads
                result = api(repo, suffix, method=method, body=body)
                if suffix == "pulls/1":
                    reads += 1
                    if reads == 1:
                        return {**result, "mergeable": None, "merge_commit_sha": None}
                    return {**result, "head": {"sha": "e" * 40}}
                if suffix == "git/commits/" + "c" * 40:
                    return {**result, "parents": [{"sha": "b" * 40}, {"sha": "e" * 40}]}
                return result

            module.github = moving
            with patch.object(module.time, "sleep"), self.assertRaises(ValueError):
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertGreater(reads, 1)
            self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_history_checks_have_a_distinct_fixed_name_from_pr_admission(self):
            """A push or complete-history success cannot satisfy the fixed PR gate name."""
            for kind, number in (
                ("push", 0),
                ("schedule", 0),
                ("workflow_dispatch", 0),
                ("workflow_dispatch", 1),
                ("pull_request_target", 0),
            ):
                with self.subTest(kind=kind, number=number):
                    module = gate()
                    event, _responses, checks, calls = pr_api_fixture(module)
                    event["before"] = "b" * 40
                    with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
                        source = module.context(event, kind, "forlex-ai/unit", number)
                    expected = "TruffleHog secret scan" if source["pr"] else "TruffleHog history scan"
                    self.assertEqual({check["name"] for check in checks.values()}, {expected})
                    report = {
                        **source,
                        "version": 1,
                        "result": "pass",
                        "blocked": 0,
                        "suppressed": 0,
                        "commit_count": 3,
                    }
                    if source["pr"]:
                        report.update(
                            candidate_policy_validated=True,
                            candidate_policy_source=source["merge"],
                            candidate_policy_blob="f" * 40,
                        )
                    self.assertEqual(module.publish(source, report)["conclusion"], "success")
                    self.assertEqual(
                        {body["output"]["title"] for method, _, body in calls if method == "PATCH"}, {expected}
                    )

    def test_missing_old_push_tip_scans_all_reachable_new_history_but_pr_is_strict(self):
            """An orphaned force-push source is complete without the old tip; PR scope remains exact."""
            module = gate()
            with tempfile.TemporaryDirectory() as directory:
                repo = Path(directory)
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
                for message in ("first", "second"):
                    subprocess.run(
                        [
                            "git",
                            "-C",
                            str(repo),
                            "-c",
                            "user.name=Unit",
                            "-c",
                            "user.email=unit@example.invalid",
                            "commit",
                            "--allow-empty",
                            "-qm",
                            message,
                        ],
                        check=True,
                    )
                head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
                expected = subprocess.check_output(
                    ["git", "-C", str(repo), "rev-list", "HEAD"], text=True
                ).splitlines()
                self.assertEqual(
                    module.git_range(repo, head, "f" * 40, full_if_nonforward=True), (None, expected)
                )
                with self.assertRaises(ValueError):
                    module.git_range(repo, head, "f" * 40)
                with self.assertRaises(ValueError):
                    module.git_range(repo, "e" * 40, "f" * 40, full_if_nonforward=True)

    def test_pending_mergeability_is_polled_before_creating_either_check(self):
            """GitHub's asynchronous null mergeability is retried using authenticated current facts."""
            module = gate()
            event, _responses, checks, _calls = pr_api_fixture(module)
            api = module.github
            reads = 0

            def pending(repo, suffix, *, method="GET", body=None):
                nonlocal reads
                result = api(repo, suffix, method=method, body=body)
                if method == "GET" and suffix == "pulls/1":
                    reads += 1
                    if reads < 3:
                        return {**result, "mergeable": None, "merge_commit_sha": None}
                if method == "POST":
                    self.assertGreaterEqual(reads, 3)
                return result

            module.github = pending
            with patch.object(module.time, "sleep"):
                source = module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertEqual(reads, 3)
            self.assertEqual((source["head"], source["base"], source["merge"]), ("a" * 40, "b" * 40, "c" * 40))
            self.assertEqual(len(checks), 2)

    def test_polling_waits_for_exact_current_prospective_merge_parents(self):
            """A stale merge object cannot authorize checks even after mergeability becomes true."""
            module = gate()
            event, _responses, checks, _calls = pr_api_fixture(module)
            api = module.github
            reads = 0

            def stale_merge(repo, suffix, *, method="GET", body=None):
                nonlocal reads
                result = api(repo, suffix, method=method, body=body)
                if suffix == "git/commits/" + "c" * 40:
                    reads += 1
                    if reads < 2:
                        return {**result, "parents": [{"sha": "d" * 40}, {"sha": "a" * 40}]}
                if method == "POST":
                    self.assertGreaterEqual(reads, 2)
                return result

            module.github = stale_merge
            with patch.object(module.time, "sleep"):
                source = module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertEqual(source["base"], "b" * 40)
            self.assertEqual(reads, 2)
            self.assertEqual(len(checks), 2)

    def test_publication_and_cleanup_reject_checks_from_the_other_scan_mode(self):
            """Name separation remains exact during preflight, terminal writes and cleanup."""
            for kind in ("push", "pull_request_target"):
                with self.subTest(kind=kind):
                    module = gate()
                    event, _responses, checks, calls = pr_api_fixture(module)
                    event["before"] = "b" * 40
                    with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
                        source = module.context(event, kind, "forlex-ai/unit")
                    wrong = "TruffleHog secret scan" if kind == "push" else "TruffleHog history scan"
                    for check in checks.values():
                        check["name"] = wrong
                    with self.assertRaises(ValueError):
                        module.publish(source, {"result": "error"})
                    self.assertFalse(any(method == "PATCH" for method, _, _ in calls))

    def test_publication_preflight_failure_cleans_independently_verified_checks(self):
            """Initial identity outages and mismatches must not strand the other original check."""
            for failed_target in ("check-runs/3", "check-runs/4"):
                for fault in ("once", "outage", "foreign"):
                    with self.subTest(target=failed_target, fault=fault):
                        module = gate()
                        event, _responses, checks, calls = pr_api_fixture(module)
                        source = module.context(event, "pull_request_target", "forlex-ai/unit")
                        report = {
                            **source,
                            "version": 1,
                            "result": "pass",
                            "blocked": 0,
                            "suppressed": 0,
                            "commit_count": 3,
                            "candidate_policy_validated": True,
                            "candidate_policy_source": source["merge"],
                            "candidate_policy_blob": "f" * 40,
                        }
                        api = module.github
                        failed = False
                        if fault == "foreign":
                            checks[failed_target]["app"]["id"] = 46505

                        def failing(
                            repo,
                            suffix,
                            *,
                            method="GET",
                            body=None,
                            failed_target=failed_target,
                            fault=fault,
                            api=api,
                            calls=calls,
                            module=module,
                        ):
                            nonlocal failed
                            if (
                                method == "GET"
                                and suffix == failed_target
                                and fault != "foreign"
                                and (not failed or fault == "outage")
                            ):
                                failed = True
                                calls.append((method, suffix, body))
                                raise module.SecretScanRefusal("private-preflight-response-marker")
                            return api(repo, suffix, method=method, body=body)

                        module.github = failing
                        with self.assertRaises(ValueError) as refused:
                            module.publish(source, report)
                        self.assertNotIn("private-preflight-response-marker", str(refused.exception))
                        other = "check-runs/4" if failed_target == "check-runs/3" else "check-runs/3"
                        self.assertEqual(checks[other]["status"], "completed")
                        self.assertEqual(checks[other]["conclusion"], "failure")
                        patches = [(suffix, body) for method, suffix, body in calls if method == "PATCH"]
                        self.assertTrue(all(body["conclusion"] == "failure" for _, body in patches))
                        if fault == "once":
                            self.assertEqual(checks[failed_target]["conclusion"], "failure")
                        else:
                            self.assertFalse(any(suffix == failed_target for suffix, _ in patches))
                        for index, (method, suffix, _) in enumerate(calls):
                            if method == "PATCH":
                                self.assertEqual(calls[index - 1], ("GET", suffix, None))

    def test_unready_or_conflicting_merge_polling_is_bounded_and_creates_no_checks(self):
            """Pending, conflicting and malformed readiness cannot become premature admission."""
            for readiness in (None, False, "true", 1):
                with self.subTest(readiness=readiness):
                    module = gate()
                    event, responses, _checks, calls = pr_api_fixture(module)
                    responses["pulls/1"]["mergeable"] = readiness
                    with patch.object(module.time, "sleep"), self.assertRaises(ValueError):
                        module.context(event, "pull_request_target", "forlex-ai/unit")
                    reads = sum(method == "GET" and suffix == "pulls/1" for method, suffix, _ in calls)
                    self.assertGreaterEqual(reads, 1)
                    self.assertLessEqual(reads, 5)
                    if readiness is None:
                        self.assertGreater(reads, 1)
                    self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_context_cli_persistence_errors_fail_all_acknowledged_owned_checks(self):
        """Local context/output write or close failures cannot strand created checks."""
        for kind in ("pull_request_target", "push"):
            for fault in ("context", "github_output", "missing_output", "stream_write", "stream_close"):
                with self.subTest(kind=kind, fault=fault):
                    module = gate()
                    event, _responses, checks, calls = pr_api_fixture(module)
                    event["before"] = "b" * 40
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        ep, output, gha = root / "event", root / "context", root / "gha"
                        ep.write_text(json.dumps(event))
                        if fault == "context":
                            output.mkdir()
                        elif fault == "github_output":
                            gha.mkdir()
                        argv = [
                            "secret_scan.py",
                            "context",
                            "--event",
                            str(ep),
                            "--kind",
                            kind,
                            "--repository",
                            "forlex-ai/unit",
                            "--output",
                            str(output),
                        ]

                        class FailingOutput(io.StringIO):
                            def write(self, value, fault=fault):
                                super().write(value)
                                if fault == "stream_write":
                                    raise OSError("private-context-write-marker")
                                return len(value)

                            def __exit__(self, *args, fault=fault):
                                if fault == "stream_close":
                                    raise OSError("private-context-write-marker")
                                return super().__exit__(*args)

                        stream = FailingOutput()
                        console = io.StringIO()
                        with (
                            patch.object(sys, "argv", argv),
                            patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha), "GITHUB_SHA": "a" * 40}),
                            patch("sys.stdout", console),
                        ):
                            if fault == "missing_output":
                                os.environ.pop("GITHUB_OUTPUT")
                            if fault in {"stream_write", "stream_close"}:
                                with patch.object(module, "open", return_value=stream, create=True):
                                    self.assertEqual(module.main(), 1)
                            else:
                                self.assertEqual(module.main(), 1)
                        self.assertNotIn("private-context-write-marker", console.getvalue())
                        self.assertNotIn("head=", console.getvalue())
                        self.assertNotIn('"check_id"', console.getvalue())
                    self.assertEqual(len(checks), 2 if kind == "pull_request_target" else 1)
                    self.assertTrue(
                        all(
                            check.get("conclusion") == "failure" and check["status"] == "completed"
                            for check in checks.values()
                        )
                    )
                    patches = [(i, suffix, body) for i, (method, suffix, body) in enumerate(calls) if method == "PATCH"]
                    self.assertEqual(len(patches), len(checks))
                    for index, suffix, body in patches:
                        self.assertEqual(calls[index - 1], ("GET", suffix, None))
                        self.assertEqual(body["conclusion"], "failure")

    def test_context_persistence_cleanup_preserves_identity_and_continues_after_read_failure(self):
        """The CLI guard uses verified cleanup without letting one target block another."""
        for fault in ("foreign", "unavailable"):
            module = gate()
            event, _responses, checks, calls = pr_api_fixture(module)
            api = module.github

            def failed_read(repo, suffix, *, method="GET", body=None, api=api, calls=calls, checks=checks, fault=fault, module=module):
                if method == "GET" and suffix == "check-runs/3":
                    if fault == "foreign":
                        checks[suffix]["app"]["id"] = 46505
                    else:
                        calls.append((method, suffix, body))
                        raise module.SecretScanRefusal("private-context-api-marker")
                return api(repo, suffix, method=method, body=body)

            module.github = failed_read
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ep, output, gha = root / "event", root / "context", root / "gha"
                ep.write_text(json.dumps(event))
                output.mkdir()
                argv = [
                    "secret_scan.py",
                    "context",
                    "--event",
                    str(ep),
                    "--kind",
                    "pull_request_target",
                    "--repository",
                    "forlex-ai/unit",
                    "--output",
                    str(output),
                ]
                console = io.StringIO()
                with (
                    patch.object(sys, "argv", argv),
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha)}),
                    patch("sys.stdout", console),
                ):
                    self.assertEqual(module.main(), 1)
                self.assertNotIn("private-context-api-marker", console.getvalue())
                self.assertFalse(gha.exists())
            self.assertEqual(checks["check-runs/3"]["status"], "in_progress")
            self.assertEqual(checks["check-runs/4"].get("conclusion"), "failure")
            self.assertEqual([suffix for method, suffix, _ in calls if method == "PATCH"], ["check-runs/4"])

    def test_second_context_creation_failure_closes_only_the_known_original_check(self):
        """An unacknowledged second POST cannot strand the acknowledged owned head."""
        for lost_ack in (False, True):
            module = gate()
            event, _responses, checks, calls = pr_api_fixture(module)
            api = module.github
            posts = 0

            def failing(repo, suffix, *, method="GET", body=None, api=api, calls=calls, lost_ack=lost_ack, module=module):
                nonlocal posts
                if method == "POST":
                    posts += 1
                    if posts == 2:
                        if lost_ack:
                            api(repo, suffix, method=method, body=body)
                        else:
                            calls.append((method, suffix, body))
                        raise module.SecretScanRefusal("private-response-marker")
                return api(repo, suffix, method=method, body=body)

            module.github = failing
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                ep, output, gha = root / "event", root / "context", root / "gha"
                ep.write_text(json.dumps(event))
                argv = [
                    "secret_scan.py",
                    "context",
                    "--event",
                    str(ep),
                    "--kind",
                    "pull_request_target",
                    "--repository",
                    "forlex-ai/unit",
                    "--output",
                    str(output),
                ]
                console = io.StringIO()
                with (
                    patch.object(sys, "argv", argv),
                    patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha)}),
                    patch("sys.stdout", console),
                ):
                    self.assertEqual(module.main(), 1)
                self.assertFalse(output.exists())
                self.assertFalse(gha.exists())
                self.assertNotIn("private-response-marker", console.getvalue())
            self.assertEqual(checks["check-runs/3"].get("conclusion"), "failure")
            self.assertEqual(checks["check-runs/3"]["status"], "completed")
            self.assertEqual([suffix for method, suffix, _ in calls if method == "PATCH"], ["check-runs/3"])
            if lost_ack:
                self.assertEqual(checks["check-runs/4"]["status"], "in_progress")

    def test_context_cleanup_cannot_mutate_foreign_or_unverifiable_checks(self):
        """Cleanup requires a fresh exact identity and never guesses an unknown POST id."""
        for changed in ("id", "head", "name", "app", "read_outage"):
            module = gate()
            event, _responses, checks, calls = pr_api_fixture(module)
            api = module.github
            posts = 0

            def failing(repo, suffix, *, method="GET", body=None, api=api, calls=calls, changed=changed, checks=checks, module=module):
                nonlocal posts
                if method == "POST":
                    posts += 1
                    if posts == 2:
                        calls.append((method, suffix, body))
                        check = checks["check-runs/3"]
                        if changed == "id":
                            check["id"] = 3.0
                        elif changed == "head":
                            check["head_sha"] = "e" * 40
                        elif changed == "name":
                            check["name"] = "Other check"
                        elif changed == "app":
                            check["app"]["id"] = 15368.0
                        raise module.SecretScanRefusal("private-response-marker")
                if changed == "read_outage" and method == "GET" and suffix == "check-runs/3":
                    calls.append((method, suffix, body))
                    raise module.SecretScanRefusal("private-response-marker")
                return api(repo, suffix, method=method, body=body)

            module.github = failing
            with self.assertRaises(ValueError) as refused:
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertNotIn("private-response-marker", str(refused.exception))
            self.assertIn(("GET", "check-runs/3", None), calls)
            self.assertFalse(any(method == "PATCH" for method, _, _ in calls))

    def test_context_refuses_non_integer_created_check_identity(self):
        """Only an acknowledged positive integer id identifies a created original check."""
        for identity in (True, 3.0, "3", None, 0, -1):
            module = gate()
            event, _responses, _checks, calls = pr_api_fixture(module)
            api = module.github

            def invalid(repo, suffix, *, method="GET", body=None, api=api, identity=identity):
                result = api(repo, suffix, method=method, body=body)
                return {**result, "id": identity} if method == "POST" else result

            module.github = invalid
            with self.assertRaises(ValueError):
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertFalse(any(method == "PATCH" for method, _, _ in calls))

    def test_partial_publication_failure_downgrades_each_verified_original_check(self):
        """A failed or lost completion acknowledgement never leaves acknowledged success."""
        for failed_target in ("check-runs/3", "check-runs/4"):
            for lost_ack in (False, True):
                module = gate()
                event, _responses, checks, calls = pr_api_fixture(module)
                source = module.context(event, "pull_request_target", "forlex-ai/unit")
                report = {
                    **source,
                    "version": 1,
                    "result": "pass",
                    "blocked": 0,
                    "suppressed": 0,
                    "commit_count": 3,
                    "candidate_policy_validated": True,
                    "candidate_policy_source": source["merge"],
                    "candidate_policy_blob": "f" * 40,
                }
                api = module.github

                def failing(repo, suffix, *, method="GET", body=None, api=api, calls=calls, failed_target=failed_target, lost_ack=lost_ack, module=module):
                    if method == "PATCH" and suffix == failed_target and body["conclusion"] == "success":
                        if lost_ack:
                            api(repo, suffix, method=method, body=body)
                        else:
                            calls.append((method, suffix, body))
                        raise module.SecretScanRefusal("private-response-marker")
                    return api(repo, suffix, method=method, body=body)

                module.github = failing
                with self.assertRaises(ValueError) as refused:
                    module.publish(source, report)
                self.assertNotIn("private-response-marker", str(refused.exception))
                self.assertEqual([check.get("conclusion") for check in checks.values()], ["failure", "failure"])
                for suffix in ("check-runs/3", "check-runs/4"):
                    writes = [
                        i
                        for i, (method, target, body) in enumerate(calls)
                        if method == "PATCH" and target == suffix and body["conclusion"] == "failure"
                    ]
                    self.assertEqual(len(writes), 1)
                    self.assertEqual(calls[writes[0] - 1], ("GET", suffix, None))

    def test_cleanup_continues_when_one_original_check_cannot_be_confirmed(self):
        """An outage, foreign identity or lost cleanup ack cannot skip the other owned target."""
        for failed_target in ("check-runs/3", "check-runs/4"):
            for fault in ("read", "write", "lost_ack", "unconfirmed", "foreign"):
                module = gate()
                event, _responses, checks, calls = pr_api_fixture(module)
                source = module.context(event, "pull_request_target", "forlex-ai/unit")
                report = {
                    **source,
                    "version": 1,
                    "result": "pass",
                    "blocked": 0,
                    "suppressed": 0,
                    "commit_count": 3,
                    "candidate_policy_validated": True,
                    "candidate_policy_source": source["merge"],
                    "candidate_policy_blob": "f" * 40,
                }
                api = module.github
                cleaning = False

                def failing(repo, suffix, *, method="GET", body=None, api=api, calls=calls, checks=checks, failed_target=failed_target, fault=fault, module=module):
                    nonlocal cleaning
                    if method == "PATCH" and suffix == "check-runs/4" and body["conclusion"] == "success":
                        calls.append((method, suffix, body))
                        cleaning = True
                        if fault == "foreign":
                            checks[failed_target]["app"]["id"] = 46505
                        raise module.SecretScanRefusal("private-response-marker")
                    if cleaning and suffix == failed_target:
                        if fault == "read" and method == "GET":
                            calls.append((method, suffix, body))
                            raise module.SecretScanRefusal("private-response-marker")
                        if method == "PATCH":
                            if fault == "write":
                                calls.append((method, suffix, body))
                                raise module.SecretScanRefusal("private-response-marker")
                            result = api(repo, suffix, method=method, body=body)
                            if fault == "lost_ack":
                                raise module.SecretScanRefusal("private-response-marker")
                            if fault == "unconfirmed":
                                return {**result, "status": "in_progress"}
                            return result
                    return api(repo, suffix, method=method, body=body)

                module.github = failing
                with self.assertRaises(ValueError) as refused:
                    module.publish(source, report)
                self.assertNotIn("private-response-marker", str(refused.exception))
                other = "check-runs/4" if failed_target == "check-runs/3" else "check-runs/3"
                self.assertEqual(checks[other].get("conclusion"), "failure")
                self.assertEqual(checks[other]["status"], "completed")
                self.assertIn(("GET", failed_target, None), calls)
                if fault == "foreign":
                    self.assertFalse(
                        any(
                            method == "PATCH" and target == failed_target and body["conclusion"] == "failure"
                            for method, target, body in calls
                        )
                    )

    def test_pr_context_uses_current_base_ref_and_binds_both_evaluated_commits(self):
        """A cached Pulls API base cannot select obsolete qualification history."""
        module = gate()
        event, _responses, checks, calls = pr_api_fixture(module)
        source = module.context(event, "pull_request_target", "forlex-ai/unit")
        self.assertEqual(source["base"], "b" * 40)
        self.assertEqual(source["base_ref"], "test")
        self.assertEqual(source["merge"], "c" * 40)
        self.assertEqual(source["check_id"], 3)
        self.assertEqual(source["merge_check_id"], 4)
        self.assertEqual([c["head_sha"] for c in checks.values()], ["a" * 40, "c" * 40])
        self.assertIn(("GET", "git/ref/heads/test", None), calls)

    def test_unaccepted_base_and_wrong_prospective_parents_cannot_create_checks(self):
        """Auxiliary bases and stale/foreign merge results refuse before check creation."""
        for changed in ["auxiliary", "parent", "reverse", "missing_merge", "bad_ref"]:
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            if changed == "auxiliary":
                responses["pulls/1"]["base"]["ref"] = "topic"
            elif changed == "parent":
                responses["git/commits/" + "c" * 40]["parents"][1]["sha"] = "e" * 40
            elif changed == "reverse":
                responses["git/commits/" + "c" * 40]["parents"].reverse()
            elif changed == "missing_merge":
                responses["pulls/1"]["merge_commit_sha"] = None
            else:
                responses["git/ref/heads/test"]["object"]["type"] = "tag"
            with self.assertRaises(ValueError):
                module.context(event, "pull_request_target", "forlex-ai/unit")
            self.assertFalse(checks)
            self.assertFalse(any(method == "POST" for method, _, _ in calls))

    def test_context_cli_outputs_merge_and_accepts_manifest_integration_branch(self):
        """The owning manifest branch can replace the common test default explicitly."""
        module = gate()
        event, responses, _checks, _calls = pr_api_fixture(module)
        responses["pulls/1"]["base"]["ref"] = "release"
        responses["git/ref/heads/release"] = {**responses.pop("git/ref/heads/test"), "ref": "refs/heads/release"}
        event["pull_request"]["base"]["ref"] = "release"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ep = root / "event"
            output = root / "context"
            gha = root / "output"
            ep.write_text(json.dumps(event))
            argv = [
                "secret_scan.py",
                "context",
                "--event",
                str(ep),
                "--kind",
                "pull_request_target",
                "--repository",
                "forlex-ai/unit",
                "--integration-branch",
                "release",
                "--output",
                str(output),
            ]
            with patch.object(sys, "argv", argv), patch.dict(os.environ, {"GITHUB_OUTPUT": str(gha)}):
                self.assertEqual(module.main(), 0)
            self.assertIn("merge=" + "c" * 40 + "\n", gha.read_text())
            self.assertEqual(json.loads(output.read_text())["integration_branch"], "release")

    def test_dual_check_publication_requires_current_ref_merge_and_trusted_candidate_parse(self):
        """Both immutable check targets complete only for the same qualified prospective result."""
        for changed in [None, "base", "head", "merge", "report_merge", "candidate_unvalidated"]:
            module = gate()
            event, responses, checks, calls = pr_api_fixture(module)
            source = module.context(event, "pull_request_target", "forlex-ai/unit")
            report = {
                **source,
                "version": 1,
                "result": "pass",
                "blocked": 0,
                "suppressed": 0,
                "commit_count": 3,
                "candidate_policy_validated": True,
                "candidate_policy_source": source["merge"],
                "candidate_policy_blob": "f" * 40,
            }
            if changed == "base":
                responses["git/ref/heads/test"]["object"]["sha"] = "e" * 40
            elif changed == "head":
                responses["pulls/1"]["head"]["sha"] = "e" * 40
            elif changed == "merge":
                responses["pulls/1"]["merge_commit_sha"] = "e" * 40
            elif changed == "report_merge":
                report["merge"] = "e" * 40
            elif changed == "candidate_unvalidated":
                report.pop("candidate_policy_validated")
            result = module.publish(source, report)
            expected = "success" if changed is None else "failure"
            self.assertEqual(result["conclusion"], expected)
            self.assertEqual([c["conclusion"] for c in checks.values()], [expected, expected])
            self.assertEqual([s for method, s, _ in calls if method == "PATCH"], ["check-runs/3", "check-runs/4"])

    def test_foreign_prospective_check_refuses_success_and_fails_only_verified_head(self):
            """A foreign merge check remains untouched while the verified original head fails safely."""
            module = gate()
            event, _responses, checks, calls = pr_api_fixture(module)
            source = module.context(event, "pull_request_target", "forlex-ai/unit")
            checks["check-runs/4"]["app"]["id"] = 46505
            report = {
                **source,
                "version": 1,
                "result": "pass",
                "blocked": 0,
                "suppressed": 0,
                "commit_count": 3,
                "candidate_policy_validated": True,
                "candidate_policy_source": source["merge"],
                "candidate_policy_blob": "f" * 40,
            }
            with self.assertRaises(ValueError):
                module.publish(source, report)
            self.assertEqual(
                [(suffix, body["conclusion"]) for method, suffix, body in calls if method == "PATCH"],
                [("check-runs/3", "failure")],
            )
            self.assertEqual(checks["check-runs/3"]["status"], "completed")
            self.assertEqual(checks["check-runs/4"]["status"], "in_progress")

    def test_base_moving_between_dual_writes_downgrades_both_original_checks(self):
        """A successful first write cannot remain qualified after live source changes."""
        module = gate()
        event, responses, checks, _calls = pr_api_fixture(module)
        source = module.context(event, "pull_request_target", "forlex-ai/unit")
        api = module.github

        def racing(repo, suffix, *, method="GET", body=None):
            result = api(repo, suffix, method=method, body=body)
            if method == "PATCH" and suffix == "check-runs/3" and body["conclusion"] == "success":
                responses["git/ref/heads/test"]["object"]["sha"] = "e" * 40
            return result

        module.github = racing
        report = {
            **source,
            "version": 1,
            "result": "pass",
            "blocked": 0,
            "suppressed": 0,
            "commit_count": 3,
            "candidate_policy_validated": True,
            "candidate_policy_source": source["merge"],
            "candidate_policy_blob": "f" * 40,
        }
        result = module.publish(source, report)
        self.assertEqual(result["conclusion"], "failure")
        self.assertEqual([check["conclusion"] for check in checks.values()], ["failure", "failure"])

    def test_candidate_policy_is_parsed_from_regular_git_data_without_following_symlinks(self):
        """Candidate executable helpers and symlink policy targets cannot run or change authority."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            path = repo / ".forlex/security"
            path.mkdir(parents=True)
            marker = root / "executed"
            outside = root / "outside-policy"
            outside.write_text('{"version":1,"exceptions":[]}')
            (path / "secret_scan.py").write_text("open(" + repr(str(marker)) + ',"w").write("executed")\n')
            target = path / "exceptions.json"

            def commit():
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        "commit",
                        "-qm",
                        "policy",
                    ],
                    check=True,
                )
                return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            target.write_text('{"version":1,"exceptions":[]}')
            head = commit()
            self.assertTrue(gate().validate_candidate_policy(repo, head))
            target.write_text('{"version":1,"version":1,"exceptions":[]}')
            head = commit()
            with self.assertRaises(ValueError):
                gate().validate_candidate_policy(repo, head)
            target.unlink()
            target.symlink_to(outside)
            head = commit()
            with self.assertRaises(ValueError):
                gate().validate_candidate_policy(repo, head)
            self.assertFalse(marker.exists())
            self.assertEqual(outside.read_text(), '{"version":1,"exceptions":[]}')

    def test_scan_cli_requires_prospective_candidate_policy_but_allows_prepolicy_history(self):
        """PR acceptance validates proposed rules; old historical/tag data keeps trusted rules."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(repo), "-c", "user.name=Unit", "-c", "user.email=unit@example.invalid", *args],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()

            git("commit", "--allow-empty", "-qm", "initial")
            ancestor = git("rev-parse", "HEAD")
            git("checkout", "-qb", "feature")
            (repo / "feature").write_text("clean candidate")
            git("add", ".")
            git("commit", "-qm", "feature")
            head = git("rev-parse", "HEAD")
            git("checkout", "-qb", "accepted", ancestor)
            (repo / "base").write_text("clean accepted")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            git("merge", "--no-ff", "-qm", "prospective", "feature")
            merge = git("rev-parse", "HEAD")
            marker = root / "scanner-called"
            scanner = root / "scanner"
            scanner.write_text(
                "#!/usr/bin/env python3\nfrom pathlib import Path\nPath("
                + repr(str(marker))
                + ').write_text("called")\n'
            )
            scanner.chmod(0o700)
            policy = root / "accepted-policy"
            policy.write_text('{"version":1,"exceptions":[]}')
            context = root / "context"
            output = root / "report"
            command = [
                "secret_scan.py",
                "scan",
                "--repo",
                str(repo),
                "--scanner",
                str(scanner),
                "--policy",
                str(policy),
                "--context",
                str(context),
                "--output",
                str(output),
            ]
            context.write_text(
                json.dumps(
                    {
                        "repository": "forlex-ai/unit",
                        "pr": 1,
                        "head": head,
                        "base": base,
                        "merge": merge,
                        "kind": "pull_request_target",
                    }
                )
            )
            with patch.object(sys, "argv", command):
                self.assertEqual(gate().main(), 1)
            self.assertFalse(marker.exists())
            self.assertEqual(json.loads(output.read_text())["result"], "error")
            context.write_text(
                json.dumps(
                    {"repository": "forlex-ai/unit", "pr": None, "head": ancestor, "base": None, "kind": "schedule"}
                )
            )
            with patch.object(sys, "argv", command):
                self.assertEqual(gate().main(), 0)
            self.assertTrue(marker.exists())
            self.assertEqual(json.loads(output.read_text())["result"], "pass")

    def test_proof_must_bind_immutable_repository_commit_and_path(self):
        """An exception cannot cite another source, a branch, or a mutable proof URL."""
        row = exception(finding())
        row["proof"] = "https://github.com/forlex-ai/unit/blob/" + row["commit"] + "/" + row["path"]
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps({"version": 1, "exceptions": [row]}))
            self.assertEqual(gate().read_policy(policy), [row])
            for proof in (
                row["proof"].replace("/unit/", "/other/"),
                row["proof"].replace(row["commit"], "main"),
                row["proof"].replace(row["commit"], "b" * 40),
                row["proof"] + "?raw=1",
                row["proof"] + "#line",
                row["proof"].replace("https://", "http://"),
                row["proof"].replace("/tests/", "/elsewhere/"),
            ):
                policy.write_text(json.dumps({"version": 1, "exceptions": [{**row, "proof": proof}]}))
                with self.assertRaises(ValueError):
                    gate().read_policy(policy)

    def test_json_writes_explicitly_label_the_request_body(self):
        """Checks API writes carry JSON content type and reads stay credential scoped."""
        module = gate()
        requests = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"{}"

        def send(request, **kwargs):
            requests.append(request)
            return Response()

        with (
            patch.dict(os.environ, {"GH_TOKEN": "inert-unit-auth"}),
            patch.object(module.urllib.request, "urlopen", send),
        ):
            module.github("forlex-ai/unit", "check-runs", method="POST", body={"name": "unit"})
            module.github("forlex-ai/unit", "check-runs/3", method="PATCH", body={"status": "completed"})
            module.github("forlex-ai/unit", "pulls/1")
        self.assertTrue(all(r.get_header("Content-type") == "application/json" for r in requests[:2]))
        self.assertIsNone(requests[2].data)

    def test_live_output_bounds_stop_both_streams_and_cleanup_the_process_group(self):
        """Refuse producers while they write, including a child retaining pipe descriptors."""
        module = gate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for stream in ["stdout", "stderr"]:
                output = root / (stream + "-out")
                errors = root / (stream + "-err")
                sentinel = root / (stream + "-survived")
                body = "import os,sys,time\nif os.fork()==0:\n time.sleep(0.5)\n open(sys.argv[1],'w').write('survived')\n os._exit(0)\n"
                body += "stream=sys." + stream + ".buffer\nwhile True:\n stream.write(b'x'*4096);stream.flush()\n"
                started = time.monotonic()
                with self.assertRaises(ValueError):
                    module.run_bounded_scanner(
                        [sys.executable, "-c", body, str(sentinel)],
                        os.environ.copy(),
                        output,
                        errors,
                        time.monotonic() + 4,
                        output_limit=8192,
                        error_limit=8192,
                    )
                self.assertLess(time.monotonic() - started, 2)
                self.assertLessEqual(output.stat().st_size, 8192)
                self.assertLessEqual(errors.stat().st_size, 8192)
                time.sleep(0.6)
                self.assertFalse(sentinel.exists(), "Scanner child survived refusal")

    def test_rewind_range_rescans_reachable_history(self):
        """A backwards branch update cannot claim an empty clean range."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "first",
                ],
                check=True,
            )
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "later",
                ],
                check=True,
            )
            before = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            effective, commits = gate().git_range(repo, head, before)
            self.assertIsNone(effective)
            self.assertEqual(commits, [head])

    def test_nonforward_push_with_unrelated_history_scans_the_complete_new_head(self):
        """A rewritten branch with no merge base retains complete replacement coverage."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def commit(message):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        "commit",
                        "--allow-empty",
                        "-qm",
                        message,
                    ],
                    check=True,
                )
                return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            before = commit("old history")
            subprocess.run(
                ["git", "-C", str(repo), "checkout", "--orphan", "replacement"], check=True, capture_output=True
            )
            first = commit("new root")
            head = commit("new tip")
            effective, commits = gate().git_range(repo, head, before, full_if_nonforward=True)
            self.assertIsNone(effective)
            self.assertEqual(commits, [head, first])

    def test_all_detection_states_block_by_default(self):
        """Verify all detection states block by default."""
        for row in (finding(), finding(verified=True), finding(error="verification unavailable")):
            with self.subTest(verified=row["Verified"]):
                self.assertFalse(gate().classify(row, [], "forlex-ai/unit")["suppressed"])

    def test_test_directories_are_scanned(self):
        """Verify test directories are scanned."""
        row = finding(path="tests/unit/new_secret.py")
        self.assertFalse(gate().classify(row, [], "forlex-ai/unit")["suppressed"])

    def test_exception_requires_exact_value_detector_path_commit_and_repo(self):
        """Verify exception requires exact value detector path commit and repo."""
        row = finding()
        rule = exception(row)
        self.assertTrue(gate().classify(row, [rule], "forlex-ai/unit")["suppressed"])
        for key, value in (
            ("path", "tests/unit/elsewhere.py"),
            ("detector", "GitHub"),
            ("commit", "b" * 40),
            ("fingerprint", "0" * 64),
            ("repository", "forlex-ai/another"),
        ):
            changed = {**rule, key: value}
            self.assertFalse(gate().classify(row, [changed], "forlex-ai/unit")["suppressed"])

    def test_verified_detection_cannot_be_suppressed(self):
        """Verify verified detection cannot be suppressed."""
        row = finding(verified=True)
        self.assertFalse(gate().classify(row, [exception(row)], "forlex-ai/unit")["suppressed"])

    def test_expired_exception_does_not_allow_a_finding(self):
        """Verify expired exception does not allow a finding."""
        row = finding()
        rule = {**exception(row), "expires": "2000-01-01"}
        self.assertFalse(gate().classify(row, [rule], "forlex-ai/unit")["suppressed"])

    def test_report_omits_raw_redacted_error_and_fingerprints(self):
        """Verify report omits raw redacted error and fingerprints."""
        raw = "never-print-this-synthetic-test-value"
        row = finding(raw, error=raw)
        row["Redacted"] = raw
        output = json.dumps(gate().classify(row, [], "forlex-ai/unit"))
        self.assertNotIn(raw, output)
        self.assertNotIn(hashlib.sha256(raw.encode()).hexdigest(), output)
        self.assertNotIn("VerificationError", output)

    def test_secret_in_filename_is_not_published(self):
        """Never publish credential bytes carried in Git path metadata."""
        raw = "synthetic-path-credential"
        row = finding(raw, path="tests/" + raw + ".py")
        result = gate().classify(row, [], "forlex-ai/unit")
        self.assertNotIn(raw, json.dumps(result))
        self.assertEqual(
            result["path_digest"], hashlib.sha256(row["SourceMetadata"]["Data"]["Git"]["file"].encode()).hexdigest()
        )

    def test_missing_or_invalid_finding_fields_fail_closed(self):
        """Verify missing or invalid finding fields fail closed."""
        for row in (
            {},
            {**finding(), "Raw": ""},
            {**finding(), "Verified": "false"},
            {**finding(), "SourceMetadata": {"Data": {"Git": {"commit": "HEAD"}}}},
        ):
            with self.assertRaises(ValueError):
                gate().classify(row, [], "forlex-ai/unit")

    def test_duplicate_json_keys_are_refused(self):
        """Verify duplicate json keys are refused."""
        with self.assertRaises(ValueError):
            gate().strict_json('{"Raw":"first","Raw":"second"}')

    def test_exception_policy_requires_all_explicit_fields(self):
        """Verify exception policy requires all explicit fields."""
        row = exception(finding())
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps({"version": 1, "exceptions": [row]}))
            self.assertEqual(gate().read_policy(policy), [row])
            for key in row:
                policy.write_text(
                    json.dumps({"version": 1, "exceptions": [{k: v for k, v in row.items() if k != key}]})
                )
                with self.assertRaises(ValueError):
                    gate().read_policy(policy)

    def test_validate_policy_cli_uses_strict_policy_and_redacts_rejections(self):
        """Validate the actual candidate policy without publishing rejected field values."""
        secret = "sensitive-policy-authority"
        rule = exception(finding())
        invalid = (
            "{",
            '{"version":1,"version":1,"exceptions":[]}',
            json.dumps({"version": 2, "exceptions": []}),
            json.dumps({"version": 1, "exceptions": [{**rule, "owner": secret}]}),
            json.dumps({"version": 1, "exceptions": [rule, rule]}),
        )
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            command = [
                sys.executable,
                str(Path(__file__).with_name("secret_scan.py")),
                "validate-policy",
                "--policy",
                str(policy),
            ]
            for body in invalid:
                with self.subTest(body=body):
                    policy.write_text(body)
                    result = subprocess.run(command, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn(secret, result.stdout + result.stderr)
            policy.write_text(json.dumps({"version": 1, "exceptions": [rule]}))
            self.assertEqual(subprocess.run(command, capture_output=True, check=False).returncode, 0)

    def test_scanner_error_and_invalid_output_fail_and_never_expose_output(self):
        """Verify scanner error and invalid output fail and never expose output."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            scanner = root / "scanner"
            for body in (
                "print('sensitive-but-synthetic-output'); raise SystemExit(1)",
                "print('invalid-json')",
                'import sys; print(\'{"level":"error","message":"sensitive-but-synthetic-output"}\', file=sys.stderr)',
                "import sys; print('unparsed-sensitive-diagnostic', file=sys.stderr)",
            ):
                scanner.write_text("#!/usr/bin/env python3\n" + body + "\n")
                scanner.chmod(0o700)
                result = gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 10)
                self.assertEqual(result["result"], "error")
                self.assertNotIn("sensitive-but-synthetic-output", json.dumps(result))
                self.assertEqual(list(root.glob("trufflehog-raw*")), [])

    def test_scanner_has_no_inherited_tokens_and_no_live_verification(self):
        """Verify scanner has no inherited tokens and no live verification."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            scanner = root / "scanner"
            scanner.write_text(
                "#!/usr/bin/env python3\nimport os,sys\nassert not any(k in os.environ for k in ('GH_TOKEN','GITHUB_TOKEN','AWS_SECRET_ACCESS_KEY'))\nassert '--no-verification' in sys.argv\nassert '--no-ignore-tag' in sys.argv\n"
            )
            scanner.chmod(0o700)
            original = os.environ.get("GH_TOKEN")
            os.environ["GH_TOKEN"] = "never-inherit-this-fixture"
            try:
                self.assertEqual(gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 10)["result"], "pass")
            finally:
                if original is None:
                    os.environ.pop("GH_TOKEN", None)
                else:
                    os.environ["GH_TOKEN"] = original

    def test_git_range_uses_merge_base_without_losing_intermediate_commits(self):
        """Verify git range uses merge base without losing intermediate commits."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def commit(text):
                (repo / "file").write_text(text)
                subprocess.run(["git", "-C", str(repo), "add", "file"], check=True)
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        "commit",
                        "-qm",
                        "change",
                    ],
                    check=True,
                )
                return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            base = commit("safe")
            introduced = commit("synthetic secret introduced")
            head = commit("safe again")
            effective, commits = gate().git_range(repo, head, base)
            self.assertEqual(effective, base)
            self.assertIn(introduced, commits)
            self.assertIn(head, commits)

    def test_missing_commit_and_shallow_history_are_refused(self):
        """Verify missing commit and shallow history are refused."""
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            gate().git_range(Path(directory), "a" * 40, None)

    def test_scan_timeout_fails_closed(self):
        """Verify scan timeout fails closed."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            scanner = root / "scanner"
            scanner.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(10)\n")
            scanner.chmod(0o700)
            self.assertEqual(gate().scan(repo, head, None, scanner, policy, "forlex-ai/unit", 0.1)["result"], "error")

    def test_stale_pr_and_foreign_check_cannot_publish_success(self):
        """Refuse changed source and a check owned by another publishing app."""
        module = gate()
        source = {"repository": "forlex-ai/unit", "pr": 1, "head": "a" * 40, "base": "b" * 40, "check_id": 3}
        report = {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": 2}
        calls = []

        def api(repository, suffix, *, method="GET", body=None):
            calls.append((method, suffix))
            if suffix.startswith("pulls/"):
                return {"state": "open", "head": {"sha": "c" * 40}, "base": {"sha": source["base"]}}
            return {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 46505}}

        module.github = api
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertFalse(any(method == "PATCH" for method, _ in calls))
        source["pr"] = None
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertFalse(any(method == "PATCH" for method, _ in calls))

    def test_original_check_identity_mismatch_never_patches(self):
        """Reject checks with a different original identity or publishing app."""
        source = {"repository": "forlex-ai/unit", "pr": 1, "head": "a" * 40, "base": "b" * 40, "check_id": 3}
        report = {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": 2}
        owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}
        for mismatched in (
            {**owned, "id": 4},
            {**owned, "head_sha": "c" * 40},
            {**owned, "name": "Other check"},
            {**owned, "app": {"id": 46505}},
        ):
            with self.subTest(mismatched=mismatched):
                module = gate()
                calls = []

                def api(
                    repository, suffix, *, method="GET", body=None, calls=calls, mismatched=mismatched, module=module
                ):
                    calls.append((method, suffix))
                    if suffix.startswith("pulls/"):
                        raise module.SecretScanRefusal("private current PR error")
                    return mismatched

                module.github = api
                with self.assertRaises(module.SecretScanRefusal):
                    module.publish(source, report)
                self.assertFalse(any(method == "PATCH" for method, _ in calls))

    def test_changed_or_unreadable_pr_finishes_original_owned_check_as_failure(self):
        """Close the original check safely when current PR evidence changes or is unavailable."""
        secret = "sensitive-current-pr-read-error"
        source = {"repository": "forlex-ai/unit", "pr": 1, "head": "a" * 40, "base": "b" * 40, "check_id": 3}
        report = {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": 2}
        for changed in ("head", "base", "closed", "unreadable"):
            with self.subTest(changed=changed):
                module = gate()
                calls = []
                owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}

                def api(
                    repository,
                    suffix,
                    *,
                    method="GET",
                    body=None,
                    calls=calls,
                    changed=changed,
                    module=module,
                    owned=owned,
                ):
                    calls.append((method, suffix, body))
                    if suffix.startswith("pulls/"):
                        if changed == "unreadable":
                            raise module.SecretScanRefusal(secret)
                        return {
                            "state": "closed" if changed == "closed" else "open",
                            "head": {"sha": "c" * 40 if changed == "head" else source["head"]},
                            "base": {"sha": "c" * 40 if changed == "base" else source["base"]},
                        }
                    return {**owned, **body} if method == "PATCH" else owned

                module.github = api
                try:
                    result = module.publish(source, report)
                except module.SecretScanRefusal:
                    result = {"conclusion": "refused"}
                self.assertEqual(result["conclusion"], "failure")
                patches = [(suffix, body) for method, suffix, body in calls if method == "PATCH"]
                self.assertEqual(len(patches), 1)
                self.assertEqual(patches[0][0], "check-runs/3")
                self.assertEqual(patches[0][1]["status"], "completed")
                self.assertNotIn(secret, json.dumps(result))

    def test_check_read_and_patch_errors_refuse_without_exposing_provider_text(self):
            """Unavailable check identity or completion must not claim a terminal result."""
            secret = "sensitive-check-provider-error"
            source = {"repository": "forlex-ai/unit", "pr": 1, "head": "a" * 40, "base": "b" * 40, "check_id": 3}
            report = {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": 2}
            for failed in ("check-read", "patch"):
                with self.subTest(failed=failed):
                    module = gate()
                    calls = []

                    def api(
                        repository, suffix, *, method="GET", body=None, calls=calls, failed=failed, module=module
                    ):
                        calls.append((method, suffix, body))
                        if suffix.startswith("pulls/"):
                            raise module.SecretScanRefusal(secret)
                        if failed == "check-read" or method == "PATCH":
                            raise module.SecretScanRefusal(secret)
                        return {
                            "id": 3,
                            "head_sha": source["head"],
                            "name": "TruffleHog secret scan",
                            "app": {"id": 15368},
                        }

                    module.github = api
                    with self.assertRaises(module.SecretScanRefusal) as refusal:
                        module.publish(source, report)
                    self.assertNotIn(secret, str(refusal.exception))
                    patches = [body for method, _, body in calls if method == "PATCH"]
                    self.assertEqual(len(patches), 2 if failed == "patch" else 0)
                    self.assertTrue(all(body["conclusion"] == "failure" for body in patches))
                    for index, (method, suffix, _body) in enumerate(calls):
                        if method == "PATCH":
                            self.assertEqual(calls[index - 1], ("GET", suffix, None))

    def test_patch_response_must_confirm_original_owned_terminal_result(self):
            """Never infer successful completion from an incomplete or contradictory API response."""
            source = {"repository": "forlex-ai/unit", "pr": None, "head": "a" * 40, "base": None, "check_id": 3}
            report = {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": 2}
            owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog history scan", "app": {"id": 15368}}
            for response in (
                {**owned, "status": "completed", "conclusion": "success", "id": 4},
                {**owned, "status": "in_progress", "conclusion": "success"},
                {**owned, "status": "completed", "conclusion": "failure"},
                {**owned, "status": "completed", "conclusion": "success", "head_sha": "c" * 40},
                {**owned, "status": "completed", "conclusion": "success", "app": {"id": 46505}},
                {},
            ):
                with self.subTest(response=response):
                    module = gate()
                    module.github = lambda *args, method="GET", response=response, **kwargs: (
                        response if method == "PATCH" else owned
                    )
                    with self.assertRaises(module.SecretScanRefusal):
                        module.publish(source, report)

    def test_failed_report_counts_are_redacted_in_published_failure(self):
            """Malformed counts cannot carry secret bytes into a terminal summary."""
            module = gate()
            secret = "sensitive-report-count"
            source = {"repository": "forlex-ai/unit", "pr": None, "head": "a" * 40, "base": None, "check_id": 3}
            owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog history scan", "app": {"id": 15368}}
            module.github = lambda *args, method="GET", body=None: (
                {**owned, **body} if method == "PATCH" else owned
            )
            result = module.publish(
                source, {"result": "error", "blocked": secret, "suppressed": secret, "commit_count": secret}
            )
            self.assertEqual(result["conclusion"], "failure")
            self.assertNotIn(secret, json.dumps(result))

    def test_missing_and_inconsistent_reports_publish_failure(self):
            """Do not accept a declared pass with failed or incomplete scan counts."""
            module = gate()
            source = {"repository": "forlex-ai/unit", "pr": None, "head": "a" * 40, "base": None, "check_id": 3}

            def api(repository, suffix, *, method="GET", body=None):
                owned = {
                    "id": 3,
                    "head_sha": source["head"],
                    "name": "TruffleHog history scan",
                    "app": {"id": 15368},
                }
                if method == "PATCH":
                    return {**owned, **body}
                return owned

            module.github = api
            for report in (
                {"result": "error"},
                {**source, "version": 1, "result": "pass", "blocked": 1, "suppressed": 0, "commit_count": 2},
                {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": -1},
            ):
                self.assertEqual(module.publish(source, report)["conclusion"], "failure")

    def test_publish_cli_unreadable_or_nonobject_report_finishes_owned_check_as_failure(self):
        """Damaged report artifacts still terminate only the verified trusted check."""
        secret = "sensitive-report-artifact"
        source = {"repository": "forlex-ai/unit", "pr": 1, "head": "a" * 40, "base": "b" * 40, "check_id": 3}
        owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}
        artifacts = (
            ("malformed", '{"raw":"' + secret),
            ("duplicate", '{"raw":"' + secret + '","raw":"duplicate"}'),
            ("string", json.dumps(secret)),
            ("list", json.dumps([secret])),
            ("null", "null"),
            ("number", "7"),
            ("boolean", "true"),
            ("encoding", b"\xff" + secret.encode()),
            ("directory", None),
            ("missing", None),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = root / "context.json"
            context.write_text(json.dumps(source))
            for kind, data in artifacts:
                with self.subTest(kind=kind):
                    module = gate()
                    calls = []
                    report = root / kind
                    if isinstance(data, bytes):
                        report.write_bytes(data)
                    elif isinstance(data, str):
                        report.write_text(data)
                    elif kind == "directory":
                        report.mkdir()

                    def api(repository, suffix, *, method="GET", body=None, calls=calls):
                        calls.append((method, suffix, body))
                        if suffix.startswith("pulls/"):
                            return {"state": "open", "head": {"sha": source["head"]}, "base": {"sha": source["base"]}}
                        return {**owned, **body} if method == "PATCH" else owned

                    module.github = api
                    argv = ["secret_scan.py", "publish", "--context", str(context), "--report", str(report)]
                    with (
                        patch.object(sys, "argv", argv),
                        patch("sys.stdout", new_callable=io.StringIO) as stdout,
                        patch("sys.stderr", new_callable=io.StringIO) as stderr,
                    ):
                        self.assertEqual(module.main(), 1)
                    self.assertEqual(
                        [(method, suffix) for method, suffix, _ in calls],
                        [("GET", "pulls/1"), ("GET", "check-runs/3"), ("PATCH", "check-runs/3")],
                    )
                    self.assertEqual(calls[-1][2]["conclusion"], "failure")
                    self.assertEqual(calls[-1][2]["status"], "completed")
                    self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue() + json.dumps(calls))

    def test_publish_cli_unreadable_context_cannot_choose_a_check(self):
        """Refuse before API access when trusted check identity cannot be read."""
        secret = "sensitive-context-artifact"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text('{"result":"error"}')
            for name, data in (
                ("malformed", '{"raw":"' + secret),
                ("nonobject", json.dumps([secret])),
                ("missing", None),
            ):
                with self.subTest(name=name):
                    module = gate()
                    module.github = lambda *args, **kwargs: self.fail("Unverifiable context reached the API")
                    context = root / name
                    if data is not None:
                        context.write_text(data)
                    argv = ["secret_scan.py", "publish", "--context", str(context), "--report", str(report)]
                    with (
                        patch.object(sys, "argv", argv),
                        patch("sys.stdout", new_callable=io.StringIO) as stdout,
                        patch("sys.stderr", new_callable=io.StringIO) as stderr,
                    ):
                        self.assertEqual(module.main(), 1)
                    self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

    def test_unsupported_events_cannot_create_checks(self):
        """Allow only the explicitly supported trusted workflow events."""
        module = gate()
        module.github = lambda *args, **kwargs: self.fail("An unsupported event reached the GitHub API")
        with self.assertRaises(ValueError):
            module.context({"repository": {"full_name": "forlex-ai/unit"}}, "issue_comment", "forlex-ai/unit")

    def test_tag_push_uses_native_commit_head_and_full_history_scope(self):
        """An updated annotated tag's prior object cannot limit metadata admission."""
        module = gate()
        module.github = lambda *args, **kwargs: {"id": 3}
        event = {
            "repository": {"full_name": "forlex-ai/unit"},
            "ref": "refs/tags/release",
            "before": "b" * 40,
            "after": "c" * 40,
        }
        with patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
            source = module.context(event, "push", "forlex-ai/unit")
            self.assertEqual(source["head"], "a" * 40)
            self.assertIsNone(source["base"])
            self.assertEqual(source.get("tag_object"), "c" * 40)
            self.assertEqual(source.get("tag_ref"), "refs/tags/release")
            source = module.context({**event, "ref": "refs/heads/test"}, "push", "forlex-ai/unit")
            self.assertEqual(source["base"], "b" * 40)
            self.assertNotIn("tag_object", source)

    def test_tag_context_cli_outputs_validated_exact_pushed_object(self):
        """The inert checkout must receive the immutable event object, never a mutable ref."""
        module = gate()
        module.github = lambda *args, **kwargs: {"id": 3}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / "event.json"
            output = root / "context.json"
            gha_output = root / "gha-output"
            event.write_text(
                json.dumps(
                    {"repository": {"full_name": "forlex-ai/unit"}, "ref": "refs/tags/release", "after": "c" * 40}
                )
            )
            argv = [
                "secret_scan.py",
                "context",
                "--event",
                str(event),
                "--kind",
                "push",
                "--repository",
                "forlex-ai/unit",
                "--output",
                str(output),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.dict(os.environ, {"GITHUB_SHA": "a" * 40, "GITHUB_OUTPUT": str(gha_output)}),
            ):
                self.assertEqual(module.main(), 0)
            self.assertIn("tag_object=" + "c" * 40 + "\n", gha_output.read_text())
            self.assertNotIn("refs/tags/release", gha_output.read_text())

    def test_tag_report_must_bind_exact_pushed_object_and_ref_digest(self):
            """A commit-only pass cannot stand in for the pushed tag object's scan."""
            module = gate()
            source = {
                "repository": "forlex-ai/unit",
                "pr": None,
                "head": "a" * 40,
                "base": None,
                "check_id": 3,
                "tag_object": "c" * 40,
                "tag_ref": "refs/tags/release",
            }
            report = {
                "repository": source["repository"],
                "head": source["head"],
                "base": None,
                "version": 1,
                "result": "pass",
                "blocked": 0,
                "suppressed": 0,
                "commit_count": 2,
            }
            owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog history scan", "app": {"id": 15368}}
            module.github = lambda *args, method="GET", body=None: (
                {**owned, **body} if method == "PATCH" else owned
            )
            self.assertEqual(module.publish(source, report)["conclusion"], "failure")
            qualified = {
                **report,
                "tag_object": source["tag_object"],
                "tag_ref_digest": hashlib.sha256(source["tag_ref"].encode()).hexdigest(),
            }
            self.assertEqual(module.publish(source, qualified)["conclusion"], "success")


@unittest.skipUnless(
    os.environ.get("TRUFFLEHOG_BINARY"), "Real pinned scanner not provided; native qualification is separate"
)
class NativeScannerTests(unittest.TestCase):
    """Exercise real offline detection in disposable Git history."""

    def test_native_missing_old_push_tip_still_detects_reachable_canary(self):
            """Real offline detection covers new reachable history when the orphaned old tip is absent."""
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo = root / "repo"
                repo.mkdir()
                self.git(repo, "init", "-q")
                value = self.canary()
                (repo / "fixture.txt").write_text("token=" + value + "\n")
                introduced = self.commit(repo)
                (repo / "fixture.txt").unlink()
                head = self.commit(repo)
                policy = root / "policy.json"
                policy.write_text('{"version":1,"exceptions":[]}')
                module = gate()
                report = module.scan(
                    repo,
                    head,
                    "f" * 40,
                    Path(os.environ["TRUFFLEHOG_BINARY"]),
                    policy,
                    "forlex-ai/unit",
                    60,
                    full_if_nonforward=True,
                )
                self.assertEqual(report["result"], "fail", json.dumps(report))
                self.assertIsNone(report["effective_base"])
                self.assertEqual(report["commit_count"], 2)
                self.assertGreater(report["blocked"], 0)
                self.assertTrue(any(row["commit"] == introduced for row in report["findings"]))
                self.assertNotIn(value, json.dumps(report))
                self.assertEqual(
                    module.scan(
                        repo, head, "f" * 40, Path(os.environ["TRUFFLEHOG_BINARY"]), policy, "forlex-ai/unit", 60
                    )["result"],
                    "error",
                )

    def git(self, repo, *args):
        """Operate on one inert disposable fixture repository."""
        return subprocess.check_output(
            ["git", "-C", str(repo), "-c", "user.name=Unit", "-c", "user.email=unit@example.invalid", *args],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()

    def canary(self, marker=""):
        """Create an unregistered valid-format detector canary."""
        return (
            "ghp_"
            + marker
            + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36 - len(marker)))
        )

    def commit(self, repo, message="fixture"):
        """Record fixture data without executing repository hooks."""
        self.git(repo, "add", ".")
        self.git(repo, "commit", "-qm", message)
        return self.git(repo, "rev-parse", "HEAD")

    def scan(self, root, repo, head, base=None, exceptions=None):
        """Run the pinned offline executable against actual fixture history."""
        policy = root / "policy.json"
        rules = [{**row, "proof": proof_url(row)} for row in exceptions or []]
        policy.write_text(json.dumps({"version": 1, "exceptions": rules}))
        return gate().scan(repo, head, base, Path(os.environ["TRUFFLEHOG_BINARY"]), policy, "forlex-ai/unit", 60)

    def test_same_canary_in_distinct_blobs_retains_the_unexcepted_occurrence(self):
        """Native value deduplication cannot hide another distinct exact source."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            (repo / "first.txt").write_text("TOKEN = " + repr(raw) + "\n")
            first = self.commit(repo)
            (repo / "second.txt").write_text("different blob context\nTOKEN = " + repr(raw) + "\n")
            head = self.commit(repo)
            rule = {**exception(finding(raw, path="first.txt")), "commit": first, "detector": "Github"}
            result = self.scan(root, repo, head, exceptions=[rule])
            self.assertEqual(result["result"], "fail", json.dumps(result))
            self.assertGreater(result["suppressed"], 0)
            self.assertGreater(result["blocked"], 0)
            self.assertNotIn(raw, json.dumps(result))
            self.assertTrue(
                any(
                    r["commit"] == head
                    and r["path_digest"] == hashlib.sha256(b"second.txt").hexdigest()
                    and not r["suppressed"]
                    for r in result["findings"]
                )
            )

    def test_unchanged_second_parent_fixture_is_not_rebound_to_merge_commit(self):
        """Merging the accepted base preserves its original exact fixture authority."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            (repo / "README").write_text("clean\n")
            ancestor = self.commit(repo)
            self.git(repo, "checkout", "-qb", "feature")
            (repo / "feature.txt").write_text("clean feature\n")
            self.commit(repo)
            self.git(repo, "checkout", "-qb", "accepted", ancestor)
            raw = self.canary()
            (repo / "fixture.txt").write_text("TOKEN = " + repr(raw) + "\n")
            base = self.commit(repo)
            self.git(repo, "checkout", "-q", "feature")
            self.git(repo, "merge", "--no-ff", "-qm", "merge accepted base", "accepted")
            head = self.git(repo, "rev-parse", "HEAD")
            rule = {**exception(finding(raw, path="fixture.txt")), "commit": base, "detector": "Github"}
            result = self.scan(root, repo, head, base, [rule])
            self.assertEqual(result["result"], "pass", json.dumps(result))
            payloads = root / "payloads"
            payloads.mkdir()
            _, commits = gate().git_range(repo, head, base)
            index = gate().materialize(repo, commits, payloads, time.monotonic() + 60)
            self.assertFalse(any(s["file"] == "fixture.txt" for sources in index.values() for s in sources))

    def test_native_rewind_still_detects_reachable_canary(self):
        """A later clean commit cannot make an earlier unsafe head an empty rewind."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            (repo / "fixture.txt").write_text("TOKEN = " + repr(raw) + "\n")
            head = self.commit(repo)
            (repo / "fixture.txt").write_text("clean after removal\n")
            before = self.commit(repo)
            result = self.scan(root, repo, head, before)
            self.assertEqual(result["result"], "fail", json.dumps(result))
            self.assertGreater(result["blocked"], 0)

    def test_prospective_merge_result_is_scanned_and_wrong_parent_binding_refuses(self):
        """A source found only in the validated merge result blocks pre-acceptance."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            (repo / "README").write_text("clean common source\n")
            ancestor = self.commit(repo)
            self.git(repo, "checkout", "-qb", "feature")
            (repo / "feature").write_text("clean candidate\n")
            head = self.commit(repo)
            self.git(repo, "checkout", "-qb", "accepted", ancestor)
            (repo / "base").write_text("clean accepted\n")
            base = self.commit(repo)
            self.git(repo, "merge", "--no-ff", "--no-commit", "feature")
            raw = self.canary()
            (repo / "merged").write_text("TOKEN = " + repr(raw) + "\n")
            merge = self.commit(repo)
            policy = root / "policy"
            policy.write_text('{"version":1,"exceptions":[]}')
            module = gate()
            scanner = Path(os.environ["TRUFFLEHOG_BINARY"])
            self.assertEqual(module.scan(repo, head, base, scanner, policy, "forlex-ai/unit", 60)["result"], "pass")
            result = module.scan(repo, head, base, scanner, policy, "forlex-ai/unit", 60, merge=merge)
            self.assertEqual(result["result"], "fail", json.dumps(result))
            self.assertEqual(result["merge"], merge)
            self.assertTrue(any(r["commit"] == merge for r in result["findings"]))
            self.assertNotIn(raw, json.dumps(result))
            self.assertEqual(
                module.scan(repo, head, ancestor, scanner, policy, "forlex-ai/unit", 60, merge=merge)["result"], "error"
            )

    def test_valid_candidate_exception_is_inert_and_cannot_waive_accepted_policy(self):
        """Even schema-valid candidate fixture rules cannot suppress a trusted scan."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            (repo / "fixture.txt").write_text("TOKEN = " + repr(raw) + "\n")
            first = self.commit(repo)
            rule = {**exception(finding(raw, path="fixture.txt")), "commit": first, "detector": "Github"}
            rule["proof"] = proof_url(rule)
            path = repo / ".forlex/security"
            path.mkdir(parents=True)
            (path / "exceptions.json").write_text(json.dumps({"version": 1, "exceptions": [rule]}))
            head = self.commit(repo)
            policy = root / "accepted-policy"
            policy.write_text('{"version":1,"exceptions":[]}')
            result = gate().scan(
                repo,
                head,
                None,
                Path(os.environ["TRUFFLEHOG_BINARY"]),
                policy,
                "forlex-ai/unit",
                60,
                candidate_policy=".forlex/security/exceptions.json",
            )
            self.assertEqual(result["result"], "fail", json.dumps(result))
            self.assertTrue(result["candidate_policy_validated"])
            self.assertEqual(result["candidate_policy_source"], head)
            self.assertGreater(result["blocked"], 0)
            self.assertEqual(result["suppressed"], 0)

    def test_annotated_tag_message_is_scanned_only_in_full_history_and_never_excepted(self):
        """Current tag metadata blocks independently of commit-range fixture policy."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            (repo / "README").write_text("clean source\n")
            base = self.commit(repo)
            raw = self.canary()
            self.git(repo, "tag", "-a", "release", "-m", "TOKEN = " + raw)
            tag = self.git(repo, "rev-parse", "refs/tags/release")
            self.git(repo, "tag", "lightweight", base)
            (repo / "README").write_text("clean updated source\n")
            head = self.commit(repo)
            rule = {**exception(finding(raw, path="@tag-metadata")), "commit": tag, "detector": "Github"}
            delta = self.scan(root, repo, head, base, [rule])
            self.assertEqual(delta["result"], "pass", json.dumps(delta))
            self.assertFalse(any(row["source_kind"] == "tag_metadata" for row in delta["findings"]))
            full = self.scan(root, repo, head, exceptions=[rule])
            self.assertEqual(full["result"], "fail", json.dumps(full))
            self.assertTrue(
                any(row["source_kind"] == "tag_metadata" and row["commit"] == tag for row in full["findings"])
            )
            self.assertEqual(full["suppressed"], 0)
            self.assertNotIn(raw, json.dumps(full))
            payloads = root / "payloads"
            payloads.mkdir()
            _, commits = gate().git_range(repo, head, None)
            index = gate().materialize(repo, commits, payloads, time.monotonic() + 60, include_tags=True)
            tag_sources = [
                source for sources in index.values() for source in sources if source["kind"] == "tag_metadata"
            ]
            self.assertEqual([source["commit"] for source in tag_sources], [tag])

    def test_nested_annotated_tag_metadata_remains_scanned_after_inner_ref_is_deleted(self):
        """Scan every tag object reachable through a current annotated tag ref."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            (repo / "README").write_text("clean source\n")
            head = self.commit(repo)
            raw = self.canary()
            self.git(repo, "tag", "-a", "inner", "-m", "TOKEN = " + raw)
            inner = self.git(repo, "rev-parse", "refs/tags/inner")
            self.git(repo, "tag", "-a", "outer", "inner", "-m", "Clean outer tag")
            outer = self.git(repo, "rev-parse", "refs/tags/outer")
            self.git(repo, "tag", "-d", "inner")
            report = self.scan(root, repo, head)
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertTrue(
                any(row["source_kind"] == "tag_metadata" and row["commit"] == inner for row in report["findings"])
            )
            self.assertNotIn(raw, json.dumps(report))
            payloads = root / "payloads"
            payloads.mkdir()
            _, commits = gate().git_range(repo, head, None)
            index = gate().materialize(repo, commits, payloads, time.monotonic() + 60, include_tags=True)
            admitted = {
                source["commit"] for sources in index.values() for source in sources if source["kind"] == "tag_metadata"
            }
            self.assertEqual(admitted, {inner, outer})

    def test_pushed_tag_object_remains_bound_after_ref_moves_and_missing_object_refuses(self):
        """Current clean metadata cannot replace an immutable pushed tag object."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            (repo / "README").write_text("clean source\n")
            head = self.commit(repo)
            raw = self.canary()
            self.git(repo, "tag", "-a", "release", "-m", "TOKEN = " + raw)
            pushed = self.git(repo, "rev-parse", "refs/tags/release")
            self.git(repo, "tag", "-f", "-a", "release", "-m", "Clean replacement")
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            self.assertEqual(self.scan(root, repo, head)["result"], "pass")

            def pushed_scan():
                return gate().scan(
                    repo,
                    head,
                    None,
                    Path(os.environ["TRUFFLEHOG_BINARY"]),
                    policy,
                    "forlex-ai/unit",
                    60,
                    tag_object=pushed,
                    tag_ref="refs/tags/release",
                )

            report = pushed_scan()
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertEqual(report["tag_object"], pushed)
            self.assertTrue(
                any(row["source_kind"] == "tag_metadata" and row["commit"] == pushed for row in report["findings"])
            )
            self.assertNotIn(raw, json.dumps(report))
            self.assertNotIn("refs/tags/release", json.dumps(report))
            (repo / ".git" / "objects" / pushed[:2] / pushed[2:]).unlink()
            self.assertEqual(pushed_scan()["result"], "error")

    def test_lightweight_tag_push_is_commit_bound_and_invalid_tag_scope_refuses(self):
        """Lightweight pushes scan commits without inventing annotated metadata."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            (repo / "README").write_text("clean source\n")
            first = self.commit(repo)
            self.git(repo, "tag", "release", first)
            (repo / "README").write_text("clean later source\n")
            head = self.commit(repo)
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            module = gate()
            scanner = Path(os.environ["TRUFFLEHOG_BINARY"])
            report = module.scan(
                repo, first, None, scanner, policy, "forlex-ai/unit", 60, tag_object=first, tag_ref="refs/tags/release"
            )
            self.assertEqual(report["result"], "pass", json.dumps(report))
            self.assertFalse(any(row["source_kind"] == "tag_metadata" for row in report["findings"]))
            payloads = root / "payloads"
            payloads.mkdir()
            _, commits = module.git_range(repo, first, None)
            index = module.materialize(
                repo, commits, payloads, time.monotonic() + 60, include_tags=True, tag_object=first, tag_head=first
            )
            self.assertFalse(any(source["kind"] == "tag_metadata" for sources in index.values() for source in sources))
            mismatch = module.scan(
                repo, head, None, scanner, policy, "forlex-ai/unit", 60, tag_object=first, tag_ref="refs/tags/release"
            )
            self.assertEqual(mismatch["result"], "error")
            delta = module.scan(
                repo, head, first, scanner, policy, "forlex-ai/unit", 60, tag_object=first, tag_ref="refs/tags/release"
            )
            self.assertEqual(delta["result"], "error")

    def test_merge_only_resolution_is_scanned(self):
        """Detect a secret present only in the resolved merge commit."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            target = repo / "source.txt"
            target.write_text("base\n")
            base = self.commit(repo)
            self.git(repo, "checkout", "-qb", "feature")
            target.write_text("feature\n")
            self.commit(repo)
            self.git(repo, "checkout", "-qb", "side", base)
            target.write_text("side\n")
            self.commit(repo)
            self.git(repo, "checkout", "-q", "feature")
            merged = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "merge",
                    "side",
                    "--no-commit",
                ],
                capture_output=True,
                check=False,
            )
            self.assertEqual(merged.returncode, 1)
            raw = self.canary()
            target.write_text("TOKEN = " + repr(raw) + "\n")
            head = self.commit(repo)
            for since in (base, None):
                report = self.scan(root, repo, head, since)
                self.assertEqual(report["result"], "fail", json.dumps(report))
                self.assertNotIn(raw, json.dumps(report))

    def test_modified_rename_is_scanned_in_full_history_and_pr_range(self):
        """Cover a high-similarity rename that native Git history skipped."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            lines = "".join("safe line " + str(i) + "\n" for i in range(100))
            (repo / "old.txt").write_text(lines)
            base = self.commit(repo)
            self.git(repo, "mv", "old.txt", "new.txt")
            raw = self.canary()
            (repo / "new.txt").write_text(lines + "TOKEN = " + repr(raw) + "\n")
            head = self.commit(repo)
            self.assertTrue(self.git(repo, "diff", "--name-status", base, head).startswith("R"))
            for since in (base, None):
                report = self.scan(root, repo, head, since)
                self.assertEqual(report["result"], "fail", json.dumps(report))
                self.assertNotIn(raw, json.dumps(report))

    def test_wordlist_and_filename_do_not_waive_or_expose_canaries(self):
        """Keep native filtered findings and hide arbitrary source filenames."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary("example")
            (repo / (raw + ".txt")).write_text("TOKEN = " + repr(raw) + "\n")
            head = self.commit(repo)
            report = self.scan(root, repo, head)
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertNotIn(raw, json.dumps(report))

    def test_commit_metadata_and_symlink_targets_are_scanned_as_inert_data(self):
        """Preserve metadata coverage and never follow candidate symlinks."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            (repo / "link").symlink_to(raw)
            head = self.commit(repo, self.canary())
            report = self.scan(root, repo, head)
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertGreaterEqual(report["blocked"], 2)
            self.assertNotIn(raw, json.dumps(report))

    def test_exact_fixture_exception_does_not_waive_new_commit_associations(self):
        """A subsequent file edit must qualify its own immutable exception."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            self.git(repo, "init", "-q")
            raw = self.canary()
            target = repo / "fixture.txt"
            target.write_text("TOKEN = " + repr(raw) + "\n")
            first = self.commit(repo)
            row = finding(raw, path="fixture.txt")
            rule = {**exception(row), "detector": "Github", "commit": first}
            first_report = self.scan(root, repo, first, exceptions=[rule])
            self.assertEqual(first_report["result"], "pass", json.dumps(first_report))
            target.write_text(target.read_text() + "safe edit\n")
            head = self.commit(repo)
            report = self.scan(root, repo, head, exceptions=[rule])
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertGreater(report["suppressed"], 0)

    def test_real_scanner_catches_introduced_then_deleted_test_directory_canary(self):
        """Verify real scanner catches introduced then deleted test directory canary."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)

            def commit():
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=Unit",
                        "-c",
                        "user.email=unit@example.invalid",
                        "commit",
                        "-qm",
                        "fixture",
                    ],
                    check=True,
                )
                return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            (repo / "README").write_text("safe source")
            base = commit()
            target = repo / "tests/unit/canary.py"
            target.parent.mkdir(parents=True)
            # Random valid-format canary, never registered at GitHub or any provider.
            value = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
            target.write_text("TOKEN = " + repr(value) + "  # trufflehog:ignore\n")
            introduced = commit()
            target.unlink()
            head = commit()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            report = gate().scan(repo, head, base, Path(os.environ["TRUFFLEHOG_BINARY"]), policy, "forlex-ai/unit", 60)
            self.assertEqual(report["result"], "fail", json.dumps(report))
            self.assertGreater(report["blocked"], 0)
            self.assertTrue(
                any(
                    row["commit"] == introduced
                    and row["path_digest"] == hashlib.sha256(b"tests/unit/canary.py").hexdigest()
                    for row in report["findings"]
                )
            )
            self.assertNotIn(value, json.dumps(report))

    def test_real_scanner_clean_full_history_passes(self):
        """Verify real scanner clean full history passes."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "README").write_text("clean source\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Unit",
                    "-c",
                    "user.email=unit@example.invalid",
                    "commit",
                    "-qm",
                    "initial",
                ],
                check=True,
            )
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            policy = root / "policy.json"
            policy.write_text('{"version":1,"exceptions":[]}')
            report = gate().scan(repo, head, None, Path(os.environ["TRUFFLEHOG_BINARY"]), policy, "forlex-ai/unit", 60)
            self.assertEqual(report["result"], "pass", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
