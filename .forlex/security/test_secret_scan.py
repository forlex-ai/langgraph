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
    return {
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


class GateTests(unittest.TestCase):
    """Exercise redaction, exception boundaries and scanner failure behavior."""

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

                def api(repository, suffix, *, method="GET", body=None, calls=calls, failed=failed, module=module):
                    calls.append((method, suffix, body))
                    if suffix.startswith("pulls/"):
                        raise module.SecretScanRefusal(secret)
                    if failed == "check-read" or method == "PATCH":
                        raise module.SecretScanRefusal(secret)
                    return {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}

                module.github = api
                with self.assertRaises(module.SecretScanRefusal) as refusal:
                    module.publish(source, report)
                self.assertNotIn(secret, str(refusal.exception))
                patches = [body for method, _, body in calls if method == "PATCH"]
                self.assertEqual(len(patches), 1 if failed == "patch" else 0)
                self.assertTrue(all(body["conclusion"] == "failure" for body in patches))

    def test_patch_response_must_confirm_original_owned_terminal_result(self):
        """Never infer successful completion from an incomplete or contradictory API response."""
        source = {"repository": "forlex-ai/unit", "pr": None, "head": "a" * 40, "base": None, "check_id": 3}
        report = {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": 2}
        owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}
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
        owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}
        module.github = lambda *args, method="GET", body=None: {**owned, **body} if method == "PATCH" else owned
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
            owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}
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
        owned = {"id": 3, "head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}
        module.github = lambda *args, method="GET", body=None: {**owned, **body} if method == "PATCH" else owned
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
        policy.write_text(json.dumps({"version": 1, "exceptions": exceptions or []}))
        return gate().scan(repo, head, base, Path(os.environ["TRUFFLEHOG_BINARY"]), policy, "forlex-ai/unit", 60)

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
