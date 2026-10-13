"""Behavioral tests for the secret gate; no live credential is used."""

import hashlib
import importlib.util
import json
import os
import secrets
import string
import subprocess
import tempfile
import unittest
from pathlib import Path


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
            return {"head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 46505}}

        module.github = api
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertFalse(any(method == "PATCH" for method, _ in calls))
        source["pr"] = None
        with self.assertRaises(ValueError):
            module.publish(source, report)
        self.assertFalse(any(method == "PATCH" for method, _ in calls))

    def test_missing_and_inconsistent_reports_publish_failure(self):
        """Do not accept a declared pass with failed or incomplete scan counts."""
        module = gate()
        source = {"repository": "forlex-ai/unit", "pr": None, "head": "a" * 40, "base": None, "check_id": 3}

        def api(repository, suffix, *, method="GET", body=None):
            if method == "PATCH":
                return body
            return {"head_sha": source["head"], "name": "TruffleHog secret scan", "app": {"id": 15368}}

        module.github = api
        for report in (
            {"result": "error"},
            {**source, "version": 1, "result": "pass", "blocked": 1, "suppressed": 0, "commit_count": 2},
            {**source, "version": 1, "result": "pass", "blocked": 0, "suppressed": 0, "commit_count": -1},
        ):
            self.assertEqual(module.publish(source, report)["conclusion"], "failure")

    def test_unsupported_events_cannot_create_checks(self):
        """Allow only the explicitly supported trusted workflow events."""
        module = gate()
        module.github = lambda *args, **kwargs: self.fail("An unsupported event reached the GitHub API")
        with self.assertRaises(ValueError):
            module.context({"repository": {"full_name": "forlex-ai/unit"}}, "issue_comment", "forlex-ai/unit")


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
                ["git", "-C", str(repo), "merge", "side", "--no-commit"], capture_output=True, check=False
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
