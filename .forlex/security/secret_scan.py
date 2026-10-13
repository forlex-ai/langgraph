"""TruffleHog gate: scan Git data only, fail closed, and never publish secret bytes."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, date, datetime
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
EXCEPTION_FIELDS = {"id", "repository", "detector", "path", "commit", "fingerprint", "owner", "rationale", "expires"}
CHECK_NAME = "TruffleHog secret scan"


class SecretScanRefusal(ValueError):
    """A policy or source gap refuses secret-scan admission."""


def strict_json(text):
    """Parse JSON without accepting duplicate keys.

    Returns:
        The decoded JSON value, with unique object keys.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SecretScanRefusal("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise SecretScanRefusal("invalid JSON") from error


def read_policy(path):
    """Require an exact, owned and time-bounded exception policy.

    Returns:
        Validated exact exception records.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    policy = strict_json(Path(path).read_text())
    if not isinstance(policy, dict) or set(policy) != {"version", "exceptions"} or policy["version"] != 1:
        raise SecretScanRefusal("unsupported exception policy")
    rows = policy["exceptions"]
    if not isinstance(rows, list):
        raise SecretScanRefusal("invalid exception list")
    ids = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != EXCEPTION_FIELDS:
            raise SecretScanRefusal("incomplete exception")
        if any(not isinstance(value, str) or not value.strip() for value in row.values()):
            raise SecretScanRefusal("invalid exception field")
        if row["id"] in ids or not SHA.fullmatch(row["commit"]):
            raise SecretScanRefusal("invalid exception identity")
        if not re.fullmatch(r"[0-9a-f]{64}", row["fingerprint"]) or row["owner"] != "danielbichuetti":
            raise SecretScanRefusal("unreviewed exception authority")
        if not row["repository"].startswith("forlex-ai/") or any(x in row["path"] for x in ("*", "?", "\n", "\r")):
            raise SecretScanRefusal("broad exception refused")
        date.fromisoformat(row["expires"])
        ids.add(row["id"])
    return rows


def classify(row, exceptions, repository):
    """Expose only finding locations and the narrow exception disposition.

    Returns:
        Redacted detection location and exception disposition.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    if not isinstance(row, dict):
        raise SecretScanRefusal("invalid detection")
    try:
        source = row["SourceMetadata"]["Data"]["Git"]
        detector, raw, verified = row["DetectorName"], row.get("RawV2") or row["Raw"], row["Verified"]
        commit, path, line = source["commit"], source["file"], source["line"]
    except (KeyError, TypeError) as error:
        raise SecretScanRefusal("incomplete detection") from error
    if not isinstance(verified, bool) or not isinstance(raw, str) or not raw:
        raise SecretScanRefusal("invalid detection data")
    if (
        not isinstance(detector, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", detector)
        or not isinstance(path, str)
        or not path
    ):
        raise SecretScanRefusal("missing detection location")
    if not isinstance(commit, str) or not SHA.fullmatch(commit) or not isinstance(line, int) or line < 1:
        raise SecretScanRefusal("invalid Git location")
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()
    exception_id = None
    kind = source.get("kind", "file_content")
    if kind not in {"file_content", "filename", "commit_metadata", "tag_metadata"}:
        raise SecretScanRefusal("unknown source kind")
    if not verified and kind == "file_content":
        for rule in exceptions:
            if (rule["repository"], rule["detector"], rule["path"], rule["commit"], rule["fingerprint"]) == (
                repository,
                detector,
                path,
                commit,
                fingerprint,
            ) and date.fromisoformat(rule["expires"]) >= datetime.now(UTC).date():
                exception_id = rule["id"]
                break
    # Deliberately discard Raw, RawV2, Redacted, email and verification error text.
    return {
        "detector": detector,
        "commit": commit,
        "path_digest": hashlib.sha256(os.fsencode(path)).hexdigest(),
        "source_kind": kind,
        "line": line,
        "verification": "verified" if verified else "unknown" if row.get("VerificationError") else "unverified",
        "suppressed": exception_id is not None,
        "exception_id": exception_id,
    }


def git_range(repo, head, base):
    """Validate complete source history and retain every introduced commit.

    Returns:
        The effective merge base and all introduced commit SHAs.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    if not SHA.fullmatch(head) or (base is not None and not SHA.fullmatch(base)):
        raise SecretScanRefusal("invalid source SHA")

    def git(*args):
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_NO_LAZY_FETCH": "1", "LANG": "C.UTF-8"},
        )
        if result.returncode:
            raise SecretScanRefusal("Git source unavailable")
        return result.stdout.strip()

    if git("rev-parse", "--is-shallow-repository") != "false":
        raise SecretScanRefusal("shallow history refused")
    if git("rev-parse", head + "^{commit}") != head:
        raise SecretScanRefusal("source identity mismatch")
    effective = git("merge-base", base, head) if base else None
    commits = git("rev-list", head, *(["^" + effective] if effective else [])).splitlines()
    return effective, commits


def materialize(repo, commits, directory, deadline, *, include_tags=False, tag_object=None, tag_head=None):
    """Enumerate every changed Git blob and materialize inert, deduplicated data.

    Returns:
        An exact generated-path index retaining every immutable source association.

    Raises:
        SecretScanRefusal: Missing objects, unsupported modes, or resource bounds.
    """
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_NO_LAZY_FETCH": "1", "LANG": "C.UTF-8"}
    command = ["git", "--no-replace-objects", "-C", str(repo)]

    def git(*args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SecretScanRefusal("source enumeration timeout")
        result = subprocess.run(
            command + list(args), capture_output=True, timeout=min(60, remaining), env=environment, check=False
        )
        if result.returncode or len(result.stdout) > 256 * 1024 * 1024:
            raise SecretScanRefusal("incomplete Git object enumeration")
        return result.stdout

    payloads, associations = {}, 0

    def add(key, source):
        nonlocal associations
        associations += 1
        if associations > 1_000_000:
            raise SecretScanRefusal("source association limit exceeded")
        if key not in payloads:
            path = directory / ("payload-" + str(len(payloads)))
            payloads[key] = (path, [])
        payloads[key][1].append(source)

    for commit in commits:
        parents = git("rev-list", "--parents", "-n", "1", commit).decode("ascii").split()
        if not parents or parents[0] != commit or any(not SHA.fullmatch(value) for value in parents):
            raise SecretScanRefusal("invalid commit identity")
        add(("commit", commit), {"commit": commit, "file": "@commit-metadata", "kind": "commit_metadata"})
        # Comparing each merge to its first parent covers newly resolved content.
        args = ["diff-tree", "--no-renames", "--no-commit-id", "--raw", "-z", "-r"]
        changes = git(*args, *([parents[1], commit] if len(parents) > 1 else ["--root", commit])).split(b"\0")
        if changes[-1] != b"" or (len(changes) - 1) % 2:
            raise SecretScanRefusal("incomplete changed-object stream")
        for offset in range(0, len(changes) - 1, 2):
            entry, raw_path = changes[offset], changes[offset + 1]
            fields = entry.split()
            if len(fields) != 5 or not fields[0].startswith(b":") or not raw_path:
                raise SecretScanRefusal("invalid changed-object entry")
            _, mode, _, object_id, status = fields
            if status == b"D":
                continue
            if status not in {b"A", b"M", b"T"} or not SHA.fullmatch(object_id.decode("ascii")):
                raise SecretScanRefusal("unsupported changed-object identity")
            path = os.fsdecode(raw_path)
            source = {"commit": commit, "file": path, "kind": "file_content"}
            add(("filename", raw_path), {**source, "kind": "filename"})
            if mode == b"160000":
                # Child content belongs to its own repository's independently accepted gate.
                continue
            if mode not in {b"100644", b"100755", b"120000"}:
                raise SecretScanRefusal("unsupported Git object mode")
            add(("blob", object_id.decode("ascii")), source)

    if tag_object is not None and not include_tags:
        raise SecretScanRefusal("pushed tag requires full-history admission")
    if include_tags:
        references = []
        visited = set()
        for row in git("for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags").splitlines():
            fields = row.decode("ascii").split()
            if len(fields) != 2 or not SHA.fullmatch(fields[0]) or fields[1] not in {"tag", "commit", "tree", "blob"}:
                raise SecretScanRefusal("invalid tag reference")
            references.append(fields)
        if tag_object is not None:
            if not SHA.fullmatch(tag_object) or not isinstance(tag_head, str) or not SHA.fullmatch(tag_head):
                raise SecretScanRefusal("invalid pushed tag binding")
            if git("rev-parse", tag_object + "^{commit}").strip().decode("ascii") != tag_head:
                raise SecretScanRefusal("pushed tag commit identity mismatch")
            references.append((tag_object, git("cat-file", "-t", tag_object).strip().decode("ascii")))
        for object_id, kind in references:
            depth = 0
            while kind == "tag" and object_id not in visited:
                depth += 1
                if depth > 64:
                    raise SecretScanRefusal("tag nesting limit exceeded")
                visited.add(object_id)
                add(("tag", object_id), {"commit": object_id, "file": "@tag-metadata", "kind": "tag_metadata"})
                headers = git("cat-file", "tag", object_id).partition(b"\n\n")[0].splitlines()
                if len(headers) < 3 or not headers[0].startswith(b"object ") or not headers[1].startswith(b"type "):
                    raise SecretScanRefusal("invalid annotated tag object")
                object_id, kind = headers[0][7:].decode("ascii"), headers[1][5:].decode("ascii")
                if not SHA.fullmatch(object_id) or kind not in {"tag", "commit", "tree", "blob"}:
                    raise SecretScanRefusal("invalid tag target")
                if git("cat-file", "-t", object_id).strip().decode("ascii") != kind:
                    raise SecretScanRefusal("tag target identity mismatch")

    objects = [(key, value) for key, value in payloads.items() if key[0] != "filename"]
    request = directory.parent / "git-object-request"
    request.write_bytes(b"".join(key[1].encode("ascii") + b"\n" for key, _ in objects))
    total = 0
    with request.open("rb") as stdin, (directory.parent / "git-object-errors").open("wb") as stderr:
        process = subprocess.Popen(
            command + ["cat-file", "--batch"], stdin=stdin, stdout=subprocess.PIPE, stderr=stderr, env=environment
        )
        try:
            for (kind, object_id), (path, _) in objects:
                header = process.stdout.readline(200)
                fields = header.rstrip(b"\n").split()
                if (
                    len(fields) != 3
                    or fields[:2] != [object_id.encode("ascii"), kind.encode("ascii")]
                    or not fields[2].isdigit()
                ):
                    raise SecretScanRefusal("missing or mismatched Git object")
                size = int(fields[2])
                total += size
                if size > 256 * 1024 * 1024 or total > 8 * 1024 * 1024 * 1024:
                    raise SecretScanRefusal("source materialization limit exceeded")
                with path.open("wb") as output:
                    os.chmod(path, 0o600)
                    remaining = size
                    while remaining:
                        if time.monotonic() >= deadline:
                            raise SecretScanRefusal("source extraction timeout")
                        data = process.stdout.read(min(1024 * 1024, remaining))
                        if not data:
                            raise SecretScanRefusal("truncated Git object")
                        output.write(data)
                        remaining -= len(data)
                if process.stdout.read(1) != b"\n":
                    raise SecretScanRefusal("invalid Git object separator")
            if process.stdout.read(1) or process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise SecretScanRefusal("incomplete Git object extraction")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
    for (kind, data), (path, _) in payloads.items():
        if kind == "filename":
            path.write_bytes(data)
            os.chmod(path, 0o600)
    return {str(path): sources for path, sources in payloads.values()}


def validate_diagnostics(path):
    """Refuse source/detector errors even when the native scanner exits zero.

    Raises:
        SecretScanRefusal: Malformed, unknown, warning, or error diagnostics.
    """
    if path.stat().st_size > 16 * 1024 * 1024:
        raise SecretScanRefusal("scanner diagnostic limit exceeded")
    with path.open() as stream:
        for line in stream:
            row = strict_json(line)
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("level"), str)
                or not re.fullmatch(r"(?:info(?:-[0-5])?|debug)", row["level"])
            ):
                raise SecretScanRefusal("scanner reported incomplete detection")


def scan(repo, head, base, scanner, policy, repository, timeout, *, tag_object=None, tag_ref=None):
    """Run the pinned scanner without credentials and redact its complete output.

    Returns:
        A redacted pass, failure or error report.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    report = {"version": 1, "repository": repository, "head": head, "base": base, "result": "error", "findings": []}
    try:
        if tag_object is not None:
            if (
                not isinstance(tag_object, str)
                or not SHA.fullmatch(tag_object)
                or not isinstance(tag_ref, str)
                or not tag_ref.startswith("refs/tags/")
                or base is not None
            ):
                raise SecretScanRefusal("invalid pushed tag source")
            report.update(
                {"tag_object": tag_object, "tag_ref_digest": hashlib.sha256(os.fsencode(tag_ref)).hexdigest()}
            )
        elif tag_ref is not None:
            raise SecretScanRefusal("incomplete pushed tag source")
        exceptions = read_policy(policy)
        effective, commits = git_range(repo, head, base)
        report.update({"effective_base": effective, "commit_count": len(commits)})
        # No candidate scripts, hooks, dependencies, provider verification or injected credentials.
        command = [
            str(Path(scanner).resolve()),
            "filesystem",
            "--json",
            "--no-update",
            "--no-verification",
            "--no-ignore-tag",
            "--fail-on-scan-errors",
            "--results=verified,unknown,unverified,filtered_unverified",
            "--concurrency=4",
        ]
        with tempfile.TemporaryDirectory(prefix="trufflehog-private-") as directory:
            directory = Path(directory)
            deadline = time.monotonic() + timeout
            payload_directory = directory / "payloads"
            payload_directory.mkdir(mode=0o700)
            index = materialize(
                repo,
                commits,
                payload_directory,
                deadline,
                include_tags=base is None,
                tag_object=tag_object,
                tag_head=head,
            )
            report["payload_count"] = len(index)
            command.append(str(payload_directory))
            environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(directory), "LANG": "C.UTF-8"}
            output, errors = directory / "raw.jsonl", directory / "stderr"
            with output.open("wb") as stdout, errors.open("wb") as stderr:
                os.chmod(output, 0o600)
                os.chmod(errors, 0o600)
                process = subprocess.Popen(
                    command, stdout=stdout, stderr=stderr, env=environment, start_new_session=True
                )
                try:
                    code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise SecretScanRefusal("scanner timeout") from None
            if code != 0:
                raise SecretScanRefusal("scanner execution failed")
            validate_diagnostics(errors)
            if output.stat().st_size > 256 * 1024 * 1024:
                raise SecretScanRefusal("scanner output limit exceeded")
            blocked, suppressed = 0, 0
            with output.open() as stream:
                for line in stream:
                    if len(line) > 8 * 1024 * 1024 or not line.strip():
                        raise SecretScanRefusal("invalid scanner stream")
                    row = strict_json(line)
                    try:
                        location = row["SourceMetadata"]["Data"]["Filesystem"]
                        sources = index[location["file"]]
                        number = location["line"]
                    except (KeyError, TypeError) as error:
                        raise SecretScanRefusal("finding not bound to enumerated source") from error
                    for source in sources:
                        normalized = {**row, "SourceMetadata": {"Data": {"Git": {**source, "line": number}}}}
                        finding = classify(normalized, exceptions, repository)
                        if finding["suppressed"]:
                            suppressed += 1
                        else:
                            blocked += 1
                        if len(report["findings"]) < 100:
                            report["findings"].append(finding)
            report.update({"blocked": blocked, "suppressed": suppressed, "result": "fail" if blocked else "pass"})
    except (ValueError, OSError, subprocess.SubprocessError):
        report["error"] = (
            "Source, policy, scanner execution or complete output validation failed; no success was inferred."
        )
    return report


def github(repository, suffix, *, method="GET", body=None):
    """Use scoped GitHub APIs without exposing tokens or response bodies.

    Returns:
        The authenticated JSON response.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    if not re.fullmatch(r"forlex-ai/[A-Za-z0-9_.-]+", repository):
        raise SecretScanRefusal("unexpected repository")
    token = os.environ.get("GH_TOKEN")
    if not token:
        raise SecretScanRefusal("GitHub authentication unavailable")
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        "https://api.github.com/repos/" + repository + "/" + suffix, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return strict_json(response.read().decode())
    except (urllib.error.URLError, ValueError, OSError) as error:
        raise SecretScanRefusal("GitHub request failed") from error


def context(event, kind, repository, pr_number=0):
    """Bind authenticated live source facts before creating the check.

    Returns:
        The current source context and newly created check identity.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    if kind not in {"pull_request_target", "push", "schedule", "workflow_dispatch"}:
        raise SecretScanRefusal("unsupported workflow event")
    if event.get("repository", {}).get("full_name") != repository:
        raise SecretScanRefusal("event repository mismatch")
    number = event.get("number") if kind == "pull_request_target" else pr_number
    tag_object, tag_ref = None, None
    if number:
        if not isinstance(number, int) or number < 1:
            raise SecretScanRefusal("invalid PR")
        pr = github(repository, "pulls/" + str(number))
        if pr["state"] != "open" or pr["base"]["repo"]["full_name"] != repository:
            raise SecretScanRefusal("closed or foreign PR")
        head, base = pr["head"]["sha"], pr["base"]["sha"]
        if kind == "pull_request_target" and (head, base) != (
            event["pull_request"]["head"]["sha"],
            event["pull_request"]["base"]["sha"],
        ):
            raise SecretScanRefusal("stale PR event")
    else:
        head = os.environ["GITHUB_SHA"]
        base = event.get("before") if kind == "push" else None
        if kind == "push" and event.get("ref", "").startswith("refs/tags/"):
            tag_object, tag_ref = event.get("after"), event["ref"]
            if not isinstance(tag_object, str) or not SHA.fullmatch(tag_object) or tag_object == "0" * 40:
                raise SecretScanRefusal("pushed tag object unavailable")
            base = None
        if base == "0" * 40:
            base = None
    if not SHA.fullmatch(head) or (base is not None and not SHA.fullmatch(base)):
        raise SecretScanRefusal("invalid source identity")
    result = {"repository": repository, "pr": number or None, "head": head, "base": base}
    if tag_object is not None:
        result.update({"tag_object": tag_object, "tag_ref": tag_ref})
    created = github(
        repository, "check-runs", method="POST", body={"name": CHECK_NAME, "head_sha": head, "status": "in_progress"}
    )
    result["check_id"] = created["id"]
    return result


def publish(source, report):
    """Publish success only for the unchanged source and owned check.

    Returns:
        The completed GitHub check response.

    Raises:
        SecretScanRefusal: Invalid or incomplete evidence; scan captures this as an error report.
    """
    repository = source["repository"]
    current_context = True
    if source["pr"]:
        try:
            current = github(repository, "pulls/" + str(source["pr"]))
            current_context = current["state"] == "open" and (current["head"]["sha"], current["base"]["sha"]) == (
                source["head"],
                source["base"],
            )
        except (KeyError, TypeError, ValueError, OSError):
            current_context = False
    counts = (report.get("blocked"), report.get("suppressed"), report.get("commit_count"))
    complete = all(type(value) is int and value >= 0 for value in counts)
    tag_matches = report.get("tag_object") == source.get("tag_object") and (
        source.get("tag_object") is None
        or (
            isinstance(source.get("tag_ref"), str)
            and report.get("tag_ref_digest") == hashlib.sha256(os.fsencode(source["tag_ref"])).hexdigest()
        )
    )
    success = (
        current_context
        and complete
        and tag_matches
        and report.get("blocked") == 0
        and report.get("version") == 1
        and not report.get("error")
        and report.get("result") == "pass"
        and (report.get("head"), report.get("base"), report.get("repository"))
        == (source["head"], source["base"], repository)
    )

    def owned(check):
        return (
            isinstance(check, dict)
            and type(check.get("id")) is int
            and type(source["check_id"]) is int
            and check["id"] == source["check_id"]
            and check.get("head_sha") == source["head"]
            and check.get("name") == CHECK_NAME
            and isinstance(check.get("app"), dict)
            and check["app"].get("id") == 15368
        )

    try:
        check = github(repository, "check-runs/" + str(source["check_id"]))
    except (KeyError, TypeError, ValueError, OSError):
        raise SecretScanRefusal("check identity verification unavailable") from None
    if not owned(check):
        raise SecretScanRefusal("check identity mismatch")
    blocked, suppressed, commits = (value if type(value) is int and value >= 0 else "unavailable" for value in counts)
    summary = f"Result: {'pass' if success else 'failure'}. Scanned commits: {commits}. Blocking detections: {blocked}. Exact fixture exceptions: {suppressed}. Raw secrets and verification responses are never published."
    if not current_context:
        summary += " Current PR context changed or could not be verified; a fresh scan is required."
    conclusion = "success" if success else "failure"
    try:
        result = github(
            repository,
            "check-runs/" + str(source["check_id"]),
            method="PATCH",
            body={
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": CHECK_NAME, "summary": summary},
            },
        )
    except (KeyError, TypeError, ValueError, OSError):
        raise SecretScanRefusal("check completion unavailable") from None
    if not owned(result) or result.get("status") != "completed" or result.get("conclusion") != conclusion:
        raise SecretScanRefusal("check completion was not confirmed")
    return result


def main():
    """Execute one gate stage and fail closed on incomplete evidence.

    Returns:
        Zero only for a successfully completed gate stage.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-policy")
    validate.add_argument("--policy", type=Path, required=True)
    prepare = sub.add_parser("context")
    prepare.add_argument("--event", type=Path, required=True)
    prepare.add_argument("--kind", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--pr", type=int, default=0)
    prepare.add_argument("--output", type=Path, required=True)
    run = sub.add_parser("scan")
    run.add_argument("--context", type=Path, required=True)
    run.add_argument("--repo", type=Path, required=True)
    run.add_argument("--scanner", type=Path, required=True)
    run.add_argument("--policy", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--timeout", type=int, default=1200)
    finish = sub.add_parser("publish")
    finish.add_argument("--context", type=Path, required=True)
    finish.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate-policy":
            read_policy(args.policy)
        elif args.command == "context":
            result = context(strict_json(args.event.read_text()), args.kind, args.repository, args.pr)
            args.output.write_text(json.dumps(result) + "\n")
            with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
                stream.write("head=" + result["head"] + "\n")
                if result.get("tag_object") is not None:
                    stream.write("tag_object=" + result["tag_object"] + "\n")
        elif args.command == "scan":
            source = strict_json(args.context.read_text())
            report = scan(
                args.repo,
                source["head"],
                source["base"],
                args.scanner,
                args.policy,
                source["repository"],
                args.timeout,
                tag_object=source.get("tag_object"),
                tag_ref=source.get("tag_ref"),
            )
            args.output.write_text(json.dumps(report, indent=2) + "\n")
            return 0 if report["result"] == "pass" else 1
        else:
            source = strict_json(args.context.read_text())
            try:
                report = strict_json(args.report.read_text())
            except (ValueError, OSError, TypeError):
                report = {"result": "error"}
            if not isinstance(report, dict):
                report = {"result": "error"}
            result = publish(source, report)
            return 0 if result["conclusion"] == "success" else 1
    except (KeyError, ValueError, OSError, TypeError):
        print("Secret gate refused incomplete or changed context; no secret bytes are included.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
