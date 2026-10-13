# Secret scanning

`TruffleHog secret scan` blocks every unsuppressed detection. Provider verification is disabled: CI does not contact live services using candidate credentials. Native verified, unknown, unverified and filtered-unverified results are retained; offline nonverified results are reported as unverified.

The scanner release and download checksum are immutable. PR scans use policy from the accepted base and never execute candidate code. Ordinary PR regression tests have no write token. The privileged job has only repository read and check-write permissions; the scanner subprocess receives no GitHub or provider credentials.

The gate enumerates every introduced commit from the merge base. It scans complete added, modified and type-changed blobs, including merge resolutions, changed renames and symlink targets. Generated regular files keep candidate paths and symlinks inert. Commit metadata and changed filenames are scanned separately. A deleted secret remains covered by its introducing commit. Scheduled scans cover the full reachable default-branch history; each submodule repository owns its own Git content scan. External Git LFS object contents are outside the stored Git object scope.

Results expose only detector, immutable commit, path digest, line, source kind and disposition. Raw findings, filenames, email and scanner diagnostics are never published. Missing objects, incomplete output, warnings/errors, malformed diagnostics, timeout or resource limits refuse a pass. Bounds are 256 MiB per stored object, 8 GiB unique object data, one million source associations and 256 MiB scanner output. Exceeding a bound requires qualification of a larger bounded scan, never an automatic clean verdict.

`exceptions.json` is empty by default. A source-proven false-positive exception needs repository, detector, exact path, immutable commit, SHA256 of the detector's raw value, Daniel's ownership, source proof, rationale and expiry. Verified findings, commit metadata and filename detections cannot be excepted. Exceptions do not propagate: an unrelated later edit to a file containing a fixture requires a separately reviewed commit-specific exception. Never waive an entire directory, detector or value across commits. Expired exceptions block again.

Before approving an exception, inspect its immutable source in a private review, prove the matched value is a synthetic fixture or program/interface identifier, and verify no live credential is involved. For a real credential, rotate it and handle historical exposure; deleting its latest source does not clear history.

Run `TRUFFLEHOG_BINARY=/absolute/path/to/checksum-verified/trufflehog python3 .forlex/security/test_secret_scan.py` to qualify both protocol tests and real offline canaries. Omitting the binary skips native qualification and is insufficient for rollout.

Rollout is ordered: accept the owning source PR, publish this source to the default branch where required, manually qualify open PR heads, enable the Actions-owned required check, then remove the old GitGuardian requirement and integration. Preserve other branch rules. A repository with Actions disabled is not covered until its scanner workflow is explicitly enabled. Only redacted result artifacts are retained, for 14 days.
