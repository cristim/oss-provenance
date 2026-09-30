# oss-provenance

A Rust CLI that scans staged source fingerprints with SCANOSS, checks matches against an explicitly admitted license policy, and prepares third-party notices. A match is evidence to investigate, not an accusation of plagiarism. A negative search is limited to the scanner's corpus and algorithm.

The native fingerprint implementation is tested against the official reference. Python is not required at runtime. See [backend verification](docs/backend-contract.md).

## Build

```sh
cargo build --locked --release
cargo install --locked --path .
make verify
```

Rust 1.98.0 is pinned. The tool is not published and its own distribution license has not been selected. The adapted SCANOSS fingerprint code and bundled reference retain their MIT notices in `LICENSE-NOTICES/scanoss-winnowing/`.

## Enroll a project explicitly

Run `oss-provenance --repo /path/to/project init`. This creates `.oss-provenance.toml` with transmission disabled and no allowed licenses. Edit the example's target license, use context, approved license requirements, and exact paths or directory-prefix exclusions. The example `MIT` value is not a license inference.

Commit the proposed policy and its reviewed evidence artifacts. Evaluate the complete candidate tree before admission:

```sh
oss-provenance evaluate --all --head HEAD --policy-ref HEAD --initial-enrollment --format json
```

Evaluation always exits 1 and marks its report `evaluation_only`. It never admits policy or satisfies a commit gate. Resolve its findings, then have the project maintainer record the exact reviewed full commit ID:

For later maintenance, supply `--base PRIOR_LEDGER_SHA` instead of `--initial-enrollment`, so historical notice removal remains visible.

```sh
git config --local oss-provenance.policy-ref FULL_REVIEWED_COMMIT_SHA
```

Ordinary checks reject moving policy references such as `HEAD` or `main`. CI passes its admitted full SHA through `--policy-ref` from protected configuration. Candidate policy edits require a new evaluation and separate admission. A local hook does not protect against a repository owner bypassing or modifying the checker.

Enabling `[scanner].enabled` authorizes fingerprint transmission to the configured HTTPS endpoint. The payload contains opaque identities, byte lengths, and fingerprints, not plaintext source or repository paths. Evidence collection and accepted-match verification separately download public GitHub source. Failed or incomplete requests never become a passing negative result.

## Check staged code

```sh
oss-provenance check --staged
oss-provenance check --staged --format json
oss-provenance check --all --staged
oss-provenance check --base BASE_SHA --head HEAD_SHA --policy-ref POLICY_SHA
oss-provenance check --all --base PRIOR_LEDGER_SHA --head HEAD_SHA --policy-ref POLICY_SHA
```

The index supplies file contents, including partially staged files. Full commit checks require a prior ledger baseline. A CI caller resolves the current target tip, computes the merge-base with the proposed head, and supplies those immutable SHAs. Checks compare endpoint trees, not intermediate commits. Reports identify candidate and baseline content as well as the admitted policy.

Exit 0 means no unresolved in-scope findings or violations of the admitted, machine-checkable obligations. It does not certify all legal obligations or complete corpus coverage. Exit 1 means blocked, unresolved, insufficient coverage, missing notice, or evaluation-only results. Exit 2 means an operational or configuration error. JSON is available for completed assessment reports; operational errors are currently written to stderr.

Empty, tiny, binary, non-UTF-8, symlink, and submodule inputs cannot silently pass as scanned text. Explicit policy exclusions appear in reports. Every changed file is considered; a fingerprintable file does not guarantee detection of every tiny addition.

## Resolve source licensing

A scanner license label cannot clear a finding. The current automatic evidence collector supports public GitHub repositories. It resolves the reported version to a commit, verifies source identity, and downloads applicable grant artifacts from that revision:

```sh
oss-provenance check --staged --format json > findings.json
oss-provenance collect-evidence --report findings.json --finding 0 --output /path/to/new-evidence-directory
```

The evidence proposal remains pending. A maintainer reviews grant applicability, nested/file licensing, required notices, source headers, and release obligations before adding an `[[evidence]]` record to the admitted policy. [Evidence documentation](docs/evidence.md) describes optional, version-pinned ScanCode reports. ScanCode is not embedded or automatically executed.

An admitted evidence record contains `file_md5`, `source_sha256`, `repository`, full `revision`, `path`, upstream `license`, concrete `selected_license`, review rationale, and `artifacts` with repository-relative paths and SHA-256 values. The artifacts must exist in the admitted commit under `LICENSE-NOTICES/`. The selected SPDX requirements must satisfy the original grant. `allow` and `deny` contain individual requirements, not compound expressions. Compatibility rules are explicit project decisions, not a universal legal table.

Accepted matches fetch and hash-check the pinned source again, then verify supported local/upstream content correspondence. Unsupported fuzzy correspondence remains unresolved. Missing evidence, custom terms, ambiguous candidates, and unavailable evidence services block clearance.

Each evidence record requires an explicit `obligations` decision. `kind = "artifact_only"` means the reviewer determined the retained artifacts suffice for this use. `kind = "source_prefix"` additionally requires `text`, an exact leading block in every local file containing active reuse; include required source headers and modification statements there. Checks enforce it even when only a header is deleted. `kind = "unsupported"` with a `reason` blocks clearance. Collection defaults to unsupported until reviewed. Obligations outside these supported forms require review and remain blocked, rather than being inferred from a license name.

## Prepare or update notices

```sh
oss-provenance resolve --staged --description 'Used by the request parser to decode fields' --output /path/to/new-notice-proposal
git apply --check -p2 /path/to/new-notice-proposal/notices.patch
git apply -p2 /path/to/new-notice-proposal/notices.patch
git add LICENSE-NOTICES
oss-provenance check --staged
```

Review the proposal before application, and stage only its actual changed paths if the notice folder has unrelated changes. `resolve` exits 1 because an unapplied proposal has not cleared the commit. It never edits the repository, stages files, or commits. Omitting `--output` creates a new temporary proposal directory and prints its location.

The manifest records one source identity and multiple local uses. Repeated resolution is deterministic. Exact grant/NOTICE bytes accompany generated descriptions. Conflicting manual README edits are preserved by refusing regeneration. Edit descriptions in the manifest and keep its generated README consistent. Staged notice deletion, forged positions, policy changes, and removed historical entries are checked even when no source lines were added.

To remove recorded reuse, add a maintainer-reviewed `[[retirements]]` record to admitted policy, with `evidence_id`, `path`, `snippet_sha256`, and `reason`. Resolve marks the matching use retired while preserving attribution history. A candidate cannot retire itself, and the old snippet must no longer be present at that path.

## Agent rewrite handoff

```sh
oss-provenance resolve --staged --agent claude --brief /path/to/independent-requirements.md --output /path/to/new-handoff
```

`--agent codex` is also accepted. This currently prepares a blocked handoff only. It copies the explicit behavioral brief and target paths, without copying source matches, repository history, or prior conversations. No provider is launched, no candidate tests are executed, and no automatic rewrite/retry loop is claimed. The handoff directs the caller to an isolated fresh session, trusted tests, a rescan, and a two-attempt limit.

An enforced and verified provider/test sandbox is required before automatic repair can be enabled. A fresh session alone is not proof of independent creation. See [remaining limitations](known-issues.md).

## Hook and CI integration

The supplied `.pre-commit-hooks.yaml` exposes hook ID `oss-provenance`. For a local install:

```yaml
repos:
  - repo: local
    hooks:
      - id: oss-provenance
        name: OSS provenance
        entry: oss-provenance check --staged
        language: system
        pass_filenames: false
        always_run: true
        require_serial: true
```

Run the same gate in CI using a pinned checker installation and protected policy SHA. Do not install or execute the checker from untrusted PR contents in a privileged job. The workflow in this tool's repository tests its Rust code; consuming projects must add their own provenance gate and trusted baseline selection. No hooks are installed automatically.
