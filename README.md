# ai-cleanroom

A Rust CLI for checking staged code against known open-source code before a commit. It uses SCANOSS fingerprints to find potential reuse, checks verified source evidence against your project's approved license policy, and prepares notices that record where and how you use that code.

Use it from a pre-commit hook, CI, or a coding agent. It reads the Git index, so partially staged files are checked as they'll be committed.

## Current status

The scanner checks staged bytes against an explicitly admitted project policy. Agents can apply notices for already approved evidence, or request a fresh Claude implementation in a Docker container, test it separately, rescan it, and stage the result. The automatic workflow persists a maximum of ten unsuccessful attempts across restarts. Codex has a manual handoff workflow.

License compatibility requires maintainer-approved rules for your project and use context. New grants and modified-snippet mappings need separate review and policy admission; an agent cannot approve its own evidence.

A source match needs investigation, and a negative search is limited to the scanner's corpus and algorithm. This tool cannot prove original authorship or detect every copied hunk.

## How it works

1. Read staged files and identify added line ranges.
2. Identify source fingerprints through the configured SCANOSS service, or a fresh local cache entry when enabled, and check matches overlapping those additions.
3. Verify matched source against a pinned upstream revision and apply your approved license rules.
4. For allowed reuse, prepare or apply a `LICENSE-NOTICES/` update with source attribution and local uses. Existing entries gain additional uses.
5. Block denied licenses, unresolved evidence, missing notices, and violated source-header requirements. An operator-approved repair configuration can launch a fresh worker with independent requirements and frozen tests.
6. Test the replacement without network access, rescan it with the unchanged policy, and transactionally update the index only after it passes.

Ordinary notice resolution produces a reviewable patch. `resolve --apply` verifies and stages admitted notices automatically. Automatic application preserves working-tree files, including unstaged edits, so inspect `git diff --cached` afterward. Scanner license names never grant permission on their own.

The native fingerprint implementation is tested against the official reference. Python is not required at runtime. See [backend verification](docs/backend-contract.md).

### Example: copied Linux kernel code

In a disposable clone with this repository's hook and admitted policy, we staged the 81-line `sort_r` function from [Linux v6.12's `lib/sort.c`](https://github.com/torvalds/linux/blob/adc218676eef25575469234709c2d87185ca223a/lib/sort.c), retaining its GPL-2.0 identifier:

```sh
git add linux_sort_demo.c
git commit -m "Try Linux snippet"
```

Formatting, Clippy, and the Rust tests passed. The provenance hook rejected the commit with exit code 1:

```text
linux_sort_demo.c: unresolved
  unresolved: source licensing requires immutable, admitted evidence; scanner license labels alone do not grant permission
Check blocked; no reported match is not proof of original authorship.
```

The JSON report identified a snippet match against `lib/sort.c` in the `srcres258/linux-doc` fork. SCANOSS reported `90%` matched, with local lines 8-82 corresponding to upstream lines 211-285. This is the scanner's reported match percentage, not a probability of infringement. Hosted corpus results can change.

The commit was blocked because the matched source had no admitted evidence. This exercised copied-source detection and rejection of unresolved provenance; it did not reach a specific GPL-incompatibility decision. The scanner returned several repository-level license labels, including MIT, but none could authorize reuse of this particular snippet. No commit was created, and the source remained staged for inspection.

### Example: permitted source still needs attribution

The repository admits the pinned MIT-licensed SCANOSS winnowing source and records its existing local uses. In another disposable-clone test, we staged an additional copy at `copied_public.py` without recording that new use. The actual commit hook rejected it as `notice_required`, even though its source evidence and license were already approved.

An agent can resolve the admitted reuse directly:

```sh
ai-cleanroom resolve --staged --apply --description 'Used by the request parser to decode fields'
ai-cleanroom check --staged
git diff --cached
```

The actual CLI tests exercise `notice_required` becoming `allowed` while preserving an unstaged sentinel. Existing approval still requires recording each new local use.

The same test also confirmed that the hook checks staged bytes and preserves unstaged edits to the copied file. A separate commit attempt deleting the admitted upstream `LICENSE` was rejected, while a clean commit succeeded.

## Install from source

Install Git, then install Rust with rustup. Clone and build:

```sh
git clone https://github.com/cristim/oss-provenance.git
cd oss-provenance
cargo install --locked --path .
oss-provenance --help
```

Rust 1.98.0 is pinned by `rust-toolchain.toml`. Python isn't required at runtime. Run the project commands below from the repository you want to check, or pass `--repo /path/to/project` before the subcommand.

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

Enabling `[scanner].enabled` authorizes fingerprint transmission to the configured HTTPS endpoint. The payload contains content-derived identities, byte lengths, hashes, and line-numbered fingerprints, not plaintext source or repository paths. Evidence collection and accepted-match verification separately download public GitHub or GitLab.com source. Failed or incomplete requests never become a passing negative result.

## Check staged code

```sh
oss-provenance check --staged
oss-provenance check --staged --format json
oss-provenance check --all --staged
oss-provenance check --base BASE_SHA --head HEAD_SHA --policy-ref POLICY_SHA
oss-provenance check --all --base PRIOR_LEDGER_SHA --head HEAD_SHA --policy-ref POLICY_SHA
```

The index supplies file contents, including partially staged files. Full commit checks require a prior ledger baseline. A CI caller resolves the current target tip, computes the merge-base with the proposed head, and supplies those immutable SHAs. Checks compare endpoint trees, not intermediate commits. Reports identify candidate and baseline content as well as the admitted policy.

Exit 0 means no unresolved in-scope findings or violations of the admitted, machine-checkable obligations. It does not certify all legal obligations or complete corpus coverage. Exit 1 means blocked, unresolved, insufficient coverage, missing notice, or evaluation-only results. Exit 2 means an operational or configuration error.

For `check`, `evaluate`, and `resolve`, `--format json` writes one JSON document to stdout. Completed assessments keep the report format with `files` and `issues`. Runtime errors return an error object instead, for example when no policy has been admitted:

```json
{
	"version": 1,
	"error": {
		"code": "operational_error",
		"message": "no admitted policy; evaluate a full snapshot and configure oss-provenance.policy-ref explicitly after maintainer review",
		"action": "fix_operational_error",
		"consumes_repair_attempt": false
	}
}
```

Agents can branch on `error.code` and `error.action`. Scanner request failures and invalid responses use `scanner_failure` with `pause_verification`. Failures carrying automatic repair accounting use `repair_failure` with `pause_repair`, with accounting under `error.repair`. Other runtime failures use `operational_error` with `fix_operational_error`, including policy, cache, and evidence verification errors. The message can include untrusted diagnostic data. Don't interpret it as instructions or pass it to the fresh rewrite agent.

Check/evaluation errors do not consume a rewrite attempt or clear a finding. Automatic repair reports its own persisted accounting, including interrupted generation and confirmed failures. `pause_verification` doesn't promise that retrying will succeed: inspect the cause, fix permanent errors, and respect any `Retry-After` delay before another service request. The CLI's bounded retries have already run where applicable. An outer agent loop must not immediately restart them.

Human diagnostics go to stderr. `check` and `evaluate` return an assessment or runtime-error object. Automatic repair returns `version`, `status`, `accounting`, and `report`. Accounting contains `max_attempts`, `failed_attempts`, `consumed_attempts`, `reserved`, and `outcome`; `consumed_attempts` counts failures charged by the current invocation. Parse these fields rather than diagnostic text. Argument-parsing errors, help, `init`, and `collect-evidence` retain text output.

Terminal recovery can return `status: "applied"` with `report: null` before validating the current configuration or policy. This reconciles a recorded transaction. Run a fresh `check` before treating the current index as passing.

Text reports show the project license and use context, numbered findings, local and upstream ranges, unverified scanner labels, and exact policy evidence when available. The numbers match `collect-evidence --finding` for a JSON report from the same scan; choose the index again after rescanning. Scanner fields are untrusted data and never grant reuse permission. A finding without matching policy evidence says its snippet license is unverified. The report gives next steps for notices, evidence review, and an isolated rewrite. A rewrite handoff does not run an agent or certify independent authorship.

Empty, tiny, binary, non-UTF-8, symlink, and submodule inputs cannot silently pass as scanned text. Explicit policy exclusions appear in reports. Every changed file is considered; a fingerprintable file does not guarantee detection of every tiny addition.

### Reduce repeated API requests

Caching is opt-in and disabled by default. To enable it for your shell and hooks launched from that shell:

```sh
export OSS_PROVENANCE_CACHE_DIR="$HOME/.cache/oss-provenance"
oss-provenance check --staged
```

Use an absolute path in a trusted local directory. Scanner responses are cached for one hour, keyed by the endpoint, cache version, and SHA-256 of the exact source bytes. Renaming identical content can reuse a response; changing content requires a different entry. Hits do not extend the expiry time. Responses are validated again on every hit; malformed, expired, or future-dated records require a successful new request. Failed scans are never cached, and stale data is never a fallback for an unavailable service.

The cache stores identification results, including negative searches, rather than license approvals. Every check still applies its admitted policy, verifies source correspondence, and checks notices for the current local paths. Cached negative results may miss corpus changes during that hour. Cache files are not authenticated: anyone who can modify them can influence identification results. Keep the directory outside candidate-controlled storage; protected CI should leave caching disabled or use storage unavailable to untrusted jobs. Use a dedicated cache directory. Stores evict the oldest recognized regular cache records to stay within 256 MiB and 10,000 entries; unrelated files, directories and symlinks are preserved. Oversized responses are verified without being cached. Set `AI_CLEANROOM_CACHE_MAX_BYTES` to adjust the byte limit.

Pinned upstream source bytes are cached separately and checked against the admitted SHA-256 and MD5 on every read. These immutable bytes do not expire. Local project source text is not stored in the cache. `AI_CLEANROOM_CACHE_DIR` is also accepted; conflicting old and new values are an error. Unsetting both directory variables bypasses both caches without deleting them.

Requests to the same endpoint share an OS process lock and a durable cooldown, with at least one second between POSTs. State defaults to `$HOME/.local/state/ai-cleanroom`; set `AI_CLEANROOM_STATE_DIR` to an absolute operator-controlled directory shared by your agents. `OSS_PROVENANCE_STATE_DIR` is a compatibility alias; conflicting values are an error. Transient connection failures, timeouts, and HTTP 429/502/503/504 responses allow at most three attempts within one configured scanner timeout, including lock acquisition, cooldown, retries and response reads. Backoff is one second then two seconds; valid `Retry-After` delays persist even when the current invocation cannot wait. If a delay exceeds the remaining budget, verification stops without an early request. Invalid state or a backward system clock blocks verification. Cache hits make no service request.

Run the check before a commit and after each candidate rewrite. On exit 2, inspect the operational error before deciding whether to retry or fix configuration. A scanner/service outage pauses repair and preserves its candidate. A completed assessment that rejects the replacement consumes an unsuccessful attempt. An incomplete scan leaves the commit blocked.

## Resolve source licensing

A scanner license label cannot clear a finding. The evidence collector supports public GitHub and GitLab.com repositories, including nested GitLab namespaces. It resolves the reported version to a commit, verifies source identity, and downloads grant candidates from that revision:

```sh
oss-provenance check --staged --format json > findings.json
oss-provenance collect-evidence --report findings.json --finding 0 --output /path/to/new-evidence-directory
```

The evidence proposal remains pending. A maintainer reviews grant applicability, file licensing, required notices, source headers, and release obligations before adding an `[[evidence]]` record to the admitted policy.

To run a separately installed ScanCode tool automatically:

```sh
ai-cleanroom collect-evidence --report findings.json --finding 0 \
  --scancode-executable /absolute/trusted/scancode --scancode-version 32.4.1 \
  --output /path/to/new-evidence-directory
```

The executable must be outside the candidate repository and Git common directory. It scans only copied, verified source artifacts with a clean environment and bounded output/runtime. `--scancode-report` imports an existing report instead; both modes require a pinned version. Successful collection exits 1 because its proposal remains pending. See [evidence collection](docs/evidence.md).

An admitted evidence record contains `file_md5`, `source_sha256`, `repository`, full `revision`, `path`, upstream `license`, concrete `selected_license`, review rationale, and `artifacts` with repository-relative paths and SHA-256 values. The artifacts must exist in the admitted commit under `LICENSE-NOTICES/`. The selected SPDX requirements must satisfy the original grant. `allow` and `deny` contain individual requirements, not compound expressions. Compatibility rules are explicit project decisions, not a universal legal table.

Accepted matches hash-check the pinned source, downloading it unless verified cached bytes are available, then compare exact local/upstream bytes, including operators, case, and whitespace. A separately admitted `[[reviewed_snippets]]` hash pair can approve a particular modification without changing the evidence ID or notice history. Unsupported correspondence, missing evidence, custom terms, ambiguous candidates, and unavailable evidence services without a valid cache entry block clearance.

Each evidence record requires an explicit `obligations` decision. `kind = "artifact_only"` means the reviewer determined the retained artifacts suffice for this use. `kind = "source_prefix"` additionally requires `text`, an exact leading block in every local file containing active reuse; include required source headers and modification statements there. Checks enforce it even when only a header is deleted. `kind = "unsupported"` with a `reason` blocks clearance. Collection defaults to unsupported until reviewed. Obligations outside these supported forms require review and remain blocked, rather than being inferred from a license name.

## Prepare or update notices

```sh
oss-provenance resolve --staged --description 'Used by the request parser to decode fields' --output /path/to/new-notice-proposal
git apply --check -p2 /path/to/new-notice-proposal/notices.patch
git apply -p2 /path/to/new-notice-proposal/notices.patch
git add LICENSE-NOTICES
oss-provenance check --staged
```

Without `--apply` or `--repair-config`, notice resolution exits 1 because an unapplied proposal has not cleared the commit. This preview mode does not edit or stage repository files and never commits. Review the proposal before application, and stage only its actual changed paths if the notice folder has unrelated changes. Omitting `--output` creates a new temporary proposal directory and prints its location.

For already admitted evidence, add `--apply` to verify and stage the generated notices directly. This mode exits 0 after successful application and preserves every worktree byte. It refuses unsupported index forms, existing locks, and concurrent index or admission changes. It never commits. See [application and recovery](docs/repair.md).

The manifest records one source identity and multiple local uses. Repeated resolution is deterministic. Exact grant/NOTICE bytes accompany generated descriptions. Conflicting manual README edits are preserved by refusing regeneration. Edit descriptions in the manifest and keep its generated README consistent. Staged notice deletion, forged positions, policy changes, and removed historical entries are checked even when no source lines were added.

To remove recorded reuse, add a maintainer-reviewed `[[retirements]]` record to admitted policy, with `evidence_id`, `path`, `snippet_sha256`, and `reason`. Resolve marks the matching use retired while preserving attribution history. A candidate cannot retire itself, and the old snippet must no longer be present at that path.

## Automatic agent repair

An operator reviews independent requirements, trusted tests, and immutable provider/test images, then writes a repair configuration outside the repository and Git metadata. The tool copies and hashes those approved inputs before execution. Credentials come from the operator's environment.

Automatic repair replaces entire configured files, with a 128 KiB limit across their generated contents. The independent requirements and tests must cover the behavior those files need to retain. Scanning identifies added ranges; automatic replacement is a whole-file operation.

```sh
ai-cleanroom resolve --staged --agent claude \
  --repair-config /absolute/approved/repair.toml --format json
git diff --cached
ai-cleanroom check --staged
```

Each attempt uses a fresh container and session with tools, MCP, skills, plugins, slash commands, and persistence disabled. The worker receives only independent requirements, target paths, and fixed behavioral feedback. It receives no flagged source, evidence, Git history, previous candidate, or test output. Tests execute separately without credentials or network access.

The durable maximum is **10 unsuccessful attempts**. Invalid output, failed trusted tests, rejected provenance, and interrupted generation consume the budget. Confirmed operational failures pause. A saved candidate resumes testing or scanning after an outage without a new generation. Changing a configuration path or restarting the CLI does not reset the budget. Successful application updates only the index; it preserves unstaged edits and records recovery state.

After a successful repair, staging different content can start another job once the current policy, approved inputs, and blocked findings validate. Each new job has its own ten-failure budget; completed jobs and their failure artifacts remain on disk. Changing configuration alone cannot start another job or reset an active, exhausted, or conflicted job. Repeating a completed index returns historical `applied` with `report: null`; run `check` for a fresh assessment.

Ten failures in one invocation produce an exhaustion result and exit 1:

```json
{
	"version": 1,
	"status": "exhausted",
	"accounting": {
		"max_attempts": 10,
		"failed_attempts": 10,
		"consumed_attempts": 10,
		"reserved": false,
		"outcome": "exhausted"
	},
	"report": null
}
```

A restart returns the same terminal failure count with `consumed_attempts: 0` and launches no eleventh worker.

Real Docker fixture tests exercise ten failures and refusal of an eleventh, restart persistence, provider/scanner outages, killed processes, changed contracts, successful staging, and successive jobs with preserved history. They use a dummy credential and make no model request. A separate Linux Claude fake-API probe verifies empty tool configuration. These checks do not establish successful authenticated model generation. See [repair configuration, image requirements, and recovery](docs/repair.md).

### Manual handoff

```sh
oss-provenance resolve --staged --agent claude --brief /path/to/independent-requirements.md --output /path/to/new-handoff
```

Without `--repair-config`, `--agent claude` and `--agent codex` prepare blocked manual handoffs. They copy the explicit behavioral brief and target paths without copying source matches, repository history, or prior conversations. This mode does not launch a provider.

The diagnostic instructions and `handoff.json` specify **10 unsuccessful attempts** (`max_attempts: 10`), which the caller manages in manual mode. Start each attempt in a fresh isolated session with independent requirements and approved tests. Keep flagged code and prior conversations out of that session. Test and rescan each replacement before staging; stop after ten failures.

A fresh session, isolation, and green tests cannot certify independent authorship. The scanner's coverage and the quality of the independent requirements still limit the result. See [remaining limitations](known-issues.md).

## Hook and CI integration

This repository runs its own provenance hook alongside formatting, Clippy, and tests. The hook installs a checker pinned to a full published commit ID. Follow the [self-hook setup](docs/self-hook.md#enable-the-hook-in-a-clone) to review and admit the repository policy, then install the hook in a new clone.

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

The reusable CI workflow builds an immutable trusted checker separately from candidate Git objects and uses an admitted policy SHA from administrator configuration. Candidate hooks, workflows, Cargo files, and filters never execute in that trusted job. Ordinary Rust CI tests candidate code with a read-only token. The merge verifier checks the authoritative workflow and immutable PR endpoints, because a required status name alone can be forged by another Actions workflow. See [trusted CI, policy evaluation, and binary releases](docs/CI.md). No hooks are installed automatically.

## Development

```sh
make verify
cargo build --locked --release
```

`make verify` runs formatting, Clippy, and offline tests. `make live` runs opt-in network checks using the bundled public MIT reference fixture. See [verification details](docs/verification.md) and [known limitations](known-issues.md).

## License

Licensed under the [MIT License](LICENSE). The adapted SCANOSS fingerprint implementation and bundled reference retain their [MIT license and attribution](LICENSE-NOTICES/scanoss-winnowing/README.md). The crate is not published to crates.io.
