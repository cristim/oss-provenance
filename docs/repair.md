# Applying notices and repairing blocked code

`resolve --apply` generates notices from already admitted evidence, verifies the
result with the current policy, and updates the Git index. It preserves every
working-tree file, including unstaged edits. Inspect `git diff --cached` before
committing; the working tree may consequently differ from the newly staged code.

```console
oss-provenance resolve --apply --policy-ref <admitted-commit>
```

Automatic application accepts ordinary version-2 indexes containing regular
files, preserving executable modes. Split and sparse indexes, merge conflicts,
intent-to-add, assume-unchanged, skip-worktree, symlinks, and submodules are
unsupported. Existing index locks and concurrent index, HEAD, or admission
changes block application. Alternate `GIT_INDEX_FILE` indexes and linked
worktrees have separate transaction state.

## Independent generation

An operator supplies an absolute configuration path outside the repository and
Git metadata. The requirements and trusted tests must also be outside that
ancestry. Review those inputs independently of the suspect implementation.

```toml
version = 1
provider_image = "sha256:<64 lowercase hexadecimal digits>"
test_image = "sha256:<64 lowercase hexadecimal digits>"
requirements = "/absolute/approved/requirements.txt"
tests = "/absolute/approved/tests"
test_command = ["/bin/sh", "/trusted/test.sh"]
targets = ["src/implementation.c"]
```

Build the provider image from `containers/claude/Dockerfile`, then use its full
local image ID. The supplied Dockerfile pins Claude Code 2.1.285 and an ARM64
Node 22 base. The test image must contain the compiler/runtime needed by the
approved test command and `/usr/bin/timeout` from GNU coreutils.
The preflight verifies GNU timeout and that the configured executable exists and
is executable. The operator must also approve its interpreter and runtime
dependencies. After the container starts, any nonzero test exit counts as a
failed attempt, including 125, 126, and 127. Missing interpreters or runtime
libraries after preflight therefore count as test failures. A missing executable
fails preflight and pauses without consuming an attempt.
Images must already exist locally; execution never pulls
an image. The test command is an argv array, with an absolute executable path.

Provide exactly one authentication variable, `ANTHROPIC_API_KEY` or
`CLAUDE_CODE_OAUTH_TOKEN`, using the operator's credential mechanism. Tokens are
read from the operator environment and transferred on stdin to a fixed wrapper
inside the container. The wrapper exports only the selected authentication
variable for the worker, then executes the provider with the remaining prompt
bytes. Tokens must be UTF-8, at most 16 KiB, and contain no NUL or line breaks.
They are never placed in the Docker client's environment, container Config.Env
or Cmd metadata, command arguments, or home mounts.
Provider daemon logging is disabled; the resolver captures and bounds the
attached output without retaining Docker stdout/stderr logs.

```console
oss-provenance resolve --agent claude --repair-config /absolute/approved/repair.toml --policy-ref <admitted-commit> --format json
```

The provider receives only the frozen independent requirements, target names,
and fixed feedback categories. It receives no repository, Git history, source
evidence, previous candidate, or test output. Every invocation creates a fresh
container and session. Tools, skills, MCP servers, plugins, slash commands, and
session persistence are disabled. Initialization and result events must confirm
the empty tool configuration and a fresh, consistent session ID. Responses must
be plain JSON with exactly the requested files; Markdown fences are rejected.

Provider containers have a read-only root, a private bounded temporary home,
no host mounts, an unprivileged user, dropped capabilities, and process, memory,
CPU, output, and time limits. Provider network access remains enabled for the
service connection. Tests run separately with networking disabled, without
credentials, and with read-only mounts at `/candidate` and `/trusted`. Use
`/tmp` for compilation output. Tests execute copied approved bytes, so later
changes to their original files cannot change an in-flight test.

GNU `timeout` runs as container PID 1 and terminates provider execution after
180 seconds or tests after 60 seconds, even if the resolver is killed.
Normal cleanup removes only the container ID recorded by that invocation.
An abruptly killed resolver can leave stopped container metadata. The resolver
does not prune containers without its own ownership record.

The first automatic provider is Claude. Codex remains available only through
the explicit `--agent codex --brief ... --output ...` manual handoff workflow.
Isolation and test success do not themselves establish licensing permission;
the replacement must still pass the unchanged provenance policy before staging.

## Attempts and recovery

The maximum is ten unsuccessful attempts and cannot be overridden. Invalid
candidates, failed independent tests, rejected provenance, and interrupted
generation consume the budget. Confirmed provider or infrastructure outages
pause without consuming an unsuccessful attempt. A scanner outage preserves the
candidate and resumes verification without generating another implementation.
JSON reports include the persisted failure count, reservations, and attempts
consumed by the current invocation.
Cleanup errors pause execution after saving any confirmed test outcome or
generated candidate. They never refund an already confirmed failed attempt.

State lives under the Git common directory's `ai-cleanroom` directory, with a
separate lock and journal for each worktree and active index. Changing the
configuration path, requirements, tests, images, arguments, targets, policy, `--all`, or
original staged snapshot cannot reset an active, exhausted, or conflicted job's
budget. Failed candidate
artifacts remain local and are never supplied to subsequent workers.

Application uses a durable prepared index and journal. After interruption,
the repair state must match the journal's original snapshot, final candidate,
and policy transaction identity; an earlier notice transaction cannot satisfy it.
Recovery installs only a still-pending transaction whose original index and
policy identities match. An already installed transaction is reconciled; a
completed transaction never overwrites a later user reversion. If the index was
installed while HEAD or admission changed, recovery reports an installed
conflict and requires manual review. Do not delete journals or an existing
`index.lock` to force an unresolved operation through.

A recovered `applied` result describes the recorded transaction and has no new
check report. Run `check` to assess the current policy. Recovery reports an
installed conflict before validating a changed or missing repair configuration.

After a completed repair, staging different index content starts a new job when
the current policy, approved inputs, and fresh blocked findings validate. A
configuration change alone cannot start another job. Repeating the completed
index, including after committing it, returns historical `applied` with no new
report. Same-index admission changes still require conflict review.

Completed jobs are preserved as immutable `completed-<job>.json` records with
their counts and provider sessions. Immutable `applied-<identity>.json` receipts
survive subsequent notice applications. Failed candidate files remain unchanged:
the first job uses `failed-<attempt>.json`; later jobs use
`failed-<job>-<attempt>.json`. The completed record is durable before a new job's
state replaces the active state, so an interruption cannot erase the old history
or reset a partially started job.

## Run the container workflow tests

The deterministic fixture exercises the real CLI, Docker boundary, persisted
attempt limit, process interruption, scanner recovery, and index application.
It uses a dummy credential and makes no model request. Build it after the
provider image:

```console
docker build -t ai-cleanroom-claude:2.1.285 containers/claude
docker build -t ai-cleanroom-repair-fixture tests/fixtures/repair-provider
docker image inspect ai-cleanroom-repair-fixture --format '{{.Id}}'
```

Set `AI_CLEANROOM_TEST_PROVIDER_IMAGE` to that image ID, then run:

```console
cargo test --test check_workflow repair_cli_ -- --ignored --test-threads=1
cargo test --lib sandbox::tests::running_output_limit_fails_tests_but_missing_image_is_operational -- --ignored
```

These tests do not prove authenticated model generation. That requires a
separate approved provider call with independent requirements and tests.
