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

