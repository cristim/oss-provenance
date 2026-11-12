use oss_provenance::git::{ApplicationStatus, IndexSession};
use oss_provenance::git::{LineRange, Scope, Snapshot};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

struct Repo(TempDir);

#[test]
fn application_identity_includes_captured_admission() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    let first = repo.staged(false);
    let raw = fs::read(repo.path().join(".git/index")).unwrap();
    repo.git(&["config", "oss-provenance.policy-ref", &reference]);
    let second = repo.staged(false);
    assert_eq!(fs::read(repo.path().join(".git/index")).unwrap(), raw);
    assert_eq!(
        first.staged_identity().unwrap(),
        second.staged_identity().unwrap()
    );
    assert_ne!(
        IndexSession::application_identity(&first, &first, &reference).unwrap(),
        IndexSession::application_identity(&second, &second, &reference).unwrap()
    );
}

#[test]
fn completion_receipts_survive_later_applications_without_reinstalling() {
    use oss_provenance::git::CompletedApplication;
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    let session = IndexSession::open(repo.path()).unwrap();
    let original = repo.staged(false);
    let candidate = original
        .overlay(&BTreeMap::from([(
            "source.rs".into(),
            b"replacement\n".to_vec(),
        )]))
        .unwrap();
    let id = IndexSession::application_identity(&original, &candidate, &reference).unwrap();
    session.apply(&original, &candidate, &reference).unwrap();
    let receipt = session.state_dir.join(format!("applied-{id}.json"));
    let receipt_bytes = fs::read(&receipt).unwrap();
    let current = repo.staged(false);
    session.apply(&current, &current, &reference).unwrap();
    assert_eq!(
        session
            .completed_application(&id, &repo.staged(false))
            .unwrap(),
        Some(CompletedApplication::SameIndex)
    );
    assert_eq!(
        session.recover_application(&id).unwrap(),
        Some(ApplicationStatus::Applied)
    );
    repo.git(&["commit", "-m", "commit replacement"]);
    assert_eq!(
        session
            .completed_application(&id, &repo.staged(false))
            .unwrap(),
        Some(CompletedApplication::SameIndex)
    );
    let raw = fs::read(&session.index_path).unwrap();
    assert!(session.recover_application(&id).is_err());
    assert_eq!(fs::read(&session.index_path).unwrap(), raw);
    repo.write("source.rs", "new job\n");
    repo.git(&["add", "source.rs"]);
    repo.git(&["config", "oss-provenance.policy-ref", "new-policy"]);
    assert_eq!(
        session
            .completed_application(&id, &repo.staged(false))
            .unwrap(),
        Some(CompletedApplication::ChangedIndex)
    );
    assert_eq!(fs::read(receipt).unwrap(), receipt_bytes);
}

#[test]
fn immutable_history_rejects_collisions_and_symlinks() {
    use oss_provenance::git::durable_write_once;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("history");
    durable_write_once(&path, b"saved").unwrap();
    durable_write_once(&path, b"saved").unwrap();
    assert!(durable_write_once(&path, b"different").is_err());
    assert_eq!(fs::read(&path).unwrap(), b"saved");
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(durable_write_once(&link, b"saved").is_err());
}

#[test]
fn repository_root_preserves_a_trailing_newline_in_its_name() {
    let repo = Repo(tempfile::Builder::new().suffix("\n").tempdir().unwrap());
    repo.git(&["init", "-q"]);
    repo.write("source.rs", "original\n");
    repo.git(&["add", "source.rs"]);
    let snapshot = repo.staged(false);
    assert_eq!(snapshot.files["source.rs"].bytes, b"original\n");
    let session = IndexSession::open(repo.path()).unwrap();
    assert_eq!(session.root, fs::canonicalize(repo.path()).unwrap());
    assert_eq!(
        session.common_dir,
        fs::canonicalize(repo.path().join(".git")).unwrap()
    );
}

#[test]
fn session_identity_uses_worktree_root() {
    let repo = Repo::new();
    repo.write("sub/source.rs", "original\n");
    repo.commit();
    let session = IndexSession::open(repo.path()).unwrap();
    let state_dir = session.state_dir.clone();
    drop(session);
    assert_eq!(
        IndexSession::open(&repo.path().join("sub"))
            .unwrap()
            .state_dir,
        state_dir
    );
}

#[test]
fn application_rejects_changed_admission_and_completed_reversion() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    repo.git(&["config", "oss-provenance.policy-ref", &reference]);
    let session = IndexSession::open(repo.path()).unwrap();
    let before = repo.staged(false);
    let raw = fs::read(&session.index_path).unwrap();
    let candidate = before
        .overlay(&BTreeMap::from([(
            "source.rs".into(),
            b"replacement\n".to_vec(),
        )]))
        .unwrap();
    repo.git(&["config", "oss-provenance.policy-ref", "changed-admission"]);
    assert!(session.apply(&before, &candidate, &reference).is_err());
    assert_eq!(fs::read(&session.index_path).unwrap(), raw);
    repo.git(&["config", "oss-provenance.policy-ref", &reference]);
    assert_eq!(
        session.apply(&before, &candidate, &reference).unwrap(),
        ApplicationStatus::Applied
    );
    fs::write(&session.index_path, &raw).unwrap();
    assert!(
        session
            .recover_application(
                &IndexSession::application_identity(&before, &candidate, &reference).unwrap()
            )
            .is_err()
    );
    assert_eq!(fs::read(&session.index_path).unwrap(), raw);
}

#[test]
fn linked_worktrees_have_distinct_journals() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    repo.commit();
    let linked_parent = tempfile::tempdir().unwrap();
    let linked = linked_parent.path().join("linked");
    repo.git(&[
        "worktree",
        "add",
        "--detach",
        linked.to_str().unwrap(),
        "HEAD",
    ]);
    let original = IndexSession::open(repo.path()).unwrap();
    let other = IndexSession::open(&linked).unwrap();
    assert_eq!(original.common_dir, other.common_dir);
    assert_ne!(original.state_dir, other.state_dir);
    assert_ne!(original.index_path, other.index_path);
}

#[test]
fn prepared_index_cannot_silently_replace_an_ancestor_path() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    let session = IndexSession::open(repo.path()).unwrap();
    let original = repo.staged(false);
    let raw = fs::read(&session.index_path).unwrap();
    let candidate = original
        .overlay(&BTreeMap::from([(
            "source.rs/child.rs".into(),
            b"replacement\n".to_vec(),
        )]))
        .unwrap();
    assert!(session.apply(&original, &candidate, &reference).is_err());
    assert_eq!(fs::read(&session.index_path).unwrap(), raw);
    assert_eq!(repo.git(&["ls-files"]), "source.rs");
}

fn isolated(mut command: Command) -> Command {
    let keys: Vec<_> = std::env::vars_os()
        .map(|(key, _)| key)
        .chain(command.get_envs().map(|(key, _)| key.to_owned()))
        .filter(|key| key.to_string_lossy().starts_with("GIT_"))
        .collect();
    for key in keys {
        command.env_remove(key);
    }
    command
}

impl Repo {
    fn new() -> Self {
        let repo = Self(tempfile::tempdir().unwrap());
        repo.git(&["init", "--initial-branch=main"]);
        repo.git(&["config", "user.name", "Snapshot Test"]);
        repo.git(&["config", "user.email", "snapshot@example.invalid"]);
        repo
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = isolated(Command::new("git"))
            .arg("-C")
            .arg(self.path())
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.fsmonitor=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        let path = self.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn commit(&self) -> String {
        self.git(&["add", "."]);
        self.git(&["commit", "-m", "fixture"]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn staged(&self, all: bool) -> Snapshot {
        Snapshot::capture(self.path(), Scope::Staged { all }).unwrap()
    }
}

#[test]
fn partial_staging_uses_index_and_tracks_only_added_lines() {
    let repo = Repo::new();
    repo.write("source with spaces.rs", "old\nkeep\nlast\n");
    repo.commit();
    repo.write("source with spaces.rs", "new\nkeep\nlast\nadded\n");
    repo.git(&["add", "."]);
    repo.write("source with spaces.rs", "unstaged only\n");
    let snapshot = repo.staged(false);
    assert_eq!(
        snapshot.files["source with spaces.rs"].bytes,
        b"new\nkeep\nlast\nadded\n"
    );
    assert_eq!(
        snapshot.baseline["source with spaces.rs"].bytes,
        b"old\nkeep\nlast\n"
    );
    assert_eq!(
        snapshot.added["source with spaces.rs"],
        [
            LineRange { start: 1, end: 1 },
            LineRange { start: 4, end: 4 }
        ]
    );
    snapshot.verify_unchanged().unwrap();
}

#[test]
fn unborn_head_and_paths_with_tabs_newlines_and_leading_dashes() {
    let repo = Repo::new();
    for path in ["-dash.rs", "tab\tfile.rs", "line\nfile.rs"] {
        repo.write(path, "one\ntwo");
    }
    repo.git(&["add", "."]);
    let snapshot = repo.staged(false);
    assert!(snapshot.baseline.is_empty());
    assert_eq!(snapshot.files.len(), 3);
    for ranges in snapshot.added.values() {
        assert_eq!(*ranges, [LineRange { start: 1, end: 2 }]);
    }
    repo.commit();
    assert!(
        snapshot
            .verify_unchanged()
            .unwrap_err()
            .to_string()
            .contains("HEAD changed")
    );
}

#[test]
fn deletions_and_metadata_only_changes_remain_visible_without_source_additions() {
    let repo = Repo::new();
    repo.write("LICENSE-NOTICES/manifest.json", "{}\n");
    repo.write("source.rs", "first\nsecond\n");
    repo.commit();
    fs::remove_file(repo.path().join("LICENSE-NOTICES/manifest.json")).unwrap();
    repo.write("source.rs", "first\n");
    repo.git(&["add", "."]);
    let snapshot = repo.staged(false);
    assert!(
        snapshot
            .baseline
            .contains_key("LICENSE-NOTICES/manifest.json")
    );
    assert!(!snapshot.files.contains_key("LICENSE-NOTICES/manifest.json"));
    assert!(snapshot.added.is_empty());
    let all = repo.staged(true);
    assert_eq!(all.added["source.rs"], [LineRange { start: 1, end: 1 }]);
}

#[test]
fn renames_are_scanned_at_the_destination_and_binary_modes_are_preserved() {
    let repo = Repo::new();
    repo.write("old.rs", "original\n");
    repo.write("binary.bin", [0, 1, 2]);
    repo.commit();
    repo.git(&["mv", "old.rs", "new.rs"]);
    repo.write("binary.bin", [0, 1, 3]);
    repo.git(&["add", "."]);
    repo.git(&["update-index", "--chmod=+x", "new.rs"]);
    let snapshot = repo.staged(false);
    assert!(snapshot.baseline.contains_key("old.rs"));
    assert!(!snapshot.files.contains_key("old.rs"));
    assert_eq!(snapshot.files["new.rs"].mode, "100755");
    assert_eq!(snapshot.added["new.rs"], [LineRange { start: 1, end: 1 }]);
    assert_eq!(snapshot.files["binary.bin"].bytes, [0, 1, 3]);
    assert!(snapshot.added.contains_key("binary.bin"));
}

#[test]
fn detects_index_drift_independently_of_worktree() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    repo.commit();
    let snapshot = repo.staged(false);
    repo.write("source.rs", "two\n");
    snapshot.verify_unchanged().unwrap();
    repo.git(&["add", "."]);
    assert!(
        snapshot
            .verify_unchanged()
            .unwrap_err()
            .to_string()
            .contains("index changed")
    );
}

#[test]
fn range_uses_exact_commits_and_detects_ref_drift_even_with_identical_trees() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    let base = repo.commit();
    repo.write("source.rs", "one\ntwo\n");
    repo.commit();
    let snapshot = Snapshot::capture(
        repo.path(),
        Scope::Range {
            base,
            head: "main".into(),
        },
    )
    .unwrap();
    assert_eq!(
        snapshot.added["source.rs"],
        [LineRange { start: 2, end: 2 }]
    );
    repo.git(&["commit", "--allow-empty", "-m", "ref drift"]);
    assert!(
        snapshot
            .verify_unchanged()
            .unwrap_err()
            .to_string()
            .contains("reference")
    );
}

#[test]
fn full_scope_reads_committed_tree_and_safe_reference_paths() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    let oid = repo.commit();
    repo.write("source.rs", "two\n");
    repo.git(&["add", "."]);
    let snapshot = Snapshot::capture(repo.path(), Scope::Full { head: oid.clone() }).unwrap();
    assert_eq!(snapshot.files["source.rs"].bytes, b"one\n");
    assert_eq!(
        snapshot.read_at(&oid, "source.rs").unwrap(),
        Some(b"one\n".to_vec())
    );
    assert_eq!(snapshot.read_at(&oid, "missing.rs").unwrap(), None);
    assert!(snapshot.read_at(&oid, "../source.rs").is_err());
    assert!(snapshot.resolve_ref("--help").is_err());
    assert!(snapshot.resolve_ref("does-not-exist").is_err());
}

#[test]
fn hostile_attributes_cannot_hide_text_additions() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    repo.commit();
    repo.write("source.rs", "two\n");
    repo.git(&["add", "."]);

    repo.write(".gitattributes", "* -diff\n");
    assert_eq!(
        repo.staged(false).added["source.rs"],
        [LineRange { start: 1, end: 1 }]
    );

    repo.write(".gitattributes", "");
    let external = tempfile::tempdir().unwrap();
    let attributes = external.path().join("attributes");
    fs::write(&attributes, "* -diff\n").unwrap();
    repo.git(&[
        "config",
        "core.attributesFile",
        attributes.to_str().unwrap(),
    ]);
    assert_eq!(
        repo.staged(false).added["source.rs"],
        [LineRange { start: 1, end: 1 }]
    );
}

#[test]
fn does_not_run_external_diff_or_textconv() {
    let repo = Repo::new();
    repo.write("source.txt", "one\n");
    repo.write(".gitattributes", "*.txt diff=hostile\n");
    repo.commit();
    repo.git(&["config", "diff.external", "false"]);
    repo.git(&["config", "diff.hostile.textconv", "false"]);
    repo.write("source.txt", "two\n");
    repo.git(&["add", "."]);
    assert_eq!(
        repo.staged(false).added["source.txt"],
        [LineRange { start: 1, end: 1 }]
    );
}

#[test]
fn unmerged_index_fails() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    repo.commit();
    repo.git(&["checkout", "-b", "other"]);
    repo.write("source.rs", "other\n");
    repo.commit();
    repo.git(&["checkout", "main"]);
    repo.write("source.rs", "main\n");
    repo.commit();
    let merge = isolated(Command::new("git"))
        .arg("-C")
        .arg(repo.path())
        .args(["-c", "core.hooksPath=/dev/null", "merge", "other"])
        .output()
        .unwrap();
    assert!(!merge.status.success());
    let error = Snapshot::capture(repo.path(), Scope::Staged { all: false })
        .err()
        .unwrap();
    assert!(error.to_string().contains("unmerged"), "{error}");
}

#[cfg(unix)]
#[test]
fn symlinks_and_gitlinks_preserve_modes_without_reading_targets() {
    use std::os::unix::fs::symlink;
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    let oid = repo.commit();
    symlink("/not/read/by/snapshot", repo.path().join("link.rs")).unwrap();
    repo.git(&["add", "."]);
    repo.git(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{oid},submodule"),
    ]);
    let snapshot = repo.staged(false);
    assert_eq!(snapshot.files["link.rs"].mode, "120000");
    assert_eq!(snapshot.files["link.rs"].bytes, b"/not/read/by/snapshot");
    assert_eq!(snapshot.files["submodule"].mode, "160000");
    assert!(snapshot.files["submodule"].bytes.is_empty());
    assert!(snapshot.added.contains_key("submodule"));
}

#[test]
fn non_utf8_paths_fail_explicitly() {
    use std::io::Write;
    use std::process::Stdio;
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    repo.commit();
    let oid = repo.git(&["rev-parse", "HEAD:source.rs"]);
    let mut entry = format!("100644 {oid}\t").into_bytes();
    entry.extend_from_slice(b"invalid-\xff.rs\0");
    let mut child = isolated(Command::new("git"))
        .arg("-C")
        .arg(repo.path())
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "update-index",
            "-z",
            "--index-info",
        ])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&entry).unwrap();
    assert!(child.wait().unwrap().success());
    let error = Snapshot::capture(repo.path(), Scope::Staged { all: false })
        .err()
        .unwrap();
    assert!(error.to_string().contains("non-UTF-8"), "{error}");
}

#[test]
fn staged_head_drift_is_detected_even_when_the_index_is_unchanged() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    repo.commit();
    let snapshot = repo.staged(false);
    repo.git(&["commit", "--allow-empty", "-m", "move HEAD"]);
    assert!(
        snapshot
            .verify_unchanged()
            .unwrap_err()
            .to_string()
            .contains("HEAD changed")
    );
}

#[test]
fn tree_oids_are_supported_without_ancestry_requirements() {
    let repo = Repo::new();
    repo.write("source.rs", "one\n");
    repo.commit();
    let base = repo.git(&["rev-parse", "HEAD^{tree}"]);
    repo.write("source.rs", "two\n");
    repo.commit();
    let head = repo.git(&["rev-parse", "HEAD^{tree}"]);
    let snapshot = Snapshot::capture(
        repo.path(),
        Scope::Range {
            base,
            head: head.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        snapshot.added["source.rs"],
        [LineRange { start: 1, end: 1 }]
    );
    assert_eq!(
        snapshot.read_at(&head, "source.rs").unwrap(),
        Some(b"two\n".to_vec())
    );
}

#[test]
fn transaction_stages_exact_bytes_preserving_worktree_and_executable_mode() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    repo.git(&["update-index", "--chmod=+x", "source.rs"]);
    repo.write("source.rs", "unstaged edits\n");
    repo.write("new.rs", "untracked sentinel\n");
    repo.git(&["config", "filter.hostile.clean", "false"]);
    repo.write(".gitattributes", "* filter=hostile\n");
    let session = IndexSession::open(repo.path()).unwrap();
    let before = repo.staged(false);
    session.validate_supported(&before).unwrap();
    let candidate = before
        .overlay(&BTreeMap::from([
            ("source.rs".into(), b"replacement\n".to_vec()),
            ("new.rs".into(), b"generated\n".to_vec()),
        ]))
        .unwrap();
    assert_eq!(
        session.apply(&before, &candidate, &reference).unwrap(),
        ApplicationStatus::Applied
    );
    assert_eq!(repo.git(&["show", ":source.rs"]), "replacement");
    assert_eq!(repo.git(&["show", ":new.rs"]), "generated");
    assert_eq!(repo.staged(false).files["source.rs"].mode, "100755");
    assert_eq!(
        fs::read(repo.path().join("source.rs")).unwrap(),
        b"unstaged edits\n"
    );
    assert_eq!(
        fs::read(repo.path().join("new.rs")).unwrap(),
        b"untracked sentinel\n"
    );
}

#[test]
fn transaction_refuses_concurrent_changes_and_foreign_index_lock() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    let session = IndexSession::open(repo.path()).unwrap();
    let before = repo.staged(false);
    let candidate = before
        .overlay(&BTreeMap::from([(
            "source.rs".into(),
            b"replacement\n".to_vec(),
        )]))
        .unwrap();
    let lock = session.index_path.with_file_name("index.lock");
    fs::write(&lock, b"someone else's lock").unwrap();
    assert!(session.apply(&before, &candidate, &reference).is_err());
    assert_eq!(fs::read(&lock).unwrap(), b"someone else's lock");
    fs::remove_file(&lock).unwrap();
    repo.write("source.rs", "concurrent staged change\n");
    repo.git(&["add", "source.rs"]);
    assert!(session.recover().is_err());
    assert_eq!(
        repo.git(&["show", ":source.rs"]),
        "concurrent staged change"
    );
}

#[test]
fn pending_installation_is_discovered_by_stable_index_identity() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    let session = IndexSession::open(repo.path()).unwrap();
    let before = repo.staged(false);
    let raw = fs::read(&session.index_path).unwrap();
    let candidate = before
        .overlay(&BTreeMap::from([(
            "source.rs".into(),
            b"replacement\n".to_vec(),
        )]))
        .unwrap();
    session.apply(&before, &candidate, &reference).unwrap();
    let journal_path = session.state_dir.join("application.json");
    let mut journal: serde_json::Value =
        serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
    journal["status"] = "prepared".into();
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    fs::write(&session.index_path, raw).unwrap();
    let state_dir = session.state_dir.clone();
    let application_id =
        IndexSession::application_identity(&before, &candidate, &reference).unwrap();
    drop(session);
    let resumed = IndexSession::open(repo.path()).unwrap();
    assert_eq!(resumed.state_dir, state_dir);
    assert_eq!(
        resumed.recover_application(&application_id).unwrap(),
        Some(ApplicationStatus::Applied)
    );
    assert_eq!(repo.git(&["show", ":source.rs"]), "replacement");
    journal["status"] = "prepared".into();
    fs::write(&journal_path, serde_json::to_vec(&journal).unwrap()).unwrap();
    let installed = fs::read(&resumed.index_path).unwrap();
    repo.git(&["commit", "--allow-empty", "-m", "ref movement"]);
    fs::write(&resumed.index_path, installed).unwrap();
    assert_eq!(
        resumed.recover_application(&application_id).unwrap(),
        Some(ApplicationStatus::InstalledButConflicted)
    );
    assert_eq!(repo.git(&["show", ":source.rs"]), "replacement");
}

#[test]
fn recovery_cannot_accept_an_unrelated_application() {
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    let reference = repo.commit();
    let session = IndexSession::open(repo.path()).unwrap();
    let original = repo.staged(false);
    session.apply(&original, &original, &reference).unwrap();
    let raw = fs::read(&session.index_path).unwrap();
    let path = session.state_dir.join("application.json");
    let mut journal: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let other = "0".repeat(64);
    assert_eq!(session.recover_application(&other).unwrap(), None);
    for status in ["prepared", "installed_but_conflicted"] {
        journal["status"] = status.into();
        let bytes = serde_json::to_vec(&journal).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(session.recover_application(&other).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(&session.index_path).unwrap(), raw);
    }
}

#[test]
fn unsupported_index_features_are_rejected() {
    for args in [
        vec!["update-index", "--assume-unchanged", "source.rs"],
        vec!["update-index", "--skip-worktree", "source.rs"],
        vec!["update-index", "--split-index"],
        vec!["update-index", "--index-version=4"],
    ] {
        let repo = Repo::new();
        repo.write("source.rs", "original\n");
        repo.commit();
        repo.git(&args);
        let session = IndexSession::open(repo.path()).unwrap();
        assert!(
            session.validate_supported(&repo.staged(false)).is_err(),
            "accepted {args:?}"
        );
    }
    let repo = Repo::new();
    repo.write("source.rs", "original\n");
    repo.commit();
    repo.write("pending.rs", "not staged\n");
    repo.git(&["add", "--intent-to-add", "pending.rs"]);
    let session = IndexSession::open(repo.path()).unwrap();
    assert!(session.validate_supported(&repo.staged(false)).is_err());
}
