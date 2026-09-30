use oss_provenance::git::{LineRange, Scope, Snapshot};
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

struct Repo(TempDir);

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
        let output = Command::new("git")
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
    let merge = Command::new("git")
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
    let mut child = Command::new("git")
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
