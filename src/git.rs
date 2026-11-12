use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::{fs, io::Write};

#[derive(Clone, Debug)]
pub struct Blob {
    pub mode: String,
    pub oid: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LineRange {
    pub start: usize,
    pub end: usize,
}

pub enum Scope {
    Staged { all: bool },
    Range { base: String, head: String },
    Full { head: String },
}

#[derive(Clone)]
pub struct Snapshot {
    pub root: PathBuf,
    pub baseline: BTreeMap<String, Blob>,
    pub files: BTreeMap<String, Blob>,
    pub added: BTreeMap<String, Vec<LineRange>>,
    captured_refs: Vec<(String, String)>,
    captured_index: Option<Vec<u8>>,
    captured_head: Option<Option<String>>,
    captured_raw_index: Option<(PathBuf, Option<Vec<u8>>)>,
    captured_admitted_config: Option<Option<String>>,
}

impl Snapshot {
    pub fn capture(root: &Path, scope: Scope) -> Result<Self> {
        let root = repository_root(root)?;
        let mut snapshot = Self {
            root,
            baseline: BTreeMap::new(),
            files: BTreeMap::new(),
            added: BTreeMap::new(),
            captured_refs: Vec::new(),
            captured_index: None,
            captured_head: None,
            captured_raw_index: None,
            captured_admitted_config: None,
        };
        let all = match scope {
            Scope::Staged { all } => {
                snapshot.captured_admitted_config = Some(admitted_config(&snapshot.root)?);
                let path = index_path(&snapshot.root)?;
                snapshot.captured_raw_index = Some((path.clone(), read_index(&path)?));
                let head = head_oid(&snapshot.root)?;
                let index = git(&snapshot.root, &["ls-files", "--stage", "-z"])?;
                snapshot.files = load_entries(&snapshot.root, &index, true)?;
                if let Some(reference) = &head {
                    snapshot.baseline = load_tree(&snapshot.root, reference)?;
                }
                snapshot.captured_head = Some(head);
                snapshot.captured_index = Some(index);
                all
            }
            Scope::Range { base, head } => {
                let base_oid = snapshot.resolve_ref(&base)?;
                let head_oid = snapshot.resolve_ref(&head)?;
                snapshot.baseline = load_tree(&snapshot.root, &base_oid)?;
                snapshot.files = load_tree(&snapshot.root, &head_oid)?;
                snapshot.captured_refs = vec![(base, base_oid), (head, head_oid)];
                false
            }
            Scope::Full { head } => {
                let oid = snapshot.resolve_ref(&head)?;
                snapshot.files = load_tree(&snapshot.root, &oid)?;
                snapshot.captured_refs.push((head, oid));
                true
            }
        };
        for (path, blob) in &snapshot.files {
            let ranges = if all {
                full_range(blob)
            } else {
                changed_ranges(&snapshot.root, snapshot.baseline.get(path), blob)?
            };
            if !ranges.is_empty() {
                snapshot.added.insert(path.clone(), ranges);
            }
        }
        snapshot.verify_unchanged()?;
        Ok(snapshot)
    }

    pub fn verify_unchanged(&self) -> Result<()> {
        if let Some(expected) = &self.captured_admitted_config {
            ensure!(
                admitted_config(&self.root)? == *expected,
                "admitted policy configuration changed during scan"
            );
        }
        if let Some(expected) = &self.captured_head {
            ensure!(
                head_oid(&self.root)? == *expected,
                "HEAD changed during scan"
            );
        }
        if let Some((path, expected)) = &self.captured_raw_index {
            ensure!(
                index_path(&self.root)? == *path && read_index(path)? == *expected,
                "Git index changed during scan (raw bytes)"
            );
        }
        if let Some(expected) = &self.captured_index {
            ensure!(
                git(&self.root, &["ls-files", "--stage", "-z"])? == *expected,
                "Git index changed during scan"
            );
        }
        for (reference, expected) in &self.captured_refs {
            ensure!(
                self.resolve_ref(reference)? == *expected,
                "Git reference {reference:?} changed during scan"
            );
        }
        Ok(())
    }

    pub fn read_at(&self, reference: &str, path: &str) -> Result<Option<Vec<u8>>> {
        validate_path(path)?;
        let oid = self.resolve_ref(reference)?;
        let output = git(&self.root, &["ls-tree", "-r", "-z", "--full-tree", &oid])?;
        for record in output
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
        {
            let (metadata, entry_path) = parse_record(record)?;
            if entry_path == path {
                let fields: Vec<_> = metadata.split_ascii_whitespace().collect();
                ensure!(fields.len() == 3, "malformed Git tree entry");
                ensure!(fields[1] == "blob", "{path:?} is not a Git blob");
                return Ok(Some(git(&self.root, &["cat-file", "blob", fields[2]])?));
            }
        }
        Ok(None)
    }

    pub fn resolve_ref(&self, reference: &str) -> Result<String> {
        ensure!(
            !reference.is_empty() && !reference.starts_with('-'),
            "invalid Git reference"
        );
        let expression = format!("{reference}^{{object}}");
        let output = git(
            &self.root,
            &["rev-parse", "--verify", "--end-of-options", &expression],
        )?;
        Ok(std::str::from_utf8(&output)?.trim().to_owned())
    }

    pub fn overlay(&self, changes: &BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let mut candidate = self.clone();
        for (path, bytes) in changes {
            validate_path(path)?;
            let output = git_input(
                &self.root,
                &["hash-object", "-w", "--stdin", "--no-filters"],
                bytes,
                None,
            )?;
            let blob = Blob {
                mode: self
                    .files
                    .get(path)
                    .map_or("100644", |blob| blob.mode.as_str())
                    .to_owned(),
                oid: std::str::from_utf8(&output)?.trim().to_owned(),
                bytes: bytes.clone(),
            };
            let ranges = changed_ranges(&self.root, self.baseline.get(path), &blob)?;
            candidate.added.remove(path);
            if !ranges.is_empty() {
                candidate.added.insert(path.clone(), ranges);
            }
            candidate.files.insert(path.clone(), blob);
        }
        Ok(candidate)
    }

    pub fn staged_identity(&self) -> Result<String> {
        let (path, bytes) = self
            .captured_raw_index
            .as_ref()
            .context("repair requires a staged snapshot")?;
        Ok(crate::policy::sha256(&serde_json::to_vec(&(
            path,
            digest(bytes),
            &self.captured_head,
            logical_digest(&self.files),
            logical_digest(&self.baseline),
        ))?))
    }
}

fn git_command(root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    command
}

fn git_output(root: &Path, args: &[&str]) -> Result<Output> {
    git_command(root)
        .args(args)
        .output()
        .context("could not run Git")
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = git_output(root, args)?;
    ensure!(
        output.status.success(),
        "git {} failed: {}",
        args[0],
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

fn head_oid(root: &Path) -> Result<Option<String>> {
    let output = git_output(root, &["rev-parse", "--verify", "--quiet", "HEAD"])?;
    if output.status.success() {
        return Ok(Some(std::str::from_utf8(&output.stdout)?.trim().to_owned()));
    }
    let symbolic = git(root, &["symbolic-ref", "--quiet", "HEAD"])?;
    let reference = std::str::from_utf8(&symbolic)?.trim();
    let exists = git_output(root, &["show-ref", "--verify", "--quiet", reference])?;
    ensure!(exists.status.code() == Some(1), "HEAD cannot be resolved");
    Ok(None)
}

fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.contains('\0')
            && !path.starts_with('/')
            && !path
                .split('/')
                .any(|part| part == ".." || part == "." || part.is_empty()),
        "unsafe Git path {path:?}"
    );
    Ok(())
}

fn parse_record(record: &[u8]) -> Result<(&str, &str)> {
    let tab = record
        .iter()
        .position(|byte| *byte == b'\t')
        .context("malformed Git entry")?;
    let metadata = std::str::from_utf8(&record[..tab])?;
    let path =
        std::str::from_utf8(&record[tab + 1..]).context("non-UTF-8 Git paths are unsupported")?;
    validate_path(path)?;
    Ok((metadata, path))
}

fn load_tree(root: &Path, reference: &str) -> Result<BTreeMap<String, Blob>> {
    let output = git(root, &["ls-tree", "-r", "-z", "--full-tree", reference])?;
    load_entries(root, &output, false)
}

fn load_entries(root: &Path, output: &[u8], index: bool) -> Result<BTreeMap<String, Blob>> {
    let mut files = BTreeMap::new();
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let (metadata, path) = parse_record(record)?;
        let fields: Vec<_> = metadata.split_ascii_whitespace().collect();
        ensure!(fields.len() == 3, "malformed Git entry");
        if index && fields[2] != "0" {
            bail!("unmerged Git index entry at {path:?}");
        }
        let oid = fields[if index { 1 } else { 2 }];
        let bytes = if fields[0] == "160000" {
            Vec::new()
        } else {
            git(root, &["cat-file", "blob", oid])?
        };
        files.insert(
            path.to_owned(),
            Blob {
                mode: fields[0].to_owned(),
                oid: oid.to_owned(),
                bytes,
            },
        );
    }
    Ok(files)
}

fn full_range(blob: &Blob) -> Vec<LineRange> {
    let lines = blob.bytes.split_inclusive(|byte| *byte == b'\n').count();
    if lines == 0 && matches!(blob.mode.as_str(), "100644" | "100755") {
        Vec::new()
    } else {
        vec![LineRange {
            start: 1,
            end: lines.max(1),
        }]
    }
}

fn changed_ranges(root: &Path, before: Option<&Blob>, after: &Blob) -> Result<Vec<LineRange>> {
    let Some(before) = before else {
        return Ok(full_range(after));
    };
    if before.oid == after.oid && before.mode == after.mode {
        return Ok(Vec::new());
    }
    if !matches!(before.mode.as_str(), "100644" | "100755")
        || !matches!(after.mode.as_str(), "100644" | "100755")
        || before.bytes.contains(&0)
        || after.bytes.contains(&0)
    {
        return Ok(full_range(after));
    }
    let output = git(
        root,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--text",
            "--no-color",
            "--no-renames",
            "--diff-algorithm=myers",
            "--no-indent-heuristic",
            "--unified=0",
            &before.oid,
            &after.oid,
            "--",
        ],
    )?;
    let mut ranges = Vec::new();
    for line in output.split(|byte| *byte == b'\n') {
        if !line.starts_with(b"@@ ") {
            continue;
        }
        let line = std::str::from_utf8(line).context("invalid Git hunk header")?;
        let span = line
            .split_ascii_whitespace()
            .nth(2)
            .context("missing Git hunk range")?;
        let span = span.strip_prefix('+').context("invalid Git hunk range")?;
        let (start, count) = span.split_once(',').unwrap_or((span, "1"));
        let start: usize = start.parse()?;
        let count: usize = count.parse()?;
        if count > 0 {
            ranges.push(LineRange {
                start,
                end: start + count - 1,
            });
        }
    }
    Ok(ranges)
}

fn git_input(root: &Path, args: &[&str], input: &[u8], index: Option<&Path>) -> Result<Vec<u8>> {
    let mut command = git_command(root);
    command.args(args);
    if let Some(path) = index {
        command.env("GIT_INDEX_FILE", path);
    }
    let output = crate::process::run(
        &mut command,
        input,
        crate::process::Limits {
            timeout: std::time::Duration::from_secs(30),
            max_output_bytes: 1024 * 1024,
        },
    )?;
    ensure!(
        output.status.success(),
        "Git index operation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn git_path(root: &Path, name: &str) -> Result<PathBuf> {
    let output = git(
        root,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    )?;
    let text = std::str::from_utf8(&output)?
        .strip_suffix('\n')
        .context("Git path has no terminator")?;
    let path = Path::new(text);
    Ok(
        fs::canonicalize(path.parent().context("Git path has no parent")?)?
            .join(path.file_name().context("Git path has no name")?),
    )
}

fn index_path(root: &Path) -> Result<PathBuf> {
    git_path(root, "index")
}

fn read_index(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= 128 * 1024 * 1024,
                "index must be a bounded regular file"
            );
            Ok(Some(fs::read(path)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("reading Git index"),
    }
}

fn digest(bytes: &Option<Vec<u8>>) -> Option<String> {
    bytes.as_deref().map(crate::policy::sha256)
}

fn logical_digest(files: &BTreeMap<String, Blob>) -> String {
    let mut bytes = Vec::new();
    for (path, blob) in files {
        for field in [path.as_bytes(), blob.mode.as_bytes(), blob.oid.as_bytes()] {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        }
    }
    crate::policy::sha256(&bytes)
}

fn admitted_config(root: &Path) -> Result<Option<String>> {
    let output = git_output(
        root,
        &["config", "--local", "--get", "oss-provenance.policy-ref"],
    )?;
    match output.status.code() {
        Some(0) => Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned())),
        Some(1) => Ok(None),
        _ => bail!("could not read admitted policy configuration"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn crash_at(point: &str) {
        if std::env::var("AI_CLEANROOM_TEST_CRASH").as_deref() == Ok(point) {
            unsafe { libc::_exit(86) }
        }
    }

    fn isolated(mut command: Command) -> Command {
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
    }

    fn child(root: &Path) -> Command {
        let mut command = isolated(Command::new(std::env::current_exe().unwrap()));
        command
            .args(["--exact", "git::tests::transaction_child", "--ignored"])
            .env("AI_CLEANROOM_TEST_ROOT", root);
        command
    }

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("source.rs"), b"original\n").unwrap();
        for args in [
            vec!["init", "-q"],
            vec!["add", "source.rs"],
            vec![
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            ],
        ] {
            assert!(
                isolated(Command::new("git"))
                    .arg("-C")
                    .arg(root.path())
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        root
    }

    #[test]
    #[ignore = "private subprocess worker"]
    fn transaction_child() {
        let root = PathBuf::from(std::env::var_os("AI_CLEANROOM_TEST_ROOT").unwrap());
        let session = IndexSession::open(&root).unwrap();
        if std::env::var_os("AI_CLEANROOM_TEST_RECOVER").is_some() {
            let journal: ApplicationJournal = serde_json::from_slice(
                &fs::read(session.state_dir.join("application.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                session
                    .recover_application(&journal.application_id)
                    .unwrap(),
                Some(ApplicationStatus::Applied)
            );
        } else {
            let original = Snapshot::capture(&root, Scope::Staged { all: false }).unwrap();
            let candidate = original
                .overlay(&BTreeMap::from([(
                    "source.rs".into(),
                    b"replacement\n".to_vec(),
                )]))
                .unwrap();
            let reference = original.resolve_ref("HEAD").unwrap();
            assert_eq!(
                session.apply(&original, &candidate, &reference).unwrap(),
                ApplicationStatus::Applied
            );
        }
        let snapshot = Snapshot::capture(&root, Scope::Staged { all: false }).unwrap();
        assert_eq!(snapshot.files["source.rs"].bytes, b"replacement\n");
    }

    #[test]
    fn process_crashes_reconcile_prepared_renamed_and_terminal_indexes() {
        for point in ["prepared", "rename", "terminal"] {
            let root = fixture();
            let failed = child(root.path())
                .env("AI_CLEANROOM_TEST_CRASH", point)
                .output()
                .unwrap();
            assert_eq!(failed.status.code(), Some(86), "{failed:?}");
            let recovered = child(root.path())
                .env("AI_CLEANROOM_TEST_RECOVER", "1")
                .output()
                .unwrap();
            assert!(recovered.status.success(), "{recovered:?}");
            assert_eq!(
                fs::read(root.path().join("source.rs")).unwrap(),
                b"original\n"
            );
        }
    }

    #[test]
    fn alternate_index_application_preserves_primary_index() {
        let root = fixture();
        let primary = root.path().join(".git/index");
        let before = fs::read(&primary).unwrap();
        let alternate = root.path().join("alternate-index");
        fs::write(&alternate, &before).unwrap();
        let output = child(root.path())
            .env("GIT_INDEX_FILE", &alternate)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(fs::read(&primary).unwrap(), before);
        assert_ne!(fs::read(&alternate).unwrap(), before);
        let output = child(root.path()).output().unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}

pub fn durable_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("durable file has no parent")?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "durable state path is not a regular file"
        );
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn durable_write_once(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("durable file has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if let Err(error) = temporary.persist_noclobber(path) {
        ensure!(
            error.error.kind() == std::io::ErrorKind::AlreadyExists,
            "could not preserve immutable state: {}",
            error.error
        );
        ensure!(
            read_index(path)?.as_deref() == Some(bytes),
            "immutable state differs from previously saved bytes"
        );
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationStatus {
    Prepared,
    Applied,
    InstalledButConflicted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletedApplication {
    SameIndex,
    ChangedIndex,
    AdmissionConflict,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ApplicationJournal {
    version: u8,
    application_id: String,
    status: ApplicationStatus,
    index_path: PathBuf,
    before_raw: Option<String>,
    after_raw: String,
    before_logical: String,
    after_logical: String,
    head: Option<String>,
    policy_ref: String,
    admitted_config: Option<String>,
}

pub struct IndexSession {
    pub root: PathBuf,
    pub common_dir: PathBuf,
    pub index_path: PathBuf,
    pub state_dir: PathBuf,
    _lock: fs::File,
}

pub fn repository_root(root: &Path) -> Result<PathBuf> {
    let output = git(root, &["rev-parse", "--show-toplevel"])?;
    let text = std::str::from_utf8(&output)?;
    Ok(fs::canonicalize(text.strip_suffix('\n').unwrap_or(text))?)
}

pub fn common_dir(root: &Path) -> Result<PathBuf> {
    let output = git(
        root,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    let text = std::str::from_utf8(&output)?;
    Ok(fs::canonicalize(text.strip_suffix('\n').unwrap_or(text))?)
}

impl IndexSession {
    pub fn open(root: &Path) -> Result<Self> {
        let root = repository_root(root)?;
        let index_path = index_path(&root)?;
        let common_dir = common_dir(&root)?;
        let identity = serde_json::to_vec(&(&common_dir, &root, &index_path))?;
        let parent = common_dir.join("ai-cleanroom");
        let state_dir = parent.join(crate::policy::sha256(&identity));
        for path in [&parent, &state_dir] {
            match fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error).context("creating index journal directory"),
            }
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "journal directory is not a real directory"
            );
        }
        let lock_path = state_dir.join("session.lock");
        if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
            ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "journal lock is not a regular file"
            );
        }
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock()
            .context("another resolver holds this index journal")?;
        Ok(Self {
            root,
            common_dir,
            index_path,
            state_dir,
            _lock: lock,
        })
    }

    pub fn validate_supported(&self, snapshot: &Snapshot) -> Result<()> {
        ensure!(
            snapshot.root == self.root,
            "snapshot belongs to a different worktree"
        );
        ensure!(
            snapshot
                .files
                .values()
                .all(|blob| matches!(blob.mode.as_str(), "100644" | "100755")),
            "automatic application requires regular Git blobs only"
        );
        let sparse = git_output(&self.root, &["config", "--bool", "core.sparseCheckout"])?;
        ensure!(
            sparse.status.code() == Some(1)
                || (sparse.status.success() && sparse.stdout == b"false\n"),
            "sparse indexes/worktrees are unsupported for automatic application"
        );
        let split = git(&self.root, &["rev-parse", "--shared-index-path"])?;
        ensure!(
            split.iter().all(u8::is_ascii_whitespace),
            "split indexes are unsupported for automatic application"
        );
        if let Some(bytes) = read_index(&self.index_path)? {
            ensure!(
                bytes.len() >= 12
                    && &bytes[..4] == b"DIRC"
                    && u32::from_be_bytes(bytes[4..8].try_into()?) == 2,
                "automatic application supports ordinary version-2 indexes only; extended flags and compressed indexes are unsupported"
            );
        }
        let flags = git(&self.root, &["ls-files", "-v", "-z"])?;
        ensure!(
            flags
                .split(|byte| *byte == 0)
                .filter(|entry| !entry.is_empty())
                .all(|entry| entry.starts_with(b"H ")),
            "assume-unchanged and skip-worktree index entries are unsupported"
        );
        snapshot.verify_unchanged()
    }

    pub fn recover(&self) -> Result<Option<ApplicationStatus>> {
        self.recover_journal(None)
    }

    pub fn recover_application(&self, expected_id: &str) -> Result<Option<ApplicationStatus>> {
        self.recover_journal(Some(expected_id))
    }

    fn read_journal(&self, path: &Path) -> Result<Option<ApplicationJournal>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_index(path)?.context("application journal disappeared")?;
        let journal: ApplicationJournal =
            serde_json::from_slice(&bytes).context("invalid application journal")?;
        ensure!(
            journal.version == 1 && journal.index_path == self.index_path,
            "application journal identity mismatch"
        );
        Ok(Some(journal))
    }

    fn receipt_path(&self, id: &str) -> Result<PathBuf> {
        ensure!(
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid application identity"
        );
        Ok(self.state_dir.join(format!("applied-{id}.json")))
    }

    fn receipt(&self, id: &str) -> Result<Option<ApplicationJournal>> {
        let receipt = self.read_journal(&self.receipt_path(id)?)?;
        if let Some(receipt) = &receipt {
            ensure!(
                receipt.application_id == id && receipt.status == ApplicationStatus::Applied,
                "completed application receipt identity or status mismatch"
            );
        }
        Ok(receipt)
    }

    pub fn completed_application(
        &self,
        id: &str,
        current: &Snapshot,
    ) -> Result<Option<CompletedApplication>> {
        let Some(receipt) = self.receipt(id)? else {
            return Ok(None);
        };
        ensure!(
            current.root == self.root,
            "snapshot belongs to a different worktree"
        );
        let result = if logical_digest(&current.files) != receipt.after_logical {
            CompletedApplication::ChangedIndex
        } else if current
            .captured_admitted_config
            .as_ref()
            .context("missing staged admission identity")?
            != &receipt.admitted_config
        {
            CompletedApplication::AdmissionConflict
        } else {
            CompletedApplication::SameIndex
        };
        current.verify_unchanged()?;
        Ok(Some(result))
    }

    fn recover_journal(&self, expected_id: Option<&str>) -> Result<Option<ApplicationStatus>> {
        let mut journal = self.read_journal(&self.state_dir.join("application.json"))?;
        if let Some(id) = expected_id
            && journal.as_ref().is_none_or(|journal| {
                journal.status == ApplicationStatus::Applied && journal.application_id != id
            })
            && let Some(receipt) = self.receipt(id)?
        {
            journal = Some(receipt);
        }
        let Some(mut journal) = journal else {
            return Ok(None);
        };
        if journal.status == ApplicationStatus::Applied
            && expected_id != Some(&journal.application_id)
        {
            return Ok(None);
        }
        ensure!(
            expected_id.is_none_or(|id| id == journal.application_id),
            "pending application belongs to a different transaction"
        );
        if journal.status == ApplicationStatus::InstalledButConflicted {
            return Ok(Some(journal.status));
        }
        self.install(&mut journal)?;
        Ok(Some(journal.status))
    }

    pub fn apply(
        &self,
        original: &Snapshot,
        candidate: &Snapshot,
        policy_ref: &str,
    ) -> Result<ApplicationStatus> {
        self.validate_supported(original)?;
        ensure!(
            candidate.root == self.root && candidate.baseline.keys().eq(original.baseline.keys()),
            "candidate snapshot identity mismatch"
        );
        let pending = self.recover()?;
        ensure!(
            pending.is_none(),
            "a pending index application was reconciled; rerun resolution"
        );
        ensure!(
            candidate
                .files
                .keys()
                .all(|path| validate_path(path).is_ok())
                && original
                    .files
                    .keys()
                    .all(|path| candidate.files.contains_key(path)),
            "automatic application cannot delete index entries"
        );
        let (expected_path, before) = original
            .captured_raw_index
            .as_ref()
            .context("application requires a staged snapshot")?;
        ensure!(*expected_path == self.index_path, "active index changed");
        let temporary = tempfile::tempdir_in(&self.state_dir)?;
        let prepared = temporary.path().join("index");
        if let Some(bytes) = before {
            fs::write(&prepared, bytes)?;
        } else {
            git_input(&self.root, &["read-tree", "--empty"], b"", Some(&prepared))?;
        }
        let mut entries = Vec::new();
        for (path, blob) in &candidate.files {
            ensure!(
                matches!(blob.mode.as_str(), "100644" | "100755"),
                "candidate must contain regular Git blobs"
            );
            if original
                .files
                .get(path)
                .is_some_and(|old| old.oid == blob.oid && old.mode == blob.mode)
            {
                continue;
            }
            entries.extend_from_slice(format!("{} {}\t{}\0", blob.mode, blob.oid, path).as_bytes());
        }
        git_input(
            &self.root,
            &["update-index", "-z", "--index-info"],
            &entries,
            Some(&prepared),
        )?;
        let prepared_entries = git_input(
            &self.root,
            &["ls-files", "--stage", "-z"],
            b"",
            Some(&prepared),
        )?;
        ensure!(
            logical_digest(&load_entries(&self.root, &prepared_entries, true)?)
                == logical_digest(&candidate.files),
            "prepared index differs from the assessed candidate; refusing implicit path deletion"
        );
        let after = fs::read(&prepared)?;
        let mut journal = ApplicationJournal {
            version: 1,
            application_id: Self::application_identity(original, candidate, policy_ref)?,
            status: ApplicationStatus::Prepared,
            index_path: self.index_path.clone(),
            before_raw: digest(before),
            after_raw: crate::policy::sha256(&after),
            before_logical: logical_digest(&original.files),
            after_logical: logical_digest(&candidate.files),
            head: original
                .captured_head
                .clone()
                .context("missing staged HEAD identity")?,
            policy_ref: policy_ref.into(),
            admitted_config: original
                .captured_admitted_config
                .clone()
                .context("missing staged admission identity")?,
        };
        original.verify_unchanged()?;
        durable_write(&self.state_dir.join("prepared.index"), &after)?;
        self.save_journal(&journal)?;
        #[cfg(test)]
        tests::crash_at("prepared");
        self.install(&mut journal)?;
        Ok(journal.status)
    }

    pub fn application_identity(
        original: &Snapshot,
        candidate: &Snapshot,
        policy_ref: &str,
    ) -> Result<String> {
        Ok(crate::policy::sha256(&serde_json::to_vec(&(
            original.staged_identity()?,
            logical_digest(&candidate.files),
            policy_ref,
            original
                .captured_admitted_config
                .as_ref()
                .context("missing staged admission identity")?,
        ))?))
    }

    fn save_journal(&self, journal: &ApplicationJournal) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(journal)?;
        if journal.status == ApplicationStatus::Applied {
            durable_write_once(&self.receipt_path(&journal.application_id)?, &bytes)?;
        }
        durable_write(&self.state_dir.join("application.json"), &bytes)
    }

    fn refs_match(&self, journal: &ApplicationJournal) -> Result<bool> {
        let reference = format!("{}^{{commit}}", journal.policy_ref);
        let output = git_output(
            &self.root,
            &["rev-parse", "--verify", "--end-of-options", &reference],
        )?;
        Ok(head_oid(&self.root)? == journal.head
            && admitted_config(&self.root)? == journal.admitted_config
            && output.status.success()
            && std::str::from_utf8(&output.stdout)?.trim() == journal.policy_ref)
    }

    fn install(&self, journal: &mut ApplicationJournal) -> Result<()> {
        let mut lock_name = self.index_path.as_os_str().to_owned();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        let mut lock = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .context("Git index lock already exists or cannot be created")?;
        let mut renamed = false;
        let result = (|| {
            let actual = read_index(&self.index_path)?;
            let actual_digest = digest(&actual);
            if actual_digest.as_deref() == Some(&journal.after_raw) {
                fs::File::open(self.index_path.parent().unwrap())?.sync_all()?;
                journal.status = if self.refs_match(journal)? {
                    ApplicationStatus::Applied
                } else {
                    ApplicationStatus::InstalledButConflicted
                };
                return self.save_journal(journal);
            }
            ensure!(
                journal.status == ApplicationStatus::Prepared,
                "completed application index changed; refusing to reinstall"
            );
            ensure!(
                actual_digest == journal.before_raw,
                "index differs from both prepared transaction states; refusing overwrite"
            );
            ensure!(
                self.refs_match(journal)?,
                "HEAD or admitted policy changed before index installation"
            );
            let prepared = fs::read(self.state_dir.join("prepared.index"))?;
            ensure!(
                crate::policy::sha256(&prepared) == journal.after_raw,
                "prepared index bytes changed"
            );
            lock.write_all(&prepared)?;
            lock.sync_all()?;
            fs::rename(&lock_path, &self.index_path)?;
            renamed = true;
            #[cfg(test)]
            tests::crash_at("rename");
            fs::File::open(self.index_path.parent().unwrap())?.sync_all()?;
            journal.status = if self.refs_match(journal)? {
                ApplicationStatus::Applied
            } else {
                ApplicationStatus::InstalledButConflicted
            };
            self.save_journal(journal)?;
            #[cfg(test)]
            tests::crash_at("terminal");
            Ok(())
        })();
        drop(lock);
        if !renamed {
            fs::remove_file(&lock_path).context("removing this transaction's index lock")?;
        }
        result
    }
}
