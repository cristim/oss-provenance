use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

pub struct Snapshot {
    pub root: PathBuf,
    pub baseline: BTreeMap<String, Blob>,
    pub files: BTreeMap<String, Blob>,
    pub added: BTreeMap<String, Vec<LineRange>>,
    captured_refs: Vec<(String, String)>,
    captured_index: Option<Vec<u8>>,
    captured_head: Option<Option<String>>,
}

impl Snapshot {
    pub fn capture(root: &Path, scope: Scope) -> Result<Self> {
        let root_output = git(root, &["rev-parse", "--show-toplevel"])?;
        let root_text =
            std::str::from_utf8(&root_output).context("repository root is not UTF-8")?;
        let root = PathBuf::from(root_text.strip_suffix('\n').unwrap_or(root_text));
        let mut snapshot = Self {
            root,
            baseline: BTreeMap::new(),
            files: BTreeMap::new(),
            added: BTreeMap::new(),
            captured_refs: Vec::new(),
            captured_index: None,
            captured_head: None,
        };
        let all = match scope {
            Scope::Staged { all } => {
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
        if let Some(expected) = &self.captured_head {
            ensure!(
                head_oid(&self.root)? == *expected,
                "HEAD changed during scan"
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
}

fn git_output(root: &Path, args: &[&str]) -> Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
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
