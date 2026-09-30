use crate::{
    git::{Scope, Snapshot},
    notices,
    policy::{self, Decision, Policy},
    scanner::{Candidate, ScanResult, Scanner},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::{collections::BTreeSet, path::Path, process::Command};

#[derive(Debug, Serialize)]
pub struct Report {
    pub version: u32,
    pub policy_ref: String,
    pub policy_sha256: String,
    pub candidate_sha256: String,
    pub baseline_sha256: String,
    pub evaluation_only: bool,
    pub files: Vec<FileReport>,
    pub issues: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FileReport {
    pub path: String,
    pub status: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub candidate: Candidate,
    pub status: String,
    pub reason: String,
    pub evidence_id: Option<String>,
}

impl Report {
    pub fn passed(&self) -> bool {
        !self.evaluation_only
            && self.issues.is_empty()
            && self.files.iter().all(|file| {
                matches!(
                    file.status.as_str(),
                    "no_match" | "excluded" | "allowed" | "unchanged_matches"
                ) && file
                    .findings
                    .iter()
                    .all(|finding| finding.status == "allowed")
            })
    }
}

pub fn admitted_ref(root: &Path, explicit: Option<&str>) -> Result<String> {
    if let Some(reference) = explicit {
        ensure!(
            immutable_id(reference),
            "ordinary checks require an admitted full immutable commit ID, not a moving reference"
        );
        return Ok(reference.to_owned());
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["config", "--local", "--get", "oss-provenance.policy-ref"])
        .output()?;
    ensure!(
        output.status.success(),
        "no admitted policy; evaluate a full snapshot and configure oss-provenance.policy-ref explicitly after maintainer review"
    );
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    ensure!(!value.is_empty(), "empty admitted policy reference");
    ensure!(
        immutable_id(&value),
        "ordinary checks require an admitted full immutable commit ID, not a moving reference"
    );
    Ok(value)
}

pub fn trusted_policy(
    snapshot: &Snapshot,
    reference: &str,
    evaluation: bool,
) -> Result<(String, Vec<u8>, Policy)> {
    if !evaluation {
        ensure!(
            immutable_id(reference),
            "admitted policy must be a full immutable commit ID"
        );
    }
    let reference = snapshot.resolve_ref(reference)?;
    let kind = Command::new("git")
        .arg("-C")
        .arg(&snapshot.root)
        .args(["cat-file", "-t", &reference])
        .output()?;
    ensure!(
        kind.status.success() && kind.stdout == b"commit\n",
        "policy source must be a commit"
    );
    let bytes = snapshot
        .read_at(&reference, policy::POLICY_PATH)?
        .context("admitted reference has no policy file")?;
    let policy = Policy::parse(&bytes)?;
    if !evaluation {
        let candidate = snapshot
            .files
            .get(policy::POLICY_PATH)
            .context("candidate removed the admitted policy")?;
        ensure!(
            candidate.bytes == bytes && matches!(candidate.mode.as_str(), "100644" | "100755"),
            "candidate policy differs from admitted policy; maintenance evaluation and explicit admission required"
        );
    }
    for evidence in &policy.evidence {
        for artifact in &evidence.artifacts {
            let contents = snapshot
                .read_at(&reference, &artifact.path)?
                .with_context(|| format!("admitted grant artifact missing: {}", artifact.path))?;
            policy::verify_artifact(artifact, &contents)?;
        }
    }
    Ok((reference, bytes, policy))
}

pub fn check(
    root: &Path,
    scope: Scope,
    reference: &str,
    all: bool,
    evaluation: bool,
) -> Result<(Snapshot, Policy, Report)> {
    ensure!(
        evaluation || !matches!(scope, Scope::Full { .. }),
        "enrolled full scans require a comparison baseline"
    );
    let snapshot = Snapshot::capture(root, scope)?;
    let (reference, bytes, policy) = trusted_policy(&snapshot, reference, evaluation)?;
    ensure!(
        policy.scanner.enabled,
        "fingerprint transmission is disabled by admitted policy"
    );
    let scanner = Scanner::new(&policy.scanner.endpoint, policy.scanner.timeout_secs)?;
    let report = assess(
        &snapshot,
        &policy,
        &reference,
        &bytes,
        all,
        evaluation,
        |path, bytes| scanner.scan(path, bytes),
        |evidence| crate::evidence::verify_source(evidence, policy.scanner.timeout_secs),
    )?;
    snapshot.verify_unchanged()?;
    Ok((snapshot, policy, report))
}

#[allow(clippy::too_many_arguments)]
pub fn assess(
    snapshot: &Snapshot,
    policy: &Policy,
    reference: &str,
    policy_bytes: &[u8],
    all: bool,
    evaluation: bool,
    mut scan: impl FnMut(&str, &[u8]) -> Result<ScanResult>,
    mut source: impl FnMut(&policy::Evidence) -> Result<Vec<u8>>,
) -> Result<Report> {
    let mut report = Report {
        version: 1,
        policy_ref: reference.into(),
        policy_sha256: policy::sha256(policy_bytes),
        candidate_sha256: tree_digest(&snapshot.files),
        baseline_sha256: tree_digest(&snapshot.baseline),
        evaluation_only: evaluation,
        files: Vec::new(),
        issues: notices::validate(snapshot, policy)?,
    };
    let manifest = notices::load(&snapshot.files)?;
    let mut paths: BTreeSet<String> = snapshot.added.keys().cloned().collect();
    for (path, blob) in &snapshot.files {
        if all
            || !snapshot.baseline.contains_key(path)
            || snapshot
                .baseline
                .get(path)
                .is_some_and(|old| old.oid != blob.oid || old.mode != blob.mode)
        {
            paths.insert(path.clone());
        }
    }
    for path in paths {
        let blob = &snapshot.files[&path];
        let mut file = FileReport {
            path: path.clone(),
            status: "unresolved".into(),
            findings: Vec::new(),
        };
        if policy.excluded(&path) {
            file.status = "excluded".into();
            report.files.push(file);
            continue;
        }
        if !matches!(blob.mode.as_str(), "100644" | "100755")
            || std::str::from_utf8(&blob.bytes).is_err()
            || blob.bytes.contains(&0)
        {
            report.issues.push(format!(
                "{path}: unsupported mode or non-text content; explicitly review coverage policy"
            ));
            report.files.push(file);
            continue;
        }
        let result = scan(&path, &blob.bytes).with_context(|| format!("scanning {path}"))?;
        if !result.fingerprintable {
            report.issues.push(format!(
                "{path}: insufficient meaningful fingerprints; not a negative search result"
            ));
        }
        let has_matches = !result.candidates.is_empty();
        for candidate in result.candidates {
            let in_scope = all
                || candidate.local_ranges.iter().any(|(start, end)| {
                    snapshot.added.get(&path).is_some_and(|ranges| {
                        ranges
                            .iter()
                            .any(|range| *start <= range.end && *end >= range.start)
                    })
                });
            if !in_scope {
                continue;
            }
            let mut finding = Finding { candidate, status: "unresolved".into(), reason: "source licensing requires immutable, admitted evidence; scanner license labels alone do not grant permission".into(), evidence_id: None };
            if let Some(evidence) = finding
                .candidate
                .file_hash
                .as_deref()
                .and_then(|hash| policy.evidence_for(hash))
            {
                if finding.candidate.url.as_deref() != Some(evidence.repository.as_str())
                    || finding.candidate.file.as_deref() != Some(evidence.path.as_str())
                {
                    finding.reason =
                        "matched source identity conflicts with admitted evidence".into();
                } else {
                    let upstream = source(evidence)?;
                    ensure!(
                        policy::sha256(&upstream) == evidence.source_sha256
                            && format!("{:x}", md5::Md5::digest(&upstream)) == evidence.file_md5,
                        "admitted source hashes differ from verified bytes"
                    );
                    if !corresponds(&blob.bytes, &upstream, &finding.candidate) {
                        finding.reason="local/upstream content correspondence is unsupported or differs from verified source".into();
                        file.findings.push(finding);
                        continue;
                    }
                    let id = notices::evidence_id(evidence)?;
                    finding.evidence_id = Some(id.clone());
                    match policy.decide(evidence)? {
                        Decision::Allowed => {
                            let recorded = manifest.entries.iter().find(|entry| entry.id == id);
                            let covered =
                                finding.candidate.local_ranges.iter().all(|(start, end)| {
                                    recorded.is_some_and(|entry| {
                                        entry.uses.iter().any(|usage| {
                                            usage.path == path
                                                && notices::covers_usage(
                                                    &blob.bytes,
                                                    usage,
                                                    *start,
                                                    *end,
                                                )
                                        })
                                    })
                                });
                            if covered {
                                finding.status = "allowed".into();
                                finding.reason = "admitted evidence and reuse notice present; artifact integrity checked separately".into();
                            } else {
                                finding.status = "notice_required".into();
                                finding.reason = "policy allows reuse; run resolve to record this use and its required artifacts".into();
                            }
                        }
                        Decision::Blocked(reason) => {
                            finding.status = "blocked".into();
                            finding.reason = reason;
                        }
                        Decision::Unresolved(reason) => {
                            finding.reason = reason;
                        }
                    }
                }
            }
            file.findings.push(finding);
        }
        if result.fingerprintable {
            file.status = if file.findings.is_empty() {
                if has_matches {
                    "unchanged_matches"
                } else {
                    "no_match"
                }
            } else if file
                .findings
                .iter()
                .all(|finding| finding.status == "allowed")
            {
                "allowed"
            } else {
                "unresolved"
            }
            .into();
        }
        report.files.push(file);
    }
    snapshot.verify_unchanged()?;
    Ok(report)
}

use md5::Digest;

fn immutable_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn tree_digest(files: &std::collections::BTreeMap<String, crate::git::Blob>) -> String {
    let mut digest = sha2::Sha256::new();
    for (path, blob) in files {
        for field in [
            path.as_bytes(),
            blob.mode.as_bytes(),
            blob.oid.as_bytes(),
            blob.bytes.as_slice(),
        ] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
    }
    format!("{:x}", digest.finalize())
}

fn corresponds(local: &[u8], upstream: &[u8], candidate: &Candidate) -> bool {
    if candidate.id == "file" {
        return local == upstream;
    }
    if candidate.local_ranges.len() != candidate.upstream_ranges.len() {
        return false;
    }
    candidate
        .local_ranges
        .iter()
        .zip(&candidate.upstream_ranges)
        .all(|(local_range, upstream_range)| {
            match (range(local, *local_range), range(upstream, *upstream_range)) {
                (Some(left), Some(right)) => !left.is_empty() && left == right,
                _ => false,
            }
        })
}

fn range(bytes: &[u8], (start, end): (usize, usize)) -> Option<Vec<u8>> {
    let lines: Vec<_> = bytes.split_inclusive(|b| *b == b'\n').collect();
    if start == 0 || end < start || end > lines.len() {
        return None;
    }
    Some(
        lines[start - 1..end]
            .concat()
            .into_iter()
            .filter(|b| b.is_ascii_alphanumeric())
            .map(|b| b.to_ascii_lowercase())
            .collect(),
    )
}

pub fn ensure_resolvable(report: &Report) -> Result<()> {
    if report
        .files
        .iter()
        .flat_map(|file| &file.findings)
        .any(|finding| !matches!(finding.status.as_str(), "allowed" | "notice_required"))
    {
        bail!(
            "unresolved or blocked matches require source evidence review or an isolated rewrite; no code was changed"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn symbolic_admission_is_rejected_before_scanning() {
        for value in ["HEAD", "main", "HEAD~1", ""] {
            assert!(admitted_ref(Path::new("."), Some(value)).is_err());
        }
    }
    #[test]
    fn correspondence_requires_real_content() {
        let candidate = Candidate {
            id: "snippet".into(),
            local_ranges: vec![(1, 1)],
            upstream_ranges: vec![(1, 1)],
            url: None,
            file: None,
            file_hash: None,
            licenses: vec![],
            raw: serde_json::json!({}),
        };
        assert!(corresponds(
            b"int result = 1;\n",
            b"int result=1;\n",
            &candidate
        ));
        assert!(!corresponds(
            b"unrelated implementation\n",
            b"int result=1;\n",
            &candidate
        ));
        assert!(!corresponds(b"\n", b"", &candidate));
        assert!(!corresponds(b"!!!\n", b"...\n", &candidate));
        assert!(!corresponds(
            "你好\n".as_bytes(),
            "世界\n".as_bytes(),
            &candidate
        ));
    }
    #[test]
    fn snapshot_identity_includes_gitlink_commit() {
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            "module".into(),
            crate::git::Blob {
                mode: "160000".into(),
                oid: "a".repeat(40),
                bytes: Vec::new(),
            },
        );
        let before = tree_digest(&files);
        files.get_mut("module").unwrap().oid = "b".repeat(40);
        assert_ne!(before, tree_digest(&files));
    }
}
