use crate::git::{Blob, Snapshot};
use crate::policy::{Decision, Evidence, Obligations, Policy, safe_path, sha256, verify_artifact};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MANIFEST_PATH: &str = "LICENSE-NOTICES/manifest.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub evidence: Evidence,
    pub uses: Vec<Usage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub path: String,
    pub start: usize,
    pub end: usize,
    pub snippet_sha256: String,
    pub description: String,
    #[serde(default)]
    pub retired: bool,
}

pub fn evidence_id(evidence: &Evidence) -> Result<String> {
    Ok(sha256(&serde_json::to_vec(evidence)?))
}

pub fn load(files: &BTreeMap<String, Blob>) -> Result<Manifest> {
    let Some(blob) = files.get(MANIFEST_PATH) else {
        return Ok(Manifest {
            version: 1,
            entries: Vec::new(),
        });
    };
    ensure!(regular(blob), "notice manifest must be a regular file");
    let manifest = serde_json::from_slice(&blob.bytes).context("invalid notice manifest JSON")?;
    check_structure(&manifest)?;
    Ok(manifest)
}

fn check_structure(manifest: &Manifest) -> Result<()> {
    ensure!(manifest.version == 1, "unsupported notice manifest version");
    let mut ids = BTreeSet::new();
    for entry in &manifest.entries {
        ensure!(
            entry.id == evidence_id(&entry.evidence)?,
            "notice evidence identity differs: {}",
            entry.id
        );
        ensure!(
            ids.insert(&entry.id),
            "duplicate notice entry: {}",
            entry.id
        );
        ensure!(
            !entry.uses.is_empty(),
            "notice entry has no recorded uses: {}",
            entry.id
        );
        for artifact in &entry.evidence.artifacts {
            safe_path(&artifact.path)?;
            ensure!(
                artifact.path.starts_with("LICENSE-NOTICES/"),
                "notice artifact outside LICENSE-NOTICES"
            );
        }
        let mut uses = BTreeSet::new();
        for usage in &entry.uses {
            safe_path(&usage.path)?;
            ensure!(
                usage.start > 0 && usage.end >= usage.start,
                "invalid notice line range: {}",
                usage.path
            );
            ensure!(
                usage.snippet_sha256.len() == 64
                    && usage
                        .snippet_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid notice snippet hash: {}",
                usage.path
            );
            ensure!(
                uses.insert((&usage.path, &usage.snippet_sha256)),
                "duplicate notice use: {}",
                usage.path
            );
        }
    }
    Ok(())
}

pub fn validate(snapshot: &Snapshot, policy: &Policy) -> Result<Vec<String>> {
    let baseline = load(&snapshot.baseline).context("baseline notices")?;
    let manifest = load(&snapshot.files).context("candidate notices")?;
    let mut issues = Vec::new();
    if snapshot.baseline.contains_key(MANIFEST_PATH) && !snapshot.files.contains_key(MANIFEST_PATH)
    {
        issues.push("notice manifest was removed".into());
    }
    for old in &baseline.entries {
        let Some(current) = manifest.entries.iter().find(|entry| entry.id == old.id) else {
            issues.push(format!("historical notice entry was removed: {}", old.id));
            continue;
        };
        for usage in &old.uses {
            if !current.uses.iter().any(|u| {
                u.path == usage.path
                    && u.snippet_sha256 == usage.snippet_sha256
                    && u.end - u.start == usage.end - usage.start
            }) {
                issues.push(format!(
                    "historical notice use was removed or changed: {} ({})",
                    usage.path, old.id
                ));
            }
        }
    }
    check_readmes(&baseline, &snapshot.baseline, "baseline", &mut issues)?;
    check_readmes(&manifest, &snapshot.files, "candidate", &mut issues)?;
    for entry in &manifest.entries {
        if entry.uses.iter().any(|usage| !usage.retired) {
            if !policy
                .evidence
                .iter()
                .any(|evidence| evidence == &entry.evidence)
            {
                issues.push(format!(
                    "notice evidence is not admitted by policy: {}",
                    entry.id
                ));
            }
            match policy.decide(&entry.evidence)? {
                Decision::Allowed => {}
                Decision::Blocked(reason) => issues.push(format!(
                    "active notice is blocked by current policy: {}: {reason}",
                    entry.id
                )),
                Decision::Unresolved(reason) => issues.push(format!(
                    "active notice is unresolved under current policy: {}: {reason}",
                    entry.id
                )),
            }
        }
        for artifact in &entry.evidence.artifacts {
            match snapshot.files.get(&artifact.path) {
                Some(blob) if regular(blob) => {
                    if let Err(error) = verify_artifact(artifact, &blob.bytes) {
                        issues.push(error.to_string());
                    }
                }
                _ => issues.push(format!(
                    "missing regular notice artifact: {}",
                    artifact.path
                )),
            }
        }
        for usage in &entry.uses {
            let retirement = retirement_admitted(policy, &entry.id, usage);
            if usage.retired {
                if !retirement {
                    issues.push(format!(
                        "notice retirement is not admitted by policy: {} ({})",
                        usage.path, entry.id
                    ));
                }
                if snapshot
                    .files
                    .get(&usage.path)
                    .is_some_and(|blob| regular(blob) && contains_snippet(&blob.bytes, usage))
                {
                    issues.push(format!(
                        "retired notice snippet is still present: {} ({})",
                        usage.path, entry.id
                    ));
                }
                continue;
            }
            if retirement {
                issues.push(format!(
                    "admitted notice retirement has not been recorded in the manifest: {} ({})",
                    usage.path, entry.id
                ));
            }
            match snapshot.files.get(&usage.path) {
                Some(blob) if regular(blob) => {
                    if let Obligations::SourcePrefix { text } = &entry.evidence.obligations
                        && !blob.bytes.starts_with(text.as_bytes())
                    {
                        issues.push(format!(
                            "required source prefix is missing or changed: {} ({})",
                            usage.path, entry.id
                        ));
                    }
                    if !contains_snippet(&blob.bytes, usage) {
                        issues.push(format!(
                            "recorded notice snippet is missing or changed: {}:{}-{}",
                            usage.path, usage.start, usage.end
                        ));
                    }
                }
                _ => issues.push(format!(
                    "recorded notice use is missing or not a regular file: {}",
                    usage.path
                )),
            }
        }
    }
    Ok(issues)
}

fn regular(blob: &Blob) -> bool {
    matches!(blob.mode.as_str(), "100644" | "100755")
}

fn line_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offsets = vec![0];
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        offsets.push(offsets.last().unwrap() + line.len());
    }
    offsets
}

fn contains_snippet(bytes: &[u8], usage: &Usage) -> bool {
    let offsets = line_offsets(bytes);
    let span = usage.end - usage.start + 1;
    if span >= offsets.len() {
        return false;
    }
    (0..offsets.len() - span)
        .any(|start| sha256(&bytes[offsets[start]..offsets[start + span]]) == usage.snippet_sha256)
}

pub fn covers_usage(bytes: &[u8], usage: &Usage, start: usize, end: usize) -> bool {
    if usage.retired || start == 0 || end < start || usage.start == 0 || usage.end < usage.start {
        return false;
    }
    let offsets = line_offsets(bytes);
    let span = usage.end - usage.start + 1;
    if span >= offsets.len() || end >= offsets.len() {
        return false;
    }
    (0..offsets.len() - span).any(|offset| {
        offset < start
            && offset + span >= end
            && sha256(&bytes[offsets[offset]..offsets[offset + span]]) == usage.snippet_sha256
    })
}

fn retirement_admitted(policy: &Policy, id: &str, usage: &Usage) -> bool {
    policy.retirements.iter().any(|retirement| {
        retirement.evidence_id == id
            && retirement.path == usage.path
            && retirement.snippet_sha256 == usage.snippet_sha256
            && !retirement.reason.trim().is_empty()
    })
}

pub fn reconcile_retirements(manifest: &mut Manifest, policy: &Policy) {
    for entry in &mut manifest.entries {
        for usage in &mut entry.uses {
            if retirement_admitted(policy, &entry.id, usage) {
                usage.retired = true;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn upsert(
    manifest: &mut Manifest,
    evidence: &Evidence,
    path: &str,
    start: usize,
    end: usize,
    bytes: &[u8],
    description: &str,
) -> Result<()> {
    check_structure(manifest)?;
    safe_path(path)?;
    let offsets = line_offsets(bytes);
    ensure!(
        start > 0 && end >= start && end < offsets.len(),
        "notice line range is outside {path}"
    );
    let snippet_sha256 = sha256(&bytes[offsets[start - 1]..offsets[end]]);
    let id = evidence_id(evidence)?;
    let entry = match manifest.entries.iter().position(|entry| entry.id == id) {
        Some(index) => &mut manifest.entries[index],
        None => {
            manifest.entries.push(Entry {
                id,
                evidence: evidence.clone(),
                uses: Vec::new(),
            });
            manifest.entries.last_mut().unwrap()
        }
    };
    if let Some(usage) = entry
        .uses
        .iter_mut()
        .find(|usage| usage.path == path && usage.snippet_sha256 == snippet_sha256)
    {
        ensure!(
            !usage.retired,
            "previously retired notice use requires explicit review before reuse: {path}"
        );
        usage.start = start;
        usage.end = end;
    } else {
        entry.uses.push(Usage {
            path: path.into(),
            start,
            end,
            snippet_sha256,
            description: description.into(),
            retired: false,
        });
    }
    entry.uses.sort_by(|a, b| {
        (&a.path, a.start, a.end, &a.snippet_sha256).cmp(&(
            &b.path,
            b.start,
            b.end,
            &b.snippet_sha256,
        ))
    });
    manifest.entries.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(())
}

pub fn proposed_files(manifest: &Manifest) -> Result<BTreeMap<String, Vec<u8>>> {
    check_structure(manifest)?;
    let mut files = BTreeMap::new();
    let mut json = serde_json::to_vec_pretty(manifest)?;
    json.push(b'\n');
    files.insert(MANIFEST_PATH.into(), json);
    for entry in &manifest.entries {
        files.insert(readme_path(entry), render_readme(entry).into_bytes());
    }
    for entry in &manifest.entries {
        for artifact in &entry.evidence.artifacts {
            ensure!(
                !files.contains_key(&artifact.path),
                "evidence artifact collides with generated notice: {}",
                artifact.path
            );
        }
    }
    Ok(files)
}

fn readme_path(entry: &Entry) -> String {
    format!("LICENSE-NOTICES/{}/README.md", entry.id)
}

fn render_readme(entry: &Entry) -> String {
    let evidence = &entry.evidence;
    let mut text = format!(
        "# Third-party source notice\n\nSource repository: {}\n\nImmutable revision: {}\n\nUpstream path: {}\n\nSource SHA-256: {}\n\nUpstream license expression: {}\n\nSelected license: {}\n\nReview of applicability and obligations:\n\n{}\n\n## Preserved license and notice artifacts\n\n",
        evidence.repository,
        evidence.revision,
        evidence.path,
        evidence.source_sha256,
        evidence.license,
        evidence.selected_license,
        evidence.review
    );
    for artifact in &evidence.artifacts {
        text.push_str(&format!(
            "- {} (SHA-256: {})\n",
            artifact.path, artifact.sha256
        ));
    }
    text.push_str("\n## Uses in this project\n\n");
    for usage in &entry.uses {
        text.push_str(&format!(
            "### {}:{}-{}\n\nSnippet SHA-256: {}\n\n{}\n\n",
            usage.path, usage.start, usage.end, usage.snippet_sha256, usage.description
        ));
        if usage.retired {
            text.push_str(
                "Status: retired under an explicit policy record; attribution retained.\n\n",
            );
        }
    }
    text
}

fn check_readmes(
    manifest: &Manifest,
    files: &BTreeMap<String, Blob>,
    scope: &str,
    issues: &mut Vec<String>,
) -> Result<()> {
    for (path, expected) in proposed_files(manifest)? {
        if path == MANIFEST_PATH {
            continue;
        }
        match files.get(&path) {
            Some(blob) if regular(blob) && blob.bytes == expected => {}
            _ => issues.push(format!("{scope} notice README is missing or differs from its manifest: {path}; preserve human descriptions in the manifest")),
        }
    }
    Ok(())
}

pub fn validate_existing_readmes(files: &BTreeMap<String, Blob>) -> Result<Vec<String>> {
    let manifest = load(files)?;
    let mut issues = Vec::new();
    for (path, expected) in proposed_files(&manifest)? {
        if path == MANIFEST_PATH {
            continue;
        }
        if let Some(blob) = files.get(&path)
            && (!regular(blob) || blob.bytes != expected)
        {
            issues.push(format!("existing notice README differs from its manifest: {path}; preserve human descriptions in the manifest"));
        }
    }
    Ok(issues)
}
