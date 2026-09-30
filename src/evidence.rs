use crate::policy::{self, Artifact, Evidence, Obligations};
use crate::scanner::Candidate;
use anyhow::{Context, Result, ensure};
use md5::{Digest, Md5};
use reqwest::{Url, blocking::Client};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::{Duration, Instant};

const MAX_RESPONSE: u64 = 8 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 64;
const MAX_TOTAL: usize = 32 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub evidence: Option<Evidence>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub issues: Vec<String>,
}

struct Identity {
    owner: String,
    repo: String,
    path: String,
    version: String,
    md5: String,
}

impl Identity {
    fn parse(candidate: &Candidate) -> Result<Self> {
        let raw_url = candidate.url.as_deref().context("missing repository URL")?;
        let path = candidate.file.as_deref().context("missing upstream path")?;
        let version = candidate
            .raw
            .get("version")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .context("missing upstream version or commit")?;
        let md5 = candidate
            .file_hash
            .as_deref()
            .context("missing upstream file MD5")?;
        Self::new(raw_url, path, version, md5)
    }

    fn new(raw_url: &str, path: &str, version: &str, md5: &str) -> Result<Self> {
        let url = Url::parse(raw_url).context("invalid repository URL")?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == Some("github.com")
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "only public HTTPS github.com repository URLs are supported"
        );
        let parts: Vec<_> = url
            .path()
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .collect();
        ensure!(
            parts.len() == 2,
            "repository URL must identify owner/repository"
        );
        let repo = parts[1].strip_suffix(".git").unwrap_or(parts[1]);
        for part in [parts[0], repo] {
            ensure!(
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "unsupported GitHub repository name"
            );
        }
        policy::safe_path(path)?;
        ensure!(
            version.len() <= 256 && !version.chars().any(char::is_control),
            "invalid upstream version"
        );
        ensure!(hex_hash(md5, 32), "invalid upstream file MD5");
        Ok(Self {
            owner: parts[0].into(),
            repo: repo.into(),
            path: path.into(),
            version: version.into(),
            md5: md5.into(),
        })
    }

    fn url(&self, host: &str, rest: &[&str]) -> Result<Url> {
        let mut url = Url::parse(&format!("https://{host}"))?;
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid fixed host"))?;
        if host == "api.github.com" {
            segments.push("repos");
        }
        segments.extend([self.owner.as_str(), self.repo.as_str()]);
        segments.extend(rest);
        drop(segments);
        Ok(url)
    }
}

fn hex_hash(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Download {
    client: Client,
    deadline: Instant,
    total: usize,
}

impl Download {
    fn new(timeout_secs: u64) -> Result<Self> {
        ensure!(
            (1..=300).contains(&timeout_secs),
            "evidence timeout must be 1..300 seconds"
        );
        Ok(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("oss-provenance/", env!("CARGO_PKG_VERSION")))
                .build()?,
            deadline: Instant::now() + Duration::from_secs(timeout_secs),
            total: 0,
        })
    }

    fn get(&mut self, url: Url) -> Result<Vec<u8>> {
        ensure!(
            url.scheme() == "https"
                && matches!(
                    url.host_str(),
                    Some("api.github.com" | "raw.githubusercontent.com")
                ),
            "unsupported download host"
        );
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .context("evidence collection timed out")?;
        let response = self
            .client
            .get(url)
            .timeout(remaining)
            .send()
            .context("upstream evidence request failed")?;
        ensure!(
            response.status().is_success(),
            "upstream evidence returned HTTP {}",
            response.status()
        );
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .context("reading upstream evidence")?;
        ensure!(
            bytes.len() as u64 <= MAX_RESPONSE,
            "upstream response exceeds 8 MiB"
        );
        self.total += bytes.len();
        ensure!(
            self.total <= MAX_TOTAL,
            "evidence collection exceeds 32 MiB"
        );
        Ok(bytes)
    }
}

#[derive(Deserialize)]
struct Commit {
    sha: String,
    commit: CommitObject,
}
#[derive(Deserialize)]
struct CommitObject {
    tree: ObjectId,
}
#[derive(Deserialize)]
struct ObjectId {
    sha: String,
}
#[derive(Deserialize)]
struct Tree {
    sha: String,
    truncated: bool,
    tree: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    path: String,
    mode: String,
    #[serde(rename = "type")]
    kind: String,
}

fn applicable(path: &str, source: &str) -> bool {
    if path == format!("{source}.license") {
        return true;
    }
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    let source_parent = source.rsplit_once('/').map_or("", |(parent, _)| parent);
    let ancestor = parent.is_empty()
        || parent == source_parent
        || source_parent.starts_with(&format!("{parent}/"));
    let upper = name.to_ascii_uppercase();
    let notice = [
        "LICENSE",
        "LICENCE",
        "COPYING",
        "NOTICE",
        "COPYRIGHT",
        "AUTHORS",
    ]
    .iter()
    .any(|base| {
        upper == *base
            || upper.starts_with(&format!("{base}."))
            || upper.starts_with(&format!("{base}-"))
    });
    (ancestor && notice) || path.starts_with("LICENSES/")
}

fn source_expression(source: &[u8]) -> Result<Option<String>> {
    let source =
        std::str::from_utf8(source).context("source is not UTF-8; grant review required")?;
    let mut expressions = BTreeSet::new();
    for line in source.lines().take(100) {
        let line = line
            .trim()
            .trim_start_matches(['#', '/', '*', ';', '!', '<', '-'])
            .trim();
        if let Some(value) = line.strip_prefix("SPDX-License-Identifier:") {
            let value = value
                .trim()
                .trim_end_matches("*/")
                .trim_end_matches("-->")
                .trim();
            spdx::Expression::parse(value).context("invalid source SPDX identifier")?;
            expressions.insert(value.to_owned());
        }
    }
    ensure!(
        expressions.len() <= 1,
        "conflicting source SPDX identifiers require review"
    );
    Ok(expressions.into_iter().next())
}

fn verify_source_md5(bytes: &[u8], expected: &str) -> Result<()> {
    ensure!(
        format!("{:x}", Md5::digest(bytes)) == expected,
        "upstream source MD5 differs from scanner match; no grant can be bound to this candidate"
    );
    Ok(())
}

pub fn collect(candidate: &Candidate, timeout_secs: u64) -> Result<Proposal> {
    collect_inner(candidate, timeout_secs, None)
}

pub fn verify_source(evidence: &Evidence, timeout_secs: u64) -> Result<Vec<u8>> {
    ensure!(
        hex_hash(&evidence.revision, 40),
        "source verification requires a full GitHub commit hash"
    );
    ensure!(
        hex_hash(&evidence.source_sha256, 64),
        "invalid admitted source SHA-256"
    );
    let identity = Identity::new(
        &evidence.repository,
        &evidence.path,
        &evidence.revision,
        &evidence.file_md5,
    )?;
    let mut rest = vec![evidence.revision.as_str()];
    rest.extend(evidence.path.split('/'));
    let bytes =
        Download::new(timeout_secs)?.get(identity.url("raw.githubusercontent.com", &rest)?)?;
    verify_admitted_source(&bytes, evidence)?;
    Ok(bytes)
}

fn verify_admitted_source(bytes: &[u8], evidence: &Evidence) -> Result<()> {
    verify_source_md5(bytes, &evidence.file_md5)?;
    ensure!(
        policy::sha256(bytes) == evidence.source_sha256,
        "downloaded source SHA-256 differs from admitted evidence"
    );
    Ok(())
}

pub fn collect_with_scancode_report(
    candidate: &Candidate,
    timeout_secs: u64,
    report: &[u8],
    expected_version: &str,
) -> Result<Proposal> {
    collect_inner(candidate, timeout_secs, Some((report, expected_version)))
}

fn collect_inner(
    candidate: &Candidate,
    timeout_secs: u64,
    scancode: Option<(&[u8], &str)>,
) -> Result<Proposal> {
    ensure!(
        (1..=300).contains(&timeout_secs),
        "evidence timeout must be 1..300 seconds"
    );
    let mut proposal = Proposal {
        evidence: None,
        artifacts: BTreeMap::new(),
        issues: vec![],
    };
    let identity = match Identity::parse(candidate) {
        Ok(identity) => identity,
        Err(error) => {
            proposal.issues.push(error.to_string());
            return Ok(proposal);
        }
    };
    let mut download = Download::new(timeout_secs)?;
    let commit_bytes =
        download.get(identity.url("api.github.com", &["commits", &identity.version])?)?;
    let commit: Commit =
        serde_json::from_slice(&commit_bytes).context("invalid GitHub commit response")?;
    ensure!(
        hex_hash(&commit.sha, 40) && hex_hash(&commit.commit.tree.sha, 40),
        "GitHub did not return immutable commit/tree IDs"
    );
    let mut tree_url =
        identity.url("api.github.com", &["git", "trees", &commit.commit.tree.sha])?;
    tree_url.set_query(Some("recursive=1"));
    let tree_bytes = download.get(tree_url)?;
    let tree: Tree = serde_json::from_slice(&tree_bytes).context("invalid GitHub tree response")?;
    ensure!(
        !tree.truncated && tree.sha == commit.commit.tree.sha,
        "incomplete or mismatched revision tree"
    );
    let mut paths = BTreeSet::new();
    let mut selected = Vec::new();
    for entry in &tree.tree {
        policy::safe_path(&entry.path)?;
        ensure!(paths.insert(&entry.path), "duplicate upstream tree path");
        if entry.path == identity.path || applicable(&entry.path, &identity.path) {
            if entry.kind == "tree" {
                continue;
            }
            ensure!(
                entry.kind == "blob" && matches!(entry.mode.as_str(), "100644" | "100755"),
                "applicable evidence is not a regular file: {}",
                entry.path
            );
            selected.push(entry.path.as_str());
        }
    }
    ensure!(
        selected.contains(&identity.path.as_str()),
        "upstream source absent from resolved tree"
    );
    ensure!(
        selected.len() <= MAX_ARTIFACTS,
        "more than 64 evidence files require manual collection"
    );
    let prefix = format!(
        "LICENSE-NOTICES/{}",
        policy::sha256(
            format!(
                "{}/{}/{}/{}",
                identity.owner, identity.repo, commit.sha, identity.path
            )
            .as_bytes()
        )
    );
    let mut files = BTreeMap::new();
    for path in selected {
        let mut rest = vec![commit.sha.as_str()];
        rest.extend(path.split('/'));
        files.insert(
            path.to_owned(),
            download.get(identity.url("raw.githubusercontent.com", &rest)?)?,
        );
    }
    let source = &files[&identity.path];
    if let Err(error) = verify_source_md5(source, &identity.md5) {
        proposal.issues.push(error.to_string());
        return Ok(proposal);
    }
    let source_sha256 = policy::sha256(source);
    let mut expression = match source_expression(source) {
        Ok(value) => value,
        Err(error) => {
            proposal.issues.push(error.to_string());
            None
        }
    };
    if let Some((report, expected_version)) = scancode {
        let detected = scancode_expressions(report, expected_version, &files)?;
        if let Some(detection) = detected.get(&identity.path) {
            if expression
                .as_ref()
                .is_some_and(|header| header != detection)
            {
                proposal
                    .issues
                    .push("ScanCode and source header disagree; resolve grant conflict".into());
                expression = None;
            } else {
                expression = Some(detection.clone());
            }
        }
        proposal
            .artifacts
            .insert(format!("{prefix}/scancode.json"), report.to_vec());
    } else {
        proposal.issues.push("ScanCode report unavailable; exact-version license detection and grant review remain pending".into());
    }
    if files.len() == 1 {
        proposal.issues.push(
            "No separate ancestor or file-specific grant found; inspect retained source header"
                .into(),
        );
    }
    for (path, bytes) in files {
        proposal
            .artifacts
            .insert(format!("{prefix}/upstream/{path}"), bytes);
    }
    proposal
        .artifacts
        .insert(format!("{prefix}/commit.json"), commit_bytes);
    proposal
        .artifacts
        .insert(format!("{prefix}/tree.json"), tree_bytes);
    proposal.issues.push("Pending review: confirm grant applicability, third-party exceptions, selected license branch, obligations, and project use context before policy admission".into());
    if let Some(license) = expression {
        proposal.evidence = Some(Evidence {
            file_md5: identity.md5, source_sha256,
            repository: format!("https://github.com/{}/{}", identity.owner, identity.repo),
            revision: commit.sha, path: identity.path, selected_license: license.clone(), license,
            review: "PENDING: collected source and grant artifacts; applicability and obligations have not been reviewed".into(),
            obligations: Obligations::Unsupported { reason: "PENDING: review source-level obligations before selecting a supported enforcement rule".into() },
            artifacts: proposal.artifacts.iter().map(|(path, bytes)| Artifact { path: path.clone(), sha256: policy::sha256(bytes) }).collect(),
        });
    } else {
        proposal.issues.push(
            "No unambiguous source SPDX grant detected; scanner license labels are not evidence"
                .into(),
        );
    }
    Ok(proposal)
}

fn scancode_expressions(
    report: &[u8],
    expected_version: &str,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, String>> {
    ensure!(
        !expected_version.trim().is_empty(),
        "ScanCode version must be pinned explicitly"
    );
    ensure!(
        report.len() as u64 <= MAX_RESPONSE,
        "ScanCode report exceeds 8 MiB"
    );
    let value: Value = serde_json::from_slice(report).context("invalid ScanCode report")?;
    let headers = value["headers"]
        .as_array()
        .context("missing ScanCode headers")?;
    ensure!(
        headers.len() == 1
            && headers[0]["tool_name"] == "scancode-toolkit"
            && headers[0]["tool_version"] == expected_version,
        "ScanCode version/tool differs from explicit pin"
    );
    ensure!(
        headers[0]["options"]["--license"] == true && headers[0]["options"]["--info"] == true,
        "ScanCode report needs --license and --info"
    );
    for field in ["errors", "scan_errors"] {
        ensure!(
            headers[0]
                .get(field)
                .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty)),
            "ScanCode reported a scan-level error"
        );
    }
    let files = value["files"]
        .as_array()
        .context("missing ScanCode files")?;
    let mut expressions = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for file in files {
        if file["type"] == "directory" {
            continue;
        }
        ensure!(file["type"] == "file", "unsupported ScanCode entry type");
        let path = file["path"].as_str().context("missing ScanCode path")?;
        ensure!(seen.insert(path), "duplicate ScanCode path");
        ensure!(
            file["scan_errors"].as_array().is_some_and(Vec::is_empty),
            "ScanCode errors or absent error accounting"
        );
        let bytes = artifacts
            .get(path)
            .context("ScanCode file is not a collected upstream artifact; use --strip-root")?;
        verify_source_md5(
            bytes,
            file["md5"].as_str().context("missing ScanCode file MD5")?,
        )?;
        if let Some(expression) = file["detected_license_expression_spdx"]
            .as_str()
            .filter(|s| !s.is_empty())
        {
            spdx::Expression::parse(expression).context("unsupported ScanCode SPDX expression")?;
            ensure!(
                !expression.contains("LicenseRef-"),
                "unknown/custom ScanCode license requires manual review"
            );
            expressions.insert(path.into(), expression.into());
        }
    }
    ensure!(
        seen.len() == artifacts.len(),
        "ScanCode report does not cover every collected upstream artifact"
    );
    Ok(expressions)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_source_requires_both_hashes_and_an_immutable_safe_origin() {
        let source = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py");
        let mut evidence = Evidence {
            file_md5: format!("{:x}", Md5::digest(source)),
            source_sha256: policy::sha256(source),
            repository: "https://github.com/scanoss/scanoss.py".into(),
            revision: "0c1292bd4d53bc504804411dd42ff1ab0fa7aa76".into(),
            path: "src/scanoss/winnowing.py".into(),
            license: "MIT".into(),
            selected_license: "MIT".into(),
            review: "test fixture".into(),
            obligations: Obligations::ArtifactOnly {},
            artifacts: vec![],
        };
        verify_admitted_source(source, &evidence).unwrap();
        evidence.source_sha256 = "0".repeat(64);
        assert!(
            verify_admitted_source(source, &evidence)
                .unwrap_err()
                .to_string()
                .contains("SHA-256")
        );
        evidence.source_sha256 = policy::sha256(source);
        evidence.file_md5 = "0".repeat(32);
        assert!(
            verify_admitted_source(source, &evidence)
                .unwrap_err()
                .to_string()
                .contains("MD5")
        );
        evidence.file_md5 = format!("{:x}", Md5::digest(source));
        evidence.repository = "https://example.com/scanoss/scanoss.py".into();
        assert!(
            verify_source(&evidence, 1)
                .unwrap_err()
                .to_string()
                .contains("github.com")
        );
        evidence.repository = "https://github.com/scanoss/scanoss.py".into();
        evidence.revision = "main".into();
        assert!(
            verify_source(&evidence, 1)
                .unwrap_err()
                .to_string()
                .contains("full GitHub commit")
        );
    }

    #[test]
    fn applicability_collects_ancestors_and_sidecars_without_sibling_grants() {
        for path in [
            "LICENSE",
            "COPYING.txt",
            "src/NOTICE",
            "src/nested/LICENSE-MIT",
            "src/nested/code.rs.license",
            "LICENSES/MIT.txt",
        ] {
            assert!(applicable(path, "src/nested/code.rs"), "{path}");
        }
        for path in [
            "other/LICENSE",
            "src/nested/other.rs.license",
            "src/nested/README",
            "src/nested/licensee.rs",
        ] {
            assert!(!applicable(path, "src/nested/code.rs"), "{path}");
        }
    }
    #[test]
    fn source_hash_and_explicit_headers_are_required() {
        assert!(verify_source_md5(b"a", "0cc175b9c0f1b6a831c399e269772661").is_ok());
        assert!(verify_source_md5(b"b", "0cc175b9c0f1b6a831c399e269772661").is_err());
        assert_eq!(
            source_expression(b"/* SPDX-License-Identifier: MIT */\n").unwrap(),
            Some("MIT".into())
        );
        assert_eq!(
            source_expression(b"this uses MIT technology").unwrap(),
            None
        );
        assert!(
            source_expression(
                b"// SPDX-License-Identifier: MIT\n// SPDX-License-Identifier: Apache-2.0"
            )
            .is_err()
        );
    }
    #[test]
    fn pinned_scancode_must_account_for_exact_bytes() {
        let artifacts = BTreeMap::from([("LICENSE".into(), b"a".to_vec())]);
        let report = serde_json::json!({"headers":[{"tool_name":"scancode-toolkit","tool_version":"32.4.1","options":{"--license":true,"--info":true}}],"files":[{"path":"LICENSE","type":"file","md5":"0cc175b9c0f1b6a831c399e269772661","scan_errors":[],"detected_license_expression_spdx":"MIT"}]});
        let bytes = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            scancode_expressions(&bytes, "32.4.1", &artifacts).unwrap()["LICENSE"],
            "MIT"
        );
        assert!(scancode_expressions(&bytes, "32.3.0", &artifacts).is_err());
        assert!(
            scancode_expressions(
                &bytes,
                "32.4.1",
                &BTreeMap::from([("LICENSE".into(), b"b".to_vec())])
            )
            .is_err()
        );
        let mut error = report;
        error["files"][0]["scan_errors"] = serde_json::json!(["timeout"]);
        assert!(
            scancode_expressions(&serde_json::to_vec(&error).unwrap(), "32.4.1", &artifacts)
                .is_err()
        );
    }
}
