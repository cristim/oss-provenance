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
const MAX_TREE_PAGES: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceHost {
    GitHub,
    GitLab,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub evidence: Option<Evidence>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub issues: Vec<String>,
}

struct Identity {
    host: SourceHost,
    project: String,
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
                && matches!(url.host_str(), Some("github.com" | "gitlab.com"))
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "only public HTTPS github.com and gitlab.com repository URLs are supported"
        );
        let host = if url.host_str() == Some("github.com") {
            SourceHost::GitHub
        } else {
            SourceHost::GitLab
        };
        let mut parts: Vec<_> = url
            .path()
            .trim_end_matches('/')
            .split('/')
            .skip(1)
            .collect();
        ensure!(
            parts.len() >= 2 && (host == SourceHost::GitLab || parts.len() == 2),
            "repository URL must identify a namespace and repository"
        );
        let last = parts.last_mut().unwrap();
        *last = last.strip_suffix(".git").unwrap_or(last);
        for part in &parts {
            ensure!(
                !part.is_empty()
                    && *part != "."
                    && *part != ".."
                    && (host != SourceHost::GitLab || *part != "-")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "unsupported repository name"
            );
        }
        policy::safe_path(path)?;
        ensure!(
            version.len() <= 256 && !version.chars().any(char::is_control),
            "invalid upstream version"
        );
        ensure!(hex_hash(md5, 32), "invalid upstream file MD5");
        Ok(Self {
            host,
            project: parts.join("/"),
            path: path.into(),
            version: version.into(),
            md5: md5.into(),
        })
    }

    fn repository(&self) -> String {
        let host = match self.host {
            SourceHost::GitHub => "github.com",
            SourceHost::GitLab => "gitlab.com",
        };
        format!("https://{host}/{}", self.project)
    }

    fn api_url(&self, rest: &[&str]) -> Result<Url> {
        let mut url = Url::parse(match self.host {
            SourceHost::GitHub => "https://api.github.com",
            SourceHost::GitLab => "https://gitlab.com",
        })?;
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid fixed host"))?;
        match self.host {
            SourceHost::GitHub => {
                segments.push("repos").extend(self.project.split('/'));
            }
            SourceHost::GitLab => {
                segments.extend(["api", "v4", "projects", &self.project]);
            }
        }
        segments.extend(rest);
        drop(segments);
        Ok(url)
    }

    fn source_url(&self, revision: &str, path: &str) -> Result<Url> {
        if self.host == SourceHost::GitLab {
            let mut url = self.api_url(&["repository", "files", path, "raw"])?;
            url.query_pairs_mut().append_pair("ref", revision);
            return Ok(url);
        }
        let mut url = Url::parse("https://raw.githubusercontent.com")?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid fixed host"))?
            .extend(self.project.split('/'))
            .push(revision)
            .extend(path.split('/'));
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

struct Page {
    bytes: Vec<u8>,
    page: Option<String>,
    next_page: Option<String>,
}

fn pagination_header(headers: &reqwest::header::HeaderMap, name: &str) -> Result<Option<String>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    ensure!(values.next().is_none(), "duplicate GitLab {name} header");
    first
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .context("invalid GitLab pagination header")
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
        Ok(self.get_page(url)?.bytes)
    }

    fn get_page(&mut self, url: Url) -> Result<Page> {
        ensure!(
            url.scheme() == "https"
                && matches!(
                    url.host_str(),
                    Some("api.github.com" | "raw.githubusercontent.com" | "gitlab.com")
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
        let page = pagination_header(response.headers(), "x-page")?;
        let next_page = pagination_header(response.headers(), "x-next-page")?;
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
        Ok(Page {
            bytes,
            page,
            next_page,
        })
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

struct ResolvedTree {
    revision: String,
    entries: Vec<Entry>,
    metadata: BTreeMap<String, Vec<u8>>,
}

fn resolve_tree(
    identity: &Identity,
    mut fetch: impl FnMut(Url) -> Result<Page>,
) -> Result<ResolvedTree> {
    if identity.host == SourceHost::GitHub {
        let commit_bytes = fetch(identity.api_url(&["commits", &identity.version])?)?.bytes;
        let commit: Commit =
            serde_json::from_slice(&commit_bytes).context("invalid GitHub commit response")?;
        ensure!(
            hex_hash(&commit.sha, 40) && hex_hash(&commit.commit.tree.sha, 40),
            "GitHub did not return immutable commit/tree IDs"
        );
        ensure!(
            !hex_hash(&identity.version, 40) || identity.version == commit.sha,
            "resolved commit differs from requested immutable revision"
        );
        let mut url = identity.api_url(&["git", "trees", &commit.commit.tree.sha])?;
        url.set_query(Some("recursive=1"));
        let tree_bytes = fetch(url)?.bytes;
        let tree: Tree =
            serde_json::from_slice(&tree_bytes).context("invalid GitHub tree response")?;
        ensure!(
            !tree.truncated && tree.sha == commit.commit.tree.sha,
            "incomplete or mismatched revision tree"
        );
        return Ok(ResolvedTree {
            revision: commit.sha,
            entries: tree.tree,
            metadata: BTreeMap::from([
                ("commit.json".into(), commit_bytes),
                ("tree.json".into(), tree_bytes),
            ]),
        });
    }
    let commit_bytes =
        fetch(identity.api_url(&["repository", "commits", &identity.version])?)?.bytes;
    let commit: Value =
        serde_json::from_slice(&commit_bytes).context("invalid GitLab commit response")?;
    let revision = commit["id"].as_str().context("missing GitLab commit ID")?;
    ensure!(
        hex_hash(revision, 40),
        "GitLab did not return an immutable commit ID"
    );
    ensure!(
        !hex_hash(&identity.version, 40) || identity.version == revision,
        "resolved commit differs from requested immutable revision"
    );
    let revision = revision.to_owned();
    let mut metadata = BTreeMap::from([("commit.json".into(), commit_bytes)]);
    let mut entries = Vec::new();
    for number in 1..=MAX_TREE_PAGES {
        let number_text = number.to_string();
        let mut url = identity.api_url(&["repository", "tree"])?;
        url.query_pairs_mut().extend_pairs([
            ("ref", revision.as_str()),
            ("recursive", "true"),
            ("per_page", "100"),
            ("page", number_text.as_str()),
        ]);
        let response = fetch(url)?;
        ensure!(
            response.page.as_deref() == Some(number_text.as_str()),
            "missing or mismatched GitLab tree page accounting"
        );
        let next = response
            .next_page
            .as_deref()
            .context("missing GitLab next-page accounting")?;
        let page: Vec<Entry> =
            serde_json::from_slice(&response.bytes).context("invalid GitLab tree response")?;
        ensure!(
            page.len() <= 100 && (next.is_empty() || !page.is_empty()),
            "invalid GitLab tree page size"
        );
        entries.extend(page);
        metadata.insert(format!("tree-{number}.json"), response.bytes);
        if next.is_empty() {
            return Ok(ResolvedTree {
                revision,
                entries,
                metadata,
            });
        }
        ensure!(
            next == (number + 1).to_string(),
            "nonsequential GitLab tree pagination"
        );
    }
    anyhow::bail!("GitLab tree exceeds 100 pages; manual collection required")
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
    verify_source_with_cache(
        evidence,
        timeout_secs,
        &crate::cache::Cache::from_env()?,
        |mut download, url| download.get(url),
    )
}

fn verify_source_with_cache(
    evidence: &Evidence,
    timeout_secs: u64,
    cache: &crate::cache::Cache,
    fetch: impl FnOnce(Download, Url) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    ensure!(
        hex_hash(&evidence.revision, 40),
        "source verification requires a full GitHub or GitLab commit hash"
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
    let url = identity.source_url(&evidence.revision, &evidence.path)?;
    let download = Download::new(timeout_secs)?;
    let key = crate::cache::key(&[
        b"source",
        url.as_str().as_bytes(),
        evidence.source_sha256.as_bytes(),
        evidence.file_md5.as_bytes(),
    ]);
    if let Some(bytes) = cache.load(&key, None, MAX_RESPONSE)?
        && verify_admitted_source(&bytes, evidence).is_ok()
    {
        return Ok(bytes);
    }
    let bytes = fetch(download, url)?;
    verify_admitted_source(&bytes, evidence)?;
    cache.store(&key, &bytes)?;
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
    let mut download = Download::new(timeout_secs)?;
    collect_with_fetch(candidate, scancode, |url| download.get_page(url))
}

fn collect_with_fetch(
    candidate: &Candidate,
    scancode: Option<(&[u8], &str)>,
    mut fetch: impl FnMut(Url) -> Result<Page>,
) -> Result<Proposal> {
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
    let tree = resolve_tree(&identity, &mut fetch)?;
    let mut paths = BTreeSet::new();
    let mut selected = Vec::new();
    for entry in &tree.entries {
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
    let repository = identity.repository();
    let prefix = format!(
        "LICENSE-NOTICES/{}",
        policy::sha256(format!("{}/{}/{}", repository, tree.revision, identity.path).as_bytes())
    );
    let mut files = BTreeMap::new();
    for path in selected {
        files.insert(
            path.to_owned(),
            fetch(identity.source_url(&tree.revision, path)?)?.bytes,
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
    for (name, bytes) in tree.metadata {
        proposal.artifacts.insert(format!("{prefix}/{name}"), bytes);
    }
    proposal.issues.push("Pending review: confirm grant applicability, third-party exceptions, selected license branch, obligations, and project use context before policy admission".into());
    if let Some(license) = expression {
        proposal.evidence = Some(Evidence {
            file_md5: identity.md5, source_sha256,
            repository,
            revision: tree.revision, path: identity.path, selected_license: license.clone(), license,
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
mod gitlab_tests {
    use super::*;

    const REVISION: &str = "f6a93079dd611ffeec26f9f599dc1f78397f41ba";
    const SOURCE: &[u8] = include_bytes!("../LICENSE-NOTICES/gitlab-labkit/fields.go");
    const LICENSE: &[u8] = include_bytes!("../LICENSE-NOTICES/gitlab-labkit/LICENSE");
    const PAGES: [&str; 9] = [
        include_str!("../tests/fixtures/gitlab/tree-1.json"),
        include_str!("../tests/fixtures/gitlab/tree-2.json"),
        include_str!("../tests/fixtures/gitlab/tree-3.json"),
        include_str!("../tests/fixtures/gitlab/tree-4.json"),
        include_str!("../tests/fixtures/gitlab/tree-5.json"),
        include_str!("../tests/fixtures/gitlab/tree-6.json"),
        include_str!("../tests/fixtures/gitlab/tree-7.json"),
        include_str!("../tests/fixtures/gitlab/tree-8.json"),
        include_str!("../tests/fixtures/gitlab/tree-9.json"),
    ];

    fn candidate() -> Candidate {
        Candidate {
            id: "file".into(),
            local_ranges: vec![(1, 1)],
            upstream_ranges: vec![],
            url: Some("https://gitlab.com/gitlab-org/labkit".into()),
            file: Some("fields/fields.go".into()),
            file_hash: Some("da966675939febb440609aeea0bac49b".into()),
            licenses: vec!["MIT".into()],
            raw: serde_json::json!({"version":"master"}),
        }
    }

    fn recorded(url: Url) -> Result<Page> {
        assert_eq!(url.host_str(), Some("gitlab.com"));
        assert!(
            url.path()
                .starts_with("/api/v4/projects/gitlab-org%2Flabkit/repository/")
        );
        let query: BTreeMap<_, _> = url.query_pairs().collect();
        if url.path().ends_with("/commits/master") {
            assert!(query.is_empty());
            return Ok(Page {
                bytes: include_bytes!("../tests/fixtures/gitlab/commit.json").to_vec(),
                page: None,
                next_page: None,
            });
        }
        assert_eq!(query["ref"], REVISION);
        if url.path().ends_with("/tree") {
            assert_eq!(query["recursive"], "true");
            assert_eq!(query["per_page"], "100");
            let number: usize = query["page"].parse()?;
            let value: Value = serde_json::from_str(PAGES[number - 1])?;
            return Ok(Page {
                bytes: serde_json::to_vec(&value["body"])?,
                page: value["page"].as_str().map(str::to_owned),
                next_page: value["next_page"].as_str().map(str::to_owned),
            });
        }
        let bytes = if url.path().ends_with("/files/fields%2Ffields.go/raw") {
            SOURCE
        } else if url.path().ends_with("/files/LICENSE/raw") {
            LICENSE
        } else {
            anyhow::bail!("unexpected fixture request: {url}")
        };
        Ok(Page {
            bytes: bytes.to_vec(),
            page: None,
            next_page: None,
        })
    }

    #[test]
    fn recorded_gitlab_collection_pins_all_nine_pages_and_exact_grants() {
        let mut requests = 0;
        let proposal = collect_with_fetch(&candidate(), None, |url| {
            requests += 1;
            recorded(url)
        })
        .unwrap();
        assert_eq!(requests, 12);
        assert_eq!(proposal.artifacts.len(), 12);
        assert!(proposal.artifacts.values().any(|bytes| bytes == SOURCE));
        assert!(proposal.artifacts.values().any(|bytes| bytes == LICENSE));
        assert!(
            proposal
                .artifacts
                .keys()
                .any(|path| path.ends_with("/tree-9.json"))
        );
        assert!(proposal.evidence.is_none());
        assert!(
            proposal
                .issues
                .iter()
                .any(|issue| issue.starts_with("Pending review:"))
        );
        assert_eq!(
            policy::sha256(SOURCE),
            "f0356f426a0da955390eec27c5f546d6d72e3241bf3fcc21f39d41a422308747"
        );
        assert_eq!(
            policy::sha256(LICENSE),
            "d08172d312bc93d0d098342e1ac50d35439152e5ea17c4f668e55e868fd4d1da"
        );
    }

    #[test]
    fn gitlab_rejects_missing_repeated_and_skipped_page_accounting() {
        for (page, next_page) in [
            (None, Some("2")),
            (Some("2"), Some("2")),
            (Some("1"), None),
            (Some("1"), Some("1")),
            (Some("1"), Some("3")),
        ] {
            assert!(
                collect_with_fetch(&candidate(), None, |url| {
                    let first = url
                        .query_pairs()
                        .any(|(key, value)| key == "page" && value == "1");
                    let mut response = recorded(url)?;
                    if first {
                        response.page = page.map(str::to_owned);
                        response.next_page = next_page.map(str::to_owned);
                    }
                    Ok(response)
                })
                .is_err()
            );
        }
    }

    #[test]
    fn gitlab_rejects_duplicate_pagination_headers_before_conversion() {
        for name in ["x-page", "x-next-page"] {
            for values in [["", "2"], ["2", ""], ["1", "1"]] {
                let mut headers = reqwest::header::HeaderMap::new();
                for value in values {
                    headers.append(name, value.parse().unwrap());
                }
                assert!(
                    pagination_header(&headers, name)
                        .unwrap_err()
                        .to_string()
                        .contains("duplicate")
                );
            }
        }
    }

    #[test]
    fn gitlab_rejects_revision_changes_and_unbounded_trees() {
        let mut pinned = candidate();
        pinned.raw["version"] = "0".repeat(40).into();
        let error = collect_with_fetch(&pinned, None, |_| {
            recorded(Url::parse("https://gitlab.com/api/v4/projects/gitlab-org%2Flabkit/repository/commits/master").unwrap())
        })
        .unwrap_err();
        assert!(error.to_string().contains("differs from requested"));

        let mut pages = 0;
        let error = collect_with_fetch(&candidate(), None, |url| {
            if !url.path().ends_with("/tree") {
                return recorded(url);
            }
            pages += 1;
            Ok(Page {
                bytes: br#"[{"path":"file","mode":"100644","type":"blob"}]"#.to_vec(),
                page: Some(pages.to_string()),
                next_page: Some((pages + 1).to_string()),
            })
        })
        .unwrap_err();
        assert_eq!(pages, MAX_TREE_PAGES);
        assert!(error.to_string().contains("exceeds 100 pages"));
    }

    #[test]
    fn gitlab_rejects_links_duplicates_and_source_hash_mismatches() {
        for mode in ["120000", "160000"] {
            assert!(
                collect_with_fetch(&candidate(), None, |url| {
                    let tree = url.path().ends_with("/tree");
                    let mut response = recorded(url)?;
                    if tree {
                        let mut entries: Vec<Value> = serde_json::from_slice(&response.bytes)?;
                        for entry in &mut entries {
                            if entry["path"] == "fields/fields.go" {
                                entry["mode"] = mode.into();
                            }
                        }
                        response.bytes = serde_json::to_vec(&entries)?;
                    }
                    Ok(response)
                })
                .unwrap_err()
                .to_string()
                .contains("regular file")
            );
        }
        assert!(
            collect_with_fetch(&candidate(), None, |url| {
                let tree = url.path().ends_with("/tree");
                let mut response = recorded(url)?;
                if tree {
                    let mut entries: Vec<Value> = serde_json::from_slice(&response.bytes)?;
                    if entries.len() > 1 {
                        entries[1] = entries[0].clone();
                    }
                    response.bytes = serde_json::to_vec(&entries)?;
                }
                Ok(response)
            })
            .unwrap_err()
            .to_string()
            .contains("duplicate")
        );
        let mut bad = candidate();
        bad.file_hash = Some("0".repeat(32));
        let proposal = collect_with_fetch(&bad, None, recorded).unwrap();
        assert!(proposal.evidence.is_none() && proposal.artifacts.is_empty());
        assert!(proposal.issues[0].contains("MD5 differs"));
    }

    #[test]
    fn nested_gitlab_projects_use_encoded_segments_and_separate_origins() {
        let identity = Identity::new(
            "https://gitlab.com/group/subgroup/repo.git",
            "src/a b.rs",
            "release/1",
            &"0".repeat(32),
        )
        .unwrap();
        assert_eq!(
            identity.repository(),
            "https://gitlab.com/group/subgroup/repo"
        );
        assert_eq!(
            identity
                .api_url(&["repository", "commits", &identity.version])
                .unwrap()
                .as_str(),
            "https://gitlab.com/api/v4/projects/group%2Fsubgroup%2Frepo/repository/commits/release%2F1"
        );
        assert_eq!(
            identity
                .source_url(REVISION, &identity.path)
                .unwrap()
                .as_str(),
            format!(
                "https://gitlab.com/api/v4/projects/group%2Fsubgroup%2Frepo/repository/files/src%2Fa%20b.rs/raw?ref={REVISION}"
            )
        );
        for url in [
            "https://gitlab.com.evil.invalid/group/repo",
            "https://user@gitlab.com/group/repo",
            "https://gitlab.com:8443/group/repo",
            "https://gitlab.com/group/repo?token=x",
            "https://gitlab.com/group/repo/-/tree/main",
            "https://gitlab.com/group/%2Frepo",
        ] {
            assert!(
                Identity::new(url, "src/a.rs", REVISION, &"0".repeat(32)).is_err(),
                "{url}"
            );
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    const SOURCE: &[u8] = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py");

    fn evidence() -> Evidence {
        Evidence {
            file_md5: format!("{:x}", Md5::digest(SOURCE)),
            source_sha256: policy::sha256(SOURCE),
            repository: "https://github.com/scanoss/scanoss.py".into(),
            revision: "0c1292bd4d53bc504804411dd42ff1ab0fa7aa76".into(),
            path: "src/scanoss/winnowing.py".into(),
            license: "MIT".into(),
            selected_license: "MIT".into(),
            review: "test fixture".into(),
            obligations: Obligations::ArtifactOnly {},
            artifacts: vec![],
        }
    }

    fn key(evidence: &Evidence) -> String {
        let url = format!(
            "https://raw.githubusercontent.com/scanoss/scanoss.py/{}/{}",
            evidence.revision, evidence.path
        );
        crate::cache::key(&[
            b"source",
            url.as_bytes(),
            evidence.source_sha256.as_bytes(),
            evidence.file_md5.as_bytes(),
        ])
    }

    #[test]
    fn immutable_source_hit_rechecks_hashes_without_fetch_or_refresh() {
        let directory = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::at(directory.path().to_owned()).unwrap();
        let evidence = evidence();
        let key = key(&evidence);
        cache.store(&key, SOURCE).unwrap();
        let mut before = std::fs::read(directory.path().join(&key)).unwrap();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;
        before[10..18].copy_from_slice(&stamp.to_be_bytes());
        std::fs::write(directory.path().join(&key), &before).unwrap();
        let bytes = verify_source_with_cache(&evidence, 5, &cache, |_, _| {
            panic!("cache hit fetched source")
        })
        .unwrap();
        assert_eq!(bytes, SOURCE);
        assert_eq!(std::fs::read(directory.path().join(key)).unwrap(), before);
    }

    #[test]
    fn poisoned_source_cache_requires_valid_fresh_source() {
        let directory = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::at(directory.path().to_owned()).unwrap();
        let evidence = evidence();
        let key = key(&evidence);
        cache.store(&key, b"poisoned source").unwrap();
        let calls = std::cell::Cell::new(0);
        let bytes = verify_source_with_cache(&evidence, 5, &cache, |_, url| {
            calls.set(calls.get() + 1);
            assert_eq!(url.as_str(), "https://raw.githubusercontent.com/scanoss/scanoss.py/0c1292bd4d53bc504804411dd42ff1ab0fa7aa76/src/scanoss/winnowing.py");
            Ok(SOURCE.to_vec())
        }).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(bytes, SOURCE);
        assert_eq!(
            cache.load(&key, None, MAX_RESPONSE).unwrap().unwrap(),
            SOURCE
        );
        cache.store(&key, b"poisoned source").unwrap();
        let error = verify_source_with_cache(&evidence, 5, &cache, |_, _| {
            anyhow::bail!("upstream unavailable")
        })
        .unwrap_err();
        assert!(error.to_string().contains("upstream unavailable"));
        assert!(
            verify_source_with_cache(&evidence, 5, &cache, |_, _| Ok(b"bad live source".to_vec()))
                .is_err()
        );
        assert_eq!(
            cache.load(&key, None, MAX_RESPONSE).unwrap().unwrap(),
            b"poisoned source"
        );
    }

    #[test]
    fn cached_bytes_must_match_both_admitted_hashes() {
        let directory = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::at(directory.path().to_owned()).unwrap();
        let mut bad_sha = evidence();
        bad_sha.source_sha256 = "0".repeat(64);
        let mut bad_md5 = evidence();
        bad_md5.file_md5 = "0".repeat(32);
        for evidence in [bad_sha, bad_md5] {
            cache.store(&key(&evidence), SOURCE).unwrap();
            let error = verify_source_with_cache(&evidence, 5, &cache, |_, _| {
                anyhow::bail!("fresh verification required")
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "fresh verification required");
        }
    }

    #[test]
    fn cache_cannot_bypass_origin_revision_path_or_timeout_validation() {
        let directory = tempfile::tempdir().unwrap();
        let cache = crate::cache::Cache::at(directory.path().to_owned()).unwrap();
        let original = evidence();
        cache.store(&key(&original), SOURCE).unwrap();
        for timeout in [0, 301] {
            assert!(
                verify_source_with_cache(&original, timeout, &cache, |_, _| panic!(
                    "invalid timeout fetched"
                ))
                .is_err()
            );
        }
        let mut bad_origin = evidence();
        bad_origin.repository = "https://github.com.evil.invalid/scanoss/scanoss.py".into();
        let mut bad_revision = evidence();
        bad_revision.revision = "main".into();
        let mut bad_path = evidence();
        bad_path.path = "../private".into();
        let mut bad_hash = evidence();
        bad_hash.source_sha256 = "invalid".into();
        for evidence in [bad_origin, bad_revision, bad_path, bad_hash] {
            assert!(
                verify_source_with_cache(&evidence, 5, &cache, |_, _| panic!(
                    "invalid evidence fetched"
                ))
                .is_err()
            );
        }
    }
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
                .contains("full GitHub or GitLab commit")
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
