use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const POLICY_PATH: &str = ".oss-provenance.toml";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub project_license: String,
    pub use_context: String,
    pub scanner: ScannerConfig,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub retirements: Vec<Retirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Retirement {
    pub evidence_id: String,
    pub path: String,
    pub snippet_sha256: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    pub endpoint: String,
    pub enabled: bool,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub file_md5: String,
    pub source_sha256: String,
    pub repository: String,
    pub revision: String,
    pub path: String,
    pub license: String,
    pub selected_license: String,
    pub review: String,
    pub obligations: Obligations,
    pub artifacts: Vec<Artifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Obligations {
    ArtifactOnly {},
    SourcePrefix { text: String },
    Unsupported { reason: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Blocked(String),
    Unresolved(String),
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn safe_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && !path.contains(['\\', '\0', '\n', '\r']),
        "unsafe path"
    );
    ensure!(
        path.split('/').all(|part| !part.is_empty()
            && part != "."
            && part != ".."
            && !part.eq_ignore_ascii_case(".git")),
        "unsafe repository-relative path: {path}"
    );
    ensure!(!path.contains(':'), "colon in artifact path");
    Ok(())
}

fn valid_hash(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Policy {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut policy: Self =
            toml::from_str(std::str::from_utf8(bytes)?).context("invalid policy TOML")?;
        ensure!(policy.version == 1, "unsupported policy version");
        spdx::Expression::parse(&policy.project_license)
            .context("invalid project SPDX expression")?;
        ensure!(
            !policy.use_context.trim().is_empty(),
            "use_context must be explicit"
        );
        ensure!(
            (1..=300).contains(&policy.scanner.timeout_secs),
            "scanner timeout must be 1..300 seconds"
        );
        for term in policy.allow.iter_mut().chain(policy.deny.iter_mut()) {
            let expression = spdx::Expression::parse(term).context("invalid SPDX policy term")?;
            ensure!(
                expression.requirements().count() == 1,
                "allow and deny entries must be individual SPDX requirements"
            );
            *term = expression.requirements().next().unwrap().req.to_string();
        }
        for term in &policy.deny {
            ensure!(
                !policy.allow.contains(term),
                "license appears in allow and deny"
            );
        }
        let mut retired = BTreeSet::new();
        for retirement in &policy.retirements {
            ensure!(
                valid_hash(&retirement.evidence_id, 64)
                    && valid_hash(&retirement.snippet_sha256, 64),
                "invalid retirement identity"
            );
            safe_path(&retirement.path)?;
            ensure!(
                !retirement.reason.trim().is_empty(),
                "retirement requires an admitted rationale"
            );
            ensure!(
                retired.insert((
                    &retirement.evidence_id,
                    &retirement.path,
                    &retirement.snippet_sha256
                )),
                "duplicate retirement"
            );
        }
        for path in &policy.exclude {
            safe_path(path.trim_end_matches('/'))?;
        }
        let mut identities = BTreeSet::new();
        for evidence in &policy.evidence {
            ensure!(valid_hash(&evidence.file_md5, 32), "invalid evidence MD5");
            ensure!(
                valid_hash(&evidence.source_sha256, 64),
                "invalid evidence SHA-256"
            );
            ensure!(
                valid_hash(&evidence.revision, 40) || valid_hash(&evidence.revision, 64),
                "evidence revision must be a full immutable commit hash"
            );
            ensure!(
                identities.insert(&evidence.file_md5),
                "conflicting evidence for source hash"
            );
            let url = reqwest::Url::parse(&evidence.repository)?;
            ensure!(
                url.scheme() == "https"
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.host_str().is_some(),
                "evidence repository must be an HTTPS URL without credentials"
            );
            safe_path(&evidence.path)?;
            ensure!(
                !evidence.review.trim().is_empty(),
                "evidence must include reviewed grant applicability and obligations"
            );
            match &evidence.obligations {
                Obligations::ArtifactOnly {} => {}
                Obligations::SourcePrefix { text } => ensure!(
                    !text.trim().is_empty(),
                    "source prefix obligation must contain nonempty required text"
                ),
                Obligations::Unsupported { reason } => ensure!(
                    !reason.trim().is_empty(),
                    "unsupported obligations must explain the unresolved requirement"
                ),
            }
            let original = spdx::Expression::parse(&evidence.license)?;
            let chosen = spdx::Expression::parse(&evidence.selected_license)?;
            let chosen_terms: BTreeSet<String> =
                chosen.requirements().map(|r| r.req.to_string()).collect();
            let original_terms: BTreeSet<String> =
                original.requirements().map(|r| r.req.to_string()).collect();
            ensure!(
                chosen_terms.is_subset(&original_terms),
                "selected license contains terms absent from the upstream grant"
            );
            ensure!(
                original.evaluate(|r| chosen_terms.contains(&r.to_string())),
                "selected license does not satisfy the upstream expression"
            );
            ensure!(
                !chosen.iter().any(|node| matches!(
                    node,
                    spdx::expression::ExprNode::Op(spdx::expression::Operator::Or)
                )),
                "selected_license must record a concrete branch"
            );
            ensure!(
                !evidence.artifacts.is_empty(),
                "verified grant artifacts are required"
            );
            let mut paths = BTreeSet::new();
            for artifact in &evidence.artifacts {
                safe_path(&artifact.path)?;
                ensure!(
                    artifact.path.starts_with("LICENSE-NOTICES/"),
                    "evidence artifacts must live inside LICENSE-NOTICES"
                );
                ensure!(valid_hash(&artifact.sha256, 64), "invalid artifact SHA-256");
                ensure!(paths.insert(&artifact.path), "duplicate evidence artifact");
            }
        }
        Ok(policy)
    }

    pub fn excluded(&self, path: &str) -> bool {
        self.exclude.iter().any(|p| {
            if p.ends_with('/') {
                path.starts_with(p)
            } else {
                path == p
            }
        })
    }

    pub fn decide(&self, evidence: &Evidence) -> Result<Decision> {
        let expression = spdx::Expression::parse(&evidence.selected_license)?;
        for requirement in expression.requirements() {
            let term = requirement.req.to_string();
            if self.deny.contains(&term) {
                return Ok(Decision::Blocked(format!(
                    "{term} is denied for {} ({})",
                    self.project_license, self.use_context
                )));
            }
        }
        if let Obligations::Unsupported { reason } = &evidence.obligations {
            return Ok(Decision::Unresolved(format!(
                "unsupported source obligations: {reason}"
            )));
        }
        if expression.evaluate(|r| self.allow.contains(&r.to_string())) {
            Ok(Decision::Allowed)
        } else {
            Ok(Decision::Unresolved(
                "selected license has requirements without an admitted rule".into(),
            ))
        }
    }

    pub fn evidence_for(&self, file_md5: &str) -> Option<&Evidence> {
        self.evidence.iter().find(|e| e.file_md5 == file_md5)
    }
}

pub fn verify_artifact(artifact: &Artifact, bytes: &[u8]) -> Result<()> {
    if sha256(bytes) != artifact.sha256 {
        bail!(
            "evidence artifact differs from admitted hash: {}",
            artifact.path
        );
    }
    Ok(())
}

pub const EXAMPLE: &str = r#"version = 1
project_license = "MIT"
use_context = "EDIT: describe how this project combines and distributes reused code"
allow = []
deny = []
exclude = [".oss-provenance.toml", "LICENSE-NOTICES/", "Cargo.lock"]

[scanner]
endpoint = "https://api.osskb.org/scan/direct"
enabled = false
timeout_secs = 30
"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn example_is_inert() {
        let policy = Policy::parse(EXAMPLE.as_bytes()).unwrap();
        assert!(!policy.scanner.enabled);
        assert!(policy.allow.is_empty());
        assert!(policy.excluded("LICENSE-NOTICES/one/LICENSE"));
        assert!(!policy.excluded("src/lib.rs"));
    }
    #[test]
    fn paths_cannot_escape() {
        for path in [
            "../x",
            "/x",
            ".git/config",
            "x/../y",
            "x\\y",
            "x\ny",
            "x//y",
        ] {
            assert!(safe_path(path).is_err(), "{path}");
        }
        assert!(safe_path("LICENSE-NOTICES/source/LICENSE").is_ok());
    }
    #[test]
    fn rejects_unknown_settings_and_ambiguous_policy() {
        assert!(Policy::parse(format!("typo = true\n{EXAMPLE}").as_bytes()).is_err());
        assert!(
            Policy::parse(
                EXAMPLE
                    .replace("allow = []", "allow = [\"MIT\"]")
                    .replace("deny = []", "deny = [\"MIT\"]")
                    .as_bytes()
            )
            .is_err()
        );
    }
    #[test]
    fn policy_terms_are_atomic_and_canonical() {
        assert!(
            Policy::parse(
                EXAMPLE
                    .replace("deny = []", "deny = [\"MIT OR Apache-2.0\"]")
                    .as_bytes()
            )
            .is_err()
        );
        let policy = Policy::parse(
            EXAMPLE
                .replace("deny = []", "deny = [\"(MIT)\"]")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(policy.deny, vec!["MIT"]);
        assert!(
            Policy::parse(
                EXAMPLE
                    .replace("deny = []", "deny = [\"(MIT)\"]")
                    .replace("allow = []", "allow = [\"MIT\"]")
                    .as_bytes()
            )
            .is_err()
        );
    }
}
