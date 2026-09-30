use crate::{check::Report, git::Snapshot};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

pub fn prepare_handoff(
    snapshot: &Snapshot,
    report: &Report,
    brief: &Path,
    output: &Path,
    agent: &str,
) -> Result<()> {
    ensure!(matches!(agent, "claude" | "codex"), "unsupported agent");
    ensure!(
        !output.exists(),
        "handoff directory already exists; refusing to overwrite"
    );
    ensure!(
        report
            .files
            .iter()
            .flat_map(|file| &file.findings)
            .any(|finding| matches!(finding.status.as_str(), "blocked" | "unresolved")),
        "no blocked source match requires a rewrite"
    );
    let metadata = fs::symlink_metadata(brief).context("reading independent brief")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 128 * 1024,
        "brief must be a regular file of at most 128 KiB"
    );
    let requirements = fs::read_to_string(brief)?;
    ensure!(
        !requirements.trim().is_empty(),
        "independent behavioral brief is empty"
    );
    let targets: Vec<_> = report
        .files
        .iter()
        .filter(|file| {
            file.findings
                .iter()
                .any(|finding| matches!(finding.status.as_str(), "blocked" | "unresolved"))
        })
        .map(|file| file.path.as_str())
        .collect();
    snapshot.verify_unchanged()?;
    fs::create_dir(output)?;
    fs::write(output.join("requirements.md"), requirements)?;
    fs::write(
        output.join("handoff.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version":1,"agent":agent,"status":"manual_isolation_required","targets":targets,
            "policy_ref":report.policy_ref,"max_attempts":10,
            "instructions":"Start a new non-resumed session in an enforced isolated environment containing only requirements.md and independently approved interfaces/tests. Do not mount the repository, history, source evidence or prior conversations. Test candidate code in a separate restricted sandbox, then run oss-provenance check on the reviewed staged replacement. Stop blocked after 10 unsuccessful attempts. This handoff does not certify clean-room authorship."
        }))?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        check::{FileReport, Finding},
        git::Scope,
        scanner::Candidate,
    };
    use std::process::Command;

    #[test]
    fn handoff_never_copies_source_or_resumes_a_session() {
        let root = tempfile::tempdir().unwrap();
        let mut command = Command::new("git");
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        assert!(
            command
                .args(["init", "-q"])
                .arg(root.path())
                .status()
                .unwrap()
                .success()
        );
        let snapshot = Snapshot::capture(root.path(), Scope::Staged { all: false }).unwrap();
        let report = Report {
            version: 1,
            policy_ref: "admitted".into(),
            policy_sha256: "hash".into(),
            candidate_sha256: "candidate".into(),
            baseline_sha256: "baseline".into(),
            evaluation_only: false,
            issues: vec![],
            files: vec![FileReport {
                path: "src/target.rs".into(),
                status: "unresolved".into(),
                findings: vec![Finding {
                    status: "blocked".into(),
                    reason: "denied".into(),
                    evidence_id: None,
                    candidate: Candidate {
                        id: "snippet".into(),
                        local_ranges: vec![(1, 3)],
                        upstream_ranges: vec![(1, 3)],
                        url: None,
                        file: None,
                        file_hash: None,
                        licenses: vec![],
                        raw: serde_json::json!({"secret":"SUSPECT_SOURCE"}),
                    },
                }],
            }],
        };
        let inputs = tempfile::tempdir().unwrap();
        let brief = inputs.path().join("brief.md");
        fs::write(&brief, "Return the sum of two integers.").unwrap();
        let output = inputs.path().join("handoff");
        prepare_handoff(&snapshot, &report, &brief, &output, "claude").unwrap();
        let contents = fs::read_to_string(output.join("handoff.json")).unwrap();
        assert!(!contents.contains("SUSPECT_SOURCE"));
        assert!(contents.contains("manual_isolation_required"));
        assert_eq!(
            fs::read_to_string(output.join("requirements.md")).unwrap(),
            "Return the sum of two integers."
        );
        assert!(prepare_handoff(&snapshot, &report, &brief, &output, "claude").is_err());
    }
}
