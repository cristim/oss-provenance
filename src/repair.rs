use crate::{check::Report, git::Snapshot};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

mod config;
mod state;
pub use state::{Accounting, AccountingOutcome};

#[derive(Debug)]
pub struct RepairFailure {
    pub message: String,
    pub accounting: Accounting,
}

impl std::fmt::Display for RepairFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for RepairFailure {}

#[derive(serde::Serialize)]
pub struct RepairOutcome {
    pub version: u8,
    pub status: &'static str,
    pub accounting: Accounting,
    pub report: Option<Report>,
}

pub fn run(
    root: &Path,
    reference: Option<&str>,
    all: bool,
    config_path: &Path,
) -> Result<RepairOutcome> {
    use crate::{
        check,
        git::{ApplicationStatus, CompletedApplication, IndexSession, Scope},
        policy, sandbox,
    };
    use state::{Failure, MAX_ATTEMPTS, Phase, State};
    let session = IndexSession::open(root)?;
    let mut existing = State::load(&session)?;
    let mut accounting = Accounting::new(existing.as_ref().map_or(0, |state| state.failed));
    if existing
        .as_ref()
        .is_some_and(|state| state.phase == Phase::Reserved)
    {
        accounting.reserved = true;
        accounting.outcome = AccountingOutcome::Reserved;
    }
    let operation = (|| -> Result<RepairOutcome> {
        let mut rollover = false;
        if let Some(state) = &mut existing {
            if state.phase == Phase::Conflicted {
                accounting.outcome = AccountingOutcome::InstalledConflict;
                anyhow::bail!(
                    "replacement was installed with a conflict; manual conflict review is required"
                );
            }
            if state.phase == Phase::Applied {
                ensure!(
                    session.recover()?.is_none(),
                    "a pending index application was recovered; rerun repair"
                );
                let current = Snapshot::capture(root, Scope::Staged { all })?;
                match session.completed_application(
                    state
                        .application_id
                        .as_deref()
                        .context("missing application identity")?,
                    &current,
                )? {
                    Some(CompletedApplication::SameIndex) => {
                        accounting.outcome = AccountingOutcome::Applied;
                        return Ok(RepairOutcome {
                            version: 1,
                            status: "applied",
                            accounting: accounting.clone(),
                            report: None,
                        });
                    }
                    Some(CompletedApplication::AdmissionConflict) => {
                        state.phase = Phase::Conflicted;
                        state.save(&session)?;
                        accounting.outcome = AccountingOutcome::InstalledConflict;
                        anyhow::bail!(
                            "replacement was installed but admitted policy changed; manual conflict review is required"
                        );
                    }
                    Some(CompletedApplication::ChangedIndex) => rollover = true,
                    None => {}
                }
            }
        }
        let previous = if rollover { existing.take() } else { None };
        if let Some(state) = &mut existing {
            if matches!(
                state.phase,
                Phase::Apply | Phase::Applied | Phase::Conflicted
            ) {
                match session.recover_application(
                    state
                        .application_id
                        .as_deref()
                        .context("missing application identity")?,
                )? {
                    Some(ApplicationStatus::Applied) => {
                        state.phase = Phase::Applied;
                        state.save(&session)?;
                        accounting.outcome = AccountingOutcome::Applied;
                        return Ok(RepairOutcome {
                            version: 1,
                            status: "applied",
                            accounting: accounting.clone(),
                            report: None,
                        });
                    }
                    Some(ApplicationStatus::InstalledButConflicted) => {
                        state.phase = Phase::Conflicted;
                        state.save(&session)?;
                        accounting.outcome = AccountingOutcome::InstalledConflict;
                        anyhow::bail!(
                            "replacement was installed but HEAD or policy changed; manual conflict review is required"
                        );
                    }
                    _ => ensure!(
                        state.phase == Phase::Apply,
                        "terminal repair has no matching application journal"
                    ),
                }
            } else {
                ensure!(
                    session.recover()?.is_none(),
                    "another pending index application was recovered; rerun repair"
                );
            }
        } else {
            ensure!(
                session.recover()?.is_none(),
                "a pending index application was recovered; rerun repair"
            );
        }
        let reference = check::admitted_ref(root, reference)?;
        let frozen = config::Frozen::load(config_path, &session)?;
        if let Some(state) = &existing {
            ensure!(
                state.contract == frozen.hash
                    && state.targets == frozen.config.targets
                    && state.all == all
                    && state.policy_ref == reference,
                "approved repair contract or policy changed; refusing to reset the attempt budget"
            );
        }
        let original = Snapshot::capture(root, Scope::Staged { all })?;
        session.validate_supported(&original)?;
        config::validate_paths(original.files.keys().map(String::as_str))?;
        let (resolved_ref, policy_bytes, policy) =
            check::trusted_policy(&original, &reference, false)?;
        let identity = original.staged_identity()?;
        let mut state = if let Some(state) = existing.take() {
            ensure!(
                state.snapshot == identity && state.policy_sha256 == policy::sha256(&policy_bytes),
                "original index, HEAD, or admitted policy changed; saved repair cannot continue"
            );
            state
        } else {
            let (_, report) = check::check_snapshot(&original, &reference, all, false)?;
            ensure!(
                report.issues.is_empty(),
                "repair cannot resolve notice-ledger or policy issues"
            );
            ensure!(
                !report
                    .files
                    .iter()
                    .any(|file| file.status == "unresolved" && file.findings.is_empty()),
                "unsupported scanner coverage must be resolved before rewriting"
            );
            let targets: std::collections::BTreeSet<_> = report
                .files
                .iter()
                .filter(|file| {
                    file.findings
                        .iter()
                        .any(|finding| matches!(finding.status.as_str(), "blocked" | "unresolved"))
                })
                .map(|file| file.path.as_str())
                .collect();
            ensure!(
                !targets.is_empty()
                    && targets == frozen.config.targets.iter().map(String::as_str).collect(),
                "repair targets must exactly match blocked or unresolved source findings"
            );
            let state = State {
                version: 1,
                job: previous.as_ref().map_or(Ok(0), |state| {
                    state
                        .job
                        .checked_add(1)
                        .context("repair job counter exhausted")
                })?,
                snapshot: identity,
                policy_ref: resolved_ref,
                policy_sha256: policy::sha256(&policy_bytes),
                contract: frozen.hash.clone(),
                targets: frozen.config.targets.clone(),
                all,
                failed: 0,
                phase: Phase::Ready,
                feedback: None,
                sessions: Default::default(),
                candidate: None,
                candidate_sha256: None,
                application_id: None,
            };
            original.verify_unchanged()?;
            if let Some(previous) = &previous {
                previous.start_next(&state, &session)?;
            } else {
                state.save(&session)?;
            }
            accounting = Accounting::new(0);
            state
        };
        if state.phase == Phase::Reserved {
            state.fail(Failure::Interrupted, &session)?;
            accounting.failed_attempts = state.failed;
            accounting.consumed_attempts += 1;
            accounting.reserved = false;
            accounting.outcome = AccountingOutcome::InterruptedReconciliation;
        }
        loop {
            if state.failed == MAX_ATTEMPTS || state.phase == Phase::Exhausted {
                accounting.outcome = AccountingOutcome::Exhausted;
                return Ok(RepairOutcome {
                    version: 1,
                    status: "exhausted",
                    accounting: accounting.clone(),
                    report: None,
                });
            }
            original.verify_unchanged()?;
            if state.phase == Phase::Ready {
                state.phase = Phase::Reserved;
                state.save(&session)?;
                accounting.reserved = true;
                accounting.outcome = AccountingOutcome::Reserved;
                let prompt = frozen.prompt(
                    state
                        .feedback
                        .map_or("No previous attempt.", Failure::feedback),
                )?;
                match sandbox::generate(
                    &frozen.config.provider_image,
                    &prompt,
                    &state.targets,
                    &state.sessions,
                ) {
                    Ok(generated) => {
                        state.sessions.insert(generated.session_id);
                        state.candidate_sha256 =
                            Some(policy::sha256(&serde_json::to_vec(&generated.files)?));
                        state.candidate = Some(generated.files);
                        state.phase = Phase::Test;
                        state.save(&session)?;
                        accounting.reserved = false;
                        if let Some(message) = generated.cleanup_error {
                            anyhow::bail!("provider candidate saved; {message}");
                        }
                    }
                    Err(error)
                        if matches!(
                            error.downcast_ref::<sandbox::ProviderFailure>(),
                            Some(sandbox::ProviderFailure::InvalidCandidate { .. })
                        ) =>
                    {
                        if let Some(sandbox::ProviderFailure::InvalidCandidate {
                            session_id, ..
                        }) = error.downcast_ref::<sandbox::ProviderFailure>()
                        {
                            state.sessions.insert(session_id.clone());
                        }
                        state.fail(Failure::InvalidCandidate, &session)?;
                        accounting.failed_attempts = state.failed;
                        accounting.consumed_attempts += 1;
                        accounting.reserved = false;
                        accounting.outcome = AccountingOutcome::ConfirmedFailed;
                        if let Some(sandbox::ProviderFailure::InvalidCandidate {
                            cleanup_error: Some(message),
                            ..
                        }) = error.downcast_ref::<sandbox::ProviderFailure>()
                        {
                            anyhow::bail!("invalid candidate failure recorded; {message}");
                        }
                        continue;
                    }
                    Err(error) => {
                        state.phase = Phase::Ready;
                        state.save(&session)?;
                        accounting.reserved = false;
                        accounting.outcome = AccountingOutcome::OperationalPause;
                        return Err(error).context("provider execution paused");
                    }
                }
            }
            let files = state
                .candidate
                .as_ref()
                .context("saved repair phase has no candidate")?;
            ensure!(
                files
                    .keys()
                    .map(String::as_str)
                    .eq(state.targets.iter().map(String::as_str)),
                "saved candidate target mismatch"
            );
            if state.phase == Phase::Test {
                let frozen_execution = tempfile::Builder::new()
                    .prefix("ai-cleanroom-frozen-")
                    .tempdir()?;
                let candidate_path = frozen_execution.path().join("candidate");
                let trusted_path = frozen_execution.path().join("trusted");
                config::materialize(&candidate_path, files)?;
                config::materialize(&trusted_path, &frozen.tests)?;
                let outcome = sandbox::test(
                    &frozen.config.test_image,
                    &candidate_path,
                    &trusted_path,
                    &frozen.config.test_command,
                )?;
                if !outcome.passed {
                    state.fail(Failure::Tests, &session)?;
                    accounting.failed_attempts = state.failed;
                    accounting.consumed_attempts += 1;
                    accounting.outcome = AccountingOutcome::ConfirmedFailed;
                    if let Some(message) = outcome.cleanup_error {
                        anyhow::bail!("failed test attempt recorded; {message}");
                    }
                    continue;
                }
                state.phase = Phase::Scan;
                state.save(&session)?;
                if let Some(message) = outcome.cleanup_error {
                    anyhow::bail!("passing test outcome saved; {message}");
                }
            }
            let candidate =
                original.overlay(state.candidate.as_ref().context("missing candidate")?)?;
            let (_, mut report) = check::check_snapshot(&candidate, &reference, all, false)?;
            let verified = if !report.passed() {
                if !report.issues.is_empty()
                    || report.files.iter().any(|file| {
                        file.findings.iter().any(|finding| {
                            matches!(finding.status.as_str(), "blocked" | "unresolved")
                        })
                    })
                {
                    state.fail(Failure::Provenance, &session)?;
                    accounting.failed_attempts = state.failed;
                    accounting.consumed_attempts += 1;
                    accounting.outcome = AccountingOutcome::ConfirmedFailed;
                    continue;
                }
                check::ensure_resolvable(&report)?;
                let proposed = crate::notices::resolution(
                    &candidate,
                    &policy,
                    &report,
                    "Independently generated replacement",
                )?;
                let with_notices = candidate.overlay(&proposed)?;
                let (_, resolved) = check::check_snapshot(&with_notices, &reference, all, false)?;
                ensure!(
                    resolved.passed(),
                    "candidate verification remains unresolved"
                );
                report = resolved;
                with_notices
            } else {
                candidate
            };
            state.application_id = Some(IndexSession::application_identity(
                &original, &verified, &reference,
            )?);
            state.phase = Phase::Apply;
            state.save(&session)?;
            if session.apply(&original, &verified, &reference)? != ApplicationStatus::Applied {
                state.phase = Phase::Conflicted;
                state.save(&session)?;
                accounting.outcome = AccountingOutcome::InstalledConflict;
                anyhow::bail!("replacement installed with concurrent HEAD or policy conflict");
            }
            state.phase = Phase::Applied;
            state.save(&session)?;
            accounting.outcome = AccountingOutcome::Applied;
            return Ok(RepairOutcome {
                version: 1,
                status: "applied",
                accounting: accounting.clone(),
                report: Some(report),
            });
        }
    })();
    operation.map_err(|error| {
        if !accounting.reserved
            && !matches!(accounting.outcome, AccountingOutcome::InstalledConflict)
        {
            accounting.outcome = AccountingOutcome::OperationalPause;
        }
        RepairFailure {
            message: format!("{error:#}"),
            accounting,
        }
        .into()
    })
}

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
