use crate::{
    git::{IndexSession, durable_write, durable_write_once},
    policy,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

pub const MAX_ATTEMPTS: u8 = 10;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Ready,
    Reserved,
    Test,
    Scan,
    Apply,
    Applied,
    Exhausted,
    Conflicted,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Failure {
    Tests,
    Provenance,
    InvalidCandidate,
    Interrupted,
}

impl Failure {
    pub fn feedback(self) -> &'static str {
        match self {
            Self::Tests => "The implementation failed independent compilation or behavioral tests.",
            Self::Provenance => {
                "The implementation did not clear the unchanged source provenance policy. Implement independently from the requirements."
            }
            Self::InvalidCandidate => {
                "The response was not a complete valid JSON candidate for the requested paths."
            }
            Self::Interrupted => {
                "The previous independent attempt was interrupted before its outcome was durably recorded."
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub version: u8,
    #[serde(default)]
    pub job: u64,
    pub snapshot: String,
    pub policy_ref: String,
    pub policy_sha256: String,
    pub contract: String,
    pub targets: Vec<String>,
    pub all: bool,
    pub failed: u8,
    pub phase: Phase,
    pub feedback: Option<Failure>,
    pub sessions: BTreeSet<String>,
    pub candidate: Option<BTreeMap<String, Vec<u8>>>,
    pub candidate_sha256: Option<String>,
    pub application_id: Option<String>,
}

impl State {
    pub fn load(session: &IndexSession) -> Result<Option<Self>> {
        let path = session.state_dir.join("repair.json");
        if !path.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 4 * 1024 * 1024,
            "repair state must be a bounded regular file"
        );
        let state: Self = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            state.version == 1 && state.failed <= MAX_ATTEMPTS,
            "invalid repair state version or attempt count"
        );
        let candidate_hash = state
            .candidate
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()?
            .map(|bytes| policy::sha256(&bytes));
        ensure!(
            candidate_hash == state.candidate_sha256,
            "saved candidate hash mismatch"
        );
        ensure!(
            !matches!(state.phase, Phase::Test | Phase::Scan | Phase::Apply)
                || state.candidate.is_some(),
            "saved repair phase has no candidate"
        );
        ensure!(
            !matches!(
                state.phase,
                Phase::Apply | Phase::Applied | Phase::Conflicted
            ) || state
                .application_id
                .as_deref()
                .is_some_and(|id| id.len() == 64
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
            "saved application phase has no valid transaction identity"
        );
        Ok(Some(state))
    }

    pub fn save(&self, session: &IndexSession) -> Result<()> {
        durable_write(
            &session.state_dir.join("repair.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }

    pub fn start_next(&self, next: &Self, session: &IndexSession) -> Result<()> {
        ensure!(
            self.phase == Phase::Applied,
            "only completed repair jobs may be archived"
        );
        durable_write_once(
            &session
                .state_dir
                .join(format!("completed-{}.json", self.job)),
            &serde_json::to_vec_pretty(self)?,
        )?;
        #[cfg(test)]
        tests::crash_at("archive");
        next.save(session)?;
        #[cfg(test)]
        tests::crash_at("ready");
        Ok(())
    }

    pub fn fail(&mut self, failure: Failure, session: &IndexSession) -> Result<()> {
        ensure!(
            self.failed < MAX_ATTEMPTS,
            "repair attempt budget is already exhausted"
        );
        if let Some(candidate) = &self.candidate {
            let name = if self.job == 0 {
                format!("failed-{}.json", self.failed + 1)
            } else {
                format!("failed-{}-{}.json", self.job, self.failed + 1)
            };
            durable_write_once(
                &session.state_dir.join(name),
                &serde_json::to_vec(candidate)?,
            )?;
        }
        self.failed += 1;
        self.feedback = Some(failure);
        self.candidate = None;
        self.candidate_sha256 = None;
        self.application_id = None;
        self.phase = if self.failed == MAX_ATTEMPTS {
            Phase::Exhausted
        } else {
            Phase::Ready
        };
        self.save(session)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingOutcome {
    Reserved,
    ConfirmedFailed,
    OperationalPause,
    InterruptedReconciliation,
    Applied,
    Exhausted,
    InstalledConflict,
}

#[derive(Clone, Debug, Serialize)]
pub struct Accounting {
    pub max_attempts: u8,
    pub failed_attempts: u8,
    pub consumed_attempts: u8,
    pub reserved: bool,
    pub outcome: AccountingOutcome,
}

impl Accounting {
    pub(super) fn new(failed: u8) -> Self {
        Self {
            max_attempts: MAX_ATTEMPTS,
            failed_attempts: failed,
            consumed_attempts: 0,
            reserved: false,
            outcome: AccountingOutcome::OperationalPause,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    pub(super) fn crash_at(point: &str) {
        if std::env::var("AI_CLEANROOM_TEST_ARCHIVE_CRASH").as_deref() == Ok(point) {
            unsafe { libc::_exit(86) }
        }
    }

    fn state(job: u64) -> State {
        State {
            version: 1,
            job,
            snapshot: "snapshot".into(),
            policy_ref: "policy".into(),
            policy_sha256: "policy-hash".into(),
            contract: "contract".into(),
            targets: vec!["source.rs".into()],
            all: false,
            failed: 0,
            phase: Phase::Ready,
            feedback: None,
            sessions: BTreeSet::new(),
            candidate: None,
            candidate_sha256: None,
            application_id: None,
        }
    }

    fn child(root: &std::path::Path) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "repair::state::tests::archive_child",
                "--ignored",
            ])
            .env("AI_CLEANROOM_TEST_ARCHIVE_ROOT", root);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
    }

    #[test]
    #[ignore = "private subprocess worker"]
    fn archive_child() {
        let root =
            std::path::PathBuf::from(std::env::var_os("AI_CLEANROOM_TEST_ARCHIVE_ROOT").unwrap());
        let session = IndexSession::open(&root).unwrap();
        let old = State::load(&session).unwrap().unwrap();
        if old.job == 0 {
            old.start_next(&state(1), &session).unwrap();
        }
    }

    #[test]
    fn archive_crashes_preserve_history_and_resume_the_next_job_once() {
        for point in ["archive", "ready"] {
            let root = tempfile::tempdir().unwrap();
            let mut git = Command::new("git");
            git.args(["-C", root.path().to_str().unwrap(), "init", "-q"]);
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("GIT_") {
                    git.env_remove(key);
                }
            }
            assert!(git.status().unwrap().success());
            let session = IndexSession::open(root.path()).unwrap();
            let mut old = state(0);
            old.candidate = Some(BTreeMap::from([(
                "source.rs".into(),
                b"failed original".to_vec(),
            )]));
            old.fail(Failure::Tests, &session).unwrap();
            old.phase = Phase::Applied;
            old.application_id = Some("a".repeat(64));
            old.sessions.insert("original-session".into());
            old.save(&session).unwrap();
            let original = fs::read(session.state_dir.join("repair.json")).unwrap();
            let artifact = fs::read(session.state_dir.join("failed-1.json")).unwrap();
            let directory = session.state_dir.clone();
            drop(session);
            let crashed = child(root.path())
                .env("AI_CLEANROOM_TEST_ARCHIVE_CRASH", point)
                .output()
                .unwrap();
            assert_eq!(crashed.status.code(), Some(86), "{crashed:?}");
            assert_eq!(
                fs::read(directory.join("completed-0.json")).unwrap(),
                original
            );
            let session = IndexSession::open(root.path()).unwrap();
            assert_eq!(
                State::load(&session).unwrap().unwrap().job,
                u64::from(point == "ready")
            );
            drop(session);
            assert!(child(root.path()).status().unwrap().success());
            let session = IndexSession::open(root.path()).unwrap();
            let mut next = State::load(&session).unwrap().unwrap();
            assert_eq!(next.job, 1);
            assert_eq!(next.failed, 0);
            next.candidate = Some(BTreeMap::from([(
                "source.rs".into(),
                b"failed next".to_vec(),
            )]));
            next.fail(Failure::Tests, &session).unwrap();
            assert!(directory.join("failed-1-1.json").exists());
            assert_eq!(fs::read(directory.join("failed-1.json")).unwrap(), artifact);
            assert_eq!(
                fs::read(directory.join("completed-0.json")).unwrap(),
                original
            );
        }
    }
}
