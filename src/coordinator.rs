use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub(crate) struct Coordinator {
    root: PathBuf,
    key: String,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    last_wall_ms: u64,
    next_allowed_ms: u64,
    #[serde(default)]
    in_flight: bool,
}

pub(crate) struct Turn {
    _lock: File,
    path: PathBuf,
    state: State,
    deadline: Instant,
}

impl Coordinator {
    #[cfg(not(test))]
    pub(crate) fn from_env(endpoint: &str) -> Result<Self> {
        let current = std::env::var_os("AI_CLEANROOM_STATE_DIR");
        let legacy = std::env::var_os("OSS_PROVENANCE_STATE_DIR");
        ensure!(
            current.is_none() || legacy.is_none() || current == legacy,
            "conflicting scanner state directories"
        );
        let root = match current.or(legacy) {
            Some(path) => PathBuf::from(path),
            None => PathBuf::from(
                std::env::var_os("HOME").context("HOME required for scanner coordination")?,
            )
            .join(".local/state/ai-cleanroom"),
        };
        Self::at(root, endpoint)
    }

    pub(crate) fn at(root: PathBuf, endpoint: &str) -> Result<Self> {
        ensure!(
            root.is_absolute(),
            "scanner state directory must be absolute"
        );
        fs::create_dir_all(&root).context("creating scanner state directory")?;
        ensure!(
            fs::symlink_metadata(&root)?.file_type().is_dir(),
            "scanner state directory must be a real directory"
        );
        Ok(Self {
            root,
            key: format!("{:x}", Sha256::digest(endpoint.as_bytes())),
        })
    }

    pub(crate) fn acquire(&self, deadline: Instant) -> Result<Turn> {
        let lock_path = self.root.join(format!("{}.lock", self.key));
        if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
            ensure!(
                metadata.file_type().is_file(),
                "scanner lock must be a regular file"
            );
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .context("opening scanner coordinator lock")?;
        loop {
            ensure!(
                Instant::now() < deadline,
                "scanner total timeout exhausted waiting for shared lock"
            );
            match lock.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) => {
                    std::thread::sleep(
                        Duration::from_millis(25)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(error).context("locking scanner coordinator");
                }
            }
        }
        let path = self.root.join(format!("{}.json", self.key));
        let state = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_file(),
                    "scanner state must be a regular file"
                );
                let mut bytes = Vec::new();
                File::open(&path)?.take(4097).read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 4096, "scanner state exceeds limit");
                serde_json::from_slice(&bytes).context("invalid scanner coordinator state")?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(error) => return Err(error).context("reading scanner coordinator state"),
        };
        let mut turn = Turn {
            _lock: lock,
            path,
            state,
            deadline,
        };
        if turn.state.in_flight {
            turn.complete()?;
        }
        Ok(turn)
    }
}

impl Turn {
    pub(crate) fn before_post(&mut self) -> Result<()> {
        let now = self.now()?;
        let delay = Duration::from_millis(self.state.next_allowed_ms.saturating_sub(now));
        ensure!(
            delay < self.deadline.saturating_duration_since(Instant::now()),
            "shared scanner cooldown exceeds remaining total timeout; no request sent"
        );
        std::thread::sleep(delay);
        self.state.in_flight = true;
        self.defer(Duration::from_secs(1))
    }

    pub(crate) fn complete(&mut self) -> Result<()> {
        self.state.in_flight = false;
        self.defer(Duration::from_secs(1))
    }

    pub(crate) fn defer(&mut self, delay: Duration) -> Result<()> {
        let now = self.now()?;
        let milliseconds =
            u64::try_from(delay.as_millis()).context("scanner cooldown overflows")?;
        self.state.last_wall_ms = now;
        self.state.next_allowed_ms = self.state.next_allowed_ms.max(
            now.checked_add(milliseconds)
                .context("scanner cooldown timestamp overflows")?,
        );
        let mut temporary = tempfile::NamedTempFile::new_in(self.path.parent().unwrap())?;
        temporary.write_all(&serde_json::to_vec(&self.state)?)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .context("saving scanner cooldown")?;
        File::open(self.path.parent().unwrap())?.sync_all()?;
        Ok(())
    }

    fn now(&self) -> Result<u64> {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock precedes Unix epoch")?
                .as_millis(),
        )?;
        ensure!(
            now >= self.state.last_wall_ms,
            "system clock moved backwards; scanner coordination paused"
        );
        Ok(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_survives_a_new_coordinator_and_respects_one_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let coordinator = Coordinator::at(directory.path().to_owned(), "fixture").unwrap();
        let mut turn = coordinator
            .acquire(Instant::now() + Duration::from_secs(5))
            .unwrap();
        turn.before_post().unwrap();
        turn.defer(Duration::from_secs(60)).unwrap();
        drop(turn);
        let mut resumed = Coordinator::at(directory.path().to_owned(), "fixture")
            .unwrap()
            .acquire(Instant::now() + Duration::from_millis(50))
            .unwrap();
        assert!(
            resumed
                .before_post()
                .unwrap_err()
                .to_string()
                .contains("cooldown")
        );
    }

    #[test]
    fn malformed_state_and_clock_reversal_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let coordinator = Coordinator::at(directory.path().to_owned(), "fixture").unwrap();
        let path = directory.path().join(format!("{}.json", coordinator.key));
        fs::write(&path, b"{}").unwrap();
        assert!(
            coordinator
                .acquire(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        fs::write(
            &path,
            serde_json::to_vec(&State {
                last_wall_ms: u64::MAX,
                next_allowed_ms: u64::MAX,
                in_flight: false,
            })
            .unwrap(),
        )
        .unwrap();
        let mut turn = coordinator
            .acquire(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert!(turn.before_post().is_err());
    }

    #[test]
    fn independent_processes_serialize_and_recover_after_death() {
        use std::process::Command;
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("started");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "coordinator::tests::coordinator_child",
                "--ignored",
            ])
            .env("COORDINATOR_TEST_ROOT", directory.path())
            .env("COORDINATOR_TEST_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let wait = Instant::now() + Duration::from_secs(5);
        while !marker.exists() && Instant::now() < wait {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.exists());
        let coordinator = Coordinator::at(directory.path().to_owned(), "process-fixture").unwrap();
        assert!(
            coordinator
                .acquire(Instant::now() + Duration::from_millis(50))
                .is_err()
        );
        child.kill().unwrap();
        child.wait().unwrap();
        let mut resumed = coordinator
            .acquire(Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert!(
            resumed
                .before_post()
                .unwrap_err()
                .to_string()
                .contains("cooldown")
        );
    }

    #[test]
    fn interrupted_dispatch_requires_a_fresh_conservative_delay() {
        let directory = tempfile::tempdir().unwrap();
        let coordinator = Coordinator::at(directory.path().to_owned(), "dispatch-fixture").unwrap();
        let mut turn = coordinator
            .acquire(Instant::now() + Duration::from_secs(5))
            .unwrap();
        turn.before_post().unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        drop(turn);
        let start = Instant::now();
        let mut next = coordinator
            .acquire(Instant::now() + Duration::from_secs(3))
            .unwrap();
        next.before_post().unwrap();
        assert!(start.elapsed() >= Duration::from_secs(1));
    }

    #[test]
    #[ignore = "spawned by independent_processes_serialize_and_recover_after_death"]
    fn coordinator_child() {
        let directory = std::env::var_os("COORDINATOR_TEST_ROOT").unwrap();
        let coordinator = Coordinator::at(PathBuf::from(directory), "process-fixture").unwrap();
        let mut turn = coordinator
            .acquire(Instant::now() + Duration::from_secs(5))
            .unwrap();
        turn.before_post().unwrap();
        turn.defer(Duration::from_secs(60)).unwrap();
        fs::write(
            std::env::var_os("COORDINATOR_TEST_MARKER").unwrap(),
            b"locked",
        )
        .unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }
}
