use crate::{git::IndexSession, policy, sandbox};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub version: u8,
    pub provider_image: String,
    pub test_image: String,
    pub requirements: PathBuf,
    pub tests: PathBuf,
    pub test_command: Vec<String>,
    pub targets: Vec<String>,
}

pub(super) struct Frozen {
    pub config: Config,
    pub requirements: String,
    pub tests: BTreeMap<String, Vec<u8>>,
    pub hash: String,
}

pub(super) fn validate_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut normalized = BTreeSet::new();
    for path in paths {
        policy::safe_path(path)?;
        ensure!(
            path.is_ascii() && !path.contains(['\\', '\0', '\n', '\r']),
            "repair paths must be plain ASCII relative paths"
        );
        ensure!(
            normalized.insert(path.to_ascii_lowercase()),
            "case-colliding or repeated paths"
        );
    }
    for path in &normalized {
        for (index, byte) in path.bytes().enumerate() {
            if byte == b'/' {
                ensure!(
                    !normalized.contains(&path[..index]),
                    "prefix-conflicting paths"
                );
            }
        }
    }
    Ok(())
}

fn external(path: &Path, session: &IndexSession, directory: bool) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "repair inputs must use absolute paths");
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
        "repair input has an unsupported file type"
    );
    let canonical = fs::canonicalize(path)?;
    for forbidden in [&session.root, &session.common_dir] {
        ensure!(
            !canonical.starts_with(forbidden) && !forbidden.starts_with(&canonical),
            "repair inputs must be outside repository and Git metadata ancestry"
        );
    }
    Ok(canonical)
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit as u64,
        "approved input must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "approved input grew beyond size limit"
    );
    Ok(bytes)
}

fn read_tests(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    remaining: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "trusted test snapshot cannot contain symlinks"
        );
        if metadata.is_dir() {
            read_tests(root, &entry.path(), files, remaining)?;
        } else {
            ensure!(files.len() < 256, "trusted test snapshot exceeds 256 files");
            let bytes = read_regular(&entry.path(), *remaining)?;
            *remaining -= bytes.len();
            let name = entry
                .path()
                .strip_prefix(root)?
                .to_str()
                .context("test path is not UTF-8")?
                .to_owned();
            files.insert(name, bytes);
        }
    }
    Ok(())
}

impl Frozen {
    pub fn load(path: &Path, session: &IndexSession) -> Result<Self> {
        let path = external(path, session, false)?;
        let bytes = read_regular(&path, 128 * 1024)?;
        let mut config: Config = toml::from_str(std::str::from_utf8(&bytes)?)?;
        ensure!(config.version == 1, "unsupported repair config version");
        sandbox::validate_image(&config.provider_image)?;
        sandbox::validate_image(&config.test_image)?;
        ensure!(
            !config.targets.is_empty() && config.targets.len() <= 32,
            "repair requires 1 to 32 targets"
        );
        validate_paths(config.targets.iter().map(String::as_str))?;
        config.targets.sort();
        ensure!(
            !config.test_command.is_empty()
                && config.test_command[0].starts_with('/')
                && config.test_command.iter().all(|arg| !arg.contains('\0')),
            "test command requires an absolute container executable and valid argv"
        );
        config.requirements = external(&config.requirements, session, false)?;
        config.tests = external(&config.tests, session, true)?;
        let requirements = String::from_utf8(read_regular(&config.requirements, 128 * 1024)?)?;
        ensure!(
            !requirements.trim().is_empty(),
            "independent requirements are empty"
        );
        let mut tests = BTreeMap::new();
        read_tests(
            &config.tests,
            &config.tests,
            &mut tests,
            &mut (8 * 1024 * 1024),
        )?;
        ensure!(!tests.is_empty(), "trusted test directory is empty");
        validate_paths(tests.keys().map(String::as_str))?;
        let hash = policy::sha256(&serde_json::to_vec(&(&config, &requirements, &tests))?);
        Ok(Self {
            config,
            requirements,
            tests,
            hash,
        })
    }

    pub fn prompt(&self, feedback: &str) -> Result<String> {
        Ok(format!(
            "Independent requirements:\n{}\n\nTarget paths: {}\nReturn exactly {{\"files\":[{{\"path\":\"one target path\",\"content\":\"complete source\"}}]}} covering every target.\nBehavioral feedback: {}",
            self.requirements,
            serde_json::to_string(&self.config.targets)?,
            feedback
        ))
    }
}

pub(super) fn materialize(directory: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    validate_paths(files.keys().map(String::as_str))?;
    fs::create_dir(directory)?;
    for (name, bytes) in files {
        let path = directory.join(name);
        fs::create_dir_all(path.parent().context("file has no parent")?)?;
        fs::write(path, bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_tests_keep_original_bytes_after_inputs_change() {
        let inputs = tempfile::tempdir().unwrap();
        let tests = inputs.path().join("tests");
        fs::create_dir(&tests).unwrap();
        fs::write(tests.join("verify.sh"), b"approved bytes\n").unwrap();
        let mut frozen = BTreeMap::new();
        read_tests(&tests, &tests, &mut frozen, &mut 1024).unwrap();
        fs::write(tests.join("verify.sh"), b"mutated bytes\n").unwrap();
        let output = inputs.path().join("frozen");
        materialize(&output, &frozen).unwrap();
        assert_eq!(
            fs::read(output.join("verify.sh")).unwrap(),
            b"approved bytes\n"
        );
        std::os::unix::fs::symlink("verify.sh", tests.join("link.sh")).unwrap();
        assert!(read_tests(&tests, &tests, &mut BTreeMap::new(), &mut 1024).is_err());
        assert!(read_regular(&tests.join("link.sh"), 1024).is_err());
    }

    #[test]
    fn paths_reject_collisions_before_materializing() {
        for paths in [
            ["A/test", "a/Test"],
            ["a", "a/test"],
            ["../escape", "valid"],
            ["a\\b", "valid"],
        ] {
            assert!(validate_paths(paths).is_err());
        }
        assert!(validate_paths(["src/a.rs", "tests/a.rs"]).is_ok());
    }
}
