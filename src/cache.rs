use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8] = b"OSSPCACHE\x01";

#[derive(Clone, Debug)]
pub(crate) struct Cache {
    root: Option<PathBuf>,
    max_bytes: u64,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            root: None,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

impl Cache {
    pub(crate) fn from_env() -> Result<Self> {
        let current = std::env::var_os("AI_CLEANROOM_CACHE_DIR");
        let legacy = std::env::var_os("OSS_PROVENANCE_CACHE_DIR");
        ensure!(
            current.is_none() || legacy.is_none() || current == legacy,
            "conflicting cache directories"
        );
        let Some(root) = current.or(legacy) else {
            return Ok(Self::default());
        };
        let mut cache = Self::at(PathBuf::from(root))?;
        if let Some(value) = std::env::var_os("AI_CLEANROOM_CACHE_MAX_BYTES") {
            let limit = value
                .to_str()
                .context("cache byte limit must be UTF8")?
                .parse::<u64>()
                .context("cache byte limit must be a positive integer")?;
            ensure!(
                (1..=1024 * 1024 * 1024 * 1024).contains(&limit),
                "cache byte limit must be 1..1099511627776"
            );
            cache.max_bytes = limit;
        }
        Ok(cache)
    }

    pub(crate) fn at(root: PathBuf) -> Result<Self> {
        ensure!(
            root.is_absolute(),
            "OSS_PROVENANCE_CACHE_DIR must be an absolute path"
        );
        fs::create_dir_all(&root)
            .with_context(|| format!("creating cache directory {}", root.display()))?;
        ensure!(
            fs::symlink_metadata(&root)?.file_type().is_dir(),
            "cache path must be a real dedicated directory"
        );
        Ok(Self {
            root: Some(root),
            ..Self::default()
        })
    }

    pub(crate) fn load(
        &self,
        key: &str,
        max_age: Option<Duration>,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(root) = &self.root else {
            return Ok(None);
        };
        validate_key(key)?;
        let _lock = lock(root)?;
        let path = root.join(key);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => ensure!(
                metadata.file_type().is_file(),
                "cache record must be a regular file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("inspecting cache record"),
        }
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("opening cache record {}", path.display()));
            }
        };
        ensure!(
            file.metadata()?.is_file(),
            "cache record must be a regular file"
        );
        let header_len = MAGIC.len() + 8;
        let mut record = Vec::new();
        file.take(max_bytes + header_len as u64 + 1)
            .read_to_end(&mut record)
            .with_context(|| format!("reading cache record {}", path.display()))?;
        if record.len() < header_len
            || record.len() as u64 > max_bytes + header_len as u64
            || !record.starts_with(MAGIC)
        {
            return Ok(None);
        }
        let stamp = u64::from_be_bytes(record[MAGIC.len()..header_len].try_into()?);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_secs();
        if stamp > now || max_age.is_some_and(|ttl| now - stamp >= ttl.as_secs()) {
            return Ok(None);
        }
        Ok(Some(record.split_off(header_len)))
    }

    pub(crate) fn store(&self, key: &str, body: &[u8]) -> Result<()> {
        let Some(root) = &self.root else {
            return Ok(());
        };
        validate_key(key)?;
        let _lock = lock(root)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_secs();
        let length = u64::try_from(body.len())?
            .checked_add((MAGIC.len() + 8) as u64)
            .context("cache record length overflows")?;
        if length > self.max_bytes {
            eprintln!(
                "cache record exceeds configured byte limit; response was verified but not cached"
            );
            return Ok(());
        }
        let path = root.join(key);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_file(),
                    "cache record must be a regular file"
                );
                let mut header = vec![0; MAGIC.len()];
                let complete = match File::open(&path)?.read_exact(&mut header) {
                    Ok(()) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => false,
                    Err(error) => return Err(error).context("reading existing cache header"),
                };
                if !complete || header != MAGIC {
                    eprintln!(
                        "cache destination is not a recognized record; verified response was not cached and existing file was preserved"
                    );
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspecting cache destination"),
        }
        let mut file = tempfile::NamedTempFile::new_in(root).context("creating cache record")?;
        file.write_all(MAGIC)?;
        file.write_all(&stamp.to_be_bytes())?;
        file.write_all(body)?;
        file.as_file().sync_all()?;
        file.persist(root.join(key))
            .context("publishing cache record")?;
        self.prune(stamp)?;
        File::open(root)?.sync_all()?;
        Ok(())
    }

    fn prune(&self, now: u64) -> Result<()> {
        let root = self.root.as_ref().unwrap();
        let mut records = Vec::new();
        let mut bytes = 0_u64;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(|name| validate_key(name).is_ok())
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            let mut header = [0; 18];
            match File::open(entry.path())?.read_exact(&mut header) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => continue,
                Err(error) => return Err(error).context("reading cache eviction header"),
            }
            if !header.starts_with(MAGIC) {
                continue;
            }
            let stamp = u64::from_be_bytes(header[MAGIC.len()..].try_into()?);
            if stamp > now {
                continue;
            }
            let length = entry.metadata()?.len();
            bytes = bytes.checked_add(length).context("cache size overflows")?;
            records.push((stamp, entry.path(), length));
        }
        records.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        let mut count = records.len();
        for (_, path, length) in records {
            if bytes <= self.max_bytes && count <= 10_000 {
                break;
            }
            fs::remove_file(path).context("evicting owned cache record")?;
            bytes -= length;
            count -= 1;
        }
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<()> {
    ensure!(
        key.len() == 64
            && key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "cache key must be a lowercase SHA256"
    );
    Ok(())
}

fn lock(root: &std::path::Path) -> Result<File> {
    let path = root.join(".ai-cleanroom-cache.lock");
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        ensure!(
            metadata.file_type().is_file(),
            "cache lock must be a regular file"
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                ensure!(Instant::now() < deadline, "cache lock timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error).context("locking cache"),
        }
    }
}

pub(crate) fn key(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"oss-provenance-cache-v1");
    hash.update(env!("CARGO_PKG_VERSION").as_bytes());
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_cache_and_invalid_configuration() {
        let cache = Cache::default();
        cache.store("unused", b"body").unwrap();
        assert!(cache.load("unused", None, 20).unwrap().is_none());
        assert!(Cache::at(PathBuf::from("relative")).is_err());
        let file = tempfile::NamedTempFile::new().unwrap();
        assert!(Cache::at(file.path().to_owned()).is_err());
    }

    #[test]
    fn bounded_records_reject_corruption_future_and_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path().to_owned()).unwrap();
        let key = key(&[b"scanner", b"endpoint", b"content"]);
        cache.store(&key, b"body").unwrap();
        assert_eq!(cache.load(&key, None, 4).unwrap().unwrap(), b"body");
        assert!(cache.load(&key, None, 3).unwrap().is_none());
        let path = directory.path().join(&key);
        let mut record = fs::read(&path).unwrap();
        record[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        fs::write(&path, &record).unwrap();
        assert!(cache.load(&key, None, 4).unwrap().is_none());
        let boundary = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        record[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&boundary.to_be_bytes());
        fs::write(&path, &record).unwrap();
        assert!(
            cache
                .load(&key, Some(Duration::from_secs(3600)), 4)
                .unwrap()
                .is_none()
        );
        record[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&0_u64.to_be_bytes());
        fs::write(&path, &record).unwrap();
        assert!(
            cache
                .load(&key, Some(Duration::from_secs(3600)), 4)
                .unwrap()
                .is_none()
        );
        record[0] = 0;
        fs::write(&path, record).unwrap();
        assert!(cache.load(&key, None, 4).unwrap().is_none());
    }

    #[test]
    fn real_io_errors_are_not_cache_misses() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path().to_owned()).unwrap();
        let key = key(&[b"unreadable"]);
        fs::create_dir(directory.path().join(&key)).unwrap();
        assert!(cache.load(&key, None, 4).is_err());
        assert!(cache.store(&key, b"body").is_err());
    }

    #[test]
    fn keys_separate_namespaces_and_parts() {
        assert_ne!(
            key(&[b"scanner", b"ab", b"c"]),
            key(&[b"scanner", b"a", b"bc"])
        );
        assert_ne!(
            key(&[b"scanner", b"url", b"hash"]),
            key(&[b"source", b"url", b"hash"])
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_records_cannot_be_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::at(directory.path().to_owned()).unwrap();
        let original = key(&[b"original"]);
        let alias = key(&[b"alias"]);
        cache.store(&original, b"body").unwrap();
        std::os::unix::fs::symlink(
            directory.path().join(original),
            directory.path().join(&alias),
        )
        .unwrap();
        assert!(cache.load(&alias, None, 4).is_err());
    }

    #[test]
    fn eviction_bounds_owned_records_and_preserves_unrelated_files() {
        let directory = tempfile::tempdir().unwrap();
        let mut cache = Cache::at(directory.path().to_owned()).unwrap();
        cache.max_bytes = 44;
        let first = key(&[b"first"]);
        cache.store(&first, b"body").unwrap();
        let path = directory.path().join(&first);
        let mut record = fs::read(&path).unwrap();
        record[MAGIC.len()..MAGIC.len() + 8].copy_from_slice(&1_u64.to_be_bytes());
        fs::write(&path, record).unwrap();
        let foreign = key(&[b"foreign"]);
        fs::write(directory.path().join(&foreign), b"unrelated data").unwrap();
        fs::create_dir(directory.path().join(".metadata")).unwrap();
        cache.store(&key(&[b"second"]), b"body").unwrap();
        cache.store(&key(&[b"third"]), b"body").unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::read(directory.path().join(&foreign)).unwrap(),
            b"unrelated data"
        );
        assert!(directory.path().join(".metadata").is_dir());
        cache.store(&foreign, b"body").unwrap();
        assert_eq!(
            fs::read(directory.path().join(&foreign)).unwrap(),
            b"unrelated data"
        );
        let oversized = key(&[b"oversized"]);
        cache.store(&oversized, &[0; 45]).unwrap();
        assert!(!directory.path().join(oversized).exists());
        assert!(cache.load("../outside", None, 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pruning_leaves_symlinks_and_their_targets_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), b"sentinel").unwrap();
        let alias = key(&[b"foreign symlink"]);
        std::os::unix::fs::symlink(outside.path(), directory.path().join(&alias)).unwrap();
        let mut cache = Cache::at(directory.path().to_owned()).unwrap();
        cache.max_bytes = 22;
        cache.store(&key(&[b"one"]), b"body").unwrap();
        cache.store(&key(&[b"two"]), b"body").unwrap();
        assert!(
            fs::symlink_metadata(directory.path().join(&alias))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(outside.path()).unwrap(), b"sentinel");
        assert!(cache.store(&alias, b"body").is_err());
    }

    #[test]
    fn concurrent_process_stores_preserve_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let children: Vec<_> = (0..4)
            .map(|number| {
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "cache::tests::cache_writer_child", "--ignored"])
                    .env("CACHE_TEST_ROOT", directory.path())
                    .env("CACHE_TEST_WRITER", number.to_string())
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap()
            })
            .collect();
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let bytes: u64 = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| validate_key(name).is_ok())
            })
            .map(|entry| entry.metadata().unwrap().len())
            .sum();
        assert_eq!(bytes, 88);
    }

    #[test]
    #[ignore = "spawned by concurrent_process_stores_preserve_capacity"]
    fn cache_writer_child() {
        let mut cache =
            Cache::at(PathBuf::from(std::env::var_os("CACHE_TEST_ROOT").unwrap())).unwrap();
        cache.max_bytes = 88;
        let writer = std::env::var("CACHE_TEST_WRITER").unwrap();
        for number in 0_u32..10 {
            cache
                .store(&key(&[writer.as_bytes(), &number.to_be_bytes()]), b"body")
                .unwrap();
        }
    }
}
