use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8] = b"OSSPCACHE\x01";

#[derive(Clone, Debug, Default)]
pub(crate) struct Cache {
    root: Option<PathBuf>,
}

impl Cache {
    pub(crate) fn from_env() -> Result<Self> {
        let Some(root) = std::env::var_os("OSS_PROVENANCE_CACHE_DIR") else {
            return Ok(Self::default());
        };
        Self::at(PathBuf::from(root))
    }

    pub(crate) fn at(root: PathBuf) -> Result<Self> {
        ensure!(
            root.is_absolute(),
            "OSS_PROVENANCE_CACHE_DIR must be an absolute path"
        );
        fs::create_dir_all(&root)
            .with_context(|| format!("creating cache directory {}", root.display()))?;
        ensure!(root.is_dir(), "cache path must be a directory");
        Ok(Self { root: Some(root) })
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
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock precedes Unix epoch")?
            .as_secs();
        let mut file = tempfile::NamedTempFile::new_in(root).context("creating cache record")?;
        file.write_all(MAGIC)?;
        file.write_all(&stamp.to_be_bytes())?;
        file.write_all(body)?;
        file.as_file().sync_all()?;
        file.persist(root.join(key))
            .context("publishing cache record")?;
        Ok(())
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
}
