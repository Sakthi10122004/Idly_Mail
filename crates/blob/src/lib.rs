//! Content-addressed blobs: each message is stored once, under the BLAKE3
//! hash of its bytes, however many mailboxes or accounts hold it.
//!
//! The disk backend writes `<root>/ab/cd/<hash>` like the queue writes
//! spool files: a temporary file, fsync, rename, fsync of the directory.
//! A blob is therefore either completely there or not at all after a
//! crash. Reads verify the hash, so silent corruption is reported instead
//! of served. Reference counting is the store's job; this crate only
//! stores, reads, lists and deletes.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// A blob's address: the BLAKE3 hash of its content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// The id `data` would get.
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses the 64-character lower-case hex form.
    pub fn parse(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = hex.get(i * 2..i * 2 + 2)?;
            if !pair
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return None;
            }
            *byte = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({self})")
    }
}

/// Where blobs live. Calls block; async callers use `spawn_blocking`.
pub trait BlobStore: Send + Sync + 'static {
    /// Stores `data` durably and returns its id. Storing the same bytes
    /// again is cheap and returns the same id.
    fn put(&self, data: &[u8]) -> io::Result<BlobId>;
    /// The blob's bytes, None if absent. Corrupt data is an
    /// [`io::ErrorKind::InvalidData`] error.
    fn get(&self, id: &BlobId) -> io::Result<Option<Vec<u8>>>;
    /// Whether the blob exists.
    fn exists(&self, id: &BlobId) -> io::Result<bool>;
    /// Removes the blob; false if it wasn't there.
    fn delete(&self, id: &BlobId) -> io::Result<bool>;
    /// Every blob with its modification time, for garbage collection.
    fn list(&self) -> io::Result<Vec<(BlobId, SystemTime)>>;
}

/// Blobs as files on local disk.
#[derive(Debug)]
pub struct Disk {
    root: PathBuf,
    counter: AtomicU64,
}

impl Disk {
    /// Opens (creating) the directory and removes temporary files left by
    /// a crash.
    pub fn open(root: &Path) -> io::Result<Self> {
        let tmp = root.join("tmp");
        fs::create_dir_all(&tmp)?;
        for e in fs::read_dir(&tmp)? {
            fs::remove_file(e?.path())?;
        }
        Ok(Self {
            root: root.into(),
            counter: AtomicU64::new(0),
        })
    }

    fn path(&self, id: &BlobId) -> PathBuf {
        let hex = id.to_string();
        let (a, rest) = hex.split_at(2);
        let (b, _) = rest.split_at(2);
        self.root.join(a).join(b).join(&hex)
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

impl BlobStore for Disk {
    fn put(&self, data: &[u8]) -> io::Result<BlobId> {
        let id = BlobId::of(data);
        let path = self.path(&id);
        if path.exists() {
            return Ok(id);
        }
        let dir = path.parent().unwrap_or(&self.root).to_path_buf();
        let parent_existed = dir.exists();
        fs::create_dir_all(&dir)?;
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{id}.{}.{n}", std::process::id()));
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &path)?;
        sync_dir(&dir)?;
        if !parent_existed {
            // New directories must be durable too.
            if let Some(up) = dir.parent() {
                sync_dir(up)?;
                if let Some(top) = up.parent() {
                    sync_dir(top)?;
                }
            }
        }
        Ok(id)
    }

    fn get(&self, id: &BlobId) -> io::Result<Option<Vec<u8>>> {
        let data = match fs::read(self.path(id)) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if BlobId::of(&data) != *id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("blob {id} is corrupt"),
            ));
        }
        Ok(Some(data))
    }

    fn exists(&self, id: &BlobId) -> io::Result<bool> {
        self.path(id).try_exists()
    }

    fn delete(&self, id: &BlobId) -> io::Result<bool> {
        match fs::remove_file(self.path(id)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn list(&self) -> io::Result<Vec<(BlobId, SystemTime)>> {
        let mut out = Vec::new();
        for a in fs::read_dir(&self.root)? {
            let a = a?;
            if a.file_name() == "tmp" || !a.file_type()?.is_dir() {
                continue;
            }
            for b in fs::read_dir(a.path())? {
                let b = b?;
                if !b.file_type()?.is_dir() {
                    continue;
                }
                for f in fs::read_dir(b.path())? {
                    let f = f?;
                    let Some(id) = f.file_name().to_str().and_then(BlobId::parse) else {
                        continue;
                    };
                    out.push((id, f.metadata()?.modified()?));
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_dedup_delete() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Disk::open(dir.path()).unwrap();
        let id = disk.put(b"hello").unwrap();
        assert_eq!(
            id.to_string(),
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
        assert_eq!(disk.put(b"hello").unwrap(), id, "same bytes, same id");
        assert_eq!(disk.get(&id).unwrap().as_deref(), Some(&b"hello"[..]));
        assert!(disk.exists(&id).unwrap());
        assert!(dir.path().join("ea/8f").join(id.to_string()).is_file());
        assert_eq!(disk.list().unwrap().len(), 1);
        assert!(disk.delete(&id).unwrap());
        assert!(!disk.delete(&id).unwrap());
        assert_eq!(disk.get(&id).unwrap(), None);
        assert!(disk.list().unwrap().is_empty());
    }

    #[test]
    fn corruption_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let disk = Disk::open(dir.path()).unwrap();
        let id = disk.put(b"original").unwrap();
        fs::write(disk.path(&id), b"tampered").unwrap();
        let err = disk.get(&id).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn crash_leftovers_are_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        drop(Disk::open(dir.path()).unwrap());
        fs::write(dir.path().join("tmp/half-written"), b"x").unwrap();
        let disk = Disk::open(dir.path()).unwrap();
        assert_eq!(fs::read_dir(dir.path().join("tmp")).unwrap().count(), 0);
        assert!(disk.list().unwrap().is_empty());
    }

    #[test]
    fn ids_round_trip() {
        let id = BlobId::of(b"x");
        assert_eq!(BlobId::parse(&id.to_string()), Some(id));
        assert_eq!(BlobId::parse("zz"), None);
        assert_eq!(BlobId::parse(&"A".repeat(64)), None);
        assert_eq!(BlobId::parse(&"é".repeat(32)), None);
    }
}
