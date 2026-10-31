//! Free disk space, for the storage guard.

use std::path::Path;

/// Reports free space on the filesystem holding a path.
pub trait SpaceProbe: Send + Sync + 'static {
    /// Bytes available to an unprivileged user on `path`'s filesystem.
    fn available(&self, path: &Path) -> std::io::Result<u64>;
}

/// The real probe: `statvfs(2)` through rustix (no unsafe code here).
#[derive(Debug, Clone, Copy, Default)]
pub struct Statvfs;

impl SpaceProbe for Statvfs {
    fn available(&self, path: &Path) -> std::io::Result<u64> {
        let s = rustix::fs::statvfs(path)?;
        Ok(s.f_bavail.saturating_mul(s.f_frsize))
    }
}

/// Default floor: refuse new mail below 1 GiB free.
pub const DEFAULT_MIN_FREE: u64 = 1024 * 1024 * 1024;

/// Whether `path`'s filesystem has at least `floor` bytes free. An error
/// reading the free space counts as "not enough": refusing temporarily is
/// safer than accepting mail we may not be able to store.
pub fn enough(probe: &dyn SpaceProbe, path: &Path, floor: u64) -> bool {
    probe.available(path).is_ok_and(|free| free >= floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_probe_reports_something() {
        let free = Statvfs.available(Path::new(".")).unwrap();
        assert!(free > 0);
        assert!(enough(&Statvfs, Path::new("."), 0));
        assert!(
            !enough(&Statvfs, Path::new("/nonexistent/path"), 0),
            "errors count as full"
        );
    }
}
