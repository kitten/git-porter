//! Disposable bounded inventory. No authorization or credential URL is cached.
use super::{Identity, Options};
use crate::server::config::ServerConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 4 * 1024 * 1024;
const COVERAGE_SECONDS: u64 = 15;
// Older inventories predate filesystem-alias-aware traversal exclusions.
const VERSION: u8 = 5;

#[derive(Serialize, Deserialize)]
pub(super) struct Repository {
    pub path: PathBuf,
    pub digest: String,
    pub identity: Option<Identity>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Inventory {
    version: u8,
    scope: String,
    created: u64,
    pub complete: bool,
    pub directories: Vec<(PathBuf, String)>,
    pub repositories: Vec<Repository>,
}
impl Inventory {
    pub fn new(config: &ServerConfig) -> Self {
        Self {
            version: VERSION,
            scope: scope(config),
            created: now(),
            complete: true,
            directories: Vec::new(),
            repositories: Vec::new(),
        }
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn scope(config: &ServerConfig) -> String {
    // Versioned options include roots, depth, exclusions, executable and access
    // boundary. Cache reuse never depends on policy file modification times.
    let mut options = config.discovery.clone();
    options.roots = super::search_roots(&options);
    let bytes =
        serde_json::to_vec(&(VERSION, &options, &config.home, &config.git)).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}
fn filename(config: &ServerConfig) -> PathBuf {
    config
        .discovery
        .cache
        .join(format!("{}.json", scope(config)))
}
fn owned(metadata: &fs::Metadata) -> bool {
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}
fn directory(options: &Options, create: bool) -> Option<()> {
    if create {
        // Creating the parent cache namespace is harmless; the product directory
        // itself must be a private real directory, never a symlink.
        fs::create_dir_all(options.cache.parent()?).ok()?;
        match fs::DirBuilder::new().mode(0o700).create(&options.cache) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return None,
        }
    }
    let metadata = fs::symlink_metadata(&options.cache).ok()?;
    (metadata.is_dir() && owned(&metadata)).then_some(())
}
pub(super) fn load(config: &ServerConfig) -> Option<Inventory> {
    directory(&config.discovery, false)?;
    let path = filename(config);
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || !owned(&meta) || meta.len() > MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_BYTES {
        return None;
    }
    let inventory: Inventory = serde_json::from_slice(&bytes).ok()?;
    if inventory.version != VERSION
        || inventory.scope != scope(config)
        || inventory.repositories.len() > 10_000
        || inventory.directories.len() > 10_000
    {
        return None;
    }
    Some(inventory)
}
pub(super) fn fresh(inventory: &Inventory, start: Instant) -> bool {
    let now = now();
    inventory.complete
        && now >= inventory.created
        && now - inventory.created < COVERAGE_SECONDS
        && inventory.directories.iter().all(|(path, stamp)| {
            start.elapsed() < super::SEARCH_TIME && directory_stamp(path).as_ref() == Some(stamp)
        })
        && inventory
            .repositories
            .iter()
            .all(|entry| start.elapsed() < super::SEARCH_TIME && super::is_repository(&entry.path))
}

/// Generate variable namespace candidates from evidence, never permission.
/// A ranked parent list is sufficient at the bounded 10,000-entry scale; component
/// containment deduplicates overlaps without a separately persisted trie.
pub(super) fn hints(inventory: &Inventory, identity: &Identity) -> Vec<PathBuf> {
    let wanted: Vec<_> = identity.repository.split('/').collect();
    let mut paths = Vec::new();
    for entry in &inventory.repositories {
        let Some(known) = &entry.identity else {
            continue;
        };
        if known.host != identity.host || known.port != identity.port {
            continue;
        }
        let Some((mut anchor, slots)) = structure(&entry.path, known) else {
            continue;
        };
        if slots > wanted.len() {
            continue;
        }
        for part in &wanted[wanted.len() - slots..] {
            anchor.push(part);
        }
        paths.push(anchor);
    }
    paths.sort();
    paths.dedup();
    paths
}
pub(super) fn save(config: &ServerConfig, inventory: &Inventory) {
    let write = || -> Option<()> {
        directory(&config.discovery, true)?;
        let bytes = serde_json::to_vec(inventory).ok()?;
        if bytes.len() as u64 > MAX_BYTES {
            return None;
        }
        let mut file = tempfile::NamedTempFile::new_in(&config.discovery.cache).ok()?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .ok()?;
        file.write_all(&bytes).ok()?;
        file.as_file().sync_all().ok()?;
        file.persist(filename(config)).ok()?;
        Some(())
    };
    let _ = write();
}
pub(super) fn directory_stamp(path: &Path) -> Option<String> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_dir() {
        return None;
    }
    Some(format!(
        "{}:{}:{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ))
}

pub(super) fn configuration(path: &Path) -> (String, bool) {
    let layout = match super::layout::resolve(path) {
        Ok(layout) => layout,
        Err(_) => return ("invalid repository layout".into(), true),
    };
    let mut hash = Sha256::new();
    for (path, bytes) in &layout.pointers {
        hash.update((path.as_os_str().as_encoded_bytes().len() as u64).to_le_bytes());
        hash.update(path.as_os_str().as_encoded_bytes());
        match bytes {
            Some(bytes) => {
                hash.update([1]);
                hash.update((bytes.len() as u64).to_le_bytes());
                hash.update(bytes);
            }
            None => hash.update([0]),
        }
    }
    let super::layout::Layout { gitdir, common, .. } = layout;
    let volatile = std::cell::Cell::new(false);
    let mut read = |file: &Path| -> Option<Vec<u8>> {
        hash.update((file.as_os_str().as_encoded_bytes().len() as u64).to_le_bytes());
        hash.update(file.as_os_str().as_encoded_bytes());
        if !fs::metadata(file).is_ok_and(|m| m.is_file()) {
            if file.exists() {
                volatile.set(true);
            }
            hash.update([0]);
            return None;
        }
        match fs::File::open(file) {
            Ok(f) => {
                let mut bytes = Vec::new();
                let bytes = f.take(65537).read_to_end(&mut bytes).ok().map(|_| bytes);
                match bytes {
                    Some(bytes) if bytes.len() <= 65536 => {
                        hash.update([1]);
                        hash.update((bytes.len() as u64).to_le_bytes());
                        hash.update(&bytes);
                        // Conservative: any possible includes, even comments,
                        // require config inspection every time. This covers
                        // missing/conditional/external include dependencies.
                        if bytes.windows(7).any(|v| v.eq_ignore_ascii_case(b"include")) {
                            volatile.set(true);
                        }
                        Some(bytes)
                    }
                    _ => {
                        volatile.set(true);
                        None
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                hash.update([0]);
                None
            }
            Err(_) => {
                volatile.set(true);
                None
            }
        }
    };
    for dir in std::iter::once(&gitdir).chain((common != gitdir).then_some(&common)) {
        // Conditional includes are volatile, so branch-dependent resolution is
        // already re-queried; ordinary HEAD movement cannot change a remote.
        for name in ["config", "config.worktree"] {
            read(&dir.join(name));
        }
    }
    (format!("{:x}", hash.finalize()), volatile.get())
}

pub(super) fn structure(path: &Path, identity: &Identity) -> Option<(PathBuf, usize)> {
    let mut anchor = path.to_owned();
    let mut slots = 0;
    for part in identity.repository.split('/').rev() {
        if anchor
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.strip_suffix(".git").unwrap_or(v) == part)
        {
            anchor.pop();
            slots += 1;
        } else {
            break;
        }
    }
    (slots != 0).then_some((anchor, slots))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn learned_slots_preserve_variable_namespaces_and_distinct_clusters() {
        let inventory = Inventory {
            version: VERSION,
            scope: String::new(),
            created: 0,
            complete: false,
            directories: vec![],
            repositories: vec![
                Repository {
                    path: "/home/projects/kitten/linn".into(),
                    digest: String::new(),
                    identity: Some(Identity::parse("git@example.com:kitten/linn").unwrap()),
                },
                Repository {
                    path: "/home/deep/group/sub/tool".into(),
                    digest: String::new(),
                    identity: Some(Identity::parse("git@example.com:group/sub/tool").unwrap()),
                },
                Repository {
                    path: "/home/flat/widget".into(),
                    digest: String::new(),
                    identity: Some(Identity::parse("git@example.com:org/widget").unwrap()),
                },
            ],
        };
        let identity = Identity::parse("git@example.com:third/new/repo").unwrap();
        assert_eq!(
            hints(&inventory, &identity),
            vec![
                PathBuf::from("/home/deep/third/new/repo"),
                "/home/flat/repo".into(),
                "/home/projects/new/repo".into()
            ]
        );
        assert!(
            hints(
                &inventory,
                &Identity::parse("git@elsewhere.com:third/new/repo").unwrap()
            )
            .is_empty()
        );
    }
}
