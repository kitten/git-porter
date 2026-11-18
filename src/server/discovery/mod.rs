//! Bounded identity-based candidates. Selection still requires access validation.
//! @ref LLP 0002#lookup
use crate::{Result, server::config::ServerConfig};
use serde::{Deserialize, Serialize};
mod cache;
mod identity;
mod layout;
pub use identity::Identity;
pub(crate) use identity::{RemoteIdentities, repository_identity};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
pub(crate) const SEARCH_TIME: Duration = Duration::from_secs(5);

pub fn origin(repository: &Path) -> Result<Identity> {
    native_identity(repository)
}

/// Read local/worktree config in-process, following gitdir/commondir and includes.
/// As in linn, use libgit2 config entries rather than spawning Git per candidate.
fn native_identity(repository: &Path) -> Result<Identity> {
    let layout::Layout { gitdir, common, .. } = layout::resolve(repository)?;
    // Even Repository::open_ext can inspect ambient config; do not open a repository.
    let mut config = git2::Config::open(&common.join("config"))?;
    let worktree = match config.get_bool("extensions.worktreeconfig") {
        Ok(enabled) => enabled,
        Err(error) if error.code() == git2::ErrorCode::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if worktree && gitdir.join("config.worktree").exists() {
        config.add_file(
            &gitdir.join("config.worktree"),
            git2::ConfigLevel::Worktree,
            false,
        )?;
    }
    let mut entries = config.entries(None)?;
    let mut remotes = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut rewrites = Vec::new();
    let mut size = 0;
    while let Some(entry) = entries.next() {
        let entry = entry?;
        let name = std::str::from_utf8(entry.name_bytes())?;
        let value = std::str::from_utf8(entry.value_bytes())?;
        if name.starts_with("includeif.") {
            return Err("conditional includes are not supported for discovery; use plain repo-local includes or an explicit path".into());
        }
        size += name.len() + value.len();
        if size > 65536 {
            return Err("repository remote config exceeds 64 KiB".into());
        }
        if let Some((remote, field)) = name
            .strip_prefix("remote.")
            .and_then(|s| s.rsplit_once('.'))
        {
            let urls = remotes.entry(remote.into()).or_default();
            if field == "url" {
                if value.is_empty() {
                    urls.clear();
                } else {
                    urls.push(value.into());
                }
            }
        } else if let Some(base) = name
            .strip_prefix("url.")
            .and_then(|s| s.strip_suffix(".insteadof"))
        {
            rewrites.push((value.to_owned(), base.to_owned()));
        }
    }
    let urls = if let Some(urls) = remotes.get("origin") {
        urls
    } else if remotes.len() == 1 {
        identity::component(remotes.keys().next().unwrap())?;
        remotes.values().next().unwrap()
    } else {
        return Err("repository needs an origin or one unambiguous secondary remote".into());
    };
    let [url] = urls.as_slice() else {
        return Err("repository identity requires one origin URL".into());
    };
    let length = rewrites
        .iter()
        .filter(|(prefix, _)| url.starts_with(prefix))
        .map(|(prefix, _)| prefix.len())
        .max();
    let mut matches = rewrites
        .iter()
        .filter(|(prefix, _)| Some(prefix.len()) == length && url.starts_with(prefix))
        .map(|(prefix, base)| format!("{base}{}", &url[prefix.len()..]))
        .collect::<std::collections::BTreeSet<_>>();
    if matches.len() > 1 {
        return Err("ambiguous repository URL rewrite".into());
    }
    let url = matches.pop_first().unwrap_or_else(|| url.clone());
    if url.len() > 4096 {
        return Err("repository metadata output exceeds 4096 bytes".into());
    }
    Identity::parse(&url)
}

/// Trusted search/access scope. Findings never enlarge the receiver home boundary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub roots: Vec<PathBuf>,
    /// porter.searchStrict: confine discovery/access to roots and ignore sender hints.
    pub strict: bool,
    pub depth: usize,
    pub excludes: Vec<String>,
    pub cache: PathBuf,
}
impl Options {
    fn excludes_path(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        // Case aliases must not bypass exclusions on macOS, but differently
        // cased directories on a case-sensitive filesystem remain independent.
        let aliases = |other: &Path| {
            let (Ok(left), Ok(right)) = (
                std::fs::symlink_metadata(path),
                std::fs::symlink_metadata(other),
            ) else {
                return false;
            };
            (left.dev(), left.ino()) == (right.dev(), right.ino())
        };
        path.file_name().is_some_and(|name| {
            name.as_encoded_bytes().starts_with(b".")
                || self.excludes.iter().any(|excluded| {
                    name == excluded.as_str()
                        || name
                            .as_encoded_bytes()
                            .eq_ignore_ascii_case(excluded.as_bytes())
                            && path
                                .parent()
                                .is_some_and(|parent| aliases(&parent.join(excluded)))
                })
                || self.cache.file_name().is_some_and(|cache| {
                    name.as_encoded_bytes()
                        .eq_ignore_ascii_case(cache.as_encoded_bytes())
                        && aliases(&self.cache)
                })
        }) || path == self.cache
    }
}

/// A shortcut may select only a directory the recursive walk could reach.
/// Ineligible hints are absent candidates, never discovery errors.
pub(crate) fn hint_candidates(options: &Options, hint: &str) -> Vec<PathBuf> {
    if crate::runtime::protocol::relative_hint(hint).is_err() {
        return Vec::new();
    }
    let scopes = search_roots(options);
    options
        .roots
        .iter()
        .filter_map(|root| {
            let target = root.join(hint);
            // Keep configured roots as layout anchors, but measure reachability from
            // the same non-overlapping roots as the walker. A redundant deeper root
            // cannot bypass an ancestor repository or reset the depth allowance.
            let scope = scopes.iter().find(|scope| target.starts_with(scope))?;
            let relative = target.strip_prefix(scope).ok()?;
            if relative.components().count() > options.depth {
                return None;
            }
            let mut candidate = scope.clone();
            if !std::fs::symlink_metadata(&candidate).ok()?.is_dir() {
                return None;
            }
            for component in relative.components() {
                if is_repository(&candidate) {
                    return None;
                }
                candidate.push(component);
                if options.excludes_path(&candidate)
                    || !std::fs::symlink_metadata(&candidate).ok()?.is_dir()
                {
                    return None;
                }
            }
            let canonical = candidate.canonicalize().ok()?;
            canonical.starts_with(scope).then_some(canonical)
        })
        .collect()
}

pub struct Scan {
    pub candidates: Vec<PathBuf>,
    pub visited: usize,
    pub identity_reads: usize,
    pub coverage_checks: usize,
    pub configuration_checks: usize,
    pub complete: bool,
    pub cached: bool,
    pub elapsed: Duration,
}

pub fn scan(config: &ServerConfig, identity: &Identity) -> Result<Scan> {
    scan_with_budget(config, identity, SEARCH_TIME)
}
pub(crate) fn scan_with_budget(
    config: &ServerConfig,
    identity: &Identity,
    budget: Duration,
) -> Result<Scan> {
    scan_with_reader(config, identity, budget, cache::configuration)
}
fn scan_with_reader(
    config: &ServerConfig,
    identity: &Identity,
    budget: Duration,
    mut read_config: impl FnMut(&Path) -> (String, bool),
) -> Result<Scan> {
    let start = Instant::now();
    let mut result = Scan {
        candidates: Vec::new(),
        visited: 0,
        identity_reads: 0,
        coverage_checks: 0,
        configuration_checks: 0,
        complete: true,
        cached: false,
        elapsed: Duration::ZERO,
    };
    if budget.is_zero() {
        result.complete = false;
        return Ok(result);
    }
    let previous = cache::load(config);
    let reusable = previous
        .as_ref()
        .is_some_and(|inventory| cache::fresh(inventory, start));
    let mut hints = Vec::new();
    if !reusable {
        hints = previous
            .as_ref()
            .map(|i| cache::hints(i, identity))
            .unwrap_or_default();
        hints.extend(
            config
                .discovery
                .roots
                .iter()
                .map(|root| root.join(&identity.repository)),
        );
        let repo_name = identity.repository.rsplit('/').next().unwrap_or("");
        let expected = hints.clone();
        let mut parents = std::collections::BTreeSet::new();
        'paths: for expected in expected {
            for parent in expected
                .parent()
                .into_iter()
                .chain(expected.parent().and_then(Path::parent))
            {
                if !config
                    .discovery
                    .roots
                    .iter()
                    .any(|root| parent.starts_with(root))
                {
                    continue;
                }
                if !parents.insert(parent.to_path_buf()) {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        // Heuristic work shares the global scan deadline and has
                        // its own smaller enumeration cap. Warm cache hits skip it.
                        if result.visited >= 512 || start.elapsed() >= budget {
                            break 'paths;
                        }
                        result.visited += 1;
                        let path = entry.path();
                        if entry
                            .file_type()
                            .is_ok_and(|t| t.is_dir() && !t.is_symlink())
                            && !entry.file_name().as_encoded_bytes().starts_with(b".")
                        {
                            hints.push(path.clone());
                            hints.push(path.join(repo_name));
                        }
                    }
                }
            }
        }
    }
    hints.sort();
    hints.dedup();
    let mut inventory = match previous {
        Some(i) if reusable => {
            result.cached = true;
            i
        }
        previous => {
            let mut inventory = walk(config, start, budget, &mut result, &hints);
            if let Some(previous) = previous {
                let mut known: std::collections::BTreeMap<_, _> = previous
                    .repositories
                    .into_iter()
                    .map(|entry| (entry.path, (entry.digest, entry.identity)))
                    .collect();
                for entry in &mut inventory.repositories {
                    if let Some((digest, identity)) = known.remove(&entry.path) {
                        entry.digest = digest;
                        entry.identity = identity;
                    }
                }
            }
            inventory
        }
    };
    if result.cached {
        result.coverage_checks = inventory.directories.len() + inventory.repositories.len();
    }
    result.complete = inventory.complete;
    // Re-read configuration contents, including linked-worktree/common paths.
    // Plain includes are volatile and re-read on every lookup.
    inventory
        .repositories
        .sort_by_key(|entry| hints.binary_search(&entry.path).is_err());
    for entry in &mut inventory.repositories {
        result.configuration_checks += 1;
        if start.elapsed() >= budget {
            result.complete = false;
            break;
        }
        let (digest, volatile) = read_config(&entry.path);
        if start.elapsed() >= budget {
            result.complete = false;
            break;
        }
        if entry.digest.is_empty()
            || (!result.cached && entry.identity.is_none())
            || volatile
            || entry.digest != digest
            || entry.identity.as_ref() == Some(identity)
        {
            result.identity_reads += 1;
            entry.identity = native_identity(&entry.path).ok();
            if start.elapsed() >= budget {
                result.complete = false;
                break;
            }
            entry.digest = digest;
        }
        if entry.identity.as_ref() == Some(identity) && eligible(config, &entry.path) {
            result.candidates.push(entry.path.clone());
        }
    }
    result.candidates.sort();
    result.candidates.dedup();
    // Failed writes cannot change the answer. Incomplete coverage is not reusable,
    // but validated entries survive refreshes and negative answers still expire.
    inventory.complete &= result.complete;
    cache::save(config, &inventory);
    result.elapsed = start.elapsed();
    Ok(result)
}

fn eligible(config: &ServerConfig, path: &Path) -> bool {
    path.canonicalize().is_ok_and(|p| {
        config.permits_path(&p)
            && p.strip_prefix(&config.home).is_ok_and(|relative| {
                relative
                    .components()
                    .all(|v| !v.as_os_str().as_encoded_bytes().starts_with(b"."))
            })
    })
}

/// Match the walker's actual scope, independent of root order or redundant hints.
fn search_roots(options: &Options) -> Vec<PathBuf> {
    let mut roots = options.roots.clone();
    roots.sort();
    let mut distinct: Vec<PathBuf> = Vec::new();
    for root in roots {
        if distinct
            .last()
            .is_none_or(|parent| !root.starts_with(parent))
        {
            distinct.push(root);
        }
    }
    distinct
}

fn is_repository(path: &Path) -> bool {
    path.join(".git").exists() || (path.join("HEAD").is_file() && path.join("objects").is_dir())
}

/// Hints are sorted once; the first path at or after this prefix is decisive.
fn hinted(path: &Path, hints: &[PathBuf]) -> bool {
    let index = hints.partition_point(|hint| hint.as_path() < path);
    hints.get(index).is_some_and(|hint| hint.starts_with(path))
}

fn walk(
    config: &ServerConfig,
    start: Instant,
    budget: Duration,
    result: &mut Scan,
    hints: &[PathBuf],
) -> cache::Inventory {
    let options = &config.discovery;
    let mut inventory = cache::Inventory::new(config);
    let roots = search_roots(options);
    let mut stack: std::collections::BinaryHeap<_> = roots
        .into_iter()
        .map(|p| (hinted(&p, hints), p, 0usize))
        .collect();
    while let Some((_, path, depth)) = stack.pop() {
        // Learned flat/namespace/deeper patterns rank likely branches first.
        // Coverage is still required before claiming a unique match.
        if result.visited >= 10_000 || start.elapsed() >= budget {
            inventory.complete = false;
            break;
        }
        result.visited += 1;
        let Some(stamp) = cache::directory_stamp(&path) else {
            inventory.complete = false;
            continue;
        };
        if is_repository(&path) {
            inventory.repositories.push(cache::Repository {
                path,
                digest: String::new(),
                identity: None,
            });
            continue;
        }
        inventory.directories.push((path.clone(), stamp));
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => {
                inventory.complete = false;
                continue;
            }
        };
        for entry in entries {
            result.visited += 1;
            if result.visited >= 10_000 || start.elapsed() >= budget {
                inventory.complete = false;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    inventory.complete = false;
                    continue;
                }
            };
            if options.excludes_path(&entry.path()) {
                continue;
            }
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {
                    if depth >= options.depth {
                        inventory.complete = false;
                    } else {
                        let path = entry.path();
                        stack.push((hinted(&path, hints), path, depth + 1));
                    }
                }
                Err(_) => inventory.complete = false,
                _ => (),
            }
        }
    }
    inventory
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relative_hints_obey_recursive_walk_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let mut options = Options {
            roots: vec![home.clone(), home.join("projects")],
            strict: false,
            depth: 6,
            excludes: vec!["node_modules".into(), "target".into(), "Library".into()],
            cache: home.join("cache"),
        };
        let directory = |relative: &str| {
            let path = home.join(relative);
            std::fs::create_dir_all(&path).unwrap();
            path
        };
        let valid = directory("projects/repo");
        std::fs::create_dir(valid.join(".git")).unwrap();
        assert_eq!(
            hint_candidates(&options, "repo"),
            std::slice::from_ref(&valid)
        );
        assert_eq!(hint_candidates(&options, "projects/repo"), [valid]);
        let deepest = directory("a/b/c/d/e/repo");
        assert_eq!(hint_candidates(&options, "a/b/c/d/e/repo"), [deepest]);
        directory("deep/a/b/c/d/e/repo");
        options.roots.push(home.join("deep"));
        // A redundant root remains a layout anchor, but cannot reset depth.
        assert!(
            hint_candidates(&options, "a/b/c/d/e/repo")
                .iter()
                .all(|path| !path.starts_with(home.join("deep")))
        );
        assert!(hint_candidates(&options, "deep/a/b/c/d/e/repo").is_empty());

        for name in [".hidden", "node_modules", "target", "Library", "cache"] {
            let path = directory(&format!("{name}/repo"));
            assert!(
                hint_candidates(&options, &format!("{name}/repo")).is_empty(),
                "{name}"
            );
            let mut overlapping = options.clone();
            overlapping.roots = vec![home.clone(), path.parent().unwrap().to_owned()];
            assert!(hint_candidates(&overlapping, "repo").is_empty(), "{name}");
        }
        if home.join("library").is_dir() {
            assert!(hint_candidates(&options, "library/repo").is_empty());
        } else {
            let distinct = directory("library/repo");
            assert_eq!(hint_candidates(&options, "library/repo"), [distinct]);
            let linked = directory("case-links/library/repo");
            std::os::unix::fs::symlink("library", home.join("case-links/Library")).unwrap();
            assert_eq!(
                hint_candidates(&options, "case-links/library/repo"),
                [linked]
            );
        }
        if home.join("CACHE").is_dir() {
            assert!(hint_candidates(&options, "CACHE/repo").is_empty());
        }
        for marker in ["directory", "file", "bare"] {
            let parent = directory(&format!("parent-{marker}"));
            let nested = directory(&format!("parent-{marker}/child/repo"));
            match marker {
                "directory" => std::fs::create_dir(parent.join(".git")).unwrap(),
                "file" => std::fs::write(parent.join(".git"), "gitdir: elsewhere\n").unwrap(),
                _ => {
                    std::fs::write(parent.join("HEAD"), "ref: refs/heads/main\n").unwrap();
                    std::fs::create_dir(parent.join("objects")).unwrap();
                }
            }
            assert!(
                hint_candidates(&options, &format!("parent-{marker}/child/repo")).is_empty(),
                "{marker}"
            );
            let mut overlapping = options.clone();
            overlapping.roots = vec![home.clone(), nested.parent().unwrap().to_owned()];
            assert!(hint_candidates(&overlapping, "repo").is_empty(), "{marker}");
        }
        std::os::unix::fs::symlink(home.join("projects"), home.join("alias")).unwrap();
        assert!(hint_candidates(&options, "alias/repo").is_empty());
        for invalid in ["", "/projects/repo", "../repo", "projects/../repo"] {
            assert!(hint_candidates(&options, invalid).is_empty());
        }
    }

    #[test]
    fn sorted_hints_rank_component_prefixes_without_text_prefix_matches() {
        let hints = vec![
            PathBuf::from("/tree/owner/repo"),
            PathBuf::from("/tree/owner2/other"),
        ];
        for path in [
            "/",
            "/tree",
            "/tree/owner",
            "/tree/owner/repo",
            "/tree/owner2",
        ] {
            assert!(hinted(Path::new(path), &hints), "{path}");
        }
        for path in [
            "/tree/ow",
            "/tree/owner/re",
            "/tree/owner/repo/child",
            "/tree/owner3",
            "/z",
        ] {
            assert!(!hinted(Path::new(path), &hints), "{path}");
        }
        assert!(!hinted(Path::new("/tree"), &[]));
        let options = Options {
            roots: vec![
                "/tree/owner/sub".into(),
                "/tree/owner2".into(),
                "/tree/owner".into(),
                "/tree/owner".into(),
            ],
            strict: false,
            depth: 6,
            excludes: vec![],
            cache: "/cache".into(),
        };
        assert_eq!(
            search_roots(&options),
            vec![PathBuf::from("/tree/owner"), PathBuf::from("/tree/owner2")]
        );
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn cached_nonmatch_digest_cannot_exhaust_budget_and_report_complete() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let repo = git2::Repository::init_bare(home.join("repo")).unwrap();
        repo.remote("origin", "git@example.org:org/other").unwrap();
        let path = home.join(".gitconfig");
        std::fs::write(&path, "[porter]\n").unwrap();
        let config =
            ServerConfig::read_environment(&path, &home, &home, &home.join(".cache/git-porter"))
                .unwrap();
        let identity = Identity::parse("git@example.org:org/wanted").unwrap();
        scan(&config, &identity).unwrap();
        scan(&config, &identity).unwrap();
        let mut reads = 0;
        let result = scan_with_reader(&config, &identity, Duration::from_millis(40), |path| {
            reads += 1;
            std::thread::sleep(Duration::from_millis(80));
            cache::configuration(path)
        })
        .unwrap();
        assert_eq!(reads, 1);
        assert_eq!(
            result.identity_reads, 0,
            "cached nonmatch should need no identity read"
        );
        assert!(!result.complete);
    }
    #[test]
    fn exhausted_budget_never_claims_complete_coverage() {
        let home = tempfile::tempdir().unwrap();
        let policy = home.path().join(".gitconfig");
        std::fs::write(&policy, "[porter]\n").unwrap();
        let config = ServerConfig::read_environment(
            &policy,
            home.path(),
            home.path(),
            &home.path().join("cache"),
        )
        .unwrap();
        let identity = Identity::parse("git@example.org:org/repo").unwrap();
        let result = scan_with_budget(&config, &identity, Duration::ZERO).unwrap();
        assert!(!result.complete);
        assert_eq!(result.identity_reads, 0);
    }
}
