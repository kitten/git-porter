use crate::Result;
mod session;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::process::Command;

// Resolve missing metadata paths too, following dangling symlinks so that a
// future ref or object directory cannot silently extend the exposed root.
fn resolve(path: &Path, depth: usize) -> io::Result<PathBuf> {
    if depth > 64 {
        return Err(io::Error::other("too many path indirections"));
    }
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(error)?;
            if let Ok(target) = fs::read_link(path) {
                return resolve(&parent.join(target), depth + 1);
            }
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::other("invalid path"))?;
            Ok(resolve(parent, depth + 1)?.join(name))
        }
        Err(error) => Err(error),
    }
}

pub(crate) struct Access {
    home: PathBuf,
    roots: Vec<PathBuf>,
    git: PathBuf,
    hooks: PathBuf,
    prefixes: Vec<String>,
    data: PathBuf,
    data_home: PathBuf,
    tool_path: std::ffi::OsString,
    account_agent: bool,
    hook_context: String,
}

impl Access {
    pub(crate) fn managed_hook(&self) -> Result<()> {
        let hook = self.hooks.join("pre-receive");
        if fs::symlink_metadata(&hook).is_err()
            || fs::read_link(&hook).is_err()
            || hook.canonicalize().ok() != Some(env::current_exe()?.canonicalize()?)
        {
            return Err("receiver SSH setup is incomplete: the managed pre-receive hook is missing or stale".into());
        }
        Ok(())
    }
    pub(crate) fn allowed(&self, reference: &str) -> bool {
        allowed_ref(reference, &self.prefixes)
    }

    fn within_root(&self, path: &Path) -> Result<PathBuf> {
        let path = resolve(path, 0)?;
        if !path.starts_with(&self.home) || !self.roots.iter().any(|root| path.starts_with(root)) {
            return Err("repository or metadata is outside the allowed directories".into());
        }
        Ok(path)
    }

    pub(crate) fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = crate::runtime::supervision::command(program);
        // Do not inherit credentials, client GIT_* variables, or personal Git
        // settings. Incomplete partial clones must be hydrated by their owner.
        command
            .env_clear()
            .current_dir(&self.home)
            .env("PATH", &self.tool_path)
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0");
        command.env("GIT_PORTER_HOOK_CONTEXT", &self.hook_context);
        if self.account_agent
            && let Some(socket) = std::env::var_os("SSH_AUTH_SOCK")
        {
            command.env("SSH_AUTH_SOCK", socket);
        }
        if let Ok(protocol) = env::var("GIT_PROTOCOL")
            && matches!(protocol.as_str(), "version=0" | "version=1" | "version=2")
        {
            command.env("GIT_PROTOCOL", protocol);
        }
        command
    }

    pub(crate) fn git(&self) -> Command {
        let mut command = self.command(&self.git);
        for setting in [
            format!("core.hooksPath={}", self.hooks.display()),
            "core.fsmonitor=false".into(),
            "gc.auto=0".into(),
            "maintenance.auto=false".into(),
            "receive.autogc=false".into(),
            "receive.denyCurrentBranch=refuse".into(),
            "receive.denyDeleteCurrent=true".into(),
            "transfer.fsckObjects=true".into(),
            "receive.fsckObjects=true".into(),
        ] {
            command.arg("-c").arg(setting);
        }
        command
    }

    fn metadata_command(&self, repository: &Path, arguments: &[&str]) -> Command {
        let mut command = self.git();
        command
            .arg("-C")
            .arg(repository)
            .arg("rev-parse")
            .args(arguments);
        command
    }
    fn metadata_value(success: bool, bytes: Vec<u8>) -> Result<String> {
        if !success {
            return Err("not a usable Git repository".into());
        }
        let value = String::from_utf8(bytes)?;
        Ok(value.strip_suffix('\n').unwrap_or(&value).to_owned())
    }
    pub(crate) fn metadata(&self, repository: &Path, arguments: &[&str]) -> Result<String> {
        let output = self.metadata_command(repository, arguments).output()?;
        Self::metadata_value(output.status.success(), output.stdout)
    }
    pub(crate) fn metadata_in(
        &self,
        repository: &Path,
        arguments: &[&str],
        session: &crate::runtime::supervision::Session,
    ) -> Result<String> {
        let mut command = self.metadata_command(repository, arguments);
        command.stderr(std::process::Stdio::null());
        let (status, bytes) = session.run(command, true)?;
        Self::metadata_value(status.success(), bytes)
    }

    pub(crate) fn ensure_worktrees<'a>(
        &self,
        repository: &Path,
        references: impl IntoIterator<Item = &'a str>,
        session: &crate::runtime::supervision::Session,
    ) -> Result<()> {
        let mut references = references.into_iter().peekable();
        if references.peek().is_none() {
            return Ok(());
        }
        let mut command = self.git();
        command
            .arg("-C")
            .arg(repository)
            .args(["worktree", "list", "--porcelain"])
            .stderr(std::process::Stdio::null());
        let (status, bytes) = session.run(command, true)?;
        if !status.success() {
            return Err("cannot inspect destination worktrees".into());
        }
        let text = String::from_utf8(bytes)?;
        let branches: std::collections::BTreeSet<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix("branch "))
            .collect();
        if let Some(reference) = references.find(|reference| branches.contains(reference)) {
            return Err(format!(
                "destination branch is checked out in a linked worktree: {reference}"
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn repository(&self, name: &str) -> Result<PathBuf> {
        let path = self.home.join(name);
        let repository = match path.canonicalize() {
            Ok(repository) => repository,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && path.file_name().is_some_and(|part| part != ".git")
                    && name.ends_with(".git") =>
            {
                self.home
                    .join(name.strip_suffix(".git").unwrap())
                    .canonicalize()?
            }
            Err(error) => return Err(error.into()),
        };
        self.within_root(&repository)?;
        if repository
            .strip_prefix(&self.home)?
            .components()
            .any(|component| component.as_os_str().as_encoded_bytes().starts_with(b"."))
        {
            return Err("repositories in dot directories are not accessible".into());
        }
        let gitdir = self.within_root(Path::new(
            &self.metadata(&repository, &["--absolute-git-dir"])?,
        ))?;
        let common = self.within_root(Path::new(
            &self.metadata(&repository, &["--path-format=absolute", "--git-common-dir"])?,
        ))?;
        let toplevel = if self.metadata(&repository, &["--is-bare-repository"])? == "true" {
            gitdir.clone()
        } else {
            PathBuf::from(self.metadata(&repository, &["--show-toplevel"])?).canonicalize()?
        };
        if toplevel != repository {
            return Err("expected a repository root".into());
        }
        for directory in [&gitdir, &common] {
            for entry in [
                "HEAD",
                "config",
                "config.worktree",
                "objects",
                "refs",
                "logs",
                "packed-refs",
                "reftable",
                "shallow",
                "hooks",
                "info",
            ] {
                self.within_root(&directory.join(entry))?;
            }
        }
        for entry in ["objects/info", "objects/pack", "objects/info/alternates"] {
            self.within_root(&common.join(entry))?;
        }
        match fs::metadata(common.join("objects/info/alternates")) {
            Ok(metadata) if metadata.len() > 0 => {
                return Err("object alternates are not supported".into());
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        Ok(repository)
    }
}

/// Ordinary home-relative or absolute repository path syntax; resolution and
/// access-root containment are checked separately.
pub(crate) fn repository_path(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        || name
            .strip_prefix('/')
            .unwrap_or(name)
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err("invalid repository path".into());
    }
    Ok(())
}

fn valid_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn allowed_ref(reference: &str, prefixes: &[String]) -> bool {
    crate::runtime::push_result::direct_branch(reference)
        && prefixes.iter().any(|prefix| {
            let branch = &reference["refs/heads/".len()..];
            branch.starts_with(prefix) && branch.len() > prefix.len()
        })
}

fn prefix_error(reference: &str, prefixes: &[String]) -> String {
    let allowed = if prefixes.is_empty() {
        "none (branch updates are disabled)".to_owned()
    } else {
        prefixes.join(", ")
    };
    format!(
        "ref {reference} is not permitted; allowed branch prefixes: {allowed}. Rename your branch before sending it."
    )
}

pub(crate) fn check(context: &crate::server::config::HookContext) -> Result<()> {
    let config = &context.config;
    let git = &config.git;
    let prefixes = &config.prefixes;
    let mut updates = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3
            || !valid_sha(fields[0])
            || !valid_sha(fields[1])
            || fields[1].bytes().all(|byte| byte == b'0')
        {
            return Err(
                "only non-deletion updates to permitted branch prefixes are allowed".into(),
            );
        }
        if let Some(expected) = &context.reference
            && (fields[2] != expected.as_str() || context.sha.as_deref() != Some(fields[1]))
        {
            return Err("update differs from pinned publication intent".into());
        }
        if !allowed_ref(fields[2], prefixes) {
            return Err(prefix_error(fields[2], prefixes).into());
        }
        let mode = &context.mode;
        if mode == "lease" {
            let observed = context.observed.as_deref().ok_or("missing hook lease")?;
            let old = if fields[0].bytes().all(|b| b == b'0') {
                ""
            } else {
                fields[0]
            };
            if old != observed {
                return Err("receiver moved since the sender observed its tip; inspect the current tips before retrying".into());
            }
        }
        if !fields[0].bytes().all(|byte| byte == b'0')
            && !matches!(mode.as_str(), "force" | "lease")
            && !crate::runtime::supervision::command(git)
                .args(["merge-base", "--is-ancestor", fields[0], fields[1]])
                .status()?
                .success()
        {
            return Err("receiver refuses non-fast-forward update; inspect the current tips before retrying".into());
        }
        updates.push((
            fields[0].to_owned(),
            fields[1].to_owned(),
            fields[2].to_owned(),
        ));
        // receive-pack dereferences symbolic refs: an allowed name could otherwise
        // update a forbidden branch. Only direct refs may be received.
        let symbolic = crate::runtime::supervision::command(git)
            .args(["symbolic-ref", "--quiet", fields[2]])
            .output()?;
        if symbolic.status.code() != Some(1) {
            return Err("updates to symbolic branch refs are forbidden".into());
        }
    }
    let session = crate::runtime::supervision::Session::new()?;
    let access = configured_access(config)?;
    access.ensure_worktrees(
        &env::current_dir()?,
        updates.iter().map(|(_, _, reference)| reference.as_str()),
        &session,
    )?;
    crate::server::publication::pre_receive(config, &updates, context.publication.as_deref())?;
    Ok(())
}

// @ref LLP 0000#boundary
pub(crate) fn serve(config: &crate::server::config::ServerConfig) -> Result<()> {
    if config.keys.is_empty() {
        return Err("receiver SSH setup is incomplete: no sender access key is configured".into());
    }
    let request = env::var("SSH_ORIGINAL_COMMAND")?;
    if request == "git-porter-session-v1" {
        return session::run(config);
    }
    if request.starts_with(crate::runtime::protocol::ROUTE_COMMAND) {
        // This is a dispatch marker, never shell code to execute. The framed
        // intent still supplies and validates every operation and repository.
        use std::io::Write;
        let mut output = io::stdout().lock();
        output.write_all(crate::runtime::protocol::PORTER_ROUTE)?;
        output.flush()?;
        drop(output);
        return session::run(config);
    }
    let (operation, argument) = request.split_once(' ').ok_or("expected Git command")?;
    let operation = match operation {
        "git-upload-pack" => "upload-pack",
        "git-receive-pack" if !config.prefixes.is_empty() => "receive-pack",
        "git-receive-pack" => return Err("receiver branch updates are disabled".into()),
        _ => return Err("only permitted Git fetch/push commands are accepted".into()),
    };
    let name = argument
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or("expected single-quoted repository path")?;
    repository_path(name)?;
    let access = configured_access(config)?;
    let repository = access.repository(name)?;
    if operation == "receive-pack" {
        access.managed_hook()?;
    }
    let _lock = if operation == "receive-pack" {
        Some(RepositoryLock::acquire(&access, &repository)?)
    } else {
        None
    };
    let session = crate::runtime::supervision::Session::new()?;
    if session
        .run(
            {
                let mut command = access.git();
                command.arg(operation).arg(repository);
                command
            },
            false,
        )?
        .0
        .success()
    {
        Ok(())
    } else {
        Err("local Git transfer failed".into())
    }
}

pub(crate) fn configured_access(config: &crate::server::config::ServerConfig) -> Result<Access> {
    Ok(Access {
        hook_context: config.hook_context().encode()?,
        account_agent: config.publication.skip_wrapped_key,
        home: config.home.clone(),
        roots: config.discovery.roots.clone(),
        git: config.git.clone(),
        hooks: config.data.join("hooks"),
        prefixes: config.prefixes.clone(),
        data: config.data.clone(),
        data_home: config
            .data
            .parent()
            .ok_or("data directory has no parent")?
            .to_owned(),
        tool_path: config.tool_path()?,
    })
}

fn resolve_repository_hint(
    config: &crate::server::config::ServerConfig,
    access: &Access,
    path: &str,
    origin: &str,
    hint: Option<&str>,
) -> Result<PathBuf> {
    if !path.is_empty() {
        repository_path(path)?;
        return access.repository(path);
    }
    use crate::server::discovery::{Identity, RemoteIdentities, SEARCH_TIME};
    use std::{collections::BTreeSet, time::Instant};
    let identities = RemoteIdentities::parse(origin)?;
    let deadline = Instant::now() + SEARCH_TIME;
    let find = |urls: &[String], use_hint: bool| -> Result<BTreeSet<PathBuf>> {
        let mut matches = BTreeSet::new();
        for url in urls {
            let identity = Identity::parse(url)?;
            if use_hint && let Some(hint) = hint.filter(|_| !config.discovery.strict) {
                for candidate in crate::server::discovery::hint_candidates(&config.discovery, hint)
                {
                    if let Some(path) = candidate.to_str()
                        && let Ok(repository) = access.repository(path)
                        && crate::server::discovery::origin(&repository)
                            .is_ok_and(|found| found == identity)
                    {
                        matches.insert(repository);
                    }
                }
                if matches.len() == 1 {
                    return Ok(matches);
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let scan = crate::server::discovery::scan_with_budget(config, &identity, remaining)?;
            if !scan.complete || Instant::now() >= deadline {
                return Err("repository search incomplete; retry with an explicit receiver path: git send [--local-only] user@host:/absolute/path/to/repository (or git receive user@host:/absolute/path/to/repository)".into());
            }
            matches.extend(scan.candidates);
        }
        Ok(matches)
    };
    // An ambiguous preferred match must never be hidden by a secondary remote.
    let mut matches = match identities.preferred {
        Some(url) => find(&[url], true)?,
        None => BTreeSet::new(),
    };
    if matches.is_empty() {
        // Consider all fallback identities together, without a hint shortcut that
        // could conceal another matching remote/repository.
        matches = find(&identities.alternatives, false)?;
    }
    match matches.len() {
        0 => Err("no authorized repository matches the remote identities; check the receiver checkout's remote, or supply an explicit repository path as user@host:/absolute/path/to/repository".into()),
        1 => access.repository(matches.pop_first().unwrap().to_str().ok_or("non-UTF8 repository path")?),
        _ => Err("multiple authorized repositories match the remote identities; select the intended receiver checkout with user@host:/absolute/path/to/repository".into()),
    }
}

struct RepositoryLock(std::fs::File);
impl RepositoryLock {
    fn acquire(access: &Access, repository: &Path) -> Result<Self> {
        use std::os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let common =
            access.metadata(repository, &["--path-format=absolute", "--git-common-dir"])?;
        use sha2::{Digest, Sha256};
        let locks = access.data.join("locks");
        crate::credentials::keys::owner_directory(&locks)?;
        let name = format!("{:x}", Sha256::digest(common.as_bytes()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(locks.join(name))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("unsafe repository operation lock".into());
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another porter operation is active for this repository; wait for it to finish, then retry. If it is waiting for sender signing, complete or cancel that operation first".into());
        }
        Ok(Self(file))
    }
}
impl Drop for RepositoryLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;
    #[test]
    fn repository_writer_lock_is_exclusive_and_released() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let git = crate::server::config::executable("git").unwrap();
        let repo = home.join("repo.git");
        assert!(
            Command::new(git)
                .env_clear()
                .env("HOME", &home)
                .args(["init", "--bare", "-q"])
                .arg(&repo)
                .status()
                .unwrap()
                .success()
        );
        let path = home.join(".gitconfig");
        fs::write(
            &path,
            format!(
                "[porter]\nsearchRoot = {}\nsearchStrict = true\n",
                home.display()
            ),
        )
        .unwrap();
        let config = crate::server::config::ServerConfig::read_environment(
            &path,
            &home,
            &home,
            &home.join("cache"),
        )
        .unwrap();
        let access = configured_access(&config).unwrap();
        let first = RepositoryLock::acquire(&access, &repo).unwrap();
        assert!(
            RepositoryLock::acquire(&access, &repo)
                .err()
                .unwrap()
                .to_string()
                .contains("another porter operation is active for this repository")
        );
        drop(first);
        assert!(RepositoryLock::acquire(&access, &repo).is_ok());
    }
    #[test]
    fn relative_hint_confirms_remote_and_falls_back() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let git = crate::server::config::executable("git").unwrap();
        for (name, origin) in [
            ("wrong", "git@example.org:other/repo"),
            ("actual", "git@example.org:org/repo"),
            ("node_modules/hidden", "git@example.org:org/repo"),
            ("wrong/nested", "git@example.org:org/repo"),
        ] {
            let repo = home.join(name);
            for args in [
                vec!["init", "--bare", "-q"],
                vec!["config", "remote.origin.url", origin],
            ] {
                let mut command = Command::new(&git);
                command.env_clear().env("HOME", &home);
                if args[0] == "init" {
                    command.args(args).arg(&repo);
                } else {
                    command.arg("-C").arg(&repo).args(args);
                }
                assert!(command.status().unwrap().success());
            }
        }
        let path = home.join(".gitconfig");
        fs::write(&path, "[porter]\n").unwrap();
        let config = crate::server::config::ServerConfig::read_environment(
            &path,
            &home,
            &home,
            &home.join("cache"),
        )
        .unwrap();
        for hint in [
            None,
            Some("wrong"),
            Some("actual"),
            Some("node_modules/hidden"),
            Some("wrong/nested"),
        ] {
            assert_eq!(
                resolve_repository_hint(
                    &config,
                    &configured_access(&config).unwrap(),
                    "",
                    "git@example.org:org/repo",
                    hint
                )
                .unwrap(),
                home.join("actual")
            );
        }
        // Explicit paths retain access-policy semantics, independent of discovery.
        for path in ["node_modules/hidden", "wrong/nested"] {
            assert_eq!(
                resolve_repository_hint(
                    &config,
                    &configured_access(&config).unwrap(),
                    path,
                    "",
                    None
                )
                .unwrap(),
                home.join(path)
            );
        }
    }
    #[test]
    fn sender_origin_wins_then_all_secondary_matches_must_be_unambiguous() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let git = crate::server::config::executable("git").unwrap();
        let make_repo = |name: &str, url: &str| {
            let repo = home.join(name);
            for args in [
                vec!["init", "--bare", "-q"],
                vec!["config", "remote.origin.url", url],
            ] {
                let mut command = Command::new(&git);
                command.env_clear().env("HOME", &home);
                if args[0] == "init" {
                    command.args(args).arg(&repo);
                } else {
                    command.arg("-C").arg(&repo).args(args);
                }
                assert!(command.status().unwrap().success());
            }
            repo
        };
        let parent = make_repo("parent", "git@example.org:org/repo");
        let config_path = home.join(".gitconfig");
        fs::write(&config_path, "[porter]\n").unwrap();
        let config = crate::server::config::ServerConfig::read_environment(
            &config_path,
            &home,
            &home,
            &home.join("cache"),
        )
        .unwrap();
        let access = configured_access(&config).unwrap();
        let mut identities = crate::server::discovery::RemoteIdentities {
            preferred: Some("git@example.org:agent/repo".into()),
            alternatives: vec!["https://example.org/org/repo.git".into()],
        };
        let resolve = |identities: &crate::server::discovery::RemoteIdentities, hint| {
            resolve_repository_hint(&config, &access, "", &identities.encode().unwrap(), hint)
        };
        assert_eq!(resolve(&identities, None).unwrap(), parent);
        let fork = make_repo("fork", "git@example.org:agent/repo");
        // The fallback hint must not override a real origin match elsewhere.
        assert_eq!(resolve(&identities, Some("parent")).unwrap(), fork);
        identities.preferred = None;
        assert_eq!(resolve(&identities, None).unwrap(), parent);
        identities
            .alternatives
            .push("git@example.org:agent/repo".into());
        assert!(
            resolve(&identities, Some("parent"))
                .unwrap_err()
                .to_string()
                .contains("multiple authorized repositories")
        );
        identities.preferred = Some("git@example.org:agent/repo".into());
        make_repo("duplicate", "git@example.org:agent/repo");
        assert!(
            resolve(&identities, None)
                .unwrap_err()
                .to_string()
                .contains("multiple authorized repositories")
        );
    }

    #[test]
    fn strict_roots_constrain_explicit_paths_and_home_is_always_the_outer_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let repo = home.join("repo.git");
        let hints = home.join("search-only");
        fs::create_dir(&hints).unwrap();
        let git = crate::server::config::executable("git").unwrap();
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .args(["init", "--bare", "-q"])
                .arg(&repo)
                .status()
                .unwrap()
                .success()
        );
        let path = home.join(".gitconfig");
        let read = || {
            crate::server::config::ServerConfig::read_environment(
                &path,
                &home,
                &home,
                &home.join("cache"),
            )
            .unwrap()
        };
        fs::write(
            &path,
            "[porter]\nsearchRoot = search-only\nsearchStrict = true\n",
        )
        .unwrap();
        let config = read();
        assert_eq!(config.discovery.roots, vec![hints.clone()]);
        assert!(
            configured_access(&config)
                .unwrap()
                .repository("repo.git")
                .is_err()
        );
        let allowed = hints.join("allowed.git");
        assert!(
            Command::new(&git)
                .env_clear()
                .env("HOME", &home)
                .args(["init", "--bare", "-q"])
                .arg(&allowed)
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            configured_access(&config)
                .unwrap()
                .repository("search-only/allowed.git")
                .unwrap(),
            allowed
        );
        // A repository inside a strict root cannot keep its object store elsewhere.
        let objects = home.join("elsewhere-objects");
        fs::rename(allowed.join("objects"), &objects).unwrap();
        std::os::unix::fs::symlink(&objects, allowed.join("objects")).unwrap();
        assert!(
            configured_access(&config)
                .unwrap()
                .repository("search-only/allowed.git")
                .is_err()
        );
        fs::remove_file(allowed.join("objects")).unwrap();
        fs::rename(objects, allowed.join("objects")).unwrap();

        // Both absolute paths and symlink escapes are refused even without strict mode.
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.join("escape")).unwrap();
        fs::write(
            &path,
            "[porter]\nsearchRoot = search-only\nsearchStrict = false\n",
        )
        .unwrap();
        let config = read();
        let access = configured_access(&config).unwrap();
        assert!(config.discovery.roots.contains(&home));
        assert_eq!(access.repository("repo.git").unwrap(), repo);
        assert!(access.repository(outside.path().to_str().unwrap()).is_err());
        assert!(access.repository("escape").is_err());
        fs::rename(allowed.join("objects"), outside.path().join("objects")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("objects"), allowed.join("objects"))
            .unwrap();
        assert!(access.repository("search-only/allowed.git").is_err());
    }
}
