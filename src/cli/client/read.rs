//! Ordinary SSH read preparation using the logged-in account's upstream access.
//! @ref LLP 0002#ssh-route-selection
use super::repository::Repository;
use crate::{Result, runtime::supervision::Session};
use std::path::Path;

pub(crate) fn native(path: &Path, reference: &str) -> Result<()> {
    let path = path.canonicalize()?;
    let repository = Repository::open(&path)?;
    std::env::set_current_dir(&path)?;
    let session = Session::new()?;
    crate::runtime::read::validate_reference(repository.command(), reference, &session)?;
    let url = crate::runtime::read::origin(|| repository.command(), &session)?;
    let uses_ssh = |url: &str| {
        url.starts_with("ssh://")
            || !url.contains("://")
                && url
                    .split_once(':')
                    .is_some_and(|(host, _)| !host.contains('/'))
    };
    let directory = tempfile::tempdir()?;
    let helper = directory.path().join("hydration-ssh");
    std::os::unix::fs::symlink(std::env::current_exe()?, &helper)?;
    let clean = || {
        let mut cmd = crate::runtime::supervision::command("git");
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                cmd.env_remove(key);
            }
        }
        cmd.env("GIT_DIR", directory.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["-c", "gc.auto=0", "-c", "maintenance.auto=false"]);
        cmd
    };
    let with_ssh = |ssh: Option<&String>| {
        let mut cmd = clean();
        cmd.env("GIT_ALLOW_PROTOCOL", "ssh:https:file");
        if let Some(ssh) = ssh {
            cmd.env("GIT_SSH_COMMAND", crate::cli::ssh::quoted_path(&helper))
                .env("GIT_SSH_VARIANT", "ssh")
                .env("GIT_PORTER_USER_SSH", ssh);
        }
        cmd
    };
    let ssh = url
        .as_deref()
        .filter(|url| uses_ssh(url))
        .map(|_| crate::cli::ssh::selected())
        .transpose()?;
    let prepared = crate::runtime::read::prepare(
        directory.path(),
        || repository.command(),
        || with_ssh(ssh.as_ref()),
        reference,
        url.as_deref(),
        &session,
    )?;
    prepared.upload(clean(), &session)
}
