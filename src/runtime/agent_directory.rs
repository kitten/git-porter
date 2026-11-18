//! Private, recognized agent directories shared by sender and forwarder lifecycles.
//! @ref LLP 0001#sender-bootstrap
use crate::Result;
use std::fs;

pub(crate) struct AgentDirectory(Option<tempfile::TempDir>);
impl AgentDirectory {
    pub(crate) fn new() -> Result<Self> {
        sweep_in(&std::env::temp_dir().canonicalize()?)?;
        let directory = Self(Some(
            tempfile::Builder::new()
                .prefix(&format!("porter-agent-{}-", std::process::id()))
                .tempdir()?,
        ));
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        fs::write(
            directory.path().join("owner.pid"),
            std::process::id().to_string(),
        )?;
        Ok(directory)
    }
    pub(crate) fn path(&self) -> &std::path::Path {
        self.0.as_ref().unwrap().path()
    }
    pub(crate) fn close(mut self) -> std::io::Result<()> {
        self.0.take().unwrap().close()
    }
}
impl Drop for AgentDirectory {
    fn drop(&mut self) {
        if let Some(directory) = self.0.take()
            && let Err(error) = directory.close()
        {
            crate::cli::terminal::warning(format_args!("porter agent directory cleanup: {error}"));
        }
    }
}
fn sweep_in(root: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("porter-agent-") else {
            continue;
        };
        let Some((pid, _)) = rest.split_once('-') else {
            continue;
        };
        let Ok(pid) = pid.parse::<i32>() else {
            continue;
        };
        if pid < 2 {
            continue;
        }
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
        {
            continue;
        }
        let owner = entry.path().join("owner.pid");
        let Ok(owner_metadata) = fs::symlink_metadata(&owner) else {
            continue;
        };
        if !owner_metadata.is_file()
            || owner_metadata.uid() != metadata.uid()
            || owner_metadata.len() > 32
            || owner_metadata.mode() & 0o022 != 0
        {
            continue;
        }
        let owner = match fs::read_to_string(owner) {
            Ok(owner) => owner,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if owner.trim() != pid.to_string() {
            continue;
        }
        if unsafe { libc::kill(pid, 0) } == 0
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            continue;
        }
        let files = match fs::read_dir(entry.path()) {
            Ok(files) => files.collect::<std::io::Result<Vec<_>>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if files.iter().any(|e| {
            !["owner.pid", "agent", "identity.pub", "known_hosts"]
                .iter()
                .any(|n| e.file_name() == *n)
        }) {
            continue;
        }
        for file in files {
            remove_missing_ok(fs::remove_file(file.path()))?;
        }
        remove_missing_ok(fs::remove_dir(entry.path()))?;
    }
    Ok(())
}

fn remove_missing_ok(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn stale_sweep_preserves_live_foreign_and_unrecognized_directories() {
        let root = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let dead = child.id();
        child.wait().unwrap();
        let stale = root.path().join(format!("porter-agent-{dead}-stale"));
        fs::create_dir(&stale).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(stale.join("owner.pid"), dead.to_string()).unwrap();
        fs::write(stale.join("identity.pub"), "public").unwrap();
        let live = root
            .path()
            .join(format!("porter-agent-{}-live", std::process::id()));
        fs::create_dir(&live).unwrap();
        fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(live.join("owner.pid"), std::process::id().to_string()).unwrap();
        let foreign = root.path().join(format!("porter-agent-{dead}-foreign"));
        fs::create_dir(&foreign).unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(foreign.join("owner.pid"), dead.to_string()).unwrap();
        fs::write(foreign.join("unrelated"), "keep").unwrap();
        sweep_in(root.path()).unwrap();
        assert!(!stale.exists());
        assert!(live.exists());
        assert!(foreign.join("unrelated").exists());
    }
}
