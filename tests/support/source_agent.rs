//! Synthetic sender agent fixture, independent of the restricted forwarder agent.
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
};
pub struct Agent {
    child: Child,
    directory: tempfile::TempDir,
    pub public: PathBuf,
}
impl Agent {
    pub fn start(key: ssh_key::PrivateKey) -> git_porter::Result<Self> {
        let directory = tempfile::tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let socket = directory.path().join("agent");
        let child = isolated("ssh-agent", directory.path())
            .args(["-D", "-a"])
            .arg(&socket)
            .env("HOME", directory.path())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .spawn()?;
        let agent = Self {
            child,
            public: directory.path().join("identity.pub"),
            directory,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !socket.exists() {
            if std::time::Instant::now() > deadline {
                return Err("fixture agent did not start".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        fs::write(
            &agent.public,
            key.public_key().to_openssh().map_err(|e| e.to_string())?,
        )?;
        let mut add = isolated("ssh-add", agent.directory.path())
            .arg("-")
            .env("HOME", agent.directory.path())
            .env("SSH_AUTH_SOCK", socket)
            .env("SSH_ASKPASS_REQUIRE", "never")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        add.stdin.take().unwrap().write_all(
            key.to_openssh(ssh_key::LineEnding::LF)
                .map_err(|e| e.to_string())?
                .as_bytes(),
        )?;
        if !add.wait()?.success() {
            return Err("fixture key loading failed".into());
        }
        Ok(agent)
    }
    pub fn socket(&self) -> PathBuf {
        self.directory.path().join("agent")
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn isolated(program: &str, home: &std::path::Path) -> Command {
    let mut command = Command::new(program);
    for (key, _) in std::env::vars_os().filter(|(k, _)| k.to_string_lossy().starts_with("XDG_")) {
        command.env_remove(key);
    }
    command.env("HOME", home);
    command
}
