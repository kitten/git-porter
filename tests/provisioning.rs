#[path = "support/source_agent.rs"]
mod source_agent;
use git_porter::credentials::keys;
use source_agent::Agent;
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}
#[test]
fn remote_one_time_provisioning_is_repo_independent_and_uses_no_receiver_agent() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(".local/share/git-porter");
    keys::owner_directory(&data).unwrap();
    let private =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let source = private.public_key().clone();
    let public = root.join("source.pub");
    fs::write(&public, source.to_openssh().unwrap()).unwrap();
    let source_agent = Agent::start(private).unwrap();
    let config = root.join(".gitconfig");
    fs::write(
        &config,
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\npublishTo = forge.example\n",
            root.display(),
            source.to_openssh().unwrap()
        ),
    )
    .unwrap();
    let log = root.join("setup.log");
    let registration = root.join("registration.pub");
    let mut setup = Process(
        Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .arg("setup")
            .stdin(Stdio::piped())
            .env_remove("GIT_CONFIG_GLOBAL")
            .env("HOME", &root)
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .env_remove("SSH_AUTH_SOCK")
            .stdout(Stdio::from(fs::File::create(&registration).unwrap()))
            .stderr(Stdio::from(fs::File::create(&log).unwrap()))
            .spawn()
            .unwrap(),
    );
    use std::io::Write;
    setup
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"y\nwait\n")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let identifier = loop {
        if let Some(status) = setup.0.try_wait().unwrap() {
            panic!(
                "setup stopped {status}: {}",
                fs::read_to_string(&log).unwrap()
            );
        }
        if let Ok(entries) = fs::read_dir(data.join("pending"))
            && let Some(entry) = entries
                .filter_map(Result::ok)
                .find(|e| e.path().extension().is_some_and(|s| s == "job"))
        {
            break entry
                .path()
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "setup did not publish a pending job"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!data.join("publication.wrapped").exists());
    let concurrent = Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .arg("key:create")
        .arg(&public)
        .env_remove("GIT_CONFIG_GLOBAL")
        .env("HOME", &root)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("XDG_DATA_DIRS")
        .env_remove("XDG_CONFIG_DIRS")
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap();
    assert!(!concurrent.status.success());
    assert!(String::from_utf8_lossy(&concurrent.stderr).contains("active"));
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let ssh = bin.join("ssh");
    fs::write(&ssh,format!("#!/bin/sh\nexport SSH_ORIGINAL_COMMAND=git-porter-session-v1\nunset SSH_AUTH_SOCK\nexec {} internal:serve\n",quote(Path::new(env!("CARGO_BIN_EXE_git-porter"))))).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let participate = |agent: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_git-porter"));
        command
            .current_dir(&root)
            .args(["key:create", "--sign", "operator@fixture"])
            .env("PATH", &path)
            .env("HOME", &root)
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .env("GIT_CONFIG_GLOBAL", "/dev/null");
        if agent {
            command.env("SSH_AUTH_SOCK", source_agent.socket());
        } else {
            command.env("HOME", &root).env_remove("SSH_AUTH_SOCK");
        }
        command.output().unwrap()
    };
    let wrong = Agent::start(
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap(),
    )
    .unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .args(["key:create", "--sign", "operator@fixture"])
        .env("PATH", &path)
        .env("HOME", &root)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env("SSH_AUTH_SOCK", wrong.socket())
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(!data.join("publication.wrapped").exists());
    assert!(!participate(false).status.success());
    assert!(!data.join("publication.wrapped").exists());
    let pending = data.join("pending").join(format!("{identifier}.job"));
    let original = fs::read_to_string(&pending).unwrap();
    let mut fields: Vec<_> = original.lines().map(str::to_owned).collect();
    fields[1] = "0".into();
    fs::write(&pending, fields.join("\n") + "\n").unwrap();
    assert!(!participate(true).status.success());
    assert!(!data.join("publication.wrapped").exists());
    fields = original.lines().map(str::to_owned).collect();
    fields[3].replace_range(0..2, "00");
    fs::write(&pending, fields.join("\n") + "\n").unwrap();
    assert!(!participate(true).status.success());
    assert!(!data.join("publication.wrapped").exists());
    fs::write(&pending, &original).unwrap();
    let completed = participate(true);
    assert!(
        completed.status.success(),
        "{}",
        String::from_utf8_lossy(&completed.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = setup.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "{}", fs::read_to_string(&log).unwrap());
    let public = keys::public(&data).unwrap();
    assert_eq!(
        keys::public(&data).unwrap().to_openssh().unwrap().trim(),
        public.to_openssh().unwrap()
    );
    assert!(
        !data
            .join("pending")
            .join(format!("{identifier}.job"))
            .exists()
    );
    assert!(!participate(true).status.success());
    assert_eq!(keys::public(&data).unwrap().key_data(), public.key_data());
}

#[test]
fn canceling_a_waiting_operation_removes_its_job_without_creating_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let data = root.join(".local/share/git-porter");
    let source =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let public = root.join("source.pub");
    fs::write(&public, source.public_key().to_openssh().unwrap()).unwrap();
    keys::owner_directory(&data).unwrap();
    fs::copy(&public, data.join("publication.source.pub")).unwrap();
    fs::write(
        root.join(".gitconfig"),
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\npublishTo = forge.example\n",
            root.display()
        ),
    )
    .unwrap();
    let mut setup = Process(
        Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .args(["key:create"])
            .env_remove("GIT_CONFIG_GLOBAL")
            .env("HOME", &root)
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .env_remove("SSH_AUTH_SOCK")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !data.join("pending").exists() || fs::read_dir(data.join("pending")).unwrap().count() == 0
    {
        assert!(Instant::now() < deadline);
        assert!(setup.0.try_wait().unwrap().is_none());
        std::thread::sleep(Duration::from_millis(10));
    }
    // A stalled signing prompt must still honor owner cancellation.
    let pending = fs::read_dir(data.join("pending"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let metadata = fs::read_to_string(pending).unwrap();
    let socket = metadata.lines().nth(2).unwrap();
    let mut channel = std::os::unix::net::UnixStream::connect(socket).unwrap();
    channel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut incoming = git_porter::runtime::protocol::Budget::default();
    assert_eq!(
        incoming.read(&mut channel).unwrap().0,
        git_porter::runtime::protocol::Kind::DeriveEd25519V2
    );
    git_porter::runtime::protocol::Budget::default()
        .write(
            &mut channel,
            git_porter::runtime::protocol::Kind::Signing,
            b"",
        )
        .unwrap();
    unsafe {
        libc::kill(setup.0.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = setup.0.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fs::read_dir(data.join("pending")).unwrap().count(), 0);
    assert!(!data.join("publication.wrapped").exists());
    assert!(!data.join("credentials/current").exists());
}
