//! Sender-only exact-key signing through an existing or operation-owned SSH agent.
//! @ref LLP 0001#sender-bootstrap
use crate::{
    Result,
    credentials::{agent::Client, derivation::SourceAgent, wrapping},
    runtime::{
        agent_directory::AgentDirectory,
        supervision::{self, OwnedChild, Session},
    },
    server::{config::executable, publication::policy::runtime_file},
};
use ssh_key::{PublicKey, Signature};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

pub(super) struct Signer {
    client: Client,
    owned: Option<OwnedAgent>,
}
struct OwnedAgent {
    // Drop order matters: reap the agent before removing its socket directory.
    child: OwnedChild,
    directory: AgentDirectory,
}
impl Signer {
    pub(super) fn open(host: &str, source: &PublicKey, session: &Session) -> Result<Self> {
        session.check()?;
        if let Some(socket) = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) {
            return Self::existing(Path::new(&socket), session);
        }
        let selection = crate::cli::ssh::sender_identities(host, session)?;
        if let Some(socket) = selection.agent {
            return Self::existing(&socket, session);
        }
        let path = source_file(&selection.files, source, session)?;
        Self::start(&path, source, session)
    }
    pub(super) fn local(
        source: &PublicKey,
        public_path: Option<&Path>,
        session: &Session,
    ) -> Result<Self> {
        if let Some(socket) = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty()) {
            return Self::existing(Path::new(&socket), session);
        }
        let absolute = public_path.map(std::path::absolute).transpose()?;
        let path = absolute.as_deref().and_then(|p| p.to_str()).and_then(|p| p.strip_suffix(".pub"))
            .ok_or("sender signing is unavailable: no SSH agent or matching private-key path is available")?;
        let path = source_file(&[PathBuf::from(path)], source, session)?;
        Self::start(&path, source, session)
    }
    fn existing(socket: &Path, session: &Session) -> Result<Self> {
        let mut client = Client::connect(socket)?;
        client.cancel_on(session);
        Ok(Self {
            client,
            owned: None,
        })
    }
    fn start(path: &Path, source: &PublicKey, session: &Session) -> Result<Self> {
        let directory = AgentDirectory::new()?;
        let socket = directory.path().join("agent");
        socket2::SockAddr::unix(&socket).map_err(|error| {
            format!(
                "sender agent socket path is invalid or too long; use a shorter TMPDIR: {error}"
            )
        })?;
        let mut command = supervision::command(executable("ssh-agent")?);
        command
            .args(["-D", "-t", "1200", "-a"])
            .arg(&socket)
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let child = session.spawn(command)?;
        let mut owner = OwnedAgent { child, directory };
        let ready = Instant::now() + Duration::from_secs(2);
        while !socket.exists() {
            session.check()?;
            if owner.child.try_wait()?.is_some() || Instant::now() >= ready {
                return Err("temporary sender SSH agent failed to start".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut add = supervision::command(executable("ssh-add")?);
        add.args(["-k", "-t", "1200"])
            .arg(path)
            .env("SSH_AUTH_SOCK", &socket)
            .env_remove("SSH_AGENT_PID")
            .env("SSH_ASKPASS_REQUIRE", "never")
            .stdin(Stdio::null())
            .stderr(Stdio::inherit());
        if !session.run(add, true)?.0.success() {
            return Err("could not load the sender key into the temporary SSH agent".into());
        }
        let mut client = Client::connect(&socket)?;
        client.cancel_on(session);
        let identities = client.list_all_identities()?;
        if !matches!(identities.as_slice(), [key] if key.key_data() == source.key_data()) {
            return Err(
                "the temporary sender agent did not load exactly the expected sender key".into(),
            );
        }
        Ok(Self {
            client,
            owned: Some(owner),
        })
    }
    /// Explicit cleanup before a response leaves the sender. Drop remains a safety net.
    pub(super) fn close(self) -> Result<()> {
        let Self { client, owned } = self;
        drop(client);
        if let Some(mut owned) = owned {
            let stopped = owned.child.stop();
            drop(owned.child);
            let removed = owned.directory.close();
            match (stopped, removed) {
                (Ok(()), Ok(())) => (),
                (Err(a), Err(b)) => {
                    return Err(format!("sender agent cleanup: {a}; directory cleanup: {b}").into());
                }
                (Err(error), _) | (_, Err(error)) => {
                    return Err(format!("sender agent cleanup: {error}").into());
                }
            }
        }
        Ok(())
    }
}
fn fingerprint_matches(bytes: &[u8], expected: &str) -> bool {
    if bytes.len() > 4096 {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.lines();
    let Some(line) = lines.next() else {
        return false;
    };
    lines.next().is_none() && line.split_whitespace().nth(1) == Some(expected)
}
fn source_file(paths: &[PathBuf], source: &PublicKey, session: &Session) -> Result<PathBuf> {
    let expected = source.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let keygen = executable("ssh-keygen")?;
    for path in paths {
        let Ok(path) = runtime_file(path, true) else {
            continue;
        };
        if std::fs::metadata(&path)?.len() > wrapping::MAX_KEY_SIZE as u64 {
            continue;
        }
        let mut query = supervision::command(&keygen);
        query
            .args(["-l", "-E", "sha256", "-f"])
            .arg(&path)
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        let (status, bytes) = session.run(query, true)?;
        if status.success() && fingerprint_matches(&bytes, &expected) {
            return Ok(path);
        }
    }
    Err(format!("no available SSH identity file matches sender key {expected}").into())
}
impl SourceAgent for Signer {
    fn identities(&mut self) -> Result<Vec<PublicKey>> {
        self.client.list_all_identities()
    }
    fn sign(&mut self, source: &PublicKey, challenge: &[u8]) -> Result<Signature> {
        self.client.sign(source, challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{credentials::derivation::PublishRequest, runtime::protocol::SigningBudget};
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn owned_agent_is_exact_key_and_its_socket_is_removed_before_handoff() {
        // Native loader/agent children must never inherit the account's real HOME/XDG.
        if std::env::var_os("PORTER_BOOTSTRAP_TEST_CHILD").is_none() {
            let home = tempfile::tempdir().unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.env_clear().env("PATH", std::env::var_os("PATH").unwrap())
                .env("HOME", home.path()).env("PORTER_BOOTSTRAP_TEST_CHILD", "1")
                .env("TMPDIR", std::env::temp_dir()).current_dir(home.path())
                .args(["--exact", "cli::client::signing::tests::owned_agent_is_exact_key_and_its_socket_is_removed_before_handoff", "--nocapture"]);
            for name in [
                "XDG_DATA_HOME",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "XDG_STATE_HOME",
                "XDG_RUNTIME_DIR",
                "XDG_DATA_DIRS",
                "XDG_CONFIG_DIRS",
            ] {
                command.env(name, home.path().join(name));
            }
            use std::os::unix::process::CommandExt;
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            assert!(command.status().unwrap().success());
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("source key");
        let source =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        fs::write(
            &path,
            source
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let session = Session::new().unwrap();
        let selected =
            source_file(std::slice::from_ref(&path), source.public_key(), &session).unwrap();
        let mut signer = Signer::start(&selected, source.public_key(), &session).unwrap();
        let socket = signer
            .owned
            .as_ref()
            .unwrap()
            .directory
            .path()
            .join("agent");
        let directory = socket.parent().unwrap().to_owned();
        assert!(socket.exists());
        let metadata = wrapping::Metadata::generate(source.public_key()).unwrap();
        let request = PublishRequest::new(source.public_key().clone(), metadata).unwrap();
        let mut budget = SigningBudget::default();
        let response = request.sign(&mut budget, &mut signer).unwrap();
        request.current.identity(&response[..64]).unwrap();
        request.next.identity(&response[64..]).unwrap();
        assert!(request.sign(&mut budget, &mut signer).is_err());
        signer.close().unwrap();
        assert!(!directory.exists());
        assert!(Client::connect(&socket).is_err());
        let signer = Signer::start(&selected, source.public_key(), &session).unwrap();
        let abandoned = signer.owned.as_ref().unwrap().directory.path().to_owned();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _signer = signer;
                panic!("synthetic sender failure");
            }))
            .is_err()
        );
        assert!(!abandoned.exists(), "unwind left an agent socket directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(source_file(std::slice::from_ref(&path), source.public_key(), &session).is_err());
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), 1);
        // Native key inspection handles encrypted files, but headless loading
        // must refuse without consuming protocol stdin or leaking an agent.
        let encrypted = home.path().join("encrypted");
        let mut generate = supervision::command(executable("ssh-keygen").unwrap());
        generate
            .args(["-q", "-t", "ed25519", "-N", "fixture passphrase", "-f"])
            .arg(&encrypted)
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        assert!(session.run(generate, true).unwrap().0.success());
        let public = wrapping::read_public(&encrypted.with_extension("pub")).unwrap();
        let selected = source_file(std::slice::from_ref(&encrypted), &public, &session).unwrap();
        let failure = match Signer::start(&selected, &public, &session) {
            Ok(_) => panic!("headless encrypted key loading unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(
            failure
                .to_string()
                .contains("could not load the sender key")
        );
        let prefix = format!("porter-agent-{}-", std::process::id());
        assert!(!fs::read_dir(std::env::temp_dir()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(&prefix)
        }));
    }
    #[test]
    fn fingerprint_selection_is_bounded_and_does_not_accept_other_keys_or_extra_rows() {
        let expected = "SHA256:expected";
        assert!(fingerprint_matches(
            b"256 SHA256:expected comment (ED25519)\n",
            expected
        ));
        for bytes in [
            b"256 SHA256:other comment\n".as_slice(),
            b"256 SHA256:expected\n256 SHA256:expected\n",
            b"",
            &[255],
        ] {
            assert!(!fingerprint_matches(bytes, expected));
        }
        assert!(!fingerprint_matches(&vec![b'x'; 4097], expected));
    }
}
