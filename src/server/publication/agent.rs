//! Transaction-owned SSH agent and private-key signing; no persisted key material.
//! @ref LLP 0001#ownership
use crate::{
    Result,
    runtime::agent_directory::AgentDirectory,
    runtime::ssh_wire::{string, take},
};
use signature::Signer;
use ssh_key::PrivateKey;
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

/// The private key never leaves this process; socket/public files are disposable.
pub struct Agent {
    directory: Option<AgentDirectory>,
    stopping: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<std::result::Result<(), String>>>,
    pub public: PathBuf,
}
impl Agent {
    pub fn start(
        private: PrivateKey,
        config: &crate::server::config::ServerConfig,
        url: &str,
        session: &crate::runtime::supervision::Session,
    ) -> Result<Self> {
        let (destination, user) = super::policy::parse_url(url)?;
        let host = if destination.port.unwrap_or(22) == 22 {
            destination.host.clone()
        } else {
            format!("[{}]:{}", destination.host, destination.port.unwrap())
        };
        let policy = &config.publication;
        let mut hosts = Vec::new();
        let mut query =
            crate::runtime::supervision::command(crate::server::config::executable("ssh-keygen")?);
        query
            .args(["-F", &host, "-f"])
            .arg(&policy.known_hosts)
            .stderr(std::process::Stdio::null());
        let (_, output) = session.run(query, true)?;
        let mut lines = String::from_utf8(output)?;
        for line in crate::server::host_trust::KEYS.lines() {
            if line.split_whitespace().next() == Some(host.as_str()) {
                lines.push_str(line);
                lines.push('\n');
            }
        }
        for line in lines.lines().filter(|s| !s.starts_with(['#', '@'])) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "ssh-ed25519" {
                hosts.push(
                    ssh_key::PublicKey::from_openssh(&fields[1..].join(" "))
                        .map_err(|e| e.to_string())?,
                );
            }
        }
        if hosts.is_empty() {
            return Err(
                "origin pre-authentication: no trusted Ed25519 forge host key; establish SSH trust before publishing".into(),
            );
        }
        let owner = super::peer::process(std::process::id() as i32)?;
        let native = |path: &std::path::Path| {
            let wrapped = path.with_file_name(format!(
                ".{}-wrapped",
                path.file_name().unwrap().to_string_lossy()
            ));
            if wrapped.is_file() {
                wrapped.canonicalize().unwrap_or(wrapped)
            } else {
                path.to_owned()
            }
        };
        let git = native(&config.git);
        let ssh = native(&config.ssh);

        let directory = AgentDirectory::new()?;
        let socket = directory.path().join("agent");
        let public = directory.path().join("identity.pub");
        let mut key = private.public_key().clone();
        key.set_comment("");
        fs::write(&public, key.to_openssh().map_err(|e| e.to_string())?)?;
        let listener = UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopping);
        let worker = thread::spawn(move || {
            let signed = std::sync::Mutex::new(std::collections::BTreeSet::new());
            thread::scope(|scope| -> Result<()> {
                struct Stop(Arc<AtomicBool>);
                impl Drop for Stop {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Relaxed);
                    }
                }
                let _stop_on_unwind = Stop(Arc::clone(&stop));
                let mut clients: Vec<
                    thread::ScopedJoinHandle<'_, std::result::Result<(), String>>,
                > = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let mut index = 0;
                    while index < clients.len() {
                        if clients[index].is_finished() {
                            clients
                                .swap_remove(index)
                                .join()
                                .map_err(|_| "agent peer worker panicked")??;
                        } else {
                            index += 1;
                        }
                    }
                    let (stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let Ok(peer) = super::peer::peer(&stream) else {
                        continue;
                    };
                    if super::peer::allowed(&peer, &owner, &git, &ssh).is_err() {
                        continue;
                    }
                    if clients.len() >= 8 {
                        continue;
                    }
                    let private = &private;
                    let stop = &stop;
                    let signed = &signed;
                    let hosts = &hosts;
                    let user = &user;
                    let owner = &owner;
                    let git = &git;
                    let ssh = &ssh;
                    clients.push(scope.spawn(move || {
                        serve_agent(
                            stream,
                            private,
                            stop,
                            Permit {
                                peer: &peer,
                                owner,
                                git,
                                ssh,
                                hosts,
                                user,
                                signed,
                            },
                        )
                        .map_err(|e| e.to_string())
                    }));
                }
                for client in clients {
                    client.join().map_err(|_| "agent peer worker panicked")??;
                }
                Ok(())
            })
            .map_err(|e| e.to_string())
        });
        Ok(Self {
            directory: Some(directory),
            stopping,
            worker: Some(worker),
            public,
        })
    }
    pub fn socket(&self) -> PathBuf {
        self.directory.as_ref().unwrap().path().join("agent")
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => (),
                Ok(Err(e)) => {
                    crate::cli::terminal::warning(format_args!("forwarder agent teardown: {e}"))
                }
                Err(_) => crate::cli::terminal::warning(format_args!(
                    "forwarder agent worker panicked; scoped peer workers joined"
                )),
            }
        }
        if let Some(directory) = self.directory.take()
            && let Err(error) = directory.close()
        {
            crate::cli::terminal::warning(format_args!(
                "forwarder agent directory cleanup: {error}"
            ));
        }
    }
}

fn agent_read(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &mut [u8],
    stopping: &AtomicBool,
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() && !stopping.load(Ordering::Relaxed) {
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    if offset == bytes.len() {
        Ok(())
    } else {
        Err(std::io::ErrorKind::Interrupted.into())
    }
}

fn sign_private(private: &PrivateKey, challenge: &[u8], flags: u32) -> Result<ssh_key::Signature> {
    if private.algorithm() != ssh_key::Algorithm::Ed25519 || flags != 0 {
        return Err("forwarder keys must be Ed25519".into());
    }
    Ok(private.try_sign(challenge).map_err(|e| e.to_string())?)
}

struct Permit<'a> {
    peer: &'a super::peer::Process,
    owner: &'a super::peer::Process,
    git: &'a std::path::Path,
    ssh: &'a std::path::Path,
    hosts: &'a [ssh_key::PublicKey],
    user: &'a str,
    signed: &'a std::sync::Mutex<std::collections::BTreeSet<(i32, (u64, u64))>>,
}
fn claim_signature(
    signed: &std::sync::Mutex<std::collections::BTreeSet<(i32, (u64, u64))>>,
    peer: &super::peer::Process,
) -> Result<()> {
    if !signed
        .lock()
        .map_err(|_| "agent signer poisoned")?
        .insert((peer.pid, peer.birth))
    {
        return Err("ssh process already consumed its one signature".into());
    }
    Ok(())
}
fn serve_agent(
    mut stream: std::os::unix::net::UnixStream,
    private: &PrivateKey,
    stop: &AtomicBool,
    permit: Permit<'_>,
) -> Result<()> {
    let Permit {
        peer,
        owner,
        git,
        ssh,
        hosts,
        user,
        signed,
    } = permit;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    stream.set_write_timeout(Some(Duration::from_millis(100)))?;
    let mut binding = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !stop.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
        let mut header = [0; 4];
        if agent_read(&mut stream, &mut header, stop).is_err() {
            break;
        }
        let size = u32::from_be_bytes(header) as usize;
        if size == 0 || size > 128 * 1024 {
            break;
        }
        let mut request = zeroize::Zeroizing::new(vec![0; size]);
        if agent_read(&mut stream, &mut request, stop).is_err() {
            break;
        }
        let response = (|| -> Result<Vec<u8>> {
            let mut input = &request[1..];
            super::peer::allowed(peer, owner, git, ssh)?;
            match request[0] {
                27 if binding.is_none() => {
                    binding = Some(super::binding::bind(input, hosts)?);
                    Ok(vec![6])
                }

                11 if input.is_empty() => {
                    let mut out = vec![12];
                    out.extend(1u32.to_be_bytes());
                    string(
                        &mut out,
                        &private.public_key().to_bytes().map_err(|e| e.to_string())?,
                    );
                    string(&mut out, b"");
                    Ok(out)
                }
                13 => {
                    let key = take(&mut input)?;
                    let challenge = take(&mut input)?;
                    if key != private.public_key().to_bytes().map_err(|e| e.to_string())? {
                        return Err("wrong transaction identity".into());
                    }
                    let flags =
                        u32::from_be_bytes(input.try_into().map_err(|_| "invalid signing flags")?);
                    let binding = binding.as_ref().ok_or("unbound agent signature request")?;
                    super::binding::userauth(challenge, binding, user, private.public_key())?;
                    claim_signature(signed, peer)?;
                    let signature = sign_private(private, challenge, flags)?;
                    let bytes = zeroize::Zeroizing::new(
                        Vec::<u8>::try_from(signature).map_err(|e| e.to_string())?,
                    );
                    let mut out = vec![14];
                    string(&mut out, &bytes);
                    Ok(out)
                }
                _ => Err("unsupported agent request".into()),
            }
        })()
        .unwrap_or_else(|_| vec![5]);
        if stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

pub(crate) fn validate_private(private: &PrivateKey) -> Result<()> {
    use signature::Verifier;
    let challenge = b"git-porter publication key consistency check v1";
    let signature = sign_private(private, challenge, 0)
        .map_err(|_| "unsupported or inconsistent forwarder private key")?;
    private
        .public_key()
        .key_data()
        .verify(challenge, &signature)
        .map_err(|_| "forwarder private key does not match its public half")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_allowance_is_per_process_birth_across_connections() {
        let used = std::sync::Mutex::new(std::collections::BTreeSet::new());
        let mut peer = super::super::peer::process(std::process::id() as i32).unwrap();
        assert!(claim_signature(&used, &peer).is_ok());
        assert!(claim_signature(&used, &peer).is_err());
        peer.birth.0 += 1;
        assert!(claim_signature(&used, &peer).is_ok());
    }
    #[test]
    fn arbitrary_same_account_peer_fails_before_slot_allocation() {
        let root = tempfile::tempdir().unwrap();
        let listener = std::os::unix::net::UnixListener::bind(root.path().join("agent")).unwrap();
        let _connection =
            std::os::unix::net::UnixStream::connect(root.path().join("agent")).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let peer = super::super::peer::peer(&accepted).unwrap();
        assert!(
            super::super::peer::allowed(
                &peer,
                &peer,
                std::path::Path::new("/not/git"),
                std::path::Path::new("/not/ssh")
            )
            .is_err()
        );
    }
}
