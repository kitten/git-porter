//! Approved one-time provisioning jobs. Public metadata persists; signatures do not.
//! @ref LLP 0001#ownership
use crate::{
    Result,
    credentials::derivation::Request,
    runtime::ipc::connect,
    runtime::protocol::{Budget, DeadlineIo, Kind},
    server::config::ServerConfig,
};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixListener},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2)
        || text.len() > 9216
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid job encoding".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
struct Pending {
    path: PathBuf,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            crate::cli::terminal::warning(format_args!("pending key creation cleanup: {error}"));
        }
    }
}

/// Retain the account provisioning lock around this call and the completion closure.
pub(crate) fn participate<T>(
    data: &Path,
    request: &Request,
    complete: impl FnOnce(age::x25519::Identity) -> Result<T>,
) -> Result<T> {
    crate::runtime::supervision::disable_core_dumps()?;
    let signing_session = crate::runtime::supervision::Session::new()?;
    if let Some(socket) = std::env::var_os("SSH_AUTH_SOCK").filter(|s| !s.is_empty())
        && let Ok(mut agent) = crate::credentials::agent::Client::connect(Path::new(&socket))
    {
        agent.cancel_on(&signing_session);
        if let Some(response) = request.sign_if_loaded(
            &mut crate::runtime::protocol::SigningBudget::default(),
            &mut agent,
        )? {
            let identity = request.identity(&response)?;
            drop(response);
            signing_session.check()?;
            return complete(identity);
        }
    }
    let jobs = data.join("pending");
    crate::credentials::keys::owner_directory(&jobs)?;
    if fs::read_dir(&jobs)?.take(33).count() > 32 {
        return Err("too many pending jobs; receiver owner must remove stale job metadata".into());
    }
    let directory = tempfile::Builder::new()
        .prefix("porter-provision-")
        .tempdir()?;
    let socket = directory.path().join("job");
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    let identifier = format!("{:032x}", rand::random::<u128>());
    let path = jobs.join(format!("{identifier}.job"));
    let _pending = Pending { path: path.clone() };
    let expires = now()? + 600;
    let encoded = request.encode()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    writeln!(
        file,
        "porter-provision-v2\n{expires}\n{}\n{}",
        socket.display(),
        hex(&encoded)
    )?;
    file.sync_all()?;
    eprintln!(
        "Waiting for approval from sender key {}.\nLeave this command running. On the sender, run:\n  git porter key:create --sign user@host",
        request.source.fingerprint(ssh_key::HashAlg::Sha256)
    );
    let mut deadline = Instant::now() + Duration::from_secs(600);
    loop {
        signing_session.check()?;
        if Instant::now() >= deadline {
            return Err(
                "key creation was canceled or timed out; existing credentials were preserved"
                    .into(),
            );
        }
        let (stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_nonblocking(false)?;
        let mut channel = DeadlineIo::new(stream, Duration::from_secs(30));
        channel.cancel_on(&signing_session);
        let mut outgoing = Budget::default();
        let mut incoming = Budget::default();
        if outgoing
            .write(&mut channel, Kind::DeriveEd25519V2, &encoded)
            .is_err()
        {
            continue;
        }
        let started = Instant::now();
        let response = match (|| -> Result<Vec<u8>> {
            incoming.expect_empty(&mut channel, Kind::Signing)?;
            channel.pause()?;
            let done = incoming.expect_empty(&mut channel, Kind::SigningDone);
            channel.resume();
            done?;
            incoming.expect(&mut channel, Kind::Signature)
        })() {
            Ok(response) => Zeroizing::new(response),
            _ => continue,
        };
        deadline += started.elapsed();
        let identity = match request.identity(&response) {
            Ok(identity) => identity,
            Err(_) => continue,
        };
        drop(response);
        signing_session.check()?;
        if Instant::now() >= deadline {
            return Err(
                "key creation was canceled or timed out; existing credentials were preserved"
                    .into(),
            );
        }
        let result = complete(identity)?;
        let _ = outgoing.write(&mut channel, Kind::Complete, identifier.as_bytes());
        return Ok(result);
    }
}

pub fn serve(
    config: &ServerConfig,
    session: &crate::runtime::supervision::Session,
    input: &mut DeadlineIo<impl Read + std::os::fd::AsRawFd>,
    output: &mut DeadlineIo<impl Write + std::os::fd::AsRawFd>,
    mut incoming: Budget,
    mut outgoing: Budget,
) -> Result<()> {
    if config.publication.skip_wrapped_key {
        return Err("receiver uses its account SSH agent; wrapped key creation and sender participation are not needed".into());
    }
    crate::runtime::supervision::disable_core_dumps()?;

    outgoing.write(output, Kind::Hello, b"provision-v2")?;
    let intent = incoming.expect(input, Kind::Intent)?;

    // Jobs are never selected by the sender: exactly one live job may match.
    if intent != b"provision\0" {
        return Err("invalid provisioning intent".into());
    }
    let directory = config.data.join("pending");
    let mut matches = Vec::new();
    for entry in fs::read_dir(&directory)
        .map_err(|_| "no pending key-creation request was found on the receiver")?
        .take(33)
    {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("invalid pending job filename")?;
        let Some(id) = name.strip_suffix(".job") else {
            continue;
        };
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() > 16384
        {
            return Err("unsafe pending job metadata".into());
        }
        let bytes =
            crate::credentials::wrapping::read_bounded(fs::File::open(entry.path())?, 16384)?;
        let text = std::str::from_utf8(&bytes)?;
        let fields: Vec<_> = text.lines().collect();
        let [version, expires, socket, request] = fields.as_slice() else {
            return Err("invalid pending job metadata".into());
        };
        if *version != "porter-provision-v2" {
            return Err("unsupported pending job version".into());
        }
        if expires.parse::<u64>()? <= now()? {
            continue;
        }
        matches.push((id.to_owned(), PathBuf::from(socket), unhex(request)?));
    }
    let [(id, socket, expected)] = matches.as_slice() else {
        return Err("receiver has no unique pending key-creation request".into());
    };
    let stream = connect(socket, Duration::from_secs(2))
        .map_err(|_| "the pending key-creation process is no longer running on the receiver")?;
    let mut channel = provisioning_channel(stream, session);
    let mut local_in = Budget::default();
    let mut local_out = Budget::default();
    let request = local_in.expect(&mut channel, Kind::DeriveEd25519V2)?;
    if &request != expected {
        return Err("pending provisioning job changed".into());
    }
    Request::parse(&request)?;

    outgoing.write(output, Kind::Resolved, id.as_bytes())?;

    outgoing.write(output, Kind::DeriveEd25519V2, &request)?;
    relay_signature(input, output, &mut channel, &mut incoming, &mut local_out)?;
    let completion = local_in.expect(&mut channel, Kind::Complete)?;
    if completion != id.as_bytes() {
        return Err("provisioning completion does not match job".into());
    }

    outgoing.write(
        output,
        Kind::Complete,
        b"Forwarder credential provisioned; receiver prints the forge registration key",
    )?;
    incoming.close();
    outgoing.close();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipc_connection_is_bounded_when_setup_backlog_is_full() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("job");
        use std::os::fd::AsRawFd;
        let listener = UnixListener::bind(&socket).unwrap();
        // SAFETY: narrow this owned fixture listener's backlog explicitly;
        // the standard library's default capacity differs between platforms.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let start = Instant::now();
        let mut pending = Vec::new();
        let mut bounded = false;
        for _ in 0..8 {
            match connect(&socket, Duration::from_millis(30)) {
                Ok(connection) => pending.push(connection),
                Err(error) => {
                    assert!(matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::ConnectionRefused
                    ));
                    bounded = true;
                    break;
                }
            }
        }
        assert!(!pending.is_empty());
        assert!(bounded);
        assert!(start.elapsed() < Duration::from_secs(3));
    }
    #[test]
    fn malformed_public_job_encoding_is_rejected() {
        for value in ["0", "éé", "zz", "001x"] {
            assert!(unhex(value).is_err());
        }
    }
}

fn relay_signature(
    input: &mut DeadlineIo<impl Read + std::os::fd::AsRawFd>,
    output: &mut DeadlineIo<impl Write + std::os::fd::AsRawFd>,
    channel: &mut DeadlineIo<impl Read + Write + std::os::fd::AsRawFd>,
    incoming: &mut Budget,
    local_out: &mut Budget,
) -> Result<()> {
    incoming.expect_empty(input, Kind::Signing)?;
    local_out.write(channel, Kind::Signing, b"")?;
    channel.pause()?;
    let done = crate::runtime::protocol::finish_approval(incoming, input, output);
    channel.resume();
    done?;
    local_out.write(channel, Kind::SigningDone, b"")?;
    let response = Zeroizing::new(incoming.expect(input, Kind::Signature)?);
    // The approved owner verifies this exact signature before deriving or storing anything.
    local_out.write(channel, Kind::Signature, &response)?;
    Ok(())
}
#[cfg(test)]
mod relay_tests {
    use super::*;
    #[test]
    fn provisioning_approval_pauses_both_network_clocks() {
        use std::os::unix::net::UnixStream;
        let (receiver, mut sender) = UnixStream::pair().unwrap();
        let (local, mut owner) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut frames = Budget::default();
            frames.write(&mut sender, Kind::Signing, b"").unwrap();
            std::thread::sleep(Duration::from_millis(150));
            frames.write(&mut sender, Kind::SigningDone, b"").unwrap();
            frames
                .write(&mut sender, Kind::Signature, &[7; 64])
                .unwrap();
            Budget::default()
                .expect(&mut sender, Kind::Complete)
                .unwrap();
        });
        let mut input = DeadlineIo::new(receiver.try_clone().unwrap(), Duration::from_millis(75));
        let mut output = DeadlineIo::new(receiver, Duration::from_millis(75));
        let mut channel = DeadlineIo::new(local, Duration::from_millis(75));
        relay_signature(
            &mut input,
            &mut output,
            &mut channel,
            &mut Budget::default(),
            &mut Budget::default(),
        )
        .unwrap();
        let mut frames = Budget::default();
        frames.expect_empty(&mut owner, Kind::Signing).unwrap();
        frames.expect_empty(&mut owner, Kind::SigningDone).unwrap();
        assert_eq!(
            frames.expect(&mut owner, Kind::Signature).unwrap(),
            vec![7; 64]
        );
        Budget::default()
            .write(&mut output, Kind::Complete, b"ok")
            .unwrap();
        worker.join().unwrap();
    }
}

fn provisioning_channel(
    stream: std::os::unix::net::UnixStream,
    session: &crate::runtime::supervision::Session,
) -> DeadlineIo<std::os::unix::net::UnixStream> {
    let mut channel = DeadlineIo::new(stream, Duration::from_secs(30));
    channel.cancel_on(session);
    channel
}
#[cfg(test)]
mod cancellation_tests {
    use super::*;
    #[test]
    fn silent_owner_cannot_outlive_receiver_session() {
        let (stream, _owner) = std::os::unix::net::UnixStream::pair().unwrap();
        let session =
            crate::runtime::supervision::Session::with_timeout(Duration::from_millis(40)).unwrap();
        let mut channel = provisioning_channel(stream, &session);
        let start = Instant::now();
        let error = Budget::default()
            .expect(&mut channel, Kind::Complete)
            .unwrap_err();
        assert!(error.to_string().contains("canceled"), "{error}");
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
