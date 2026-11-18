//! Compiled sender SSH role: negotiation, signing and native Git byte transport.
//! @ref LLP 0001#framing
use crate::{
    Result,
    runtime::protocol::{Budget, DeadlineIo, Kind},
};
use std::{path::Path, process::Stdio, time::Duration};
fn exchange_hello(
    input: &mut impl std::io::Read,
    output: &mut impl std::io::Write,
    capability: &[u8],
    incoming: &mut Budget,
    outgoing: &mut Budget,
) -> Result<Vec<u8>> {
    (|| -> Result<_> {
        outgoing.write(output, Kind::Hello, capability)?;
        incoming.expect(input, Kind::Hello)
    })()
    .map_err(|e| format!("receiver negotiation failed: {e}").into())
}

fn save_push_result(report: &crate::runtime::push_result::Report) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    report.pin(
        &std::env::var("GIT_PORTER_CLIENT_REF")?,
        &std::env::var("GIT_PORTER_CLIENT_SHA")?,
    )?;
    let path = std::env::var_os("GIT_PORTER_RESULT_FILE")
        .ok_or("missing private push-result destination")?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&report.encode()?)?;
    file.sync_all()?;
    Ok(())
}
fn control(input: &mut impl std::io::Read, budget: &mut Budget, expected: Kind) -> Result<Vec<u8>> {
    let frame = budget.read(input)?;
    if frame.0 == Kind::Result {
        save_push_result(&crate::runtime::push_result::Report::parse(&frame.1)?)?;
        return Err(crate::runtime::push_result::Reported.into());
    }
    budget.require(frame, expected)
}
pub(crate) fn run() -> Result<()> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "Git transport arguments must be UTF-8")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let destination = std::env::var("GIT_PORTER_CLIENT_DESTINATION")?;
    let command = arguments.last().ok_or("missing Git transport command")?;
    let operation = if command.starts_with("git-upload-pack ") {
        "upload"
    } else if command.starts_with("git-receive-pack ") {
        "receive"
    } else {
        return Err("unsupported Git transport command".into());
    };
    let publication = operation == "receive"
        && std::env::var("GIT_PORTER_CLIENT_PUBLISH").is_ok_and(|s| s == "true");
    let mut signing = publication;
    let capability = if publication {
        b"publish-v5".as_slice()
    } else {
        b"local-v1".as_slice()
    };
    let explicit = std::env::var("GIT_PORTER_CLIENT_PATH").unwrap_or_default();
    let origin = std::env::var("GIT_PORTER_CLIENT_ORIGIN").unwrap_or_default();
    let force = std::env::var("GIT_PORTER_CLIENT_MODE").as_deref() == Ok("force");
    let lease_mode = std::env::var("GIT_PORTER_CLIENT_MODE").as_deref() == Ok("lease");
    let lease = operation == "receive" && lease_mode;
    if !explicit.is_empty() && !publication && !force && !lease_mode {
        return native(&destination, &explicit, operation);
    }
    if publication {
        crate::runtime::supervision::disable_core_dumps()?;
        // Reserve the operation before connecting, so malformed negotiation or
        // a reconnect cannot obtain a fresh signing allowance in another helper.
        let marker =
            std::env::var_os("GIT_PORTER_SIGN_BUDGET").ok_or("missing operation signing budget")?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)
            .map_err(|_| "publication negotiation already attempted for this send")?;
    }
    let session = crate::runtime::supervision::Session::new()?;
    let native_path = std::env::var("GIT_PORTER_NATIVE_PATH").unwrap_or_else(|_| explicit.clone());
    let native_command = if native_path.is_empty() {
        "false".into()
    } else {
        validate_path(&native_path)?;
        format!("git-{operation}-pack '{native_path}'")
    };
    let routed_command = format!(
        "{}{native_command}",
        crate::runtime::protocol::ROUTE_COMMAND
    );
    let mut command = crate::cli::ssh::command(&destination, &routed_command)?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = session.spawn(command)?;
    let result = (|| -> Result<()> {
        use std::io::Read;
        let mut input = DeadlineIo::new(
            child.stdout.take().ok_or("missing SSH output")?,
            Duration::from_secs(30),
        );
        input.cancel_on(&session);
        let output = child.stdin.take().ok_or("missing SSH input")?;
        let mut route = [0; crate::runtime::protocol::NATIVE_ROUTE.len()];
        input.read_exact(&mut route).map_err(|e| {
            format!("receiver did not identify its SSH route; no fallback attempted: {e}")
        })?;
        if route == crate::runtime::protocol::NATIVE_ROUTE {
            signing = false;
            record_route(b"native")?;
            if native_path.is_empty() {
                return Err("ordinary SSH requires a checkout beneath sender HOME at the same relative path on the receiver, or an explicit user@host:path".into());
            }
            crate::runtime::relay::run(&session, input.into_inner(), output)?;
            return if child.wait()?.success() {
                Ok(())
            } else {
                Err("SSH Git transfer failed".into())
            };
        }
        if route != crate::runtime::protocol::PORTER_ROUTE {
            return Err("receiver returned an invalid SSH route; no fallback attempted".into());
        }
        record_route(b"porter")?;
        if explicit.is_empty()
            && let Ok(error) = std::env::var("GIT_PORTER_LOOKUP_ERROR")
            && !error.is_empty()
        {
            return Err(error.into());
        }

        let input = input.into_inner();
        let mut incoming = Budget::default();
        let mut outgoing = Budget::default();
        let (input, output) = {
            let mut reader = DeadlineIo::new(input, Duration::from_secs(30));
            let mut writer = DeadlineIo::new(output, Duration::from_secs(30));
            reader.cancel_on(&session);
            writer.cancel_on(&session);

            let hello = exchange_hello(
                &mut reader,
                &mut writer,
                capability,
                &mut incoming,
                &mut outgoing,
            )?;

            if publication && hello == b"publish-account-v3" {
                signing = false;
            } else if hello != capability {
                return Err("receiver does not support the requested capability".into());
            }
            let mut intent = format!("{operation}\0{explicit}\0{origin}");
            if force && !publication {
                intent.push_str("\0force-v1");
            }
            if publication || lease {
                intent.insert_str(0, "intent-v2\0");
                intent.push_str(&format!(
                    "\0{}\0{}\0{}\0{}",
                    std::env::var("GIT_PORTER_CLIENT_MODE")?,
                    std::env::var("GIT_PORTER_CLIENT_REF")?,
                    std::env::var("GIT_PORTER_CLIENT_SHA")?,
                    std::env::var("GIT_PORTER_CLIENT_LEASE").unwrap_or_default()
                ));
            }
            let hint = match std::env::var("GIT_PORTER_CLIENT_HINT") {
                Ok(value) => value,
                Err(std::env::VarError::NotPresent) => String::new(),
                Err(error) => return Err(error.into()),
            };
            if !hint.is_empty() {
                crate::runtime::protocol::relative_hint(&hint)?;
                intent.push_str("\0path-hint-v1\0");
                intent.push_str(&hint);
            }

            outgoing.write(&mut writer, Kind::Intent, intent.as_bytes())?;
            let resolved = control(&mut reader, &mut incoming, Kind::Resolved)?;

            let mut resolved_repository = None;
            if publication {
                let value: crate::runtime::push_result::Resolved =
                    serde_json::from_slice(&resolved)?;
                if value.version != 1
                    || !value.repository.starts_with('/')
                    || value.repository.len() > 4096
                    || value.repository.chars().any(char::is_control)
                    || value.signing && !value.publication
                    || value.signing != signing && value.publication
                {
                    return Err("invalid resolved publication metadata".into());
                }
                resolved_repository = Some(value.repository);
                if signing && !value.publication {
                    signing = false;
                }
            }
            if signing {
                let payload = control(&mut reader, &mut incoming, Kind::ApprovePublishV1)?;
                let request = crate::credentials::derivation::PublishRequest::parse(&payload)?;
                request.approval.matches_intent(
                    resolved_repository
                        .as_deref()
                        .ok_or("missing resolved repository")?,
                    &std::env::var("GIT_PORTER_CLIENT_REF")?,
                    &std::env::var("GIT_PORTER_CLIENT_SHA")?,
                    &std::env::var("GIT_PORTER_CLIENT_MODE")?,
                    &std::env::var("GIT_PORTER_CLIENT_LEASE").unwrap_or_default(),
                )?;
                let response = (|| -> Result<_> {
                    outgoing.write(&mut writer, Kind::Signing, b"")?;
                    reader.pause()?;
                    writer.pause()?;
                    let mut signer = super::signing::Signer::open(
                        &destination,
                        &request.current.source,
                        &session,
                    )?;
                    let response = request.sign(
                        &mut crate::runtime::protocol::SigningBudget::default(),
                        &mut signer,
                    )?;
                    signer.close()?;
                    session.check()?;
                    Ok(response)
                })();
                reader.resume();
                writer.resume();
                let response = match response {
                    Ok(response) => response,
                    Err(error) => {
                        crate::cli::report_error("git-send", &error);
                        outgoing.write(&mut writer, Kind::Error, b"signer-refused-v1")?;
                        return control(&mut reader, &mut incoming, Kind::Result)
                            .and_then(|_| Err("receiver did not report sender refusal".into()));
                    }
                };
                outgoing.write(&mut writer, Kind::SigningDone, b"")?;

                outgoing.write(&mut writer, Kind::Signature, &response)?;
            }
            // Origin authentication is receiver work, not a stalled control peer.
            let ready = if publication {
                wait_ready(&mut reader, &mut incoming, Duration::from_secs(150))?
            } else {
                control(&mut reader, &mut incoming, Kind::Ready)?
            };

            if !ready.is_empty() {
                return Err("expected READY".into());
            }
            incoming.close();
            outgoing.close();
            (reader.into_inner(), writer.into_inner())
        };
        session.check()?;
        if publication {
            let report = crate::runtime::relay::framed(&session, input, output)?;
            save_push_result(&report)?;
            let remote_ok = child.wait()?.success();
            if !report.successful() || !remote_ok {
                return Err(crate::runtime::push_result::Reported.into());
            }
            return Ok(());
        }
        crate::runtime::relay::run(&session, input, output)?;
        if !child.wait()?.success() {
            return Err("receiver transfer failed; check the Git/SSH diagnostics above".into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        if publication
            && signing
            && !std::env::var_os("GIT_PORTER_RESULT_FILE").is_some_and(|p| Path::new(&p).is_file())
        {
            eprintln!(
                "No confirmed publication result is available. If the receiver accepted the commit, inspect origin before retrying."
            );
        }
    }
    result
}

fn wait_ready<T: std::io::Read + std::os::fd::AsRawFd>(
    reader: &mut DeadlineIo<T>,
    incoming: &mut Budget,
    allowance: Duration,
) -> Result<Vec<u8>> {
    reader.reset(allowance);
    control(reader, incoming, Kind::Ready)
}

pub(crate) fn is_role(argv0: &Path) -> bool {
    argv0.file_name().is_some_and(|s| s == "client-ssh")
}

pub(crate) fn validate_path(value: &str) -> Result<()> {
    crate::server::access::repository_path(value).map_err(|_| {
        "explicit paths require an ordinary home-relative or absolute repository path".into()
    })
}

// Retain explicit native reads/local-only writes, including git-shell endpoints.
fn native(host: &str, repository: &str, operation: &str) -> Result<()> {
    validate_path(repository)?;
    let remote = format!("git-{operation}-pack '{repository}'");
    let command = crate::cli::ssh::command(host, &remote)?;
    let session = crate::runtime::supervision::Session::new()?;
    if session.run(command, false)?.0.success() {
        Ok(())
    } else {
        Err("SSH transport failed".into())
    }
}

pub(super) fn is_native_route(path: &Path) -> Result<bool> {
    match std::fs::read(path) {
        Ok(bytes) if bytes == b"native" => Ok(true),
        Ok(bytes) if bytes == b"porter" => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        _ => Err("invalid private SSH route record".into()),
    }
}
fn record_route(route: &[u8]) -> Result<()> {
    use std::io::Write;
    let Some(path) = std::env::var_os("GIT_PORTER_ROUTE_FILE") else {
        return Ok(());
    };
    let path = Path::new(&path);
    let mut temporary =
        tempfile::NamedTempFile::new_in(path.parent().ok_or("route record has no directory")?)?;
    temporary.write_all(route)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::read(path)? == route {
                Ok(())
            } else {
                Err("SSH route changed during this operation; no fallback attempted".into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod hello_tests {
    use super::*;
    #[test]
    fn ready_wait_allows_slow_origin_beyond_setup_deadline() {
        use std::os::unix::net::UnixStream;
        let (receiver, mut forwarder) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            // Model receiver origin pre-authentication, with no network messages yet.
            std::thread::sleep(Duration::from_millis(150));
            Budget::default()
                .write(&mut forwarder, Kind::Ready, b"")
                .unwrap();
        });
        let mut reader = DeadlineIo::new(receiver, Duration::from_millis(50));
        assert!(
            wait_ready(
                &mut reader,
                &mut Budget::default(),
                Duration::from_millis(500)
            )
            .unwrap()
            .is_empty()
        );
        worker.join().unwrap();
    }
    struct ClosedReceiver;
    impl std::io::Write for ClosedReceiver {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn receiver_exit_before_hello_write_reports_negotiation_failure_as_eof() {
        for early_close in [true, false] {
            let mut input = std::io::empty();
            let mut incoming = Budget::default();
            let mut outgoing = Budget::default();
            let error = if early_close {
                exchange_hello(
                    &mut input,
                    &mut ClosedReceiver,
                    b"publish-v3",
                    &mut incoming,
                    &mut outgoing,
                )
            } else {
                exchange_hello(
                    &mut input,
                    &mut Vec::new(),
                    b"publish-v3",
                    &mut incoming,
                    &mut outgoing,
                )
            }
            .unwrap_err()
            .to_string();
            assert!(error.starts_with("receiver negotiation failed:"), "{error}");
            for speculative_hint in ["upgrade", "porter.", "key:create", "ssh-add"] {
                assert!(!error.contains(speculative_hint), "{error}");
            }
        }
    }
}
