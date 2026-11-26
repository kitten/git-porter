//! Negotiated receiver session: signing, receipt and final outcome reporting.
//! @ref LLP 0001#framing
use super::{RepositoryLock, configured_access, resolve_repository_hint, valid_sha};
use crate::Result;
mod intent;
mod signing;
use intent::{Intent, Update};
use std::fs;

pub(super) fn run(config: &crate::server::config::ServerConfig) -> Result<()> {
    use crate::runtime::protocol::{Budget, Kind};
    let session = crate::runtime::supervision::Session::new()?;
    let access = configured_access(config)?;
    use std::os::fd::BorrowedFd;
    // StdinLock buffers reads; exec must inherit every post-frame byte.
    let input_fd = unsafe { BorrowedFd::borrow_raw(0) }.try_clone_to_owned()?;
    let output_fd = unsafe { BorrowedFd::borrow_raw(1) }.try_clone_to_owned()?;
    let mut input = crate::runtime::protocol::DeadlineIo::new(
        fs::File::from(input_fd),
        std::time::Duration::from_secs(30),
    );
    let mut output = crate::runtime::protocol::DeadlineIo::new(
        fs::File::from(output_fd),
        std::time::Duration::from_secs(30),
    );
    input.cancel_on(&session);
    output.cancel_on(&session);
    use crate::runtime::push_result::{self, Forwarded, Outcome, Reason, Report};
    let mut report = Report::default();
    let mut result_channel = false;
    let mut native_started = false;
    let mut resources = Resources::default();
    let mut incoming = Budget::default();
    let mut outgoing = Budget::default();
    let result = (|| -> Result<()> {
        let payload = incoming.expect(&mut input, Kind::Hello)?;
        if payload == b"provision-v2" {
            return crate::credentials::jobs::serve(
                config,
                &session,
                &mut input,
                &mut output,
                incoming,
                outgoing,
            );
        }
        let publication = payload == b"publish-v5";
        let read_session = payload == b"read-v1";
        result_channel = publication;
        let signing = (publication || read_session) && !config.publication.skip_wrapped_key;

        if !publication && !read_session && payload != b"local-v1" {
            return Err("unsupported session capabilities".into());
        }

        outgoing.write(
            &mut output,
            Kind::Hello,
            if read_session && !signing {
                b"read-account-v1"
            } else if read_session {
                b"read-v1"
            } else if publication && !signing {
                b"publish-account-v3"
            } else if publication {
                b"publish-v5"
            } else {
                b"local-v1"
            },
        )?;
        let payload = incoming.expect(&mut input, Kind::Intent)?;
        let Intent {
            operation,
            path,
            origin,
            request,
            hint,
            mode,
            read,
        } = Intent::parse(&payload, publication)?;
        if let Some(Update { reference, sha, .. }) = request
            && push_result::reference(reference)
            && push_result::oid(sha)
        {
            report.reference = Some(reference.into());
            report.intended = Some(sha.into());
        }
        let operation = match operation {
            b"upload" => "upload-pack",
            b"receive" if !config.prefixes.is_empty() => "receive-pack",
            b"receive" => return Err("receiver branch updates are disabled".into()),
            _ => return Err("unsupported or unauthorized operation".into()),
        };
        let repository = resolve_repository_hint(
            config,
            &access,
            std::str::from_utf8(path)?,
            std::str::from_utf8(origin)?,
            hint,
        )?;
        if read_session != read.is_some() {
            return Err("read capability requires a read intent".into());
        }
        if let Some(reference) = read {
            crate::runtime::read::validate_reference(access.git(), reference, &session)?;
            let upstream = super::read::origin(&access, &repository, &session)?;
            if let Some(upstream) = upstream.as_ref().filter(|u| u.network) {
                config.publication.allows(&upstream.url).map_err(|e| {
                    format!(
                        "{e}; use --local-only to receive existing refs without upstream access"
                    )
                })?;
            }
            let needs_signing = signing && upstream.as_ref().is_some_and(|u| u.network);
            outgoing.write(
                &mut output,
                Kind::Resolved,
                &serde_json::to_vec(&push_result::Resolved {
                    version: 1,
                    repository: repository.to_str().ok_or("non-UTF8 repository")?.into(),
                    publication: false,
                    signing: needs_signing,
                })?,
            )?;
            let private = if needs_signing {
                resources.bundle_lock =
                    Some(crate::credentials::keys::Lock::acquire(&config.data)?);
                let policy = config.publication.ready()?;
                let approval = crate::credentials::derivation::Approval::new(
                    repository.to_str().ok_or("non-UTF8 repository")?,
                    &upstream.as_ref().ok_or("missing origin")?.url,
                    reference,
                    "",
                    "read",
                    "",
                )?;
                Some(signing::unlock(
                    &policy,
                    &mut report.reason,
                    approval,
                    |derive| {
                        outgoing.write(&mut output, Kind::ApprovePublishV1, &derive.encode()?)?;
                        crate::runtime::protocol::signature(&mut incoming, &mut input, &mut output)
                    },
                )?)
            } else {
                None
            };
            // Unlocking is complete. Keep the in-memory key, not the bundle
            // lock, during network fetching and the client transfer.
            drop(resources.bundle_lock.take());
            input.reset(std::time::Duration::from_secs(1200));
            output.reset(std::time::Duration::from_secs(1200));
            let ready = || {
                outgoing.write(&mut output, Kind::Ready, b"")?;
                incoming.close();
                outgoing.close();
                Ok(())
            };
            return super::read::serve(
                config,
                &access,
                &repository,
                reference,
                upstream,
                private,
                &session,
                ready,
            );
        }
        report.repository = Some(
            repository
                .to_str()
                .ok_or("non-UTF8 receiver repository")?
                .into(),
        );
        let onward =
            publication && crate::server::publication::has_origin(&access, &repository, &session)?;
        if onward {
            report.forwarded = Some(Forwarded {
                url: None,
                rows: vec![],
                outcome: Outcome::NotAttempted {
                    reason: Reason::PolicyRefused,
                },
            });
        }
        if operation == "receive-pack" {
            report.reason = Reason::HookUnavailable;
            access.managed_hook()?;
        }
        resources.repository_lock = if operation == "receive-pack" {
            Some(RepositoryLock::acquire(&access, &repository)?)
        } else {
            None
        };

        outgoing.write(
            &mut output,
            Kind::Resolved,
            &if result_channel {
                serde_json::to_vec(&push_result::Resolved {
                    version: 1,
                    repository: repository.to_str().ok_or("non-UTF8 repository")?.into(),
                    publication: onward,
                    signing: signing && onward,
                })?
            } else {
                repository.as_os_str().as_encoded_bytes().to_vec()
            },
        )?;
        report.reason = Reason::PolicyRefused;
        if let Some(Update {
            reference,
            sha,
            observed,
        }) = request
        {
            let mode = mode.as_str();
            if operation != "receive-pack" || !valid_sha(sha) {
                return Err("invalid publication intent".into());
            }
            if !access.allowed(reference) {
                return Err(super::prefix_error(reference, &config.prefixes).into());
            }
            let mut symbolic = access.git();
            symbolic
                .arg("-C")
                .arg(&repository)
                .args(["symbolic-ref", "--quiet", reference])
                .stderr(std::process::Stdio::null());
            if session.run(symbolic, true)?.0.code() != Some(1) {
                return Err("publication requires a direct branch; select one with git send --branch <name>, not a symbolic ref".into());
            }
            access.ensure_worktrees(&repository, std::iter::once(reference), &session)?;
            if mode == "lease" {
                if !observed.is_empty() && !valid_sha(observed) {
                    return Err("invalid observed lease tip".into());
                }
                let current = access
                    .metadata_in(&repository, &["--verify", reference], &session)
                    .unwrap_or_default();
                if current != observed {
                    report.reason = Reason::ReceiverMoved;
                    return Err("receiver moved since the sender observed its tip; neither repository was updated. Inspect the current tips before retrying".into());
                }
            }
            if onward {
                let destination =
                    crate::server::publication::destination(&access, &repository, &session)?;
                report.forwarded.as_mut().unwrap().url = Some(destination.clone());
                report.reason = Reason::DestinationRefused;
                config.publication.allows(&destination)?;
                report.reason = Reason::CredentialsUnavailable;
                let private = if signing {
                    resources.bundle_lock =
                        Some(crate::credentials::keys::Lock::acquire(&config.data)?);
                    let policy = config.publication.ready().map_err(|e| {
                        format!("receiver forwarder-key setup is incomplete or invalid: {e}")
                    })?;
                    let approval = crate::credentials::derivation::Approval::new(
                        repository.to_str().ok_or("non-UTF8 repository")?,
                        &destination,
                        reference,
                        sha,
                        mode,
                        observed,
                    )?;
                    let private =
                        signing::unlock(&policy, &mut report.reason, approval, |derive| {
                            outgoing.write(
                                &mut output,
                                Kind::ApprovePublishV1,
                                &derive.encode()?,
                            )?;
                            crate::runtime::protocol::signature(
                                &mut incoming,
                                &mut input,
                                &mut output,
                            )
                            .map_err(|e| format!("sender publication approval failed: {e}").into())
                        })?;
                    Some(private)
                } else {
                    None
                };
                report.reason = Reason::OriginUnavailable;
                output.reset(std::time::Duration::from_secs(150));
                input.reset(std::time::Duration::from_secs(150));
                resources.transaction = Some(crate::server::publication::Transaction::prepare(
                    config,
                    &access,
                    &repository,
                    private,
                    crate::server::publication::Intent {
                        mode,
                        reference,
                        observed,
                        sha,
                        url: &destination,
                    },
                    &mut report.reason,
                    &session,
                )?);
            }
        }
        let mut hook_context = config.hook_context();
        hook_context.publication = resources
            .transaction
            .as_ref()
            .map(|t| t.context().to_owned());
        hook_context.mode = mode.as_str().into();
        if let Some(Update {
            reference,
            sha,
            observed,
        }) = request
        {
            hook_context.reference = Some(reference.into());
            hook_context.sha = Some(sha.into());
            hook_context.observed = Some(observed.into());
        }
        let hook_context = hook_context.encode()?;
        outgoing.write(&mut output, Kind::Ready, b"")?;
        incoming.close();
        outgoing.close();
        native_started = result_channel;
        output.reset(std::time::Duration::from_secs(1200));
        if resources.transaction.is_some()
            && let Some(Update { reference, sha, .. }) = request
            && access
                .metadata_in(&repository, &["--verify", reference], &session)
                .ok()
                .as_deref()
                == Some(sha)
        {
            // Git will not invoke a hook for an up-to-date ref. Run that same role
            // after READY, using existing objects; there is no local mutation.
            use std::io::Write;
            let mut command = access.command(config.data.join("hooks/pre-receive"));
            command
                .current_dir(&repository)
                .env("GIT_PORTER_HOOK_CONTEXT", &hook_context)
                .stdin(std::process::Stdio::piped());
            let mut child = session.spawn(command)?;
            child
                .stdin
                .take()
                .ok_or("missing hook input")?
                .write_all(format!("{sha} {sha} {reference}\n").as_bytes())?;
            if !child.wait()?.success() {
                report.reason = Reason::PolicyRefused;
                return Err(push_result::Reported.into());
            }
        }

        let mut receive = access.git();
        receive.arg(operation).arg(&repository);
        receive.env("GIT_PORTER_HOOK_CONTEXT", &hook_context);
        report.reason = Reason::ReceiverRejected;
        let result = if result_channel {
            crate::runtime::relay::receive_framed(&session, receive, &mut output)
                .map(|status| (status, Vec::new()))
        } else {
            session.run(receive, false)
        };
        let failure = match result {
            Err(error) => Some(format!("local receive interrupted: {error}")),
            Ok((status, _)) if !status.success() => Some("local receiver update failed".into()),
            _ => {
                if let Some(Update { reference, sha, .. }) = request {
                    match access.metadata_in(&repository, &["--verify", reference], &session) {
                        Ok(actual) if actual == sha => None,
                        _ => Some("local receiver ref differs from requested commit".into()),
                    }
                } else {
                    None
                }
            }
        };
        if let Some(failure) = failure {
            return Err(failure.into());
        }
        report.receiver_ok = true;
        Ok(())
    })();
    if result_channel {
        resources.finish(config, &access, &session, &mut report);
        if !native_started
            && let Err(error) = &result
            && !error.is::<push_result::Reported>()
        {
            crate::cli::report_error("git-porter", error);
        }
        if native_started {
            push_result::write_final(&mut output, &report)?;
        } else {
            Budget::default().write(&mut output, Kind::Result, &report.encode()?)?;
        }
        return if result.is_ok() && report.successful() {
            Ok(())
        } else {
            Err(push_result::Reported.into())
        };
    }
    result
}

#[derive(Default)]
struct Resources {
    transaction: Option<crate::server::publication::Transaction>,
    bundle_lock: Option<crate::credentials::keys::Lock>,
    repository_lock: Option<RepositoryLock>,
}
impl Resources {
    // Consume all credentials and locks before writing the final network result.
    fn finish(
        mut self,
        config: &crate::server::config::ServerConfig,
        access: &super::Access,
        session: &crate::runtime::supervision::Session,
        report: &mut crate::runtime::push_result::Report,
    ) {
        use crate::runtime::push_result::{Forwarded, Outcome};
        if let Some(tx) = self.transaction.take() {
            let url = tx.url().to_owned();
            match tx.finish(config, access, report.receiver_ok, session) {
                Ok((forwarded, reason)) => {
                    report.forwarded = Some(forwarded);
                    report.receiver_reason = reason;
                }
                Err(_) => {
                    report.forwarded = Some(Forwarded {
                        url: Some(url),
                        rows: vec![],
                        outcome: Outcome::Unknown,
                    });
                    report.receiver_reason = Some("onward result uncertain".into());
                }
            }
        } else if let Some(f) = report.forwarded.as_mut() {
            f.outcome = Outcome::NotAttempted {
                reason: report.reason.clone(),
            };
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use crate::{
        runtime::{
            push_result::{HookReport, Outcome, Reason, Report},
            supervision::Session,
        },
        server::{
            config::{ServerConfig, executable},
            publication::{Intent, Transaction},
        },
    };
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    fn quote(path: &std::path::Path) -> String {
        format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
    }
    #[test]
    fn canceled_delayed_guardian_never_launches_git_and_releases_locks() {
        for cancel in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().canonicalize().unwrap();
            let repo = home.join("repo");
            git2::Repository::init_bare(&repo).unwrap();
            let policy = home.join(".gitconfig");
            fs::write(&policy, "[porter]\n").unwrap();
            let config =
                ServerConfig::read_environment(&policy, &home, &home, &home.join("cache")).unwrap();
            let access = configured_access(&config).unwrap();
            let resources = Resources {
                transaction: None,
                bundle_lock: Some(crate::credentials::keys::Lock::acquire(&home).unwrap()),
                repository_lock: Some(RepositoryLock::acquire(&access, &repo).unwrap()),
            };
            let started = home.join("guardian-pid");
            let wrapper = home.join("delayed-guardian");
            let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|dir| dir.join("sleep"))
                .find(|path| path.is_file())
                .unwrap();
            let native = crate::runtime::supervision::command(&config.git);
            fs::write(
                &wrapper,
                format!(
                    "#!/bin/sh\nprintf '%s' $$ > {}\n{} 30\nexec {} \"$@\"\n",
                    quote(&started),
                    quote(&sleep),
                    quote(std::path::Path::new(native.get_program()))
                ),
            )
            .unwrap();
            fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
            let mut command = std::process::Command::new(&wrapper);
            command.args(native.get_args()).arg("-C").arg(&repo).args([
                "config",
                "fixture.launched",
                "true",
            ]);
            let session = Session::with_timeout(if cancel {
                Duration::from_secs(10)
            } else {
                Duration::from_millis(500)
            })
            .unwrap();
            let canceled_at = std::sync::Mutex::new(None);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let start = Instant::now();
                    while fs::read_to_string(&started)
                        .ok()
                        .and_then(|value| value.parse::<i32>().ok())
                        .is_none()
                    {
                        assert!(start.elapsed() < Duration::from_secs(5));
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    *canceled_at.lock().unwrap() = Some(Instant::now());
                    if cancel {
                        session.cancel();
                    }
                });
                assert!(session.spawn(command).is_err());
            });
            resources.finish(&config, &access, &session, &mut Report::default());
            assert!(
                canceled_at.lock().unwrap().unwrap().elapsed() < Duration::from_secs(1),
                "startup cancellation did not promptly release resources"
            );
            let pid: i32 = fs::read_to_string(started).unwrap().parse().unwrap();
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "guardian not reaped");
            let local = git2::Config::open(&repo.join("config")).unwrap();
            assert!(
                local.get_string("fixture.launched").is_err(),
                "native Git launched after cancellation"
            );
            assert!(RepositoryLock::acquire(&access, &repo).is_ok());
            assert!(crate::credentials::keys::Lock::acquire(&home).is_ok());
        }
    }
    #[test]
    fn canceled_origin_checks_drop_the_key_and_both_locks_without_a_new_authentication() {
        for stage in [
            "metadata",
            "init",
            "config",
            "preflight",
            "recheck",
            "ref-check",
            "already-canceled",
        ] {
            let preflight = matches!(stage, "metadata" | "init" | "config" | "preflight");
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().canonicalize().unwrap();
            let repo = home.join("repo");
            git2::Repository::init_bare(&repo).unwrap();
            let policy = home.join(".gitconfig");
            fs::write(&policy, "[porter]\n").unwrap();
            let mut config =
                ServerConfig::read_environment(&policy, &home, &home, &home.join("cache")).unwrap();
            let slow = home.join("slow");
            let started = home.join("origin-started");
            let socket_record = home.join("socket-record");
            let git = home.join("git-spy");
            let native = executable("git").unwrap();
            let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|dir| dir.join("sleep"))
                .find(|path| path.is_file())
                .unwrap();
            fs::write(&git, format!(
                "#!/bin/sh\nblock=''\nif [ -f {slow} ]; then read -r block < {slow}; fi\nfor arg; do if [ \"$arg\" = ls-remote ]; then printf '%s' \"$GIT_PORTER_TRANSACTION_SOCKET\" > {socket}; fi; if [ \"$arg\" = \"$block\" ]; then : > {started}; exec {sleep} 30; fi; done\nfor arg; do if [ \"$arg\" = ls-remote ]; then printf '%s\\t%s\\n' '{}' 'refs/heads/contributors/test'; exit 0; fi; done\nexec {git} \"$@\"\n",
                "a".repeat(40), slow=quote(&slow), socket=quote(&socket_record),
                started=quote(&started), sleep=quote(&sleep), git=quote(&native)
            )).unwrap();
            fs::set_permissions(&git, fs::Permissions::from_mode(0o700)).unwrap();
            config.git = git;
            let access = configured_access(&config).unwrap();
            let session = Session::new().unwrap();
            let mut resources = Resources {
                transaction: None,
                bundle_lock: Some(crate::credentials::keys::Lock::acquire(&home).unwrap()),
                repository_lock: Some(RepositoryLock::acquire(&access, &repo).unwrap()),
            };
            let private =
                ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                    .unwrap();
            if preflight {
                let command = match stage {
                    "metadata" => "rev-parse",
                    "init" => "init",
                    "config" => "config",
                    _ => "ls-remote",
                };
                fs::write(&slow, format!("{command}\n")).unwrap();
            }
            let canceled_at = std::sync::Mutex::new(None);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    if stage == "already-canceled" {
                        return;
                    }
                    let start = Instant::now();
                    while !started.exists() {
                        assert!(
                            start.elapsed() < Duration::from_secs(5),
                            "origin check never started"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    *canceled_at.lock().unwrap() = Some(Instant::now());
                    session.cancel();
                });
                let tx = Transaction::prepare(
                    &config,
                    &access,
                    &repo,
                    Some(private),
                    Intent {
                        mode: "ff",
                        reference: "refs/heads/contributors/test",
                        observed: "",
                        sha: &"b".repeat(40),
                        url: "git@github.com:org/repo",
                    },
                    &mut Reason::OriginUnavailable,
                    &session,
                );
                if preflight {
                    assert!(tx.is_err());
                } else {
                    let tx = tx.unwrap();
                    let record = HookReport {
                        version: 1,
                        reference: "refs/heads/contributors/test".into(),
                        intended: "b".repeat(40),
                        attempted: true,
                        accepted: false,
                        rows: vec![],
                        reason: Reason::Interrupted,
                    };
                    crate::server::authorized::atomic(
                        &tx.context().parent().unwrap().join("hook-result.json"),
                        &serde_json::to_vec(&record).unwrap(),
                    )
                    .unwrap();
                    resources.transaction = Some(tx);
                    fs::write(
                        &slow,
                        if stage == "ref-check" {
                            b"rev-parse\n".as_slice()
                        } else {
                            b"ls-remote\n".as_slice()
                        },
                    )
                    .unwrap();
                    if stage == "already-canceled" {
                        *canceled_at.lock().unwrap() = Some(Instant::now());
                        session.cancel();
                    }
                }
                if stage == "ref-check" {
                    assert!(
                        access
                            .metadata_in(
                                &repo,
                                &["--verify", "refs/heads/contributors/test"],
                                &session
                            )
                            .is_err()
                    );
                }
                let mut report = Report::default();
                resources.finish(&config, &access, &session, &mut report);
                if !preflight {
                    assert!(matches!(
                        report.forwarded.unwrap().outcome,
                        Outcome::Unknown
                    ));
                }
            });
            assert!(
                canceled_at.lock().unwrap().unwrap().elapsed() < Duration::from_secs(3),
                "key-held subprocess outlived cancellation in {stage}"
            );
            fs::remove_file(&slow).unwrap();
            if stage == "already-canceled" {
                assert!(
                    !started.exists(),
                    "canceled receiver started fresh authentication"
                );
            }
            if socket_record.exists() {
                let socket = std::path::PathBuf::from(fs::read_to_string(&socket_record).unwrap());
                assert!(
                    !socket.exists(),
                    "transaction signing material/socket still live"
                );
                assert!(
                    !socket.parent().unwrap().exists(),
                    "agent directory retained"
                );
            } else {
                assert!(
                    matches!(stage, "metadata" | "init" | "config"),
                    "preflight never reached agent"
                );
            }
            assert!(RepositoryLock::acquire(&access, &repo).is_ok());
            assert!(crate::credentials::keys::Lock::acquire(&home).is_ok());
            // A canceled owner cannot prepare another origin command.
            assert!(session.bounded(Duration::from_secs(120)).is_err());
        }
    }
}
