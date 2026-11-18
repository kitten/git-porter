#[path = "support/source_agent.rs"]
mod source_agent;
use git_porter::runtime::supervision::{self, Session};
use source_agent::Agent;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "bounded lifecycle condition was not met"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn git(path: &Path, args: &[&str]) -> std::process::Output {
    let result = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result
}
#[test]
fn exec_guardian_preserves_environment_bytes_streams_and_exit_status() {
    let session = Session::new().unwrap();
    let mut command = supervision::command("/bin/sh");
    command.env_clear().env("EXACT", "space ' quote").args([
        "-c",
        "printf '%s:%s' \"$EXACT\" \"${GIT_PORTER_CHILD_CONTROL-unset}\"",
    ]);
    let (status, output) = session.run(command, true).unwrap();
    assert!(status.success());
    assert_eq!(output, b"space ' quote:unset");
    let mut command = supervision::command("/bin/sh");
    command.args(["-c", "exit 42"]);
    assert_eq!(session.run(command, true).unwrap().0.code(), Some(42));
}
#[test]
fn killing_client_or_helper_stops_git_ssh_and_descendants_without_touching_source_agent() {
    let source =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let source_public = source.public_key().clone();
    let agent = Agent::start(source).unwrap();
    for helper in [false, true] {
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().canonicalize().unwrap();
            let repository = root.join("repository");
            fs::create_dir(&repository).unwrap();
            git(&repository, &["init", "-q"]);
            git(
                &repository,
                &["symbolic-ref", "HEAD", "refs/heads/contributors/work"],
            );
            git(
                &repository,
                &[
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "fixture",
                ],
            );
            git(
                &repository,
                &[
                    "remote",
                    "add",
                    "origin",
                    "git@example.invalid:group/repo.git",
                ],
            );
            let bin = root.join("bin");
            fs::create_dir(&bin).unwrap();
            let native = root.join("native-pid");
            let descendant = root.join("descendant-pid");
            let ssh = bin.join("ssh");
            fs::write(
                &ssh,
                format!(
                    "#!/bin/sh\nprintf '%s' $$ > {}\nsleep 60 &\nprintf '%s' $! > {}\nwait\n",
                    quote(&native),
                    quote(&descendant)
                ),
            )
            .unwrap();
            fs::set_permissions(ssh, fs::Permissions::from_mode(0o700)).unwrap();
            let mut command = if helper {
                let path = bin.join("client-ssh");
                std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &path).unwrap();
                let mut command = Command::new(path);
                command
                    .args(["fixture", "git-receive-pack 'porter'"])
                    .env("GIT_PORTER_CLIENT_DESTINATION", "fixture")
                    .env("GIT_PORTER_CLIENT_PUBLISH", "false")
                    .env(
                        "GIT_PORTER_CLIENT_ORIGIN",
                        "git@example.invalid:group/repo.git",
                    );
                command
            } else {
                let mut command = Command::new(env!("CARGO_BIN_EXE_git-send"));
                command.args(["--local-only", "fixture"]);
                command
            };
            command
                .current_dir(&repository)
                .env(
                    "PATH",
                    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                )
                .env("HOME", &root)
                .env_remove("XDG_DATA_HOME")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("XDG_CACHE_HOME")
                .env_remove("XDG_STATE_HOME")
                .env_remove("XDG_RUNTIME_DIR")
                .env_remove("XDG_DATA_DIRS")
                .env_remove("XDG_CONFIG_DIRS")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("SSH_AUTH_SOCK", agent.socket())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(fs::File::create(root.join("lifecycle-stderr")).unwrap());
            let mut process = Process(command.spawn().unwrap());
            wait_for(|| {
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "client exited before SSH fixture: {}",
                    fs::read_to_string(root.join("lifecycle-stderr")).unwrap()
                );
                fs::read_to_string(&descendant).is_ok_and(|s| !s.is_empty())
            });
            let native: i32 = fs::read_to_string(native).unwrap().parse().unwrap();
            let descendant: i32 = fs::read_to_string(descendant).unwrap().parse().unwrap();
            let start = Instant::now();
            assert_eq!(unsafe { libc::kill(process.0.id() as i32, signal) }, 0);
            wait_for(|| process.0.try_wait().unwrap().is_some());
            wait_for(|| unsafe { libc::kill(native, 0) } == -1 && unsafe { libc::kill(descendant, 0) } == -1);
            assert!(start.elapsed() < Duration::from_secs(3));
            let identities = git_porter::credentials::agent::Client::connect(&agent.socket())
                .unwrap()
                .list_all_identities()
                .unwrap();
            assert!(
                identities
                    .iter()
                    .any(|id| id.key_data() == source_public.key_data())
            );
        }
    }
}

#[test]
fn receiver_key_and_onward_processes_end_when_the_unwrapped_owner_is_killed() {
    use git_porter::{
        credentials::derivation::PublishRequest,
        credentials::wrapping::{Bundle, Metadata},
        runtime::protocol::{Budget, DeadlineIo, Kind},
    };
    use signature::Signer;
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let home = root.join("home");
        let repo = home.join("repositories/repo.git");
        let data = home.join(".local/share/git-porter");
        let bin = root.join("bin");
        for path in [&home, &repo, &data, &bin] {
            fs::create_dir_all(path).unwrap();
        }
        git(&repo, &["init", "--bare", "-q"]);
        git(
            &repo,
            &[
                "remote",
                "add",
                "origin",
                "git@forge.example:group/repo.git",
            ],
        );
        let source =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let source_agent = Agent::start(source.clone()).unwrap();
        let key = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let public = key.public_key().clone();
        let metadata = Metadata::generate(source.public_key()).unwrap();
        let signature: ssh_key::Signature = source
            .try_sign(&metadata.challenge(source.public_key()).unwrap())
            .unwrap();
        let identity = metadata
            .from_signature(source.public_key(), &signature)
            .unwrap();
        let plaintext = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let mut bundle = Vec::new();
        Bundle {
            metadata,
            ciphertext: age::encrypt(&identity.to_public(), plaintext.as_bytes()).unwrap(),
        }
        .write(&mut bundle)
        .unwrap();
        fs::write(data.join("publication.wrapped"), bundle).unwrap();
        fs::set_permissions(
            data.join("publication.wrapped"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(
            data.join("publication.source.pub"),
            source.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        fs::write(data.join("publication.pub"), public.to_openssh().unwrap()).unwrap();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(
            home.join(".ssh/known_hosts"),
            format!(
                "forge.example {}\n",
                source.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        for entry in ["hooks/pre-receive", "transport/ssh"] {
            let path = data.join(entry);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), path).unwrap();
        }
        let config = home.join(".gitconfig");
        fs::write(&config, format!("[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\nallowedPushPrefix = contributors/\npublishTo = forge.example\n", repo.parent().unwrap().display(), source.public_key().to_openssh().unwrap())).unwrap();
        let forbidden = root.join("transport-must-not-execute");
        let forged = Command::new(data.join("transport/ssh"))
            .args([
                "--porter-owned-command",
                "/bin/sh",
                "-c",
                "touch \"$1\"",
                "fixture",
            ])
            .arg(&forbidden)
            .env("HOME", &home)
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap();
        assert!(!forged.status.success());
        assert!(!forbidden.exists());
        let log = root.join("onward-argv");
        let pid = root.join("onward-pid");
        let ssh = bin.join("ssh");
        fs::write(
            &ssh,
            format!(
                "#!/bin/sh\nprintf '%s' $$ > {}\nprintf '%s\\n' \"$@\" > {}\nexec {} 60\n",
                quote(&pid),
                quote(&log),
                quote(
                    &std::env::split_paths(&std::env::var_os("PATH").unwrap())
                        .map(|directory| directory.join("sleep"))
                        .find(|path| path.is_file())
                        .expect("devShell sleep executable"),
                )
            ),
        )
        .unwrap();
        fs::set_permissions(ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let make_server = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_git-porter"));
            for (key, _) in
                std::env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("XDG_"))
            {
                command.env_remove(key);
            }
            command
                .arg("internal:serve")
                .env(
                    "PATH",
                    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                )
                .env("SSH_ORIGINAL_COMMAND", "git-porter-session-v1")
                .env("HOME", &home)
                .env("SSH_AUTH_SOCK", "/receiver-local-agent-must-not-be-used")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(fs::File::create(root.join("server-stderr")).unwrap());
            command
        };
        let intent = format!(
            "intent-v2\0receive\0{}\0\0ff\0refs/heads/contributors/test\0{}\0",
            repo.display(),
            "a".repeat(40)
        );
        // A forbidden rewritten destination must fail before any derivation
        // request, not merely before network authentication or receipt.
        git(
            &repo,
            &[
                "remote",
                "set-url",
                "origin",
                "git@disallowed.example:group/repo.git",
            ],
        );
        let mut bad = make_server().spawn().unwrap();
        let mut frames = Vec::new();
        let mut budget = Budget::default();
        budget
            .write(&mut frames, Kind::Hello, b"publish-v5")
            .unwrap();
        budget
            .write(&mut frames, Kind::Intent, intent.as_bytes())
            .unwrap();
        use std::io::Write;
        bad.stdin.take().unwrap().write_all(&frames).unwrap();
        let denied = bad.wait_with_output().unwrap();
        assert!(!denied.status.success());
        let mut bytes = denied.stdout.as_slice();
        let mut budget = Budget::default();
        assert_eq!(budget.read(&mut bytes).unwrap().0, Kind::Hello);
        assert_eq!(budget.read(&mut bytes).unwrap().0, Kind::Resolved);
        let (kind, result) = budget.read(&mut bytes).unwrap();
        assert_eq!(kind, Kind::Result);
        let result = git_porter::runtime::push_result::Report::parse(&result).unwrap();
        assert!(matches!(
            result.forwarded.unwrap().outcome,
            git_porter::runtime::push_result::Outcome::NotAttempted { .. }
        ));
        assert!(bytes.is_empty(), "forbidden origin requested derivation");
        assert!(!log.exists());
        git(
            &repo,
            &[
                "remote",
                "set-url",
                "origin",
                "git@forge.example:group/repo.git",
            ],
        );
        let mut server = Process(make_server().spawn().unwrap());
        let mut input = DeadlineIo::new(server.0.stdout.take().unwrap(), Duration::from_secs(5));
        let mut output = DeadlineIo::new(server.0.stdin.take().unwrap(), Duration::from_secs(5));
        let mut incoming = Budget::default();
        let mut outgoing = Budget::default();
        outgoing
            .write(&mut output, Kind::Hello, b"publish-v5")
            .unwrap();
        assert_eq!(
            incoming.read(&mut input).unwrap(),
            (Kind::Hello, b"publish-v5".to_vec())
        );
        outgoing
            .write(&mut output, Kind::Intent, intent.as_bytes())
            .unwrap();
        assert_eq!(incoming.read(&mut input).unwrap().0, Kind::Resolved);
        let (kind, request) = incoming.read(&mut input).unwrap();
        assert_eq!(kind, Kind::ApprovePublishV1);
        let request = PublishRequest::parse(&request).unwrap();
        let mut response = Vec::new();
        for challenge in [
            request
                .current
                .metadata
                .challenge(&request.current.source)
                .unwrap(),
            request.approval_challenge().unwrap(),
        ] {
            let signature: ssh_key::Signature = source.try_sign(&challenge).unwrap();
            response.extend(signature.as_bytes());
        }
        outgoing.write(&mut output, Kind::Signing, b"").unwrap();
        outgoing.write(&mut output, Kind::SigningDone, b"").unwrap();
        outgoing
            .write(&mut output, Kind::Signature, &response)
            .unwrap();
        wait_for(|| fs::read_to_string(&log).is_ok_and(|s| s.contains("IdentityAgent=")));
        let native: i32 = fs::read_to_string(pid).unwrap().parse().unwrap();
        let args = fs::read_to_string(log).unwrap();
        let agent = args
            .lines()
            .find_map(|s| {
                s.strip_prefix("IdentityAgent=\"")
                    .and_then(|s| s.strip_suffix('"'))
            })
            .unwrap();
        let socket = Path::new(agent);
        let mut connection = git_porter::credentials::agent::Client::connect(socket).unwrap();
        assert!(
            connection.list_all_identities().is_err(),
            "non-ssh peer must not access transaction agent"
        );
        let directory = socket.parent().unwrap();
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                assert!(!fs::read_to_string(path).unwrap().contains("PRIVATE KEY"));
            }
        }
        let start = Instant::now();
        assert_eq!(unsafe { libc::kill(server.0.id() as i32, signal) }, 0);
        wait_for(|| server.0.try_wait().unwrap().is_some());
        wait_for(|| unsafe { libc::kill(native, 0) } == -1);
        assert!(connection.list_all_identities().is_err());
        assert!(git_porter::credentials::agent::Client::connect(socket).is_err());
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(
            git_porter::credentials::agent::Client::connect(&source_agent.socket())
                .unwrap()
                .list_all_identities()
                .is_ok()
        );
        assert!(git(&repo, &["for-each-ref"]).stdout.is_empty());
        if directory.exists() {
            assert!(
                directory
                    .file_name()
                    .unwrap()
                    .as_encoded_bytes()
                    .starts_with(b"porter-agent-")
            );
            fs::remove_dir_all(directory).unwrap();
        }
    }
}
