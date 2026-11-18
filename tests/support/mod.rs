mod source_agent;
use git_porter::server::authorized;
use source_agent::Agent;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

fn ok(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn command(program: impl AsRef<std::ffi::OsStr>, home: &Path) -> Command {
    let mut c = Command::new(program);
    c.env("HOME", home)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("XDG_DATA_DIRS")
        .env_remove("XDG_CONFIG_DIRS")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env_remove("SSH_AUTH_SOCK");
    if home.join("custom-config/git/config").exists() {
        c.env("XDG_CONFIG_HOME", home.join("custom-config"));
    }
    c
}
fn git(repo: &Path, args: &[&str]) -> Output {
    ok(command("git", repo)
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap())
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Actual OpenSSH, compiled forced command, temporary receiver/forge/client homes
/// and synthetic credentials. Managed mode executes only the module's fragment.
pub fn acceptance(managed: bool) {
    let tmp = tempfile::Builder::new()
        .prefix("porter-e2e-")
        .tempdir()
        .unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let receiver_home = root.join("receiver");
    let forge_home = root.join("forge");
    let client = root.join("client");
    let destination = receiver_home.join("projects/other-owner/repo");
    let origin = forge_home.join("projects/repo");
    for p in [&destination, &origin, &client] {
        fs::create_dir_all(p).unwrap();
    }
    git(&destination, &["init", "--bare", "-q"]);
    git(&origin, &["init", "--bare", "-q"]);
    git(&client, &["init", "-q"]);
    git(
        &client,
        &["symbolic-ref", "HEAD", "refs/heads/contributors/test"],
    );
    git(&client, &["commit", "--allow-empty", "-qm", "first"]);
    let sender_hook = client.join(".git/hooks/pre-push");
    fs::write(
        &sender_hook,
        "#!/bin/sh\nprintf 'sender pre-push diagnostic\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&sender_hook, fs::Permissions::from_mode(0o700)).unwrap();
    let source =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let source_public = source.public_key().clone();
    let agent = Agent::start(source.clone()).unwrap();
    let auth = root.join("authentication");
    fs::write(
        &auth,
        source
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        root.join("authentication.pub"),
        source_public.to_openssh().unwrap(),
    )
    .unwrap();
    let host = root.join("host");
    ok(command("ssh-keygen", &root)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&host)
        .output()
        .unwrap());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let username =
        String::from_utf8(ok(Command::new("id").arg("-un").output().unwrap()).stdout).unwrap();
    let username = username.trim();
    let trust = root.join("known_hosts");
    fs::write(
        &trust,
        format!(
            "[127.0.0.1]:{port} {}",
            fs::read_to_string(root.join("host.pub")).unwrap()
        ),
    )
    .unwrap();
    let mut binaries = std::env::var_os("GIT_PORTER_TEST_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_BIN_EXE_git-porter"))
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .canonicalize()
        .expect("test binary directory must exist");
    let data = receiver_home.join(".local/share/git-porter");
    let config = receiver_home.join(".gitconfig");
    fs::create_dir_all(&data).unwrap();
    fs::write(
        data.join("publication.source.pub"),
        source_public.to_openssh().unwrap(),
    )
    .unwrap();
    let activation = if managed {
        let flake = std::env::var("GIT_PORTER_TEST_FLAKE")
            .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").into());
        let metadata = ok(Command::new("nix")
            .args(["flake", "metadata", "--json", &flake])
            .output()
            .unwrap());
        let metadata: serde_json::Value = serde_json::from_slice(&metadata.stdout).unwrap();
        let snapshot = metadata["path"].as_str().unwrap();
        binaries = PathBuf::from(
            String::from_utf8(
                ok(Command::new("nix")
                    .args([
                        "build",
                        "--no-link",
                        "--print-out-paths",
                        &format!("path:{snapshot}#default"),
                    ])
                    .output()
                    .unwrap())
                .stdout,
            )
            .unwrap()
            .trim(),
        )
        .join("bin");
        let args = root.join("module.json");
        fs::write(&args,serde_json::to_vec(&serde_json::json!({"home":receiver_home,"username":username,"publicKey":source_public.to_openssh().unwrap()})).unwrap()).unwrap();
        let expression = format!(
            "import {snapshot}/tests/e2e/managed.nix ((builtins.fromJSON (builtins.readFile {})) // {{ flake = builtins.getFlake \"path:{snapshot}\"; }})",
            serde_json::to_string(&args).unwrap()
        );
        let output = ok(Command::new("nix")
            .args(["eval", "--impure", "--json", "--expr", &expression])
            .output()
            .unwrap());
        let fixture: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            PathBuf::from(fixture["package"].as_str().unwrap()).join("bin"),
            binaries
        );
        for file in fixture["files"].as_array().unwrap() {
            let target = Path::new(file["target"].as_str().unwrap());
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            if let Some(text) = file["text"].as_str() {
                fs::write(target, text).unwrap();
                fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
            } else {
                std::os::unix::fs::symlink(file["source"].as_str().unwrap(), target).unwrap();
            }
        }
        let activation = root.join("activation");
        fs::write(
            &activation,
            format!(
                "#!/bin/sh\nset -eu\nrun() {{ \"$@\"; }}\n{}",
                fixture["activation"].as_str().unwrap()
            ),
        )
        .unwrap();
        Some(activation)
    } else {
        None
    };
    let porter = binaries.join("git-porter");
    let sender = binaries.join("git-send");
    let receive = binaries.join("git-receive");
    let url = format!("ssh://{username}@127.0.0.1:{port}{}", origin.display());
    for repo in [&client, &destination] {
        git(repo, &["remote", "add", "origin", &url]);
    }
    if let Some(activation) = &activation {
        ok(command("bash", &receiver_home)
            .arg(activation)
            .env("XDG_CONFIG_HOME", root.join("wrong-config"))
            .output()
            .unwrap());
    } else {
        fs::create_dir_all(&data).unwrap();
        fs::write(&config,format!("[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\nallowedPushPrefix = contributors/\npublishTo = 127.0.0.1\n",receiver_home.join("projects").display(),source_public.to_openssh().unwrap())).unwrap();
        ok(command(&porter, &receiver_home)
            .args(["setup", "--yes"])
            .output()
            .unwrap());
    }
    let mut setup = command(&porter, &receiver_home);
    setup.arg("key:create");
    setup.stdout(Stdio::null()).stderr(Stdio::from(
        fs::File::create(root.join("setup.err")).unwrap(),
    ));
    if !managed {
        setup.env("SSH_AUTH_SOCK", agent.socket());
    }
    let mut setup = Daemon(setup.spawn().unwrap());
    if managed {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let jobs = fs::read_dir(data.join("pending"))
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .any(|e| e.path().extension().is_some_and(|s| s == "job"));
            if jobs {
                break;
            }
            assert!(
                setup.0.try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(root.join("setup.err")).unwrap()
            );
            assert!(Instant::now() < until, "pending job missing");
            std::thread::sleep(Duration::from_millis(20));
        }
    } else {
        assert!(
            setup.0.wait().unwrap().success(),
            "{}",
            fs::read_to_string(root.join("setup.err")).unwrap()
        );
    }
    let authorization = root.join("authorized_keys");
    fs::write(&authorization, fixture_authorization(&receiver_home)).unwrap();
    let sshd_config = root.join("sshd_config");
    fs::write(&sshd_config,format!("Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}/pid\nAuthorizedKeysFile {} {}/.ssh/authorized_keys\nStrictModes no\nUsePAM no\nPermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowAgentForwarding no\nDisableForwarding yes\nSetEnv SSH_AUTH_SOCK=/nonexistent/receiver-local-agent\nAllowUsers {username}\n",host.display(),root.display(),authorization.display(),forge_home.display())).unwrap();
    let sshd = git_porter::server::config::executable("sshd").unwrap();
    let mut daemon = Daemon(
        command(sshd, &root)
            .args(["-D", "-e", "-f"])
            .arg(&sshd_config)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                fs::File::create(root.join("sshd.log")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(5);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            daemon.0.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(root.join("sshd.log")).unwrap()
        );
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(20));
    }
    let client_trust = root.join("client-known_hosts");
    fs::copy(&trust, &client_trust).unwrap();
    let ssh_config = root.join("ssh_config");
    fs::write(&ssh_config,format!("Host fixture\n HostName 127.0.0.1\n Port {port}\n User {username}\n IdentityFile {}\n IdentityAgent none\n IdentitiesOnly yes\n UserKnownHostsFile {}\n StrictHostKeyChecking yes\n",auth.display(),client_trust.display())).unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let ssh = git_porter::server::config::executable("ssh").unwrap();
    let wrapper = bin.join("ssh");
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec {} -F {} \"$@\"\n",
            quote(&ssh),
            quote(&ssh_config)
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let client_command = |binary: &Path, flags: &[&str]| {
        let mut c = command(binary, &client);
        c.current_dir(&client)
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .args(flags)
            .arg("fixture");
        c
    };
    let run_client = |binary: &Path, flags: &[&str]| {
        client_command(binary, flags)
            .env("SSH_AUTH_SOCK", agent.socket())
            .output()
            .unwrap()
    };
    let without_agent = |binary: &Path, flags: &[&str]| {
        client_command(binary, flags)
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap()
    };
    if managed {
        ok(without_agent(&porter, &["key:create", "--sign"]));
        assert!(
            setup.0.wait().unwrap().success(),
            "{}",
            fs::read_to_string(root.join("setup.err")).unwrap()
        );
    }
    let receiver_trust = {
        let path = receiver_home.join(".ssh/known_hosts");
        fs::copy(&trust, &path).unwrap();
        path
    };
    let public = fs::read_to_string(data.join("publication.pub")).unwrap();
    let forge_data = forge_home.join(".local/share/git-porter");
    fs::create_dir_all(&forge_data).unwrap();
    fs::write(forge_home.join(".gitconfig"),format!("[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\nallowedPushPrefix = contributors/\n",forge_home.join("projects").display(),public.trim())).unwrap();
    fs::create_dir_all(forge_home.join(".ssh")).unwrap();
    fs::write(forge_home.join(".ssh/authorized_keys"), "").unwrap();
    ok(command(&porter, &forge_home)
        .args(["setup", "--yes"])
        .output()
        .unwrap());
    fs::write(
        forge_home.join(".ssh/authorized_keys"),
        fixture_authorization(&forge_home),
    )
    .unwrap();
    ok(git(
        &client,
        &["push", origin.to_str().unwrap(), "HEAD:refs/heads/main"],
    ));
    ok(git(&origin, &["symbolic-ref", "HEAD", "refs/heads/main"]));
    let stored_bundle = fs::read(data.join("publication.wrapped")).unwrap();
    let sent = ok(without_agent(&sender, &[]));
    let stderr = String::from_utf8_lossy(&sent.stderr);
    for noise in ["Identity added:", "Lifetime set to", "Unsupported option"] {
        assert!(
            !stderr.contains(noise),
            "unexpected internal diagnostic: {stderr}"
        );
    }
    assert_eq!(
        fs::read(data.join("publication.wrapped")).unwrap(),
        stored_bundle,
        "successful forwarding must not rewrite the encrypted bundle"
    );
    if managed {
        let intended = git(&client, &["rev-parse", "HEAD"]).stdout;
        for repository in [&destination, &origin] {
            assert_eq!(
                git(repository, &["rev-parse", "refs/heads/contributors/test"]).stdout,
                intended
            );
        }
        return;
    }
    for scenario in [
        InlineScenario::SlowForge,
        InlineScenario::CheckoutDuringApproval,
    ] {
        inline_publication_after_approval(
            &porter,
            &receiver_home,
            &forge_home,
            &destination,
            &source,
            scenario,
        );
    }

    // With no environment socket, use an explicitly configured agent first.
    let original_ssh = fs::read_to_string(&ssh_config).unwrap();
    fs::write(
        &ssh_config,
        original_ssh.replace("IdentityAgent none", "IdentityAgent SSH_AUTH_SOCK"),
    )
    .unwrap();
    ok(without_agent(&sender, &[]));

    fs::write(
        &ssh_config,
        original_ssh.replace(
            "IdentityAgent none",
            &format!("IdentityAgent {}", agent.socket().display()),
        ),
    )
    .unwrap();
    ok(without_agent(&sender, &[]));
    let bundle_before_broken_agent = fs::read(data.join("publication.wrapped")).unwrap();
    fs::write(
        &ssh_config,
        original_ssh.replace(
            "IdentityAgent none",
            &format!("IdentityAgent {}", root.join("missing-agent").display()),
        ),
    )
    .unwrap();
    assert!(
        !without_agent(&sender, &[]).status.success(),
        "broken configured agent fell back to a valid file"
    );
    assert_eq!(
        fs::read(data.join("publication.wrapped")).unwrap(),
        bundle_before_broken_agent
    );
    fs::write(&ssh_config, original_ssh).unwrap();
    // Protection is independent of matching write prefixes and force mode.
    ok(git(
        &origin,
        &["symbolic-ref", "HEAD", "refs/heads/contributors/test"],
    ));
    let protected = run_client(&sender, &["--force"]);
    assert!(!protected.status.success());
    assert!(!String::from_utf8_lossy(&protected.stderr).contains("porter."));
    assert!(
        String::from_utf8_lossy(&protected.stderr).contains("default branch is protected"),
        "{}",
        String::from_utf8_lossy(&protected.stderr)
    );
    let original = fs::read_to_string(&config).unwrap();
    ok(git(
        &receiver_home,
        &[
            "config",
            "--file",
            config.to_str().unwrap(),
            "porter.allowDefaultBranch",
            "true",
        ],
    ));
    ok(run_client(&sender, &[]));
    fs::write(&config, &original).unwrap();
    ok(git(
        &origin,
        &["symbolic-ref", "HEAD", "refs/heads/unknown"],
    ));
    let unknown = run_client(&sender, &[]);
    assert!(!unknown.status.success());
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("default branch could not be determined"),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );
    ok(git(
        &origin,
        &["symbolic-ref", "HEAD", "refs/heads/contributors/test"],
    ));
    ok(git(
        &receiver_home,
        &[
            "config",
            "--file",
            config.to_str().unwrap(),
            "--unset-all",
            "porter.allowedPushPrefix",
        ],
    ));
    assert!(!run_client(&sender, &[]).status.success());
    fs::write(&config, &original).unwrap();
    ok(git(&origin, &["symbolic-ref", "HEAD", "refs/heads/main"]));
    let tip = git(&client, &["rev-parse", "HEAD"]).stdout;
    assert_eq!(
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        tip
    );
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        tip
    );
    git(&client, &["commit", "--allow-empty", "-qm", "second"]);
    let before = git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout;
    // A wrong ambient agent cannot fall back to the otherwise matching source file.
    let before_refusal = fs::read(data.join("publication.wrapped")).unwrap();
    let wrong_source = Agent::start(
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap(),
    )
    .unwrap();
    let denied = client_command(&sender, &[])
        .env("SSH_AUTH_SOCK", wrong_source.socket())
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert_eq!(
        before_refusal,
        fs::read(data.join("publication.wrapped")).unwrap()
    );
    assert_eq!(
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        before
    );
    let trust_bytes = fs::read(&receiver_trust).unwrap();
    fs::write(&receiver_trust, "# deliberately missing onward host key\n").unwrap();
    let rejected = run_client(&sender, &[]);
    assert!(!rejected.status.success(), "unknown origin host accepted");
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("pre-authentication"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert_eq!(
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        before
    );
    fs::write(&receiver_trust, trust_bytes).unwrap();
    let success = ok(run_client(&sender, &[]));
    assert!(String::from_utf8_lossy(&success.stderr).contains("sender pre-push diagnostic"));
    let tip = git(&client, &["rev-parse", "HEAD"]).stdout;
    git(&client, &["reset", "--hard", "HEAD~1"]);
    ok(run_client(&receive, &[]));
    assert_eq!(git(&client, &["rev-parse", "HEAD"]).stdout, tip);
    let before_origin = git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout;
    git(&client, &["commit", "--allow-empty", "-qm", "local only"]);
    ok(run_client(&sender, &["--local-only"]));
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        before_origin
    );
    let forge_policy = forge_home.join(".gitconfig");
    let original_policy = fs::read_to_string(&forge_policy).unwrap();
    fs::write(
        &forge_policy,
        original_policy.replace("contributors/", "blocked/"),
    )
    .unwrap();
    fs::write(
        forge_home.join(".ssh/authorized_keys"),
        fixture_authorization(&forge_home),
    )
    .unwrap();
    // Receiver already has the local-only commit: the explicit hook path must
    // re-check origin after its rejected onward push too.
    let already_present = run_client(&sender, &[]);
    assert!(!already_present.status.success());
    assert!(
        String::from_utf8_lossy(&already_present.stderr).contains("[not published]"),
        "{}",
        String::from_utf8_lossy(&already_present.stderr)
    );
    let before_receiver = git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout;
    git(
        &client,
        &[
            "commit",
            "--allow-empty",
            "-qm",
            "must be rejected with origin",
        ],
    );
    let partial = run_client(&sender, &[]);
    assert!(!partial.status.success());
    assert!(
        String::from_utf8_lossy(&partial.stderr).contains("[not published]"),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    assert!(
        String::from_utf8_lossy(&partial.stderr).contains("rejected"),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    assert_eq!(
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        before_receiver
    );
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        before_origin
    );
    fs::write(&forge_policy, original_policy).unwrap();
    fs::write(
        forge_home.join(".ssh/authorized_keys"),
        fixture_authorization(&forge_home),
    )
    .unwrap();
    ok(run_client(&sender, &[]));
    assert_eq!(
        git_porter::credentials::agent::Client::connect(&agent.socket())
            .unwrap()
            .list_all_identities()
            .unwrap()
            .len(),
        1
    );
    assert!(!client.join(".local/share/git-porter").exists());
    assert!(!data.join("credentials").exists());
    for name in [
        "publication.wrapped",
        "publication.pub",
        "publication.source.pub",
    ] {
        assert!(
            !fs::symlink_metadata(data.join(name))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    git(
        &client,
        &["commit", "--amend", "--allow-empty", "-qm", "rewritten"],
    );
    assert!(!run_client(&sender, &[]).status.success());
    ok(run_client(&sender, &["--force-with-lease"]));
    let rewritten = git(&client, &["rev-parse", "HEAD"]).stdout;
    assert_eq!(
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        rewritten
    );
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        rewritten
    );
    git(
        &client,
        &[
            "commit",
            "--allow-empty",
            "-qm",
            "partial local update failure",
        ],
    );
    let previous = git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout;
    let lock = destination.join("refs/heads/contributors/test.lock");
    fs::write(&lock, b"fixture lock").unwrap();
    let partial = run_client(&sender, &[]);
    assert!(!partial.status.success());
    assert!(
        String::from_utf8_lossy(&partial.stderr).contains("intended commit confirmed at origin"),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    assert_eq!(
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        previous
    );
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        git(&client, &["rev-parse", "HEAD"]).stdout
    );
    fs::remove_file(lock).unwrap();
    ok(run_client(&sender, &[]));
    // Inject a ref move after the client's ls-remote session, before its push.
    for moved in [&origin, &destination] {
        let baseline = git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout;
        git(
            &client,
            &["commit", "--allow-empty", "-qm", "competing writer"],
        );
        let competing = String::from_utf8(git(&client, &["rev-parse", "HEAD"]).stdout).unwrap();
        let competing = competing.trim();
        git(
            moved,
            &["fetch", "--no-tags", client.to_str().unwrap(), competing],
        );
        git(
            &client,
            &[
                "commit",
                "--amend",
                "--allow-empty",
                "-qm",
                "intended update",
            ],
        );
        let raced = root.join("race-ssh");
        let marker = root.join("race-once");
        if marker.exists() {
            fs::remove_file(&marker).unwrap();
        }
        fs::write(&raced,format!("#!/bin/sh\n{} -F {} \"$@\" || exit\nif [ ! -e {} ]; then : > {}; {} --git-dir={} update-ref refs/heads/contributors/test {}; fi\n",quote(&ssh),quote(&ssh_config),quote(&marker),quote(&marker),quote(&git_porter::server::config::executable("git").unwrap()),quote(moved),competing)).unwrap();
        fs::set_permissions(&raced, fs::Permissions::from_mode(0o700)).unwrap();
        let result = command(&sender, &client)
            .current_dir(&client)
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("SSH_AUTH_SOCK", agent.socket())
            .env("GIT_SSH_COMMAND", quote(&raced))
            .args(["--force-with-lease", "fixture"])
            .output()
            .unwrap();
        assert!(
            !result.status.success(),
            "a stale observed lease was accepted"
        );
        let untouched = if moved == &origin {
            &destination
        } else {
            &origin
        };
        assert_eq!(
            git(untouched, &["rev-parse", "refs/heads/contributors/test"]).stdout,
            baseline
        );
        ok(run_client(&sender, &["--force"]));
        let new = git(&client, &["rev-parse", "HEAD"]).stdout;
        assert_eq!(
            git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout,
            new
        );
        assert_eq!(
            git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
            new
        );
    }
    assert!(
        !run_client(&sender, &["--force", "--force-with-lease"])
            .status
            .success()
    );
    // A missing promisor blob must be hydrated by an additional SSH process
    // descended from the onward Git command, without broadening credentials.
    fs::write(client.join("hydrate"), b"synthetic lazy object hydration").unwrap();
    ok(git(&client, &["add", "hydrate"]));
    ok(git(
        &client,
        &["commit", "-qm", "hydrate isolated onward objects"],
    ));
    ok(git(
        &client,
        &[
            "push",
            origin.to_str().unwrap(),
            "HEAD:refs/heads/hydration-seed",
        ],
    ));
    ok(git(
        &origin,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    ));
    ok(git(&origin, &["config", "uploadpack.allowFilter", "true"]));
    ok(git(
        &origin,
        &["update-ref", "-d", "refs/heads/hydration-seed"],
    ));
    ok(run_client(&sender, &["--local-only"]));
    let blob = String::from_utf8(git(&client, &["rev-parse", "HEAD:hydrate"]).stdout).unwrap();
    let blob = blob.trim();
    let loose = destination
        .join("objects")
        .join(&blob[..2])
        .join(&blob[2..]);
    assert!(loose.is_file(), "fixture requires a loose hydration blob");
    fs::remove_file(&loose).unwrap();
    ok(run_client(&sender, &[]));
    assert!(
        git(&destination, &["cat-file", "-e", blob])
            .status
            .success()
    );
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        git(&client, &["rev-parse", "HEAD"]).stdout
    );
    let wrapped = fs::read(data.join("publication.wrapped")).unwrap();
    let authorization = fs::read(receiver_home.join(".ssh/authorized_keys")).unwrap();
    ok(command(&porter, &receiver_home)
        .args(["setup", "--yes"])
        .output()
        .unwrap());
    assert_eq!(wrapped, fs::read(data.join("publication.wrapped")).unwrap());
    assert_eq!(
        authorization,
        fs::read(receiver_home.join(".ssh/authorized_keys")).unwrap()
    );
    let quiet_wrapped = ok(run_client(&sender, &["--quiet"]));
    assert!(!String::from_utf8_lossy(&quiet_wrapped.stderr).contains("Forwarded to "));
    assert!(!String::from_utf8_lossy(&quiet_wrapped.stderr).contains("To fixture:"));
    // Explicit account-agent mode requires neither bundle files nor sender agent.
    let forge_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let forge_public = forge_key.public_key().clone();
    let receiver_agent = Agent::start(forge_key.clone()).unwrap();
    let forge_config = forge_home.join(".gitconfig");
    use std::io::Write as _;
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .open(&forge_config)
            .unwrap(),
        "[porter]\nauthorizedKey = {}",
        forge_public.to_openssh().unwrap()
    )
    .unwrap();
    fs::create_dir_all(forge_home.join(".ssh")).unwrap();
    fs::write(forge_home.join(".ssh/authorized_keys"), "").unwrap();
    ok(command(&porter, &forge_home)
        .args(["setup", "--yes"])
        .output()
        .unwrap());
    fs::write(
        forge_home.join(".ssh/authorized_keys"),
        fixture_authorization(&forge_home),
    )
    .unwrap();
    ok(git(
        &receiver_home,
        &[
            "config",
            "--file",
            config.to_str().unwrap(),
            "porter.skipWrappedKey",
            "true",
        ],
    ));
    for name in [
        "publication.wrapped",
        "publication.pub",
        "publication.source.pub",
    ] {
        fs::rename(data.join(name), data.join(format!("saved-{name}"))).unwrap();
    }
    let setup = ok(command(&porter, &receiver_home)
        .args(["setup", "--yes"])
        .output()
        .unwrap());
    let warning = String::from_utf8_lossy(&setup.stderr);
    assert!(
        warning.contains("any process on this receiver account can push"),
        "{warning}"
    );
    assert!(!warning.contains("run git porter key:create"));
    let entry = fixture_authorization(&receiver_home);
    let set_agent = |socket: Option<&Path>| {
        let prefix = socket
            .map(|p| format!("env SSH_AUTH_SOCK={} ", quote(p)))
            .unwrap_or_else(|| "env -u SSH_AUTH_SOCK ".into());
        fs::write(
            root.join("authorized_keys"),
            entry.replace("command=\"", &format!("command=\"{prefix}")),
        )
        .unwrap();
    };
    let send_without_sender_agent = |flags: &[&str]| without_agent(&sender, flags);
    // Even an otherwise valid account key file cannot substitute for an agent.
    fs::write(
        receiver_home.join(".ssh/id_ed25519"),
        forge_key
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    fs::set_permissions(
        receiver_home.join(".ssh/id_ed25519"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    set_agent(None);
    let missing = send_without_sender_agent(&[]);
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr)
            .contains("receiver/forwarder's inherited SSH_AUTH_SOCK is not set"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );
    set_agent(Some(Path::new("/nonexistent/porter-agent")));
    let unusable = send_without_sender_agent(&[]);
    assert!(!unusable.status.success());
    assert!(
        String::from_utf8_lossy(&unusable.stderr).contains("SSH_AUTH_SOCK is unusable"),
        "{}",
        String::from_utf8_lossy(&unusable.stderr)
    );
    set_agent(Some(&receiver_agent.socket()));
    ok(git(
        &client,
        &[
            "commit",
            "--allow-empty",
            "-qm",
            "account agent publication",
        ],
    ));
    ok(send_without_sender_agent(&[]));
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout,
        git(&client, &["rev-parse", "HEAD"]).stdout
    );
    let public = ok(command(&porter, &receiver_home)
        .env("SSH_AUTH_SOCK", receiver_agent.socket())
        .arg("key:public")
        .output()
        .unwrap());
    assert_eq!(
        ssh_key::PublicKey::from_openssh(String::from_utf8_lossy(&public.stdout).trim())
            .unwrap()
            .key_data(),
        forge_public.key_data()
    );
    ok(command(&porter, &receiver_home)
        .args([
            "key:create",
            "--key-import",
            "/nonexistent/unused-porter-import",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap());
    assert!(!data.join("publication.wrapped").exists());
    // Explicit false cannot fall back to the working account agent.
    ok(git(
        &receiver_home,
        &[
            "config",
            "--file",
            config.to_str().unwrap(),
            "porter.skipWrappedKey",
            "false",
        ],
    ));
    let wrapped_required = send_without_sender_agent(&[]);
    assert!(!wrapped_required.status.success());
    assert!(
        String::from_utf8_lossy(&wrapped_required.stderr)
            .contains("forwarder-key setup is incomplete")
    );
    ok(git(
        &receiver_home,
        &[
            "config",
            "--file",
            config.to_str().unwrap(),
            "porter.skipWrappedKey",
            "true",
        ],
    ));
    assert!(
        git_porter::credentials::agent::Client::connect(&receiver_agent.socket())
            .unwrap()
            .list_all_identities()
            .is_ok()
    );
    // The credential-mode switch must still reach the common publication guard.
    ok(git(
        &origin,
        &["symbolic-ref", "HEAD", "refs/heads/contributors/test"],
    ));
    let protected = send_without_sender_agent(&["--force"]);
    assert!(!protected.status.success());
    assert!(String::from_utf8_lossy(&protected.stderr).contains("default branch is protected"));
    ok(git(&origin, &["symbolic-ref", "HEAD", "refs/heads/main"]));
    // With no origin, publication negotiation neither signs nor creates a block.
    ok(git(&destination, &["remote", "rename", "origin", "backup"]));
    let no_origin = ok(send_without_sender_agent(&[]));
    assert!(!String::from_utf8_lossy(&no_origin.stderr).contains("Forwarded to "));
    let quiet = ok(send_without_sender_agent(&["--quiet"]));
    assert!(!String::from_utf8_lossy(&quiet.stderr).contains("To fixture:"));
    ok(git(&destination, &["remote", "rename", "backup", "origin"]));
    let bad = authorized::render(&porter, &source_public).unwrap();
    assert!(bad.starts_with("restrict,command="));
    assert!(!bad.contains("agent-forwarding"));
}

fn fixture_authorization(home: &Path) -> String {
    if home.file_name().is_some_and(|name| name == "forge") {
        // Model an independent forge: it permits forced pushes, while retaining
        // the fixture hook for policy-failure/outcome-reporting scenarios.
        let data = home.join(".local/share/git-porter");
        let config = git_porter::server::config::ServerConfig::read_environment(
            &home.join(".gitconfig"),
            home,
            &data,
            &home.join(".cache/git-porter"),
        )
        .unwrap();
        let mut context = config.hook_context();
        context.mode = "force".into();
        let snapshot = home.join("forge-context");
        fs::write(&snapshot, context.encode().unwrap()).unwrap();
        let script = home.join("forge-shell");
        let git_shell = git_porter::server::config::executable("git-shell").unwrap();
        fs::write(&script, format!("#!/bin/sh\nexport HOME={} XDG_DATA_HOME={}\nexport GIT_PORTER_HOOK_CONTEXT=\"$(cat {})\"\nexport GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0={}\nexec {} -c \"$SSH_ORIGINAL_COMMAND\"\n", quote(home), quote(&home.join(".local/share")), quote(&snapshot), quote(&home.join(".local/share/git-porter/hooks")), quote(&git_shell))).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let entry = fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap();
        return entry
            .lines()
            .filter(|line| line.starts_with("restrict,command="))
            .map(|line| {
                let (_, key) = line.rsplit_once("\" ").unwrap();
                format!("restrict,command=\"{}\" {}\n", quote(&script), key)
            })
            .collect();
    }
    fs::read_to_string(home.join(".ssh/authorized_keys"))
        .unwrap()
        .replace(
            "command=\"",
            &format!(
                "command=\"env HOME={} XDG_DATA_HOME={} XDG_CACHE_HOME={} XDG_CONFIG_HOME={} ",
                quote(home),
                quote(&home.join(".local/share")),
                quote(&home.join(".cache")),
                quote(&if home.join("custom-config/git/config").exists() {
                    home.join("custom-config")
                } else {
                    home.join(".config")
                })
            ),
        )
}

// Real receiver + forge path, with a short sender READY deadline and slow forge hook.
#[derive(Clone, Copy)]
enum InlineScenario {
    SlowForge,
    CheckoutDuringApproval,
}
fn inline_publication_after_approval(
    porter: &Path,
    receiver: &Path,
    forge: &Path,
    repository: &Path,
    source: &ssh_key::PrivateKey,
    scenario: InlineScenario,
) {
    use git_porter::{
        credentials::derivation::PublishRequest,
        runtime::{
            protocol::{Budget, DeadlineIo, Kind},
            push_result::{self, Frame, Outcome},
        },
    };
    use signature::Signer;
    use std::io::Write;
    let origin = forge.join("projects/repo");
    // Receiver already has the intended commit, but the forge needs an actual update.
    git(
        &origin,
        &["update-ref", "-d", "refs/heads/contributors/test"],
    );
    let script = forge.join("forge-shell");
    let original = fs::read_to_string(&script).unwrap();
    let marker = forge.join("slow-receive-started");
    let delay = format!(
        "case \"$SSH_ORIGINAL_COMMAND\" in git-receive-pack*) touch {}; sleep 2 ;; esac\n",
        quote(&marker)
    );
    let _ = fs::remove_file(&marker);
    if matches!(scenario, InlineScenario::SlowForge) {
        fs::write(
            &script,
            original.replacen("exec ", &format!("{delay}exec "), 1),
        )
        .unwrap();
    }
    let before = git(
        &origin,
        &["for-each-ref", "--format=%(objectname) %(refname)"],
    )
    .stdout;
    let checkout = receiver.join("approval-checkout");
    let sha =
        String::from_utf8(git(repository, &["rev-parse", "refs/heads/contributors/test"]).stdout)
            .unwrap()
            .trim()
            .to_owned();
    let mut child = command(porter, receiver)
        .arg("internal:serve")
        .env("SSH_ORIGINAL_COMMAND", "git-porter-session-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = DeadlineIo::new(child.stdout.take().unwrap(), Duration::from_secs(10));
    let mut outgoing = Budget::default();
    let mut incoming = Budget::default();
    outgoing
        .write(&mut input, Kind::Hello, b"publish-v5")
        .unwrap();
    incoming.expect(&mut output, Kind::Hello).unwrap();
    let intent = format!(
        "intent-v2\0receive\0{}\0\0ff\0refs/heads/contributors/test\0{sha}\0",
        repository.display()
    );
    outgoing
        .write(&mut input, Kind::Intent, intent.as_bytes())
        .unwrap();
    incoming.expect(&mut output, Kind::Resolved).unwrap();
    let request = PublishRequest::parse(
        &incoming
            .expect(&mut output, Kind::ApprovePublishV1)
            .unwrap(),
    )
    .unwrap();
    outgoing.write(&mut input, Kind::Signing, b"").unwrap();
    if matches!(scenario, InlineScenario::CheckoutDuringApproval) {
        git(
            repository,
            &[
                "worktree",
                "add",
                "-q",
                checkout.to_str().unwrap(),
                "contributors/test",
            ],
        );
    }
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
    outgoing.write(&mut input, Kind::SigningDone, b"").unwrap();
    outgoing
        .write(&mut input, Kind::Signature, &response)
        .unwrap();
    // The forge push deliberately takes 2s; READY must arrive first, within 1s.
    let mut output = DeadlineIo::new(output.into_inner(), Duration::from_secs(1));
    incoming.expect_empty(&mut output, Kind::Ready).unwrap();
    let mut output = DeadlineIo::new(output.into_inner(), Duration::from_secs(10));
    input.write_all(b"0000").unwrap();
    drop(input);
    let started = Instant::now();
    let report = loop {
        match push_result::read_frame(&mut output).unwrap() {
            Frame::Data(_) => (),
            Frame::Final(report) => break report,
        }
    };
    match scenario {
        InlineScenario::SlowForge => {
            assert!(report.receiver_ok, "{report:?}");
            assert!(matches!(
                report.forwarded.unwrap().outcome,
                Outcome::Complete
            ));
            assert!(child.wait().unwrap().success());
            assert!(marker.exists(), "forge receive command was not exercised");
            assert!(
                started.elapsed() >= Duration::from_secs(1),
                "slow origin delay was not exercised"
            );
            assert_eq!(
                String::from_utf8(
                    git(&origin, &["rev-parse", "refs/heads/contributors/test"]).stdout
                )
                .unwrap()
                .trim(),
                sha
            );
        }
        InlineScenario::CheckoutDuringApproval => {
            assert!(!report.receiver_ok, "checked-out branch was published");
            assert!(matches!(
                report.forwarded.unwrap().outcome,
                Outcome::NotAttempted { .. }
            ));
            assert!(!child.wait().unwrap().success());
            assert_eq!(
                git(
                    &origin,
                    &["for-each-ref", "--format=%(objectname) %(refname)"]
                )
                .stdout,
                before,
                "forge changed while branch was checked out during approval"
            );
            git(
                repository,
                &["worktree", "remove", "--force", checkout.to_str().unwrap()],
            );
            git(
                &origin,
                &["update-ref", "refs/heads/contributors/test", &sha],
            );
        }
    }
    fs::write(&script, original).unwrap();
}
