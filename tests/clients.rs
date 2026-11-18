use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn git(path: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .args(args)
        .output()
        .unwrap()
}
fn assert_ok(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}
#[test]
fn installed_clients_discover_send_receive_and_preserve_worktree_and_ref_policy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let source = root.join("client-home/source");
    fs::create_dir_all(&source).unwrap();
    let receiver_home = root.join("receiver");
    fs::create_dir(&receiver_home).unwrap();
    let destination = receiver_home.join("different/layout/copy.git");
    fs::create_dir_all(&destination).unwrap();
    assert_ok(git(&source, &["init", "-q"]));
    assert_ok(git(
        &source,
        &["symbolic-ref", "HEAD", "refs/heads/contributors/test"],
    ));
    use rand::RngCore;
    let mut payload = vec![0; 1200000];
    rand::rngs::OsRng.fill_bytes(&mut payload);
    fs::write(source.join("payload"), &payload).unwrap();
    assert_ok(git(&source, &["add", "payload"]));
    assert_ok(git(&source, &["commit", "--allow-empty", "-qm", "first"]));
    assert_ok(git(
        &source,
        &[
            "remote",
            "add",
            "origin",
            "git@example.invalid:org/repo.git",
        ],
    ));
    assert_ok(git(
        root,
        &["init", "--bare", "-q", destination.to_str().unwrap()],
    ));
    assert_ok(git(
        &destination,
        &[
            "remote",
            "add",
            "origin",
            "https://example.invalid/org/repo",
        ],
    ));
    let data = receiver_home.join(".local/share/git-porter");
    fs::create_dir_all(&data).unwrap();
    let hooks = data.join("hooks");
    fs::create_dir(&hooks).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), hooks.join("pre-receive"))
        .unwrap();
    let xdg = receiver_home.join("custom-config");
    fs::create_dir_all(xdg.join("git")).unwrap();
    let config = xdg.join("git/config");
    fs::write(
        receiver_home.join(".gitconfig"),
        "[porter]\nallowedPushPrefix = unrelated/\n",
    )
    .unwrap();
    let access_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    fs::write(
        &config,
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\nallowedPushPrefix = contributors/\n",
            receiver_home.display(), access_key.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let immutable = root.join("immutable");
    fs::create_dir(&immutable).unwrap();
    let stored = immutable.join("gitconfig");
    fs::rename(&config, &stored).unwrap();
    std::os::unix::fs::symlink(&stored, &config).unwrap();
    let log = root.join("ssh-argv");
    // This fixture models SSH byte transport; real sshd acceptance is a separate gate.
    let ssh = bin.join("ssh");
    fs::write(&ssh, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nfor arg do SSH_ORIGINAL_COMMAND=$arg; done\nexport SSH_ORIGINAL_COMMAND\nexport HOME={}\nexport XDG_DATA_HOME={}\nexport XDG_CONFIG_HOME={}\nunset SSH_AUTH_SOCK\nexec {} internal:serve\n", quote(&log), quote(&receiver_home), quote(&receiver_home.join(".local/share")), quote(&xdg), quote(Path::new(env!("CARGO_BIN_EXE_git-porter"))))).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let probes = root.join("repository-probes");
    let git_binary = git_porter::server::config::executable("git").unwrap();
    let git_spy = bin.join("git");
    fs::write(
        &git_spy,
        format!(
            "#!/bin/sh\nif test \"$1\" = rev-parse; then echo probe >> {}; fi\nexec {} \"$@\"\n",
            quote(&probes),
            quote(&git_binary)
        ),
    )
    .unwrap();
    fs::set_permissions(&git_spy, fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());

    // Git parses GIT_SSH_COMMAND through a shell, unlike literal GIT_SSH.
    use std::os::unix::ffi::OsStringExt;
    let mut temporary_name = b"tmp 'quoted' $literal".to_vec();
    if cfg!(target_os = "linux") {
        temporary_name.push(0xff);
    }
    let temporary = root.join(std::ffi::OsString::from_vec(temporary_name));
    fs::create_dir(&temporary).unwrap();
    let run = |binary: &str, extra: &[&str]| {
        let mut command = Command::new(binary);
        if binary.ends_with("git-send") {
            command.arg("--local-only");
        }
        command
            .current_dir(&source)
            .env("TMPDIR", &temporary)
            .env("PATH", &path)
            .env("HOME", root.join("client-home"))
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_PORTER_CLIENT_MODE", "force")
            .env("GIT_PORTER_CLIENT_LEASE", "untrusted-inherited-value")
            .args(extra);
        if !extra.iter().any(|arg| arg.starts_with("operator@fixture:")) {
            command.arg("operator@fixture");
        }
        command.output().unwrap()
    };
    let selected = git(&source, &["rev-parse", "HEAD"]).stdout;
    assert_ok(git(&source, &["checkout", "--detach", "-q"]));
    let detached = run(env!("CARGO_BIN_EXE_git-send"), &[]);
    assert!(!detached.status.success());
    assert!(String::from_utf8_lossy(&detached.stderr).contains("--branch <name>"));
    fs::write(&probes, "").unwrap();
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &["--branch", "contributors/test"],
    ));
    let count = fs::read_to_string(&probes).unwrap().lines().count();
    assert!(
        count <= 3,
        "repository was resolved repeatedly: {count} probes"
    );
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-receive"),
        &["--branch", "contributors/test"],
    ));
    // An arbitrarily named secondary remote matches the receiver's origin when
    // the sender's origin is its own agent fork. Exercise both Git subcommands.
    assert_ok(git(
        &source,
        &[
            "remote",
            "add",
            "parent/project",
            "https://example.invalid/org/repo",
        ],
    ));
    assert_ok(git(
        &source,
        &[
            "remote",
            "set-url",
            "origin",
            "git@example.invalid:agent/repo.git",
        ],
    ));
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &["--branch", "contributors/test"],
    ));
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-receive"),
        &["--branch", "contributors/test"],
    ));
    assert_ok(git(
        &source,
        &[
            "remote",
            "set-url",
            "origin",
            "git@example.invalid:org/repo.git",
        ],
    ));
    assert_ok(git(&source, &["remote", "remove", "parent/project"]));
    assert_eq!(git(&source, &["rev-parse", "HEAD"]).stdout, selected);
    assert_ok(git(&source, &["checkout", "-q", "contributors/test"]));
    assert_ok(git(&source, &["branch", "forbidden/test"]));
    // Native local-only receipt and negotiated lease preflight must both give
    // the original receiver's actionable rename instruction, not a protocol error.
    for extra in [
        vec!["--branch", "forbidden/test"],
        vec!["--force-with-lease", "--branch", "forbidden/test"],
    ] {
        let refused = run(env!("CARGO_BIN_EXE_git-send"), &extra);
        let diagnostics = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success());
        assert!(
            diagnostics.contains(
                "ref refs/heads/forbidden/test is not permitted; allowed branch prefixes:"
            ),
            "{diagnostics}"
        );
        assert!(diagnostics.contains("contributors/"), "{diagnostics}");
        assert!(
            diagnostics.contains("Rename your branch before sending it."),
            "{diagnostics}"
        );
        assert!(
            !git(
                &destination,
                &["show-ref", "--verify", "refs/heads/forbidden/test"]
            )
            .status
            .success()
        );
    }
    assert_ok(git(&source, &["branch", "-D", "forbidden/test"]));
    for bad in ["bad name", "../escape", "a..b"] {
        assert!(
            !run(env!("CARGO_BIN_EXE_git-send"), &["--branch", bad])
                .status
                .success()
        );
    }
    assert_ok(git(
        &source,
        &[
            "symbolic-ref",
            "refs/heads/contributors/symbolic",
            "refs/heads/contributors/test",
        ],
    ));
    assert!(
        !run(
            env!("CARGO_BIN_EXE_git-send"),
            &["--branch", "contributors/symbolic"]
        )
        .status
        .success()
    );
    assert!(
        !run(
            env!("CARGO_BIN_EXE_git-receive"),
            &["--branch", "contributors/symbolic"]
        )
        .status
        .success()
    );
    // Ordinary inherited push configuration must not change the transfer.
    for (key, value) in [
        ("push.gpgSign", "true"),
        ("push.pushOption", "adversarial-option"),
        ("push.followTags", "true"),
        ("push.recurseSubmodules", "on-demand"),
        ("push.negotiate", "true"),
    ] {
        assert_ok(git(&source, &["config", key, value]));
    }
    assert_ok(git(
        &destination,
        &["config", "receive.fsckObjects", "false"],
    ));
    assert_ok(git(
        &source,
        &["config", "porter.destination", "wrong@invalid"],
    ));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &[])); // explicit target wins
    assert_ok(git(&source, &["config", "--unset", "porter.destination"]));
    let nested = source.join("nested");
    fs::create_dir(&nested).unwrap();
    let nested_send = Command::new(env!("CARGO_BIN_EXE_git-send"))
        .arg("--local-only")
        .current_dir(&nested)
        .env("HOME", root.join("client-home"))
        .env("PATH", &path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("operator@fixture")
        .output()
        .unwrap();
    assert_ok(nested_send);
    fs::remove_dir(nested).unwrap();
    // Repo receive.fsckObjects=false must not override the forced receive check.
    {
        use std::{io::Write, process::Stdio};
        let tree = String::from_utf8(git(&source, &["rev-parse", "HEAD^{tree}"]).stdout).unwrap();
        let bad = format!(
            "tree {}\nauthor invalid 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\nbad\n",
            tree.trim()
        );
        let mut child = Command::new("git")
            .current_dir(&source)
            .args([
                "hash-object",
                "--literally",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(bad.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let oid = String::from_utf8(out.stdout).unwrap();
        assert_ok(git(
            &source,
            &["update-ref", "refs/heads/contributors/fsck", oid.trim()],
        ));
        let rejected = run(
            env!("CARGO_BIN_EXE_git-send"),
            &["--branch", "contributors/fsck"],
        );
        assert!(!rejected.status.success());
        let error = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            error.contains("fsck") || error.contains("missingEmail"),
            "{error}"
        );
        assert!(
            !git(
                &destination,
                &["rev-parse", "--verify", "refs/heads/contributors/fsck"]
            )
            .status
            .success()
        );
    }
    let empty_objects = root.join("empty-objects");
    fs::create_dir(&empty_objects).unwrap();
    let sanitized = Command::new(env!("CARGO_BIN_EXE_git-send"))
        .arg("--local-only")
        .current_dir(&source)
        .env("HOME", root.join("client-home"))
        .env("PATH", &path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OBJECT_DIRECTORY", &empty_objects)
        .env(
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "/nonexistent-alternates",
        )
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "push.pushOption")
        .env("GIT_CONFIG_VALUE_0", "injected-option")
        .arg("operator@fixture")
        .output()
        .unwrap();
    assert_ok(sanitized);
    // SSH rewrites must still use the pinned receiver through our helper.
    assert_ok(git(
        &source,
        &[
            "config",
            "url.ssh://wrong.invalid/.insteadOf",
            "operator@fixture:",
        ],
    ));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &[]));
    assert_eq!(
        git(
            &destination,
            &["show", "refs/heads/contributors/test:payload"]
        )
        .stdout,
        payload
    );

    // A real installation directory named deps is not a Cargo harness.
    let installed = root.join("deps");
    fs::create_dir(&installed).unwrap();
    for (name, binary) in [
        ("git-porter", env!("CARGO_BIN_EXE_git-porter")),
        ("git-send", env!("CARGO_BIN_EXE_git-send")),
        ("git-receive", env!("CARGO_BIN_EXE_git-receive")),
    ] {
        fs::copy(binary, installed.join(name)).unwrap();
    }
    assert_ok(run(installed.join("git-send").to_str().unwrap(), &[]));
    assert_ok(git(&source, &["branch", "forbidden/test"]));
    assert!(
        !run(
            env!("CARGO_BIN_EXE_git-send"),
            &["--branch", "forbidden/test"]
        )
        .status
        .success()
    );
    assert!(
        !git(
            &destination,
            &["rev-parse", "--verify", "refs/heads/forbidden/test"]
        )
        .status
        .success()
    );
    let source_tip = git(&source, &["rev-parse", "HEAD"]).stdout;
    assert_eq!(
        source_tip,
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout
    );
    assert_ok(git(&source, &["commit", "--allow-empty", "-qm", "second"]));
    // Local-only leases intentionally check only the receiver, never its origin.
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &["--force-with-lease"]));
    let second = git(&source, &["rev-parse", "HEAD"]).stdout;
    assert_ok(git(&source, &["reset", "--hard", "HEAD~1"]));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &["--force-with-lease"]));
    assert_ok(git(
        &source,
        &[
            "reset",
            "--hard",
            std::str::from_utf8(&second).unwrap().trim(),
        ],
    ));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &[]));
    assert_ok(git(&source, &["reset", "--hard", "HEAD~1"]));
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &[
            "--force-with-lease",
            &format!("operator@fixture:{}", destination.display()),
        ],
    ));
    // Explicit-path local-only force must negotiate too.
    assert_ok(git(
        &source,
        &[
            "reset",
            "--hard",
            std::str::from_utf8(&second).unwrap().trim(),
        ],
    ));
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &[
            "--force",
            &format!("operator@fixture:{}", destination.display()),
        ],
    ));

    assert_ok(git(&source, &["reset", "--hard", "HEAD~1"]));
    assert_ok(run(env!("CARGO_BIN_EXE_git-receive"), &[]));
    assert_eq!(
        git(&source, &["rev-parse", "HEAD"]).stdout,
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout
    );
    // Divergent current/non-current receives retain fetched history and actionable guidance.
    assert_ok(git(&source, &["reset", "--hard", "HEAD~1"]));
    assert_ok(git(
        &source,
        &["commit", "--allow-empty", "-qm", "divergent"],
    ));
    let divergent = run(env!("CARGO_BIN_EXE_git-receive"), &[]);
    assert!(!divergent.status.success());
    let guidance = String::from_utf8_lossy(&divergent.stderr);
    assert!(
        guidance.contains("history remains in FETCH_HEAD"),
        "{guidance}"
    );
    assert!(
        guidance.contains("git log --left-right --graph refs/heads/contributors/test...FETCH_HEAD"),
        "{guidance}"
    );
    assert_ok(git(&source, &["checkout", "-qb", "contributors/other"]));
    let divergent = run(
        env!("CARGO_BIN_EXE_git-receive"),
        &["--branch", "contributors/test"],
    );
    assert!(!divergent.status.success());
    assert!(
        String::from_utf8_lossy(&divergent.stderr)
            .contains("inspect FETCH_HEAD before merging or rebasing")
    );
    assert_ok(git(&source, &["checkout", "-q", "contributors/test"]));
    assert_ok(git(&source, &["reset", "--hard", "FETCH_HEAD"]));
    let transport_script = fs::read_to_string(&ssh).unwrap();
    let switching = transport_script.replace("exec ", "")
        + &format!(
            "\ngit -C {} symbolic-ref HEAD refs/heads/contributors/other\n",
            quote(&source)
        );
    fs::write(&ssh, switching).unwrap();
    let changed = run(env!("CARGO_BIN_EXE_git-receive"), &[]);
    assert!(!changed.status.success());
    assert!(
        String::from_utf8_lossy(&changed.stderr)
            .contains("Current branch changed during fetch; fetched history remains in FETCH_HEAD")
    );
    fs::write(&ssh, transport_script).unwrap();
    assert_ok(git(&source, &["checkout", "-q", "contributors/test"]));
    fs::write(source.join("untracked"), "dirty").unwrap();
    assert!(!run(env!("CARGO_BIN_EXE_git-receive"), &[]).status.success());
    fs::remove_file(source.join("untracked")).unwrap();
    assert_ok(git(
        &source,
        &[
            "remote",
            "set-url",
            "origin",
            "git@example.invalid:org/repo.git",
        ],
    ));
    assert_ok(git(&source, &["remote", "rename", "origin", "mirror"]));
    assert_ok(git(&destination, &["remote", "rename", "origin", "mirror"]));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &[]));
    assert_ok(run(env!("CARGO_BIN_EXE_git-receive"), &[]));
    assert_ok(git(
        &source,
        &[
            "remote",
            "add",
            "upstream",
            "git@example.com:another/repository.git",
        ],
    ));
    // Multiple sender remotes are not inherently ambiguous: only mirror has a
    // receiver match, so the unrelated secondary remote must not prevent lookup.
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &[]));
    assert_ok(run(env!("CARGO_BIN_EXE_git-receive"), &[]));
    assert_ok(git(&source, &["remote", "remove", "upstream"]));
    assert!(
        !run(env!("CARGO_BIN_EXE_git-send"), &["--unsupported"])
            .status
            .success()
    );
    let before = git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout;
    fs::remove_file(hooks.join("pre-receive")).unwrap();
    assert_ok(git(
        &source,
        &[
            "commit",
            "--allow-empty",
            "-qm",
            "must not receive without policy hook",
        ],
    ));
    let missing_hook = run(env!("CARGO_BIN_EXE_git-send"), &[]);
    assert!(!missing_hook.status.success());
    assert!(String::from_utf8_lossy(&missing_hook.stderr).contains("pre-receive hook is missing"));
    assert_eq!(
        before,
        git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout
    );
    let argv = fs::read_to_string(log).unwrap();
    assert!(argv.contains("-a\n-o\nForwardAgent=no\n-S\nnone\n"));
    assert!(!argv.contains("-A\n"));
    assert!(!argv.contains("wrong.invalid"));
    assert!(!root.join("client-home/.local/share/git-porter").exists());
}

#[test]
fn malformed_publication_handshake_consumes_budget_across_helper_processes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let helper = root.join("client-ssh");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &helper).unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let log = root.join("attempts");
    let ssh = bin.join("ssh");
    fs::write(
        &ssh,
        format!("#!/bin/sh\nprintf x >> {}\nprintf chatter\n", quote(&log)),
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let run = || {
        Command::new(&helper)
            .arg("fixture")
            .arg("git-receive-pack 'porter'")
            .env("PATH", &path)
            .env("HOME", root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_SSH_COMMAND")
            .env_remove("GIT_SSH")
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_PORTER_CLIENT_DESTINATION", "fixture")
            .env("GIT_PORTER_CLIENT_PUBLISH", "true")
            .env("GIT_PORTER_SIGN_BUDGET", root.join("used"))
            .output()
            .unwrap()
    };
    assert!(!run().status.success());
    let second = run();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("already attempted"));
    assert_eq!(fs::read(log).unwrap(), b"x");
}

#[test]
fn url_rewrites_cannot_replace_controlled_transfers_with_other_transports() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let source = root.join("source");
    let bypass = root.join("bypass");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&bypass).unwrap();
    assert_ok(git(&source, &["init", "-q"]));
    assert_ok(git(
        &source,
        &["symbolic-ref", "HEAD", "refs/heads/contributors/test"],
    ));
    assert_ok(git(&source, &["commit", "--allow-empty", "-qm", "fixture"]));
    assert_ok(git(
        &source,
        &[
            "remote",
            "add",
            "origin",
            "git@example.invalid:org/repo.git",
        ],
    ));
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let ssh_log = root.join("ssh-log");
    let ssh = bin.join("ssh");
    fs::write(
        &ssh,
        format!("#!/bin/sh\nprintf x >> {}\nexit 1\n", quote(&ssh_log)),
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let destination = bypass.join("porter");
    assert_ok(git(
        root.as_path(),
        &["init", "--bare", "-q", destination.to_str().unwrap()],
    ));
    // Both Git's file policy and inherited protocol settings try to permit the
    // bypass. The client must impose its own whitelist on every helper command.
    assert_ok(git(&source, &["config", "protocol.file.allow", "always"]));
    for replacement in [
        format!("{}/", bypass.display()),
        format!("file://{}/", bypass.display()),
        "https://example.invalid/".into(),
        "ext::false ".into(),
        "ssh::".into(),
    ] {
        for rewrite in ["insteadOf", "pushInsteadOf"] {
            let setting = format!("url.{replacement}.{rewrite}");
            assert_ok(git(&source, &["config", &setting, "fixture:"]));
            for flags in [vec!["--local-only"], vec!["--local-only"], vec![]] {
                let receive = flags.is_empty();
                let before_ssh = fs::read(&ssh_log).unwrap_or_default().len();
                let output = Command::new(if receive {
                    env!("CARGO_BIN_EXE_git-receive")
                } else {
                    env!("CARGO_BIN_EXE_git-send")
                })
                .current_dir(&source)
                .args(&flags)
                .arg("fixture")
                .env("HOME", &root)
                .env_remove("XDG_DATA_HOME")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("XDG_CACHE_HOME")
                .env_remove("XDG_STATE_HOME")
                .env_remove("XDG_RUNTIME_DIR")
                .env_remove("XDG_DATA_DIRS")
                .env_remove("XDG_CONFIG_DIRS")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_ALLOW_PROTOCOL", "file:ssh:https:ext")
                .env("PATH", &path)
                .env_remove("SSH_AUTH_SOCK")
                .output()
                .unwrap();
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success(), "{setting} {flags:?}: {error}");
                if rewrite == "insteadOf" {
                    assert!(
                        error.contains("not allowed"),
                        "{setting} {flags:?}: {error}"
                    );
                    assert_eq!(fs::read(&ssh_log).unwrap_or_default().len(), before_ssh);
                } else {
                    // The fixed pushurl excludes pushInsteadOf. Failure must
                    // come from our SSH stub, never an unintended destination.
                    assert_eq!(fs::read(&ssh_log).unwrap().len(), before_ssh + 1);
                }
                assert!(git(&destination, &["show-ref"]).stdout.is_empty());
            }
            assert_ok(git(&source, &["config", "--unset-all", &setting]));
        }
    }
}

#[test]
fn user_ssh_precedence_and_forwarding_guards_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    assert_ok(git(&root, &["init", "-q"]));
    let helper = root.join("client-ssh");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &helper).unwrap();
    let native = git_porter::server::config::executable("ssh").unwrap();
    let log = root.join("selected");
    let mut wrappers = Vec::new();
    for name in [
        "environment-command",
        "configured-command",
        "git-ssh-command",
        "ssh",
    ] {
        let path = root.join(name);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' {name} >> {}\nexec {} -G \"$@\"\n",
                quote(&log),
                quote(&native)
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        wrappers.push(path);
    }
    assert_ok(git(
        &root,
        &[
            "config",
            "core.sshCommand",
            &format!(
                "{} -o ForwardAgent=yes -o ControlMaster=auto -o ControlPersist=5m -A -M -S ignored",
                wrappers[1].display()
            ),
        ],
    ));
    for stage in 0..4 {
        if stage == 2 {
            assert_ok(git(&root, &["config", "--unset", "core.sshCommand"]));
        }
        let mut command = Command::new(&helper);
        for (key, _) in std::env::vars_os().filter(|(k, _)| k.to_string_lossy().starts_with("XDG_"))
        {
            command.env_remove(key);
        }
        command
            .current_dir(&root)
            .env("HOME", &root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("GIT_SSH_COMMAND")
            .env_remove("GIT_SSH")
            .env(
                "PATH",
                format!("{}:{}", root.display(), std::env::var("PATH").unwrap()),
            )
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_PORTER_CLIENT_DESTINATION", "fixture")
            .env("GIT_PORTER_CLIENT_PATH", "repo")
            .env("GIT_PORTER_CLIENT_PUBLISH", "false")
            .arg("fixture")
            .arg("git-upload-pack 'repo'");
        if stage == 0 {
            command.env(
                "GIT_SSH_COMMAND",
                format!(
                    "{} -o ForwardAgent=yes -fA -nM -qSignored",
                    wrappers[0].display()
                ),
            );
        }
        if stage < 3 {
            command.env("GIT_SSH", &wrappers[2]);
        }
        for variant in ["plink", "tortoiseplink", "putty", "simple"] {
            command.env("GIT_SSH_VARIANT", variant);
            let rejected = command.output().unwrap();
            assert!(!rejected.status.success());
            assert!(String::from_utf8_lossy(&rejected.stderr).contains("requires OpenSSH"));
        }
        command.env("GIT_SSH_VARIANT", "ssh");
        let output = command.output().unwrap();
        assert_ok(output.clone());
        let settings = String::from_utf8(output.stdout).unwrap();
        for guarded in [
            "forwardagent no",
            "controlmaster false",
            "controlpersist no",
        ] {
            assert!(
                settings.lines().any(|line| line == guarded
                    || (guarded == "controlmaster false" && line == "controlmaster no")),
                "{settings}"
            );
        }
        assert_eq!(
            fs::read_to_string(&log).unwrap().lines().last().unwrap(),
            [
                "environment-command",
                "configured-command",
                "git-ssh-command",
                "ssh"
            ][stage]
        );
    }
}

#[test]
fn ordinary_ssh_uses_matching_home_paths_without_porter_policy_or_an_agent() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let sender = root.join("sender");
    let receiver = root.join("receiver");
    let source = sender.join("git/org/repo");
    let target = receiver.join("git/org/repo");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&target).unwrap();
    assert_ok(git(&source, &["init", "-q"]));
    assert_ok(git(
        &source,
        &["symbolic-ref", "HEAD", "refs/heads/@agent/a-fix"],
    ));
    assert_ok(git(&source, &["commit", "--allow-empty", "-qm", "first"]));
    assert_ok(git(&target, &["init", "--bare", "-q"]));
    // Neither side has Porter setup. An origin on the receiver must not cause
    // forwarding when SSH grants an ordinary login instead of the forced command.
    assert_ok(git(
        &target,
        &[
            "remote",
            "add",
            "origin",
            "git@unreachable.invalid:org/repo",
        ],
    ));
    let ssh = root.join("ssh");
    let flipped = root.join("flip-route");
    fs::write(&ssh, format!("#!/bin/sh\nfor arg do remote=$arg; done\nif test -e {}; then\ncase \"$remote\" in *git-receive-pack*) printf 'git-porter-route-v1:porter\\n'; exit 0 ;; esac\nfi\nexport HOME={}\ncd / || exit\nexec /bin/sh -c \"$remote\"\n", quote(&flipped), quote(&receiver))).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |binary: &str, checkout: &Path, flags: &[&str]| {
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &sender)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_SSH_COMMAND", &ssh)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_PORTER_CLIENT_MODE", "force")
            .env("GIT_PORTER_CLIENT_LEASE", "untrusted-inherited-value")
            .env("SSH_AUTH_SOCK", root.join("unusable-agent"))
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("XDG_CONFIG_HOME", sender.join(".config"))
            .env("XDG_DATA_HOME", sender.join(".local/share"))
            .env("XDG_CACHE_HOME", sender.join(".cache"))
            .env("XDG_STATE_HOME", sender.join(".local/state"))
            .env("XDG_RUNTIME_DIR", sender.join("run"))
            .current_dir(checkout)
            .args(flags);
        if !flags.iter().any(|flag| flag.starts_with("fixture:")) {
            command.arg("fixture");
        }
        command.output().unwrap()
    };
    let sent = run(env!("CARGO_BIN_EXE_git-send"), &source, &[]);
    assert!(!String::from_utf8_lossy(&sent.stderr).contains("Forwarded to"));
    assert_ok(sent);
    let first = git(&source, &["rev-parse", "HEAD"]).stdout;
    assert_eq!(
        git(&target, &["rev-parse", "refs/heads/@agent/a-fix"]).stdout,
        first
    );
    assert_ok(git(&source, &["commit", "--allow-empty", "-qm", "second"]));
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &source,
        &["--local-only"],
    ));
    let second = git(&source, &["rev-parse", "HEAD"]).stdout;
    assert_ok(git(
        &source,
        &[
            "reset",
            "--hard",
            std::str::from_utf8(&first).unwrap().trim(),
        ],
    ));
    assert!(
        !run(env!("CARGO_BIN_EXE_git-send"), &source, &[])
            .status
            .success()
    );
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &source,
        &["--force-with-lease"],
    ));
    assert_eq!(
        git(&target, &["rev-parse", "refs/heads/@agent/a-fix"]).stdout,
        first
    );
    assert_ok(git(
        &source,
        &[
            "reset",
            "--hard",
            std::str::from_utf8(&second).unwrap().trim(),
        ],
    ));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &source, &["--force"]));
    assert_ok(git(
        &source,
        &[
            "reset",
            "--hard",
            std::str::from_utf8(&first).unwrap().trim(),
        ],
    ));
    assert_ok(run(env!("CARGO_BIN_EXE_git-receive"), &source, &[]));
    assert_eq!(git(&source, &["rev-parse", "HEAD"]).stdout, second);
    let linked = sender.join("linked-checkout");
    assert_ok(git(
        &source,
        &[
            "worktree",
            "add",
            "-qb",
            "work/linked",
            linked.to_str().unwrap(),
        ],
    ));
    assert_ok(run(env!("CARGO_BIN_EXE_git-send"), &linked, &[]));
    assert_eq!(
        git(&target, &["rev-parse", "refs/heads/work/linked"]).stdout,
        second
    );
    // A different SSH identity/route on the push after lease observation cannot
    // silently change modes or start an onward/signing attempt.
    fs::write(&flipped, "").unwrap();
    let refused = run(
        env!("CARGO_BIN_EXE_git-send"),
        &source,
        &["--force-with-lease"],
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("SSH route changed"));
    let explicit = format!("fixture:{}", target.display());
    let explicit_refused = run(
        env!("CARGO_BIN_EXE_git-send"),
        &source,
        &["--force-with-lease", &explicit],
    );
    assert!(!explicit_refused.status.success());
    assert!(String::from_utf8_lossy(&explicit_refused.stderr).contains("SSH route changed"));

    assert_eq!(
        git(&target, &["rev-parse", "refs/heads/@agent/a-fix"]).stdout,
        second
    );
    assert!(!sender.join(".local/share/git-porter").exists());
    assert!(!receiver.join(".local/share/git-porter").exists());
}
