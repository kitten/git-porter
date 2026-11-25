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
    assert_ok(git(&source, &["config", "remote.origin.promisor", "true"]));
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
    let promisor = root.join("promisor.git");
    assert_ok(git(
        root,
        &[
            "clone",
            "--bare",
            source.to_str().unwrap(),
            promisor.to_str().unwrap(),
        ],
    ));
    assert_ok(git(
        &promisor,
        &["config", "uploadpack.allowFilter", "true"],
    ));
    assert_ok(git(
        &source,
        &[
            "remote",
            "add",
            "cache",
            &format!("file://{}", promisor.display()),
        ],
    ));
    assert_ok(git(&source, &["config", "remote.cache.promisor", "true"]));
    let blob = String::from_utf8(git(&source, &["rev-parse", "HEAD:payload"]).stdout).unwrap();
    let blob = blob.trim();
    fs::remove_file(
        source
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .unwrap();
    assert!(
        !isolated_command("git", &source, root)
            .args(["--no-lazy-fetch", "cat-file", "-e", blob])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::write(&probes, "").unwrap();
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-send"),
        &["--branch", "contributors/test"],
    ));
    assert_ok(git(&source, &["--no-lazy-fetch", "cat-file", "-e", blob]));
    assert_ok(git(&source, &["remote", "remove", "cache"]));
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
    fs::remove_dir(source.join(".git/objects/pack")).unwrap();
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
    let ssh_log = root.join("ssh-log");
    fs::write(&ssh, format!("#!/bin/sh\nfor arg do remote=$arg; done\nprintf '%s\\n' \"$remote\" >> {}\nif test -e {}; then\ncase \"$remote\" in *git-receive-pack*) printf 'git-porter-route-v1:porter\\n'; exit 0 ;; esac\nfi\nexport HOME={}\ncd / || exit\nexec /bin/sh -c \"$remote\"\n", quote(&ssh_log), quote(&flipped), quote(&receiver))).unwrap();
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
    assert_eq!(
        fs::read_to_string(&ssh_log).unwrap().lines().count(),
        1,
        "full senders must skip receiver observation"
    );
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

fn isolated_command(
    program: impl AsRef<std::ffi::OsStr>,
    directory: &Path,
    root: &Path,
) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .current_dir(directory)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid");
    for name in [
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_DIRS",
    ] {
        command.env(name, root.join(name));
    }
    command
}

#[test]
fn partial_clone_send_hydrates_from_promisor_without_receiver_maintenance() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let origin = root.join("origin");
    let source = root.join("source.git");
    let receiver = root.join("receiver.git");
    let log = root.join("ssh.log");
    let ssh = root.join("ssh");
    let git = |directory: &Path, args: &[&str]| {
        let output = isolated_command("git", directory, &root)
            .args(args)
            .output()
            .unwrap();
        assert_ok(output.clone());
        output
    };
    fs::create_dir(&origin).unwrap();
    git(&origin, &["init", "-q"]);
    git(&origin, &["symbolic-ref", "HEAD", "refs/heads/topic"]);
    fs::write(origin.join("file"), "promised blob\n").unwrap();
    fs::write(origin.join("second"), "another promised blob\n").unwrap();
    for i in 0..256 {
        fs::write(
            origin.join(format!("blob-{i:03}")),
            format!("payload {i}\n"),
        )
        .unwrap();
    }
    git(&origin, &["add", "."]);
    git(&origin, &["commit", "-qm", "fixture"]);
    git(&origin, &["config", "uploadpack.allowFilter", "true"]);
    let url = format!("file://{}", origin.display());
    git(
        &root,
        &[
            "clone",
            "--no-checkout",
            "--filter=tree:0",
            &url,
            source.to_str().unwrap(),
        ],
    );
    git(
        &root,
        &[
            "clone",
            "--bare",
            origin.to_str().unwrap(),
            receiver.to_str().unwrap(),
        ],
    );
    git(&receiver, &["update-ref", "-d", "refs/heads/topic"]);
    let bundle = root.join("external.bundle");
    git(
        &origin,
        &[
            "bundle",
            "create",
            bundle.to_str().unwrap(),
            "refs/heads/topic",
        ],
    );
    let bundles = root.join("bundles");
    fs::write(&bundles, format!("[bundle]\nversion = 1\nmode = all\nheuristic = creationToken\n[bundle \"one\"]\nuri = file://{}\ncreationToken = 1\n", bundle.display())).unwrap();
    git(
        &source,
        &[
            "config",
            "fetch.bundleURI",
            &format!("file://{}", bundles.display()),
        ],
    );
    // NOTE(@kitten): receiver objects must not mask a misrouted promisor fetch.
    git(
        &source,
        &["config", "remote.origin.url", "git@promisor.invalid:origin"],
    );
    let permit = root.join("permit-promisor");
    let guards = root.join("guards.log");
    fs::write(&ssh, format!(
        "#!/bin/sh\nfor arg do remote=$arg; done\nprintf '%s\\n' \"$remote\" >> {}\nif test \"$remote\" = \"git-upload-pack 'origin'\"; then {{ printf 'BEGIN\\n'; printf '%s\\n' \"$@\"; }} >> {}; fi\nif test -f {} && test \"$remote\" = \"git-upload-pack 'origin'\"; then exec git-upload-pack {}; fi\ncase \"$remote\" in git-receive-pack\\ *) unset GIT_NO_LAZY_FETCH;; esac\nexec /bin/sh -c \"$remote\"\n",
        quote(&log), quote(&guards), quote(&permit), quote(&origin)
    )).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let native_git = git_porter::server::config::executable("git").unwrap();
    fs::write(bin.join("git"), format!("#!/bin/sh\nif test \"$GIT_ALLOW_PROTOCOL\" = ssh; then test \"$GIT_NO_LAZY_FETCH\" = 1 || exit 97; fi\nexec {} \"$@\"\n", quote(&native_git))).unwrap();
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700)).unwrap();
    let send = || {
        isolated_command(env!("CARGO_BIN_EXE_git-send"), &source, &root)
            .env("GIT_SSH_COMMAND", &ssh)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_NO_LAZY_FETCH", "0")
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .args(["--local-only", &format!("fixture:{}", receiver.display())])
            .output()
            .unwrap()
    };
    let failed = send();
    assert!(
        !failed.status.success(),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    let diagnostics = String::from_utf8_lossy(&failed.stderr);
    assert!(
        diagnostics.contains("required sender objects are unavailable"),
        "{diagnostics}"
    );
    assert!(git(&receiver, &["for-each-ref"]).stdout.is_empty());
    fs::write(&permit, "").unwrap();
    git(&source, &["config", "remote.origin.promisor", "false"]);
    git(
        &source,
        &["config", "--unset", "remote.origin.partialclonefilter"],
    );
    let no_promisor = send();
    assert!(!no_promisor.status.success());
    assert!(
        String::from_utf8_lossy(&no_promisor.stderr)
            .contains("required sender objects have no configured promisor remote")
    );
    git(&source, &["config", "remote.origin.promisor", "true"]);
    git(
        &source,
        &["config", "remote.origin.partialclonefilter", "tree:0"],
    );
    let pruned_source = root.join("pruned.git");
    git(
        &root,
        &[
            "clone",
            "--bare",
            "--filter=tree:0",
            &url,
            pruned_source.to_str().unwrap(),
        ],
    );
    git(
        &pruned_source,
        &["config", "remote.origin.url", "git@promisor.invalid:origin"],
    );
    let entries = git(&origin, &["ls-tree", "-r", "HEAD"]);
    let entries = String::from_utf8(entries.stdout).unwrap();
    let missing_blob = entries
        .lines()
        .map(|line| line.split_whitespace().nth(2).unwrap())
        .max()
        .unwrap();
    let blob_path = origin
        .join(".git/objects")
        .join(&missing_blob[..2])
        .join(&missing_blob[2..]);
    let saved_blob = fs::read(&blob_path).unwrap();
    fs::remove_file(&blob_path).unwrap();
    let attempts_before = fs::read_to_string(&log)
        .unwrap()
        .matches("git-upload-pack 'origin'")
        .count();
    let pruned = isolated_command(env!("CARGO_BIN_EXE_git-send"), &pruned_source, &root)
        .env("GIT_SSH_COMMAND", &ssh)
        .env("GIT_SSH_VARIANT", "ssh")
        .args(["--local-only", &format!("fixture:{}", receiver.display())])
        .output()
        .unwrap();
    fs::write(&blob_path, saved_blob).unwrap();
    assert!(!pruned.status.success());
    assert!(
        String::from_utf8_lossy(&pruned.stderr).contains("required sender objects are unavailable")
    );
    let attempts = fs::read_to_string(&log)
        .unwrap()
        .matches("git-upload-pack 'origin'")
        .count()
        - attempts_before;
    assert!(
        attempts < 32,
        "{attempts} fetches to isolate one missing blob among 258"
    );
    let before_config = fs::read(source.join(".git/config")).unwrap();
    let fetches_before = fs::read_to_string(&log)
        .unwrap()
        .matches("git-upload-pack 'origin'")
        .count();
    assert_ok(send());
    assert_eq!(fs::read(source.join(".git/config")).unwrap(), before_config);
    let fetches_after = fs::read_to_string(&log)
        .unwrap()
        .matches("git-upload-pack 'origin'")
        .count();
    assert_eq!(
        fetches_after - fetches_before,
        2,
        "fetch the tree, then its blobs in one request"
    );
    git(&source, &["config", "remote.origin.url", &url]);
    git(&source, &["reset", "--hard", "HEAD"]);
    fs::write(source.join("file"), "staged edit\n").unwrap();
    git(&source, &["add", "file"]);
    fs::write(source.join("file"), "unstaged edit\n").unwrap();
    let index = fs::read(source.join(".git/index")).unwrap();
    // NOTE(@kitten): advertising a commit does not promise local delta bases.
    git(
        &receiver,
        &[
            "config",
            "remote.origin.url",
            root.join("unavailable").to_str().unwrap(),
        ],
    );
    git(&receiver, &["config", "remote.origin.promisor", "true"]);
    let large = (0..5000)
        .map(|i| format!("unchanged line {i}\n"))
        .collect::<String>();
    fs::write(origin.join("large"), &large).unwrap();
    git(&origin, &["add", "."]);
    git(&origin, &["commit", "-qm", "large base"]);
    git(
        &source,
        &[
            "fetch",
            "--update-head-ok",
            "origin",
            "refs/heads/topic:refs/heads/topic",
        ],
    );
    assert_ok(send());
    let base = String::from_utf8(git(&origin, &["rev-parse", "HEAD:large"]).stdout).unwrap();
    let base = base.trim();
    fs::remove_file(receiver.join("objects").join(&base[..2]).join(&base[2..])).unwrap();
    fs::write(
        origin.join("large"),
        large.replace("line 50\n", "line fifty\n"),
    )
    .unwrap();
    git(&origin, &["commit", "-qam", "intermediate"]);
    fs::write(
        origin.join("large"),
        large.replace("line 50\n", "line fifty-five\n"),
    )
    .unwrap();
    git(&origin, &["commit", "-qam", "tip"]);
    git(
        &source,
        &[
            "fetch",
            "--update-head-ok",
            "origin",
            "refs/heads/topic:refs/heads/topic",
        ],
    );
    git(&source, &["remote", "add", "upstream", &url]);
    git(
        &source,
        &["config", "remote.upstream.partialclonefilter", "blob:none"],
    );
    git(
        &source,
        &["config", "remote.origin.url", "git@promisor.invalid:origin"],
    );
    fs::remove_file(&permit).unwrap();
    let tip = String::from_utf8(git(&receiver, &["rev-parse", "refs/heads/topic"]).stdout).unwrap();
    let mut refs = format!("{} refs/tags/nonutf8-", tip.trim()).into_bytes();
    refs.extend_from_slice(b"\xff\n");
    let tags = (0..20000)
        .map(|i| format!("{} refs/tags/stale-{i:05}-{}\n", tip.trim(), "x".repeat(40)))
        .collect::<String>();
    refs.extend_from_slice(tags.as_bytes());
    assert!(refs.len() > 1024 * 1024);
    fs::write(receiver.join("packed-refs"), refs).unwrap();
    let before_config = fs::read(source.join(".git/config")).unwrap();
    let before_refs = git(&source, &["show-ref"]).stdout;
    let before_fetch = fs::read(source.join(".git/FETCH_HEAD")).unwrap();
    assert_ok(send());
    assert_eq!(fs::read(source.join(".git/config")).unwrap(), before_config);
    assert_eq!(git(&source, &["show-ref"]).stdout, before_refs);
    assert_eq!(
        fs::read(source.join(".git/FETCH_HEAD")).unwrap(),
        before_fetch
    );
    assert_eq!(fs::read(source.join(".git/index")).unwrap(), index);
    assert_eq!(fs::read(source.join("file")).unwrap(), b"unstaged edit\n");
    assert_eq!(
        git(&receiver, &["rev-parse", "refs/heads/topic"]).stdout,
        git(&source, &["rev-parse", "HEAD"]).stdout
    );
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("git-upload-pack "))
            .all(|line| line == "git-upload-pack 'origin'")
    );
    let guards = fs::read_to_string(&guards).unwrap();
    assert!(guards.starts_with("BEGIN\n"));
    for call in guards.split("BEGIN\n").skip(1) {
        assert!(
            call.starts_with(
                "-a\n-o\nForwardAgent=no\n-S\nnone\n-o\nControlMaster=no\n-o\nControlPersist=no\n"
            ),
            "{call}"
        );
    }
}

fn seed_history(forge: &Path, root: &Path, count: usize) {
    use std::{io::Write, process::Stdio};
    let mut import = isolated_command("git", forge, root)
        .arg("fast-import")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stream = import.stdin.take().unwrap();
    for i in 1..=count {
        writeln!(stream, "commit refs/heads/main\nmark :{i}\ncommitter Fixture <fixture@example.invalid> {} +0000\ndata 1\nx", 1_700_000_000 + i).unwrap();
        if i > 1 {
            writeln!(stream, "from :{}", i - 1).unwrap();
        }
        let blob = format!("historical blob {i}\n");
        writeln!(
            stream,
            "M 100644 inline file\ndata {}\n{}",
            blob.len(),
            blob
        )
        .unwrap();
        writeln!(stream).unwrap();
    }
    drop(stream);
    assert_ok(import.wait_with_output().unwrap());
    assert_ok(
        isolated_command("git", forge, root)
            .args(["symbolic-ref", "HEAD", "refs/heads/main"])
            .output()
            .unwrap(),
    );
}

#[test]
fn shallow_send_deepens_to_receiver_history_without_changing_refs() {
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    for partial in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let forge = root.join("forge.git");
        let source = root.join("sender.git");
        let receiver = root.join("receiver.git");
        let git = |directory: &Path, args: &[&str]| {
            let output = isolated_command("git", directory, &root)
                .args(args)
                .output()
                .unwrap();
            assert_ok(output.clone());
            output
        };
        git(&root, &["init", "--bare", "-q", forge.to_str().unwrap()]);
        seed_history(&forge, &root, 4096);
        let common = git(&forge, &["rev-parse", "main~3096"]);
        let common = String::from_utf8(common.stdout).unwrap();
        git(&forge, &["branch", "receiver-base", common.trim()]);
        git(
            &forge,
            &[
                "-c",
                "tag.gpgSign=false",
                "tag",
                "-a",
                "shared",
                "-m",
                "shared",
                "receiver-base",
            ],
        );
        git(
            &root,
            &[
                "clone",
                "--bare",
                "--depth=1",
                "--branch",
                "receiver-base",
                &format!("file://{}", forge.display()),
                receiver.to_str().unwrap(),
            ],
        );
        if partial {
            git(&receiver, &["update-ref", "-d", "refs/heads/receiver-base"]);
        }
        let receiver_boundary = fs::read(receiver.join("shallow")).unwrap();
        let url = format!("file://{}", forge.display());
        git(&forge, &["config", "uploadpack.allowFilter", "true"]);
        let mut clone = vec!["clone", "--no-checkout", "--depth=2"];
        if partial {
            clone.push("--filter=blob:none");
        }
        clone.extend([&url, source.to_str().unwrap()]);
        git(&root, &clone);
        if partial {
            git(&source, &["config", "extensions.partialClone", "origin"]);
            git(&source, &["config", "--unset", "remote.origin.promisor"]);
            git(
                &source,
                &["config", "--unset", "remote.origin.partialclonefilter"],
            );
        }
        if partial {
            git(
                &source,
                &[
                    "-c",
                    "fetch.negotiationAlgorithm=noop",
                    "-c",
                    "remote.origin.partialclonefilter=blob:none",
                    "fetch",
                    "--depth=1",
                    "--no-write-fetch-head",
                    "--no-tags",
                    "--refmap=",
                    "origin",
                    "refs/tags/shared",
                ],
            );
        } else {
            let missing = isolated_command("git", &source, &root)
                .args(["--no-lazy-fetch", "cat-file", "-e", common.trim()])
                .output()
                .unwrap();
            assert!(
                !missing.status.success(),
                "receiver branch tip must become known through deepening"
            );
        }
        git(&source, &["branch", "-m", "topic"]);
        let tree = git(&source, &["rev-parse", "HEAD^{tree}"]);
        let local = git(
            &source,
            &[
                "commit-tree",
                String::from_utf8_lossy(&tree.stdout).trim(),
                "-p",
                "HEAD",
                "-m",
                "unpublished",
            ],
        );
        git(
            &source,
            &[
                "update-ref",
                "refs/heads/topic",
                String::from_utf8_lossy(&local.stdout).trim(),
            ],
        );
        git(&source, &["read-tree", "HEAD"]);
        fs::write(source.join("file"), "uncommitted worktree edit\n").unwrap();
        let index = fs::read(source.join(".git/index")).unwrap();
        let block = root.join("block-pack");
        let pack = root.join("pack-hook");
        fs::write(
            &pack,
            format!(
                "#!/bin/sh\nwhile test -e {}; do sleep 0.02; done\nexec \"$@\"\n",
                quote(&block)
            ),
        )
        .unwrap();
        fs::set_permissions(&pack, fs::Permissions::from_mode(0o700)).unwrap();
        let upload = root.join("upload");
        fs::write(
            &upload,
            format!(
                "#!/bin/sh\nexec git -c {} upload-pack \"$@\"\n",
                quote(Path::new(&format!(
                    "uploadpack.packObjectsHook={}",
                    pack.display()
                )))
            ),
        )
        .unwrap();
        fs::set_permissions(&upload, fs::Permissions::from_mode(0o700)).unwrap();
        git(
            &source,
            &[
                "config",
                "remote.origin.uploadpack",
                upload.to_str().unwrap(),
            ],
        );
        if partial {
            git(&source, &["remote", "add", "aab-plain", &url]);
            git(
                &source,
                &[
                    "config",
                    "remote.aab-plain.uploadpack",
                    upload.to_str().unwrap(),
                ],
            );
        }
        git(
            &source,
            &[
                "remote",
                "add",
                "aaa-dead",
                root.join("unavailable").to_str().unwrap(),
            ],
        );
        let refs = git(&source, &["show-ref"]).stdout;
        let shallow = fs::read(source.join(".git/shallow")).unwrap();
        let config = fs::read(source.join(".git/config")).unwrap();
        let ssh = root.join("ssh");
        fs::write(
            &ssh,
            "#!/bin/sh\nfor arg do remote=$arg; done\nexec /bin/sh -c \"$remote\"\n",
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let trace = root.join("trace.json");
        let send = |destination: &Path| {
            let mut command = isolated_command(env!("CARGO_BIN_EXE_git-send"), &source, &root);
            command
                .env("GIT_TRACE2_EVENT", &trace)
                .env("GIT_SSH_COMMAND", &ssh)
                .env("GIT_SSH_VARIANT", "ssh")
                .args([
                    "--local-only",
                    &format!("fixture:{}", destination.display()),
                ]);
            command
        };
        git(
            &source,
            &[
                "config",
                "remote.origin.url",
                root.join("unavailable").to_str().unwrap(),
            ],
        );
        if partial {
            git(
                &source,
                &[
                    "config",
                    "remote.aab-plain.url",
                    root.join("unavailable").to_str().unwrap(),
                ],
            );
        }
        let refused = send(&receiver).output().unwrap();
        assert!(!refused.status.success());
        assert!(
            String::from_utf8_lossy(&refused.stderr)
                .contains("cannot deepen required sender history")
        );
        assert_eq!(fs::read(source.join(".git/shallow")).unwrap(), shallow);
        assert!(
            git(&receiver, &["for-each-ref", "refs/heads/topic"])
                .stdout
                .is_empty()
        );
        git(&source, &["config", "remote.origin.url", &url]);
        if partial {
            git(&source, &["config", "remote.aab-plain.url", &url]);
        }
        let native_lock = source.join(".git/shallow.lock");
        fs::write(&native_lock, "native Git owns this lock\n").unwrap();
        assert!(!send(&receiver).output().unwrap().status.success());
        assert_eq!(
            fs::read(&native_lock).unwrap(),
            b"native Git owns this lock\n"
        );
        assert_eq!(fs::read(source.join(".git/shallow")).unwrap(), shallow);
        fs::remove_file(&native_lock).unwrap();
        let wait_for_lock = |child: &mut std::process::Child| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline && child.try_wait().unwrap().is_none() {
                if source.join(".git/shallow.lock").exists() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        };
        fs::write(&block, "").unwrap();
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            let mut interrupted = send(&receiver)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let locked = wait_for_lock(&mut interrupted);
            unsafe {
                libc::kill(interrupted.id() as i32, signal);
            }
            let output = interrupted.wait_with_output().unwrap();
            assert!(locked, "{}", String::from_utf8_lossy(&output.stderr));
            assert!(!output.status.success());
            assert!(!source.join(".git/shallow.lock").exists());
            assert_eq!(fs::read(source.join(".git/shallow")).unwrap(), shallow);
        }
        fs::write(&trace, "").unwrap();
        let other = root.join("other.git");
        git(
            &root,
            &[
                "clone",
                "--bare",
                "--depth=1",
                "--branch",
                "receiver-base",
                &url,
                other.to_str().unwrap(),
            ],
        );
        let mut first = send(&receiver)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let locked = wait_for_lock(&mut first);
        let trace_offset = fs::read(&trace).unwrap().len();
        let mut second = send(&other)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let reached_lock = loop {
            let trace_bytes = fs::read(&trace).unwrap();
            let events: Vec<serde_json::Value> =
                String::from_utf8_lossy(&trace_bytes[trace_offset..])
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect();
            let completed = events
                .iter()
                .filter(|event| {
                    event["event"] == "start"
                        && event["argv"].as_array().is_some_and(|args| {
                            args.last().is_some_and(|arg| arg == "--git-common-dir")
                        })
                        && events
                            .iter()
                            .any(|exit| exit["event"] == "exit" && exit["sid"] == event["sid"])
                })
                .count();
            if completed >= 1 {
                break true;
            }
            if Instant::now() >= deadline || second.try_wait().unwrap().is_some() {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        std::thread::sleep(Duration::from_millis(100));
        let waiting = second.try_wait().unwrap().is_none();
        fs::remove_file(&block).unwrap();
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();
        assert!(locked && reached_lock && waiting);
        assert_ok(first);
        assert_ok(second);
        assert_eq!(git(&source, &["show-ref"]).stdout, refs);
        assert_eq!(fs::read(source.join(".git/config")).unwrap(), config);
        assert_eq!(fs::read(source.join(".git/index")).unwrap(), index);
        assert_eq!(
            fs::read(source.join("file")).unwrap(),
            b"uncommitted worktree edit\n"
        );
        assert!(!source.join(".git/FETCH_HEAD").exists());
        assert_ne!(fs::read(source.join(".git/shallow")).unwrap(), shallow);
        assert_eq!(
            git(&source, &["rev-parse", "--is-shallow-repository"]).stdout,
            b"true\n"
        );
        assert_eq!(
            git(&receiver, &["rev-parse", "refs/heads/topic"]).stdout,
            local.stdout
        );
        assert_eq!(
            fs::read(receiver.join("shallow")).unwrap(),
            receiver_boundary
        );
        let events: Vec<serde_json::Value> = fs::read_to_string(&trace)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let starts: Vec<_> = events
            .iter()
            .filter(|event| event["event"] == "start")
            .filter_map(|event| event["argv"].as_array())
            .collect();
        for depth in [256, 512, 1024, 2048] {
            assert!(
                starts
                    .iter()
                    .any(|args| args.iter().any(|arg| arg == &format!("--deepen={depth}")))
            );
        }
        assert_eq!(
            starts
                .iter()
                .filter(|args| args.iter().any(|arg| arg == "aaa-dead"))
                .count(),
            1
        );
        if partial {
            let old_blob = git(&forge, &["rev-parse", "main~4095:file"]);
            let missing = isolated_command("git", &source, &root)
                .args([
                    "--no-lazy-fetch",
                    "cat-file",
                    "-e",
                    String::from_utf8_lossy(&old_blob.stdout).trim(),
                ])
                .output()
                .unwrap();
            assert!(
                !missing.status.success(),
                "plain deepening remote hydrated excluded historical blobs"
            );
        }
        let stable = fs::read(source.join(".git/shallow")).unwrap();
        assert_ok(send(&receiver).output().unwrap());
        assert_eq!(fs::read(source.join(".git/shallow")).unwrap(), stable);
        let empty = root.join("empty.git");
        git(&root, &["init", "--bare", "-q", empty.to_str().unwrap()]);
        assert_ok(send(&empty).output().unwrap());
        assert!(!source.join(".git/shallow").exists());
        assert_eq!(git(&source, &["show-ref"]).stdout, refs);
        assert_eq!(
            git(&empty, &["rev-parse", "refs/heads/topic"]).stdout,
            local.stdout
        );
    }
}

#[test]
fn current_receiver_does_not_hydrate_excluded_historical_blobs() {
    use std::{io::Write, process::Stdio};
    for (filter, hidden) in [("blob:none", false), ("tree:0", false), ("blob:none", true)] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let forge = root.join("forge.git");
        let source = root.join("sender.git");
        let receiver = root.join("receiver.git");
        let git = |repo: &Path, args: &[&str]| {
            let output = isolated_command("git", repo, &root)
                .args(args)
                .output()
                .unwrap();
            assert_ok(output.clone());
            output
        };
        git(&root, &["init", "--bare", "-q", forge.to_str().unwrap()]);
        seed_history(&forge, &root, 512);
        let original_tree = git(&forge, &["rev-parse", "HEAD^{tree}"]);
        let original_tip = git(&forge, &["rev-parse", "HEAD"]);
        let mut import = isolated_command("git", &forge, &root)
            .arg("fast-import")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        write!(import.stdin.take().unwrap(), "commit refs/heads/main\ncommitter Fixture <fixture@example.invalid> 1700000513 +0000\ndata 1\nx\nfrom {}\nR file a/inner/file\n\n", String::from_utf8_lossy(&original_tip.stdout).trim()).unwrap();
        assert_ok(import.wait_with_output().unwrap());
        git(&forge, &["config", "uploadpack.allowFilter", "true"]);
        let url = format!("file://{}", forge.display());
        git(
            &root,
            &[
                "clone",
                "--bare",
                "--filter",
                filter,
                &url,
                source.to_str().unwrap(),
            ],
        );
        git(
            &root,
            &[
                "clone",
                "--bare",
                forge.to_str().unwrap(),
                receiver.to_str().unwrap(),
            ],
        );
        if hidden {
            git(
                &receiver,
                &["config", "receive.hideRefs", "refs/heads/main"],
            );
        }
        git(&source, &["config", "pack.usePathWalk", "true"]);
        let parent = git(&forge, &["rev-parse", "HEAD"]);
        let tree_entry = git(&forge, &["ls-tree", "HEAD"]);
        let mut tree = isolated_command("git", &source, &root)
            .args(["mktree", "--missing"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(
            tree.stdin.take().unwrap(),
            "{}040000 tree {}\tb",
            String::from_utf8(tree_entry.stdout).unwrap(),
            String::from_utf8_lossy(&original_tree.stdout).trim()
        )
        .unwrap();
        let tree = tree.wait_with_output().unwrap();
        assert!(tree.status.success());
        let mut commit = isolated_command("git", &source, &root)
            .args(["hash-object", "-w", "-t", "commit", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        write!(commit.stdin.take().unwrap(), "tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 1700000513 +0000\ncommitter Fixture <fixture@example.invalid> 1700000513 +0000\n\nunpublished\n",
            String::from_utf8_lossy(&tree.stdout).trim(), String::from_utf8_lossy(&parent.stdout).trim()).unwrap();
        let commit = commit.wait_with_output().unwrap();
        assert!(commit.status.success());
        git(
            &source,
            &[
                "update-ref",
                "refs/heads/topic",
                String::from_utf8_lossy(&commit.stdout).trim(),
            ],
        );
        let ssh = root.join("ssh");
        fs::write(
            &ssh,
            "#!/bin/sh\nfor arg do remote=$arg; done\nexec /bin/sh -c \"$remote\"\n",
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        assert_ok(
            isolated_command(env!("CARGO_BIN_EXE_git-send"), &source, &root)
                .env("GIT_SSH_COMMAND", &ssh)
                .env("GIT_SSH_VARIANT", "ssh")
                .args([
                    "--local-only",
                    "--branch",
                    "topic",
                    &format!("fixture:{}", receiver.display()),
                ])
                .output()
                .unwrap(),
        );
        let types = git(
            &source,
            &[
                "--no-lazy-fetch",
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objecttype)",
            ],
        );
        assert!(
            hidden
                || !String::from_utf8_lossy(&types.stdout)
                    .lines()
                    .any(|kind| kind == "blob"),
            "{filter}: historical blobs were hydrated"
        );
        assert_eq!(
            git(&receiver, &["rev-parse", "refs/heads/topic"]).stdout,
            commit.stdout
        );
        if hidden {
            continue;
        }
        git(
            &receiver,
            &[
                "-c",
                "tag.gpgSign=false",
                "tag",
                "-a",
                "receiver-only",
                "-m",
                "receiver-only",
                String::from_utf8_lossy(&parent.stdout).trim(),
            ],
        );
        git(&receiver, &["update-ref", "-d", "refs/heads/main"]);
        git(&receiver, &["update-ref", "-d", "refs/heads/topic"]);
        assert_ok(
            isolated_command(env!("CARGO_BIN_EXE_git-send"), &source, &root)
                .env("GIT_SSH_COMMAND", &ssh)
                .env("GIT_SSH_VARIANT", "ssh")
                .args([
                    "--local-only",
                    "--branch",
                    "topic",
                    &format!("fixture:{}", receiver.display()),
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(
            git(&receiver, &["rev-parse", "refs/heads/topic"]).stdout,
            commit.stdout
        );
    }
}

#[test]
fn merged_shallow_promisors_supply_disjoint_roots_and_objects() {
    use std::{io::Write, process::Stdio};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let fork = root.join("fork.git");
    let upstream = root.join("upstream.git");
    let source = root.join("sender.git");
    let receiver = root.join("receiver.git");
    let git = |repo: &Path, args: &[&str]| {
        let output = isolated_command("git", repo, &root)
            .args(args)
            .output()
            .unwrap();
        assert_ok(output.clone());
        output
    };
    git(&root, &["init", "--bare", "-q", fork.to_str().unwrap()]);
    seed_history(&fork, &root, 2);
    git(
        &root,
        &[
            "clone",
            "--bare",
            fork.to_str().unwrap(),
            upstream.to_str().unwrap(),
        ],
    );
    let mut tips = Vec::new();
    let mut entries = Vec::new();
    for (repo, name) in [(&fork, "fork"), (&upstream, "upstream")] {
        let parent = git(repo, &["rev-parse", "HEAD"]);
        let mut import = isolated_command("git", repo, &root)
            .arg("fast-import")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        write!(import.stdin.take().unwrap(), "commit refs/heads/main\ncommitter Fixture <fixture@example.invalid> 1700000003 +0000\ndata 1\nx\nfrom {}\nM 100644 inline file\ndata {}\n{}\n\n", String::from_utf8_lossy(&parent.stdout).trim(), name.len(), name).unwrap();
        assert_ok(import.wait_with_output().unwrap());
        git(repo, &["config", "uploadpack.allowFilter", "true"]);
        tips.push(String::from_utf8(git(repo, &["rev-parse", "HEAD"]).stdout).unwrap());
        let blob = git(repo, &["rev-parse", "HEAD:file"]);
        writeln!(
            entries,
            "100644 blob {}\t{name}",
            String::from_utf8_lossy(&blob.stdout).trim()
        )
        .unwrap();
    }
    git(
        &root,
        &[
            "clone",
            "--bare",
            "--depth=1",
            "--filter=blob:none",
            &format!("file://{}", fork.display()),
            source.to_str().unwrap(),
        ],
    );
    git(
        &source,
        &[
            "remote",
            "add",
            "upstream",
            &format!("file://{}", upstream.display()),
        ],
    );
    git(&source, &["config", "remote.upstream.promisor", "true"]);
    git(
        &source,
        &["config", "remote.upstream.partialclonefilter", "blob:none"],
    );
    git(
        &source,
        &[
            "fetch",
            "--depth=1",
            "--no-write-fetch-head",
            "upstream",
            "refs/heads/main:refs/heads/upstream",
        ],
    );
    let mut tree = isolated_command("git", &source, &root)
        .args(["mktree", "--missing"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    tree.stdin.take().unwrap().write_all(&entries).unwrap();
    let tree = tree.wait_with_output().unwrap();
    assert_ok(tree.clone());
    let commit = git(
        &source,
        &[
            "commit-tree",
            String::from_utf8_lossy(&tree.stdout).trim(),
            "-p",
            tips[0].trim(),
            "-p",
            tips[1].trim(),
            "-m",
            "merge",
        ],
    );
    git(
        &source,
        &[
            "update-ref",
            "refs/heads/main",
            String::from_utf8_lossy(&commit.stdout).trim(),
        ],
    );
    git(&root, &["init", "--bare", "-q", receiver.to_str().unwrap()]);
    let refs = git(&source, &["show-ref"]).stdout;
    let config = fs::read(source.join("config")).unwrap();
    let ssh = root.join("ssh");
    fs::write(
        &ssh,
        "#!/bin/sh\nfor arg do remote=$arg; done\nexec /bin/sh -c \"$remote\"\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    assert_ok(
        isolated_command(env!("CARGO_BIN_EXE_git-send"), &source, &root)
            .env("GIT_SSH_COMMAND", &ssh)
            .env("GIT_SSH_VARIANT", "ssh")
            .args(["--local-only", &format!("fixture:{}", receiver.display())])
            .output()
            .unwrap(),
    );
    assert_eq!(
        git(&receiver, &["rev-parse", "refs/heads/main"]).stdout,
        commit.stdout
    );
    assert_eq!(git(&source, &["show-ref"]).stdout, refs);
    assert_eq!(fs::read(source.join("config")).unwrap(), config);
    assert!(!source.join("FETCH_HEAD").exists());
    assert!(!source.join("shallow").exists());
}
