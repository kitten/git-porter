#[path = "support/source_agent.rs"]
mod source_agent;
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
        command.arg("--local-only");
        if binary.ends_with("git-receive") && extra.contains(&"--branch") {
            command.arg("--switch");
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
    let tip =
        String::from_utf8(git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout)
            .unwrap();
    assert_ok(git(
        &destination,
        &["update-ref", "refs/heads/review/é+retry", tip.trim()],
    ));
    assert_ok(run(
        env!("CARGO_BIN_EXE_git-receive"),
        &["--local-only", "--branch", "review/é+retry"],
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
        if binary.ends_with("git-receive") {
            command.arg("--local-only");
        }
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

#[test]
fn checked_out_partial_clone_still_needs_historical_blobs_for_upload() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let forge = root.join("forge");
    let serving = root.join("serving");
    let receiving = root.join("receiving");
    fs::create_dir(&forge).unwrap();
    let run = |directory: &Path, arguments: &[&str]| {
        isolated_command("git", directory, root)
            .args(arguments)
            .output()
            .unwrap()
    };
    assert_ok(run(&forge, &["init", "-q", "-b", "topic"]));
    fs::write(forge.join("file"), "historical blob\n").unwrap();
    assert_ok(run(&forge, &["add", "."]));
    assert_ok(run(&forge, &["commit", "-qm", "historical"]));
    let blob = String::from_utf8(run(&forge, &["rev-parse", "HEAD:file"]).stdout).unwrap();
    fs::write(forge.join("file"), "current blob\n").unwrap();
    assert_ok(run(&forge, &["commit", "-qam", "current"]));
    assert_ok(run(&forge, &["config", "uploadpack.allowFilter", "true"]));
    assert_ok(run(
        root,
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            &format!("file://{}", forge.display()),
            serving.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read_to_string(serving.join("file")).unwrap(),
        "current blob\n"
    );
    assert!(
        !run(
            &serving,
            &["--no-lazy-fetch", "cat-file", "-e", blob.trim()]
        )
        .status
        .success()
    );
    assert_ok(run(root, &["init", "-q", receiving.to_str().unwrap()]));
    let transfer = || {
        isolated_command("git", &receiving, root)
            .env("GIT_NO_LAZY_FETCH", "1")
            .args([
                "fetch",
                serving.to_str().unwrap(),
                "refs/heads/topic:refs/heads/topic",
            ])
            .output()
            .unwrap()
    };
    let failure = transfer();
    assert!(!failure.status.success());
    assert!(
        String::from_utf8_lossy(&failure.stderr).contains("git-pack-objects died"),
        "{}",
        String::from_utf8_lossy(&failure.stderr)
    );
    // Explicit owner-side hydration uses the actual upstream, outside a pinned
    // Porter transport. It changes objects only, with no persistent config edit.
    assert_ok(run(
        &serving,
        &["fetch", "--no-write-fetch-head", "origin", blob.trim()],
    ));
    assert_ok(transfer());
}

#[test]
fn authenticated_receive_refreshes_stale_partial_receiver_without_updating_its_checkout() {
    use git_porter::credentials::wrapping;
    use signature::Signer;
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let forge = root.join("forge");
    let home = root.join("operator");
    let client = root.join("client");
    let serving = home.join("repo");
    let bin = root.join("bin");
    for path in [&forge, &home, &client, &bin] {
        fs::create_dir_all(path).unwrap();
    }
    let git = |path: &Path, args: &[&str]| {
        isolated_command("git", path, &root)
            .args(args)
            .output()
            .unwrap()
    };
    assert_ok(git(&forge, &["init", "-q", "-b", "topic"]));
    fs::write(forge.join("file"), "historical\n").unwrap();
    assert_ok(git(&forge, &["add", "."]));
    assert_ok(git(&forge, &["commit", "-qm", "base"]));
    fs::write(forge.join("file"), "checked out\n").unwrap();
    assert_ok(git(&forge, &["commit", "-qam", "checked out tree"]));
    assert_ok(git(&forge, &["config", "uploadpack.allowFilter", "true"]));
    assert_ok(git(
        &home,
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            &format!("file://{}", forge.display()),
            serving.to_str().unwrap(),
        ],
    ));
    let old = git(&serving, &["rev-parse", "HEAD"]).stdout;
    fs::write(forge.join("file"), "latest\n").unwrap();
    assert_ok(git(&forge, &["commit", "-qam", "latest"]));
    let latest = git(&forge, &["rev-parse", "HEAD"]).stdout;
    assert_ok(git(&forge, &["branch", "review/é+retry"]));
    assert_ok(git(&forge, &["branch", "topic./sub"]));
    assert_ok(git(
        &serving,
        &["remote", "set-url", "origin", "git@github.com:test/fixture"],
    ));
    assert_ok(git(&client, &["init", "-q", "-b", "topic"]));
    let data = home.join(".local/share/git-porter");
    fs::create_dir_all(data.join("transport")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), data.join("transport/ssh"))
        .unwrap();
    let source =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let metadata = wrapping::Metadata::generate(source.public_key()).unwrap();
    let signature: ssh_key::Signature = source
        .try_sign(&metadata.challenge(source.public_key()).unwrap())
        .unwrap();
    let identity = metadata
        .from_signature(source.public_key(), &signature)
        .unwrap();
    let bundle = wrapping::Bundle {
        metadata,
        ciphertext: age::encrypt(
            &identity.to_public(),
            key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap(),
    };
    bundle
        .write(fs::File::create(data.join("publication.wrapped")).unwrap())
        .unwrap();
    fs::set_permissions(
        data.join("publication.wrapped"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::write(
        data.join("publication.pub"),
        key.public_key().to_openssh().unwrap(),
    )
    .unwrap();
    fs::write(
        data.join("publication.source.pub"),
        source.public_key().to_openssh().unwrap(),
    )
    .unwrap();
    fs::write(
        home.join(".gitconfig"),
        format!(
            "[porter]\nsearchRoot = {}\nauthorizedKey = {}\n",
            home.display(),
            source.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let agent = source_agent::Agent::start(source).unwrap();
    let fork = root.join("fork.git");
    let log = root.join("upstream-log");
    let packet_trace = root.join("upstream-packets");
    let hold = root.join("hold-upstream");
    let started = root.join("upstream-started");
    let reject = root.join("reject");
    // Only upstream SSH reaches this fixture executable; incoming Git uses the
    // separate forced-command wrapper below. No actual network or credentials.
    fs::write(
        bin.join("ssh"),
        format!(
            "#!/bin/sh\necho upstream >> {}\ntest ! -e {} || exit 1\nif test -e {}; then : > {}; while test -e {}; do sleep 0.01; done; fi\nfor arg do request=$arg; done\ncase \"$request\" in *test/fork*) GIT_TRACE_PACKET={} exec git-upload-pack {} ;; esac\nGIT_TRACE_PACKET={} exec git-upload-pack {}\n",
            quote(&log),
            quote(&reject),
            quote(&hold), quote(&started), quote(&hold),
            quote(&packet_trace), quote(&fork),
            quote(&packet_trace),
            quote(&forge)
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("ssh"), fs::Permissions::from_mode(0o700)).unwrap();
    let incoming = root.join("incoming-ssh");
    fs::write(&incoming, format!("#!/bin/sh\nfor arg do SSH_ORIGINAL_COMMAND=$arg; done\nexport SSH_ORIGINAL_COMMAND\nexport HOME={}\nexport XDG_DATA_HOME={}\nexport XDG_CONFIG_HOME={}\nunset SSH_AUTH_SOCK\nexec {} internal:serve\n", quote(&home), quote(&home.join(".local/share")), quote(&home.join(".config")), quote(Path::new(env!("CARGO_BIN_EXE_git-porter"))))).unwrap();
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
    let real_git = git_porter::server::config::executable("git").unwrap();
    let upload_environment_error = root.join("upload-environment-error");
    fs::write(bin.join("git"), format!("#!/bin/sh\nfor arg do\nif test \"$arg\" = upload-pack; then\nif test -n \"${{GIT_SSH-}}${{GIT_SSH_COMMAND-}}${{GIT_PORTER_TRANSACTION_SOCKET-}}${{SSH_AUTH_SOCK-}}\"; then : > {}; exit 99; fi\nfi\ndone\nexec {} \"$@\"\n", quote(&upload_environment_error), quote(&real_git))).unwrap();
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let remote_login = fs::read_to_string(&incoming).unwrap().replacen(
        "\nexec ",
        &format!("\nexport PATH={}\nexec ", quote(Path::new(&path))),
        1,
    );
    fs::write(&incoming, remote_login).unwrap();
    let receive = |branch: &str, local: bool| {
        let mut cmd = isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root);
        cmd.env("PATH", &path)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_SSH_COMMAND", &incoming)
            .env("SSH_AUTH_SOCK", agent.socket());
        if local {
            cmd.arg("--local-only");
        }
        cmd.arg("--switch")
            .args([
                "--branch",
                branch,
                &format!("operator:{}", serving.display()),
            ])
            .output()
            .unwrap()
    };
    let receive_matching = |branch: Option<&str>| {
        let mut cmd = isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root);
        cmd.env("PATH", &path)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_SSH_COMMAND", &incoming)
            .env("SSH_AUTH_SOCK", agent.socket());
        if let Some(branch) = branch {
            cmd.args(["--branch", branch]);
        }
        cmd.arg(format!("operator:{}", serving.display()))
            .output()
            .unwrap()
    };
    assert!(!receive("topic", true).status.success());
    assert!(
        !git(&client, &["show-ref", "--verify", "refs/heads/topic"])
            .status
            .success()
    );
    assert!(!log.exists(), "local-only must not contact upstream");
    // Matching branch names update both the branch and its checkout without
    // requiring --switch, preserving main's existing behavior.
    assert_ok(receive_matching(Some("topic")));
    assert_eq!(
        git(&client, &["symbolic-ref", "--short", "HEAD"]).stdout,
        b"topic\n"
    );
    assert_eq!(fs::read_to_string(client.join("file")).unwrap(), "latest\n");
    assert_eq!(git(&client, &["rev-parse", "topic"]).stdout, latest);
    assert_eq!(git(&serving, &["rev-parse", "HEAD"]).stdout, old);
    assert_eq!(
        fs::read_to_string(serving.join("file")).unwrap(),
        "checked out\n"
    );
    // Warm receives reuse the complete graph, while still checking upstream.
    let cache_root = root.join("XDG_CACHE_HOME/git-porter/read-objects");
    // The incoming wrapper keeps the isolated client's XDG cache directory.
    let cache_bytes = |root: &Path| {
        fn size(path: &Path) -> u64 {
            fs::read_dir(path)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        size(&path)
                    } else if path.extension().is_some_and(|e| e == "pack") {
                        fs::metadata(path).unwrap().len()
                    } else {
                        0
                    }
                })
                .sum()
        }
        size(root)
    };
    let wants = || {
        fs::read_to_string(&packet_trace)
            .unwrap()
            .lines()
            .filter(|line| line.contains("want "))
            .count()
    };
    let cold_wants = wants();
    assert!(cold_wants > 0);
    assert!(!cache_root.exists());
    let cold_size = cache_bytes(&serving.join(".git/objects"));
    assert!(cold_size > 0);
    assert_ok(receive_matching(None));
    assert_eq!(cache_bytes(&serving.join(".git/objects")), cold_size);
    assert_eq!(
        wants(),
        cold_wants,
        "warm receives must not request another pack"
    );
    fs::write(&hold, "").unwrap();
    let mut slow = isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root)
        .env("PATH", &path)
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_SSH_COMMAND", &incoming)
        .env("SSH_AUTH_SOCK", agent.socket())
        .args([
            "--branch",
            "topic",
            &format!("operator:{}", serving.display()),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !started.exists() {
        if std::time::Instant::now() > deadline {
            fs::remove_file(&hold).unwrap();
            let _ = slow.kill();
            let _ = slow.wait();
            panic!("read did not reach upstream preparation");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let key_lock = git_porter::credentials::keys::Lock::acquire(&data);
    let unlocked = key_lock.is_ok();
    drop(key_lock);
    fs::remove_file(&hold).unwrap();
    assert_ok(slow.wait_with_output().unwrap());
    assert!(
        unlocked,
        "read retained the credential bundle lock during network transfer"
    );
    assert_ok(receive("topic./sub", false));
    assert_eq!(
        git(&client, &["symbolic-ref", "--short", "HEAD"]).stdout,
        b"topic./sub\n"
    );
    assert_ok(git(&client, &["switch", "-c", "renamed-local", "topic"]));
    let pull = |source: &str| {
        isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root)
            .env("PATH", &path)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_SSH_COMMAND", &incoming)
            .env("SSH_AUTH_SOCK", agent.socket())
            .args([
                "--branch",
                source,
                &format!("operator:{}", serving.display()),
            ])
            .output()
            .unwrap()
    };
    assert_ok(pull("topic"));
    assert_eq!(
        git(&client, &["symbolic-ref", "--short", "HEAD"]).stdout,
        b"renamed-local\n"
    );
    assert_ok(git(&forge, &["switch", "-c", "pull-source"]));
    assert_ok(git(
        &forge,
        &["commit", "--allow-empty", "-qm", "pull source"],
    ));
    let pulled = git(&forge, &["rev-parse", "HEAD"]).stdout;
    assert_ok(git(&forge, &["switch", "topic"]));
    assert_ok(pull("pull-source"));
    assert_eq!(git(&client, &["rev-parse", "renamed-local"]).stdout, pulled);
    assert_eq!(git(&client, &["rev-parse", "topic"]).stdout, latest);
    assert!(
        !git(&client, &["show-ref", "--verify", "refs/heads/pull-source"])
            .status
            .success()
    );
    assert_ok(receive("pull-source", false));
    assert_eq!(
        git(&client, &["symbolic-ref", "--short", "HEAD"]).stdout,
        b"pull-source\n"
    );
    assert_ok(git(&forge, &["switch", "-c", "collision", "pull-source"]));
    fs::write(forge.join("protected-file"), "remote content").unwrap();
    assert_ok(git(&forge, &["add", "."]));
    assert_ok(git(&forge, &["commit", "-qm", "checkout conflict"]));
    assert_ok(git(&forge, &["switch", "topic"]));
    fs::write(client.join(".git/info/exclude"), "protected-file\n").unwrap();
    fs::write(client.join("protected-file"), "local content").unwrap();
    assert!(!pull("collision").status.success());
    assert_eq!(git(&client, &["rev-parse", "HEAD"]).stdout, pulled);
    assert_eq!(
        fs::read_to_string(client.join("protected-file")).unwrap(),
        "local content"
    );
    let conflict = receive("collision", false);
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("Received refs/heads/collision"));
    assert_eq!(
        fs::read_to_string(client.join("protected-file")).unwrap(),
        "local content"
    );
    assert_eq!(
        git(&client, &["symbolic-ref", "--short", "HEAD"]).stdout,
        b"pull-source\n"
    );
    fs::remove_file(client.join("protected-file")).unwrap();
    // A divergent operator head cannot block receiving the upstream branch.
    assert_ok(git(
        &serving,
        &["commit", "--allow-empty", "-qm", "operator divergence"],
    ));
    assert_ok(receive("topic", false));
    assert_eq!(git(&client, &["rev-parse", "topic"]).stdout, latest);
    let historical = git(&forge, &["rev-parse", "topic~2:file"]).stdout;
    assert_ok(git(
        &serving,
        &[
            "fetch",
            "--no-write-fetch-head",
            &format!("file://{}", forge.display()),
            std::str::from_utf8(&historical).unwrap().trim(),
        ],
    ));
    assert_ok(git(
        &serving,
        &[
            "update-ref",
            "refs/remotes/origin/review/é+retry",
            std::str::from_utf8(&old).unwrap().trim(),
        ],
    ));
    assert_ok(receive("review/é+retry", true));
    assert_eq!(git(&client, &["rev-parse", "review/é+retry"]).stdout, old);
    assert_ok(git(
        &serving,
        &[
            "update-ref",
            "refs/remotes/another/review/é+retry",
            std::str::from_utf8(&old).unwrap().trim(),
        ],
    ));
    assert!(!receive("review/é+retry", true).status.success());
    assert_ok(receive("review/é+retry", false));
    assert_eq!(
        git(&client, &["rev-parse", "review/é+retry"]).stdout,
        latest
    );
    assert!(
        !git(
            &serving,
            &["show-ref", "--verify", "refs/heads/review/é+retry"]
        )
        .status
        .success()
    );
    assert!(!receive("missing-branch", false).status.success());
    assert_ok(git(
        &serving,
        &["remote", "add", "unrelated", "git@github.com:other/repo"],
    ));
    assert_ok(git(
        &serving,
        &[
            "config",
            "--add",
            "remote.origin.url",
            "git@github.com:ambiguous/repo",
        ],
    ));
    let before = fs::read_to_string(&log).unwrap();
    assert!(!receive("topic", false).status.success());
    assert_eq!(fs::read_to_string(&log).unwrap(), before);
    assert_ok(git(
        &serving,
        &["config", "--unset-all", "remote.origin.url"],
    ));
    assert_ok(git(
        &serving,
        &["config", "remote.origin.url", "git@github.com:test/fixture"],
    ));
    fs::write(&reject, "").unwrap();
    assert!(!receive("topic", false).status.success());
    assert_eq!(git(&client, &["rev-parse", "topic"]).stdout, latest);
    fs::remove_file(&reject).unwrap();
    assert_ok(git(&client, &["switch", "topic"]));
    fs::write(client.join("local"), "local divergence").unwrap();
    assert_ok(git(&client, &["add", "."]));
    assert_ok(git(&client, &["commit", "-qm", "local"]));
    let local = git(&client, &["rev-parse", "HEAD"]).stdout;
    fs::write(forge.join("file"), "next\n").unwrap();
    assert_ok(git(&forge, &["commit", "-qam", "next"]));
    assert!(!receive("topic", false).status.success());
    assert_eq!(git(&client, &["rev-parse", "HEAD"]).stdout, local);
    // Explicit account-agent mode does not require a sender signing socket.
    let policy = fs::read_to_string(home.join(".gitconfig")).unwrap();
    fs::write(
        home.join(".gitconfig"),
        format!("{policy}skipWrappedKey = true\n"),
    )
    .unwrap();
    let wrapper = fs::read_to_string(&incoming).unwrap().replace(
        "unset SSH_AUTH_SOCK",
        &format!("export SSH_AUTH_SOCK={}", quote(&agent.socket())),
    );
    fs::write(&incoming, wrapper).unwrap();
    let account_result = isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root)
        .env("PATH", &path)
        .env("GIT_SSH_COMMAND", &incoming)
        .env("GIT_SSH_VARIANT", "ssh")
        .env("SSH_AUTH_SOCK", root.join("no-sender-agent"))
        .args([
            "--switch",
            "--branch",
            "review/é+retry",
            &format!("operator:{}", serving.display()),
        ])
        .output()
        .unwrap();
    assert_ok(account_result);
    // Ordinary SSH uses the same origin hydration algorithm with the operator's
    // selected SSH transport, without Porter policy or credential derivation.
    let native_client = root.join("native-client");
    fs::create_dir(&native_client).unwrap();
    assert_ok(git(&native_client, &["init", "-q", "-b", "topic"]));
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), bin.join("git-porter")).unwrap();
    assert_ok(git(
        &serving,
        &[
            "config",
            "core.sshCommand",
            bin.join("ssh").to_str().unwrap(),
        ],
    ));
    assert_ok(git(&serving, &["config", "ssh.variant", "ssh"]));
    let native_ssh = root.join("native-ssh");
    fs::write(&native_ssh, format!("#!/bin/sh\nfor arg do remote=$arg; done\nexport HOME={}\nunset GIT_SSH_COMMAND GIT_SSH GIT_SSH_VARIANT\nexec /bin/sh -c \"$remote\"\n", quote(&home))).unwrap();
    fs::set_permissions(&native_ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let native_result = isolated_command(env!("CARGO_BIN_EXE_git-receive"), &native_client, &root)
        .env("PATH", &path)
        .env("GIT_SSH_COMMAND", &native_ssh)
        .env("GIT_SSH_VARIANT", "ssh")
        .args([
            "--branch",
            "topic",
            &format!("operator:{}", serving.display()),
        ])
        .output()
        .unwrap();
    assert_ok(native_result);
    assert_eq!(
        git(&native_client, &["rev-parse", "topic"]).stdout,
        git(&forge, &["rev-parse", "topic"]).stdout
    );
    assert_ok(git(&serving, &["branch", "unpublished-local"]));
    assert_ok(receive("unpublished-local", false));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        git(&serving, &["rev-parse", "unpublished-local"]).stdout
    );
    assert_ok(git(
        &serving,
        &[
            "fetch",
            "--no-write-fetch-head",
            &format!("file://{}", forge.display()),
            "topic",
        ],
    ));
    let parent = String::from_utf8(git(&forge, &["rev-parse", "topic"]).stdout).unwrap();
    let tree = String::from_utf8(git(&forge, &["rev-parse", "topic^{tree}"]).stdout).unwrap();
    let ahead = String::from_utf8(
        git(
            &serving,
            &[
                "commit-tree",
                tree.trim(),
                "-p",
                parent.trim(),
                "-m",
                "operator ahead",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_ok(git(
        &serving,
        &["update-ref", "refs/heads/forward-ahead", ahead.trim()],
    ));
    assert_ok(git(
        &forge,
        &["update-ref", "refs/heads/forward-ahead", parent.trim()],
    ));
    assert_ok(receive("forward-ahead", false));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        ahead.as_bytes()
    );
    // An ahead commit with a promised blob unavailable upstream must not
    // replace the already-complete upstream graph.
    let missing_tree_input = root.join("missing-blob-tree");
    fs::write(
        &missing_tree_input,
        format!("100644 blob {}\tmissing\n", "1".repeat(40)),
    )
    .unwrap();
    let missing_tree = isolated_command("git", &serving, &root)
        .args(["mktree", "--missing"])
        .stdin(fs::File::open(&missing_tree_input).unwrap())
        .output()
        .unwrap();
    assert!(missing_tree.status.success());
    let missing_tree = String::from_utf8(missing_tree.stdout).unwrap();
    let incomplete = git(
        &serving,
        &[
            "commit-tree",
            missing_tree.trim(),
            "-p",
            parent.trim(),
            "-m",
            "incomplete ahead",
        ],
    );
    assert!(incomplete.status.success());
    let incomplete = String::from_utf8(incomplete.stdout).unwrap();
    assert_ok(git(
        &serving,
        &[
            "update-ref",
            "refs/heads/incomplete-ahead",
            incomplete.trim(),
        ],
    ));
    assert_ok(git(
        &forge,
        &["update-ref", "refs/heads/incomplete-ahead", parent.trim()],
    ));
    let received = receive("incomplete-ahead", false);
    assert!(String::from_utf8_lossy(&received.stderr).contains("operator branch is incomplete"));
    assert_ok(received);
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        parent.as_bytes()
    );
    assert_eq!(
        git(&serving, &["rev-parse", "incomplete-ahead"]).stdout,
        incomplete.as_bytes()
    );
    // Receive refreshes the publication origin, regardless of canonical upstream.
    fs::write(home.join(".gitconfig"), &policy).unwrap();
    assert_ok(git(
        &root,
        &[
            "clone",
            "--bare",
            "--no-local",
            "-q",
            forge.to_str().unwrap(),
            fork.to_str().unwrap(),
        ],
    ));
    let fork_parent = String::from_utf8(git(&fork, &["rev-parse", "HEAD"]).stdout).unwrap();
    let fork_tree = String::from_utf8(git(&fork, &["rev-parse", "HEAD^{tree}"]).stdout).unwrap();
    let first_fork = String::from_utf8(
        git(
            &fork,
            &[
                "commit-tree",
                fork_tree.trim(),
                "-p",
                fork_parent.trim(),
                "-m",
                "first fork commit",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_ok(git(
        &fork,
        &["update-ref", "refs/heads/fork-only", first_fork.trim()],
    ));
    assert_ok(git(
        &serving,
        &["remote", "add", "upstream", "git@github.com:test/fixture"],
    ));
    assert_ok(git(
        &serving,
        &["remote", "set-url", "origin", "git@github.com:test/fork"],
    ));
    assert_ok(git(&forge, &["branch", "canonical-only", "topic"]));
    assert!(!receive("canonical-only", false).status.success());
    assert_ok(receive("fork-only", false));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        first_fork.as_bytes()
    );
    assert_ok(git(
        &serving,
        &[
            "fetch",
            "--no-write-fetch-head",
            &format!("file://{}", fork.display()),
            "fork-only",
        ],
    ));
    assert_ok(git(
        &serving,
        &["update-ref", "refs/heads/fork-only", first_fork.trim()],
    ));
    let second_fork = String::from_utf8(
        git(
            &fork,
            &[
                "commit-tree",
                fork_tree.trim(),
                "-p",
                first_fork.trim(),
                "-m",
                "new fork commit",
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_ok(git(
        &fork,
        &["update-ref", "refs/heads/fork-only", second_fork.trim()],
    ));
    assert_ok(receive("fork-only", false));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        second_fork.as_bytes()
    );
    assert_eq!(
        git(&serving, &["rev-parse", "fork-only"]).stdout,
        first_fork.as_bytes()
    );
    assert_ok(git(
        &serving,
        &["config", "branch.fork-only.remote", "upstream"],
    ));
    assert_ok(git(
        &serving,
        &["config", "branch.fork-only.merge", "refs/heads/topic"],
    ));
    assert_ok(receive("fork-only", false));
    assert_eq!(
        git(&client, &["rev-parse", "FETCH_HEAD"]).stdout,
        second_fork.as_bytes()
    );
    assert_ok(git(
        &serving,
        &["config", "--unset", "branch.fork-only.remote"],
    ));
    let incomplete_commit = root.join("incomplete-commit");
    fs::write(&incomplete_commit, format!("tree {}\nparent {}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nmissing promised parent\n", fork_tree.trim(), "0".repeat(39) + "1")).unwrap();
    let incomplete = String::from_utf8(
        git(
            &serving,
            &[
                "hash-object",
                "-t",
                "commit",
                "-w",
                incomplete_commit.to_str().unwrap(),
            ],
        )
        .stdout,
    )
    .unwrap();
    assert_ok(git(
        &serving,
        &["update-ref", "refs/heads/fork-only", incomplete.trim()],
    ));
    assert_ok(receive("fork-only", false));
    assert_eq!(
        git(&client, &["rev-parse", "FETCH_HEAD"]).stdout,
        second_fork.as_bytes()
    );
    // No origin needs no wrapped-key unlock, even with another remote configured.
    fs::write(home.join(".gitconfig"), &policy).unwrap();
    fs::rename(
        data.join("publication.wrapped"),
        data.join("unused.wrapped"),
    )
    .unwrap();
    assert_ok(git(&serving, &["remote", "remove", "origin"]));
    assert_ok(git(&serving, &["remote", "remove", "unrelated"]));
    assert_ok(git(&serving, &["branch", "operator-only"]));
    assert_ok(git(
        &serving,
        &["config", "remote.phantom.promisor", "true"],
    ));
    assert_ok(receive("operator-only", false));
    assert_eq!(
        git(&client, &["rev-parse", "operator-only"]).stdout,
        git(&serving, &["rev-parse", "HEAD"]).stdout
    );
    let local_forge = home.join("local-forge.git");
    assert_ok(git(
        &home,
        &[
            "clone",
            "--bare",
            "--no-local",
            "-q",
            forge.to_str().unwrap(),
            local_forge.to_str().unwrap(),
        ],
    ));
    assert_ok(git(&local_forge, &["branch", "file-upstream-only"]));
    assert_ok(git(
        &serving,
        &["remote", "add", "origin", local_forge.to_str().unwrap()],
    ));
    assert_ok(git(
        &serving,
        &["config", "remote.upstream.promisor", "true"],
    ));
    assert_ok(receive("file-upstream-only", false));
    assert_eq!(
        git(&client, &["rev-parse", "file-upstream-only"]).stdout,
        git(&local_forge, &["rev-parse", "HEAD"]).stdout
    );
    // An ignored SSH upstream must not require a key when origin is local.
    assert_ok(git(
        &serving,
        &["config", "--remove-section", "remote.upstream"],
    ));
    assert_ok(git(
        &serving,
        &["remote", "add", "upstream", "git@github.com:test/fork"],
    ));
    assert_ok(receive("file-upstream-only", false));
    assert!(
        !upload_environment_error.exists(),
        "raw upload retained credential routing"
    );
}

#[test]
fn receive_reuses_operator_objects_without_a_porter_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let forge = root.join("forge");
    let serving = root.join("serving");
    let client = root.join("client");
    let bin = root.join("bin");
    for path in [&forge, &client, &bin] {
        fs::create_dir_all(path).unwrap();
    }
    let git = |path: &Path, args: &[&str]| {
        isolated_command("git", path, &root)
            .args(args)
            .output()
            .unwrap()
    };
    assert_ok(git(&forge, &["init", "-q", "-b", "main"]));
    for i in 0..30_000 {
        fs::write(
            forge.join(format!("file-{i:05}")),
            format!("distinct fixture blob {i}\n"),
        )
        .unwrap();
    }
    assert_ok(git(&forge, &["add", "."]));
    assert_ok(git(&forge, &["commit", "-qm", "large graph"]));
    let listing = git(
        &forge,
        &["rev-list", "--objects", "--no-object-names", "main"],
    );
    assert!(listing.stdout.len() > 1024 * 1024);
    let main = git(&forge, &["rev-parse", "main"]).stdout;
    assert_ok(git(&forge, &["branch", "a/refs/heads/main"]));
    assert_ok(git(&forge, &["config", "uploadpack.allowFilter", "true"]));
    assert_ok(git(
        &root,
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            "--no-checkout",
            &format!("file://{}", forge.display()),
            serving.to_str().unwrap(),
        ],
    ));
    assert_ok(git(
        &serving,
        &["remote", "set-url", "origin", "git@fixture.invalid:repo"],
    ));
    let packets = root.join("packets");
    let upstream = root.join("upstream-ssh");
    fs::write(
        &upstream,
        format!(
            "#!/bin/sh\nGIT_TRACE_PACKET={} exec git-upload-pack {}\n",
            quote(&packets),
            quote(&forge)
        ),
    )
    .unwrap();
    fs::set_permissions(&upstream, fs::Permissions::from_mode(0o700)).unwrap();
    assert_ok(git(
        &serving,
        &["config", "core.sshCommand", upstream.to_str().unwrap()],
    ));
    assert_ok(git(&serving, &["config", "ssh.variant", "ssh"]));
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), bin.join("git-porter")).unwrap();
    let incoming = root.join("incoming");
    fs::write(&incoming, "#!/bin/sh\nfor arg do remote=$arg; done\nunset GIT_SSH_COMMAND GIT_SSH GIT_SSH_VARIANT\nexec /bin/sh -c \"$remote\"\n").unwrap();
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let remote_login = fs::read_to_string(&incoming).unwrap().replacen(
        "\nexec ",
        &format!("\nexport PATH={}\nexec ", quote(Path::new(&path))),
        1,
    );
    fs::write(&incoming, remote_login).unwrap();
    assert_ok(git(&client, &["init", "-q", "-b", "main"]));
    let receive = |repository: &Path, branch: &str| {
        isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root)
            .env("PATH", &path)
            .env("GIT_SSH_COMMAND", &incoming)
            .env("GIT_SSH_VARIANT", "ssh")
            .args([
                "--switch",
                "--branch",
                branch,
                &format!("operator:{}", repository.display()),
            ])
            .output()
            .unwrap()
    };
    assert_ok(receive(&serving, "main"));
    assert_eq!(git(&client, &["rev-parse", "main"]).stdout, main);
    let cache_root = root.join("XDG_CACHE_HOME/git-porter/read-objects");
    assert!(!cache_root.exists());
    let pack_bytes = || {
        fs::read_dir(serving.join(".git/objects/pack"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|e| e == "pack"))
            .map(|path| fs::metadata(path).unwrap().len())
            .sum::<u64>()
    };
    let base_size = pack_bytes();
    assert!(base_size > 0);
    for name in ["topic1", "topic2"] {
        assert_ok(git(&forge, &["switch", "-c", name, "main"]));
        fs::write(forge.join("file-00000"), format!("change for {name}\n")).unwrap();
        assert_ok(git(&forge, &["commit", "-qam", name]));
        fs::write(&packets, "").unwrap();
        assert_ok(receive(&serving, name));
        assert_eq!(
            git(&client, &["rev-parse", "HEAD"]).stdout,
            git(&forge, &["rev-parse", name]).stdout
        );
        assert!(
            fs::read_to_string(&packets).unwrap().contains("have "),
            "new branches must negotiate using cached history"
        );
    }
    assert!(
        pack_bytes() < base_size * 3 / 2,
        "new branches duplicated full-history packs"
    );
    // Tracking updates must not follow an unexpected symbolic ref into a
    // checked-out branch or execute source-configured reference/upload hooks.
    let hooks = root.join("operator-hooks");
    let hook_used = root.join("operator-hook-used");
    fs::create_dir(&hooks).unwrap();
    fs::write(
        hooks.join("reference-transaction"),
        format!("#!/bin/sh\n: > {}\nexit 1\n", quote(&hook_used)),
    )
    .unwrap();
    fs::set_permissions(
        hooks.join("reference-transaction"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_ok(git(
        &serving,
        &[
            "symbolic-ref",
            "refs/remotes/origin/topic1",
            "refs/heads/main",
        ],
    ));
    assert_ok(git(
        &serving,
        &["config", "core.hooksPath", hooks.to_str().unwrap()],
    ));
    assert_ok(git(
        &serving,
        &["config", "uploadpack.packObjectsHook", "exit 99"],
    ));
    let operator_config = fs::read(serving.join(".git/config")).unwrap();
    assert_ok(receive(&serving, "topic1"));
    assert!(!hook_used.exists());
    assert!(
        !git(
            &serving,
            &["symbolic-ref", "-q", "refs/remotes/origin/topic1"]
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(serving.join(".git/config")).unwrap(),
        operator_config
    );
    assert_eq!(git(&serving, &["rev-parse", "HEAD"]).stdout, main);
    assert_ok(git(&serving, &["config", "--unset", "core.hooksPath"]));
    assert_ok(git(
        &serving,
        &["config", "--unset", "uploadpack.packObjectsHook"],
    ));
    assert!(!cache_root.exists());
    assert_eq!(
        git(&serving, &["rev-parse", "refs/remotes/origin/topic2"]).stdout,
        git(&forge, &["rev-parse", "topic2"]).stdout
    );
    assert_eq!(git(&serving, &["rev-parse", "HEAD"]).stdout, main);
    use std::io::{Read, Write};
    let want = format!("want {}\n", std::str::from_utf8(&main).unwrap().trim());
    // HEAD has a unique promised blob outside both topics. Receiving topic1
    // completes only its history; topic2 must reuse that sibling tracking tip.
    assert_ok(git(&forge, &["switch", "main"]));
    fs::write(forge.join("main-only"), "not reachable from the topics\n").unwrap();
    assert_ok(git(&forge, &["add", "main-only"]));
    assert_ok(git(&forge, &["commit", "-qm", "main-only history"]));
    let partial = root.join("incomplete-head");
    assert_ok(git(
        &root,
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            "--no-checkout",
            &format!("file://{}", forge.display()),
            partial.to_str().unwrap(),
        ],
    ));
    assert_ok(git(
        &partial,
        &["remote", "set-url", "origin", "git@fixture.invalid:repo"],
    ));
    assert_ok(git(
        &partial,
        &["config", "core.sshCommand", upstream.to_str().unwrap()],
    ));
    assert_ok(git(&partial, &["config", "ssh.variant", "ssh"]));
    assert_ok(receive(&partial, "topic1"));
    let complete = |reference: &str| {
        isolated_command("git", &partial, &root)
            .env("GIT_NO_LAZY_FETCH", "1")
            .args([
                "rev-list",
                "--objects",
                "--quiet",
                "--missing=error",
                reference,
            ])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(complete("refs/remotes/origin/topic1"));
    assert!(!complete("HEAD"));
    assert!(!complete("refs/remotes/origin/topic2"));
    fs::write(&packets, "").unwrap();
    assert_ok(receive(&partial, "topic2"));
    assert!(
        fs::read_to_string(&packets).unwrap().contains("have "),
        "receive ignored a complete sibling origin-tracking branch"
    );
    assert!(complete("refs/remotes/origin/topic2"));
    let fork = root.join("native-fork.git");
    assert_ok(git(
        &root,
        &[
            "clone",
            "--bare",
            "--no-local",
            "-q",
            forge.to_str().unwrap(),
            fork.to_str().unwrap(),
        ],
    ));
    assert_ok(git(&fork, &["branch", "native-fork-only"]));
    assert_ok(git(
        &serving,
        &["remote", "add", "upstream", forge.to_str().unwrap()],
    ));
    assert_ok(git(
        &serving,
        &["remote", "set-url", "origin", fork.to_str().unwrap()],
    ));
    assert_ok(git(&forge, &["branch", "native-canonical-only", "main"]));
    assert!(!receive(&serving, "native-canonical-only").status.success());
    assert_ok(git(
        &serving,
        &["config", "branch.native-fork-only.remote", "upstream"],
    ));
    assert_ok(git(
        &serving,
        &["config", "branch.native-fork-only.merge", "refs/heads/main"],
    ));
    assert_ok(receive(&serving, "native-fork-only"));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        git(&fork, &["rev-parse", "native-fork-only"]).stdout
    );
    let standalone = root.join("standalone");
    assert_ok(git(
        &root,
        &[
            "clone",
            "-q",
            "--no-local",
            forge.to_str().unwrap(),
            standalone.to_str().unwrap(),
        ],
    ));
    assert_ok(git(
        &standalone,
        &[
            "update-ref",
            "refs/heads/main",
            std::str::from_utf8(&main).unwrap().trim(),
        ],
    ));
    assert_ok(git(&standalone, &["remote", "remove", "origin"]));
    fs::write(
        root.join(".gitconfig"),
        "[remote \"origin\"]\npromisor = true\npartialclonefilter = blob:none\n",
    )
    .unwrap();
    let wrapper = fs::read_to_string(&incoming).unwrap().replace(
        "unset GIT_SSH_COMMAND GIT_SSH GIT_SSH_VARIANT",
        "unset GIT_SSH_COMMAND GIT_SSH GIT_SSH_VARIANT GIT_CONFIG_GLOBAL",
    );
    fs::write(&incoming, wrapper).unwrap();
    // Complete local history is served from the operator store. Standard Git
    // collection preserves history referenced by the operator branch.
    let mut pinned_read = isolated_command(env!("CARGO_BIN_EXE_git-porter"), &root, &root)
        .env("PATH", &path)
        .args([
            "internal:read",
            standalone.to_str().unwrap(),
            "refs/heads/main",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut advertised = std::io::BufReader::new(pinned_read.stdout.take().unwrap());
    loop {
        let mut header = [0; 4];
        advertised.read_exact(&mut header).unwrap();
        let size = usize::from_str_radix(std::str::from_utf8(&header).unwrap(), 16).unwrap();
        if size == 0 {
            break;
        }
        let mut row = vec![0; size - 4];
        advertised.read_exact(&mut row).unwrap();
    }
    assert_ok(git(&standalone, &["gc", "--prune=now"]));
    let mut input = pinned_read.stdin.take().unwrap();
    writeln!(input, "{:04x}{want}00000009done", want.len() + 4).unwrap();
    drop(input);
    let mut pack = Vec::new();
    advertised.read_to_end(&mut pack).unwrap();
    drop(advertised);
    let result = pinned_read.wait_with_output().unwrap();
    assert_ok(result);
    let offset = pack
        .windows(4)
        .position(|bytes| bytes == b"PACK")
        .expect("missing pack");
    let pack_path = root.join("pinned-transfer.pack");
    fs::write(&pack_path, &pack[offset..]).unwrap();
    let validation = root.join("validate-pinned.git");
    assert_ok(git(
        &root,
        &["init", "--bare", "-q", validation.to_str().unwrap()],
    ));
    assert_ok(
        isolated_command("git", &validation, &root)
            .args(["index-pack", "--strict", "--stdin"])
            .stdin(fs::File::open(pack_path).unwrap())
            .output()
            .unwrap(),
    );
    assert_ok(git(
        &validation,
        &[
            "update-ref",
            "refs/heads/main",
            std::str::from_utf8(&main).unwrap().trim(),
        ],
    ));
    assert_ok(git(&validation, &["fsck", "--full"]));
    assert_ok(receive(&standalone, "main"));
    assert_eq!(git(&client, &["rev-parse", "HEAD"]).stdout, main);
    assert_ok(git(
        &standalone,
        &["remote", "add", "origin", forge.to_str().unwrap()],
    ));
    assert_ok(receive(&standalone, "topic1"));
    let plain = standalone.join("plain/sub");
    fs::create_dir_all(&plain).unwrap();
    let refused = isolated_command(env!("CARGO_BIN_EXE_git-porter"), &root, &root)
        .env("PATH", &path)
        .args(["internal:read", plain.to_str().unwrap(), "refs/heads/main"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    let mut rows = String::from_utf8(
        git(
            &standalone,
            &["for-each-ref", "--format=%(objectname) %(refname)"],
        )
        .stdout,
    )
    .unwrap()
    .lines()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let oid = std::str::from_utf8(&main).unwrap().trim();
    for index in 0..20_000 {
        rows.push(format!("{oid} refs/remotes/r{index:05}/main"));
    }
    rows.sort_by(|a, b| {
        a.split_once(' ')
            .unwrap()
            .1
            .cmp(b.split_once(' ').unwrap().1)
    });
    fs::write(
        standalone.join(".git/packed-refs"),
        format!(
            "# pack-refs with: peeled fully-peeled sorted\n{}\n",
            rows.join("\n")
        ),
    )
    .unwrap();
    assert!(
        git(
            &root,
            &["ls-remote", "--refs", standalone.to_str().unwrap(), "main"]
        )
        .stdout
        .len()
            > 1024 * 1024
    );
    let git_shell = git_porter::server::config::executable("git-shell").unwrap();
    let shell_ssh = root.join("git-shell-ssh");
    fs::write(&shell_ssh, format!("#!/bin/sh\nfor arg do remote=$arg; done\nunset GIT_SSH_COMMAND GIT_SSH GIT_SSH_VARIANT\nexec {} -c \"$remote\"\n", quote(&git_shell))).unwrap();
    fs::set_permissions(&shell_ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let shell_receive = |local: bool| {
        let mut command = isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root);
        command
            .env("PATH", &path)
            .env("GIT_SSH_COMMAND", &shell_ssh)
            .env("GIT_SSH_VARIANT", "ssh");
        if local {
            command.arg("--local-only");
        }
        command
            .args([
                "--switch",
                "--branch",
                "main",
                &format!("operator:{}", standalone.display()),
            ])
            .output()
            .unwrap()
    };
    let unsupported = shell_receive(false);
    assert!(!unsupported.status.success());
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("--local-only"));
    assert_ok(shell_receive(true));
    assert_eq!(git(&client, &["rev-parse", "HEAD"]).stdout, main);
}

#[test]
fn native_receive_accepts_legacy_history_and_hydrates_operator_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let forge = root.join("forge.git");
    let serving = root.join("serving.git");
    let partial = root.join("partial.git");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let fetches = root.join("snapshot-fetches");
    let advertisements = root.join("snapshot-advertisements");
    let actual_git = git_porter::server::config::executable("git").unwrap();
    fs::write(bin.join("git"), format!("#!/bin/sh\nfor arg do case \"$arg\" in fetch) echo fetch >> {} ;; ls-remote) echo advertisement >> {} ;; esac; done\nexec {} \"$@\"\n", quote(&fetches), quote(&advertisements), quote(&actual_git))).unwrap();
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let git = |path: &Path, args: &[&str]| {
        isolated_command("git", path, &root)
            .args(args)
            .output()
            .unwrap()
    };
    assert_ok(git(
        &root,
        &[
            "init",
            "--bare",
            "-q",
            "-b",
            "main",
            forge.to_str().unwrap(),
        ],
    ));
    let write_object = |repo: &Path, kind: &str, bytes: &[u8]| {
        let input = root.join("object-input");
        fs::write(&input, bytes).unwrap();
        let result = isolated_command("git", repo, &root)
            .args(["hash-object", "--literally", "-w", "-t", kind, "--stdin"])
            .stdin(fs::File::open(input).unwrap())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap().trim().to_owned()
    };
    let blob = write_object(&forge, "blob", b"historical blob\n");
    let mut tree = b"0100644 legacy\0".to_vec();
    for pair in blob.as_bytes().chunks_exact(2) {
        tree.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    let tree = write_object(&forge, "tree", &tree);
    let commit = write_object(&forge, "commit", format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nlegacy filemode\n").as_bytes());
    assert_ok(git(&forge, &["update-ref", "refs/heads/main", &commit]));
    assert_ok(git(
        &root,
        &[
            "clone",
            "--bare",
            "--no-local",
            "-q",
            forge.to_str().unwrap(),
            serving.to_str().unwrap(),
        ],
    ));
    let read = |repo: &Path, branch: &str, tip: &str| {
        let want = format!("want {tip}\n");
        let input = root.join("read-input");
        fs::write(
            &input,
            format!("{:04x}{want}00000009done\n", want.len() + 4),
        )
        .unwrap();
        let result = isolated_command(env!("CARGO_BIN_EXE_git-porter"), &root, &root)
            .env("PATH", &path)
            .args([
                "internal:read",
                repo.to_str().unwrap(),
                &format!("refs/heads/{branch}"),
            ])
            .stdin(fs::File::open(input).unwrap())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "read {branch} from {}: {}",
            repo.display(),
            String::from_utf8_lossy(&result.stderr)
        );
        let offset = result
            .stdout
            .windows(4)
            .position(|bytes| bytes == b"PACK")
            .expect("missing pack");
        let pack = root.join("read.pack");
        fs::write(&pack, &result.stdout[offset..]).unwrap();
        let validation = tempfile::tempdir_in(&root).unwrap();
        assert_ok(git(
            &root,
            &["init", "--bare", "-q", validation.path().to_str().unwrap()],
        ));
        assert_ok(
            isolated_command("git", validation.path(), &root)
                .args(["index-pack", "--stdin"])
                .stdin(fs::File::open(pack).unwrap())
                .output()
                .unwrap(),
        );
        assert_ok(git(validation.path(), &["rev-list", "--objects", tip]));
    };
    // The wire envelope is permissive; actual Git grammar must still reject an
    // invalid branch before attempting origin discovery or object transfer.
    let invalid = isolated_command(env!("CARGO_BIN_EXE_git-porter"), &root, &root)
        .env("PATH", &path)
        .args([
            "internal:read",
            serving.to_str().unwrap(),
            "refs/heads/topic..bad",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid receive branch"));
    assert!(!fetches.exists());
    assert!(!advertisements.exists());
    // A normal clone/fetch accepts this tree; borrowing its objects must too.
    read(&serving, "main", &commit);
    let ahead = write_object(&serving, "commit", format!("tree {tree}\nparent {commit}\nauthor Fixture <fixture@example.invalid> 2 +00001\ncommitter Fixture <fixture@example.invalid> 2 +00001\n\nlegacy timezone\n").as_bytes());
    assert_ok(git(&serving, &["update-ref", "refs/heads/ahead", &ahead]));
    read(&serving, "ahead", &ahead);
    // No origin must import the local graph directly, without a self-fetch.
    let fetch_before = fs::read(&fetches).unwrap();
    let advertisement_before = fs::read(&advertisements).unwrap();
    assert_ok(git(&serving, &["remote", "remove", "origin"]));
    read(&serving, "main", &commit);
    read(&serving, "ahead", &ahead);
    assert_eq!(fs::read(&fetches).unwrap(), fetch_before);
    assert_eq!(fs::read(&advertisements).unwrap(), advertisement_before);
    // A shallow boundary must not make an incomplete no-origin graph appear
    // complete, or suggest retrying an operation that cannot recover its parents.
    let shallow = root.join("shallow-native.git");
    assert_ok(git(
        &root,
        &[
            "clone",
            "--bare",
            "-q",
            "--depth=1",
            "--branch",
            "ahead",
            &format!("file://{}", serving.display()),
            shallow.to_str().unwrap(),
        ],
    ));
    assert_ok(git(&shallow, &["remote", "remove", "origin"]));
    let boundary = fs::read(shallow.join("shallow")).unwrap();
    let unavailable = isolated_command(env!("CARGO_BIN_EXE_git-porter"), &root, &root)
        .env("PATH", &path)
        .args([
            "internal:read",
            shallow.to_str().unwrap(),
            "refs/heads/ahead",
        ])
        .output()
        .unwrap();
    assert!(!unavailable.status.success());
    assert!(
        unavailable.stdout.is_empty(),
        "incomplete history was advertised"
    );
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("incomplete and has no origin"));
    assert!(!String::from_utf8_lossy(&unavailable.stderr).contains("retry receive"));
    assert_eq!(fs::read(shallow.join("shallow")).unwrap(), boundary);
    assert_eq!(fs::read(&fetches).unwrap(), fetch_before);
    assert_eq!(fs::read(&advertisements).unwrap(), advertisement_before);

    // The requested local ref points to a promised commit absent from the
    // operator store. Only the approved explicit origin route may fetch it.
    assert_ok(git(
        &root,
        &[
            "init",
            "--bare",
            "-q",
            "-b",
            "main",
            partial.to_str().unwrap(),
        ],
    ));
    assert_ok(git(
        &partial,
        &["remote", "add", "origin", forge.to_str().unwrap()],
    ));
    assert_ok(git(&partial, &["config", "remote.origin.promisor", "true"]));
    assert_ok(git(
        &partial,
        &["config", "remote.origin.partialclonefilter", "blob:none"],
    ));
    fs::write(partial.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    let object_counts = || git(&partial, &["count-objects", "-v"]).stdout;
    let before = object_counts();
    read(&partial, "main", &commit);
    assert_ne!(
        object_counts(),
        before,
        "explicit origin fetch must hydrate operator objects"
    );
    // More than one old argv batch of missing blobs must use one connection.
    let mut import = String::new();
    for i in 1..=520 {
        let data = format!("promised blob {i}\n");
        import.push_str(&format!("blob\nmark :{i}\ndata {}\n{data}", data.len()));
    }
    import.push_str("commit refs/heads/fixture\ncommitter Fixture <fixture@example.invalid> 3 +0000\ndata 8\nfixture\n");
    for i in 1..=520 {
        import.push_str(&format!("M 100644 :{i} file-{i}\n"));
    }
    import.push('\n');
    let input = root.join("fast-import-input");
    fs::write(&input, import).unwrap();
    assert_ok(
        isolated_command("git", &forge, &root)
            .args(["fast-import", "--quiet"])
            .stdin(fs::File::open(input).unwrap())
            .output()
            .unwrap(),
    );
    let tip = String::from_utf8(git(&forge, &["rev-parse", "fixture"]).stdout).unwrap();
    let tree_bytes = git(&forge, &["cat-file", "tree", "fixture^{tree}"]).stdout;
    write_object(&partial, "tree", &tree_bytes);
    let commit_bytes = git(&forge, &["cat-file", "commit", "fixture"]).stdout;
    write_object(&partial, "commit", &commit_bytes);
    assert_ok(git(
        &partial,
        &["update-ref", "refs/heads/unpublished", tip.trim()],
    ));
    assert_ok(git(&forge, &["update-ref", "-d", "refs/heads/fixture"]));
    assert_ok(git(
        &forge,
        &["config", "uploadpack.allowAnySHA1InWant", "true"],
    ));
    let count = || fs::read_to_string(&fetches).unwrap().lines().count();
    let previous = count();
    let prepared = object_counts();
    read(&partial, "unpublished", tip.trim());
    assert_eq!(
        count() - previous,
        1,
        "missing objects opened multiple upstream connections"
    );
    assert_ne!(
        object_counts(),
        prepared,
        "hydration must persist in operator objects"
    );
}

#[test]
fn restricted_receive_accepts_legacy_history_and_ignores_unselected_remote_urls() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let forge = root.join("forge.git");
    let serving = root.join("serving.git");
    let client = root.join("client");
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let transports = root.join("snapshot-transports");
    let actual_git = git_porter::server::config::executable("git").unwrap();
    fs::write(bin.join("git"), format!("#!/bin/sh\nif test -n \"${{GIT_DIR-}}\"; then for arg do case \"$arg\" in fetch|ls-remote) echo transport >> {} ;; esac; done; fi\nexec {} \"$@\"\n", quote(&transports), quote(&actual_git))).unwrap();
    fs::set_permissions(bin.join("git"), fs::Permissions::from_mode(0o700)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let git = |path: &Path, args: &[&str]| {
        isolated_command("git", path, &root)
            .args(args)
            .output()
            .unwrap()
    };
    for repo in [&forge, &serving] {
        assert_ok(git(
            &root,
            &["init", "--bare", "-q", "-b", "main", repo.to_str().unwrap()],
        ));
    }
    assert_ok(git(
        &root,
        &["init", "-q", "-b", "main", client.to_str().unwrap()],
    ));
    let write_object = |kind: &str, bytes: &[u8]| {
        let input = root.join("object-input");
        fs::write(&input, bytes).unwrap();
        let result = isolated_command("git", &forge, &root)
            .args(["hash-object", "--literally", "-w", "-t", kind, "--stdin"])
            .stdin(fs::File::open(input).unwrap())
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        String::from_utf8(result.stdout).unwrap().trim().to_owned()
    };
    let blob = write_object("blob", b"legacy content\n");
    let mut raw_tree = b"0100644 file\0".to_vec();
    for pair in blob.as_bytes().chunks_exact(2) {
        raw_tree.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    let tree = write_object("tree", &raw_tree);
    let commit = write_object("commit", format!("tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nlegacy tree\n").as_bytes());
    assert_ok(git(&forge, &["update-ref", "refs/heads/main", &commit]));
    assert_ok(git(
        &serving,
        &["remote", "add", "origin", forge.to_str().unwrap()],
    ));
    let data = root.join("XDG_DATA_HOME/git-porter");
    fs::create_dir_all(data.join("transport")).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), data.join("transport/ssh"))
        .unwrap();
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    fs::write(
        root.join(".gitconfig"),
        format!(
            "[porter]\nsearchRoot = {}\nauthorizedKey = {}\n",
            root.display(),
            key.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let incoming = root.join("restricted-ssh");
    fs::write(&incoming, format!("#!/bin/sh\nfor arg do SSH_ORIGINAL_COMMAND=$arg; done\nexport SSH_ORIGINAL_COMMAND\nexport PATH={}\nunset GIT_SSH_COMMAND GIT_SSH GIT_SSH_VARIANT GIT_NO_LAZY_FETCH\nexec {} internal:serve\n", quote(Path::new(&path)), quote(Path::new(env!("CARGO_BIN_EXE_git-porter"))))).unwrap();
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
    let receive = |repo: &Path, branch: &str| {
        isolated_command(env!("CARGO_BIN_EXE_git-receive"), &client, &root)
            .env("PATH", &path)
            .env("GIT_SSH_COMMAND", &incoming)
            .env("GIT_SSH_VARIANT", "ssh")
            .args([
                "--switch",
                "--branch",
                branch,
                &format!("operator:{}", repo.display()),
            ])
            .output()
            .unwrap()
    };
    // The serving repository is empty: this must fetch the legacy tree into a
    // operator object store through the restricted authenticated fetch path.
    let operator_objects = git(&serving, &["count-objects", "-v"]).stdout;
    assert_ok(receive(&serving, "main"));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        format!("{commit}\n").as_bytes()
    );
    assert_ne!(
        git(&serving, &["count-objects", "-v"]).stdout,
        operator_objects
    );
    assert!(!root.join("XDG_CACHE_HOME/git-porter/read-objects").exists());
    let timezone = write_object("commit", format!("tree {tree}\nparent {commit}\nauthor Fixture <fixture@example.invalid> 2 +00001\ncommitter Fixture <fixture@example.invalid> 2 +00001\n\nlegacy timezone\n").as_bytes());
    assert_ok(git(
        &forge,
        &["update-ref", "refs/heads/timezone", &timezone],
    ));
    assert_ok(receive(&serving, "timezone"));
    assert_eq!(
        git(&client, &["rev-parse", "HEAD"]).stdout,
        format!("{timezone}\n").as_bytes()
    );
    // URL cardinality belongs to selected candidates, not unrelated remotes.
    assert_ok(git(
        &serving,
        &["remote", "add", "unused", forge.to_str().unwrap()],
    ));
    assert_ok(git(
        &serving,
        &[
            "config",
            "--add",
            "remote.unused.url",
            root.join("absent").to_str().unwrap(),
        ],
    ));
    assert_ok(receive(&serving, "main"));
    assert_ok(git(&serving, &["config", "branch.main.remote", "unused"]));
    assert_ok(git(
        &serving,
        &["config", "branch.main.merge", "refs/heads/absent"],
    ));
    assert_ok(receive(&serving, "main"));
    assert_ok(git(
        &serving,
        &[
            "config",
            "--add",
            "remote.origin.url",
            root.join("absent").to_str().unwrap(),
        ],
    ));
    let rejected = receive(&serving, "main");
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("exactly one fetch URL"));
    // No upstream also accepts complete legacy history, without a credential.
    let local = root.join("local.git");
    assert_ok(git(
        &root,
        &[
            "clone",
            "--bare",
            "--no-local",
            "-q",
            forge.to_str().unwrap(),
            local.to_str().unwrap(),
        ],
    ));
    assert_ok(git(&local, &["remote", "remove", "origin"]));
    assert_ok(git(
        &local,
        &["remote", "add", "upstream", forge.to_str().unwrap()],
    ));
    assert_ok(git(&forge, &["branch", "origin-absent-only", "main"]));
    assert!(!receive(&local, "origin-absent-only").status.success());
    let transports_before = fs::read(&transports).unwrap();
    assert!(
        !transports_before.is_empty(),
        "transport spy did not observe the origin fetch"
    );
    assert_ok(receive(&local, "main"));
    assert_ok(receive(&local, "timezone"));
    assert_eq!(fs::read(&transports).unwrap(), transports_before);
    let shallow = root.join("shallow-restricted.git");
    assert_ok(git(
        &root,
        &[
            "clone",
            "--bare",
            "-q",
            "--depth=1",
            "--branch",
            "timezone",
            &format!("file://{}", forge.display()),
            shallow.to_str().unwrap(),
        ],
    ));
    assert_ok(git(&shallow, &["remote", "remove", "origin"]));
    let unavailable = receive(&shallow, "timezone");
    assert!(!unavailable.status.success());
    assert!(String::from_utf8_lossy(&unavailable.stderr).contains("incomplete and has no origin"));
    assert!(!String::from_utf8_lossy(&unavailable.stderr).contains("retry receive"));
    assert_eq!(fs::read(&transports).unwrap(), transports_before);
}
