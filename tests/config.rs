use git_porter::server::config::ServerConfig;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn policy(extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".gitconfig");
    fs::write(&path, format!("[porter]\n{extra}\n")).unwrap();
    fs::create_dir(dir.path().join("git-porter")).unwrap();
    (dir, path)
}
fn context(path: &std::path::Path, home: &std::path::Path, data: &std::path::Path) -> String {
    ServerConfig::read_environment(path, home, data, &home.join(".cache/git-porter"))
        .unwrap()
        .hook_context()
        .encode()
        .unwrap()
}
#[test]
fn explicit_policy_is_read_only_and_ignores_git_config_injection() {
    let (_dir, path) = policy(
        "destination = sender@example\ndestination = other@example\n[user]\nname = Fixture\n[feature]\nexperimental\n[include]\npath = /missing",
    );
    let xdg = path.parent().unwrap().join("xdg-config");
    fs::create_dir_all(xdg.join("git")).unwrap();
    fs::write(xdg.join("git/config"), "[porter]\nsearchStrict = true\n").unwrap();
    assert!(
        ServerConfig::read_environment(
            &path,
            path.parent().unwrap(),
            path.parent().unwrap(),
            &path.parent().unwrap().join(".cache/git-porter")
        )
        .unwrap()
        .prefixes
        .is_empty()
    );
    let hook = path.parent().unwrap().join("pre-receive");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &hook).unwrap();
    let snapshot = context(&path, path.parent().unwrap(), path.parent().unwrap());
    fs::write(&path, "[porter]\nunknown = true\n").unwrap();
    let output = Command::new(&hook)
        .env("GIT_PORTER_HOOK_CONTEXT", snapshot)
        .env("GIT_CONFIG_GLOBAL", "/missing/injected")
        .env("XDG_CONFIG_HOME", &xdg)
        .env("HOME", path.parent().unwrap())
        .env("XDG_DATA_HOME", path.parent().unwrap())
        .stdin(std::process::Stdio::null())
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "porter.searchRoot")
        .env("GIT_CONFIG_VALUE_0", "/invalid/injected")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn rejects_duplicates_unknown_policy_and_writable_files() {
    for extra in [
        "repositoryRoot = /",
        "[porter]\nunknown = true",
        "allowedPushPrefix = ../",
        "skipWrappedKey = maybe",
        "allowDefaultBranch = maybe",
        "allowDefaultBranch = false\nallowDefaultBranch = true",
        "searchStrict = maybe",
        "searchStrict = false\nsearchStrict = true",
        "skipWrappedKey = false\nskipWrappedKey = true",
        "allowedPushPrefix = refs",
        "legacyForwarding = true",
        "legacyForwarding = inherited",
    ] {
        let (_dir, path) = policy(extra);
        assert!(
            ServerConfig::read_environment(
                &path,
                path.parent().unwrap(),
                path.parent().unwrap(),
                &path.parent().unwrap().join(".cache/git-porter")
            )
            .is_err(),
            "{extra}"
        );
    }
    let (_dir, path) = policy("");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(
        ServerConfig::read_environment(
            &path,
            path.parent().unwrap(),
            path.parent().unwrap(),
            &path.parent().unwrap().join(".cache/git-porter")
        )
        .is_err()
    );
}
#[test]
fn internal_hook_requires_trusted_config_and_default_serve_rejects_publication() {
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (dir, _path) = policy(&format!(
        "allowedPushPrefix = contributors/\nauthorizedKey = {}",
        key.public_key().to_openssh().unwrap()
    ));
    let hook = dir.path().join("pre-receive");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &hook).unwrap();
    assert!(!Command::new(&hook).env_clear().status().unwrap().success());
    let output = Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .env_clear()
        .env("HOME", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("TMPDIR", std::env::temp_dir())
        .arg("internal:serve")
        .env(
            "SSH_ORIGINAL_COMMAND",
            "git-receive-pack --send=ff:refs/heads/contributors/a:123 'repo'",
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("single-quoted repository path"));
}

fn git(directory: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(directory)
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
#[test]
fn real_git_runs_compiled_policy_hook_with_quarantine_and_paths_containing_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let hooks = root.join("managed hooks");
    fs::create_dir(&hooks).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), hooks.join("pre-receive"))
        .unwrap();
    let source = root.join("source");
    let destination = root.join("destination.git");
    fs::create_dir(&source).unwrap();
    assert!(git(&source, &["init", "-q"]).status.success());
    assert!(
        git(&source, &["commit", "--allow-empty", "-qm", "fixture"])
            .status
            .success()
    );
    assert!(
        git(
            root,
            &["init", "--bare", "-q", destination.to_str().unwrap()]
        )
        .status
        .success()
    );
    assert!(
        git(
            &destination,
            &["config", "core.hooksPath", hooks.to_str().unwrap()]
        )
        .status
        .success()
    );
    fs::create_dir_all(root.join(".local/share/git-porter")).unwrap();
    let config = root.join(".gitconfig");
    fs::write(
        &config,
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\nallowedPushPrefix = contributors/\n",
            root.display()
        ),
    )
    .unwrap();
    let snapshot = context(&config, root, &root.join(".local/share/git-porter"));
    let push = |reference: &str| {
        Command::new("git")
            .current_dir(&source)
            .env("GIT_PORTER_HOOK_CONTEXT", &snapshot)
            .env("HOME", root)
            .env_remove("XDG_DATA_HOME")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args([
                "push",
                destination.to_str().unwrap(),
                &format!("HEAD:{reference}"),
            ])
            .output()
            .unwrap()
    };
    let accepted = push("refs/heads/contributors/test");
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    // A raw forced push cannot bypass receiver ancestry or deletion policy.
    let first = git(&source, &["rev-parse", "HEAD"]).stdout;
    assert!(
        git(&source, &["commit", "--allow-empty", "-qm", "second"])
            .status
            .success()
    );
    assert!(push("refs/heads/contributors/test").status.success());
    assert!(
        git(
            &source,
            &[
                "reset",
                "--hard",
                std::str::from_utf8(&first).unwrap().trim()
            ]
        )
        .status
        .success()
    );
    let rejected = Command::new("git")
        .current_dir(&source)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join(".local/share"))
        .args([
            "push",
            "--force",
            destination.to_str().unwrap(),
            "HEAD:refs/heads/contributors/test",
        ])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("hook context"));
    // The hook must also reject a negotiated ff-mode update despite a malicious sender.
    use std::io::Write;
    let tip = git(&destination, &["rev-parse", "refs/heads/contributors/test"]).stdout;
    let mut hook = Command::new(hooks.join("pre-receive"))
        .current_dir(&destination)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join(".local/share"))
        .env("GIT_PORTER_HOOK_CONTEXT", &snapshot)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        hook.stdin.take().unwrap(),
        "{} {} refs/heads/contributors/test",
        std::str::from_utf8(&tip).unwrap().trim(),
        std::str::from_utf8(&first).unwrap().trim()
    )
    .unwrap();
    let refused = hook.wait_with_output().unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("non-fast-forward"));

    assert!(
        !Command::new("git")
            .current_dir(&source)
            .env("GIT_PORTER_HOOK_CONTEXT", &snapshot)
            .env("HOME", root)
            .args([
                "push",
                destination.to_str().unwrap(),
                ":refs/heads/contributors/test"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(!push("refs/heads/forbidden/test").status.success());
    assert!(!push("refs/tags/tag").status.success());
    assert!(
        git(
            &destination,
            &[
                "symbolic-ref",
                "refs/heads/contributors/symbolic",
                "refs/heads/other"
            ]
        )
        .status
        .success()
    );
    assert!(!push("refs/heads/contributors/symbolic").status.success());
}

#[test]
fn search_roots_are_hints_unless_strict() {
    let (dir, path) = policy("searchStrict = true");
    assert_eq!(
        ServerConfig::read_environment(
            &path,
            path.parent().unwrap(),
            path.parent().unwrap(),
            &path.parent().unwrap().join(".cache/git-porter")
        )
        .unwrap()
        .discovery
        .roots,
        vec![dir.path().canonicalize().unwrap()]
    );
    let sub = dir.path().join("nested");
    fs::create_dir(&sub).unwrap();
    let base = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{base}searchRoot = {}\n", sub.display())).unwrap();
    assert_eq!(
        ServerConfig::read_environment(
            &path,
            path.parent().unwrap(),
            path.parent().unwrap(),
            &path.parent().unwrap().join(".cache/git-porter")
        )
        .unwrap()
        .discovery
        .roots,
        vec![sub.canonicalize().unwrap()]
    );
}

#[test]
fn hook_context_is_required_versioned_and_strict() {
    let (dir, _path) = policy("");
    let role = dir.path().join("pre-receive");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &role).unwrap();
    for value in [None, Some("not json"), Some("{\"version\":99}")] {
        let mut command = Command::new(&role);
        command.env_clear();
        if let Some(value) = value {
            command.env("GIT_PORTER_HOOK_CONTEXT", value);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("hook context"));
    }
    let mut valid =
        serde_json::from_str::<serde_json::Value>(&context(&_path, dir.path(), dir.path()))
            .unwrap();
    for (field, value) in [
        ("git", "/"),
        ("ssh", "/"),
        ("data", "/"),
        ("git", "/invalid:parent/git"),
    ] {
        let mut malformed = valid.clone();
        malformed["config"][field] = value.into();
        let output = Command::new(&role)
            .env_clear()
            .env("GIT_PORTER_HOOK_CONTEXT", malformed.to_string())
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted invalid {field}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
    valid["version"] = 99.into();
    let output = Command::new(&role)
        .env_clear()
        .env("GIT_PORTER_HOOK_CONTEXT", valid.to_string())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported hook context version"));
}

#[test]
fn hook_context_utf8_paths_and_repeated_values_round_trip_exactly() {
    use git_porter::server::config::HookContext;
    if std::env::var_os("PORTER_CONTEXT_ROUND_TRIP_CHILD").is_some() {
        let original = std::env::var("GIT_PORTER_HOOK_CONTEXT").unwrap();
        let restored = HookContext::read().unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&std::env::var("PORTER_CONTEXT_EXPECTED").unwrap()).unwrap();
        assert_eq!(serde_json::to_value(&restored).unwrap(), expected);
        assert_eq!(restored.encode().unwrap(), original);
        return;
    }
    let (dir, path) = policy(
        "allowedPushPrefix = contributors/\nallowedPushPrefix = review/\npublishTo = github.com\npublishTo = gitlab.com",
    );
    let mut snapshot =
        ServerConfig::read_environment(&path, dir.path(), dir.path(), &dir.path().join("cache"))
            .unwrap()
            .hook_context();
    let odd = dir
        .path()
        .join("space newline\n tab\t 'quote' \\\" 雪 % dollar$");
    let c = &mut snapshot.config;
    c.home = odd.join("home");
    c.data = odd.join("data");
    c.git = odd.join("bin/git");
    c.ssh = odd.join("bin/ssh");
    c.discovery.cache = odd.join("cache");
    c.discovery.roots = vec![odd.join("first\nroot"), odd.join("second root 🐈")];
    c.publication.wrapped = odd.join("wrapped");
    c.publication.source = odd.join("source.pub");
    c.publication.public = odd.join("publication.pub");
    c.publication.known_hosts = odd.join("known_hosts");
    snapshot.publication = Some(odd.join("transaction.json"));
    snapshot.reference = Some("refs/heads/contributors/test".into());
    snapshot.sha = Some("1".repeat(40));
    let text = snapshot.encode().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .env_clear()
        .arg("--exact")
        .arg("hook_context_utf8_paths_and_repeated_values_round_trip_exactly")
        .env("PORTER_CONTEXT_ROUND_TRIP_CHILD", "1")
        .env(
            "PORTER_CONTEXT_EXPECTED",
            serde_json::to_string(&snapshot).unwrap(),
        )
        .env("GIT_PORTER_HOOK_CONTEXT", text)
        .env("HOME", dir.path());
    for key in [
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_DIRS",
    ] {
        child.env(key, dir.path().join(key));
    }
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_snapshot_path_rejects_encoding_and_a_real_push() {
    use std::os::unix::ffi::OsStrExt;
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (dir, path) = policy(&format!(
        "allowedPushPrefix = contributors/\nauthorizedKey = {}",
        key.public_key().to_openssh().unwrap()
    ));
    let home = dir.path().canonicalize().unwrap();
    let data = home.join(".local/share/git-porter");
    fs::create_dir_all(&data).unwrap();
    let invalid = home.join(std::ffi::OsStr::from_bytes(b"cache-\xff"));
    let mut snapshot = ServerConfig::read_environment(&path, &home, &data, &home.join("cache"))
        .unwrap()
        .hook_context();
    snapshot.config.discovery.cache = invalid.clone();
    let error = snapshot
        .encode()
        .expect_err("non-UTF-8 must not encode")
        .to_string();
    assert!(error.contains("UTF-8"), "{error}");

    let git = git_porter::server::config::executable("git").unwrap();
    let receiver = home.join("receiver.git");
    let source = home.join("source");
    let run = |args: &[&str]| {
        let output = Command::new(&git)
            .env_clear()
            .env("TMPDIR", std::env::temp_dir())
            .env("HOME", &home)
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&["init", "--bare", "-q", receiver.to_str().unwrap()]);
    run(&["init", "-q", source.to_str().unwrap()]);
    run(&[
        "-C",
        source.to_str().unwrap(),
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "--allow-empty",
        "-qm",
        "fixture",
    ]);
    let ssh = home.join("ssh");
    let porter = env!("CARGO_BIN_EXE_git-porter").replace('\'', "'\\''");
    fs::write(&ssh, format!("#!/bin/sh\nfor arg do SSH_ORIGINAL_COMMAND=$arg; done\nexport SSH_ORIGINAL_COMMAND\nexec '{porter}' internal:serve\n")).unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(&git)
        .env_clear()
        .env("TMPDIR", std::env::temp_dir())
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", &invalid)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_SSH", &ssh)
        .env("GIT_SSH_VARIANT", "ssh")
        .args([
            "-C",
            source.to_str().unwrap(),
            "push",
            &format!("fixture:{}", receiver.display()),
            "HEAD:refs/heads/contributors/test",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostics.contains(&error), "{diagnostics}");
    let refs = Command::new(git)
        .env_clear()
        .env("TMPDIR", std::env::temp_dir())
        .env("HOME", &home)
        .args([
            "--git-dir",
            receiver.to_str().unwrap(),
            "for-each-ref",
            "--format=%(refname)",
        ])
        .output()
        .unwrap();
    assert!(refs.status.success());
    assert!(
        refs.stdout.is_empty(),
        "ref changed despite failed encoding"
    );
    assert!(
        !home.join("cache-\u{fffd}").exists(),
        "created a lossy path"
    );
}

#[test]
fn search_roots_default_to_home_accept_relative_paths_and_never_escape_home() {
    let (dir, path) = policy("");
    let home = dir.path().canonicalize().unwrap();
    fs::create_dir(home.join("work")).unwrap();
    fs::create_dir(home.join("personal")).unwrap();
    let read = || ServerConfig::read_environment(&path, &home, &home, &home.join("cache"));
    fs::write(&path, "[porter]\n").unwrap();
    let default = read().unwrap();
    assert!(!default.discovery.strict);
    assert_eq!(default.discovery.roots, vec![home.clone()]);
    for spelling in [
        "work",
        "./work",
        "~/work",
        "$HOME/work",
        "~//work",
        "$HOME//work",
    ] {
        fs::write(
            &path,
            format!(
                "[porter]\nsearchRoot = {spelling}\nsearchRoot = personal\nsearchStrict = true\n"
            ),
        )
        .unwrap();
        assert_eq!(
            read().unwrap().discovery.roots,
            vec![home.join("work"), home.join("personal")]
        );
    }
    for spelling in [".", "~", "$HOME"] {
        fs::write(
            &path,
            format!("[porter]\nsearchRoot = {spelling}\nsearchStrict = true\n"),
        )
        .unwrap();
        assert_eq!(read().unwrap().discovery.roots, vec![home.clone()]);
    }
    let link = home.join("linked");
    std::os::unix::fs::symlink(home.join("work"), &link).unwrap();
    fs::write(
        &path,
        "[porter]\nsearchRoot = linked\nsearchStrict = true\n",
    )
    .unwrap();
    assert_eq!(read().unwrap().discovery.roots, vec![home.join("work")]);
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), home.join("escape")).unwrap();
    for bad in [
        "searchRoot =",
        "searchRoot = missing",
        "searchRoot = /",
        "searchRoot = escape",
        "repositoryRoot = .",
    ] {
        fs::write(&path, format!("[porter]\n{bad}\n")).unwrap();
        assert!(read().is_err(), "{bad}");
    }
}

#[test]
fn removing_all_receiver_keys_disables_a_stale_forced_command() {
    let (dir, path) = policy("");
    // Home Manager can leave the installed authorized_keys line when receiver
    // settings are removed. With a HOME default, no receiver policy must not
    // become implicit read access to every repository in that home.
    fs::write(path, "[porter]\ndestination = receiver\n").unwrap();
    for request in ["git-upload-pack 'repo.git'", "git-porter-session-v1"] {
        let output = Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("TMPDIR", std::env::temp_dir())
            .env("SSH_ORIGINAL_COMMAND", request)
            .arg("internal:serve")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "keyless receiver advertised Git/protocol bytes"
        );
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostics.contains("receiver SSH setup is incomplete"));
        for speculative_hint in ["porter.", "key:create", "ssh-add"] {
            assert!(!diagnostics.contains(speculative_hint), "{diagnostics}");
        }
    }
}

#[test]
fn key_commands_reject_invalid_policy_and_honor_agent_mode_before_data_exists() {
    for (setting, expected, success) in [
        (
            "unknown = true",
            "receiver setup contains an unsupported setting",
            false,
        ),
        ("skipWrappedKey = true", "No wrapped key is needed", true),
    ] {
        let home = tempfile::tempdir().unwrap();
        fs::write(
            home.path().join(".gitconfig"),
            format!("[porter]\n{setting}\n"),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("XDG_RUNTIME_DIR", home.path().join("run"))
            .env("TMPDIR", std::env::temp_dir())
            .args(["key:create", "--key-import", "/must-not-be-read"])
            .output()
            .unwrap();
        assert_eq!(output.status.success(), success);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{output:?}"
        );
        assert!(!home.path().join("data").exists());
    }
}

#[test]
fn origin_field_cannot_grant_force_to_an_explicit_path() {
    use git_porter::runtime::protocol::{Budget, Kind};
    use std::io::{Cursor, Write};
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let (home, _) = policy(&format!(
        "authorizedKey = {}\nallowedPushPrefix = contributors/",
        key.public_key().to_openssh().unwrap()
    ));
    let repository = home.path().join("repo");
    let repo = git2::Repository::init_bare(&repository).unwrap();
    let signature = git2::Signature::now("Fixture", "fixture@example.invalid").unwrap();
    let tree = repo
        .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
        .unwrap();
    let before = repo
        .commit(
            Some("refs/heads/contributors/test"),
            &signature,
            &signature,
            "before",
            &tree,
            &[],
        )
        .unwrap();
    let hooks = home.path().join("git-porter/hooks");
    fs::create_dir(&hooks).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), hooks.join("pre-receive"))
        .unwrap();
    let mut frames = Budget::default();
    let mut bytes = Vec::new();
    frames.write(&mut bytes, Kind::Hello, b"local-v1").unwrap();
    frames
        .write(&mut bytes, Kind::Intent, b"receive\0repo\0force-v1")
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("XDG_RUNTIME_DIR", home.path().join("run"))
        .env("TMPDIR", std::env::temp_dir())
        .env("SSH_ORIGINAL_COMMAND", "git-porter-session-v1")
        .arg("internal:serve")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    // Refused before repository resolution/advertisement, let alone receipt or rewriting.
    let mut stdout = Cursor::new(output.stdout);
    assert_eq!(
        Budget::default().expect(&mut stdout, Kind::Hello).unwrap(),
        b"local-v1"
    );
    assert_eq!(stdout.position(), stdout.get_ref().len() as u64);
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported remote transport"));
    assert_eq!(
        repo.find_reference("refs/heads/contributors/test")
            .unwrap()
            .target(),
        Some(before)
    );
}

#[test]
fn forced_route_marker_never_evaluates_the_native_shell_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().canonicalize().unwrap();
    let data = home.join(".local/share/git-porter");
    fs::create_dir_all(&data).unwrap();
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    fs::write(
        home.join(".gitconfig"),
        format!(
            "[porter]\nauthorizedKey = {}\n",
            key.public_key().to_openssh().unwrap()
        ),
    )
    .unwrap();
    let marker = home.join("must-not-execute");
    let output = Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env("XDG_STATE_HOME", home.join(".local/state"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env(
            "SSH_ORIGINAL_COMMAND",
            format!(
                "printf 'git-porter-route-v1:native\\n'; cd \"$HOME\" && exec touch '{}'",
                marker.display()
            ),
        )
        .arg("internal:serve")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.starts_with(b"git-porter-route-v1:porter\n"));
    assert!(!marker.exists());
}
