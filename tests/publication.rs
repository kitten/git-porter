#[path = "support/source_agent.rs"]
mod source_agent;
use git_porter::credentials::wrapping;
use source_agent::Agent;
use std::fs;
#[test]
fn malformed_external_public_metadata_is_rejected_before_derivation() {
    use git_porter::runtime::protocol::{Budget, Kind};
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let repository = root.join("repo");
    let data = root.join(".local/share/git-porter");
    fs::create_dir(&repository).unwrap();
    fs::create_dir_all(&data).unwrap();
    for args in [
        vec!["init", "--bare", "-q"],
        vec![
            "remote",
            "add",
            "origin",
            "git@forge.example:group/repo.git",
        ],
    ] {
        assert!(
            Command::new("git")
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap())
                .env("HOME", &root)
                .current_dir(&repository)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let source =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let source = source.public_key();
    // This outer bundle is valid; no ciphertext decryption is needed to check
    // whether a signature would be requested. No agent is provided to the server.
    let bundle = wrapping::Bundle {
        metadata: wrapping::Metadata::generate(source).unwrap(),
        ciphertext: b"not decrypted in this test".to_vec(),
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
        data.join("publication.source.pub"),
        source.to_openssh().unwrap(),
    )
    .unwrap();
    fs::write(
        data.join("known_hosts"),
        format!("forge.example {}\n", source.to_openssh().unwrap()),
    )
    .unwrap();
    fs::create_dir(data.join("hooks")).unwrap();
    std::os::unix::fs::symlink(
        env!("CARGO_BIN_EXE_git-porter"),
        data.join("hooks/pre-receive"),
    )
    .unwrap();
    let config = root.join(".gitconfig");
    fs::write(&config, format!("[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\nallowedPushPrefix = contributors/\npublishTo = forge.example\n", root.display(), source.to_openssh().unwrap())).unwrap();
    for (public, valid) in [
        ("not a public key".to_owned(), false),
        (source.to_openssh().unwrap(), true),
    ] {
        fs::write(data.join("publication.pub"), public).unwrap();
        let mut input = Vec::new();
        let mut outgoing = Budget::default();
        outgoing
            .write(&mut input, Kind::Hello, b"publish-v5")
            .unwrap();
        outgoing
            .write(
                &mut input,
                Kind::Intent,
                format!(
                    "intent-v2\0receive\0repo\0\0ff\0refs/heads/contributors/test\0{}\0",
                    "1".repeat(40)
                )
                .as_bytes(),
            )
            .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .arg("internal:serve")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &root)
            .env("SSH_ORIGINAL_COMMAND", "git-porter-session-v1")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let output = child.wait_with_output().unwrap();
        let mut bytes = &output.stdout[..];
        let mut incoming = Budget::default();
        assert_eq!(incoming.read(&mut bytes).unwrap().0, Kind::Hello);
        assert_eq!(incoming.read(&mut bytes).unwrap().0, Kind::Resolved);
        if valid {
            assert_eq!(incoming.read(&mut bytes).unwrap().0, Kind::ApprovePublishV1);
        } else {
            let (kind, result) = incoming.read(&mut bytes).unwrap();
            assert_eq!(
                kind,
                Kind::Result,
                "malformed metadata requested derivation"
            );
            let report = git_porter::runtime::push_result::Report::parse(&result).unwrap();
            assert!(!report.receiver_ok);
            assert!(matches!(
                report.forwarded.unwrap().outcome,
                git_porter::runtime::push_result::Outcome::NotAttempted { .. }
            ));
        }
        assert!(!output.status.success());
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .arg("show-ref")
                .output()
                .unwrap()
                .stdout
                .is_empty()
        );
    }
}

#[test]
fn onward_transport_pins_transaction_identity_and_excludes_ambient_authentication() {
    use std::{os::unix::fs::PermissionsExt, process::Command};
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    let private =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let agent = Agent::start(private).unwrap();
    let bin = home.join("bin");
    fs::create_dir(&bin).unwrap();
    // Observe the exact exec boundary; the real OpenSSH suite exercises the wire.
    let ssh = bin.join("ssh");
    fs::write(&ssh,"#!/bin/sh\nprintf '%s\\n' \"agent=$SSH_AUTH_SOCK\" \"gpg=${GPG_AGENT_INFO-unset}\" \"command=${GIT_SSH_COMMAND-unset}\"\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir_all(home.join(".local/share/git-porter")).unwrap();
    let config = home.join(".gitconfig");
    fs::write(
        &config,
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\npublishTo = forge.example\n",
            home.display()
        ),
    )
    .unwrap();
    let transport = home.join("transport");
    fs::create_dir(&transport).unwrap();
    let role = transport.join("ssh");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &role).unwrap();
    let mut command = Command::new(&role);
    for (key, _) in std::env::vars_os().filter(|(k, _)| k.to_string_lossy().starts_with("XDG_")) {
        command.env_remove(key);
    }
    let mut resolved = git_porter::server::config::ServerConfig::read_environment(
        &config,
        &home,
        &home,
        &home.join("cache"),
    )
    .unwrap();
    resolved.ssh = bin.join("ssh");
    let snapshot = resolved.hook_context().encode().unwrap();
    let out = command
        .env("GIT_PORTER_HOOK_CONTEXT", snapshot)
        .env("HOME", &home)
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("SSH_AUTH_SOCK", "/ambient/agent")
        .env("GPG_AGENT_INFO", "ambient-gpg")
        .env("GIT_SSH_COMMAND", "ambient-ssh")
        .env("GIT_PORTER_TRANSACTION_SOCKET", agent.socket())
        .env("GIT_PORTER_TRANSACTION_TRUST", home.join("known_hosts"))
        .env("GIT_PORTER_TRANSACTION_PUBLIC", &agent.public)
        .args(["git@forge.example", "git-receive-pack 'org/repo'"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let args: Vec<_> = text.lines().collect();
    assert_eq!(args[0], format!("agent={}", agent.socket().display()));
    assert!(args.contains(&"gpg=unset") && args.contains(&"command=unset"));
    for pair in [["-F", "/dev/null"], ["-i", agent.public.to_str().unwrap()]] {
        assert!(args.windows(2).any(|v| v == pair));
    }
    for option in [
        "IdentitiesOnly=yes",
        "CertificateFile=none",
        "PreferredAuthentications=publickey",
        "PubkeyAuthentication=yes",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "HostbasedAuthentication=no",
        "ForwardAgent=no",
    ] {
        assert!(args.contains(&option), "{text}");
    }
    assert!(
        !args
            .iter()
            .any(|option| option.starts_with("GSSAPIAuthentication="))
    );
    assert!(args.contains(&format!("IdentityAgent=\"{}\"", agent.socket().display()).as_str()));
    assert!(
        !text.contains("/ambient/")
            && !text.contains("ambient-gpg")
            && !text.contains("ambient-ssh")
    );
    fs::write(
        &config,
        format!(
            "[porter]\nsearchRoot = {}\nsearchStrict = true\npublishTo = forge.example\nskipWrappedKey = true\n",
            home.display()
        ),
    )
    .unwrap();
    let mut resolved = git_porter::server::config::ServerConfig::read_environment(
        &config,
        &home,
        &home,
        &home.join("cache"),
    )
    .unwrap();
    resolved.ssh = bin.join("ssh");
    let snapshot = resolved.hook_context().encode().unwrap();
    let out = command
        .env("GIT_PORTER_HOOK_CONTEXT", snapshot)
        .env("SSH_AUTH_SOCK", agent.socket())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.lines().any(|line| line == "IdentityFile=none"));
    assert!(text.lines().any(|line| line == "IdentitiesOnly=no"));
    assert!(!text.lines().any(|line| line == "-i"));
    for option in [
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "ForwardAgent=no",
        "ConnectTimeout=15",
        "ServerAliveInterval=15",
        "ServerAliveCountMax=3",
    ] {
        assert!(text.lines().any(|line| line == option), "{text}");
    }
}
