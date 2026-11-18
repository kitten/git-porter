#[path = "support/source_agent.rs"]
mod source_agent;
use source_agent::Agent;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};
fn setup(home: &Path, key: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_git-porter"));
    c.env("HOME", home)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("XDG_DATA_DIRS")
        .env_remove("XDG_CONFIG_DIRS")
        .env_remove("XDG_DATA_HOME")
        .env_remove("SSH_AUTH_SOCK")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["setup"]);
    let data = home.join(".local/share/git-porter");
    fs::create_dir_all(&data).unwrap();
    fs::copy(key, data.join("publication.source.pub")).unwrap();
    fs::write(home.join(".gitconfig"),format!("[porter]\nsearchRoot = {}\nsearchStrict = true\nauthorizedKey = {}\nallowedPushPrefix = contributors/\n",home.join("projects").display(),fs::read_to_string(key).unwrap().trim())).unwrap();
    c
}
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().canonicalize().unwrap();
    fs::create_dir(home.join("projects")).unwrap();
    let key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let public = home.join("source.pub");
    fs::write(&public, key.public_key().to_openssh().unwrap()).unwrap();
    (t, home, public)
}
#[test]
fn setup_preserves_policy_and_installs_restricted_authorization() {
    let (_t, home, key) = fixture();
    let out = setup(&home, &key).arg("--yes").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = String::from_utf8_lossy(&out.stderr);
    assert!(!plan.contains("survey"));
    assert!(plan.contains("another SSH authorization file or manager"));
    let out = setup(&home, &key).arg("--yes").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let auth = fs::read(home.join(".ssh/authorized_keys")).unwrap();
    assert!(String::from_utf8_lossy(&auth).contains("restrict,command="));
    assert!(!String::from_utf8_lossy(&auth).contains("agent-forwarding"));
    assert!(
        setup(&home, &key)
            .arg("--yes")
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(auth, fs::read(home.join(".ssh/authorized_keys")).unwrap());
}
#[test]
fn removed_policy_keys_lose_only_their_porter_managed_entry() {
    let (_t, home, key) = fixture();
    assert!(setup(&home, &key).arg("--yes").status().unwrap().success());
    let path = home.join(".ssh/authorized_keys");
    let unrelated = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl unrelated\n";
    let mut contents = fs::read_to_string(&path).unwrap();
    contents.push_str(unrelated);
    fs::write(&path, &contents).unwrap();
    let old = fs::read_to_string(&key).unwrap();
    let replacement =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let next = home.join("next.pub");
    fs::write(&next, replacement.public_key().to_openssh().unwrap()).unwrap();
    assert!(setup(&home, &next).arg("--yes").status().unwrap().success());
    let installed = fs::read_to_string(&path).unwrap();
    let old_key = old.split_whitespace().nth(1).unwrap();
    assert!(!installed.contains(old_key), "{installed}");
    assert!(
        installed.contains(
            replacement
                .public_key()
                .to_openssh()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
        )
    );
    assert!(installed.contains(unrelated));
    assert_eq!(installed.matches("# git-porter managed").count(), 1);
}
#[test]
fn readonly_authorization_prints_exact_module_action_without_failure() {
    let (_t, home, key) = fixture();
    fs::create_dir(home.join(".ssh")).unwrap();
    let immutable = home.join("immutable");
    fs::write(&immutable, "# account managed\n").unwrap();
    fs::set_permissions(&immutable, fs::Permissions::from_mode(0o444)).unwrap();
    std::os::unix::fs::symlink(&immutable, home.join(".ssh/authorized_keys")).unwrap();
    let out = setup(&home, &key).arg("--yes").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("authorizedKeys"));
    assert!(error.contains("a separate file that SSH is configured to read"));
    assert!(error.contains("restrict,command="));
    assert!(error.contains(home.join(".ssh/authorized_keys").to_str().unwrap()));
    assert_eq!(
        fs::read_to_string(immutable).unwrap(),
        "# account managed\n"
    );
}
#[test]
fn imported_private_keys_from_files_and_stdin_go_to_plain_atomic_files() {
    use git_porter::credentials::wrapping;
    for stdin in [false, true] {
        let (_t, home, _) = fixture();
        let source =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let source_file = home.join("source.pub");
        fs::write(&source_file, source.public_key().to_openssh().unwrap()).unwrap();
        let agent = Agent::start(source).unwrap();
        let private =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let input = home.join("existing-key");
        fs::write(
            &input,
            private
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
        let _ = setup(&home, &source_file);
        let recorded = home.join(".local/share/git-porter/publication.source.pub");
        fs::write(
            &recorded,
            "invalid old source; explicit input must override it",
        )
        .unwrap();
        let mut c = {
            let mut command = Command::new(env!("CARGO_BIN_EXE_git-porter"));
            command
                .env("HOME", &home)
                .env_remove("XDG_DATA_HOME")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("XDG_CACHE_HOME")
                .env_remove("XDG_STATE_HOME")
                .env_remove("XDG_RUNTIME_DIR")
                .env_remove("XDG_DATA_DIRS")
                .env_remove("XDG_CONFIG_DIRS")
                .env_remove("XDG_DATA_HOME")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("XDG_CACHE_HOME")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("key:create");
            command
        };
        if stdin {
            c.arg(fs::read_to_string(&source_file).unwrap().trim());
        } else {
            c.arg(&source_file);
        }
        c.args(["--key-import"])
            .arg(if stdin { Path::new("-") } else { &input })
            .env("SSH_AUTH_SOCK", agent.socket())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        if stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(
                    private
                        .to_openssh(ssh_key::LineEnding::LF)
                        .unwrap()
                        .as_bytes(),
                )
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let data = home.join(".local/share/git-porter");
        assert!(!data.join("credentials").exists());
        for name in [
            "publication.wrapped",
            "publication.pub",
            "publication.source.pub",
        ] {
            assert!(fs::symlink_metadata(data.join(name)).unwrap().is_file());
        }
        let bundle =
            wrapping::Bundle::read(fs::File::open(data.join("publication.wrapped")).unwrap())
                .unwrap();
        let request = git_porter::credentials::derivation::Request::new(
            wrapping::read_public(&data.join("publication.source.pub")).unwrap(),
            bundle.metadata,
        )
        .unwrap();
        let response = request
            .sign(
                &mut git_porter::runtime::protocol::SigningBudget::default(),
                &mut git_porter::credentials::agent::Client::connect(&agent.socket()).unwrap(),
            )
            .unwrap();
        let plaintext =
            wrapping::decrypt_identity(&request.identity(&response).unwrap(), &bundle.ciphertext)
                .unwrap();
        assert_eq!(
            wrapping::parse_private(&plaintext).unwrap().public_key(),
            private.public_key()
        );
        assert!(!String::from_utf8_lossy(&out.stderr).contains("PRIVATE KEY"));
        let public = Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .args(["key:public"])
            .env("HOME", &home)
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .env_remove("XDG_DATA_HOME")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(public.status.success());
        let old = fs::read(data.join("publication.pub")).unwrap();
        let rotate = Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .args(["key:create"])
            .env("HOME", &home)
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_DATA_DIRS")
            .env_remove("XDG_CONFIG_DIRS")
            .env_remove("XDG_DATA_HOME")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("SSH_AUTH_SOCK", agent.socket())
            .output()
            .unwrap();
        assert!(
            rotate.status.success(),
            "{}",
            String::from_utf8_lossy(&rotate.stderr)
        );
        assert_ne!(old, fs::read(data.join("publication.pub")).unwrap());
    }
}

#[test]
fn setup_upgrades_old_porter_links_but_preserves_unrelated_hooks() {
    for name in ["git-porter", "custom-hook"] {
        let (_directory, home, key) = fixture();
        let mut command = setup(&home, &key);
        let old = home.join("old").join(name);
        // A removed prior installation must be repairable too.
        for role in ["hooks/pre-receive", "transport/ssh"] {
            let link = home.join(".local/share/git-porter").join(role);
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&old, &link).unwrap();
        }
        let result = command.arg("--yes").output().unwrap();
        assert_eq!(
            result.status.success(),
            name == "git-porter",
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        for role in ["hooks/pre-receive", "transport/ssh"] {
            let target = fs::read_link(home.join(".local/share/git-porter").join(role)).unwrap();
            assert_eq!(
                target,
                if name == "git-porter" {
                    Path::new(env!("CARGO_BIN_EXE_git-porter"))
                        .canonicalize()
                        .unwrap()
                } else {
                    old.clone()
                }
            );
        }
    }
}

#[test]
fn missing_home_and_xdg_data_fail_clearly() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .env_remove("HOME")
        .env_remove("XDG_DATA_HOME")
        .arg("key:public")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn fresh_setup_creates_data_directories_only_after_confirmation() {
    let (_temp, home, key) = fixture();
    let data = home.join(".local/share/git-porter");
    let mut declined = setup(&home, &key);
    // Remove the preparation done by the shared fixture: this is a fresh account.
    fs::remove_dir_all(home.join(".local")).unwrap();
    declined
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = declined.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Install restricted SSH access"));
    assert!(!home.join(".local").exists());
    assert!(!home.join(".ssh").exists());
    for xdg in [None, Some(home.join("custom-data"))] {
        let mut apply = setup(&home, &key);
        fs::remove_dir_all(&data).unwrap();
        if let Some(path) = &xdg {
            apply.env("XDG_DATA_HOME", path);
        }
        let result = apply.arg("--yes").output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let created = xdg
            .map(|p| p.join("git-porter"))
            .unwrap_or_else(|| data.clone());
        assert_eq!(
            fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for entry in ["hooks/pre-receive", "transport/ssh"] {
            assert!(
                fs::symlink_metadata(created.join(entry))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        assert!(!created.join("publication.wrapped").exists());
    }
}

#[test]
fn key_creation_rejects_ambiguous_inputs_and_signing_conflicts() {
    let (_temp, home, public) = fixture();
    let key = fs::read_to_string(public).unwrap();
    let multiple = format!("{key}\n{key}");
    let list = home.join("multiple.pub");
    fs::write(&list, &multiple).unwrap();
    for args in [
        vec!["key:create", "first.pub", "second.pub"],
        vec!["key:create", "sender.pub", "--sign", "receiver"],
        vec![
            "key:create",
            "--key-import",
            "private",
            "--sign",
            "receiver",
        ],
        vec!["key:create", "ssh-ed25519 invalid"],
        vec!["key:create", &multiple],
        vec!["key:create", list.to_str().unwrap()],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .env_clear()
            .env("HOME", &home)
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("TMPDIR", std::env::temp_dir())
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("public"));
        assert!(!home.join(".local").exists());
    }
}

#[test]
fn public_wrapping_token_bootstraps_setup_without_receiver_agent_or_ssh() {
    use git_porter::{
        credentials::{
            agent::Client,
            wrapping::{self, PublicWrapping},
        },
        runtime::protocol::SigningBudget,
    };
    let (_temp, home, source_file) = fixture();
    let private =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    fs::write(&source_file, private.public_key().to_openssh().unwrap()).unwrap();
    let agent = Agent::start(private.clone()).unwrap();
    let sender = home.join("sender");
    fs::create_dir(&sender).unwrap();
    let sign = || {
        Command::new(env!("CARGO_BIN_EXE_git-porter"))
            .env_clear()
            .env("HOME", &sender)
            .env("SSH_AUTH_SOCK", agent.socket())
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("TMPDIR", std::env::temp_dir())
            .args(["key:create", "--sign"])
            .output()
            .unwrap()
    };
    let output = sign();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!sender.join(".local").exists());
    let text = std::str::from_utf8(&output.stdout).unwrap().trim();
    let token = PublicWrapping::parse(text).unwrap();
    assert_eq!(
        token.request.source.key_data(),
        private.public_key().key_data()
    );
    let second = sign();
    assert!(second.status.success());
    assert_ne!(
        output.stdout, second.stdout,
        "enrollment must use fresh salt"
    );
    // Without a host or agent, reuse the native loader for an explicit .pub sibling.
    fs::write(
        sender.join("id"),
        private
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    fs::set_permissions(sender.join("id"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        sender.join("id.pub"),
        private.public_key().to_openssh().unwrap(),
    )
    .unwrap();
    let loaded = Command::new(env!("CARGO_BIN_EXE_git-porter"))
        .env_clear()
        .env("HOME", &sender)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("TMPDIR", std::env::temp_dir())
        .current_dir(&sender)
        .args(["key:create", "./id.pub", "--sign"])
        .output()
        .unwrap();
    assert!(
        loaded.status.success(),
        "{}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    assert_eq!(
        PublicWrapping::parse(std::str::from_utf8(&loaded.stdout).unwrap().trim())
            .unwrap()
            .request
            .source
            .key_data(),
        private.public_key().key_data()
    );
    assert!(PublicWrapping::parse(&"x".repeat(4097)).is_err());
    assert!(PublicWrapping::parse(&text[..text.len() - 1]).is_err());
    let wrong =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    use signature::Signer;
    let signature: ssh_key::Signature = wrong
        .try_sign(
            &token
                .request
                .metadata
                .challenge(&token.request.source)
                .unwrap(),
        )
        .unwrap();
    assert!(token.request.identity(signature.as_bytes()).is_err());
    let response = token
        .request
        .sign(
            &mut SigningBudget::default(),
            &mut Client::connect(&agent.socket()).unwrap(),
        )
        .unwrap();
    let identity = token.request.identity(&response).unwrap();
    assert_eq!(identity.to_public(), token.recipient);
    let mut command = setup(&home, &source_file);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    writeln!(child.stdin.take().unwrap(), "y\n{text}").unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let data = home.join(".local/share/git-porter");
    let encrypted = fs::read(data.join("publication.wrapped")).unwrap();
    let bundle = wrapping::Bundle::read(encrypted.as_slice()).unwrap();
    let plaintext = wrapping::decrypt_identity(&identity, &bundle.ciphertext).unwrap();
    let forwarder = wrapping::parse_private(&plaintext).unwrap();
    assert_eq!(
        forwarder.public_key().key_data(),
        git_porter::credentials::keys::public(&data)
            .unwrap()
            .key_data()
    );
    // Re-running setup must not replace a complete forwarder key or ask to create one.
    let result = setup(&home, &source_file).arg("--yes").output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        encrypted,
        fs::read(data.join("publication.wrapped")).unwrap()
    );
}

#[test]
fn captured_prompts_end_before_diagnostics_and_piped_consent_is_explicit() {
    let (_temp, home, public) = fixture();
    let mut command = setup(&home, &public);
    command
        .env_remove("NO_COLOR")
        .env("TERM", "xterm-256color")
        .env("FORCE_COLOR", "3")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"maybe\nYES\ninvalid-token\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "guidance leaked into stdout payload"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains('\x1b'),
        "force-color must not style captured output"
    );
    assert!(
        stderr.contains("[y/N] \nWarning: Enter yes or no"),
        "{stderr}"
    );
    assert!(stderr.contains("Enter to skip: \ngit-porter:"), "{stderr}");
    assert!(
        home.join(".ssh/authorized_keys").exists(),
        "explicit YES was not accepted"
    );
    fs::remove_file(home.join(".local/share/git-porter/publication.source.pub")).unwrap();
    let mut import = Command::new(env!("CARGO_BIN_EXE_git-porter"));
    import
        .env_clear()
        .env("HOME", &home)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("TMPDIR", std::env::temp_dir())
        .args(["key:create", "--key-import", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = import.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"private import input must not become a public-key answer\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("stdin is reserved for --key-import -"),
        "{error}"
    );
    assert!(!error.contains("Sender Ed25519 public key:"));
    assert!(
        !home
            .join(".local/share/git-porter/publication.wrapped")
            .exists()
    );
}

#[test]
fn setup_wait_never_replaces_credentials_created_during_the_prompt() {
    use std::io::Read;
    for completed in [false, true] {
        let (_temp, home, key) = fixture();
        let mut command = setup(&home, &key);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut errors = child.stderr.take().unwrap();
        input.write_all(b"yes\n").unwrap();
        let prompt = b"Paste a public wrapping token, type 'wait', or press Enter to skip:";
        let mut captured = Vec::new();
        while !captured.ends_with(prompt) {
            let mut byte = [0];
            assert_eq!(
                errors.read(&mut byte).unwrap(),
                1,
                "setup ended before enrollment prompt"
            );
            captured.extend_from_slice(&byte);
            assert!(captured.len() < 32768);
        }
        let data = home.join(".local/share/git-porter");
        fs::write(
            data.join("publication.pub"),
            b"concurrently created public key",
        )
        .unwrap();
        if completed {
            fs::write(
                data.join("publication.wrapped"),
                b"concurrently created bundle",
            )
            .unwrap();
        }
        input.write_all(b"wait\n").unwrap();
        drop(input);
        errors.read_to_end(&mut captured).unwrap();
        assert!(!child.wait().unwrap().success());
        assert!(String::from_utf8_lossy(&captured).contains("setup never replaces"));
        assert_eq!(
            fs::read(data.join("publication.pub")).unwrap(),
            b"concurrently created public key"
        );
        if completed {
            assert_eq!(
                fs::read(data.join("publication.wrapped")).unwrap(),
                b"concurrently created bundle"
            );
        } else {
            assert!(!data.join("publication.wrapped").exists());
        }
    }
}
