use git_porter::runtime::push_result::{self as result, Forwarded, Outcome, Reason, Report};
const REF: &str = "refs/heads/contributors/topic";
fn report(outcome: Outcome) -> Report {
    Report {
        version: 1,
        repository: Some("/srv/repo".into()),
        reference: Some(REF.into()),
        intended: Some("a".repeat(40)),
        receiver_ok: false,
        receiver_reason: Some("onward push failed".into()),
        reason: Reason::ReceiverRejected,
        forwarded: Some(Forwarded {
            url: Some("git@forge.example:org/repo.git".into()),
            rows: vec![],
            outcome,
        }),
    }
}
#[test]
fn old_receiver_capability_is_an_explicit_mismatch() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let role = root.join("client-ssh");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &role).unwrap();
    let ssh = root.join("ssh");
    fs::write(
        &ssh,
        "#!/bin/sh\nprintf 'git-porter-route-v1:porter\\n'\nprintf '\\000\\000\\000\\014\\002\\001publish-v4'\ncat >/dev/null\n",
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let mut command = Command::new(role);
    // argv[0] can carry opaque path bytes even on filesystems that require UTF-8.
    use std::os::unix::{ffi::OsStringExt, process::CommandExt};
    command.arg0(std::ffi::OsString::from_vec(
        b"/opaque-\xff/client-ssh".to_vec(),
    ));
    for (key, _) in std::env::vars_os().filter(|(key, _)| key.to_string_lossy().starts_with("XDG_"))
    {
        command.env_remove(key);
    }
    let output = command
        .env("HOME", root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .env("GIT_SSH_COMMAND", ssh)
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_PORTER_CLIENT_DESTINATION", "fixture")
        .env("GIT_PORTER_CLIENT_PATH", "repo")
        .env("GIT_PORTER_CLIENT_ORIGIN", "")
        .env("GIT_PORTER_CLIENT_PUBLISH", "true")
        .env("GIT_PORTER_SIGN_BUDGET", root.join("budget"))
        .env("GIT_PORTER_RESULT_FILE", root.join("result"))
        .args(["fixture", "git-receive-pack 'repo'"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("receiver does not support the requested capability"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!root.join("result").exists());
}

#[test]
fn missing_or_trailing_terminal_results_fail_the_transport() {
    use git_porter::runtime::protocol::{Budget, Kind};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let role = root.join("client-ssh");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_git-porter"), &role).unwrap();
    let mut control = b"git-porter-route-v1:porter\n".to_vec();
    let mut budget = Budget::default();
    budget
        .write(&mut control, Kind::Hello, b"publish-account-v3")
        .unwrap();
    budget
        .write(
            &mut control,
            Kind::Resolved,
            br#"{"version":1,"repository":"/srv/repo","publication":true,"signing":false}"#,
        )
        .unwrap();
    budget.write(&mut control, Kind::Ready, b"").unwrap();
    let mut final_record = vec![];
    result::write_final(&mut final_record, &report(Outcome::Unknown)).unwrap();
    for (index, suffix) in [
        vec![],
        final_record[..5].to_vec(),
        [final_record.clone(), vec![0]].concat(),
        [final_record.clone(), final_record.clone()].concat(),
    ]
    .into_iter()
    .enumerate()
    {
        let case = root.join(index.to_string());
        fs::create_dir(&case).unwrap();
        let wire = case.join("wire");
        fs::write(&wire, [control.clone(), suffix].concat()).unwrap();
        let ssh = case.join("ssh");
        fs::write(
            &ssh,
            format!(
                "#!/bin/sh\ncat '{}'\ndd bs=1 count={} of=/dev/null 2>/dev/null\n",
                wire.display(),
                16 + 6
                    + format!(
                        "intent-v2\0receive\0repo\0\0ff\0{REF}\0{}\0",
                        "a".repeat(40)
                    )
                    .len()
            ),
        )
        .unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(&role);
        for (key, _) in std::env::vars_os().filter(|(k, _)| k.to_string_lossy().starts_with("XDG_"))
        {
            command.env_remove(key);
        }
        let output = command
            .current_dir(&case)
            .env("HOME", &case)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env("GIT_SSH_COMMAND", ssh)
            .env("GIT_SSH_VARIANT", "ssh")
            .env("GIT_PORTER_CLIENT_DESTINATION", "fixture")
            .env("GIT_PORTER_CLIENT_PATH", "repo")
            .env("GIT_PORTER_CLIENT_ORIGIN", "")
            .env("GIT_PORTER_CLIENT_PUBLISH", "true")
            .env("GIT_PORTER_CLIENT_MODE", "ff")
            .env("GIT_PORTER_CLIENT_REF", REF)
            .env("GIT_PORTER_CLIENT_SHA", "a".repeat(40))
            .env("GIT_PORTER_SIGN_BUDGET", case.join("budget"))
            .env("GIT_PORTER_RESULT_FILE", case.join("result"))
            .args(["fixture", "git-receive-pack 'repo'"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success(), "case {index}");
        assert!(
            !case.join("result").exists(),
            "accepted invalid terminal result"
        );
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(
            message.contains("missing or truncated") || message.contains("trailing bytes"),
            "{message}"
        );
    }
}
