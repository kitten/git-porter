//! User-selected client SSH command, separate from the controlled Git transport.
//! @ref LLP 0002#client-ssh
use crate::Result;
use std::process::Command;

/// Quote one literal Unix executable path for Git's shell-parsed override.
pub(crate) fn quoted_path(path: &std::path::Path) -> std::ffi::OsString {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let mut quoted = vec![b'\''];
    for byte in path.as_os_str().as_bytes() {
        if *byte == b'\'' {
            quoted.extend_from_slice(b"'\\''");
        } else {
            quoted.push(*byte);
        }
    }
    quoted.push(b'\'');
    std::ffi::OsString::from_vec(quoted)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Selection {
    argv: Vec<String>,
    shell: bool,
}
fn simple(value: &str) -> bool {
    !value.chars().any(|c| {
        matches!(
            c,
            '\'' | '"'
                | '$'
                | '`'
                | '|'
                | '<'
                | '>'
                | '\n'
                | '\r'
                | ';'
                | '&'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '*'
                | '?'
                | '~'
                | '\\'
                | '#'
        )
    })
}
fn parsed(value: &str) -> Result<Selection> {
    if value.trim().is_empty() {
        return Err("empty SSH command".into());
    }
    Ok(if simple(value) {
        Selection {
            argv: value.split_whitespace().map(str::to_owned).collect(),
            shell: false,
        }
    } else {
        Selection {
            argv: vec![value.into()],
            shell: true,
        }
    })
}
fn base(selection: &Selection) -> Command {
    if selection.shell {
        let mut c = crate::runtime::supervision::command("sh");
        c.args([
            "-c",
            &format!("{} \"$@\"", selection.argv[0]),
            &selection.argv[0],
        ]);
        c
    } else {
        let mut c = crate::runtime::supervision::command(&selection.argv[0]);
        c.args(&selection.argv[1..]);
        c
    }
}
pub(crate) fn selected() -> Result<String> {
    let selection = if let Ok(value) = std::env::var("GIT_SSH_COMMAND") {
        parsed(&value)?
    } else {
        let output = Command::new("git")
            .args(["config", "--get", "core.sshCommand"])
            .output()?;
        if output.status.success() {
            parsed(String::from_utf8(output.stdout)?.trim_end_matches('\n'))?
        } else if let Some(value) = std::env::var_os("GIT_SSH") {
            Selection {
                argv: vec![value.into_string().map_err(|_| "non-UTF8 GIT_SSH")?],
                shell: false,
            }
        } else {
            Selection {
                shell: false,
                argv: vec![
                    crate::server::config::executable("ssh")?
                        .to_string_lossy()
                        .into_owned(),
                ],
            }
        }
    };
    let configured = std::env::var("GIT_SSH_VARIANT").ok().or_else(|| {
        let out = Command::new("git")
            .args(["config", "--get", "ssh.variant"])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    });
    let variant = configured.unwrap_or_else(|| {
        let name = std::path::Path::new(&selection.argv[0])
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ["ssh", "plink", "tortoiseplink", "putty"].contains(&name.as_str()) {
            name
        } else if base(&selection)
            .args(["-G", "git-porter-variant-probe"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
        {
            "ssh".into()
        } else {
            "simple".into()
        }
    });
    require_openssh(&variant)?;
    Ok(serde_json::to_string(&selection)?)
}
fn guarded_command() -> Result<Command> {
    let encoded = std::env::var("GIT_PORTER_USER_SSH")
        .map(Ok)
        .unwrap_or_else(|_| selected())?;
    let selection: Selection = serde_json::from_str(&encoded)?;
    let (program, options) = selection.argv.split_first().ok_or("empty SSH command")?;
    let mut command = if selection.shell {
        base(&selection)
    } else {
        crate::runtime::supervision::command(program)
    };
    command.args([
        "-a",
        "-o",
        "ForwardAgent=no",
        "-S",
        "none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPersist=no",
    ]);
    // Direct -A/-M/-S switches overwrite values rather than using the config
    // first-value rule. Remove those, while ordinary -o settings follow guards.
    let mut options = options.iter().filter(|_| !selection.shell);
    while let Some(option) = options.next() {
        if !option.starts_with('-') || option == "-" || option.starts_with("--") {
            command.arg(option);
            continue;
        }
        for (offset, flag) in option[1..].char_indices() {
            if flag == 'A' || flag == 'M' {
                continue;
            }
            if "BbcDEeFIiJLlmOoPpQRSWw".contains(flag) {
                let suffix = &option[1 + offset + flag.len_utf8()..];
                let value = if suffix.is_empty() {
                    options
                        .next()
                        .ok_or("missing SSH option argument")?
                        .as_str()
                } else {
                    suffix
                };
                if flag != 'S' {
                    command.arg(format!("-{flag}")).arg(value);
                }
                break;
            }
            command.arg(format!("-{flag}"));
        }
    }
    Ok(command)
}

pub(crate) fn command(host: &str, remote: &str) -> Result<Command> {
    let mut command = guarded_command()?;
    command.args(["--", host, remote]);
    Ok(command)
}

/// Inspect only the same SSH command/configuration already selected for this receiver.
pub(crate) fn sender_identities(
    host: &str,
    session: &crate::runtime::supervision::Session,
) -> Result<SenderIdentities> {
    let mut command = guarded_command()?;
    command
        .args(["-G", "--", host])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let (status, bytes) = session.run(command, true)?;
    if !status.success() {
        return Err("cannot inspect the sender SSH identity configuration".into());
    }
    let home = std::env::var_os("HOME").ok_or("HOME is required for sender key bootstrap")?;
    identity_configuration(&bytes, std::path::Path::new(&home))
}

pub(crate) struct SenderIdentities {
    pub agent: Option<std::path::PathBuf>,
    pub files: Vec<std::path::PathBuf>,
}
fn identity_path(value: &str, home: &std::path::Path) -> Result<std::path::PathBuf> {
    if value.contains('%') || value.contains("${") || value.chars().any(char::is_control) {
        return Err("sender SSH identity path contains unresolved tokens".into());
    }
    let path = if let Some(relative) = value.strip_prefix("~/") {
        home.join(relative)
    } else {
        std::path::PathBuf::from(value)
    };
    if !path.is_absolute() {
        return Err("sender SSH identity path is neither absolute nor home-relative".into());
    }
    Ok(path)
}
fn identity_configuration(bytes: &[u8], home: &std::path::Path) -> Result<SenderIdentities> {
    if bytes.len() > 65536 {
        return Err("sender SSH configuration exceeds 64 KiB".into());
    }
    let text = std::str::from_utf8(bytes)?;
    let mut agents = text
        .lines()
        .filter_map(|line| line.strip_prefix("identityagent "));
    let agent = agents.next();
    if agents.next().is_some() {
        return Err("sender SSH agent selection is ambiguous".into());
    }
    // OpenSSH's special SSH_AUTH_SOCK value has no socket when that variable is absent.
    let agent = match agent {
        None | Some("none" | "SSH_AUTH_SOCK" | "$SSH_AUTH_SOCK" | "${SSH_AUTH_SOCK}") => None,
        Some(value) => Some(identity_path(value, home)?),
    };
    if agent.is_some() {
        return Ok(SenderIdentities {
            agent,
            files: vec![],
        });
    }
    let mut files = Vec::new();
    for value in text
        .lines()
        .filter_map(|line| line.strip_prefix("identityfile "))
    {
        if value == "none" {
            continue;
        }
        if files.len() >= 32 {
            return Err("sender SSH identity-file limit exceeded".into());
        }
        files.push(identity_path(value, home)?);
    }
    files.sort();
    files.dedup();
    Ok(SenderIdentities { agent, files })
}

fn require_openssh(variant: &str) -> Result<()> {
    if variant == "ssh" {
        Ok(())
    } else {
        Err(format!("git-porter requires OpenSSH; effective SSH variant is {variant}").into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_helper_paths_survive_shell_parsing_as_unix_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let path = b"/tmp/space 'quote' $variable;command-\xff/client-ssh";
        let mut script = std::ffi::OsString::from("printf '%s' ");
        script.push(quoted_path(std::path::Path::new(
            std::ffi::OsStr::from_bytes(path),
        )));
        let home = tempfile::tempdir().unwrap();
        let output = Command::new(crate::server::config::executable("sh").unwrap())
            .env_clear()
            .env("HOME", home.path())
            .env("LC_ALL", "C")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, path);
    }
    #[test]
    fn sender_identity_paths_are_bounded_and_never_guess_tokens() {
        let home = std::path::Path::new("/fixture/home");
        let paths = identity_configuration(b"hostname receiver\nidentityfile ~/key with spaces\nidentityfile /fixture/absolute\nidentityfile none\n", home).unwrap();
        assert_eq!(
            paths.files,
            vec![
                std::path::PathBuf::from("/fixture/absolute"),
                home.join("key with spaces")
            ]
        );
        let configured =
            identity_configuration(b"identityagent /fixture/agent\nidentityfile %d/key\n", home)
                .unwrap();
        assert_eq!(
            configured.agent.as_deref(),
            Some(std::path::Path::new("/fixture/agent"))
        );
        assert!(configured.files.is_empty());
        for special in [
            "none",
            "SSH_AUTH_SOCK",
            "$SSH_AUTH_SOCK",
            "${SSH_AUTH_SOCK}",
        ] {
            let selected = identity_configuration(
                format!("identityagent {special}\nidentityfile /fixture/key\n").as_bytes(),
                home,
            )
            .unwrap();
            assert!(selected.agent.is_none());
            assert_eq!(
                selected.files,
                vec![std::path::PathBuf::from("/fixture/key")]
            );
        }

        assert!(identity_configuration(b"identityagent /one\nidentityagent /two\n", home).is_err());
        for value in ["%d/key", "${HOME}/key", "relative", "~other/key"] {
            assert!(
                identity_configuration(format!("identityfile {value}\n").as_bytes(), home).is_err()
            );
        }
        assert!(identity_configuration(&vec![b'x'; 65537], home).is_err());
        assert!(
            identity_configuration("identityfile /fixture/key\n".repeat(33).as_bytes(), home)
                .is_err()
        );
    }
    #[test]
    fn command_branches_and_variants() {
        assert!(!parsed("ssh -v -AM").unwrap().shell);
        for value in ["ssh -F 'a b'", "ssh $FLAGS", "ssh | cat", "ssh\n-v"] {
            assert!(parsed(value).unwrap().shell);
        }
        for variant in ["plink", "tortoiseplink", "putty", "simple"] {
            assert!(require_openssh(variant).is_err());
        }
        assert!(require_openssh("ssh").is_ok());
        let selection = parsed("printf '%s\n'").unwrap();
        let output = base(&selection).arg("hello world").output().unwrap();
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "hello world\n");
    }
}
