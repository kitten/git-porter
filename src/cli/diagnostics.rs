//! Unsigned setup-plan checks.
//! @ref LLP 0004#setup
use crate::server::config::ServerConfig;
use std::process::{Command, Stdio};
pub(crate) fn setup_checks(config: &ServerConfig) {
    if config.keys.is_empty() {
        super::terminal::warning(
            "No sender access key is configured. Set porter.authorizedKey to an Ed25519 public key before installing restricted SSH access.",
        );
    }
    let policy = &config.publication;
    for host in &policy.destinations {
        let builtin = crate::server::host_trust::KEYS
            .lines()
            .any(|line| line.split_whitespace().next() == Some(host.as_str()));
        let known = builtin
            || Command::new("ssh-keygen")
                .args(["-F", host, "-f"])
                .arg(&policy.known_hosts)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
        if known {
            super::terminal::success(format_args!("SSH host key is trusted: {host}"));
        } else {
            super::terminal::warning(format_args!(
                "No trusted SSH host key was found for {host}. Verify and trust it through normal Git/SSH use before forwarding."
            ));
        }
    }
}
