//! Authenticated receive preparation, isolated from repository hooks and transports.
//! @ref LLP 0002#local-only-transport
use super::Access;
use crate::{Result, runtime::supervision::Session, server::config::ServerConfig};
use std::path::Path;

pub(super) struct Upstream {
    pub(super) url: String,
    pub(super) network: bool,
}

pub(super) fn origin(
    access: &Access,
    repository: &Path,
    session: &Session,
) -> Result<Option<Upstream>> {
    let make = || {
        let mut command = access.git();
        command.arg("-C").arg(repository);
        command
    };
    let Some(url) = crate::runtime::read::origin(make, session)? else {
        return Ok(None);
    };
    let local = if let Some(path) = url.strip_prefix("file://") {
        if !path.starts_with('/') || path.contains('%') {
            return Err("local origin URLs require an absolute unescaped path; configure a local path instead".into());
        }
        Some(path)
    } else if !url.contains(':')
        || url.starts_with('/')
        || url.starts_with("./")
        || url.starts_with("../")
    {
        Some(url.as_str())
    } else {
        None
    };
    if let Some(path) = local {
        let path = if Path::new(path).is_absolute() {
            std::path::PathBuf::from(path)
        } else {
            repository.join(path)
        };
        let path = path.canonicalize()?;
        let repository = access.repository(path.to_str().ok_or("origin path must be UTF-8")?)?;
        return Ok(Some(Upstream {
            url: repository
                .to_str()
                .ok_or("origin path must be UTF-8")?
                .into(),
            network: false,
        }));
    }
    Ok(Some(Upstream { url, network: true }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn serve(
    config: &ServerConfig,
    access: &Access,
    repository: &Path,
    reference: &str,
    upstream: Option<Upstream>,
    private: Option<ssh_key::PrivateKey>,
    session: &Session,
    ready: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let network = session.bounded(std::time::Duration::from_secs(120))?;
    let directory = tempfile::tempdir()?;
    let command = |socket: &Path, public: Option<&Path>| {
        let mut cmd = crate::server::publication::onward_git(
            config,
            access,
            directory.path(),
            socket,
            public,
        );
        // Receive preparation accepts the same historical formats as ordinary fetch.
        // Keep the shared write-side fsck policy, overriding only fetch here.
        cmd.args(["-c", "fetch.fsckObjects=false"])
            .env("GIT_NO_LAZY_FETCH", "1")
            .env(
                "GIT_ALLOW_PROTOCOL",
                if upstream.as_ref().is_some_and(|u| u.network) {
                    "ssh"
                } else {
                    "file"
                },
            );
        cmd
    };
    let agent =
        if upstream.as_ref().is_some_and(|u| u.network) && !config.publication.skip_wrapped_key {
            Some(crate::server::publication::Agent::start(
                private.ok_or("missing read credential")?,
                config,
                &upstream.as_ref().ok_or("missing origin")?.url,
                &network,
            )?)
        } else {
            drop(private);
            None
        };
    let socket = match &agent {
        Some(agent) => agent.socket(),
        None if upstream.as_ref().is_some_and(|u| u.network) => {
            crate::server::publication::account_socket_with(Some(&network))?
        }
        None => std::path::PathBuf::new(),
    };
    let public = agent.as_ref().map(|a| a.public.clone());
    let prepared = crate::runtime::read::prepare(
        directory.path(),
        || {
            let mut git = access.git();
            git.arg("-C").arg(repository);
            git
        },
        || command(&socket, public.as_deref()),
        reference,
        upstream.as_ref().map(|u| u.url.as_str()),
        session,
    )?;
    drop(agent);
    ready()?;
    prepared.upload(access.git(), session)
}
