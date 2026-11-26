//! Explicit onward policy and a transaction-owned in-memory SSH agent.
//! @ref LLP 0000#publication
use crate::Result;
use crate::runtime::push_result::{self, Forwarded, HookReport, Outcome, Reason};
use ssh_key::PrivateKey;
mod agent;
mod binding;
mod peer;
pub mod policy;
pub use agent::Agent;
pub(crate) use agent::validate_private;
use policy::{Policy, runtime_file};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub fn transport(
    config: &crate::server::config::ServerConfig,
    arguments: &[std::ffi::OsString],
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let policy = &config.publication;
    policy.validate_transport(arguments)?;
    let socket = PathBuf::from(
        std::env::var_os("GIT_PORTER_TRANSACTION_SOCKET").ok_or("missing transaction agent")?,
    );
    let public = if policy.skip_wrapped_key {
        None
    } else {
        Some(PathBuf::from(
            std::env::var_os("GIT_PORTER_TRANSACTION_PUBLIC")
                .ok_or("missing transaction public key")?,
        ))
    };
    let host_keys = PathBuf::from(
        std::env::var_os("GIT_PORTER_TRANSACTION_TRUST")
            .ok_or("missing transaction host trust context")?,
    );
    crate::server::authorized::atomic(&host_keys, crate::server::host_trust::KEYS.as_bytes())?;
    let mut command = std::process::Command::new(&config.ssh);
    command
        .env_clear()
        .env("HOME", &config.home)
        .env("LC_ALL", "C")
        .env("SSH_AUTH_SOCK", &socket)
        .env("SSH_ASKPASS_REQUIRE", "never")
        .args([
            "-F",
            "/dev/null",
            "-a",
            "-S",
            "none",
            "-o",
            "BatchMode=yes",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "CertificateFile=none",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "HostbasedAuthentication=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
        ])
        .arg("-o")
        .arg(Policy::ssh_path("GlobalKnownHostsFile", &host_keys)?)
        .arg("-o")
        .arg(Policy::ssh_path("UserKnownHostsFile", &policy.known_hosts)?)
        .arg("-o")
        .arg(Policy::ssh_path("IdentityAgent", Path::new(&socket))?)
        .arg("-o")
        .arg(if policy.skip_wrapped_key {
            "IdentitiesOnly=no"
        } else {
            "IdentitiesOnly=yes"
        });
    if let Some(public) = public {
        command.arg("-i").arg(public);
    } else {
        command.args(["-o", "IdentityFile=none"]);
    }
    command.args(arguments);
    Err(command.exec().into())
}

pub(crate) struct Intent<'a> {
    pub mode: &'a str,
    pub reference: &'a str,
    pub observed: &'a str,
    pub sha: &'a str,
    pub url: &'a str,
}
pub(crate) struct Transaction {
    _agent: Option<Agent>,
    _directory: tempfile::TempDir,
    context: HookContext,
    context_path: PathBuf,
    tip: String,
}
pub(crate) fn has_origin(
    access: &crate::server::access::Access,
    repository: &Path,
    session: &crate::runtime::supervision::Session,
) -> Result<bool> {
    let mut query = access.git();
    query.arg("-C").arg(repository).args([
        "config",
        "--get-regexp",
        r"^remote\.origin\.(url|pushurl)$",
    ]);
    let (status, _) = session.run(query, true)?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err("cannot inspect receiver origin configuration".into()),
    }
}
/// Resolve and pin policy before asking the source to derive anything.
pub(crate) fn destination(
    access: &crate::server::access::Access,
    repository: &Path,
    session: &crate::runtime::supervision::Session,
) -> Result<String> {
    let mut command = access.git();
    command
        .arg("-C")
        .arg(repository)
        .args(["remote", "get-url", "--push", "--all", "origin"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let (status, bytes) = session.run(command, true)?;
    if !status.success() {
        return Err("receiving repository has no usable origin".into());
    }
    let urls = std::str::from_utf8(&bytes)?;
    let urls: Vec<_> = urls.lines().collect();
    let [url] = urls.as_slice() else {
        return Err("origin requires exactly one push URL".into());
    };
    push_result::validate_url(url)?;
    Ok((*url).into())
}
impl Transaction {
    pub(crate) fn prepare(
        config: &crate::server::config::ServerConfig,
        access: &crate::server::access::Access,
        repository: &Path,
        private: Option<PrivateKey>,
        intent: Intent<'_>,
        reason: &mut Reason,
        receiver: &crate::runtime::supervision::Session,
    ) -> Result<Self> {
        let origin = receiver.bounded(std::time::Duration::from_secs(120))?;
        let Intent {
            mode,
            reference,
            observed,
            sha,
            url,
        } = intent;
        let url = url.to_owned();
        let policy = &config.publication;
        // The caller checked correspondence against its pinned credential set.
        policy.allows(&url)?;
        let objects = access.metadata_in(
            repository,
            &["--path-format=absolute", "--git-path", "objects"],
            &origin,
        )?;
        let objects = PathBuf::from(objects).canonicalize()?;
        if !config.permits_path(&objects) {
            return Err("object store escapes root".into());
        }
        let format = access.metadata_in(repository, &["--show-object-format"], &origin)?;
        let gitdir = tempfile::Builder::new()
            .prefix("porter-publication-")
            .tempdir()?;
        let mut init = access.git();
        init.args(["init", "--bare", "--quiet"])
            .arg(format!("--object-format={format}"))
            .arg(gitdir.path());
        if !origin.run(init, false)?.0.success() {
            return Err("cannot initialize isolated publication Git context".into());
        }
        // Missing promisor objects hydrate only through this transaction's origin.
        for (name, value) in [
            ("core.repositoryformatversion", "1"),
            ("extensions.partialClone", "origin"),
            ("remote.origin.promisor", "true"),
            ("remote.origin.url", url.as_str()),
        ] {
            let mut command = access.git();
            command
                .arg("-C")
                .arg(gitdir.path())
                .args(["config", name, value]);
            if !origin.run(command, false)?.0.success() {
                return Err("cannot configure isolated publication object hydration".into());
            }
        }
        *reason = Reason::CredentialsUnavailable;
        origin.check()?;
        let agent = match (policy.skip_wrapped_key, private) {
            (false, Some(private)) => Some(Agent::start(private, config, &url, &origin)?),
            (true, None) => None,
            _ => return Err("forwarder credential mode mismatch".into()),
        };
        let socket = match &agent {
            Some(agent) => agent.socket(),
            None => account_socket_with(Some(&origin))?,
        };
        let public = agent.as_ref().map(|agent| agent.public.clone());
        let context_path = gitdir.path().join("publication.json");
        let context = HookContext {
            gitdir: gitdir.path().into(),
            objects,
            socket,
            public,
            url,
            mode: mode.into(),
            observed: observed.into(),
            reference: reference.into(),
            sha: sha.into(),
        };
        let mut transaction = Self {
            _agent: agent,
            _directory: gitdir,
            context,
            context_path,
            tip: String::new(),
        };
        *reason = Reason::OriginUnavailable;
        let mut preflight = transaction.git(config, access);
        preflight
            .args(["ls-remote", "--refs", &transaction.context.url, reference])
            .stderr(std::process::Stdio::inherit());
        let (status, bytes) = origin.run(preflight, true).map_err(|e| {
            format!("origin pre-authentication interrupted; local receipt has not started: {e}")
        })?;
        if !status.success() {
            return Err("origin pre-authentication failed; local receipt has not started".into());
        }
        transaction.tip = push_result::ref_tip(&bytes, reference)?
            .unwrap_or_default()
            .into();
        if mode == "lease" && transaction.tip != observed {
            *reason = Reason::OriginMoved;
            return Err("origin moved since the sender observed the receiver tip; neither repository was updated. Inspect the current tips before retrying".into());
        }
        crate::server::authorized::atomic(
            &transaction.context_path,
            &serde_json::to_vec(&transaction.context)?,
        )?;
        Ok(transaction)
    }
    pub(crate) fn context(&self) -> &Path {
        &self.context_path
    }
    pub(crate) fn url(&self) -> &str {
        &self.context.url
    }
    pub(crate) fn finish(
        mut self,
        config: &crate::server::config::ServerConfig,
        access: &crate::server::access::Access,
        receiver_ok: bool,
        receiver: &crate::runtime::supervision::Session,
    ) -> Result<(Forwarded, Option<String>)> {
        if receiver.check().is_err() {
            drop(self._agent.take());
        }
        let context = &self.context;
        let path = context.gitdir.join("hook-result.json");
        let hook = match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() > push_result::MAX_RESULT {
                    return Err("hook result exceeds limit".into());
                }
                let h: HookReport = serde_json::from_slice(&bytes)?;
                if h.version != 1
                    || h.reference != context.reference
                    || h.intended != context.sha
                    || !push_result::rows_valid(&h.rows)
                {
                    return Err("invalid hook result".into());
                }
                Some(h)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let (rows, outcome, reason) = publication_result(hook, receiver_ok, || {
            let mut command = self.git(config, access);
            command.args(["ls-remote", "--refs", &context.url, &context.reference]);
            let origin = receiver.bounded(std::time::Duration::from_secs(120))?;
            let (status, bytes) = origin.run(command, true)?;
            if !status.success() {
                return Err("origin re-check failed".into());
            }
            origin_outcome(&bytes, &context.reference, &context.sha, &self.tip)
        });
        Ok((
            Forwarded {
                url: Some(context.url.clone()),
                rows,
                outcome,
            },
            reason,
        ))
    }
    fn git(
        &self,
        config: &crate::server::config::ServerConfig,
        access: &crate::server::access::Access,
    ) -> std::process::Command {
        let mut command = onward_git(
            config,
            access,
            &self.context.gitdir,
            &self.context.socket,
            self.context.public.as_deref(),
        );
        command.env("GIT_OBJECT_DIRECTORY", &self.context.objects);
        command
    }
}

/// Classify machine-readable origin observations, never remote diagnostic prose.
fn origin_outcome(
    bytes: &[u8],
    reference: &str,
    intended: &str,
    expected: &str,
) -> Result<Outcome> {
    let actual = push_result::ref_tip(bytes, reference)?;
    Ok(if actual == Some(intended) {
        Outcome::Published
    } else if actual.unwrap_or("") == expected {
        Outcome::NotPublished
    } else {
        Outcome::Moved {
            actual: actual.map(str::to_owned),
        }
    })
}

/// Only attempted failures need an origin recheck; both receive paths use this decision.
fn publication_result(
    hook: Option<HookReport>,
    receiver_ok: bool,
    recheck: impl FnOnce() -> Result<Outcome>,
) -> (Vec<push_result::Row>, Outcome, Option<String>) {
    match hook {
        None if receiver_ok => (vec![], Outcome::Unknown, None),
        None => (
            vec![],
            Outcome::NotAttempted {
                reason: Reason::ReceiverRejected,
            },
            None,
        ),
        Some(h) if !h.attempted => (
            vec![],
            Outcome::NotAttempted {
                reason: h.reason.clone(),
            },
            Some(h.reason.text().into()),
        ),
        Some(h) if h.accepted && receiver_ok => (h.rows, Outcome::Complete, None),
        Some(h) => {
            let outcome = recheck().unwrap_or(Outcome::Unknown);
            let reason = if h.accepted {
                "receiver update failed"
            } else if matches!(outcome, Outcome::Unknown | Outcome::Moved { .. }) {
                "onward result uncertain"
            } else {
                "onward push failed"
            };
            (h.rows, outcome, Some(reason.into()))
        }
    }
}

/// Isolated publication Git context using only the compiled transport role,
/// the transaction-selected agent/public reference and per-transaction trust.
/// Lazy fetches are permitted here: the context's only promisor is the pinned origin.
pub(crate) fn onward_git(
    config: &crate::server::config::ServerConfig,
    access: &crate::server::access::Access,
    gitdir: &Path,
    socket: &Path,
    public: Option<&Path>,
) -> std::process::Command {
    let mut command = access.git();
    command
        .env_remove("GIT_NO_LAZY_FETCH")
        .env("GIT_DIR", gitdir)
        .env("GIT_SSH", config.data.join("transport/ssh"))
        .env("GIT_SSH_VARIANT", "ssh")
        .env("GIT_PORTER_TRANSACTION_SOCKET", socket)
        .env("GIT_PORTER_TRANSACTION_TRUST", gitdir.join("known_hosts"));
    if let Some(public) = public {
        command.env("GIT_PORTER_TRANSACTION_PUBLIC", public);
    }
    command
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HookContext {
    gitdir: PathBuf,
    objects: PathBuf,
    socket: PathBuf,
    public: Option<PathBuf>,
    url: String,
    mode: String,
    observed: String,
    reference: String,
    sha: String,
}
fn claim_transaction(directory: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let claim = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("hook-claimed"))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "publication transaction was already claimed; refusing another hook".to_owned()
            } else {
                format!("cannot claim publication transaction: {error}")
            }
        })?;
    claim.sync_all()?;
    Ok(())
}

pub(crate) fn pre_receive(
    config: &crate::server::config::ServerConfig,
    updates: &[(String, String, String)],
    publication: Option<&Path>,
) -> Result<()> {
    let Some(path) = publication else {
        return Ok(());
    };
    let path = runtime_file(path, true)?;
    let context: HookContext = serde_json::from_slice(&fs::read(path)?)?;
    claim_transaction(&context.gitdir)?;
    let mut record = HookReport {
        version: 1,
        reference: context.reference.clone(),
        intended: context.sha.clone(),
        attempted: false,
        accepted: false,
        rows: vec![],
        reason: Reason::PolicyRefused,
    };
    let record_path = context.gitdir.join("hook-result.json");
    let save = |record: &HookReport| {
        crate::server::authorized::atomic(&record_path, &serde_json::to_vec(record)?)
    };
    save(&record)?;
    let [(old, new, reference)] = updates else {
        return Err("publication requires exactly one branch update".into());
    };
    if reference != &context.reference || new != &context.sha {
        return Err("hook update differs from publication intent".into());
    }
    if context.mode == "lease"
        && (if old.bytes().all(|b| b == b'0') {
            ""
        } else {
            old.as_str()
        }) != context.observed
    {
        return Err("receiver lease changed; origin was not updated".into());
    }
    let access = crate::server::access::configured_access(config)?;
    let onward = || {
        onward_git(
            config,
            &access,
            &context.gitdir,
            &context.socket,
            context.public.as_deref(),
        )
    };
    let mut push = onward();
    // Quarantined receipt objects stay private to this hook and its push.
    push.env(
        "GIT_OBJECT_DIRECTORY",
        std::env::var_os("GIT_OBJECT_DIRECTORY")
            .unwrap_or_else(|| context.objects.clone().into_os_string()),
    )
    .env(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        std::env::var_os("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .unwrap_or_else(|| context.objects.clone().into_os_string()),
    );
    if !config.publication.allow_default_branch {
        let mut query = onward();
        query.args(["ls-remote", "--symref", &context.url, "HEAD"]);
        let session = crate::runtime::supervision::Session::with_timeout(
            std::time::Duration::from_secs(120),
        )?;
        let (status, bytes) = session.run(query, true)?;
        if let Err(reason) = protect_default_branch(status.success(), &bytes, &context.reference) {
            let message = match reason {
                Reason::DefaultBranchProtected => {
                    "publication to origin's default branch is protected; rename your sender branch before sending it"
                }
                _ => "origin default branch could not be determined; publication refused",
            };
            record.reason = reason;
            save(&record)?;
            return Err(message.into());
        }
    }
    push.args([
        "-c",
        "push.pushOption=",
        "-c",
        "push.negotiate=false",
        "push",
        "--porcelain",
        "--signed=false",
        "--no-follow-tags",
        "--recurse-submodules=no",
    ]);
    match context.mode.as_str() {
        "lease" => {
            push.arg(format!(
                "--force-with-lease={}:{}",
                context.reference, context.observed
            ));
        }
        "force" => {
            push.arg("--force");
        }
        "ff" => {}
        _ => return Err("invalid publication mode".into()),
    };
    push.arg(&context.url)
        .arg(format!("{}:{}", context.sha, context.reference));
    let session =
        crate::runtime::supervision::Session::with_timeout(std::time::Duration::from_secs(120))?;
    record.attempted = true;
    record.reason = Reason::Interrupted;
    save(&record)?;
    let (status, output) = session.run(push, true)?;
    record.rows = push_result::parse_porcelain(&output, &context.reference)?;
    record.accepted = status.success();
    save(&record)?;
    if !status.success() {
        return Err(push_result::Reported.into());
    }
    Ok(())
}

fn protect_default_branch(
    success: bool,
    advertisement: &[u8],
    reference: &str,
) -> std::result::Result<(), Reason> {
    if !success {
        return Err(Reason::DefaultBranchUnknown);
    }
    let text = std::str::from_utf8(advertisement).map_err(|_| Reason::DefaultBranchUnknown)?;
    let rows: Vec<_> = text.lines().collect();
    let [symref, oid] = rows.as_slice() else {
        return Err(Reason::DefaultBranchUnknown);
    };
    let default = symref
        .strip_prefix("ref: ")
        .and_then(|s| s.strip_suffix("\tHEAD"))
        .ok_or(Reason::DefaultBranchUnknown)?;
    let oid = oid
        .strip_suffix("\tHEAD")
        .ok_or(Reason::DefaultBranchUnknown)?;
    if !default.starts_with("refs/heads/")
        || !git2::Reference::is_valid_name(default)
        || !push_result::oid(oid)
        || oid.bytes().all(|b| b == b'0')
    {
        return Err(Reason::DefaultBranchUnknown);
    }
    if default == reference {
        return Err(Reason::DefaultBranchProtected);
    }
    Ok(())
}

/// Account-agent mode never opens identity files or starts another agent.
pub fn account_socket() -> Result<PathBuf> {
    account_socket_with(None)
}
pub(crate) fn account_socket_with(
    session: Option<&crate::runtime::supervision::Session>,
) -> Result<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let socket = PathBuf::from(
        std::env::var_os("SSH_AUTH_SOCK")
            .filter(|s| !s.is_empty())
            .ok_or("receiver/forwarder's inherited SSH_AUTH_SOCK is not set")?,
    );
    let validate = || -> Result<()> {
        if !socket.is_absolute() {
            return Err("SSH_AUTH_SOCK must be an absolute socket path".into());
        }
        let metadata = fs::metadata(&socket)?;
        if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("agent socket must be owned by the receiver/forwarder account".into());
        }
        let mut agent = match session {
            Some(session) => crate::credentials::agent::Client::connect_in(&socket, session)?,
            None => crate::credentials::agent::Client::connect(&socket)?,
        };
        agent.bound_io(std::time::Duration::from_secs(2));
        if agent.list_all_identities()?.is_empty() {
            return Err("agent has no usable keys".into());
        }
        Ok(())
    };
    validate().map_err(|e| format!("receiver/forwarder SSH_AUTH_SOCK is unusable: {e}"))?;
    Ok(socket)
}

#[cfg(test)]
mod tests;
