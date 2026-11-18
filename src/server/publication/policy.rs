//! Destination policy, SSH argument validation and runtime credential paths.
//! @ref LLP 0000#publication
use crate::{
    Result,
    server::{config::boolean, discovery::Identity},
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub destinations: Vec<String>,
    pub allow_default_branch: bool,
    pub skip_wrapped_key: bool,
    pub wrapped: PathBuf,
    pub source: PathBuf,
    pub public: PathBuf,
    pub known_hosts: PathBuf,
}
pub fn policy_setting(key: &str) -> bool {
    matches!(
        key,
        "porter.publishto" | "porter.allowdefaultbranch" | "porter.skipwrappedkey"
    )
}
pub fn runtime_file(path: &Path, secret: bool) -> Result<PathBuf> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|s| s.chars().any(char::is_control))
    {
        return Err("publication paths must be absolute UTF-8 without control characters".into());
    }
    let path = path.canonicalize()?;
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file()
        || metadata.len() > 2 * 1024 * 1024
        || metadata.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
    {
        return Err("publication file must be bounded and owner-controlled".into());
    }
    if secret
        && (path.starts_with("/nix/store")
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0)
    {
        return Err(
            "wrapped credential must be account-owned, mode 0600, outside the Nix store".into(),
        );
    }
    Ok(path)
}
impl Policy {
    pub fn read(
        data: &Path,
        known_hosts: &Path,
        values: &BTreeMap<String, Vec<String>>,
    ) -> Result<Self> {
        let destinations = values.get("porter.publishto").cloned().unwrap_or_default();
        for host in &destinations {
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            {
                return Err("receiver setup contains an invalid allowed forge hostname".into());
            }
        }
        let allow_default_branch = boolean(values, "porter.allowdefaultbranch")?;
        let skip_wrapped_key = boolean(values, "porter.skipwrappedkey")?;
        Ok(Self {
            skip_wrapped_key,
            destinations,
            allow_default_branch,
            wrapped: data.join("publication.wrapped"),
            source: data.join("publication.source.pub"),
            public: data.join("publication.pub"),
            known_hosts: known_hosts.to_owned(),
        })
    }
    /// Pin and validate runtime credential files only when needed.
    pub fn ready(&self) -> Result<Self> {
        if self.skip_wrapped_key {
            return Ok(self.clone());
        }
        Ok(Self {
            wrapped: runtime_file(&self.wrapped, true)?,
            source: runtime_file(&self.source, false)?,
            public: runtime_file(&self.public, false)?,
            ..self.clone()
        })
    }
    pub fn allows(&self, url: &str) -> Result<()> {
        let (identity, _) = parse_url(url)?;
        if !self.destinations.is_empty()
            && !self
                .destinations
                .iter()
                .any(|host| host.eq_ignore_ascii_case(&identity.host))
        {
            return Err(format!(
                "origin destination {} is not permitted by the receiver",
                identity.host
            )
            .into());
        }
        Ok(())
    }
    pub(crate) fn ssh_path(option: &str, path: &Path) -> Result<String> {
        let value = path.to_str().ok_or("SSH option path must be UTF-8")?;
        if value.chars().any(char::is_control) || value.contains("${") {
            return Err(
                "SSH option paths cannot contain control characters or environment interpolation"
                    .into(),
            );
        }
        Ok(format!(
            "{option}=\"{}\"",
            value
                .replace('%', "%%")
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
        ))
    }

    pub(super) fn validate_transport(&self, args: &[std::ffi::OsString]) -> Result<()> {
        let mut index = 0;
        let mut port = 22u16;
        while index + 1 < args.len() {
            if args[index] == "-o" && args[index + 1] == "SendEnv=GIT_PROTOCOL" {
                index += 2;
            } else if args[index] == "-p" {
                port = args[index + 1].to_str().ok_or("invalid port")?.parse()?;
                index += 2;
            } else {
                break;
            }
        }
        let [host, command] = &args[index..] else {
            return Err("unsupported publication SSH arguments".into());
        };
        let host = host.to_str().ok_or("invalid host")?;
        let command = command.to_str().ok_or("invalid Git command")?;
        let path = command
            .strip_prefix("git-upload-pack '")
            .or_else(|| command.strip_prefix("git-receive-pack '"))
            .and_then(|s| s.strip_suffix('\''))
            .ok_or("only quoted Git pack commands are accepted")?;
        self.allows(&format!(
            "ssh://{host}:{port}/{}",
            path.strip_prefix('/').unwrap_or(path)
        ))?;
        Ok(())
    }
}
pub(super) fn parse_url(url: &str) -> Result<(Identity, String)> {
    let authority = if let Some(rest) = url.strip_prefix("ssh://") {
        rest.split_once('/').ok_or("missing SSH path")?.0
    } else {
        if url.contains("://") {
            return Err("publication requires SSH".into());
        }
        url.split_once(':').ok_or("missing SSH authority")?.0
    };
    let (user, _) = authority
        .split_once('@')
        .ok_or("publication requires an explicit SSH user")?;
    Ok((Identity::parse(url)?, user.into()))
}
