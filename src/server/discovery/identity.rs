//! Conservative remote identities and shared repository remote selection.
//! @ref LLP 0002#lookup
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub host: String,
    pub port: Option<u16>,
    pub repository: String,
}
impl Identity {
    pub fn parse(url: &str) -> Result<Self> {
        if url.len() > 4096
            || url.chars().any(char::is_control)
            || url.contains(['?', '#', '%', '\\'])
        {
            return Err("unsupported or credential-bearing remote identity".into());
        }
        let (host, port, path) = if let Some(rest) = url.strip_prefix("https://") {
            let (authority, path) = rest.split_once('/').ok_or("missing remote path")?;
            if authority.contains('@') {
                return Err("credential-bearing remote URL".into());
            }
            let (host, port) = authority_port(authority, 443)?;
            (host, port, path)
        } else if let Some(rest) = url.strip_prefix("ssh://") {
            let (authority, path) = rest.split_once('/').ok_or("missing remote path")?;
            let authority = if let Some((user, host)) = authority.split_once('@') {
                component(user)?;
                host
            } else {
                authority
            };
            let (host, port) = authority_port(authority, 22)?;
            (host, port, path)
        } else {
            let (authority, path) = url.split_once(':').ok_or("unsupported remote transport")?;
            let host = if let Some((user, host)) = authority.split_once('@') {
                component(user)?;
                host
            } else {
                authority
            };
            (host, None, path)
        };
        if host.is_empty()
            || host.starts_with('-')
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            return Err("unsupported remote hostname".into());
        }
        let path = path.strip_suffix(".git").unwrap_or(path);
        for part in path.split('/') {
            component(part)?;
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            repository: path.into(),
        })
    }
}
fn authority_port(authority: &str, default: u16) -> Result<(&str, Option<u16>)> {
    match authority.split_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse()?;
            if port == 0 {
                return Err("invalid service port".into());
            }
            Ok((host, (port != default).then_some(port)))
        }
        None => Ok((authority, None)),
    }
}
pub(super) fn component(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('.')
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("unsupported remote path or account component".into());
    }
    Ok(())
}

/// Versioned sender identities: origin wins, other remote names have no priority.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteIdentities {
    pub preferred: Option<String>,
    pub alternatives: Vec<String>,
}
impl RemoteIdentities {
    const PREFIX: &str = "remotes-v1 ";
    const MAX_BYTES: usize = 8192;
    const MAX_REMOTES: usize = 16;

    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value.len() > Self::MAX_BYTES {
            return Err("repository identities exceed limit".into());
        }
        let identities = if let Some(json) = value.strip_prefix(Self::PREFIX) {
            serde_json::from_str::<Self>(json)?
        } else {
            Self {
                preferred: Some(value.into()),
                alternatives: vec![],
            }
        };
        if identities.alternatives.len() + usize::from(identities.preferred.is_some())
            > Self::MAX_REMOTES
            || identities.preferred.is_none() && identities.alternatives.is_empty()
        {
            return Err("invalid repository identity count".into());
        }
        for url in identities.preferred.iter().chain(&identities.alternatives) {
            Identity::parse(url)?;
        }
        Ok(identities)
    }
    pub(crate) fn encode(&self) -> Result<String> {
        // Preserve the single-identity wire format when no fallback is needed.
        let encoded = match (&self.preferred, self.alternatives.is_empty()) {
            (Some(url), true) => url.clone(),
            _ => format!("{}{}", Self::PREFIX, serde_json::to_string(self)?),
        };
        Self::parse(&encoded)?;
        Ok(encoded)
    }
}

/// Sender lookup uses Git's effective fetch URLs; receiver inventory remains repo-local.
pub(crate) fn repository_identity(
    mut query: impl FnMut(&[&str]) -> Result<(std::process::ExitStatus, Vec<u8>)>,
) -> Result<RemoteIdentities> {
    let (status, names) = query(&["remote"])?;
    if !status.success() || names.len() > 4096 {
        return Err("cannot read bounded repository remotes".into());
    }
    let names = std::str::from_utf8(&names)?;
    let names: Vec<_> = names.lines().collect();
    if names.len() > RemoteIdentities::MAX_REMOTES {
        return Err("repository has too many remotes for discovery".into());
    }
    let mut result = RemoteIdentities {
        preferred: None,
        alternatives: vec![],
    };
    let mut seen = Vec::new();
    // Read origin first even if Git returns a different ordering.
    for name in names
        .iter()
        .filter(|n| **n == "origin")
        .chain(names.iter().filter(|n| **n != "origin"))
    {
        let (status, bytes) = query(&["remote", "get-url", "--all", "--", name])?;
        let url = std::str::from_utf8(&bytes).ok().and_then(|text| {
            let mut lines = text.lines();
            let first = lines.next()?;
            (lines.next().is_none()).then_some(first)
        });
        let identity = url
            .filter(|_| status.success() && bytes.len() <= 4096)
            .and_then(|url| Identity::parse(url).ok());
        let Some(identity) = identity else {
            if *name == "origin" {
                return Err("repository needs one usable origin URL".into());
            }
            // A local/ambiguous secondary remote supplies no discovery evidence.
            continue;
        };
        if seen.contains(&identity) {
            continue;
        }
        seen.push(identity);
        if *name == "origin" {
            result.preferred = Some(url.unwrap().into());
        } else {
            result.alternatives.push(url.unwrap().into());
        }
    }
    result.encode()?;
    Ok(result)
}

#[cfg(test)]
mod remote_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn origin_is_preferred_and_arbitrary_remote_names_supply_deduplicated_fallbacks() {
        let identities = repository_identity(|args| {
            let text = match args {
                ["remote"] => "parent\norigin\nsame\nlocal\nambiguous\n",
                ["remote", "get-url", "--all", "--", "origin"] => {
                    "git@forge.example:agent/repo.git\n"
                }
                ["remote", "get-url", "--all", "--", "parent"] => {
                    "https://forge.example/org/repo\n"
                }
                ["remote", "get-url", "--all", "--", "same"] => "git@forge.example:org/repo.git\n",
                ["remote", "get-url", "--all", "--", "local"] => "/local/repo\n",
                ["remote", "get-url", "--all", "--", "ambiguous"] => {
                    "git@forge.example:a/repo\ngit@forge.example:b/repo\n"
                }
                _ => panic!("unexpected query: {args:?}"),
            };
            Ok((
                std::process::ExitStatus::from_raw(0),
                text.as_bytes().to_vec(),
            ))
        })
        .unwrap();
        assert_eq!(
            identities.preferred.as_deref(),
            Some("git@forge.example:agent/repo.git")
        );
        assert_eq!(identities.alternatives, ["https://forge.example/org/repo"]);
        let decoded = RemoteIdentities::parse(&identities.encode().unwrap()).unwrap();
        assert_eq!(decoded.alternatives, identities.alternatives);
    }
    #[test]
    fn malformed_origin_is_refused_and_originless_remotes_form_one_fallback_tier() {
        for bytes in [
            vec![],
            vec![b'x'; 4097],
            vec![255],
            b"git@example.org:a/repo\ngit@example.org:b/repo\n".to_vec(),
            b"ssh://user:secret@example.org/repo\n".to_vec(),
        ] {
            assert!(
                repository_identity(|args| Ok((
                    std::process::ExitStatus::from_raw(0),
                    if args == ["remote"] {
                        b"origin\n".to_vec()
                    } else {
                        bytes.clone()
                    }
                )))
                .is_err()
            );
        }
        let identities = repository_identity(|args| {
            Ok((
                std::process::ExitStatus::from_raw(0),
                match args {
                    ["remote"] => b"parent/project\nbackup\n".to_vec(),
                    ["remote", "get-url", "--all", "--", "parent/project"] => {
                        b"git@example.org:org/repo\n".to_vec()
                    }
                    ["remote", "get-url", "--all", "--", "backup"] => {
                        b"git@example.org:another/repo\n".to_vec()
                    }
                    _ => panic!("unexpected query"),
                },
            ))
        })
        .unwrap();
        assert!(identities.preferred.is_none());
        assert_eq!(identities.alternatives.len(), 2);
        assert!(RemoteIdentities::parse(&identities.encode().unwrap()).is_ok());
    }
    #[test]
    fn identity_sets_are_bounded_and_validate_all_urls() {
        for value in [
            "force-v1",
            "remotes-v2:{}",
            "remotes-v1 {}",
            "remotes-v1 {\"preferred\":null,\"alternatives\":[]}",
            "remotes-v1 {\"preferred\":null,\"alternatives\":[\"/local/path\"]}",
        ] {
            assert!(RemoteIdentities::parse(value).is_err(), "{value}");
        }
        let mut identities = RemoteIdentities {
            preferred: None,
            alternatives: vec!["git@example.org:org/repo".into()],
        };
        assert!(identities.encode().is_ok());
        identities
            .alternatives
            .resize(17, "git@example.org:org/repo".into());
        assert!(identities.encode().is_err());
        assert!(RemoteIdentities::parse(&"x".repeat(8193)).is_err());
        // The version marker cannot collide with a valid SCP-style hostname.
        assert_eq!(
            RemoteIdentities::parse("remotes-v1:org/repo")
                .unwrap()
                .preferred
                .as_deref(),
            Some("remotes-v1:org/repo")
        );
        assert!(
            RemoteIdentities::parse(
                "remotes-v1 {\"preferred\":null,\"alternatives\":[],\"extra\":true}"
            )
            .is_err()
        );
    }
}
