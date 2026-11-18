//! Trusted receiver policy, independent of repository/client Git configuration.
//! @ref LLP 0000#boundary
use crate::Result;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub data: PathBuf,
    pub home: PathBuf,
    pub git: PathBuf,
    pub ssh: PathBuf,
    pub prefixes: Vec<String>,
    #[serde(with = "public_keys")]
    pub keys: Vec<ssh_key::PublicKey>,
    pub publication: crate::server::publication::policy::Policy,
    pub discovery: crate::server::discovery::Options,
}

/// Resolve and canonicalize existing roots in the receiver account, never cwd.
pub(crate) fn home_path(home: &Path, value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        return Err("search roots must not be empty".into());
    }
    let path = if matches!(value, "~" | "$HOME") {
        home.to_owned()
    } else if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("$HOME/"))
    {
        home.join(rest.trim_start_matches('/'))
    } else {
        home.join(value)
    };
    Ok(path.canonicalize().map_err(|error| {
        format!(
            "cannot resolve search root {value:?} against {}: {error}",
            home.display()
        )
    })?)
}

pub fn executable(name: &str) -> Result<PathBuf> {
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        if !directory.is_absolute() {
            continue;
        }
        let path = directory.join(name);
        if fs::metadata(&path).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
            return Ok(path.canonicalize()?);
        }
    }
    Err(format!("required executable not found: {name}").into())
}

pub(crate) fn single<'a>(
    values: &'a BTreeMap<String, Vec<String>>,
    key: &str,
) -> Result<Option<&'a str>> {
    match values.get(key).map(Vec::as_slice) {
        None => Ok(None),
        Some([value]) => Ok(Some(value)),
        _ => Err("receiver setup repeats a setting that accepts only one value".into()),
    }
}

pub(crate) fn boolean(values: &BTreeMap<String, Vec<String>>, key: &str) -> Result<bool> {
    match single(values, key)? {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err("receiver setup contains a boolean value other than true or false".into()),
    }
}

fn trusted(path: &Path) -> Result<()> {
    let link = fs::symlink_metadata(path)?;
    if link.file_type().is_symlink() {
        if link.uid() != unsafe { libc::geteuid() } && link.uid() != 0 {
            return Err("policy link must be account-controlled".into());
        }
        let target = path.canonicalize()?;
        if target.starts_with("/nix/store") && fs::metadata(&target)?.mode() & 0o222 == 0 {
            return Ok(());
        }
    }
    let metadata = fs::metadata(path)?;
    // Root-owned immutable Nix policy is valid; writable policy is account-owned.
    if ![0, unsafe { libc::geteuid() }].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(format!("policy path must be owner-controlled: {}", path.display()).into());
    }
    Ok(())
}

impl ServerConfig {
    /// Home is always the outer boundary; strict roots can only narrow it.
    pub(crate) fn permits_path(&self, path: &Path) -> bool {
        path.starts_with(&self.home)
            && self
                .discovery
                .roots
                .iter()
                .any(|root| path.starts_with(root))
    }

    pub fn read() -> Result<Self> {
        Self::read_account(false)
    }
    pub(crate) fn for_setup() -> Result<Self> {
        Self::read_account(true)
    }
    fn read_account(planning_setup: bool) -> Result<Self> {
        let home = PathBuf::from(
            std::env::var_os("HOME").ok_or("HOME is required for receiver hooks and transport")?,
        );
        let data = crate::credentials::keys::data_directory()?;
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".cache"))
            .join("git-porter");
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        Self::read_files(
            &[xdg.join("git/config"), home.join(".gitconfig")],
            &home,
            &data,
            &cache,
            planning_setup,
        )
    }

    /// Explicit environment dependency for isolated in-process callers.
    pub fn read_environment(path: &Path, home: &Path, data: &Path, cache: &Path) -> Result<Self> {
        Self::read_files(&[path.to_owned()], home, data, cache, false)
    }
    fn read_files(
        paths: &[PathBuf],
        home: &Path,
        data: &Path,
        cache: &Path,
        planning_setup: bool,
    ) -> Result<Self> {
        let git = executable("git")?;
        let ssh = executable("ssh")?;
        let mut bytes = Vec::new();
        for path in paths {
            match fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
                Ok(_) => (),
            }
            trusted(path.parent().ok_or("config has no parent")?)?;
            trusted(path)?;
            if !fs::metadata(path)?.is_file() || fs::metadata(path)?.len() > 65536 {
                return Err("global Git config must be a regular file at most 64 KiB".into());
            }
            let output = Command::new(&git)
                .env_clear()
                .env("LC_ALL", "C")
                .args(["config", "--null", "--no-includes", "--file"])
                .arg(path)
                .arg("--list")
                .stdin(Stdio::null())
                .output()?;
            if !output.status.success() {
                return Err("invalid global Git configuration".into());
            }
            bytes.extend(output.stdout);
        }
        let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for record in bytes.split(|b| *b == 0).filter(|v| !v.is_empty()) {
            let record = std::str::from_utf8(record)?;
            let (key, value) = record
                .split_once('\n')
                .map_or((record, None), |(k, v)| (k, Some(v)));
            if !key.starts_with("porter.") {
                continue;
            }
            let value = value.ok_or("policy values must be explicit")?;
            if !matches!(
                key,
                "porter.destination"
                    | "porter.allowedpushprefix"
                    | "porter.authorizedkey"
                    | "porter.searchstrict"
                    | "porter.searchroot"
            ) && !crate::server::publication::policy::policy_setting(key)
            {
                return Err("receiver setup contains an unsupported setting".into());
            }
            values.entry(key.into()).or_default().push(value.into());
        }
        let absolute = |p: &Path| -> Result<PathBuf> {
            if !p.is_absolute() {
                return Err("server paths must be absolute".into());
            }
            Ok(p.canonicalize()?)
        };
        let home = absolute(home)?;
        let data = if planning_setup
            && fs::symlink_metadata(data).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            if !data.is_absolute() {
                return Err("data directory must be absolute".into());
            }
            data.to_owned()
        } else {
            let data = absolute(data)?;
            trusted(&data)?;
            data
        };
        let publication = crate::server::publication::policy::Policy::read(
            &data,
            &home.join(".ssh/known_hosts"),
            &values,
        )?;
        let mut search_roots = values
            .get("porter.searchroot")
            .into_iter()
            .flatten()
            .map(|value| home_path(&home, value))
            .collect::<Result<Vec<_>>>()?;
        let strict = boolean(&values, "porter.searchstrict")?;
        if !strict || search_roots.is_empty() {
            search_roots.push(home.clone());
        }
        if search_roots.iter().any(|p| !p.starts_with(&home)) {
            return Err("receiver search roots must stay within the account home directory".into());
        }
        if search_roots.iter().any(|p| !p.is_dir()) {
            return Err("search roots must be directories".into());
        }
        let depth = 6;
        let excludes = vec!["node_modules".into(), "target".into(), "Library".into()];
        let cache = cache.to_path_buf();
        if !cache.is_absolute() {
            return Err("XDG cache home must be absolute".into());
        }
        let discovery = crate::server::discovery::Options {
            roots: search_roots,
            strict,
            depth,
            excludes,
            cache,
        };
        let prefixes = values
            .remove("porter.allowedpushprefix")
            .unwrap_or_default();
        for prefix in &prefixes {
            if prefix.is_empty()
                || !prefix.ends_with('/')
                || prefix
                    .split('/')
                    .any(|v| v == "." || v == ".." || v.starts_with('.'))
                || !prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@._/-".contains(&b))
                || prefix.contains("//")
            {
                return Err(
                    "allowed push prefixes must be literal branch directory prefixes".into(),
                );
            }
        }
        let mut keys = Vec::new();
        for value in values.remove("porter.authorizedkey").unwrap_or_default() {
            if value.chars().any(char::is_control) {
                return Err("control character in public key".into());
            }
            let key = ssh_key::PublicKey::from_openssh(&value).map_err(|e| e.to_string())?;
            if key.algorithm() != ssh_key::Algorithm::Ed25519 {
                return Err("receiver access keys must be Ed25519 public keys".into());
            }
            if !keys
                .iter()
                .any(|k: &ssh_key::PublicKey| k.key_data() == key.key_data())
            {
                keys.push(key);
            }
        }
        Ok(Self {
            data,
            home,
            git,
            ssh,
            prefixes,
            keys,
            publication,
            discovery,
        })
    }
}

/// Private snapshot, created after serve validates account policy and resolves paths.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookContext {
    pub version: u8,
    pub config: ServerConfig,
    pub publication: Option<PathBuf>,
    pub mode: String,
    pub reference: Option<String>,
    pub sha: Option<String>,
    pub observed: Option<String>,
}
impl ServerConfig {
    pub(crate) fn tool_path(&self) -> Result<std::ffi::OsString> {
        Ok(std::env::join_paths([
            self.git
                .parent()
                .ok_or("invalid hook Git executable path")?,
            self.ssh
                .parent()
                .ok_or("invalid hook SSH executable path")?,
        ])?)
    }
    pub fn hook_context(&self) -> HookContext {
        HookContext {
            version: 1,
            config: self.clone(),
            publication: None,
            mode: "ff".into(),
            reference: None,
            sha: None,
            observed: None,
        }
    }
}
impl HookContext {
    pub fn encode(&self) -> Result<String> {
        let text = serde_json::to_string(self)?;
        if text.len() > 65536 {
            return Err("hook context exceeds 64 KiB".into());
        }
        Ok(text)
    }
    pub fn read() -> Result<Self> {
        let text = std::env::var("GIT_PORTER_HOOK_CONTEXT")
            .map_err(|_| "missing private hook context; receive must go through internal:serve")?;
        if text.len() > 65536 {
            return Err("hook context exceeds 64 KiB".into());
        }
        let context: Self =
            serde_json::from_str(&text).map_err(|e| format!("invalid hook context: {e}"))?;
        if context.version != 1 {
            return Err("unsupported hook context version".into());
        }
        if !matches!(context.mode.as_str(), "ff" | "force" | "lease") {
            return Err("invalid hook context mode".into());
        }
        let c = &context.config;
        if [
            &c.home,
            &c.data,
            &c.git,
            &c.ssh,
            &c.discovery.cache,
            &c.publication.wrapped,
            &c.publication.source,
            &c.publication.public,
            &c.publication.known_hosts,
        ]
        .into_iter()
        .any(|p| !p.is_absolute())
            || c.discovery.roots.iter().any(|p| !p.is_absolute())
            || context
                .publication
                .as_ref()
                .is_some_and(|p| !p.is_absolute())
        {
            return Err("hook context paths must be absolute".into());
        }
        if c.data.parent().is_none() {
            return Err("invalid hook data directory".into());
        }
        c.tool_path()?;
        if context.reference.is_some() != context.sha.is_some()
            || context.mode == "lease"
                && (context.reference.is_none() || context.observed.is_none())
            || context.publication.is_some() && context.reference.is_none()
        {
            return Err("incomplete hook operation context".into());
        }
        Ok(context)
    }
}
mod public_keys {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(
        keys: &[ssh_key::PublicKey],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        keys.iter()
            .map(|k| k.to_openssh())
            .collect::<Result<Vec<_>, _>>()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<ssh_key::PublicKey>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|k| ssh_key::PublicKey::from_openssh(&k).map_err(serde::de::Error::custom))
            .collect()
    }
}
