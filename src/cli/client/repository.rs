//! Per-operation pinned repository context and sanitized Git commands.
//! @ref LLP 0002#client-git-configuration
use crate::Result;
use std::{
    path::Path,
    process::{Command, Stdio},
};
/// Resolve inherited repository selection once, then pin every local Git command.
pub(super) struct Repository {
    git_dir: String,
    work_tree: Option<String>,
}
impl Repository {
    pub(super) fn discover() -> Result<Self> {
        let git_dir = raw_git_output(&["rev-parse", "--path-format=absolute", "--git-dir"])?;
        let work_tree = if raw_git_output(&["rev-parse", "--is-bare-repository"])? == "true" {
            None
        } else {
            Some(raw_git_output(&["rev-parse", "--show-toplevel"])?)
        };
        Ok(Self { git_dir, work_tree })
    }
    pub(super) fn command(&self) -> Command {
        let mut command = crate::runtime::supervision::command("git");
        command.arg("--git-dir").arg(&self.git_dir);
        if let Some(work_tree) = &self.work_tree {
            command.arg("--work-tree").arg(work_tree);
        }
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("GIT_CONFIG_")
                || matches!(
                    name.as_ref(),
                    "GIT_DIR"
                        | "GIT_WORK_TREE"
                        | "GIT_COMMON_DIR"
                        | "GIT_INDEX_FILE"
                        | "GIT_OBJECT_DIRECTORY"
                        | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                        | "GIT_NAMESPACE"
                        | "GIT_SHALLOW_FILE"
                )
            {
                command.env_remove(key);
            }
        }
        command
    }

    pub(super) fn output(&self, args: &[&str]) -> Result<String> {
        output(self.command(), args)
    }
    pub(super) fn config_value(&self, key: &str) -> Option<String> {
        self.output(&["config", "--get", key]).ok()
    }

    pub(super) fn search_hint(&self) -> Result<Option<String>> {
        let result = self
            .command()
            .args(["config", "--null", "--get-all", "porter.searchRoot"])
            .stdin(Stdio::null())
            .output()?;
        if !result.status.success() && result.status.code() != Some(1) {
            return Err("cannot read the sender repository search hints".into());
        }
        let home = std::env::var_os("HOME").ok_or("HOME is required for searchRoot")?;
        let roots = if result.status.code() == Some(1) {
            home.to_str()
                .ok_or("HOME must be UTF-8 for repository hints")?
                .as_bytes()
        } else {
            &result.stdout
        };
        relative_hint(
            Path::new(self.work_tree.as_ref().unwrap_or(&self.git_dir)),
            Path::new(&home),
            roots,
        )
    }

    /// Mirror the original scripts: linked worktrees refer to their main checkout.
    pub(super) fn receiver_path(&self) -> Result<Option<String>> {
        let home = std::env::var_os("HOME").ok_or("HOME is required for a receiver path")?;
        let home = Path::new(&home).canonicalize()?;
        let common = self.output(&["rev-parse", "--path-format=absolute", "--git-common-dir"])?;
        let common = Path::new(&common).canonicalize()?;
        let checkout = if common.file_name().is_some_and(|name| name == ".git") {
            common
                .parent()
                .ok_or("Git directory has no parent")?
                .to_owned()
        } else {
            Path::new(self.work_tree.as_ref().unwrap_or(&self.git_dir)).canonicalize()?
        };
        Ok(checkout
            .strip_prefix(home)
            .ok()
            .and_then(|p| p.to_str())
            .filter(|p| super::transport::validate_path(p).is_ok())
            .map(str::to_owned))
    }

    pub(super) fn lookup_identity(&self) -> Result<String> {
        crate::server::discovery::repository_identity(|args| {
            let output = self
                .command()
                .args(args)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()?;
            Ok((output.status, output.stdout))
        })
        .and_then(|identities| identities.encode())
        .map_err(|error| format!("{error}; supply an explicit destination path").into())
    }
}

fn raw_git_output(args: &[&str]) -> Result<String> {
    output(crate::runtime::supervision::command("git"), args)
}
fn output(mut command: Command, args: &[&str]) -> Result<String> {
    let result = command
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(result.stdout)?
        .trim_end_matches('\n')
        .into())
}

fn relative_hint(checkout: &Path, home: &Path, roots: &[u8]) -> Result<Option<String>> {
    let checkout = checkout.canonicalize()?;
    for root in roots.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let root = std::str::from_utf8(root)?;
        let Ok(root) = crate::server::config::home_path(home, root) else {
            continue;
        };
        if let Ok(relative) = checkout.strip_prefix(root)
            && let Some(relative) = relative.to_str()
            && crate::runtime::protocol::relative_hint(relative).is_ok()
        {
            return Ok(Some(relative.into()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_contained_checkouts_send_one_relative_hint() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(home.join("git/kitten/repo")).unwrap();
        let checkout = home.join("git/kitten/repo");
        assert_eq!(
            relative_hint(&checkout, &home, b"git\0other\0")
                .unwrap()
                .as_deref(),
            Some("kitten/repo")
        );
        assert_eq!(relative_hint(&checkout, &home, b"missing\0").unwrap(), None);
        assert_eq!(
            relative_hint(&checkout, &home, b"git/kitten/repo\0").unwrap(),
            None
        );
        assert_eq!(relative_hint(&checkout, &home, b"").unwrap(), None);
    }
}
