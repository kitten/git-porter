//! One bounded metadata layout for identity reads and cache invalidation.
//! @ref LLP 0002#inventory-and-learned-structures
use crate::Result;
use std::{
    fs,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub(super) struct Layout {
    pub gitdir: PathBuf,
    pub common: PathBuf,
    pub pointers: Vec<(PathBuf, Option<Vec<u8>>)>,
}

fn pointer(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("repository pointers must be plain regular files".into());
    }
    // Nonblocking + fstat also protect the metadata/open race against a FIFO swap.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("repository pointers must be regular files".into());
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("repository pointer exceeds 4096 bytes".into());
    }
    Ok(bytes)
}
fn text(bytes: &[u8]) -> Result<&str> {
    Ok(std::str::from_utf8(bytes)?.trim_end_matches(['\n', '\r']))
}
pub(super) fn resolve(path: &Path) -> Result<Layout> {
    let marker = path.join(".git");
    let mut pointers = Vec::new();
    let gitdir = match fs::symlink_metadata(&marker) {
        Ok(metadata)
            if metadata.is_dir() || metadata.file_type().is_symlink() && marker.is_dir() =>
        {
            marker
        }
        Ok(_) => {
            let bytes = pointer(&marker)?;
            let target = text(&bytes)?
                .strip_prefix("gitdir: ")
                .filter(|p| !p.is_empty())
                .ok_or("invalid gitdir pointer")?;
            let target = path.join(target);
            pointers.push((marker, Some(bytes)));
            target
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            pointers.push((marker, None));
            path.to_owned()
        }
        Err(error) => return Err(error.into()),
    }
    .canonicalize()?;
    let common_path = gitdir.join("commondir");
    let common = match fs::symlink_metadata(&common_path) {
        Ok(_) => {
            let bytes = pointer(&common_path)?;
            let target = text(&bytes)?;
            if target.is_empty() {
                return Err("empty commondir".into());
            }
            let target = gitdir.join(target).canonicalize()?;
            pointers.push((common_path, Some(bytes)));
            target
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            pointers.push((common_path, None));
            gitdir.clone()
        }
        Err(error) => return Err(error.into()),
    };
    if !gitdir.join("HEAD").is_file() || !common.join("objects").is_dir() {
        return Err("not a repository".into());
    }
    Ok(Layout {
        gitdir,
        common,
        pointers,
    })
}
