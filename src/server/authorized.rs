//! Scoped, duplicate-aware authorized_keys rendering and installation.
//! @ref LLP 0004#setup
use crate::Result;
use ssh_key::PublicKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn render(executable: &Path, key: &PublicKey) -> Result<String> {
    let command = format!(
        "{} internal:serve",
        quote(executable.to_str().ok_or("non-UTF8 executable")?)
    );
    if command.chars().any(char::is_control) || key.comment().chars().any(char::is_control) {
        return Err("control character in restricted key entry".into());
    }
    Ok(format!(
        "restrict,command=\"{}\" {}",
        command.replace('"', "\\\""),
        key.to_openssh().map_err(|e| e.to_string())?
    ))
}
fn tokens(line: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        // authorized_keys only unescapes backslash-double-quote. Other
        // backslashes remain literal, including shell single-quote escapes.
        if quoted && character == '\\' && chars.peek() == Some(&'"') {
            token.push(character);
            token.push(chars.next().unwrap());
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            token.push(character);
            continue;
        }
        if character.is_whitespace() && !quoted {
            if !token.is_empty() {
                result.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if !token.is_empty() {
        result.push(token);
    }
    result
}

fn key(line: &str) -> Option<PublicKey> {
    if line.trim_start().starts_with('#') {
        return None;
    }
    let tokens = tokens(line);
    for (index, token) in tokens.iter().enumerate() {
        if (token.starts_with("ssh-") || token.starts_with("ecdsa-") || token.starts_with("sk-"))
            && index + 1 < tokens.len()
            && let Ok(key) = PublicKey::from_openssh(&tokens[index..].join(" "))
        {
            return Some(key);
        }
    }
    None
}
pub fn preview(home: &Path, executable: &Path, keys: &[PublicKey]) -> Result<String> {
    let directory = home.join(".ssh");
    let path = directory.join("authorized_keys");
    for checked in [&directory, &path] {
        if let Ok(metadata) = fs::symlink_metadata(checked)
            && (metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o022 != 0)
        {
            return Err("authorized-key target is linked or not account-controlled; use account configuration management".into());
        }
    }
    let original = match fs::File::open(&path) {
        Ok(file) => String::from_utf8(
            crate::credentials::wrapping::read_bounded(file, 1024 * 1024)?.to_vec(),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    reconcile(&original, executable, keys)
}

fn marker(key: &PublicKey) -> String {
    format!(
        "# git-porter managed {}",
        key.fingerprint(ssh_key::HashAlg::Sha256)
    )
}

fn reconcile(original: &str, executable: &Path, keys: &[PublicKey]) -> Result<String> {
    let wanted: BTreeSet<_> = keys.iter().map(marker).collect();
    let mut lines = Vec::new();
    let mut entries: BTreeMap<ssh_key::public::KeyData, Vec<usize>> = BTreeMap::new();
    let mut original = original.lines().peekable();
    while let Some(line) = original.next() {
        // Revoke only a matching porter-owned restricted entry, preserving
        // unrelated entries even when a stale marker appears before them.
        if line.starts_with("# git-porter managed ")
            && !wanted.contains(line)
            && original.peek().is_some_and(|next| {
                next.starts_with("restrict,command=\"")
                    && key(next).is_some_and(|key| marker(&key) == line)
            })
        {
            original.next();
            continue;
        }
        if let Some(public) = key(line) {
            entries
                .entry(public.key_data().clone())
                .or_default()
                .push(lines.len());
        }
        lines.push(line.to_owned());
    }
    for public in keys {
        let rendered = render(executable, public)?;
        let marker = marker(public);
        let matches = entries.entry(public.key_data().clone()).or_default();
        match matches.as_slice() {
            [] => {
                lines.push(marker);
                matches.push(lines.len());
                lines.push(rendered);
            }
            [index] if *index > 0 && lines[*index - 1] == marker => lines[*index] = rendered,
            _ => return Err(format!("the same SSH key already has another authorized_keys entry (possibly unrestricted): {}. Remove or migrate that bypass explicitly before installing this restriction",public.fingerprint(ssh_key::HashAlg::Sha256)).into()),
        }
    }
    Ok(if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    })
}
pub fn install(home: &Path, expected: &str) -> Result<()> {
    let directory = home.join(".ssh");
    let path = directory.join("authorized_keys");
    if !directory.exists() {
        fs::create_dir_all(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    if fs::read_to_string(&path).ok().as_deref() == Some(expected) {
        return Ok(());
    }
    if path.exists() {
        let previous = fs::read(&path)?;
        atomic(
            &directory.join("authorized_keys.git-porter-backup"),
            &previous,
        )?;
    }
    atomic(&path, expected.as_bytes())
}
pub(crate) fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().ok_or("file has no directory")?;
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0)
    {
        return Err("refusing to replace a linked or unsafe managed file".into());
    }

    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

pub(crate) fn apply_or_explain(home: &Path, executable: &Path, keys: &[PublicKey]) -> Result<()> {
    let path = home.join(".ssh/authorized_keys");
    let readonly = fs::symlink_metadata(&path)
        .is_ok_and(|m| m.file_type().is_symlink() || m.mode() & 0o200 == 0);
    let explain = || -> Result<()> {
        crate::cli::terminal::warning(format_args!(
            "Setup could not update {} automatically. Add the restricted entries below through your SSH authorization configuration, such as an authorizedKeys option or a separate file that SSH is configured to read:",
            path.display()
        ));
        for key in keys {
            eprintln!("{}", render(executable, key)?);
        }
        Ok(())
    };
    if readonly {
        return explain();
    }
    let expected = preview(home, executable, keys)?;
    match install(home, &expected) {
        Ok(()) => Ok(()),
        Err(error)
            if error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                matches!(
                    e.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
                )
            }) =>
        {
            explain()
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn public() -> PublicKey {
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }
    fn update(original: &str, keys: &[PublicKey]) -> Result<String> {
        reconcile(original, Path::new("/porter"), keys)
    }
    #[test]
    fn indexed_reconciliation_revokes_only_owned_entries_and_is_idempotent() {
        let removed = public();
        let retained = public();
        let added = public();
        let original = format!(
            "# unrelated\n{}\n{}\n{}\n",
            retained.to_openssh().unwrap(),
            marker(&removed),
            render(Path::new("/old"), &removed).unwrap()
        );
        let mut duplicate = added.clone();
        duplicate.set_comment("new comment");
        let keys = [added, duplicate];
        let result = update(&original, &keys).unwrap();
        assert!(result.starts_with(&format!(
            "# unrelated\n{}\n",
            retained.to_openssh().unwrap()
        )));
        assert!(!result.contains(&marker(&removed)));
        assert_eq!(result.matches("# git-porter managed ").count(), 1);
        assert_eq!(update(&result, &keys).unwrap(), result);
        assert!(
            update(
                &format!("{result}{}\n", keys[0].to_openssh().unwrap()),
                &keys
            )
            .is_err()
        );
    }
    #[test]
    fn stale_markers_do_not_claim_unrelated_or_unrestricted_entries() {
        let stale = public();
        let other = public();
        for line in [
            other.to_openssh().unwrap(),
            render(Path::new("/porter"), &other).unwrap(),
            stale.to_openssh().unwrap(),
        ] {
            let original = format!("{}\n{line}\n", marker(&stale));
            assert_eq!(update(&original, &[]).unwrap(), original);
        }
    }
}
