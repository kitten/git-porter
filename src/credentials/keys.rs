//! Receiver credential sets: one signature, no plaintext files, atomic activation.
//! @ref LLP 0001#ownership
use crate::{
    Result,
    credentials::derivation::Request,
    credentials::wrapping::{self, Bundle},
};
use ssh_key::{PrivateKey, PublicKey};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const FILES: [&str; 3] = [
    "publication.wrapped",
    "publication.pub",
    "publication.source.pub",
];
pub enum Choice {
    Create,
    Wrap(Box<PrivateKey>),
}
/// Advisory lock shared by create, import, rotation and pending provisioning.
pub struct Lock {
    file: File,
    data: PathBuf,
    session: crate::runtime::supervision::Session,
}
impl Lock {
    pub fn acquire(data: &Path) -> Result<Self> {
        owner_directory(data)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(data.join(".provision.lock"))?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err("unsafe provisioning lock".into());
        }
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another forwarder-key operation is active; complete or cancel it before starting key creation again".into());
        }
        Ok(Self {
            file,
            data: data.canonicalize()?,
            session: crate::runtime::supervision::Session::new()?,
        })
    }
}
impl Lock {
    pub fn check(&self, data: &Path) -> Result<()> {
        if data.canonicalize()? != self.data {
            return Err("provisioning lock does not cover this directory".into());
        }
        self.session.check()
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn data_directory() -> Result<PathBuf> {
    let path = match std::env::var_os("XDG_DATA_HOME") {
        Some(value) => PathBuf::from(value),
        None => PathBuf::from(
            std::env::var_os("HOME").ok_or("HOME is required when XDG_DATA_HOME is unset")?,
        )
        .join(".local/share"),
    }
    .join("git-porter");
    if !path.is_absolute() {
        return Err("XDG data home must be absolute".into());
    }
    Ok(path)
}
pub fn owner_directory(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.starts_with("/nix/store") {
        return Err("credential data directory must be absolute and outside the Nix store".into());
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(
                "credential directory must be account-owned and not writable by others".into(),
            );
        }
    } else {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    if path.canonicalize()?.starts_with("/nix/store") {
        return Err("credential directory resolves into the Nix store".into());
    }
    Ok(())
}
/// Read the pinned, owner-controlled credential set without unlocking it.
pub fn public(data: &Path) -> Result<PublicKey> {
    let file = |name: &str| {
        crate::server::publication::policy::runtime_file(&data.join(name), name == FILES[0])
    };
    let bundle = Bundle::read(File::open(file(FILES[0])?)?)?;
    let source = wrapping::read_public(&file(FILES[2])?)?;
    if !bundle.metadata.matches(&source)? {
        return Err("source public sidecar does not match wrapped bundle".into());
    }
    wrapping::read_public(&file(FILES[1])?)
}

/// Each artifact is a plain atomic file. The account lock serializes writers;
/// readers validate source binding and decrypted key correspondence.
pub fn install(
    lock: &Lock,
    data: &Path,
    bundle: &Bundle,
    public: &PublicKey,
    source: &PublicKey,
    replace: bool,
) -> Result<()> {
    lock.check(data)?;
    if !bundle.metadata.matches(source)? {
        return Err("source sidecar mismatch".into());
    }
    if public.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("forwarder keys must be Ed25519".into());
    }
    for name in FILES {
        let path = data.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            if !replace {
                return Err("forwarder credentials already exist; use key:create".into());
            }
            if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                return Err("credential files must be plain files; move the old credential layout aside before setup".into());
            }
            crate::server::publication::policy::runtime_file(&path, name == FILES[0])?;
        }
    }
    let mut wrapped = Vec::new();
    bundle.write(&mut wrapped)?;
    let values = [
        wrapped,
        (public.to_openssh().map_err(|e| e.to_string())? + "\n").into_bytes(),
        (source.to_openssh().map_err(|e| e.to_string())? + "\n").into_bytes(),
    ];
    // Publish ciphertext last: an interrupted multi-file replacement fails source
    // binding/correspondence validation instead of using another credential.
    for index in [1, 2, 0] {
        lock.check(data)?;
        crate::server::authorized::atomic(&data.join(FILES[index]), &values[index])?;
    }
    Ok(())
}

pub(crate) fn fulfill(
    lock: &Lock,
    data: &Path,
    choice: Choice,
    request: &Request,
    identity: age::x25519::Identity,
    replace: bool,
) -> Result<PublicKey> {
    let recipient = identity.to_public();
    drop(identity);
    fulfill_recipient(lock, data, choice, request, &recipient, replace)
}
fn fulfill_recipient(
    lock: &Lock,
    data: &Path,
    choice: Choice,
    request: &Request,
    recipient: &age::x25519::Recipient,
    replace: bool,
) -> Result<PublicKey> {
    lock.check(data)?;
    if !replace {
        ensure_create_only(lock, data)?;
    }
    let key = match choice {
        Choice::Create => PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| e.to_string())?,
        Choice::Wrap(key) => *key,
    };
    crate::server::publication::validate_private(&key)?;
    let public = key.public_key().clone();
    let plaintext = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| e.to_string())?;
    let bundle = Bundle {
        metadata: request.metadata.clone(),
        ciphertext: age::encrypt(recipient, plaintext.as_bytes())?,
    };
    install(lock, data, &bundle, &public, &request.source, true)?;
    Ok(public)
}

pub fn read_import(path: &Path) -> Result<Choice> {
    let bytes = if path == Path::new("-") {
        wrapping::read_bounded(std::io::stdin(), wrapping::MAX_KEY_SIZE)?
    } else {
        wrapping::read_bounded(
            File::open(crate::server::publication::policy::runtime_file(
                &path.canonicalize()?,
                true,
            )?)?,
            wrapping::MAX_KEY_SIZE,
        )?
    };
    Ok(Choice::Wrap(Box::new(wrapping::parse_private(&bytes)?)))
}

pub(crate) fn create_from_token(
    data: &Path,
    token: &wrapping::PublicWrapping,
    choice: Choice,
    replace: bool,
) -> Result<PublicKey> {
    let lock = Lock::acquire(data)?;
    fulfill_recipient(
        &lock,
        data,
        choice,
        &token.request,
        &token.recipient,
        replace,
    )
}
pub(crate) fn ensure_create_only(lock: &Lock, data: &Path) -> Result<()> {
    lock.check(data)?;
    for name in ["publication.wrapped", "publication.pub"] {
        match fs::symlink_metadata(data.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("forwarder key already exists; setup never replaces it".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::credentials::{
        keys::{self, Choice},
        wrapping,
    };
    use signature::Signer;
    #[test]
    fn create_only_refuses_each_forwarder_artifact_but_allows_source_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().canonicalize().unwrap();
        let lock = keys::Lock::acquire(&data).unwrap();
        std::fs::write(data.join("publication.source.pub"), b"recorded source").unwrap();
        assert!(keys::ensure_create_only(&lock, &data).is_ok());
        // Simulate another enrollment completing after setup's initial missing-key check.
        for name in ["publication.wrapped", "publication.pub"] {
            std::fs::write(data.join(name), b"concurrent artifact").unwrap();
            assert!(keys::ensure_create_only(&lock, &data).is_err());
            assert_eq!(
                std::fs::read(data.join(name)).unwrap(),
                b"concurrent artifact"
            );
            std::fs::remove_file(data.join(name)).unwrap();
        }
    }
    #[test]
    fn plain_storage_is_locked_and_replacement_is_explicit() {
        let t = tempfile::tempdir().unwrap();
        let data = t.path().canonicalize().unwrap();
        let source =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let request =
            crate::credentials::derivation::Request::generate(source.public_key().clone()).unwrap();
        let signature: ssh_key::Signature = source
            .try_sign(&request.metadata.challenge(source.public_key()).unwrap())
            .unwrap();
        let lock = keys::Lock::acquire(&data).unwrap();
        assert!(keys::Lock::acquire(&data).is_err());
        keys::fulfill(
            &lock,
            &data,
            Choice::Create,
            &request,
            request.identity(signature.as_bytes()).unwrap(),
            false,
        )
        .unwrap();
        let before = std::fs::read(data.join("publication.wrapped")).unwrap();
        assert!(keys::public(&data).is_ok());
        let bundle = wrapping::Bundle::read(&before[..]).unwrap();
        let public = keys::public(&data).unwrap();
        assert!(keys::install(&lock, &data, &bundle, &public, source.public_key(), false).is_err());
        assert_eq!(
            before,
            std::fs::read(data.join("publication.wrapped")).unwrap()
        );
        drop(lock);
        let recipient = request.identity(signature.as_bytes()).unwrap().to_public();
        let token = wrapping::PublicWrapping { request, recipient };
        assert!(keys::create_from_token(&data, &token, Choice::Create, false).is_err());
        assert_eq!(
            before,
            std::fs::read(data.join("publication.wrapped")).unwrap()
        );
        assert!(!data.join("credentials").exists());
    }
}
