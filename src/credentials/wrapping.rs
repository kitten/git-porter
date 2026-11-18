//! Domain-separated git-porter forwarder-key wrapping.
//!
//! Metadata is public. The encrypted bundle stays stable between key creations;
//! fresh session approval is separate from its reusable unlock derivation.

use crate::Result;
use bech32::{Bech32, Hrp, primitives::decode::CheckedHrpstring};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use signature::Verifier;
use ssh_key::PublicKey;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

const IDENTITY_HRP: &str = "git-porter-";
pub const MAX_KEY_SIZE: usize = 1024 * 1024;
const MAX_CIPHERTEXT_SIZE: usize = MAX_KEY_SIZE + 4096;
const MAX_BUNDLE_SIZE: usize = MAX_CIPHERTEXT_SIZE + 512;
const BUNDLE_HEADER: &[u8] = b"git-porter wrapped-key v2\n";

#[derive(Clone)]
pub struct Metadata {
    version: u8,
    fingerprint: [u8; 32],
    salt: [u8; 16],
}

impl Metadata {
    pub fn generate(public: &PublicKey) -> Result<Self> {
        require_ed25519(public)?;
        let mut salt = [0; 16];
        OsRng.try_fill_bytes(&mut salt)?;
        Ok(Self {
            version: 2,
            fingerprint: fingerprint(public)?,
            salt,
        })
    }

    pub fn parse(input: &str) -> Result<Self> {
        let lines: Vec<_> = input
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        if lines.len() != 1 {
            return Err("expected one public wrapping identity".into());
        }
        let decoded = CheckedHrpstring::new::<Bech32>(lines[0])
            .map_err(|_| "invalid wrapping identity encoding or checksum")?;
        let payload: Vec<_> = decoded.byte_iter().collect();
        if decoded.hrp() != Hrp::parse(IDENTITY_HRP)?
            || payload.len() != 49
            || !matches!(payload[0], 1 | 2)
        {
            return Err("unsupported wrapping identity format or version".into());
        }
        Ok(Self {
            version: payload[0],
            fingerprint: payload[1..33].try_into()?,
            salt: payload[33..49].try_into()?,
        })
    }

    pub fn encode(&self) -> Result<String> {
        let mut payload = vec![self.version];
        payload.extend(self.fingerprint);
        payload.extend(self.salt);
        Ok(bech32::encode_upper::<Bech32>(
            Hrp::parse(IDENTITY_HRP)?,
            &payload,
        )?)
    }

    pub fn current_version(&self) -> bool {
        self.version == 2
    }

    pub fn matches(&self, public: &PublicKey) -> Result<bool> {
        Ok(self.fingerprint == fingerprint(public)?)
    }

    pub fn challenge(&self, public: &PublicKey) -> Result<Vec<u8>> {
        require_ed25519(public)?;
        if !self.matches(public)? {
            return Err(format!(
                "source public key does not match wrapped metadata; expected {}",
                ssh_key::Fingerprint::Sha256(self.fingerprint)
            )
            .into());
        }
        let mut challenge = if self.version == 2 {
            b"git-porter/v2/publication\0"
        } else {
            b"git-porter/v1/publication\0"
        }
        .to_vec();
        challenge.extend(self.salt);
        Ok(challenge)
    }

    // @ref LLP 0001#signing
    pub fn from_signature(
        &self,
        public: &PublicKey,
        signature: &ssh_key::Signature,
    ) -> Result<age::x25519::Identity> {
        let challenge = self.challenge(public)?;
        public
            .key_data()
            .verify(&challenge, signature)
            .map_err(|_| "source agent returned an invalid wrapping signature")?;
        // The agent library owns ordinary signature buffers. Memory wiping is
        // best effort; an extra zeroizing copy would not erase those originals.
        let mut info = if self.version == 2 {
            b"git-porter/v2/publication/x25519\0"
        } else {
            b"git-porter/v1/publication/x25519\0"
        }
        .to_vec();
        info.extend(self.fingerprint);
        let mut secret = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(&self.salt), signature.as_bytes())
            .expand(&info, secret.as_mut())
            .map_err(|_| "wrapping derivation failed")?;
        let encoded = Zeroizing::new(bech32::encode_upper::<Bech32>(
            Hrp::parse("age-secret-key-")?,
            secret.as_ref(),
        )?);
        encoded
            .parse()
            .map_err(|_| "cannot construct derived age identity".into())
    }
}

fn fingerprint(public: &PublicKey) -> Result<[u8; 32]> {
    Ok(Sha256::digest(public.to_bytes().map_err(|e| e.to_string())?).into())
}

fn require_ed25519(public: &PublicKey) -> Result<()> {
    if !matches!(public.key_data(), ssh_key::public::KeyData::Ed25519(_)) {
        return Err("wrapping requires an ordinary Ed25519 source identity".into());
    }
    Ok(())
}

pub fn read_public(path: &Path) -> Result<PublicKey> {
    PublicKey::from_openssh(fs::read_to_string(path)?.trim())
        .map_err(|_| "invalid configured SSH public identity".into())
}

pub fn decrypt_identity(
    identity: &age::x25519::Identity,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|_| "invalid wrapped credential")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| "cannot unlock forwarder key with the sender identity")?;
    // Read through EOF before exposing plaintext, so truncation/authentication
    // failure cannot result in loading a partially verified credential.
    let mut plaintext = Zeroizing::new(Vec::new());
    (&mut reader)
        .take(MAX_KEY_SIZE as u64 + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| "wrapped credential authentication failed")?;
    if plaintext.len() > MAX_KEY_SIZE {
        return Err("wrapped credential exceeds size limit".into());
    }
    Ok(plaintext)
}

/// The bundle stores only public derivation metadata and encrypted key bytes.
/// Publishing never rewrites the bundle.
pub struct Bundle {
    pub metadata: Metadata,
    pub ciphertext: Vec<u8>,
}

pub fn read_bounded(reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds credential size limit".into());
    }
    Ok(bytes)
}

pub fn parse_private(plaintext: &[u8]) -> Result<ssh_key::PrivateKey> {
    if plaintext.len() > MAX_KEY_SIZE {
        return Err("input exceeds credential size limit".into());
    }
    let key = ssh_key::PrivateKey::from_openssh(plaintext)
        .map_err(|_| "credential must be an unencrypted Ed25519 OpenSSH private key")?;
    if key.is_encrypted() || key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("credential must be an unencrypted Ed25519 OpenSSH private key".into());
    }
    Ok(key)
}

impl Bundle {
    pub fn read(reader: impl Read) -> Result<Self> {
        let bytes = read_bounded(reader, MAX_BUNDLE_SIZE)?;
        let (payload, version) = if let Some(payload) = bytes.strip_prefix(BUNDLE_HEADER) {
            (payload, 2)
        } else if let Some(payload) = bytes.strip_prefix(b"git-porter wrapped-key v1\n") {
            (payload, 1)
        } else {
            return Err(
                "unsupported wrapped-key format; only git-porter v1/v2 bundles may be upgraded"
                    .into(),
            );
        };
        let newline = payload
            .iter()
            .position(|byte| *byte == b'\n')
            .filter(|position| *position <= 256)
            .ok_or("missing wrapped-key derivation metadata")?;
        let metadata = Metadata::parse(std::str::from_utf8(&payload[..newline])?)?;
        if metadata.version != version {
            return Err("bundle header and metadata versions disagree".into());
        }
        let ciphertext = &payload[newline + 1..];
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Err("invalid wrapped-key ciphertext size".into());
        }
        Ok(Self {
            metadata,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub fn write(&self, mut output: impl Write) -> Result<()> {
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Err("invalid wrapped-key ciphertext size".into());
        }
        output.write_all(if self.metadata.version == 2 {
            BUNDLE_HEADER
        } else {
            b"git-porter wrapped-key v1\n"
        })?;
        writeln!(output, "{}", self.metadata.encode()?)?;
        output.write_all(&self.ciphertext)?;
        Ok(())
    }
}

#[cfg(test)]
mod lock_tests {
    #[test]
    fn bundle_lock_serializes_different_repositories_and_key_creation() {
        let temp = tempfile::tempdir().unwrap();
        let first = crate::credentials::keys::Lock::acquire(temp.path()).unwrap();
        assert!(crate::credentials::keys::Lock::acquire(temp.path()).is_err());
        drop(first);
        assert!(crate::credentials::keys::Lock::acquire(temp.path()).is_ok());
    }
}

#[cfg(test)]
mod format_tests {
    use crate::credentials::{
        derivation::Request,
        wrapping::{self, Bundle, Metadata},
    };
    use signature::Signer;
    #[test]
    fn wrapping_roundtrip_and_domain_separation() {
        let source =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let private =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let text = private.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let request = Request::new(
            source.public_key().clone(),
            Metadata::generate(source.public_key()).unwrap(),
        )
        .unwrap();
        let signature: ssh_key::Signature = source
            .try_sign(&request.metadata.challenge(source.public_key()).unwrap())
            .unwrap();
        let response = signature.as_bytes();
        let identity = request.identity(response).unwrap();
        let bundle = Bundle {
            metadata: request.metadata,
            ciphertext: age::encrypt(&identity.to_public(), text.as_bytes()).unwrap(),
        };
        let mut encoded = Vec::new();
        bundle.write(&mut encoded).unwrap();
        let bundle = Bundle::read(&encoded[..]).unwrap();
        let plaintext = wrapping::decrypt_identity(&identity, &bundle.ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), text.as_bytes());
        let challenge = bundle.metadata.challenge(source.public_key()).unwrap();
        assert!(challenge.starts_with(b"git-porter/v2/publication\0"));
        let mut foreign = b"age-plugin-sshagent/v1/derive\0".to_vec();
        foreign.extend_from_slice(&challenge[b"git-porter/v2/publication\0".len()..]);
        let signature: ssh_key::Signature = source.try_sign(&foreign).unwrap();
        assert!(
            bundle
                .metadata
                .from_signature(source.public_key(), &signature)
                .is_err()
        );
        assert!(Bundle::read(&b"git-ssh-access wrapped-key v1\n"[..]).is_err());
        assert!(Metadata::parse("AGE-PLUGIN-SSHAGENT-1BAD").is_err());
    }
    #[test]
    fn existing_v1_bundle_stays_readable_without_upgrading_or_rewriting_it() {
        let source =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let mut metadata = Metadata::generate(source.public_key()).unwrap();
        metadata.version = 1;
        let request = Request::new(source.public_key().clone(), metadata).unwrap();
        let signature: ssh_key::Signature = source
            .try_sign(&request.metadata.challenge(source.public_key()).unwrap())
            .unwrap();
        let identity = request.identity(signature.as_bytes()).unwrap();
        let bundle = Bundle {
            metadata: request.metadata,
            ciphertext: age::encrypt(&identity.to_public(), b"forge-key").unwrap(),
        };
        let mut encoded = Vec::new();
        bundle.write(&mut encoded).unwrap();
        let restored = Bundle::read(&encoded[..]).unwrap();
        assert!(!restored.metadata.current_version());
        assert_eq!(
            &*wrapping::decrypt_identity(&identity, &restored.ciphertext).unwrap(),
            b"forge-key"
        );
        let mut roundtrip = Vec::new();
        restored.write(&mut roundtrip).unwrap();
        assert_eq!(encoded, roundtrip);
    }
    #[test]
    fn publication_import_accepts_only_ed25519() {
        use ssh_key::{
            Mpint, PrivateKey,
            private::{KeypairData, RsaKeypair, RsaPrivateKey},
            public::RsaPublicKey,
        };
        let integer = |value| Mpint::from_positive_bytes(&[value]).unwrap();
        // A codec-only RSA fixture: rejecting its algorithm needs no RSA key generation.
        let rsa = PrivateKey::new(
            KeypairData::Rsa(RsaKeypair {
                public: RsaPublicKey {
                    e: integer(3),
                    n: integer(55),
                },
                private: RsaPrivateKey {
                    d: integer(27),
                    iqmp: integer(1),
                    p: integer(5),
                    q: integer(11),
                },
            }),
            "",
        )
        .unwrap()
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap();
        assert!(PrivateKey::from_openssh(rsa.as_bytes()).is_ok());
        assert!(wrapping::parse_private(rsa.as_bytes()).is_err());
        let ed = PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap();
        assert!(wrapping::parse_private(ed.as_bytes()).is_ok());
        assert!(wrapping::parse_private(b"not a private key").is_err());
        assert!(wrapping::parse_private(&vec![0; wrapping::MAX_KEY_SIZE + 1]).is_err());
    }
}

/// Public enrollment token: source key, derivation metadata and age recipient.
/// It deliberately contains neither the signature nor the derived private identity.
pub struct PublicWrapping {
    pub request: crate::credentials::derivation::Request,
    pub recipient: age::x25519::Recipient,
}
impl PublicWrapping {
    pub fn encode(&self) -> Result<String> {
        let request = self.request.encode()?;
        let mut bytes = vec![1];
        bytes.extend(u16::try_from(request.len())?.to_be_bytes());
        bytes.extend(request);
        bytes.extend(self.recipient.to_string().bytes());
        Ok(bech32::encode_upper::<Bech32>(
            Hrp::parse("git-porter-wrap")?,
            &bytes,
        )?)
    }
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 4096 {
            return Err("public wrapping token exceeds limit".into());
        }
        let decoded = CheckedHrpstring::new::<Bech32>(text.trim())
            .map_err(|_| "invalid public wrapping token checksum or encoding")?;
        let bytes: Vec<_> = decoded.byte_iter().collect();
        if decoded.hrp() != Hrp::parse("git-porter-wrap")? || bytes.len() < 4 || bytes[0] != 1 {
            return Err("unsupported public wrapping token version".into());
        }
        let size = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        let rest = bytes.get(3..).ok_or("truncated public wrapping token")?;
        let request = crate::credentials::derivation::Request::parse(
            rest.get(..size)
                .ok_or("truncated public wrapping request")?,
        )?;
        if !request.metadata.current_version() {
            return Err("public wrapping token requires current derivation domain".into());
        }
        let recipient = std::str::from_utf8(
            rest.get(size..)
                .ok_or("missing public wrapping recipient")?,
        )?
        .parse()
        .map_err(|_| "invalid public wrapping recipient")?;
        Ok(Self { request, recipient })
    }
    pub fn is_token(text: &str) -> bool {
        text.trim()
            .to_ascii_lowercase()
            .starts_with("git-porter-wrap1")
    }
}
