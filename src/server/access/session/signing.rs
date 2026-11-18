//! Fresh approval validation and memory-only unlocking; stored ciphertext stays unchanged.
//! @ref LLP 0001#ownership
use crate::{
    Result, credentials::wrapping, runtime::push_result::Reason,
    server::publication::policy::Policy,
};
use std::fs;

pub(super) fn unlock(
    policy: &Policy,
    reason: &mut Reason,
    approval: crate::credentials::derivation::Approval,
    sign: impl FnOnce(&crate::credentials::derivation::PublishRequest) -> Result<Vec<u8>>,
) -> Result<ssh_key::PrivateKey> {
    *reason = Reason::CredentialsUnavailable;
    let bundle = wrapping::Bundle::read(fs::File::open(&policy.wrapped)?)?;
    let source = wrapping::read_public(&policy.source)?;
    let expected = wrapping::read_public(&policy.public)?;
    if expected.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err("forwarder keys must be Ed25519".into());
    }
    let derive =
        crate::credentials::derivation::PublishRequest::new(source, bundle.metadata, approval)?;

    *reason = Reason::SenderRefused;
    let response = zeroize::Zeroizing::new(sign(&derive)?);

    let identity = derive.identity(&response)?;
    *reason = Reason::CredentialsUnavailable;
    drop(response);
    let plaintext = wrapping::decrypt_identity(&identity, &bundle.ciphertext)?;
    drop(identity);
    let private = wrapping::parse_private(&plaintext)?;
    drop(plaintext);
    if private.public_key().key_data() != expected.key_data() {
        return Err("publication public sidecar does not match wrapped key".into());
    }
    Ok(private)
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;

    #[test]
    fn credential_failures_are_classified_at_the_correct_boundary() {
        for (failure, expected_reason, message) in [
            ("success", Reason::CredentialsUnavailable, ""),
            (
                "source",
                Reason::CredentialsUnavailable,
                "source public key does not match",
            ),
            (
                "public",
                Reason::CredentialsUnavailable,
                "public sidecar does not match",
            ),
            ("refused", Reason::SenderRefused, "sender refused signing"),
            ("signature", Reason::SenderRefused, "approval signature"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let key = || {
                ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                    .unwrap()
            };
            let source = key();
            let forwarder = key();
            let other = key();
            let metadata = wrapping::Metadata::generate(source.public_key()).unwrap();
            let signature: ssh_key::Signature = source
                .try_sign(&metadata.challenge(source.public_key()).unwrap())
                .unwrap();
            let identity = metadata
                .from_signature(source.public_key(), &signature)
                .unwrap();
            let plaintext = forwarder.to_openssh(ssh_key::LineEnding::LF).unwrap();
            let bundle = wrapping::Bundle {
                metadata,
                ciphertext: age::encrypt(&identity.to_public(), plaintext.as_bytes()).unwrap(),
            };
            let policy = Policy::read(
                directory.path(),
                &directory.path().join("known_hosts"),
                &Default::default(),
            )
            .unwrap();
            bundle
                .write(fs::File::create(&policy.wrapped).unwrap())
                .unwrap();
            for (path, public) in [
                (
                    &policy.source,
                    if failure == "source" {
                        other.public_key()
                    } else {
                        source.public_key()
                    },
                ),
                (
                    &policy.public,
                    if failure == "public" {
                        other.public_key()
                    } else {
                        forwarder.public_key()
                    },
                ),
            ] {
                fs::write(path, public.to_openssh().unwrap()).unwrap();
            }
            let original = fs::read(&policy.wrapped).unwrap();
            let mut captured = None;
            let mut first_nonce = None;
            let mut called = false;
            let mut reason = Reason::PolicyRefused;
            let approval = crate::credentials::derivation::Approval::new(
                "/receiver/repo",
                "git@forge.example:org/repo",
                "refs/heads/work/test",
                &"a".repeat(40),
                "ff",
                "",
            )
            .unwrap();
            let result = unlock(&policy, &mut reason, approval, |request| {
                called = true;
                first_nonce = Some(request.approval.nonce);
                if failure == "refused" {
                    return Err("sender refused signing".into());
                }
                if failure == "signature" {
                    return Ok(vec![0; 128]);
                }
                let mut response = Vec::new();
                for challenge in [
                    request.current.metadata.challenge(source.public_key())?,
                    request.approval_challenge()?,
                ] {
                    let signature: ssh_key::Signature = source.try_sign(&challenge).unwrap();
                    response.extend_from_slice(signature.as_bytes());
                }
                captured = Some(response.clone());
                Ok(response)
            });
            if failure == "success" {
                assert_eq!(result.unwrap().public_key(), forwarder.public_key());
                let approval = crate::credentials::derivation::Approval::new(
                    "/receiver/repo",
                    "git@forge.example:org/repo",
                    "refs/heads/work/test",
                    &"a".repeat(40),
                    "ff",
                    "",
                )
                .unwrap();
                let replay = unlock(&policy, &mut reason, approval, |request| {
                    assert_ne!(Some(request.approval.nonce), first_nonce);
                    // The fixed part is still valid, but the complete old response
                    // must not authorize a fresh receiver session.
                    request
                        .current
                        .identity(&captured.as_ref().unwrap()[..64])?;
                    Ok(captured.take().unwrap())
                });
                assert!(
                    replay
                        .unwrap_err()
                        .to_string()
                        .contains("approval signature")
                );
            } else {
                let error = result.unwrap_err();
                assert_eq!(reason, expected_reason, "{failure}: {error}");
                assert!(error.to_string().contains(message), "{failure}: {error}");
            }
            assert_eq!(called, failure != "source", "{failure}");
            assert_eq!(fs::read(&policy.wrapped).unwrap(), original, "{failure}");
        }
    }
}
