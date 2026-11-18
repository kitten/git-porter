//! Verify OpenSSH session-bind and the exact userauth message before signing.
use crate::Result;
use crate::runtime::ssh_wire::take;
use signature::Verifier;
use ssh_key::{PublicKey, Signature};
pub(super) struct Binding {
    pub session: Vec<u8>,
    pub host: PublicKey,
}
pub(super) fn bind(mut input: &[u8], hosts: &[PublicKey]) -> Result<Binding> {
    if take(&mut input)? != b"session-bind@openssh.com" {
        return Err("unsupported agent extension".into());
    }
    let host = PublicKey::from_bytes(take(&mut input)?).map_err(|e| e.to_string())?;
    let session = take(&mut input)?.to_vec();
    let signature = Signature::try_from(take(&mut input)?).map_err(|e| e.to_string())?;
    if input != [0]
        || session.is_empty()
        || session.len() > 128
        || !hosts.iter().any(|h| h.key_data() == host.key_data())
    {
        return Err("untrusted or forwarded session binding".into());
    }
    host.key_data()
        .verify(&session, &signature)
        .map_err(|e| e.to_string())?;
    Ok(Binding { session, host })
}
pub(super) fn userauth(
    mut input: &[u8],
    binding: &Binding,
    user: &str,
    key: &PublicKey,
) -> Result<()> {
    if take(&mut input)? != binding.session || input.first() != Some(&50) {
        return Err("unbound userauth session".into());
    }
    input = &input[1..];
    if take(&mut input)? != user.as_bytes() || take(&mut input)? != b"ssh-connection" {
        return Err("wrong user or service".into());
    }
    let method = take(&mut input)?;
    if input.first() != Some(&1) {
        return Err("unsigned userauth request".into());
    }
    input = &input[1..];
    if take(&mut input)? != b"ssh-ed25519"
        || take(&mut input)? != key.to_bytes().map_err(|e| e.to_string())?
    {
        return Err("wrong userauth key".into());
    }
    match method {
        b"publickey" => (),
        b"publickey-hostbound-v00@openssh.com" => {
            if PublicKey::from_bytes(take(&mut input)?)
                .map_err(|e| e.to_string())?
                .key_data()
                != binding.host.key_data()
            {
                return Err("wrong hostbound key".into());
            }
        }
        _ => return Err("not an SSH publickey authentication request".into()),
    }
    if !input.is_empty() {
        return Err("trailing userauth data".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::ssh_wire::string;
    use signature::Signer;
    #[test]
    fn validates_host_proof_session_user_service_key_and_hostbound_message() {
        let host = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
        let wrong =
            ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                .unwrap();
        let signature = host.try_sign(b"session").unwrap();
        let signature: Vec<u8> = signature.try_into().unwrap();
        let mut input = Vec::new();
        string(&mut input, b"session-bind@openssh.com");
        string(&mut input, &host.public_key().to_bytes().unwrap());
        string(&mut input, b"session");
        string(&mut input, &signature);
        input.push(0);
        assert!(bind(&input, &[wrong.public_key().clone()]).is_err());
        let binding = bind(&input, &[host.public_key().clone()]).unwrap();
        *input.last_mut().unwrap() = 1;
        assert!(bind(&input, &[host.public_key().clone()]).is_err());
        let mut request = Vec::new();
        string(&mut request, b"session");
        request.push(50);
        string(&mut request, b"git");
        string(&mut request, b"ssh-connection");
        string(&mut request, b"publickey");
        request.push(1);
        string(&mut request, b"ssh-ed25519");
        string(&mut request, &wrong.public_key().to_bytes().unwrap());
        assert!(userauth(&request, &binding, "git", wrong.public_key()).is_ok());
        assert!(userauth(&request, &binding, "other", wrong.public_key()).is_err());
        assert!(userauth(&request, &binding, "git", host.public_key()).is_err());
        let mut bad = request.clone();
        bad[4] ^= 1;
        assert!(userauth(&bad, &binding, "git", wrong.public_key()).is_err());
        let mut bad = request.clone();
        bad.extend(b"suffix");
        assert!(userauth(&bad, &binding, "git", wrong.public_key()).is_err());
    }
}
