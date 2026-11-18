//! Sender participation in a receiver-approved pending key creation.
//! @ref LLP 0001#ownership
use super::destination_host;
use crate::{
    Result,
    runtime::protocol::{Budget, DeadlineIo, Kind},
};
use std::{process::Stdio, time::Duration};
pub(crate) fn sign_pending(destination: &str) -> Result<()> {
    crate::runtime::supervision::disable_core_dumps()?;
    destination_host(destination)?;
    let session = crate::runtime::supervision::Session::new()?;
    let mut command = crate::cli::ssh::command(destination, "git-porter-session-v1")?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = session.spawn(command)?;
    let result = (|| -> Result<()> {
        let mut input = DeadlineIo::new(
            child.stdout.take().ok_or("missing SSH output")?,
            Duration::from_secs(30),
        );
        let mut output = DeadlineIo::new(
            child.stdin.take().ok_or("missing SSH input")?,
            Duration::from_secs(30),
        );
        input.cancel_on(&session);
        output.cancel_on(&session);
        let mut incoming = Budget::default();
        let mut outgoing = Budget::default();

        outgoing.write(&mut output, Kind::Hello, b"provision-v2")?;
        let payload = incoming.expect(&mut input, Kind::Hello)?;
        if payload != b"provision-v2" {
            return Err("receiver does not support this key-creation protocol".into());
        }

        outgoing.write(&mut output, Kind::Intent, b"provision\0")?;
        let resolved = incoming.expect(&mut input, Kind::Resolved)?;
        if resolved.len() != 32 || !resolved.iter().all(u8::is_ascii_hexdigit) {
            return Err("provisioning job selection mismatch".into());
        }
        let payload = incoming.expect(&mut input, Kind::DeriveEd25519V2)?;
        let request = crate::credentials::derivation::Request::parse(&payload)?;
        outgoing.write(&mut output, Kind::Signing, b"")?;
        input.pause()?;
        output.pause()?;
        let mut signer = super::signing::Signer::open(destination, &request.source, &session)?;
        let response = request.sign(
            &mut crate::runtime::protocol::SigningBudget::default(),
            &mut signer,
        )?;
        signer.close()?;
        session.check()?;
        input.resume();
        output.resume();
        outgoing.write(&mut output, Kind::SigningDone, b"")?;

        outgoing.write(&mut output, Kind::Signature, &response)?;
        drop(response);
        incoming.expect(&mut input, Kind::Complete)?;
        incoming.close();
        outgoing.close();
        drop(input);
        drop(output);
        if !child.wait()?.success() {
            return Err("receiver key creation did not finish".into());
        }
        eprintln!(
            "Forwarder key saved on the receiver. Register the public key printed there with your forge."
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

/// Export only a derived public recipient; retain all signing material locally.
pub(crate) fn public_wrapping(value: Option<&str>) -> Result<()> {
    use crate::credentials::{agent::Client, derivation::Request, wrapping::PublicWrapping};
    use crate::runtime::{protocol::SigningBudget, supervision::Session};
    use std::path::Path;
    let session = Session::new()?;
    let path = value.map(Path::new).filter(|p| p.is_file());
    let source = match value {
        Some(value) => {
            let text = match path {
                Some(p) => std::fs::read_to_string(p)?,
                None => value.to_owned(),
            };
            if text.trim().contains(['\n', '\r']) {
                return Err("expected one sender public key".into());
            }
            ssh_key::PublicKey::from_openssh(text.trim()).map_err(|e| e.to_string())?
        }
        None => {
            let socket =
                std::env::var_os("SSH_AUTH_SOCK").ok_or("no sender SSH agent is available")?;
            let mut agent = Client::connect(Path::new(&socket))?;
            agent.cancel_on(&session);
            let mut keys = agent
                .list_all_identities()?
                .into_iter()
                .filter(|k| k.algorithm() == ssh_key::Algorithm::Ed25519);
            let key = keys.next().ok_or("sender agent has no Ed25519 key")?;
            if keys.next().is_some() {
                return Err(
                    "sender agent has multiple Ed25519 keys; no sender key was selected".into(),
                );
            }
            key
        }
    };
    let request = Request::generate(source)?;
    let mut signer = super::signing::Signer::local(&request.source, path, &session)?;
    let signature = request.sign(&mut SigningBudget::default(), &mut signer)?;
    let identity = request.identity(&signature)?;
    drop(signature);
    let token = PublicWrapping {
        recipient: identity.to_public(),
        request,
    };
    drop(identity);
    signer.close()?;
    session.check()?;
    eprintln!(
        "Public wrapping token ready. Paste it into git porter setup on the receiver, or pass it to git porter key:create.\nThis token contains no private key or signature. Use a new token for each forwarder key."
    );
    println!("{}", token.encode()?);
    Ok(())
}
