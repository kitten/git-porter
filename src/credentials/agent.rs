//! Bounded local SSH-agent listing and Ed25519 derivation signing.
use crate::{
    Result,
    runtime::ssh_wire::{string, take},
};
use ssh_key::{PublicKey, Signature};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

pub struct Client {
    stream: crate::runtime::protocol::DeadlineIo<UnixStream>,
}
impl Client {
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = crate::runtime::ipc::connect(path, Duration::from_secs(2))?;
        Self::from_stream(stream)
    }
    pub(crate) fn connect_in(
        path: &Path,
        session: &crate::runtime::supervision::Session,
    ) -> Result<Self> {
        let stream = crate::runtime::ipc::connect_in(path, Duration::from_secs(2), session)?;
        let mut client = Self::from_stream(stream)?;
        client.cancel_on(session);
        Ok(client)
    }
    fn from_stream(stream: UnixStream) -> Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            stream: crate::runtime::protocol::DeadlineIo::new(stream, Duration::from_secs(30)),
        })
    }
    pub(crate) fn bound_io(&mut self, timeout: Duration) {
        self.stream.reset(timeout);
    }

    pub(crate) fn cancel_on(&mut self, session: &crate::runtime::supervision::Session) {
        self.stream.cancel_on(session);
    }
    fn exchange(&mut self, body: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if body.len() > 65536 {
            return Err("agent request exceeds limit".into());
        }
        self.stream.write_all(&(body.len() as u32).to_be_bytes())?;
        self.stream.write_all(body)?;
        let mut header = [0; 4];
        self.stream.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > 1024 * 1024 {
            return Err("agent response exceeds limit".into());
        }
        let mut response = zeroize::Zeroizing::new(vec![0; len]);
        self.stream.read_exact(&mut response)?;
        Ok(response)
    }
    pub fn list_all_identities(&mut self) -> Result<Vec<PublicKey>> {
        let response = self.exchange(&[11])?;
        let mut input = &response[..];
        if input.first() != Some(&12) || input.len() < 5 {
            return Err("agent refused identity listing".into());
        }
        let count = u32::from_be_bytes(input[1..5].try_into()?) as usize;
        input = &input[5..];
        if count > 256 {
            return Err("too many agent identities".into());
        }
        let mut keys = Vec::new();
        for _ in 0..count {
            let encoded = take(&mut input)?;
            let comment = take(&mut input)?;
            if let Ok(mut key) = PublicKey::from_bytes(encoded) {
                key.set_comment(String::from_utf8_lossy(comment));
                keys.push(key);
            }
        }
        if !input.is_empty() {
            return Err("trailing agent identity data".into());
        }
        Ok(keys)
    }
    pub fn sign(&mut self, key: &PublicKey, challenge: &[u8]) -> Result<Signature> {
        if key.algorithm() != ssh_key::Algorithm::Ed25519 {
            return Err("source keys must be Ed25519".into());
        }
        let mut body = vec![13];
        string(&mut body, &key.to_bytes().map_err(|e| e.to_string())?);
        string(&mut body, challenge);
        body.extend_from_slice(&0u32.to_be_bytes());
        // Local approval latency is not network I/O time. The enclosing session
        // still bounds liveness; agent implementations may enforce their own UI limit.
        self.stream.reset(Duration::from_secs(1200));
        let response = self.exchange(&body);
        self.stream.reset(Duration::from_secs(30));
        let response = response?;
        if response.first() != Some(&14) {
            return Err("source agent refused signing".into());
        }
        let mut input = &response[1..];
        let encoded = take(&mut input)?;
        let mut fields = encoded;
        if take(&mut fields)? != b"ssh-ed25519" {
            return Err("agent returned a non-Ed25519 signature".into());
        }
        let signature = Signature::new(ssh_key::Algorithm::Ed25519, take(&mut fields)?)
            .map_err(|e| e.to_string())?;
        if !fields.is_empty() {
            return Err("trailing signature fields".into());
        }
        if !input.is_empty() {
            return Err("trailing agent signature data".into());
        }
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_agent_listing_observes_the_receiver_session() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("agent");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).unwrap(), 0);
        });
        let session =
            crate::runtime::supervision::Session::with_timeout(Duration::from_millis(50)).unwrap();
        let mut client = Client::connect_in(&socket, &session).unwrap();
        assert!(
            client
                .list_all_identities()
                .unwrap_err()
                .to_string()
                .contains("canceled")
        );
        drop(client);
        peer.join().unwrap();
    }
    #[test]
    fn oversized_agent_responses_and_identity_counts_are_bounded() {
        for body in [None, Some(vec![12, 0, 0, 1, 1])] {
            let (client, mut server) = UnixStream::pair().unwrap();
            let thread = std::thread::spawn(move || {
                let mut request = [0; 5];
                server.read_exact(&mut request).unwrap();
                assert_eq!(request, [0, 0, 0, 1, 11]);
                if let Some(body) = body {
                    server
                        .write_all(&(body.len() as u32).to_be_bytes())
                        .unwrap();
                    server.write_all(&body).unwrap();
                } else {
                    server.write_all(&u32::MAX.to_be_bytes()).unwrap();
                }
            });
            let mut client = Client {
                stream: crate::runtime::protocol::DeadlineIo::new(client, Duration::from_secs(1)),
            };
            assert!(client.list_all_identities().is_err());
            thread.join().unwrap();
        }
    }
}
