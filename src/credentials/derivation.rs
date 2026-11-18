//! Typed exact-key derivation. No generic agent proxy or caller-provided challenge.
//! @ref LLP 0001#signing
use crate::{Result, credentials::wrapping::Metadata, runtime::protocol::SigningBudget};
use signature::Verifier;
use ssh_key::{PublicKey, Signature};
use zeroize::Zeroizing;

pub struct Request {
    pub source: PublicKey,
    pub metadata: Metadata,
}
impl Request {
    pub fn generate(source: PublicKey) -> Result<Self> {
        let metadata = Metadata::generate(&source)?;
        Self::new(source, metadata)
    }

    pub fn new(source: PublicKey, metadata: Metadata) -> Result<Self> {
        metadata.challenge(&source)?;
        if source.comment().len() > 256 {
            return Err("source comment exceeds 256 bytes".into());
        }
        Ok(Self { source, metadata })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.metadata.challenge(&self.source)?;
        let key = self.source.to_openssh().map_err(|e| e.to_string())?;
        if key.len() > 4096 || key.contains(['\0', '\n', '\r']) {
            return Err("invalid source public key encoding".into());
        }
        let mut payload = key.into_bytes();
        payload.push(0);
        payload.extend(self.metadata.encode()?.bytes());
        Ok(payload)
    }
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() > 4608 {
            return Err("derivation request exceeds limit".into());
        }
        let separator = payload
            .iter()
            .position(|b| *b == 0)
            .ok_or("missing derivation metadata")?;
        let (key, rest) = payload.split_at(separator);
        let metadata = &rest[1..];
        if key.len() > 4096 || metadata.len() > 512 || key.contains(&b'\n') || key.contains(&b'\r')
        {
            return Err("invalid derivation field size or encoding".into());
        }
        Self::new(
            PublicKey::from_openssh(std::str::from_utf8(key)?).map_err(|e| e.to_string())?,
            Metadata::parse(std::str::from_utf8(metadata)?)?,
        )
    }
    fn display_identity(&self) -> String {
        format!(
            "{} ({})",
            self.source.fingerprint(ssh_key::HashAlg::Sha256),
            if self.source.comment().is_empty() {
                "no comment".into()
            } else {
                self.source
                    .comment()
                    .chars()
                    .flat_map(char::escape_default)
                    .collect::<String>()
            }
        )
    }
    pub fn sign(
        &self,
        budget: &mut SigningBudget,
        agent: &mut impl SourceAgent,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.sign_if_loaded(budget, agent)?
            .ok_or_else(|| self.missing_source().into())
    }
    pub(crate) fn sign_if_loaded(
        &self,
        budget: &mut SigningBudget,
        agent: &mut impl SourceAgent,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let challenge = self.metadata.challenge(&self.source)?;
        budget.consume()?;
        if !self.loaded(agent)? {
            return Ok(None);
        }
        self.sign_challenge(&challenge, agent).map(Some)
    }
    fn missing_source(&self) -> String {
        format!(
            "sender agent has no key matching the required sender key {}",
            self.display_identity()
        )
    }
    fn loaded(&self, agent: &mut impl SourceAgent) -> Result<bool> {
        Ok(agent
            .identities()?
            .iter()
            .any(|key| key.key_data() == self.source.key_data()))
    }
    fn sign_challenge(
        &self,
        challenge: &[u8],
        agent: &mut impl SourceAgent,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let signature = agent.sign(&self.source, challenge).map_err(|error| {
            format!(
                "sender agent could not sign for {}: {error}",
                self.display_identity()
            )
        })?;
        self.source
            .key_data()
            .verify(challenge, &signature)
            .map_err(|_| "sender agent returned an invalid unlock signature")?;
        Ok(Zeroizing::new(signature.as_bytes().to_vec()))
    }
    pub fn identity(&self, response: &[u8]) -> Result<age::x25519::Identity> {
        if response.len() != 64 {
            return Err("invalid Ed25519 derivation signature length".into());
        }
        self.metadata.from_signature(
            &self.source,
            &Signature::new(ssh_key::Algorithm::Ed25519, response).map_err(|e| e.to_string())?,
        )
    }
}

pub trait SourceAgent {
    fn identities(&mut self) -> Result<Vec<PublicKey>>;
    fn sign(&mut self, source: &PublicKey, challenge: &[u8]) -> Result<Signature>;
}
impl SourceAgent for super::agent::Client {
    fn identities(&mut self) -> Result<Vec<PublicKey>> {
        self.list_all_identities()
    }
    fn sign(&mut self, source: &PublicKey, challenge: &[u8]) -> Result<Signature> {
        super::agent::Client::sign(self, source, challenge)
    }
}

/// Two exact-key derivations, consumed as one bounded publication exchange.
pub struct PublishRequest {
    pub current: Request,
    pub next: Request,
}
impl PublishRequest {
    pub fn new(source: PublicKey, metadata: Metadata) -> Result<Self> {
        let mut fresh = Metadata::generate(&source)?;
        while metadata.same_salt(&fresh) {
            fresh = Metadata::generate(&source)?;
        }
        let next = Request::new(source.clone(), fresh)?;
        Ok(Self {
            current: Request::new(source, metadata)?,
            next,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.current.encode()?;
        bytes.push(0);
        bytes.extend(self.next.metadata.encode()?.bytes());
        Ok(bytes)
    }
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let separator = payload
            .iter()
            .rposition(|b| *b == 0)
            .ok_or("missing fresh re-lock metadata")?;
        if payload.len() > 5121 || payload.len() - separator - 1 > 512 {
            return Err("publication re-lock request exceeds bounds".into());
        }
        let current = Request::parse(&payload[..separator])?;
        let next = Request::new(
            current.source.clone(),
            Metadata::parse(std::str::from_utf8(&payload[separator + 1..])?)?,
        )?;
        if !next.metadata.current_version() || current.metadata.same_salt(&next.metadata) {
            return Err("re-lock requires a fresh salt".into());
        }
        Ok(Self { current, next })
    }
    pub fn sign(
        &self,
        budget: &mut SigningBudget,
        agent: &mut impl SourceAgent,
    ) -> Result<Zeroizing<Vec<u8>>> {
        budget.consume()?;
        if self.current.source.key_data() != self.next.source.key_data()
            || !self.next.metadata.current_version()
            || self.current.metadata.same_salt(&self.next.metadata)
        {
            return Err("re-lock requires the same source key and a fresh salt".into());
        }
        let current = self.current.metadata.challenge(&self.current.source)?;
        let next = self.next.metadata.challenge(&self.next.source)?;
        if !self.current.loaded(agent)? {
            return Err(self.current.missing_source().into());
        }
        let mut response = self.current.sign_challenge(&current, agent)?;
        response.extend_from_slice(&self.next.sign_challenge(&next, agent)?);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Result,
        credentials::derivation::{Request, SourceAgent},
        credentials::wrapping::Metadata,
        runtime::protocol::SigningBudget,
    };
    use signature::Signer;
    use ssh_key::{PrivateKey, PublicKey, Signature};

    struct Agent {
        key: PrivateKey,
        identities: Vec<PublicKey>,
        calls: usize,
        lists: usize,
        refuse: bool,
        corrupt: bool,
        refuse_after: usize,
    }
    impl SourceAgent for Agent {
        fn identities(&mut self) -> Result<Vec<PublicKey>> {
            self.lists += 1;
            Ok(self.identities.clone())
        }
        fn sign(&mut self, source: &PublicKey, challenge: &[u8]) -> Result<Signature> {
            assert_eq!(source.key_data(), self.key.public_key().key_data());
            self.calls += 1;
            if self.refuse || self.calls > self.refuse_after {
                return Err("refused".into());
            }
            if self.corrupt {
                return Ok(Signature::new(ssh_key::Algorithm::Ed25519, [0; 64])
                    .map_err(|e| e.to_string())?);
            }
            Ok(self.key.try_sign(challenge).map_err(|e| e.to_string())?)
        }
    }
    fn fixture() -> (Request, Agent) {
        let key = PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let source = key.public_key().clone();
        let request = Request::new(source.clone(), Metadata::generate(&source).unwrap()).unwrap();
        (
            request,
            Agent {
                key,
                identities: vec![source],
                calls: 0,
                lists: 0,
                refuse: false,
                corrupt: false,
                refuse_after: usize::MAX,
            },
        )
    }
    #[test]
    fn exact_key_deduplicates_comments_and_verifies_unchanged_derivation() {
        let (request, mut agent) = fixture();
        let other =
            PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        agent.identities.insert(0, other.public_key().clone());
        let mut duplicate = request.source.clone();
        duplicate.set_comment("different comment");
        agent.identities.push(duplicate);
        let parsed = Request::parse(&request.encode().unwrap()).unwrap();
        let mut budget = SigningBudget::default();
        let response = parsed.sign(&mut budget, &mut agent).unwrap();
        assert_eq!(agent.calls, 1);
        let identity = parsed.identity(&response).unwrap();
        let signature = agent
            .key
            .try_sign(&request.metadata.challenge(&request.source).unwrap())
            .unwrap();
        assert_eq!(
            identity.to_public(),
            request
                .metadata
                .from_signature(&request.source, &signature)
                .unwrap()
                .to_public()
        );
        assert!(parsed.sign(&mut budget, &mut agent).is_err());
        assert_eq!((agent.calls, agent.lists), (1, 1));
        assert!(parsed.identity(&[0; 64]).is_err());
        assert!(parsed.identity(&[0; 65]).is_err());
    }
    #[test]
    fn missing_key_never_signs_and_refusal_never_retries() {
        for missing in [false, true] {
            let (request, mut agent) = fixture();
            agent.refuse = true;
            if missing {
                agent.identities.clear();
            }
            let mut budget = SigningBudget::default();
            let error = request
                .sign(&mut budget, &mut agent)
                .unwrap_err()
                .to_string();
            if missing {
                assert!(
                    error.contains("no key matching the required sender key"),
                    "{error}"
                );
                assert!(
                    error.contains(
                        &request
                            .source
                            .fingerprint(ssh_key::HashAlg::Sha256)
                            .to_string()
                    ),
                    "{error}"
                );
            }
            for speculative_hint in ["ssh-add", "key:create", "porter."] {
                assert!(!error.contains(speculative_hint), "{error}");
            }
            assert!(request.sign(&mut budget, &mut agent).is_err());
            assert_eq!(agent.calls, usize::from(!missing));
            assert_eq!(agent.lists, 1);
        }
    }
    #[test]
    fn mismatch_and_malformed_payloads_are_rejected_without_agent_access() {
        let (request, _) = fixture();
        let other =
            PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        assert!(Request::new(other.public_key().clone(), request.metadata).is_err());
        for payload in [
            vec![],
            vec![0; 4609],
            b"ssh-ed25519 invalid\0invalid".to_vec(),
        ] {
            assert!(Request::parse(&payload).is_err());
        }
    }

    #[test]
    fn fresh_relock_pair_is_bounded_and_second_refusal_returns_no_response() {
        use crate::credentials::derivation::PublishRequest;
        let (request, mut agent) = fixture();
        let publish = PublishRequest::new(request.source, request.metadata).unwrap();
        let publish = PublishRequest::parse(&publish.encode().unwrap()).unwrap();
        let mut budget = SigningBudget::default();
        agent.refuse_after = 1;
        assert!(publish.sign(&mut budget, &mut agent).is_err());
        assert_eq!((agent.calls, agent.lists), (2, 1));
        assert!(publish.sign(&mut budget, &mut agent).is_err());
        assert_eq!((agent.calls, agent.lists), (2, 1));
    }
    #[test]
    fn publication_lists_once_and_both_signatures_unlock_their_own_metadata() {
        use crate::credentials::derivation::PublishRequest;
        let (request, mut agent) = fixture();
        let mut publish = PublishRequest::new(request.source, request.metadata).unwrap();
        let response = publish
            .sign(&mut SigningBudget::default(), &mut agent)
            .unwrap();
        assert_eq!((agent.calls, agent.lists), (2, 1));
        assert_eq!(response.len(), 128);
        publish.current.identity(&response[..64]).unwrap();
        publish.next.identity(&response[64..]).unwrap();
        assert!(publish.current.identity(&response[64..]).is_err());
        let (other, _) = fixture();
        publish.next = other;
        assert!(
            publish
                .sign(&mut SigningBudget::default(), &mut agent)
                .is_err()
        );
        assert_eq!((agent.calls, agent.lists), (2, 1));
    }
    #[test]
    fn invalid_agent_signature_is_rejected_without_a_retry() {
        let (request, mut agent) = fixture();
        agent.corrupt = true;
        let mut budget = SigningBudget::default();
        assert!(request.sign(&mut budget, &mut agent).is_err());
        assert!(request.sign(&mut budget, &mut agent).is_err());
        assert_eq!((agent.calls, agent.lists), (1, 1));
    }
}
