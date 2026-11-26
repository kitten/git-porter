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

/// Fresh, narrowly typed authorization for one receiver/forwarder operation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub version: u8,
    pub nonce: [u8; 32],
    pub repository: String,
    pub destination: String,
    pub reference: String,
    pub sha: String,
    pub mode: String,
    pub observed: String,
}
impl Approval {
    pub fn new(
        repository: &str,
        destination: &str,
        reference: &str,
        sha: &str,
        mode: &str,
        observed: &str,
    ) -> Result<Self> {
        use rand::RngCore;
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let approval = Self {
            version: 1,
            nonce,
            repository: repository.into(),
            destination: destination.into(),
            reference: reference.into(),
            sha: sha.into(),
            mode: mode.into(),
            observed: observed.into(),
        };
        approval.validate()?;
        Ok(approval)
    }
    fn validate(&self) -> Result<()> {
        use crate::runtime::push_result::{oid, reference};
        if self.version != 1
            || self.nonce == [0; 32]
            || !std::path::Path::new(&self.repository).is_absolute()
            || self.repository.len() > 4096
            || self.repository.chars().any(char::is_control)
            || self.reference.len() > 1024
            || if self.mode == "read" {
                !crate::runtime::push_result::read_reference(&self.reference)
                    || !self.sha.is_empty()
            } else {
                !reference(&self.reference) || !oid(&self.sha)
            }
            || !matches!(self.mode.as_str(), "ff" | "force" | "lease" | "read")
            || self.mode == "lease" && !self.observed.is_empty() && !oid(&self.observed)
            || self.mode != "lease" && !self.observed.is_empty()
        {
            return Err("invalid publication approval context".into());
        }
        crate::server::discovery::Identity::parse(&self.destination)?;
        Ok(())
    }
    pub fn matches_intent(
        &self,
        repository: &str,
        reference: &str,
        sha: &str,
        mode: &str,
        observed: &str,
    ) -> Result<()> {
        self.validate()?;
        if self.repository != repository
            || self.reference != reference
            || self.sha != sha
            || self.mode != mode
            || self.observed != observed
        {
            return Err("publication approval does not match the sender's intended update".into());
        }
        Ok(())
    }
}

/// Stable unlock derivation plus a fresh, domain-separated operation approval.
pub struct PublishRequest {
    pub current: Request,
    pub approval: Approval,
}
impl PublishRequest {
    const MAX_SIZE: usize = 14 * 1024;
    pub fn new(source: PublicKey, metadata: Metadata, approval: Approval) -> Result<Self> {
        approval.validate()?;
        let request = Self {
            current: Request::new(source, metadata)?,
            approval,
        };
        request.encode()?;
        Ok(request)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.approval.validate()?;
        let mut bytes = self.current.encode()?;
        bytes.push(0);
        bytes.extend(serde_json::to_vec(&self.approval)?);
        if bytes.len() > Self::MAX_SIZE {
            return Err("publication approval request exceeds bounds".into());
        }
        Ok(bytes)
    }
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() > Self::MAX_SIZE {
            return Err("publication approval request exceeds bounds".into());
        }
        let separator = payload
            .iter()
            .rposition(|b| *b == 0)
            .ok_or("missing publication approval context")?;
        let current = Request::parse(&payload[..separator])?;
        let approval = serde_json::from_slice(&payload[separator + 1..])?;
        Self::new(current.source, current.metadata, approval)
    }
    pub fn approval_challenge(&self) -> Result<Vec<u8>> {
        let mut bytes = if self.approval.mode == "read" {
            b"git-porter/v1/read-approval\0".to_vec()
        } else {
            b"git-porter/v1/publish-approval\0".to_vec()
        };
        bytes.extend(self.encode()?);
        Ok(bytes)
    }
    pub fn sign(
        &self,
        budget: &mut SigningBudget,
        agent: &mut impl SourceAgent,
    ) -> Result<Zeroizing<Vec<u8>>> {
        budget.consume()?;
        let approval = self.approval_challenge()?;
        let current = self.current.metadata.challenge(&self.current.source)?;
        if !self.current.loaded(agent)? {
            return Err(self.current.missing_source().into());
        }
        // Reserve both signatures up front: reallocating a partially filled Vec
        // could leave an unwiped copy of the reusable unlock signature behind.
        let mut response = Zeroizing::new(Vec::with_capacity(128));
        response.extend_from_slice(&self.current.sign_challenge(&current, agent)?);
        response.extend_from_slice(&self.current.sign_challenge(&approval, agent)?);
        Ok(response)
    }
    /// Verify fresh approval before deriving any reusable unlock identity.
    pub fn identity(&self, response: &[u8]) -> Result<age::x25519::Identity> {
        if response.len() != 128 {
            return Err("incomplete publication approval signatures".into());
        }
        let signature = Signature::new(ssh_key::Algorithm::Ed25519, &response[64..])
            .map_err(|e| e.to_string())?;
        self.current
            .source
            .key_data()
            .verify(&self.approval_challenge()?, &signature)
            .map_err(|_| "invalid publication approval signature")?;
        self.current.identity(&response[..64])
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
    fn fresh_approval_is_bounded_and_second_refusal_returns_no_response() {
        use crate::credentials::derivation::PublishRequest;
        let (request, mut agent) = fixture();
        let publish = PublishRequest::new(request.source, request.metadata, approval()).unwrap();
        let publish = PublishRequest::parse(&publish.encode().unwrap()).unwrap();
        let mut budget = SigningBudget::default();
        agent.refuse_after = 1;
        assert!(publish.sign(&mut budget, &mut agent).is_err());
        assert_eq!((agent.calls, agent.lists), (2, 1));
        assert!(publish.sign(&mut budget, &mut agent).is_err());
        assert_eq!((agent.calls, agent.lists), (2, 1));
    }
    fn approval() -> super::Approval {
        super::Approval::new(
            "/receiver/repo",
            "git@forge.example:org/repo",
            "refs/heads/work/test",
            &"a".repeat(40),
            "ff",
            "",
        )
        .unwrap()
    }
    #[test]
    fn read_approval_is_branch_bound_and_cannot_authorize_a_push() {
        use super::{Approval, PublishRequest};
        let (request, mut agent) = fixture();
        let approval = Approval::new(
            "/receiver/repo",
            "git@github.com:org/repo",
            "refs/heads/review/é+retry",
            "",
            "read",
            "",
        )
        .unwrap();
        let mut read = PublishRequest::new(request.source, request.metadata, approval).unwrap();
        assert!(
            read.approval_challenge()
                .unwrap()
                .starts_with(b"git-porter/v1/read-approval\0")
        );
        let response = read
            .sign(&mut SigningBudget::default(), &mut agent)
            .unwrap();
        read.identity(&response).unwrap();
        assert_eq!((agent.calls, agent.lists), (2, 1));
        let destination = read.approval.destination.clone();
        read.approval.destination = "git@github.com:other/repo".into();
        assert!(read.identity(&response).is_err());
        read.approval.destination = destination;
        assert!(
            read.approval
                .matches_intent("/receiver/repo", "refs/heads/other", "", "read", "")
                .is_err()
        );
        assert!(
            read.approval
                .matches_intent(
                    "/receiver/repo",
                    "refs/heads/review/é+retry",
                    &"a".repeat(40),
                    "ff",
                    ""
                )
                .is_err()
        );
        read.approval.mode = "ff".into();
        read.approval.reference = "refs/heads/review/retry".into();
        read.approval.sha = "a".repeat(40);
        assert!(read.identity(&response).is_err());
    }
    #[test]
    fn publication_approval_is_fresh_context_bound_and_domain_separated() {
        use super::PublishRequest;
        let (request, mut agent) = fixture();
        let mut publish =
            PublishRequest::new(request.source, request.metadata, approval()).unwrap();
        let response = publish
            .sign(&mut SigningBudget::default(), &mut agent)
            .unwrap();
        assert_eq!((agent.calls, agent.lists), (2, 1));
        publish.identity(&response).unwrap();
        assert!(publish.current.identity(&response[64..]).is_err());
        let encoded = publish.encode().unwrap();
        let decoded = PublishRequest::parse(&encoded).unwrap();
        decoded.identity(&response).unwrap();
        let fresh = PublishRequest::new(
            publish.current.source.clone(),
            publish.current.metadata.clone(),
            approval(),
        )
        .unwrap();
        assert_ne!(fresh.approval.nonce, publish.approval.nonce);
        assert!(
            fresh.identity(&response).is_err(),
            "old approval cannot authorize a fresh session"
        );
        let fresh_response = fresh
            .sign(&mut SigningBudget::default(), &mut agent)
            .unwrap();
        fresh.identity(&fresh_response).unwrap();
        assert_eq!(
            &response[..64],
            &fresh_response[..64],
            "unwrap material is deliberately stable"
        );
        assert_ne!(
            &response[64..],
            &fresh_response[64..],
            "approval changes per session"
        );

        let original = publish.approval.clone();
        for field in 0..7 {
            publish.approval = original.clone();
            match field {
                0 => publish.approval.repository.push_str("-other"),
                1 => publish.approval.destination = "git@forge.example:other/repo".into(),
                2 => publish.approval.reference = "refs/heads/work/other".into(),
                3 => publish.approval.sha = "b".repeat(40),
                4 => publish.approval.mode = "force".into(),
                5 => {
                    publish.approval.mode = "lease".into();
                    publish.approval.observed = "c".repeat(40);
                }
                _ => publish.approval.nonce[0] ^= 1,
            }
            assert!(
                publish.identity(&response).is_err(),
                "tampered field {field}"
            );
        }
        publish.approval = original;
        let expected = &publish.approval;
        expected
            .matches_intent(
                &expected.repository,
                &expected.reference,
                &expected.sha,
                &expected.mode,
                &expected.observed,
            )
            .unwrap();
        assert!(
            expected
                .matches_intent(
                    "/other/repo",
                    &expected.reference,
                    &expected.sha,
                    &expected.mode,
                    &expected.observed
                )
                .is_err()
        );
        let mut bad = serde_json::to_value(&publish.approval).unwrap();
        bad["version"] = 2.into();
        publish.approval = serde_json::from_value(bad).unwrap();
        assert!(publish.encode().is_err());
        assert!(PublishRequest::parse(&vec![0; 14 * 1024 + 1]).is_err());
        let mut malformed = publish.current.encode().unwrap();
        malformed.extend_from_slice(b"\0{\"version\":1,\"unknown\":true}");
        assert!(PublishRequest::parse(&malformed).is_err());
        assert!(PublishRequest::parse(&[]).is_err());
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
