use crate::ServerSigner;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_KEY_EVENTS: usize = 64;
pub const KEY_TRANSITION_LIFETIME: u64 = 10 * 365 * 24 * 60 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyTransition {
    pub sequence: u64,
    pub previous_public_key: String,
    pub new_public_key: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub previous_hash: String,
    pub root_signature: String,
    pub previous_signature: String,
    pub possession_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyRevocation {
    pub sequence: u64,
    pub key_fingerprint: String,
    pub revoked_at: u64,
    pub reason: String,
    pub root_signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerIdentity {
    pub root_public_key: String,
    pub active_public_key: String,
    pub generation: u64,
    pub revocation_sequence: u64,
    pub transitions: Vec<KeyTransition>,
    pub revocations: Vec<KeyRevocation>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum KeyContinuityError {
    #[error("pinned server identity does not match the continuity root")]
    WrongRoot,
    #[error("server key transition chain is malformed or unauthenticated")]
    InvalidTransition,
    #[error("server key transition has expired or is not yet valid")]
    TransitionExpired,
    #[error("server key continuity moved backwards")]
    Rollback,
    #[error("the active server signing key has been revoked")]
    RevokedActiveKey,
    #[error("server revocation record is malformed or unauthenticated")]
    InvalidRevocation,
}

impl KeyTransition {
    pub fn create(
        root: &ServerSigner,
        previous: &ServerSigner,
        next: &ServerSigner,
        sequence: u64,
        previous_hash: String,
        created_at: u64,
    ) -> Self {
        let expires_at = created_at.saturating_add(KEY_TRANSITION_LIFETIME);
        let mut value = Self {
            sequence,
            previous_public_key: hex::encode(previous.public_key()),
            new_public_key: hex::encode(next.public_key()),
            created_at,
            expires_at,
            previous_hash,
            root_signature: String::new(),
            previous_signature: String::new(),
            possession_signature: String::new(),
        };
        let bytes = value.signing_bytes();
        value.root_signature = hex::encode(root.sign_bytes(&bytes));
        value.previous_signature = hex::encode(previous.sign_bytes(&bytes));
        value.possession_signature = hex::encode(next.sign_bytes(&bytes));
        value
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"AKRAT/mailbox-key-transition/v1\0".to_vec();
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        append(&mut bytes, self.previous_public_key.as_bytes());
        append(&mut bytes, self.new_public_key.as_bytes());
        bytes.extend_from_slice(&self.created_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        append(&mut bytes, self.previous_hash.as_bytes());
        bytes
    }

    pub(crate) fn digest(&self) -> String {
        let mut bytes = self.signing_bytes();
        append(&mut bytes, self.root_signature.as_bytes());
        append(&mut bytes, self.previous_signature.as_bytes());
        append(&mut bytes, self.possession_signature.as_bytes());
        hex::encode(Sha256::digest(bytes))
    }
}

impl KeyRevocation {
    pub fn create(
        root: &ServerSigner,
        key_fingerprint: String,
        sequence: u64,
        revoked_at: u64,
        reason: String,
    ) -> Self {
        let mut value = Self {
            sequence,
            key_fingerprint,
            revoked_at,
            reason,
            root_signature: String::new(),
        };
        value.root_signature = hex::encode(root.sign_bytes(&value.signing_bytes()));
        value
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"AKRAT/mailbox-key-revocation/v1\0".to_vec();
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        append(&mut bytes, self.key_fingerprint.as_bytes());
        bytes.extend_from_slice(&self.revoked_at.to_be_bytes());
        append(&mut bytes, self.reason.as_bytes());
        bytes
    }
}

impl ServerIdentity {
    pub fn receipt_key_at(&self, fingerprint: &str, signed_at: u64) -> Option<[u8; 32]> {
        let root: [u8; 32] = hex::decode(&self.root_public_key).ok()?.try_into().ok()?;
        let mut keys = vec![(root, 0u64)];
        for transition in &self.transitions {
            let key: [u8; 32] = hex::decode(&transition.new_public_key)
                .ok()?
                .try_into()
                .ok()?;
            keys.push((key, transition.created_at));
        }
        keys.into_iter()
            .enumerate()
            .find_map(|(index, (key, starts_at))| {
                let key_fingerprint = hex::encode(Sha256::digest(key));
                if key_fingerprint != fingerprint || signed_at < starts_at {
                    return None;
                }
                let rotated_at = self
                    .transitions
                    .get(index)
                    .map(|transition| transition.created_at);
                let revoked_at = self
                    .revocations
                    .iter()
                    .find(|revocation| revocation.key_fingerprint == key_fingerprint)
                    .map(|revocation| revocation.revoked_at);
                let valid_until = rotated_at.into_iter().chain(revoked_at).min();
                if valid_until.is_some_and(|until| signed_at >= until) {
                    None
                } else {
                    Some(key)
                }
            })
    }

    pub fn verify(
        &self,
        pinned_root: &[u8; 32],
        minimum_generation: u64,
        minimum_revocation_sequence: u64,
        now: u64,
    ) -> Result<Vec<[u8; 32]>, KeyContinuityError> {
        let root: [u8; 32] = decode_key(&self.root_public_key)?;
        if &root != pinned_root {
            return Err(KeyContinuityError::WrongRoot);
        }
        if self.transitions.len() > MAX_KEY_EVENTS || self.revocations.len() > MAX_KEY_EVENTS {
            return Err(KeyContinuityError::InvalidTransition);
        }
        if self.generation < minimum_generation || self.generation != self.transitions.len() as u64
        {
            return Err(KeyContinuityError::Rollback);
        }
        if self.revocation_sequence < minimum_revocation_sequence
            || self.revocation_sequence != self.revocations.last().map_or(0, |item| item.sequence)
        {
            return Err(KeyContinuityError::Rollback);
        }
        let mut active = root;
        let mut transition_hash = String::new();
        let root_key =
            VerifyingKey::from_bytes(&root).map_err(|_| KeyContinuityError::WrongRoot)?;
        let mut keys = vec![root];
        for (index, transition) in self.transitions.iter().enumerate() {
            let previous = decode_key(&transition.previous_public_key)?;
            let next = decode_key(&transition.new_public_key)?;
            if previous != active
                || transition.sequence != index as u64 + 1
                || transition.previous_hash != transition_hash
                || transition.expires_at <= now
                || transition.created_at > now.saturating_add(300)
                || transition.expires_at <= transition.created_at
                || transition.expires_at - transition.created_at > KEY_TRANSITION_LIFETIME
            {
                return Err(KeyContinuityError::TransitionExpired);
            }
            let bytes = transition.signing_bytes();
            verify(&root_key, &bytes, &transition.root_signature)
                .map_err(|_| KeyContinuityError::InvalidTransition)?;
            verify(
                &VerifyingKey::from_bytes(&previous)
                    .map_err(|_| KeyContinuityError::InvalidTransition)?,
                &bytes,
                &transition.previous_signature,
            )
            .map_err(|_| KeyContinuityError::InvalidTransition)?;
            verify(
                &VerifyingKey::from_bytes(&next)
                    .map_err(|_| KeyContinuityError::InvalidTransition)?,
                &bytes,
                &transition.possession_signature,
            )
            .map_err(|_| KeyContinuityError::InvalidTransition)?;
            active = next;
            keys.push(next);
            transition_hash = transition.digest();
        }
        if decode_key(&self.active_public_key)? != active {
            return Err(KeyContinuityError::InvalidTransition);
        }
        if self
            .revocations
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err(KeyContinuityError::InvalidRevocation);
        }
        for revocation in &self.revocations {
            let bytes = decode_key_fingerprint(&revocation.key_fingerprint)?;
            let public = keys
                .iter()
                .find(|key| {
                    hex::encode(Sha256::digest(key.as_slice())) == revocation.key_fingerprint
                })
                .ok_or(KeyContinuityError::InvalidRevocation)?;
            if revocation.reason.trim().is_empty()
                || revocation.reason.len() > 256
                || revocation.revoked_at > now.saturating_add(300)
                || hex::encode(Sha256::digest(public)) != hex::encode(bytes)
            {
                return Err(KeyContinuityError::InvalidRevocation);
            }
            verify(
                &root_key,
                &revocation.signing_bytes(),
                &revocation.root_signature,
            )
            .map_err(|_| KeyContinuityError::InvalidRevocation)?;
        }
        if self
            .revocations
            .iter()
            .any(|revocation| revocation.key_fingerprint == hex::encode(Sha256::digest(active)))
        {
            return Err(KeyContinuityError::RevokedActiveKey);
        }
        let revoked = self
            .revocations
            .iter()
            .map(|revocation| revocation.key_fingerprint.as_str())
            .collect::<std::collections::HashSet<_>>();
        keys.retain(|key| !revoked.contains(hex::encode(Sha256::digest(key)).as_str()));
        Ok(keys)
    }
}

fn decode_key(value: &str) -> Result<[u8; 32], KeyContinuityError> {
    hex::decode(value)
        .map_err(|_| KeyContinuityError::InvalidTransition)?
        .try_into()
        .map_err(|_| KeyContinuityError::InvalidTransition)
}

fn decode_key_fingerprint(value: &str) -> Result<[u8; 32], KeyContinuityError> {
    hex::decode(value)
        .map_err(|_| KeyContinuityError::InvalidRevocation)?
        .try_into()
        .map_err(|_| KeyContinuityError::InvalidRevocation)
}

fn verify(key: &VerifyingKey, bytes: &[u8], signature: &str) -> Result<(), ()> {
    let signature = hex::decode(signature).map_err(|_| ())?;
    let signature = Signature::from_slice(&signature).map_err(|_| ())?;
    key.verify(bytes, &signature).map_err(|_| ())
}

fn append(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_require_both_keys_and_preserve_old_receipt_keys() {
        let root = ServerSigner::generate().expect("root");
        let next = ServerSigner::generate().expect("next");
        let transition = KeyTransition::create(&root, &root, &next, 1, String::new(), 100);
        let identity = ServerIdentity {
            root_public_key: hex::encode(root.public_key()),
            active_public_key: hex::encode(next.public_key()),
            generation: 1,
            revocation_sequence: 0,
            transitions: vec![transition],
            revocations: Vec::new(),
        };
        let keys = identity
            .verify(&root.public_key(), 0, 0, 101)
            .expect("continuity");
        assert_eq!(keys, vec![root.public_key(), next.public_key()]);
        assert!(identity.verify(&root.public_key(), 2, 0, 101).is_err());
    }

    #[test]
    fn altered_transition_and_wrong_root_are_rejected() {
        let root = ServerSigner::generate().expect("root");
        let next = ServerSigner::generate().expect("next");
        let transition = KeyTransition::create(&root, &root, &next, 1, String::new(), 100);
        let mut identity = ServerIdentity {
            root_public_key: hex::encode(root.public_key()),
            active_public_key: hex::encode(next.public_key()),
            generation: 1,
            revocation_sequence: 0,
            transitions: vec![transition],
            revocations: Vec::new(),
        };
        identity.transitions[0].new_public_key =
            hex::encode(ServerSigner::generate().unwrap().public_key());
        assert_eq!(
            identity.verify(&root.public_key(), 0, 0, 101),
            Err(KeyContinuityError::InvalidTransition)
        );
        let mut other_root = [0u8; 32];
        other_root.copy_from_slice(&ServerSigner::generate().unwrap().public_key());
        assert_eq!(
            identity.verify(&other_root, 0, 0, 101),
            Err(KeyContinuityError::WrongRoot)
        );
    }

    #[test]
    fn revocation_is_root_authenticated_and_rejects_the_active_key() {
        let root = ServerSigner::generate().expect("root");
        let next = ServerSigner::generate().expect("next");
        let transition = KeyTransition::create(&root, &root, &next, 1, String::new(), 100);
        let revocation = KeyRevocation::create(
            &root,
            hex::encode(Sha256::digest(next.public_key())),
            1,
            100,
            "compromised".into(),
        );
        let identity = ServerIdentity {
            root_public_key: hex::encode(root.public_key()),
            active_public_key: hex::encode(next.public_key()),
            generation: 1,
            revocation_sequence: 1,
            transitions: vec![transition],
            revocations: vec![revocation],
        };
        assert_eq!(
            identity.verify(&root.public_key(), 0, 0, 101),
            Err(KeyContinuityError::RevokedActiveKey)
        );
    }

    #[test]
    fn transition_expiration_is_enforced() {
        let root = ServerSigner::generate().expect("root");
        let next = ServerSigner::generate().expect("next");
        let mut transition = KeyTransition::create(&root, &root, &next, 1, String::new(), 100);
        transition.expires_at = 101;
        let identity = ServerIdentity {
            root_public_key: hex::encode(root.public_key()),
            active_public_key: hex::encode(next.public_key()),
            generation: 1,
            revocation_sequence: 0,
            transitions: vec![transition],
            revocations: Vec::new(),
        };
        assert_eq!(
            identity.verify(&root.public_key(), 0, 0, 101),
            Err(KeyContinuityError::TransitionExpired)
        );
    }

    #[test]
    fn historical_receipt_keys_are_limited_to_their_signing_period() {
        let root = ServerSigner::generate().expect("root");
        let first = ServerSigner::generate().expect("first receipt key");
        let second = ServerSigner::generate().expect("second receipt key");
        let first_transition = KeyTransition::create(&root, &root, &first, 1, String::new(), 100);
        let second_transition =
            KeyTransition::create(&root, &first, &second, 2, first_transition.digest(), 200);
        let identity = ServerIdentity {
            root_public_key: hex::encode(root.public_key()),
            active_public_key: hex::encode(second.public_key()),
            generation: 2,
            revocation_sequence: 1,
            transitions: vec![first_transition, second_transition],
            revocations: vec![KeyRevocation::create(
                &root,
                first.fingerprint(),
                1,
                175,
                "retired receipt key".into(),
            )],
        };
        assert_eq!(
            identity.receipt_key_at(&root.fingerprint(), 99),
            Some(root.public_key())
        );
        assert_eq!(
            identity.receipt_key_at(&first.fingerprint(), 150),
            Some(first.public_key())
        );
        assert_eq!(identity.receipt_key_at(&first.fingerprint(), 175), None);
        assert_eq!(identity.receipt_key_at(&first.fingerprint(), 200), None);
        assert_eq!(
            identity.receipt_key_at(&second.fingerprint(), 200),
            Some(second.public_key())
        );
    }
}
