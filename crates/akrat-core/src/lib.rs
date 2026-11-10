use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IdentityTrust {
    Unknown,
    KnownUnverified,
    ManuallyVerified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum IdentityStatus {
    Active,
    Archived,
    LocallyRevoked,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct PrivateIdentity {
    #[zeroize(skip)]
    pub public: PublicIdentity,
    signing_key: [u8; 32],
}

impl PrivateIdentity {
    pub fn new(public: PublicIdentity, signing_key: Zeroizing<[u8; 32]>) -> Self {
        Self {
            public,
            signing_key: *signing_key,
        }
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        let secret = Zeroizing::new(self.signing_key);
        SigningKey::from_bytes(&secret).sign(message)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicIdentity {
    pub id: String,
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub status: IdentityStatus,
    pub created_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Contact {
    pub id: String,
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub trust: IdentityTrust,
    pub blocked: bool,
    pub created_at_unix: u64,
    pub last_seen_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MessageDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MessageDelivery {
    Pending,
    Transmitted,
    Received,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoredMessage {
    pub id: String,
    pub sender_identity_id: String,
    pub sent_at_unix: u64,
    pub direction: MessageDirection,
    pub delivery: MessageDelivery,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Conversation {
    pub id: String,
    pub local_identity_id: String,
    pub remote_identity_id: String,
    pub created_at_unix: u64,
    pub messages: Vec<StoredMessage>,
}

#[cfg(test)]
mod tests {
    use super::{IdentityStatus, IdentityTrust};

    #[test]
    fn trust_states_are_distinct() {
        assert_ne!(IdentityTrust::Unknown, IdentityTrust::KnownUnverified);
        assert_ne!(
            IdentityTrust::KnownUnverified,
            IdentityTrust::ManuallyVerified
        );
    }

    #[test]
    fn revoked_is_not_active() {
        assert_ne!(IdentityStatus::Active, IdentityStatus::LocallyRevoked);
    }
}
