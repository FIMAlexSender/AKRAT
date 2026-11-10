use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicIdentity {
    pub id: String,
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub status: IdentityStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Contact {
    pub id: String,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub trust: IdentityTrust,
    pub blocked: bool,
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
