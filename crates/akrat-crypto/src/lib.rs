use akrat_core::{IdentityStatus, PrivateIdentity, PublicIdentity};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub mod session;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("secure random generation failed")]
    Random,
    #[error("invalid public identity key")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
}

pub fn create_identity(display_name: String) -> Result<PrivateIdentity, IdentityError> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut()).map_err(|_| IdentityError::Random)?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = signing_key.verifying_key().to_bytes();
    let digest = Sha256::digest(public_key);
    let id = hex::encode(digest);
    let fingerprint = digest
        .chunks(2)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase();
    let created_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let public = PublicIdentity {
        id,
        display_name,
        public_key: public_key.to_vec(),
        fingerprint,
        status: IdentityStatus::Active,
        created_at_unix,
    };
    let secret_key = Zeroizing::new(signing_key.to_bytes());
    Ok(PrivateIdentity::new(public, secret_key))
}

pub fn sign(identity: &PrivateIdentity, message: &[u8]) -> Signature {
    identity.sign(message)
}

pub fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &Signature,
) -> Result<(), IdentityError> {
    let bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| IdentityError::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| IdentityError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(message, signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::{IdentityError, create_identity, sign, verify};

    #[test]
    fn identities_are_independent_and_signatures_verify() {
        let first = create_identity("Personnel".to_string()).expect("identity creation");
        let second = create_identity("Professionnel".to_string()).expect("identity creation");
        let message = b"AKRAT identity signature test";
        let signature = sign(&first, message);

        assert_ne!(first.public.id, second.public.id);
        assert_eq!(first.public.fingerprint.len(), 79);
        assert!(verify(&first.public.public_key, message, &signature).is_ok());
        assert!(matches!(
            verify(&second.public.public_key, message, &signature),
            Err(IdentityError::InvalidSignature)
        ));
    }

    #[test]
    fn altered_message_is_rejected() {
        let identity = create_identity("Test".to_string()).expect("identity creation");
        let signature = sign(&identity, b"signed");

        assert!(matches!(
            verify(&identity.public.public_key, b"modified", &signature),
            Err(IdentityError::InvalidSignature)
        ));
    }
}
