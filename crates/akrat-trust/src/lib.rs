use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RelayTrustLevel {
    #[default]
    Unknown = 0,
    IdentityVerified = 1,
    DistributionVerified = 2,
    ExecutionAttested = 3,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayIdentityPin {
    pub relay_url: String,
    pub public_key_hex: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayIdentityProof {
    pub relay_url: String,
    pub challenge_hex: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub software_version: String,
    pub signature_hex: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RelayIdentityError {
    #[error("relay identity proof is invalid")]
    InvalidProof,
    #[error("relay public key does not match the pinned fingerprint")]
    PinMismatch,
    #[error("relay identity service could not be reached")]
    Unreachable,
    #[error("relay identity response is too large or malformed")]
    InvalidResponse,
    #[error("this trust level requires provenance or hardware attestation that is unavailable")]
    HigherTrustUnavailable,
}

pub fn relay_identity_fingerprint(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key)).to_ascii_uppercase()
}

pub fn relay_identity_payload(
    relay_url: &str,
    challenge: &[u8],
    software_version: &str,
) -> Vec<u8> {
    let mut payload = b"AKRAT_RELAY_IDENTITY_V1".to_vec();
    for value in [relay_url.as_bytes(), challenge, software_version.as_bytes()] {
        payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
        payload.extend_from_slice(value);
    }
    payload
}

pub fn verify_relay_identity_proof(
    proof: &RelayIdentityProof,
    expected_url: &str,
    expected_challenge: &[u8],
    expected_fingerprint: &str,
) -> Result<RelayIdentityPin, RelayIdentityError> {
    let public_key =
        hex::decode(&proof.public_key_hex).map_err(|_| RelayIdentityError::InvalidProof)?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| RelayIdentityError::InvalidProof)?;
    let fingerprint = relay_identity_fingerprint(&public_key);
    if !fingerprint.eq_ignore_ascii_case(expected_fingerprint)
        || !fingerprint.eq_ignore_ascii_case(&proof.fingerprint)
    {
        return Err(RelayIdentityError::PinMismatch);
    }
    if proof.relay_url != expected_url
        || hex::decode(&proof.challenge_hex).map_err(|_| RelayIdentityError::InvalidProof)?
            != expected_challenge
    {
        return Err(RelayIdentityError::InvalidProof);
    }
    let signature = Signature::from_slice(
        &hex::decode(&proof.signature_hex).map_err(|_| RelayIdentityError::InvalidProof)?,
    )
    .map_err(|_| RelayIdentityError::InvalidProof)?;
    let key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| RelayIdentityError::InvalidProof)?;
    key.verify(
        &relay_identity_payload(expected_url, expected_challenge, &proof.software_version),
        &signature,
    )
    .map_err(|_| RelayIdentityError::InvalidProof)?;
    Ok(RelayIdentityPin {
        relay_url: expected_url.to_string(),
        public_key_hex: hex::encode(public_key),
        fingerprint,
    })
}

#[cfg(feature = "client")]
pub async fn verify_remote_relay_identity(
    relay_url: &str,
    expected_fingerprint: &str,
) -> Result<RelayIdentityPin, RelayIdentityError> {
    let mut endpoint =
        reqwest::Url::parse(relay_url).map_err(|_| RelayIdentityError::InvalidProof)?;
    endpoint.set_path("/");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let canonical_url = endpoint.to_string();
    endpoint
        .set_scheme("http")
        .map_err(|_| RelayIdentityError::InvalidProof)?;
    endpoint
        .set_port(Some(8090))
        .map_err(|_| RelayIdentityError::InvalidProof)?;
    endpoint.set_path("/.well-known/akrat/v1/challenge");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    verify_remote_relay_identity_at(&canonical_url, endpoint.as_str(), expected_fingerprint).await
}

#[cfg(feature = "client")]
pub async fn verify_remote_relay_identity_at(
    relay_url: &str,
    identity_endpoint: &str,
    expected_fingerprint: &str,
) -> Result<RelayIdentityPin, RelayIdentityError> {
    let mut relay = reqwest::Url::parse(relay_url).map_err(|_| RelayIdentityError::InvalidProof)?;
    relay.set_path("/");
    relay.set_query(None);
    relay.set_fragment(None);
    let canonical_url = relay.to_string();
    let mut endpoint =
        reqwest::Url::parse(identity_endpoint).map_err(|_| RelayIdentityError::InvalidProof)?;
    if endpoint.scheme() != "http" || endpoint.host_str().is_none() {
        return Err(RelayIdentityError::InvalidProof);
    }
    let challenge: [u8; 32] = {
        let mut value = [0u8; 32];
        getrandom::fill(&mut value).map_err(|_| RelayIdentityError::InvalidProof)?;
        value
    };
    endpoint.set_path("/.well-known/akrat/v1/challenge");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|_| RelayIdentityError::Unreachable)?;
    let response = client
        .post(endpoint)
        .json(&serde_json::json!({
            "relay_url": canonical_url,
            "challenge_hex": hex::encode(challenge),
        }))
        .send()
        .await
        .map_err(|_| RelayIdentityError::Unreachable)?;
    if !response.status().is_success() {
        return Err(RelayIdentityError::Unreachable);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| RelayIdentityError::InvalidResponse)?;
    if bytes.len() > 4096 {
        return Err(RelayIdentityError::InvalidResponse);
    }
    let proof: RelayIdentityProof =
        serde_json::from_slice(&bytes).map_err(|_| RelayIdentityError::InvalidResponse)?;
    verify_relay_identity_proof(&proof, &canonical_url, &challenge, expected_fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn proof_for(key: &SigningKey, relay_url: &str, challenge: &[u8]) -> RelayIdentityProof {
        let version = "0.1.12";
        let public_key = key.verifying_key().to_bytes();
        RelayIdentityProof {
            relay_url: relay_url.into(),
            challenge_hex: hex::encode(challenge),
            public_key_hex: hex::encode(public_key),
            fingerprint: relay_identity_fingerprint(&public_key),
            software_version: version.into(),
            signature_hex: hex::encode(
                key.sign(&relay_identity_payload(relay_url, challenge, version))
                    .to_bytes(),
            ),
        }
    }

    #[test]
    fn relay_identity_requires_a_pinned_key_fresh_challenge_and_matching_url() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let challenge = [9; 32];
        let url = "https://relay.example.org/";
        let proof = proof_for(&key, url, &challenge);
        let pin = verify_relay_identity_proof(&proof, url, &challenge, &proof.fingerprint)
            .expect("verify pinned relay");
        assert_eq!(pin.fingerprint, proof.fingerprint);
        assert_eq!(
            verify_relay_identity_proof(&proof, url, &[8; 32], &proof.fingerprint),
            Err(RelayIdentityError::InvalidProof)
        );
        assert_eq!(
            verify_relay_identity_proof(
                &proof,
                "https://other.example.org/",
                &challenge,
                &proof.fingerprint
            ),
            Err(RelayIdentityError::InvalidProof)
        );
        assert_eq!(
            verify_relay_identity_proof(&proof, url, &challenge, &"00".repeat(32)),
            Err(RelayIdentityError::PinMismatch)
        );
    }
}
