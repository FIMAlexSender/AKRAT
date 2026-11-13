use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RelayDisposition {
    #[default]
    Allowed,
    Favorite,
    Monitor,
    Quarantined,
    Blocked,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RelayOperationalRecord {
    pub relay_url: String,
    pub disposition: RelayDisposition,
    pub successful_checks: u64,
    pub failed_checks: u64,
    pub identity_verification_failures: u64,
    pub latency_ewma_ms: Option<u32>,
    pub last_checked_unix_seconds: Option<u64>,
}

impl RelayOperationalRecord {
    pub fn record_check(&mut self, succeeded: bool, latency_ms: Option<u32>, now: u64) {
        self.last_checked_unix_seconds = Some(now);
        if succeeded {
            self.successful_checks = self.successful_checks.saturating_add(1);
            if let Some(sample) = latency_ms {
                self.latency_ewma_ms = Some(match self.latency_ewma_ms {
                    Some(previous) => ((u64::from(previous) * 7 + u64::from(sample)) / 8)
                        .min(u64::from(u32::MAX)) as u32,
                    None => sample,
                });
            }
        } else {
            self.failed_checks = self.failed_checks.saturating_add(1);
        }
    }

    pub fn record_identity_verification(&mut self, succeeded: bool) {
        if !succeeded {
            self.identity_verification_failures =
                self.identity_verification_failures.saturating_add(1);
        }
    }

    pub fn availability_percent(&self) -> Option<u8> {
        let total = self.successful_checks.saturating_add(self.failed_checks);
        (total != 0).then(|| ((self.successful_checks.saturating_mul(100) / total).min(100)) as u8)
    }

    pub fn is_eligible(&self) -> bool {
        !matches!(
            self.disposition,
            RelayDisposition::Quarantined | RelayDisposition::Blocked
        )
    }
}

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

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayDistributionClaim {
    pub artifact_name: String,
    pub artifact_sha256: String,
    pub source_commit: String,
    pub protocol_version: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayIdentityProofV2 {
    pub relay_url: String,
    pub challenge_hex: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub software_version: String,
    pub distribution: RelayDistributionClaim,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RelayEquivocationEvidence {
    pub version: u16,
    pub relay_url: String,
    pub observed_at_unix_seconds: u64,
    pub first: RelayIdentityProofV2,
    pub second: RelayIdentityProofV2,
}

pub const MAX_RELAY_EVIDENCE_JSON_BYTES: usize = 65_536;

pub const RELEASE_ATTESTATION_SCHEMA: &str = "akrat-release-attestation/v1";
pub const RELEASE_REPOSITORY: &str = "FIMAlexSender/AKRAT";
pub const RELEASE_WORKFLOW: &str = ".github/workflows/build.yml";
pub const RELEASE_TRUST_ROOT_KEY_HEX: &str =
    "809639fb0267fe0063f586cae3e5d86bb8e8dfd227e51d43f62f33c836955f3e";

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DistributionAsset {
    pub name: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAttestation {
    pub schema: String,
    pub repository: String,
    pub tag: String,
    pub version: String,
    pub source_commit: String,
    pub workflow: String,
    pub workflow_ref: String,
    pub run_id: u64,
    pub issued_unix_seconds: u64,
    pub protocol_version: u16,
    pub assets: Vec<DistributionAsset>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDistribution {
    pub repository: String,
    pub tag: String,
    pub version: String,
    pub source_commit: String,
    pub protocol_version: u16,
    pub assets: Vec<DistributionAsset>,
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
    #[error("release attestation is malformed or does not identify an official AKRAT build")]
    InvalidAttestation,
    #[error("release attestation signature is invalid")]
    InvalidAttestationSignature,
    #[error("release attestation does not include the relay artifact")]
    AttestedArtifactMissing,
    #[error("relay distribution claim is invalid")]
    InvalidDistributionClaim,
    #[error("official release provenance is unavailable")]
    ReleaseAttestationUnavailable,
    #[error("relay misconduct evidence is invalid or does not prove contradictory signed claims")]
    InvalidEvidence,
}

pub fn verify_relay_equivocation_evidence(
    evidence: &RelayEquivocationEvidence,
    expected_fingerprint: &str,
) -> Result<(), RelayIdentityError> {
    if evidence.version != 1
        || evidence.observed_at_unix_seconds == 0
        || evidence.relay_url.len() > 2048
    {
        return Err(RelayIdentityError::InvalidEvidence);
    }
    let first_challenge = hex::decode(&evidence.first.challenge_hex)
        .map_err(|_| RelayIdentityError::InvalidEvidence)?;
    if first_challenge.len() != 32
        || evidence.first.challenge_hex != evidence.second.challenge_hex
        || evidence.first.relay_url != evidence.relay_url
        || evidence.second.relay_url != evidence.relay_url
        || evidence.first.public_key_hex != evidence.second.public_key_hex
        || evidence.first.fingerprint != evidence.second.fingerprint
        || evidence.first == evidence.second
    {
        return Err(RelayIdentityError::InvalidEvidence);
    }
    verify_relay_identity_proof_v2(
        &evidence.first,
        &evidence.relay_url,
        &first_challenge,
        expected_fingerprint,
    )?;
    verify_relay_identity_proof_v2(
        &evidence.second,
        &evidence.relay_url,
        &first_challenge,
        expected_fingerprint,
    )?;
    Ok(())
}

pub fn parse_and_verify_relay_equivocation_evidence(
    bytes: &[u8],
    expected_fingerprint: &str,
) -> Result<RelayEquivocationEvidence, RelayIdentityError> {
    if bytes.is_empty() || bytes.len() > MAX_RELAY_EVIDENCE_JSON_BYTES {
        return Err(RelayIdentityError::InvalidEvidence);
    }
    let evidence: RelayEquivocationEvidence =
        serde_json::from_slice(bytes).map_err(|_| RelayIdentityError::InvalidEvidence)?;
    verify_relay_equivocation_evidence(&evidence, expected_fingerprint)?;
    Ok(evidence)
}

pub fn relay_identity_v2_payload(
    relay_url: &str,
    challenge: &[u8],
    software_version: &str,
    distribution: &RelayDistributionClaim,
) -> Result<Vec<u8>, RelayIdentityError> {
    validate_distribution_claim(distribution)?;
    let mut payload = b"AKRAT_RELAY_IDENTITY_V2".to_vec();
    for value in [
        relay_url.as_bytes(),
        challenge,
        software_version.as_bytes(),
        distribution.artifact_name.as_bytes(),
        distribution.artifact_sha256.as_bytes(),
        distribution.source_commit.as_bytes(),
    ] {
        payload.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| RelayIdentityError::InvalidDistributionClaim)?
                .to_be_bytes(),
        );
        payload.extend_from_slice(value);
    }
    payload.extend_from_slice(&distribution.protocol_version.to_be_bytes());
    Ok(payload)
}

pub fn verify_relay_identity_proof_v2(
    proof: &RelayIdentityProofV2,
    expected_url: &str,
    expected_challenge: &[u8],
    expected_fingerprint: &str,
) -> Result<(RelayIdentityPin, RelayDistributionClaim), RelayIdentityError> {
    let public_key = decode_pinned_public_key(
        &proof.public_key_hex,
        &proof.fingerprint,
        expected_fingerprint,
    )?;
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
        &relay_identity_v2_payload(
            expected_url,
            expected_challenge,
            &proof.software_version,
            &proof.distribution,
        )?,
        &signature,
    )
    .map_err(|_| RelayIdentityError::InvalidProof)?;
    Ok((
        RelayIdentityPin {
            relay_url: expected_url.to_string(),
            public_key_hex: hex::encode(public_key),
            fingerprint: relay_identity_fingerprint(&public_key),
        },
        proof.distribution.clone(),
    ))
}

pub fn verify_distribution_claim(
    claim: &RelayDistributionClaim,
    attestation: &ReleaseAttestation,
    signature_hex: &str,
    trusted_release_key: &[u8; 32],
    relay_version: &str,
) -> Result<VerifiedDistribution, RelayIdentityError> {
    validate_distribution_claim(claim)?;
    let verified = verify_release_attestation(attestation, signature_hex, trusted_release_key)?;
    if verified.version != relay_version
        || verified.source_commit != claim.source_commit
        || verified.protocol_version != claim.protocol_version
    {
        return Err(RelayIdentityError::InvalidDistributionClaim);
    }
    verify_attested_artifact(&verified, &claim.artifact_name, &claim.artifact_sha256)?;
    Ok(verified)
}

pub fn verify_official_distribution_claim(
    claim: &RelayDistributionClaim,
    attestation: &ReleaseAttestation,
    signature_hex: &str,
    relay_version: &str,
) -> Result<VerifiedDistribution, RelayIdentityError> {
    validate_distribution_claim(claim)?;
    let verified = verify_official_release_attestation(attestation, signature_hex)?;
    if verified.version != relay_version
        || verified.source_commit != claim.source_commit
        || verified.protocol_version != claim.protocol_version
    {
        return Err(RelayIdentityError::InvalidDistributionClaim);
    }
    verify_attested_artifact(&verified, &claim.artifact_name, &claim.artifact_sha256)?;
    Ok(verified)
}

fn decode_pinned_public_key(
    public_key_hex: &str,
    presented_fingerprint: &str,
    expected_fingerprint: &str,
) -> Result<[u8; 32], RelayIdentityError> {
    let public_key: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|_| RelayIdentityError::InvalidProof)?
        .try_into()
        .map_err(|_| RelayIdentityError::InvalidProof)?;
    let fingerprint = relay_identity_fingerprint(&public_key);
    if !fingerprint.eq_ignore_ascii_case(expected_fingerprint)
        || !fingerprint.eq_ignore_ascii_case(presented_fingerprint)
    {
        return Err(RelayIdentityError::PinMismatch);
    }
    Ok(public_key)
}

fn validate_distribution_claim(claim: &RelayDistributionClaim) -> Result<(), RelayIdentityError> {
    let name_is_safe = !claim.artifact_name.is_empty()
        && claim.artifact_name.len() <= 255
        && claim
            .artifact_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if !name_is_safe
        || claim.artifact_sha256.len() != 64
        || !claim
            .artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || claim.source_commit.len() != 40
        || !claim
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || claim.protocol_version == 0
    {
        return Err(RelayIdentityError::InvalidDistributionClaim);
    }
    Ok(())
}

pub fn release_attestation_payload(
    attestation: &ReleaseAttestation,
) -> Result<Vec<u8>, RelayIdentityError> {
    validate_release_attestation(attestation)?;
    let mut payload = b"AKRAT_RELEASE_ATTESTATION_V1".to_vec();
    for value in [
        attestation.schema.as_bytes(),
        attestation.repository.as_bytes(),
        attestation.tag.as_bytes(),
        attestation.version.as_bytes(),
        attestation.source_commit.as_bytes(),
        attestation.workflow.as_bytes(),
        attestation.workflow_ref.as_bytes(),
    ] {
        payload.extend_from_slice(
            &u32::try_from(value.len())
                .map_err(|_| RelayIdentityError::InvalidAttestation)?
                .to_be_bytes(),
        );
        payload.extend_from_slice(value);
    }
    payload.extend_from_slice(&attestation.run_id.to_be_bytes());
    payload.extend_from_slice(&attestation.issued_unix_seconds.to_be_bytes());
    payload.extend_from_slice(&attestation.protocol_version.to_be_bytes());
    payload.extend_from_slice(
        &u32::try_from(attestation.assets.len())
            .map_err(|_| RelayIdentityError::InvalidAttestation)?
            .to_be_bytes(),
    );
    for asset in &attestation.assets {
        for value in [asset.name.as_bytes(), asset.sha256.as_bytes()] {
            payload.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| RelayIdentityError::InvalidAttestation)?
                    .to_be_bytes(),
            );
            payload.extend_from_slice(value);
        }
    }
    Ok(payload)
}

pub fn verify_release_attestation(
    attestation: &ReleaseAttestation,
    signature_hex: &str,
    trusted_release_key: &[u8; 32],
) -> Result<VerifiedDistribution, RelayIdentityError> {
    let payload = release_attestation_payload(attestation)?;
    let signature = Signature::from_slice(
        &hex::decode(signature_hex).map_err(|_| RelayIdentityError::InvalidAttestationSignature)?,
    )
    .map_err(|_| RelayIdentityError::InvalidAttestationSignature)?;
    let key = VerifyingKey::from_bytes(trusted_release_key)
        .map_err(|_| RelayIdentityError::InvalidAttestationSignature)?;
    key.verify(&payload, &signature)
        .map_err(|_| RelayIdentityError::InvalidAttestationSignature)?;
    Ok(VerifiedDistribution {
        repository: attestation.repository.clone(),
        tag: attestation.tag.clone(),
        version: attestation.version.clone(),
        source_commit: attestation.source_commit.clone(),
        protocol_version: attestation.protocol_version,
        assets: attestation.assets.clone(),
    })
}

pub fn verify_official_release_attestation(
    attestation: &ReleaseAttestation,
    signature_hex: &str,
) -> Result<VerifiedDistribution, RelayIdentityError> {
    let key: [u8; 32] = hex::decode(RELEASE_TRUST_ROOT_KEY_HEX)
        .map_err(|_| RelayIdentityError::InvalidAttestationSignature)?
        .try_into()
        .map_err(|_| RelayIdentityError::InvalidAttestationSignature)?;
    verify_release_attestation(attestation, signature_hex, &key)
}

pub fn verify_attested_artifact(
    attestation: &VerifiedDistribution,
    artifact_name: &str,
    artifact_sha256: &str,
) -> Result<(), RelayIdentityError> {
    let Some(asset) = attestation
        .assets
        .iter()
        .find(|asset| asset.name == artifact_name)
    else {
        return Err(RelayIdentityError::AttestedArtifactMissing);
    };
    if !asset.sha256.eq_ignore_ascii_case(artifact_sha256) {
        return Err(RelayIdentityError::InvalidAttestation);
    }
    Ok(())
}

fn validate_release_attestation(
    attestation: &ReleaseAttestation,
) -> Result<(), RelayIdentityError> {
    let version = semver::Version::parse(&attestation.version)
        .map_err(|_| RelayIdentityError::InvalidAttestation)?;
    if attestation.schema != RELEASE_ATTESTATION_SCHEMA
        || attestation.repository != RELEASE_REPOSITORY
        || attestation.tag != format!("v{version}")
        || attestation.source_commit.len() != 40
        || !attestation
            .source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || attestation.workflow != RELEASE_WORKFLOW
        || attestation.workflow_ref
            != format!(
                "{}/{workflow}@refs/tags/{}",
                RELEASE_REPOSITORY,
                attestation.tag,
                workflow = RELEASE_WORKFLOW
            )
        || attestation.run_id == 0
        || attestation.issued_unix_seconds == 0
        || attestation.protocol_version == 0
        || attestation.assets.is_empty()
        || attestation.assets.len() > 256
    {
        return Err(RelayIdentityError::InvalidAttestation);
    }
    let mut previous_name: Option<&str> = None;
    for asset in &attestation.assets {
        let name_is_safe = !asset.name.is_empty()
            && asset.name.len() <= 255
            && asset
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if !name_is_safe
            || asset.sha256.len() != 64
            || !asset
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || previous_name.is_some_and(|previous| previous >= asset.name.as_str())
        {
            return Err(RelayIdentityError::InvalidAttestation);
        }
        previous_name = Some(&asset.name);
    }
    Ok(())
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
        .post(endpoint.clone())
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

#[cfg(feature = "client")]
pub async fn verify_remote_relay_identity_with_trust(
    relay_url: &str,
    expected_fingerprint: &str,
    minimum_trust: RelayTrustLevel,
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
    endpoint.set_path("/.well-known/akrat/v2/challenge");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    verify_remote_relay_identity_with_trust_at(
        &canonical_url,
        endpoint.as_str(),
        expected_fingerprint,
        minimum_trust,
    )
    .await
}

#[cfg(feature = "client")]
pub async fn verify_remote_relay_identity_with_trust_at(
    relay_url: &str,
    identity_endpoint: &str,
    expected_fingerprint: &str,
    minimum_trust: RelayTrustLevel,
) -> Result<RelayIdentityPin, RelayIdentityError> {
    if minimum_trust < RelayTrustLevel::DistributionVerified {
        return verify_remote_relay_identity_at(relay_url, identity_endpoint, expected_fingerprint)
            .await;
    }
    if minimum_trust >= RelayTrustLevel::ExecutionAttested {
        return Err(RelayIdentityError::HigherTrustUnavailable);
    }
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
    endpoint.set_path("/.well-known/akrat/v2/challenge");
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    let mut challenge = [0u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| RelayIdentityError::InvalidProof)?;
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| RelayIdentityError::Unreachable)?;
    let response = client
        .post(endpoint.clone())
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
    if response
        .content_length()
        .is_some_and(|length| length > 8192)
    {
        return Err(RelayIdentityError::InvalidResponse);
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| RelayIdentityError::InvalidResponse)?;
    if bytes.len() > 8192 {
        return Err(RelayIdentityError::InvalidResponse);
    }
    let proof: RelayIdentityProofV2 =
        serde_json::from_slice(&bytes).map_err(|_| RelayIdentityError::InvalidResponse)?;
    let (pin, claim) =
        verify_relay_identity_proof_v2(&proof, &canonical_url, &challenge, expected_fingerprint)?;
    verify_remote_distribution_claim(&claim, &proof.software_version, endpoint.as_str(), &client)
        .await?;
    Ok(pin)
}

#[cfg(feature = "client")]
async fn verify_remote_distribution_claim(
    claim: &RelayDistributionClaim,
    relay_version: &str,
    identity_endpoint: &str,
    client: &reqwest::Client,
) -> Result<VerifiedDistribution, RelayIdentityError> {
    let version = semver::Version::parse(relay_version)
        .map_err(|_| RelayIdentityError::InvalidDistributionClaim)?;
    if !version.pre.is_empty() || !version.build.is_empty() {
        return Err(RelayIdentityError::InvalidDistributionClaim);
    }
    let tag = format!("v{version}");
    let relay_attestation = fetch_limited_relay_asset(
        client,
        identity_endpoint,
        "/.well-known/akrat/v2/release-attestation.json",
        1_048_576,
    )
    .await;
    let relay_signature = fetch_limited_relay_asset(
        client,
        identity_endpoint,
        "/.well-known/akrat/v2/release-attestation.sig",
        256,
    )
    .await;
    let (attestation_bytes, signature_bytes) = match (relay_attestation, relay_signature) {
        (Ok(attestation), Ok(signature)) => (attestation, signature),
        _ => {
            let base = format!(
                "https://github.com/{RELEASE_REPOSITORY}/releases/download/{tag}/AKRAT-{tag}-release-attestation"
            );
            (
                fetch_limited_release_asset(client, &format!("{base}.json"), 1_048_576).await?,
                fetch_limited_release_asset(client, &format!("{base}.sig"), 256).await?,
            )
        }
    };
    let attestation: ReleaseAttestation = serde_json::from_slice(&attestation_bytes)
        .map_err(|_| RelayIdentityError::InvalidResponse)?;
    let signature = std::str::from_utf8(&signature_bytes)
        .map_err(|_| RelayIdentityError::InvalidResponse)?
        .trim();
    verify_official_distribution_claim(claim, &attestation, signature, relay_version)
}

#[cfg(feature = "client")]
async fn fetch_limited_relay_asset(
    client: &reqwest::Client,
    identity_endpoint: &str,
    path: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RelayIdentityError> {
    let mut url =
        reqwest::Url::parse(identity_endpoint).map_err(|_| RelayIdentityError::InvalidProof)?;
    if url.scheme() != "http" || url.host_str().is_none() {
        return Err(RelayIdentityError::InvalidProof);
    }
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    let requested_origin = url.origin();
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| RelayIdentityError::ReleaseAttestationUnavailable)?;
    if response.url().origin() != requested_origin
        || !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(RelayIdentityError::ReleaseAttestationUnavailable);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RelayIdentityError::ReleaseAttestationUnavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(RelayIdentityError::ReleaseAttestationUnavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(feature = "client")]
async fn fetch_limited_release_asset(
    client: &reqwest::Client,
    asset_url: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, RelayIdentityError> {
    let url = reqwest::Url::parse(asset_url).map_err(|_| RelayIdentityError::InvalidAttestation)?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url
            .path()
            .starts_with(&format!("/{RELEASE_REPOSITORY}/releases/download/v"))
    {
        return Err(RelayIdentityError::InvalidAttestation);
    }
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| RelayIdentityError::ReleaseAttestationUnavailable)?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(RelayIdentityError::ReleaseAttestationUnavailable);
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(maximum_bytes as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RelayIdentityError::ReleaseAttestationUnavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(RelayIdentityError::ReleaseAttestationUnavailable);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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

    fn release_attestation() -> ReleaseAttestation {
        let tag = "v0.1.12";
        ReleaseAttestation {
            schema: RELEASE_ATTESTATION_SCHEMA.into(),
            repository: RELEASE_REPOSITORY.into(),
            tag: tag.into(),
            version: "0.1.12".into(),
            source_commit: "a".repeat(40),
            workflow: RELEASE_WORKFLOW.into(),
            workflow_ref: format!("{RELEASE_REPOSITORY}/{RELEASE_WORKFLOW}@refs/tags/{tag}"),
            run_id: 123456789,
            issued_unix_seconds: 1_794_513_600,
            protocol_version: 1,
            assets: vec![
                DistributionAsset {
                    name: "AKRAT-v0.1.12-relay-linux-x64".into(),
                    sha256: "1a".repeat(32),
                },
                DistributionAsset {
                    name: "AKRAT-v0.1.12-relay-windows-x64.exe".into(),
                    sha256: "2b".repeat(32),
                },
            ],
        }
    }

    fn signed_release_attestation(key: &SigningKey) -> (ReleaseAttestation, String) {
        let attestation = release_attestation();
        let signature = hex::encode(
            key.sign(&release_attestation_payload(&attestation).unwrap())
                .to_bytes(),
        );
        (attestation, signature)
    }

    fn proof_v2_for(
        key: &SigningKey,
        relay_url: &str,
        challenge: &[u8],
        software_version: &str,
        distribution: RelayDistributionClaim,
    ) -> RelayIdentityProofV2 {
        let public_key = key.verifying_key().to_bytes();
        RelayIdentityProofV2 {
            relay_url: relay_url.into(),
            challenge_hex: hex::encode(challenge),
            public_key_hex: hex::encode(public_key),
            fingerprint: relay_identity_fingerprint(&public_key),
            software_version: software_version.into(),
            signature_hex: hex::encode(
                key.sign(
                    &relay_identity_v2_payload(
                        relay_url,
                        challenge,
                        software_version,
                        &distribution,
                    )
                    .unwrap(),
                )
                .to_bytes(),
            ),
            distribution,
        }
    }

    #[test]
    fn signed_release_attestation_is_bound_to_repository_workflow_and_artifact() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let attestation = release_attestation();
        let signature = hex::encode(
            key.sign(&release_attestation_payload(&attestation).unwrap())
                .to_bytes(),
        );
        let verified =
            verify_release_attestation(&attestation, &signature, &key.verifying_key().to_bytes())
                .expect("official release attestation verifies");
        verify_attested_artifact(&verified, "AKRAT-v0.1.12-relay-linux-x64", &"1A".repeat(32))
            .expect("matching artifact digest verifies");
        assert_eq!(verified.source_commit, "a".repeat(40));
        assert_eq!(verified.protocol_version, 1);
        assert_eq!(
            verify_attested_artifact(&verified, "AKRAT-v0.1.12-relay-linux-x64", &"ff".repeat(32),),
            Err(RelayIdentityError::InvalidAttestation)
        );
        assert_eq!(
            verify_attested_artifact(&verified, "unknown-relay", &"1a".repeat(32)),
            Err(RelayIdentityError::AttestedArtifactMissing)
        );
    }

    #[test]
    fn embedded_release_trust_root_verifies_a_pinned_release_vector() {
        let attestation = release_attestation();
        let signature = "f907aa16a4d501de7c81a5bd3ca7e20559843452839b3fc20fe5d43350df246fc68116d75c76893da10e004f1fb267babba66209d8cb0f6459b4b4d3f644f606";
        let verified = verify_official_release_attestation(&attestation, signature)
            .expect("release trust root verifies its fixture vector");
        let claim = RelayDistributionClaim {
            artifact_name: "AKRAT-v0.1.12-relay-linux-x64".into(),
            artifact_sha256: "1a".repeat(32),
            source_commit: "a".repeat(40),
            protocol_version: 1,
        };
        verify_attested_artifact(&verified, &claim.artifact_name, &claim.artifact_sha256)
            .expect("release artifact digest is covered");
        let mut altered = attestation;
        altered.source_commit = "b".repeat(40);
        assert_eq!(
            verify_official_release_attestation(&altered, signature),
            Err(RelayIdentityError::InvalidAttestationSignature)
        );
    }

    #[test]
    fn release_attestation_rejects_modified_metadata_wrong_key_and_bad_signature() {
        let key = SigningKey::from_bytes(&[33; 32]);
        let attestation = release_attestation();
        let signature = hex::encode(
            key.sign(&release_attestation_payload(&attestation).unwrap())
                .to_bytes(),
        );
        let mut altered = attestation.clone();
        altered.source_commit = "b".repeat(40);
        assert_eq!(
            verify_release_attestation(&altered, &signature, &key.verifying_key().to_bytes()),
            Err(RelayIdentityError::InvalidAttestationSignature)
        );
        assert_eq!(
            verify_release_attestation(
                &attestation,
                &signature,
                &SigningKey::from_bytes(&[34; 32]).verifying_key().to_bytes(),
            ),
            Err(RelayIdentityError::InvalidAttestationSignature)
        );
        assert_eq!(
            verify_release_attestation(&attestation, "not-hex", &key.verifying_key().to_bytes()),
            Err(RelayIdentityError::InvalidAttestationSignature)
        );
    }

    #[test]
    fn release_attestation_rejects_noncanonical_or_untrusted_metadata() {
        let mut attestation = release_attestation();
        attestation.repository = "attacker/AKRAT".into();
        assert_eq!(
            release_attestation_payload(&attestation),
            Err(RelayIdentityError::InvalidAttestation)
        );
        let mut attestation = release_attestation();
        attestation.assets.reverse();
        assert_eq!(
            release_attestation_payload(&attestation),
            Err(RelayIdentityError::InvalidAttestation)
        );
        let mut attestation = release_attestation();
        attestation.assets[0].name = "../relay".into();
        assert_eq!(
            release_attestation_payload(&attestation),
            Err(RelayIdentityError::InvalidAttestation)
        );
        let mut attestation = release_attestation();
        attestation.workflow_ref = "FIMAlexSender/AKRAT/build.yml@refs/heads/main".into();
        assert_eq!(
            release_attestation_payload(&attestation),
            Err(RelayIdentityError::InvalidAttestation)
        );
    }

    #[test]
    fn relay_v2_distribution_claim_is_signed_with_the_fresh_identity_challenge() {
        let key = SigningKey::from_bytes(&[35; 32]);
        let url = "https://relay.example.org/";
        let challenge = [37; 32];
        let claim = RelayDistributionClaim {
            artifact_name: "AKRAT-v0.1.12-relay-linux-x64".into(),
            artifact_sha256: "1a".repeat(32),
            source_commit: "a".repeat(40),
            protocol_version: 1,
        };
        let proof = proof_v2_for(&key, url, &challenge, "0.1.12", claim.clone());
        let (pin, verified_claim) =
            verify_relay_identity_proof_v2(&proof, url, &challenge, &proof.fingerprint)
                .expect("fresh relay distribution claim verifies");
        assert_eq!(pin.fingerprint, proof.fingerprint);
        assert_eq!(verified_claim, claim);
        assert_eq!(
            verify_relay_identity_proof_v2(&proof, url, &[38; 32], &proof.fingerprint),
            Err(RelayIdentityError::InvalidProof)
        );
        let mut altered = proof;
        altered.distribution.artifact_sha256 = "ff".repeat(32);
        assert_eq!(
            verify_relay_identity_proof_v2(&altered, url, &challenge, &altered.fingerprint),
            Err(RelayIdentityError::InvalidProof)
        );
    }

    #[test]
    fn signed_equivocation_evidence_is_independently_verifiable_and_tamper_evident() {
        let key = SigningKey::from_bytes(&[41; 32]);
        let url = "https://relay.example.org/";
        let challenge = [42; 32];
        let first_claim = RelayDistributionClaim {
            artifact_name: "AKRAT-v0.1.12-relay-linux-x64".into(),
            artifact_sha256: "1a".repeat(32),
            source_commit: "a".repeat(40),
            protocol_version: 1,
        };
        let second_claim = RelayDistributionClaim {
            artifact_sha256: "2b".repeat(32),
            ..first_claim.clone()
        };
        let first = proof_v2_for(&key, url, &challenge, "0.1.12", first_claim);
        let second = proof_v2_for(&key, url, &challenge, "0.1.12", second_claim);
        let evidence = RelayEquivocationEvidence {
            version: 1,
            relay_url: url.into(),
            observed_at_unix_seconds: 1_794_513_600,
            first,
            second,
        };
        verify_relay_equivocation_evidence(&evidence, &evidence.first.fingerprint)
            .expect("contradictory signed statements prove equivocation");

        let mut forged = evidence;
        forged.second.distribution.artifact_sha256 = "3c".repeat(32);
        assert!(verify_relay_equivocation_evidence(&forged, &forged.first.fingerprint).is_err());
    }

    #[test]
    fn operational_reputation_is_separate_from_cryptographic_trust_and_local_disposition() {
        let mut record = RelayOperationalRecord {
            relay_url: "https://relay.example.org".into(),
            ..RelayOperationalRecord::default()
        };
        record.record_check(true, Some(80), 100);
        record.record_check(false, None, 101);
        record.record_check(true, Some(120), 102);
        assert_eq!(record.availability_percent(), Some(66));
        assert_eq!(record.latency_ewma_ms, Some(85));
        assert_eq!(record.last_checked_unix_seconds, Some(102));
        assert!(record.is_eligible());
        record.record_identity_verification(false);
        assert_eq!(record.identity_verification_failures, 1);
        record.disposition = RelayDisposition::Quarantined;
        assert!(!record.is_eligible());
        assert_eq!(record.availability_percent(), Some(66));
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn relay_sidecar_fetch_is_origin_bound_and_size_limited() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local HTTP fixture");
        let address = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept fixture request");
            let mut request = [0; 1024];
            let _ = stream
                .read(&mut request)
                .await
                .expect("read fixture request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nproof",
                )
                .await
                .expect("write fixture response");
        });
        let client = reqwest::Client::new();
        let endpoint = format!("http://{address}/.well-known/akrat/v2/challenge");
        let bytes = fetch_limited_relay_asset(
            &client,
            &endpoint,
            "/.well-known/akrat/v2/release-attestation.json",
            5,
        )
        .await
        .expect("fetch bounded release sidecar from the relay origin");
        assert_eq!(bytes, b"proof");
        server.await.expect("fixture server completes");

        assert_eq!(
            fetch_limited_relay_asset(&client, &endpoint, "/asset", 4).await,
            Err(RelayIdentityError::ReleaseAttestationUnavailable)
        );
    }

    #[test]
    fn distribution_claim_must_match_the_signed_release_tag_commit_protocol_and_digest() {
        let release_key = SigningKey::from_bytes(&[39; 32]);
        let (attestation, signature) = signed_release_attestation(&release_key);
        let claim = RelayDistributionClaim {
            artifact_name: "AKRAT-v0.1.12-relay-linux-x64".into(),
            artifact_sha256: "1a".repeat(32),
            source_commit: "a".repeat(40),
            protocol_version: 1,
        };
        let verified = verify_distribution_claim(
            &claim,
            &attestation,
            &signature,
            &release_key.verifying_key().to_bytes(),
            "0.1.12",
        )
        .expect("relay claim matches the signed distribution");
        assert_eq!(verified.tag, "v0.1.12");
        assert_eq!(
            verify_distribution_claim(
                &claim,
                &attestation,
                &signature,
                &release_key.verifying_key().to_bytes(),
                "0.1.11",
            ),
            Err(RelayIdentityError::InvalidDistributionClaim)
        );
        let mut changed_claim = claim;
        changed_claim.protocol_version = 2;
        assert_eq!(
            verify_distribution_claim(
                &changed_claim,
                &attestation,
                &signature,
                &release_key.verifying_key().to_bytes(),
                "0.1.12",
            ),
            Err(RelayIdentityError::InvalidDistributionClaim)
        );
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
