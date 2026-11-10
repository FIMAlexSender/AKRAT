use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::net::SocketAddr;

pub const VERSION: u16 = 1;
pub const SUITE: &str = "AKRAT_X25519_MLKEM768_HKDFSHA256_ED25519_AES256GCM_V1";
pub const MAX_FRAME_SIZE: usize = 256 * 1024;

const INVITATION_PREFIX: &str = "akrat://v1/";
const MAX_INVITATION_SIZE: usize = 4096;
const MAX_INVITATION_ADDRESSES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    pub addresses: Vec<SocketAddr>,
    pub identity_id: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum InvitationError {
    #[error("invitation is malformed")]
    Malformed,
    #[error("invitation uses an unsupported version")]
    UnsupportedVersion,
    #[error("invitation data is inconsistent")]
    Inconsistent,
    #[error("invitation exceeds size or address limits")]
    TooLarge,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InvitationDocument {
    version: u8,
    identity_id: String,
    public_key: String,
    addresses: Vec<String>,
}

impl Invitation {
    pub fn new(addresses: Vec<SocketAddr>, public_key: [u8; 32]) -> Result<Self, InvitationError> {
        let identity_id = hex::encode(sha2::Sha256::digest(public_key));
        let invitation = Self {
            addresses,
            identity_id,
            public_key,
        };
        invitation.validate()?;
        Ok(invitation)
    }

    pub fn to_uri(&self) -> Result<String, InvitationError> {
        self.validate()?;
        let mut addresses: Vec<_> = self.addresses.iter().map(ToString::to_string).collect();
        addresses.sort();
        let document = InvitationDocument {
            version: 1,
            identity_id: self.identity_id.clone(),
            public_key: hex::encode(self.public_key),
            addresses,
        };
        let json = serde_json::to_vec(&document).map_err(|_| InvitationError::Malformed)?;
        let uri = format!(
            "{INVITATION_PREFIX}{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, json,)
        );
        if uri.len() > MAX_INVITATION_SIZE {
            return Err(InvitationError::TooLarge);
        }
        Ok(uri)
    }

    pub fn from_uri(uri: &str) -> Result<Self, InvitationError> {
        if uri.len() > MAX_INVITATION_SIZE {
            return Err(InvitationError::TooLarge);
        }
        let encoded = uri
            .strip_prefix(INVITATION_PREFIX)
            .ok_or(InvitationError::UnsupportedVersion)?;
        if encoded.is_empty() || encoded.contains('/') {
            return Err(InvitationError::Malformed);
        }
        let json =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, encoded)
                .map_err(|_| InvitationError::Malformed)?;
        let document: InvitationDocument =
            serde_json::from_slice(&json).map_err(|_| InvitationError::Malformed)?;
        if document.version != 1 {
            return Err(InvitationError::UnsupportedVersion);
        }
        let canonical_json =
            serde_json::to_vec(&document).map_err(|_| InvitationError::Malformed)?;
        if canonical_json != json {
            return Err(InvitationError::Malformed);
        }
        let key_bytes =
            hex::decode(&document.public_key).map_err(|_| InvitationError::Malformed)?;
        let public_key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| InvitationError::Inconsistent)?;
        let addresses = document
            .addresses
            .iter()
            .map(|address| {
                let parsed = address
                    .parse::<SocketAddr>()
                    .map_err(|_| InvitationError::Malformed)?;
                if parsed.to_string() != *address {
                    return Err(InvitationError::Malformed);
                }
                Ok(parsed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let invitation = Self {
            addresses,
            identity_id: document.identity_id,
            public_key,
        };
        invitation.validate()?;
        if invitation.to_uri()? != uri {
            return Err(InvitationError::Malformed);
        }
        Ok(invitation)
    }

    fn validate(&self) -> Result<(), InvitationError> {
        if self.addresses.is_empty() || self.addresses.len() > MAX_INVITATION_ADDRESSES {
            return Err(if self.addresses.len() > MAX_INVITATION_ADDRESSES {
                InvitationError::TooLarge
            } else {
                InvitationError::Inconsistent
            });
        }
        if hex::encode(sha2::Sha256::digest(self.public_key)) != self.identity_id {
            return Err(InvitationError::Inconsistent);
        }
        let mut unique = std::collections::HashSet::new();
        for address in &self.addresses {
            if address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
                || !unique.insert(*address)
            {
                return Err(InvitationError::Inconsistent);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Hello {
    pub version: u16,
    pub suite: String,
    pub identity_id: String,
    pub signing_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub mlkem_public_key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Response {
    pub version: u16,
    pub suite: String,
    pub identity_id: String,
    pub signing_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub mlkem_ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub key_confirmation: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finish {
    pub session_id: Vec<u8>,
    pub authenticator: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum HandshakeFrame {
    Hello(Hello),
    Response(Response),
    Finish(Finish),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedMessage {
    pub session_id: Vec<u8>,
    pub sender_id: String,
    pub recipient_id: String,
    pub sequence: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", content = "payload", deny_unknown_fields)]
pub enum SessionPayload {
    Text { message_id: String, text: String },
    Acknowledgement { message_id: String },
    Close,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame exceeds the protocol size limit")]
    TooLarge,
    #[error("frame encoding failed")]
    Encoding,
    #[error("frame is malformed")]
    Malformed,
}

pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let bytes = serde_json::to_vec(message).map_err(|_| FrameError::Encoding)?;
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }
    Ok(bytes)
}

pub fn decode_frame<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, FrameError> {
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| FrameError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::{EncryptedMessage, FrameError, decode_frame, encode_frame};

    #[test]
    fn message_frame_round_trip() {
        let frame = EncryptedMessage {
            session_id: vec![1; 32],
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            sequence: 7,
            nonce: vec![0; 12],
            ciphertext: vec![2; 32],
        };
        let encoded = encode_frame(&frame).expect("encode");
        let decoded: EncryptedMessage = decode_frame(&encoded).expect("decode");

        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.sender_id, "alice");
    }

    #[test]
    fn oversized_frame_is_rejected_before_decoding() {
        let oversized = vec![b' '; super::MAX_FRAME_SIZE + 1];
        assert!(matches!(
            decode_frame::<EncryptedMessage>(&oversized),
            Err(FrameError::TooLarge)
        ));
    }

    #[test]
    fn invitation_round_trips_with_canonical_addresses_and_public_identity() {
        let invitation = super::Invitation::new(
            vec![
                "[2001:db8::1]:49444".parse().expect("IPv6"),
                "192.0.2.15:49444".parse().expect("IPv4"),
            ],
            [3; 32],
        )
        .expect("invitation");
        let uri = invitation.to_uri().expect("encode");
        let decoded = super::Invitation::from_uri(&uri).expect("decode");

        assert_eq!(decoded.identity_id, invitation.identity_id);
        assert_eq!(decoded.public_key, invitation.public_key);
        assert_eq!(decoded.addresses.len(), 2);
        assert!(!uri.contains(&hex::encode(invitation.public_key)));
    }

    #[test]
    fn invitation_rejects_corrupt_malformed_and_inconsistent_data() {
        let invitation =
            super::Invitation::new(vec!["127.0.0.1:49444".parse().expect("address")], [4; 32])
                .expect("invitation");
        let uri = invitation.to_uri().expect("encode");

        assert!(matches!(
            super::Invitation::from_uri(&format!("{uri}x")),
            Err(super::InvitationError::Malformed)
        ));
        assert!(matches!(
            super::Invitation::from_uri("akrat://v1/not-base64!"),
            Err(super::InvitationError::Malformed)
        ));

        let mut inconsistent = invitation;
        inconsistent.identity_id = "00".repeat(32);
        assert!(matches!(
            inconsistent.to_uri(),
            Err(super::InvitationError::Inconsistent)
        ));
    }

    #[test]
    fn invitation_rejects_unsupported_versions_and_unsafe_addresses() {
        let unsupported =
            super::Invitation::new(vec!["127.0.0.1:49444".parse().expect("address")], [5; 32])
                .expect("invitation")
                .to_uri()
                .expect("encode")
                .replacen("akrat://v1/", "akrat://v2/", 1);
        assert!(matches!(
            super::Invitation::from_uri(&unsupported),
            Err(super::InvitationError::UnsupportedVersion)
        ));
        assert!(matches!(
            super::Invitation::new(vec!["0.0.0.0:49444".parse().expect("address")], [5; 32]),
            Err(super::InvitationError::Inconsistent)
        ));
    }
}
