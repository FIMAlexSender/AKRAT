use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const SUITE: &str = "AKRAT_X25519_MLKEM768_HKDFSHA256_ED25519_AES256GCM_V1";
pub const MAX_FRAME_SIZE: usize = 256 * 1024;

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
pub struct EncryptedMessage {
    pub session_id: Vec<u8>,
    pub sender_id: String,
    pub recipient_id: String,
    pub sequence: u64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
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
}
