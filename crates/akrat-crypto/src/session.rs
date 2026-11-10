use crate::{IdentityError, verify};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use akrat_core::PrivateIdentity;
use akrat_protocol::{EncryptedMessage, Finish, Hello, Response, SUITE, VERSION};
use ed25519_dalek::Signature;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{Key, MlKem768, ml_kem_768::EncapsulationKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroizing;

const MAX_PLAINTEXT_SIZE: usize = 64 * 1024;
const MAX_SEQUENCE: u64 = u64::MAX - 1;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("handshake parameters are unsupported")]
    Parameters,
    #[error("peer identity is invalid")]
    Identity,
    #[error("handshake signature is invalid")]
    Signature,
    #[error("handshake key material is invalid")]
    KeyMaterial,
    #[error("key confirmation failed")]
    KeyConfirmation,
    #[error("secure random generation failed")]
    Random,
    #[error("handshake encoding failed")]
    Encoding,
    #[error("session message is invalid or out of sequence")]
    Sequence,
    #[error("message exceeds the size limit")]
    TooLarge,
    #[error("message authentication failed")]
    Authentication,
    #[error("session sequence space is exhausted")]
    Exhausted,
}

impl From<IdentityError> for SessionError {
    fn from(_: IdentityError) -> Self {
        Self::Identity
    }
}

pub struct InitiatorPending {
    identity_id: String,
    ephemeral_secret: EphemeralSecret,
    kem_decapsulation_key: ml_kem::ml_kem_768::DecapsulationKey,
    hello: Hello,
}

pub struct ResponderPending {
    local_identity_id: String,
    remote_identity_id: String,
    remote_public_key: Vec<u8>,
    keys: SessionKeys,
    transcript_hash: [u8; 32],
}

pub struct Session {
    session_id: [u8; 16],
    local_identity_id: String,
    remote_identity_id: String,
    send_key: Zeroizing<[u8; 32]>,
    receive_key: Zeroizing<[u8; 32]>,
    send_sequence: u64,
    receive_sequence: u64,
}

struct SessionKeys {
    session_id: [u8; 16],
    initiator_to_responder: Zeroizing<[u8; 32]>,
    responder_to_initiator: Zeroizing<[u8; 32]>,
}

#[derive(Serialize)]
struct HelloSigning<'a> {
    domain: &'static str,
    version: u16,
    suite: &'a str,
    identity_id: &'a str,
    signing_public_key: &'a [u8],
    x25519_public_key: &'a [u8],
    mlkem_public_key: &'a [u8],
    nonce: &'a [u8],
}

#[derive(Serialize)]
struct ResponseCore<'a> {
    version: u16,
    suite: &'a str,
    identity_id: &'a str,
    signing_public_key: &'a [u8],
    x25519_public_key: &'a [u8],
    mlkem_ciphertext: &'a [u8],
    nonce: &'a [u8],
}

#[derive(Serialize)]
struct FinishSigning<'a> {
    domain: &'static str,
    transcript_hash: &'a [u8; 32],
    session_id: &'a [u8],
    authenticator: &'a [u8],
}

#[derive(Serialize)]
struct MessageAad<'a> {
    version: u16,
    session_id: &'a [u8],
    sender_id: &'a str,
    recipient_id: &'a str,
    sequence: u64,
}

pub fn start_handshake(
    identity: &PrivateIdentity,
) -> Result<(Hello, InitiatorPending), SessionError> {
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public_key = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let (kem_decapsulation_key, kem_encapsulation_key) = MlKem768::generate_keypair();
    let kem_public_key = kem_encapsulation_key.to_bytes();
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| SessionError::Random)?;
    let mut hello = Hello {
        version: VERSION,
        suite: SUITE.to_string(),
        identity_id: identity.public.id.clone(),
        signing_public_key: identity.public.public_key.clone(),
        x25519_public_key: ephemeral_public_key.to_vec(),
        mlkem_public_key: kem_public_key.as_slice().to_vec(),
        nonce: nonce.to_vec(),
        signature: Vec::new(),
    };
    let payload = hello_signing_bytes(&hello)?;
    hello.signature = identity.sign(&payload).to_bytes().to_vec();
    let pending = InitiatorPending {
        identity_id: identity.public.id.clone(),
        ephemeral_secret,
        kem_decapsulation_key,
        hello: hello.clone(),
    };
    Ok((hello, pending))
}

pub fn respond_to_handshake(
    identity: &PrivateIdentity,
    hello: &Hello,
) -> Result<(Response, ResponderPending), SessionError> {
    validate_hello(hello)?;
    let hello_payload = hello_signing_bytes(hello)?;
    let hello_signature =
        Signature::from_slice(&hello.signature).map_err(|_| SessionError::Signature)?;
    verify(&hello.signing_public_key, &hello_payload, &hello_signature)
        .map_err(|_| SessionError::Signature)?;

    let remote_x25519_bytes: [u8; 32] = hello
        .x25519_public_key
        .as_slice()
        .try_into()
        .map_err(|_| SessionError::KeyMaterial)?;
    let remote_x25519_key = X25519PublicKey::from(remote_x25519_bytes);
    let ephemeral_secret = EphemeralSecret::random();
    let local_x25519_public_key = X25519PublicKey::from(&ephemeral_secret).to_bytes();
    let x25519_secret = ephemeral_secret.diffie_hellman(&remote_x25519_key);
    if !x25519_secret.was_contributory() {
        return Err(SessionError::KeyMaterial);
    }
    let x25519_shared = Zeroizing::new(x25519_secret.to_bytes());

    let encoded_kem_key = Key::<EncapsulationKey>::try_from(hello.mlkem_public_key.as_slice())
        .map_err(|_| SessionError::KeyMaterial)?;
    let kem_encapsulation_key =
        EncapsulationKey::new(&encoded_kem_key).map_err(|_| SessionError::KeyMaterial)?;
    let (kem_ciphertext, kem_shared) = kem_encapsulation_key.encapsulate();
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| SessionError::Random)?;
    let mut response = Response {
        version: VERSION,
        suite: SUITE.to_string(),
        identity_id: identity.public.id.clone(),
        signing_public_key: identity.public.public_key.clone(),
        x25519_public_key: local_x25519_public_key.to_vec(),
        mlkem_ciphertext: kem_ciphertext.as_slice().to_vec(),
        nonce: nonce.to_vec(),
        key_confirmation: Vec::new(),
        signature: Vec::new(),
    };
    let transcript_hash = transcript_hash(hello, &response)?;
    let keys = derive_session_keys(
        &transcript_hash,
        x25519_shared.as_slice(),
        kem_shared.as_slice(),
    )?;
    response.key_confirmation =
        confirmation_tag(&keys.responder_to_initiator, &transcript_hash, b"responder");
    let response_signature_payload =
        response_signature_bytes(&transcript_hash, &response.key_confirmation);
    response.signature = identity
        .sign(&response_signature_payload)
        .to_bytes()
        .to_vec();
    let pending = ResponderPending {
        local_identity_id: identity.public.id.clone(),
        remote_identity_id: hello.identity_id.clone(),
        remote_public_key: hello.signing_public_key.clone(),
        keys,
        transcript_hash,
    };
    Ok((response, pending))
}

impl InitiatorPending {
    pub fn complete(
        self,
        identity: &PrivateIdentity,
        response: &Response,
        expected_peer_public_key: Option<&[u8]>,
    ) -> Result<(Finish, Session), SessionError> {
        if identity.public.id != self.identity_id {
            return Err(SessionError::Identity);
        }
        validate_response(response)?;
        if expected_peer_public_key.is_some_and(|expected| expected != response.signing_public_key)
        {
            return Err(SessionError::Identity);
        }
        let response_signature_payload = response_signature_bytes(
            &transcript_hash(&self.hello, response)?,
            &response.key_confirmation,
        );
        let response_signature =
            Signature::from_slice(&response.signature).map_err(|_| SessionError::Signature)?;
        verify(
            &response.signing_public_key,
            &response_signature_payload,
            &response_signature,
        )
        .map_err(|_| SessionError::Signature)?;

        let transcript_hash = transcript_hash(&self.hello, response)?;
        let remote_x25519_bytes: [u8; 32] = response
            .x25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| SessionError::KeyMaterial)?;
        let remote_x25519_key = X25519PublicKey::from(remote_x25519_bytes);
        let x25519_secret = self.ephemeral_secret.diffie_hellman(&remote_x25519_key);
        if !x25519_secret.was_contributory() {
            return Err(SessionError::KeyMaterial);
        }
        let x25519_shared = Zeroizing::new(x25519_secret.to_bytes());
        let ciphertext =
            ml_kem::ml_kem_768::Ciphertext::try_from(response.mlkem_ciphertext.as_slice())
                .map_err(|_| SessionError::KeyMaterial)?;
        let kem_shared = self.kem_decapsulation_key.decapsulate(&ciphertext);
        let keys = derive_session_keys(
            &transcript_hash,
            x25519_shared.as_slice(),
            kem_shared.as_slice(),
        )?;
        if !verify_confirmation(
            &keys.responder_to_initiator,
            &transcript_hash,
            b"responder",
            &response.key_confirmation,
        ) {
            return Err(SessionError::KeyConfirmation);
        }

        let authenticator =
            confirmation_tag(&keys.initiator_to_responder, &transcript_hash, b"initiator");
        let session_id = keys.session_id;
        let finish_payload = finish_signing_bytes(&transcript_hash, &session_id, &authenticator);
        let finish = Finish {
            session_id: session_id.to_vec(),
            authenticator: authenticator.clone(),
            signature: identity.sign(&finish_payload?).to_bytes().to_vec(),
        };
        let session = Session::new(keys, self.identity_id, response.identity_id.clone(), true);
        Ok((finish, session))
    }
}

impl ResponderPending {
    pub fn accept_finish(self, finish: &Finish) -> Result<Session, SessionError> {
        if finish.session_id != self.keys.session_id || finish.authenticator.len() != 32 {
            return Err(SessionError::KeyConfirmation);
        }
        if !verify_confirmation(
            &self.keys.initiator_to_responder,
            &self.transcript_hash,
            b"initiator",
            &finish.authenticator,
        ) {
            return Err(SessionError::KeyConfirmation);
        }
        let finish_payload = finish_signing_bytes(
            &self.transcript_hash,
            &self.keys.session_id,
            &finish.authenticator,
        )?;
        let finish_signature =
            Signature::from_slice(&finish.signature).map_err(|_| SessionError::Signature)?;
        verify(&self.remote_public_key, &finish_payload, &finish_signature)
            .map_err(|_| SessionError::Signature)?;
        Ok(Session::new(
            self.keys,
            self.local_identity_id,
            self.remote_identity_id,
            false,
        ))
    }
}

impl Session {
    fn new(
        keys: SessionKeys,
        local_identity_id: String,
        remote_identity_id: String,
        initiator: bool,
    ) -> Self {
        let (send_key, receive_key) = if initiator {
            (keys.initiator_to_responder, keys.responder_to_initiator)
        } else {
            (keys.responder_to_initiator, keys.initiator_to_responder)
        };
        Self {
            session_id: keys.session_id,
            local_identity_id,
            remote_identity_id,
            send_key,
            receive_key,
            send_sequence: 0,
            receive_sequence: 0,
        }
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage, SessionError> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(SessionError::TooLarge);
        }
        if self.send_sequence > MAX_SEQUENCE {
            return Err(SessionError::Exhausted);
        }
        let sequence = self.send_sequence;
        let nonce_bytes = make_nonce(&self.session_id, sequence);
        let aad = message_aad(
            &self.session_id,
            &self.local_identity_id,
            &self.remote_identity_id,
            sequence,
        )?;
        let cipher = Aes256Gcm::new_from_slice(self.send_key.as_ref())
            .map_err(|_| SessionError::KeyMaterial)?;
        let nonce =
            Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| SessionError::KeyMaterial)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SessionError::Authentication)?;
        self.send_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(SessionError::Exhausted)?;
        Ok(EncryptedMessage {
            session_id: self.session_id.to_vec(),
            sender_id: self.local_identity_id.clone(),
            recipient_id: self.remote_identity_id.clone(),
            sequence,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    pub fn decrypt(&mut self, message: &EncryptedMessage) -> Result<Vec<u8>, SessionError> {
        if message.session_id != self.session_id
            || message.sender_id != self.remote_identity_id
            || message.recipient_id != self.local_identity_id
            || message.sequence != self.receive_sequence
            || message.sequence > MAX_SEQUENCE
            || message.ciphertext.len() > MAX_PLAINTEXT_SIZE + 16
        {
            return Err(SessionError::Sequence);
        }
        let expected_nonce = make_nonce(&self.session_id, message.sequence);
        if message.nonce != expected_nonce {
            return Err(SessionError::Sequence);
        }
        let aad = message_aad(
            &self.session_id,
            &message.sender_id,
            &message.recipient_id,
            message.sequence,
        )?;
        let cipher = Aes256Gcm::new_from_slice(self.receive_key.as_ref())
            .map_err(|_| SessionError::KeyMaterial)?;
        let nonce =
            Nonce::try_from(message.nonce.as_slice()).map_err(|_| SessionError::Sequence)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &message.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| SessionError::Authentication)?,
        );
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(SessionError::Exhausted)?;
        Ok(plaintext.to_vec())
    }
}

fn validate_hello(hello: &Hello) -> Result<(), SessionError> {
    if hello.version != VERSION
        || hello.suite != SUITE
        || hello.nonce.len() != 32
        || hello.x25519_public_key.len() != 32
        || hello.signing_public_key.len() != 32
        || hello.signature.len() != 64
        || hello.mlkem_public_key.len() != 1184
        || !identity_id_matches(&hello.identity_id, &hello.signing_public_key)
    {
        return Err(SessionError::Parameters);
    }
    Ok(())
}

fn validate_response(response: &Response) -> Result<(), SessionError> {
    if response.version != VERSION
        || response.suite != SUITE
        || response.nonce.len() != 32
        || response.x25519_public_key.len() != 32
        || response.signing_public_key.len() != 32
        || response.signature.len() != 64
        || response.mlkem_ciphertext.len() != 1088
        || response.key_confirmation.len() != 32
        || !identity_id_matches(&response.identity_id, &response.signing_public_key)
    {
        return Err(SessionError::Parameters);
    }
    Ok(())
}

fn identity_id_matches(identity_id: &str, public_key: &[u8]) -> bool {
    hex::encode(Sha256::digest(public_key)) == identity_id
}

fn hello_signing_bytes(hello: &Hello) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&HelloSigning {
        domain: "AKRAT-HANDSHAKE-HELLO-V1",
        version: hello.version,
        suite: &hello.suite,
        identity_id: &hello.identity_id,
        signing_public_key: &hello.signing_public_key,
        x25519_public_key: &hello.x25519_public_key,
        mlkem_public_key: &hello.mlkem_public_key,
        nonce: &hello.nonce,
    })
    .map_err(|_| SessionError::Encoding)
}

fn response_core_bytes(response: &Response) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&ResponseCore {
        version: response.version,
        suite: &response.suite,
        identity_id: &response.identity_id,
        signing_public_key: &response.signing_public_key,
        x25519_public_key: &response.x25519_public_key,
        mlkem_ciphertext: &response.mlkem_ciphertext,
        nonce: &response.nonce,
    })
    .map_err(|_| SessionError::Encoding)
}

fn transcript_hash(hello: &Hello, response: &Response) -> Result<[u8; 32], SessionError> {
    let hello = hello_signing_bytes(hello)?;
    let response = response_core_bytes(response)?;
    let mut transcript = Vec::with_capacity(hello.len() + response.len() + 1);
    transcript.extend_from_slice(&hello);
    transcript.push(0);
    transcript.extend_from_slice(&response);
    Ok(Sha256::digest(transcript).into())
}

fn response_signature_bytes(transcript_hash: &[u8; 32], confirmation: &[u8]) -> Vec<u8> {
    let mut bytes = b"AKRAT-RESPONSE-SIGNATURE-V1".to_vec();
    bytes.extend_from_slice(transcript_hash);
    bytes.extend_from_slice(confirmation);
    bytes
}

fn finish_signing_bytes(
    transcript_hash: &[u8; 32],
    session_id: &[u8],
    authenticator: &[u8],
) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&FinishSigning {
        domain: "AKRAT-HANDSHAKE-FINISH-V1",
        transcript_hash,
        session_id,
        authenticator,
    })
    .map_err(|_| SessionError::Encoding)
}

fn derive_session_keys(
    transcript_hash: &[u8; 32],
    x25519_shared: &[u8],
    mlkem_shared: &[u8],
) -> Result<SessionKeys, SessionError> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(x25519_shared.len() + mlkem_shared.len()));
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(mlkem_shared);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), ikm.as_slice());
    let mut output = Zeroizing::new([0u8; 80]);
    hkdf.expand(b"AKRAT-HYBRID-SESSION-KEYS-V1", output.as_mut())
        .map_err(|_| SessionError::KeyMaterial)?;
    let mut session_id = [0u8; 16];
    let mut initiator_to_responder = Zeroizing::new([0u8; 32]);
    let mut responder_to_initiator = Zeroizing::new([0u8; 32]);
    session_id.copy_from_slice(&output[..16]);
    initiator_to_responder.copy_from_slice(&output[16..48]);
    responder_to_initiator.copy_from_slice(&output[48..80]);
    Ok(SessionKeys {
        session_id,
        initiator_to_responder,
        responder_to_initiator,
    })
}

fn confirmation_tag(key: &[u8; 32], transcript_hash: &[u8; 32], role: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a 32-byte key");
    mac.update(b"AKRAT-KEY-CONFIRMATION-V1");
    mac.update(transcript_hash);
    mac.update(role);
    mac.finalize().into_bytes().to_vec()
}

fn verify_confirmation(
    key: &[u8; 32],
    transcript_hash: &[u8; 32],
    role: &[u8],
    tag: &[u8],
) -> bool {
    let Ok(mut mac) = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key) else {
        return false;
    };
    mac.update(b"AKRAT-KEY-CONFIRMATION-V1");
    mac.update(transcript_hash);
    mac.update(role);
    mac.verify_slice(tag).is_ok()
}

fn make_nonce(session_id: &[u8; 16], sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&session_id[..4]);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn message_aad(
    session_id: &[u8; 16],
    sender_id: &str,
    recipient_id: &str,
    sequence: u64,
) -> Result<Vec<u8>, SessionError> {
    serde_json::to_vec(&MessageAad {
        version: VERSION,
        session_id,
        sender_id,
        recipient_id,
        sequence,
    })
    .map_err(|_| SessionError::Encoding)
}

#[cfg(test)]
mod tests {
    use super::{SessionError, respond_to_handshake, start_handshake};
    use crate::create_identity;

    #[test]
    fn hybrid_handshake_authenticates_and_encrypts_in_both_directions() {
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let bob = create_identity("Bob".to_string()).expect("Bob identity");
        let (hello, alice_pending) = start_handshake(&alice).expect("hello");
        let (response, bob_pending) = respond_to_handshake(&bob, &hello).expect("response");
        let (finish, mut alice_session) = alice_pending
            .complete(&alice, &response, Some(&bob.public.public_key))
            .expect("initiator completion");
        let mut bob_session = bob_pending
            .accept_finish(&finish)
            .expect("responder completion");

        assert_eq!(alice_session.session_id(), bob_session.session_id());
        let first = alice_session
            .encrypt(b"message from Alice")
            .expect("encrypt");
        assert_eq!(
            bob_session.decrypt(&first).expect("decrypt"),
            b"message from Alice"
        );
        assert!(matches!(
            bob_session.decrypt(&first),
            Err(SessionError::Sequence)
        ));

        let retry = alice_session
            .encrypt(b"same logical message after uncertain delivery")
            .expect("encrypt retry");
        let retry_again = alice_session
            .encrypt(b"same logical message after uncertain delivery")
            .expect("encrypt retry again");
        assert_eq!(retry.sequence + 1, retry_again.sequence);
        assert_ne!(retry.nonce, retry_again.nonce);
        assert_ne!(retry.ciphertext, retry_again.ciphertext);
        assert_eq!(
            bob_session.decrypt(&retry).expect("decrypt retry"),
            bob_session
                .decrypt(&retry_again)
                .expect("decrypt retry again")
        );

        let reply = bob_session.encrypt(b"message from Bob").expect("encrypt");
        assert_eq!(
            alice_session.decrypt(&reply).expect("decrypt"),
            b"message from Bob"
        );
    }

    #[test]
    fn mismatched_manual_identity_pin_is_rejected() {
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let bob = create_identity("Bob".to_string()).expect("Bob identity");
        let mallory = create_identity("Mallory".to_string()).expect("Mallory identity");
        let (hello, alice_pending) = start_handshake(&alice).expect("hello");
        let (response, _) = respond_to_handshake(&bob, &hello).expect("response");

        assert!(matches!(
            alice_pending.complete(&alice, &response, Some(&mallory.public.public_key)),
            Err(SessionError::Identity)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected_without_advancing_receive_sequence() {
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let bob = create_identity("Bob".to_string()).expect("Bob identity");
        let (hello, alice_pending) = start_handshake(&alice).expect("hello");
        let (response, bob_pending) = respond_to_handshake(&bob, &hello).expect("response");
        let (finish, mut alice_session) = alice_pending
            .complete(&alice, &response, Some(&bob.public.public_key))
            .expect("initiator completion");
        let mut bob_session = bob_pending
            .accept_finish(&finish)
            .expect("responder completion");
        let message = alice_session.encrypt(b"private").expect("encrypt");
        let mut tampered = message.clone();
        tampered.ciphertext[0] ^= 1;

        assert!(matches!(
            bob_session.decrypt(&tampered),
            Err(SessionError::Authentication)
        ));
        assert_eq!(bob_session.decrypt(&message).expect("decrypt"), b"private");
        assert!(matches!(
            bob_session.decrypt(&message),
            Err(SessionError::Sequence)
        ));
    }

    #[test]
    fn handshake_signatures_bind_the_public_identity_key() {
        let identity = create_identity("Alice".to_string()).expect("identity");
        let (mut hello, _) = start_handshake(&identity).expect("hello");
        hello.nonce[0] ^= 1;
        assert!(matches!(
            super::respond_to_handshake(&create_identity("Bob".to_string()).expect("Bob"), &hello),
            Err(SessionError::Signature)
        ));
    }
}
