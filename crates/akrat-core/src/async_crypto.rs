use crate::Identity;
use libsignal_protocol::kem::{self, KeyType};
use libsignal_protocol::{
    CiphertextMessage, DeviceId, GenericSignedPreKey, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, InMemSignalProtocolStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore,
    PrivateKey, ProtocolAddress, PublicKey, SessionRecord, SessionStore, SignalMessage,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp, initiate_session,
    message_decrypt_prekey, message_decrypt_signal, message_encrypt,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;
use thiserror::Error;
use zeroize::Zeroize;

const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
const DEVICE_ID: u8 = 1;
const BUNDLE_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
const PREKEY_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum AsyncCryptoError {
    #[error("asynchronous cryptographic state is invalid")]
    InvalidState,
    #[error("the pre-key bundle belongs to another identity")]
    WrongIdentity,
    #[error("ciphertext is malformed or failed authentication")]
    InvalidCiphertext,
    #[error("libsignal protocol operation failed")]
    Protocol,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedBundle {
    pub version: u8,
    pub expires_at: u64,
    pub identity_public_key: Vec<u8>,
    pub registration_id: u32,
    pub device_id: u32,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey_public: Option<Vec<u8>>,
    pub signed_prekey_id: u32,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub pq_prekey_id: u32,
    pub pq_prekey_public: Vec<u8>,
    pub pq_prekey_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncCiphertext {
    pub version: u8,
    pub prekey: bool,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientReceipt {
    pub version: u8,
    pub mailbox_id: String,
    pub message_id: String,
    pub ciphertext_sha256: String,
    pub sender_public_key: Vec<u8>,
    pub recipient_public_key: Vec<u8>,
    pub received_at: u64,
    pub signature: Vec<u8>,
}

impl RecipientReceipt {
    pub fn create(
        recipient: &Identity,
        sender_public_key: &[u8],
        mailbox_id: String,
        message_id: String,
        ciphertext_sha256: String,
        received_at: u64,
    ) -> Result<Self, AsyncCryptoError> {
        if sender_public_key.len() != 32
            || mailbox_id.is_empty()
            || mailbox_id.len() > 128
            || message_id.is_empty()
            || message_id.len() > 128
            || ciphertext_sha256.len() != 64
            || hex::decode(&ciphertext_sha256).is_err()
        {
            return Err(AsyncCryptoError::InvalidState);
        }
        let mut receipt = Self {
            version: 1,
            mailbox_id,
            message_id,
            ciphertext_sha256,
            sender_public_key: sender_public_key.to_vec(),
            recipient_public_key: recipient.public_key().to_vec(),
            received_at,
            signature: Vec::new(),
        };
        receipt.signature = sign_identity_statement(recipient, &receipt.signing_bytes())?;
        Ok(receipt)
    }

    pub fn verify(&self) -> Result<bool, AsyncCryptoError> {
        if self.version != 1
            || self.mailbox_id.is_empty()
            || self.mailbox_id.len() > 128
            || self.message_id.is_empty()
            || self.message_id.len() > 128
            || self.ciphertext_sha256.len() != 64
            || hex::decode(&self.ciphertext_sha256).is_err()
            || self.sender_public_key.len() != 32
            || self.recipient_public_key.len() != 32
            || self.signature.len() != 64
        {
            return Ok(false);
        }
        verify_identity_statement(
            &self.recipient_public_key,
            &self.signing_bytes(),
            &self.signature,
        )
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"AKRAT/recipient-receipt/v1\0".to_vec();
        push_bytes(&mut bytes, self.mailbox_id.as_bytes());
        push_bytes(&mut bytes, self.message_id.as_bytes());
        push_bytes(&mut bytes, self.ciphertext_sha256.as_bytes());
        push_bytes(&mut bytes, &self.sender_public_key);
        push_bytes(&mut bytes, &self.recipient_public_key);
        bytes.extend_from_slice(&self.received_at.to_be_bytes());
        bytes
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedState {
    version: u8,
    registration_id: u32,
    one_time_prekeys: BTreeMap<u32, Vec<u8>>,
    #[serde(default)]
    one_time_prekey_expirations: BTreeMap<u32, u64>,
    signed_prekeys: BTreeMap<u32, Vec<u8>>,
    #[serde(default)]
    signed_prekey_expirations: BTreeMap<u32, u64>,
    pq_prekeys: BTreeMap<u32, Vec<u8>>,
    #[serde(default)]
    pq_prekey_expirations: BTreeMap<u32, u64>,
    sessions: BTreeMap<String, Vec<u8>>,
    #[serde(default)]
    current_bundle: Option<PublishedBundle>,
}

impl Drop for PersistedState {
    fn drop(&mut self) {
        for value in self.one_time_prekeys.values_mut() {
            value.zeroize();
        }
        for value in self.signed_prekeys.values_mut() {
            value.zeroize();
        }
        for value in self.pq_prekeys.values_mut() {
            value.zeroize();
        }
        for value in self.sessions.values_mut() {
            value.zeroize();
        }
    }
}

pub async fn publish_bundle(
    identity: &Identity,
    state_bytes: &[u8],
) -> Result<(PublishedBundle, Vec<u8>), AsyncCryptoError> {
    let mut rng = rand::rng();
    let mut state = decode_state(state_bytes)?;
    if state.version == 0 {
        state.version = 1;
        state.registration_id = rng.random_range(1..=16380);
    }
    let current_time = now_seconds();
    prune_expired(
        &mut state.one_time_prekeys,
        &mut state.one_time_prekey_expirations,
        current_time,
    );
    prune_expired(
        &mut state.signed_prekeys,
        &mut state.signed_prekey_expirations,
        current_time,
    );
    prune_expired(
        &mut state.pq_prekeys,
        &mut state.pq_prekey_expirations,
        current_time,
    );
    if let Some(bundle) = &state.current_bundle
        && bundle.expires_at > current_time
        && bundle
            .one_time_prekey_id
            .is_some_and(|id| state.one_time_prekeys.contains_key(&id))
    {
        return Ok((bundle.clone(), encode_state(&state)?));
    }
    if state.one_time_prekeys.len() >= 128 {
        return Err(AsyncCryptoError::InvalidState);
    }
    let mut store = make_store(identity, &state).await?;
    let one_id = next_id(&state.one_time_prekeys, &mut rng);
    let one_pair = KeyPair::generate(&mut rng);
    store
        .pre_key_store
        .save_pre_key(one_id.into(), &PreKeyRecord::new(one_id.into(), &one_pair))
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?;
    let signed_id = next_id(&state.signed_prekeys, &mut rng);
    let signed_pair = KeyPair::generate(&mut rng);
    let signed_bytes = signed_pair.public_key.serialize();
    let signed_sig = store
        .identity_store
        .get_identity_key_pair()
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?
        .private_key()
        .calculate_signature(&signed_bytes, &mut rng)
        .map_err(|_| AsyncCryptoError::Protocol)?;
    let signed_record = SignedPreKeyRecord::new(
        signed_id.into(),
        Timestamp::from_epoch_millis(now_millis()),
        &signed_pair,
        &signed_sig,
    );
    store
        .signed_pre_key_store
        .save_signed_pre_key(signed_id.into(), &signed_record)
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?;
    let pq_id = next_id(&state.pq_prekeys, &mut rng);
    let pq_pair = kem::KeyPair::generate(KeyType::Kyber1024, &mut rng);
    let pq_bytes = pq_pair.public_key.serialize();
    let pq_sig = store
        .identity_store
        .get_identity_key_pair()
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?
        .private_key()
        .calculate_signature(&pq_bytes, &mut rng)
        .map_err(|_| AsyncCryptoError::Protocol)?;
    let pq_record = KyberPreKeyRecord::new(
        pq_id.into(),
        Timestamp::from_epoch_millis(now_millis()),
        &pq_pair,
        &pq_sig,
    );
    store
        .kyber_pre_key_store
        .save_kyber_pre_key(pq_id.into(), &pq_record)
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?;
    let expires_at = current_time
        .saturating_add(BUNDLE_LIFETIME_SECONDS)
        .saturating_add(PREKEY_RETENTION_SECONDS);
    state.one_time_prekeys.insert(
        one_id,
        PreKeyRecord::new(one_id.into(), &one_pair)
            .serialize()
            .map_err(|_| AsyncCryptoError::Protocol)?,
    );
    state.one_time_prekey_expirations.insert(one_id, expires_at);
    state.signed_prekeys.insert(
        signed_id,
        signed_record
            .serialize()
            .map_err(|_| AsyncCryptoError::Protocol)?,
    );
    state
        .signed_prekey_expirations
        .insert(signed_id, expires_at);
    state.pq_prekeys.insert(
        pq_id,
        pq_record
            .serialize()
            .map_err(|_| AsyncCryptoError::Protocol)?,
    );
    state.pq_prekey_expirations.insert(pq_id, expires_at);
    let bundle = PublishedBundle {
        version: 1,
        expires_at: current_time.saturating_add(BUNDLE_LIFETIME_SECONDS),
        identity_public_key: store
            .identity_store
            .get_identity_key_pair()
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?
            .public_key()
            .serialize()
            .to_vec(),
        registration_id: state.registration_id,
        device_id: u32::from(DEVICE_ID),
        one_time_prekey_id: Some(one_id),
        one_time_prekey_public: Some(one_pair.public_key.serialize().to_vec()),
        signed_prekey_id: signed_id,
        signed_prekey_public: signed_pair.public_key.serialize().to_vec(),
        signed_prekey_signature: signed_sig.to_vec(),
        pq_prekey_id: pq_id,
        pq_prekey_public: pq_bytes.to_vec(),
        pq_prekey_signature: pq_sig.to_vec(),
    };
    state.current_bundle = Some(bundle.clone());
    Ok((bundle, encode_state(&state)?))
}

pub async fn encrypt(
    identity: &Identity,
    state_bytes: &[u8],
    recipient_public_key: &[u8],
    bundle: &PublishedBundle,
    plaintext: &[u8],
) -> Result<(AsyncCiphertext, Vec<u8>), AsyncCryptoError> {
    if bundle.version != 1
        || bundle.expires_at <= now_seconds()
        || bundle.identity_public_key.len() != 33
        || bundle.identity_public_key[0] != 5
        || bundle.identity_public_key[1..] != *recipient_public_key
    {
        return Err(AsyncCryptoError::WrongIdentity);
    }
    verify_bundle(bundle, recipient_public_key)?;
    let remote = address(recipient_public_key)?;
    let local = address(identity.public_key())?;
    let mut state = decode_state(state_bytes)?;
    if state.version == 0 {
        state.version = 1;
        state.registration_id = rand::rng().random_range(1..=16380);
    }
    let mut store = make_store(identity, &state).await?;
    let prekey_bundle = parse_bundle(bundle)?;
    let mut rng = rand::rng();
    if !state.sessions.contains_key(remote.name()) {
        initiate_session(
            &remote,
            &local,
            &mut store.session_store,
            &mut store.identity_store,
            &prekey_bundle,
            SystemTime::now(),
            &mut rng,
        )
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?;
    }
    let message = message_encrypt(
        plaintext,
        &remote,
        &local,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut rng,
    )
    .await
    .map_err(|_| AsyncCryptoError::Protocol)?;
    state.sessions.insert(
        remote.name().to_owned(),
        store
            .session_store
            .load_session(&remote)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?
            .ok_or(AsyncCryptoError::InvalidState)?
            .serialize()
            .map_err(|_| AsyncCryptoError::Protocol)?,
    );
    Ok((
        AsyncCiphertext {
            version: 1,
            prekey: matches!(message, CiphertextMessage::PreKeySignalMessage(_)),
            bytes: message.serialize().to_vec(),
        },
        encode_state(&state)?,
    ))
}

pub fn verify_bundle(
    bundle: &PublishedBundle,
    expected_identity_public_key: &[u8],
) -> Result<(), AsyncCryptoError> {
    if bundle.version != 1
        || bundle.expires_at <= now_seconds()
        || bundle.identity_public_key.len() != 33
        || bundle.identity_public_key[0] != 5
        || bundle.identity_public_key[1..] != *expected_identity_public_key
    {
        return Err(AsyncCryptoError::WrongIdentity);
    }
    let bundle = parse_bundle(bundle)?;
    let identity = bundle
        .identity_key()
        .map_err(|_| AsyncCryptoError::InvalidState)?;
    let signed_public = bundle
        .signed_pre_key_public()
        .map_err(|_| AsyncCryptoError::InvalidState)?
        .serialize();
    let signed_signature = bundle
        .signed_pre_key_signature()
        .map_err(|_| AsyncCryptoError::InvalidState)?;
    let pq_public = bundle
        .kyber_pre_key_public()
        .map_err(|_| AsyncCryptoError::InvalidState)?
        .serialize();
    let pq_signature = bundle
        .kyber_pre_key_signature()
        .map_err(|_| AsyncCryptoError::InvalidState)?;
    if !identity
        .public_key()
        .verify_signature(&signed_public, signed_signature)
        || !identity
            .public_key()
            .verify_signature(&pq_public, pq_signature)
    {
        return Err(AsyncCryptoError::InvalidState);
    }
    Ok(())
}

pub fn sign_identity_statement(
    identity: &Identity,
    statement: &[u8],
) -> Result<Vec<u8>, AsyncCryptoError> {
    let private =
        PrivateKey::deserialize(identity.private_key()).map_err(|_| AsyncCryptoError::Protocol)?;
    if private
        .public_key()
        .map_err(|_| AsyncCryptoError::Protocol)?
        .public_key_bytes()
        != identity.public_key()
    {
        return Err(AsyncCryptoError::WrongIdentity);
    }
    private
        .calculate_signature(statement, &mut rand::rng())
        .map(|signature| signature.to_vec())
        .map_err(|_| AsyncCryptoError::Protocol)
}

pub fn verify_identity_statement(
    identity_public_key: &[u8],
    statement: &[u8],
    signature: &[u8],
) -> Result<bool, AsyncCryptoError> {
    let serialized_public_key = if identity_public_key.len() == 32 {
        let mut serialized = Vec::with_capacity(33);
        serialized.push(5);
        serialized.extend_from_slice(identity_public_key);
        serialized
    } else if identity_public_key.len() == 33 && identity_public_key[0] == 5 {
        identity_public_key.to_vec()
    } else {
        return Err(AsyncCryptoError::WrongIdentity);
    };
    let public = PublicKey::try_from(serialized_public_key.as_slice())
        .map_err(|_| AsyncCryptoError::WrongIdentity)?;
    Ok(public.verify_signature(statement, signature))
}

pub async fn decrypt(
    identity: &Identity,
    state_bytes: &[u8],
    sender_public_key: &[u8],
    message: &AsyncCiphertext,
) -> Result<(Vec<u8>, Vec<u8>), AsyncCryptoError> {
    if message.version != 1 || message.bytes.is_empty() || message.bytes.len() > 256 * 1024 {
        return Err(AsyncCryptoError::InvalidCiphertext);
    }
    let remote = address(sender_public_key)?;
    let local = address(identity.public_key())?;
    let mut state = decode_state(state_bytes)?;
    if state.version == 0 {
        return Err(AsyncCryptoError::InvalidState);
    }
    let mut store = make_store(identity, &state).await?;
    let mut rng = rand::rng();
    let plaintext = if message.prekey {
        let prekey = PreKeySignalMessage::try_from(message.bytes.as_slice())
            .map_err(|_| AsyncCryptoError::InvalidCiphertext)?;
        if prekey.identity_key().public_key().public_key_bytes() != sender_public_key {
            return Err(AsyncCryptoError::WrongIdentity);
        }
        message_decrypt_prekey(
            &prekey,
            &remote,
            &local,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut rng,
        )
        .await
        .map_err(|_| AsyncCryptoError::InvalidCiphertext)?
        .plaintext
    } else {
        let signal = SignalMessage::try_from(message.bytes.as_slice())
            .map_err(|_| AsyncCryptoError::InvalidCiphertext)?;
        message_decrypt_signal(
            &signal,
            &remote,
            &local,
            &mut store.session_store,
            &mut store.identity_store,
            &mut rng,
        )
        .await
        .map_err(|_| AsyncCryptoError::InvalidCiphertext)?
    };
    persist_store(&mut state, &store, &remote).await?;
    if state.current_bundle.as_ref().is_some_and(|bundle| {
        bundle
            .one_time_prekey_id
            .is_some_and(|id| !state.one_time_prekeys.contains_key(&id))
    }) {
        state.current_bundle = None;
    }
    Ok((plaintext, encode_state(&state)?))
}

fn parse_bundle(bundle: &PublishedBundle) -> Result<PreKeyBundle, AsyncCryptoError> {
    let identity = IdentityKey::decode(&bundle.identity_public_key)
        .map_err(|_| AsyncCryptoError::InvalidState)?;
    let one_time_prekey = match (bundle.one_time_prekey_id, &bundle.one_time_prekey_public) {
        (Some(id), Some(public)) => Some((
            PreKeyId::from(id),
            PublicKey::try_from(public.as_slice()).map_err(|_| AsyncCryptoError::InvalidState)?,
        )),
        (None, None) => None,
        _ => return Err(AsyncCryptoError::InvalidState),
    };
    let signed_key = PublicKey::try_from(bundle.signed_prekey_public.as_slice())
        .map_err(|_| AsyncCryptoError::InvalidState)?;
    let pq_key = kem::PublicKey::deserialize(&bundle.pq_prekey_public)
        .map_err(|_| AsyncCryptoError::InvalidState)?;
    let device_id = u8::try_from(bundle.device_id).map_err(|_| AsyncCryptoError::InvalidState)?;
    let device = DeviceId::new(device_id).map_err(|_| AsyncCryptoError::InvalidState)?;
    PreKeyBundle::new(
        bundle.registration_id,
        device,
        one_time_prekey,
        SignedPreKeyId::from(bundle.signed_prekey_id),
        signed_key,
        bundle.signed_prekey_signature.clone(),
        KyberPreKeyId::from(bundle.pq_prekey_id),
        pq_key,
        bundle.pq_prekey_signature.clone(),
        identity,
    )
    .map_err(|_| AsyncCryptoError::InvalidState)
}

async fn make_store(
    identity: &Identity,
    state: &PersistedState,
) -> Result<InMemSignalProtocolStore, AsyncCryptoError> {
    let private =
        PrivateKey::deserialize(identity.private_key()).map_err(|_| AsyncCryptoError::Protocol)?;
    let identity_pair =
        IdentityKeyPair::try_from(private).map_err(|_| AsyncCryptoError::Protocol)?;
    if identity_pair.public_key().public_key_bytes() != identity.public_key() {
        return Err(AsyncCryptoError::WrongIdentity);
    }
    let mut store = InMemSignalProtocolStore::new(identity_pair, state.registration_id.max(1))
        .map_err(|_| AsyncCryptoError::Protocol)?;
    for (id, record) in &state.one_time_prekeys {
        let value =
            PreKeyRecord::deserialize(record).map_err(|_| AsyncCryptoError::InvalidState)?;
        store
            .pre_key_store
            .save_pre_key(PreKeyId::from(*id), &value)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
    }
    for (id, record) in &state.signed_prekeys {
        let value =
            SignedPreKeyRecord::deserialize(record).map_err(|_| AsyncCryptoError::InvalidState)?;
        store
            .signed_pre_key_store
            .save_signed_pre_key(SignedPreKeyId::from(*id), &value)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
    }
    for (id, record) in &state.pq_prekeys {
        let value =
            KyberPreKeyRecord::deserialize(record).map_err(|_| AsyncCryptoError::InvalidState)?;
        store
            .kyber_pre_key_store
            .save_kyber_pre_key(KyberPreKeyId::from(*id), &value)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
    }
    for (peer, record) in &state.sessions {
        let address = address_from_name(peer)?;
        let value =
            SessionRecord::deserialize(record).map_err(|_| AsyncCryptoError::InvalidState)?;
        store
            .session_store
            .store_session(&address, &value)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
    }
    Ok(store)
}

async fn persist_store(
    store_state: &mut PersistedState,
    store: &InMemSignalProtocolStore,
    remote: &ProtocolAddress,
) -> Result<(), AsyncCryptoError> {
    store_state.one_time_prekeys.clear();
    for id in store.all_pre_key_ids() {
        let record = store
            .pre_key_store
            .get_pre_key(*id)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
        store_state.one_time_prekeys.insert(
            (*id).into(),
            record.serialize().map_err(|_| AsyncCryptoError::Protocol)?,
        );
    }
    store_state
        .one_time_prekey_expirations
        .retain(|id, _| store_state.one_time_prekeys.contains_key(id));
    store_state.signed_prekeys.clear();
    for id in store.all_signed_pre_key_ids() {
        let record = store
            .signed_pre_key_store
            .get_signed_pre_key(*id)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
        store_state.signed_prekeys.insert(
            (*id).into(),
            record.serialize().map_err(|_| AsyncCryptoError::Protocol)?,
        );
    }
    store_state.pq_prekeys.clear();
    for id in store.all_kyber_pre_key_ids() {
        let record = store
            .kyber_pre_key_store
            .get_kyber_pre_key(*id)
            .await
            .map_err(|_| AsyncCryptoError::Protocol)?;
        store_state.pq_prekeys.insert(
            (*id).into(),
            record.serialize().map_err(|_| AsyncCryptoError::Protocol)?,
        );
    }
    if let Some(session) = store
        .session_store
        .load_session(remote)
        .await
        .map_err(|_| AsyncCryptoError::Protocol)?
    {
        store_state.sessions.insert(
            remote.name().to_owned(),
            session
                .serialize()
                .map_err(|_| AsyncCryptoError::Protocol)?,
        );
    }
    Ok(())
}

fn address(public_key: &[u8]) -> Result<ProtocolAddress, AsyncCryptoError> {
    if public_key.len() != 32 {
        return Err(AsyncCryptoError::InvalidState);
    }
    address_from_name(&hex::encode(public_key))
}

fn address_from_name(name: &str) -> Result<ProtocolAddress, AsyncCryptoError> {
    Ok(ProtocolAddress::new(
        name.to_owned(),
        DeviceId::new(DEVICE_ID).map_err(|_| AsyncCryptoError::InvalidState)?,
    ))
}

fn decode_state(bytes: &[u8]) -> Result<PersistedState, AsyncCryptoError> {
    if bytes.is_empty() {
        return Ok(PersistedState::default());
    }
    if bytes.len() > MAX_STATE_BYTES {
        return Err(AsyncCryptoError::InvalidState);
    }
    let state: PersistedState =
        serde_json::from_slice(bytes).map_err(|_| AsyncCryptoError::InvalidState)?;
    if state.version > 1
        || state.registration_id > 16380
        || state.sessions.len() > 10_000
        || state.one_time_prekeys.len() > 10_000
        || state.signed_prekeys.len() > 1024
        || state.pq_prekeys.len() > 1024
    {
        return Err(AsyncCryptoError::InvalidState);
    }
    Ok(state)
}

pub(crate) fn validate_state(bytes: &[u8]) -> Result<(), AsyncCryptoError> {
    decode_state(bytes).map(|_| ())
}

fn encode_state(state: &PersistedState) -> Result<Vec<u8>, AsyncCryptoError> {
    let bytes = serde_json::to_vec(state).map_err(|_| AsyncCryptoError::InvalidState)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(AsyncCryptoError::InvalidState);
    }
    Ok(bytes)
}

fn next_id(map: &BTreeMap<u32, Vec<u8>>, rng: &mut impl Rng) -> u32 {
    loop {
        let id = rng.random::<u32>();
        if id != 0 && !map.contains_key(&id) {
            return id;
        }
    }
}

fn prune_expired(
    records: &mut BTreeMap<u32, Vec<u8>>,
    expirations: &mut BTreeMap<u32, u64>,
    now: u64,
) {
    let expired = expirations
        .iter()
        .filter_map(|(id, expires_at)| (*expires_at <= now).then_some(*id))
        .collect::<Vec<_>>();
    for id in expired {
        expirations.remove(&id);
        records.remove(&id);
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or_default()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pqxdh_message_survives_sender_receiver_state_reload_and_ratchets() {
        let alice = Identity::generate("Alice".into()).expect("Alice identity");
        let bob = Identity::generate("Bob".into()).expect("Bob identity");
        let (bundle, bob_state) = publish_bundle(&bob, &[]).await.expect("Bob publishes");
        let (first, alice_state) =
            encrypt(&alice, &[], bob.public_key(), &bundle, b"offline hello")
                .await
                .expect("Alice encrypts offline");
        assert!(first.prekey);
        let bob_state_parsed = decode_state(&bob_state).expect("Bob state parses");
        assert_eq!(bob_state_parsed.version, 1);
        make_store(&bob, &bob_state_parsed)
            .await
            .expect("Bob protocol store restores");
        let (plaintext, bob_state) = decrypt(&bob, &bob_state, alice.public_key(), &first)
            .await
            .expect("Bob decrypts after restart");
        assert_eq!(plaintext, b"offline hello");
        let (second, _) = encrypt(
            &alice,
            &alice_state,
            bob.public_key(),
            &bundle,
            b"ratchet reply",
        )
        .await
        .expect("Alice ratchets");
        assert!(second.prekey);
        let (plaintext, _) = decrypt(&bob, &bob_state, alice.public_key(), &second)
            .await
            .expect("Bob ratchet decrypt");
        assert_eq!(plaintext, b"ratchet reply");
    }

    #[tokio::test]
    async fn pqxdh_rejects_wrong_identity_and_modified_ciphertext() {
        let alice = Identity::generate("Alice".into()).expect("Alice identity");
        let bob = Identity::generate("Bob".into()).expect("Bob identity");
        let mallory = Identity::generate("Mallory".into()).expect("Mallory identity");
        let (bundle, bob_state) = publish_bundle(&bob, &[]).await.expect("Bob publishes");
        assert!(matches!(
            encrypt(&alice, &[], mallory.public_key(), &bundle, b"hello").await,
            Err(AsyncCryptoError::WrongIdentity)
        ));
        let (mut message, _) = encrypt(&alice, &[], bob.public_key(), &bundle, b"hello")
            .await
            .expect("Alice encrypts");
        let last = message.bytes.len() - 1;
        message.bytes[last] ^= 0x80;
        assert!(
            decrypt(&bob, &bob_state, alice.public_key(), &message)
                .await
                .is_err()
        );
    }
}
