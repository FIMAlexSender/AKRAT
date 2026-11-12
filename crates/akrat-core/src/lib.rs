pub mod async_crypto;
pub mod network;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{Builder, params::NoiseParams};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u8 = 3;
const LEGACY_FORMAT_VERSION: u8 = 1;
const MAX_VAULT_SIZE: usize = 16 * 1024 * 1024;
const NOISE_PROTOCOL: &str = "Noise_XX_25519_AESGCM_SHA256";

#[derive(Debug, Error)]
pub enum AkratError {
    #[error("vault file is invalid or from an unsupported version")]
    InvalidVault,
    #[error("vault authentication failed")]
    Authentication,
    #[error("vault serialization failed")]
    Serialization,
    #[error("random number generation failed")]
    Random,
    #[error("cryptographic identity could not be created")]
    Identity,
    #[error("identity or invitation is invalid")]
    InvalidIdentity,
    #[error("I/O operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub name: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Identity {
    pub fn generate(name: String) -> Result<Self, AkratError> {
        if name.trim().is_empty() || name.len() > 128 {
            return Err(AkratError::InvalidIdentity);
        }
        let builder = Builder::new(noise_params()?);
        let keypair = builder
            .generate_keypair()
            .map_err(|_| AkratError::Identity)?;
        let id = hex::encode(Sha256::digest(&keypair.public));
        Ok(Self {
            id,
            name,
            public_key: keypair.public,
            private_key: keypair.private,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn detached_copy(&self) -> Self {
        Self {
            id: self.id.clone(),
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
        }
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }

    /// Stable transport identity derived with domain separation from this identity's secret.
    /// It is independent of the device's current IP address or network.
    pub fn transport_private_key(&self) -> Zeroizing<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(b"AKRAT/transport-key/v1\0");
        hasher.update(&self.private_key);
        Zeroizing::new(hasher.finalize().into())
    }

    pub fn transport_id(&self) -> String {
        let private_key = self.transport_private_key();
        let secret = iroh::SecretKey::from_bytes(&private_key);
        secret.public().to_string()
    }

    pub(crate) fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub fingerprint: String,
    pub name: String,
    pub public_key: Vec<u8>,
    #[serde(default)]
    pub transport_id: String,
    // Legacy vaults used a fixed IP address. Keep decoding it for migration only.
    #[serde(default, rename = "address", skip_serializing_if = "String::is_empty")]
    pub legacy_address: String,
    pub manually_verified: bool,
    #[serde(default)]
    pub mailbox_route: Option<MailboxRoute>,
    #[serde(default)]
    pub mailbox_replicas: Vec<MailboxRoute>,
}

impl Drop for MailboxRoute {
    fn drop(&mut self) {
        self.write_capability.zeroize();
        self.bundle_capability.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MailboxRoute {
    pub endpoint: String,
    pub server_noise_public_key: Vec<u8>,
    pub server_signing_public_key: Vec<u8>,
    #[serde(default)]
    pub server_key_generation: u64,
    #[serde(default)]
    pub server_revocation_sequence: u64,
    pub mailbox_id: String,
    pub write_capability: String,
    pub bundle_capability: String,
}

pub const MAX_MAILBOX_REPLICAS: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MailboxInbox {
    pub identity_id: String,
    pub endpoint: String,
    pub server_noise_public_key: Vec<u8>,
    pub server_signing_public_key: Vec<u8>,
    #[serde(default)]
    pub server_key_generation: u64,
    #[serde(default)]
    pub server_revocation_sequence: u64,
    pub mailbox_id: String,
    pub write_capability: String,
    pub read_capability: String,
    pub bundle_capability: String,
}

impl Drop for MailboxInbox {
    fn drop(&mut self) {
        self.write_capability.zeroize();
        self.read_capability.zeroize();
        self.bundle_capability.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AsyncOutboxItem {
    pub conversation: String,
    pub message_id: String,
    pub envelope: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PendingRecipientReceipt {
    pub mailbox_id: String,
    pub read_capability: String,
    pub receipt: async_crypto::RecipientReceipt,
}

impl Drop for PendingRecipientReceipt {
    fn drop(&mut self) {
        self.read_capability.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u8,
    pub fingerprint: String,
    pub public_key: Vec<u8>,
    pub transport_id: String,
}

impl Invitation {
    pub fn create(identity: &Identity) -> Result<Self, AkratError> {
        let transport_id = identity.transport_id();
        if transport_id.is_empty() {
            return Err(AkratError::InvalidIdentity);
        }
        Ok(Self {
            version: 2,
            fingerprint: identity.fingerprint(),
            public_key: identity.public_key().to_vec(),
            transport_id,
        })
    }

    pub fn to_uri(&self) -> Result<String, AkratError> {
        let encoded = serde_json::to_vec(self).map_err(|_| AkratError::Serialization)?;
        Ok(format!(
            "akrat://invite/{}",
            URL_SAFE_NO_PAD.encode(encoded)
        ))
    }

    pub fn from_uri(uri: &str) -> Result<Self, AkratError> {
        if uri.len() > 4096 {
            return Err(AkratError::InvalidIdentity);
        }
        let payload = uri
            .strip_prefix("akrat://invite/")
            .ok_or(AkratError::InvalidIdentity)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| AkratError::InvalidIdentity)?;
        let invitation: Self =
            serde_json::from_slice(&bytes).map_err(|_| AkratError::InvalidIdentity)?;
        if invitation.version != 2
            || invitation.public_key.len() != 32
            || invitation.fingerprint != fingerprint(&invitation.public_key)
            || invitation.transport_id.len() > 128
            || invitation.transport_id.is_empty()
        {
            return Err(AkratError::InvalidIdentity);
        }
        invitation
            .transport_id
            .parse::<iroh::EndpointId>()
            .map_err(|_| AkratError::InvalidIdentity)?;
        Ok(invitation)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StoredMessage {
    pub conversation: String,
    pub id: String,
    pub outgoing: bool,
    pub text: String,
    pub delivery: DeliveryState,
    pub timestamp: u64,
    #[serde(default)]
    pub delivery_events: Vec<DeliveryEvent>,
    #[serde(default)]
    pub received_ciphertext_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryEvent {
    pub timestamp: u64,
    pub kind: DeliveryEventKind,
    pub actor: DeliveryActor,
    pub actor_fingerprint: Option<String>,
    pub actor_name: Option<String>,
    pub receipt_sha256: Option<String>,
    #[serde(default)]
    pub receipt_bytes: Option<Vec<u8>>,
    pub verified: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryEventKind {
    SavedLocally,
    Encrypted,
    SentDirectly,
    Deposited,
    Retrieved,
    AuthenticatedAndSaved,
    RecipientConfirmed,
    Expired,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryActor {
    SenderClient,
    RecipientClient,
    Mailbox,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum DeliveryState {
    Pending,
    Queued,
    Sent,
    MailboxStored,
    Received,
    Acknowledged,
    Unconfirmed,
    Expired,
}

impl DeliveryState {
    pub fn needs_delivery(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Queued | Self::Sent | Self::Unconfirmed
        )
    }
}

impl StoredMessage {
    pub fn record_delivery_event(&mut self, event: DeliveryEvent) {
        if self.delivery_events.len() < 128
            && event
                .receipt_bytes
                .as_ref()
                .is_none_or(|receipt| receipt.len() <= 4096)
        {
            self.delivery_events.push(event);
        }
    }
}

#[derive(Default)]
pub struct VaultData {
    pub identities: Vec<Identity>,
    pub contacts: Vec<Contact>,
    pub messages: Vec<StoredMessage>,
    pub conversation_keys: Vec<ConversationKey>,
    pub async_protocol_states: Vec<AsyncProtocolState>,
    pub mailbox_inboxes: Vec<MailboxInbox>,
    pub async_outbox: Vec<AsyncOutboxItem>,
    pub pending_recipient_receipts: Vec<PendingRecipientReceipt>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncProtocolState {
    pub identity_id: String,
    pub state: Vec<u8>,
}

impl Drop for AsyncProtocolState {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

/// Independent local-storage key for one DM. Its fields stay private so callers
/// can carry the vault without accidentally treating this as an identity key.
pub struct ConversationKey {
    conversation: String,
    key: Zeroizing<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyVaultData {
    identities: Vec<Identity>,
    contacts: Vec<Contact>,
    messages: Vec<StoredMessage>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredConversationKey {
    conversation: String,
    key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMessageCiphertext {
    conversation: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultStorageV2 {
    identities: Vec<Identity>,
    contacts: Vec<Contact>,
    conversation_keys: Vec<StoredConversationKey>,
    messages: Vec<StoredMessageCiphertext>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultStorageV3 {
    identities: Vec<Identity>,
    contacts: Vec<Contact>,
    conversation_keys: Vec<StoredConversationKey>,
    messages: Vec<StoredMessageCiphertext>,
    async_protocol_states: Vec<AsyncProtocolState>,
    #[serde(default)]
    mailbox_inboxes: Vec<MailboxInbox>,
    #[serde(default)]
    async_outbox: Vec<AsyncOutboxItem>,
    #[serde(default)]
    pending_recipient_receipts: Vec<PendingRecipientReceipt>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEnvelope {
    version: u8,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

pub fn fingerprint(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn save_vault(path: &Path, data: &mut VaultData, passphrase: &str) -> Result<(), AkratError> {
    ensure_conversation_keys(data)?;
    validate_vault(data)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| AkratError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| AkratError::Random)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|_| AkratError::Authentication)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AkratError::Authentication)?;
    let mut encrypted_messages = Vec::with_capacity(data.messages.len());
    for message in &data.messages {
        let conversation_key = data
            .conversation_keys
            .iter()
            .find(|key| key.conversation == message.conversation)
            .ok_or(AkratError::InvalidVault)?;
        let cipher = Aes256Gcm::new_from_slice(conversation_key.key.as_ref())
            .map_err(|_| AkratError::Authentication)?;
        let mut message_nonce = [0u8; 12];
        getrandom::fill(&mut message_nonce).map_err(|_| AkratError::Random)?;
        let mut message_plaintext =
            Zeroizing::new(serde_json::to_vec(message).map_err(|_| AkratError::Serialization)?);
        let nonce =
            Nonce::try_from(message_nonce.as_slice()).map_err(|_| AkratError::Authentication)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: message_plaintext.as_slice(),
                    aad: message.conversation.as_bytes(),
                },
            )
            .map_err(|_| AkratError::Authentication)?;
        message_plaintext.zeroize();
        encrypted_messages.push(StoredMessageCiphertext {
            conversation: message.conversation.clone(),
            nonce: message_nonce.to_vec(),
            ciphertext,
        });
    }
    let storage = VaultStorageV3 {
        identities: data
            .identities
            .iter()
            .map(Identity::detached_copy)
            .collect(),
        contacts: data.contacts.clone(),
        conversation_keys: data
            .conversation_keys
            .iter()
            .map(|key| StoredConversationKey {
                conversation: key.conversation.clone(),
                key: key.key.to_vec(),
            })
            .collect(),
        messages: encrypted_messages,
        async_protocol_states: data.async_protocol_states.clone(),
        mailbox_inboxes: data.mailbox_inboxes.clone(),
        async_outbox: data.async_outbox.clone(),
        pending_recipient_receipts: data.pending_recipient_receipts.clone(),
    };
    let mut plaintext =
        Zeroizing::new(serde_json::to_vec(&storage).map_err(|_| AkratError::Serialization)?);
    if plaintext.len() > MAX_VAULT_SIZE {
        return Err(AkratError::InvalidVault);
    }
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| AkratError::Authentication)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| AkratError::Authentication)?;
    plaintext.zeroize();
    let envelope = VaultEnvelope {
        version: FORMAT_VERSION,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|_| AkratError::Serialization)?;
    write_atomically(path, &encoded)
}

pub fn load_vault(path: &Path, passphrase: &str) -> Result<VaultData, AkratError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_VAULT_SIZE as u64 {
        return Err(AkratError::InvalidVault);
    }
    let mut encoded = Vec::new();
    file.take((MAX_VAULT_SIZE + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_VAULT_SIZE {
        return Err(AkratError::InvalidVault);
    }
    let envelope: VaultEnvelope =
        serde_json::from_slice(&encoded).map_err(|_| AkratError::InvalidVault)?;
    if !(LEGACY_FORMAT_VERSION..=FORMAT_VERSION).contains(&envelope.version)
        || envelope.salt.len() != 16
        || envelope.nonce.len() != 12
        || envelope.ciphertext.len() < 16
    {
        return Err(AkratError::InvalidVault);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &envelope.salt, key.as_mut())
        .map_err(|_| AkratError::Authentication)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AkratError::Authentication)?;
    let nonce = Nonce::try_from(envelope.nonce.as_slice()).map_err(|_| AkratError::InvalidVault)?;
    let plaintext = cipher
        .decrypt(&nonce, envelope.ciphertext.as_slice())
        .map_err(|_| AkratError::Authentication)?;
    let mut plaintext = Zeroizing::new(plaintext);
    if envelope.version == LEGACY_FORMAT_VERSION {
        let legacy: LegacyVaultData =
            serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?;
        plaintext.zeroize();
        let mut result = VaultData {
            identities: legacy.identities,
            contacts: legacy.contacts,
            messages: legacy.messages,
            conversation_keys: Vec::new(),
            async_protocol_states: Vec::new(),
            mailbox_inboxes: Vec::new(),
            async_outbox: Vec::new(),
            pending_recipient_receipts: Vec::new(),
        };
        ensure_conversation_keys(&mut result)?;
        validate_vault(&result)?;
        // Upgrade in place atomically so the first unlock migrates old histories.
        save_vault(path, &mut result, passphrase)?;
        return Ok(result);
    }
    let stored: VaultStorageV3 = if envelope.version == 2 {
        let old: VaultStorageV2 =
            serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?;
        VaultStorageV3 {
            identities: old.identities,
            contacts: old.contacts,
            conversation_keys: old.conversation_keys,
            messages: old.messages,
            async_protocol_states: Vec::new(),
            mailbox_inboxes: Vec::new(),
            async_outbox: Vec::new(),
            pending_recipient_receipts: Vec::new(),
        }
    } else {
        serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?
    };
    plaintext.zeroize();
    let mut conversation_keys = Vec::with_capacity(stored.conversation_keys.len());
    for stored_key in stored.conversation_keys {
        let key: [u8; 32] = stored_key
            .key
            .try_into()
            .map_err(|_| AkratError::InvalidVault)?;
        conversation_keys.push(ConversationKey {
            conversation: stored_key.conversation,
            key: Zeroizing::new(key),
        });
    }
    let mut messages = Vec::with_capacity(stored.messages.len());
    for stored_message in stored.messages {
        if stored_message.nonce.len() != 12 {
            return Err(AkratError::InvalidVault);
        }
        let conversation_key = conversation_keys
            .iter()
            .find(|key| key.conversation == stored_message.conversation)
            .ok_or(AkratError::InvalidVault)?;
        let cipher = Aes256Gcm::new_from_slice(conversation_key.key.as_ref())
            .map_err(|_| AkratError::InvalidVault)?;
        let nonce = Nonce::try_from(stored_message.nonce.as_slice())
            .map_err(|_| AkratError::InvalidVault)?;
        let mut message_plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: stored_message.ciphertext.as_slice(),
                        aad: stored_message.conversation.as_bytes(),
                    },
                )
                .map_err(|_| AkratError::Authentication)?,
        );
        let message: StoredMessage =
            serde_json::from_slice(&message_plaintext).map_err(|_| AkratError::InvalidVault)?;
        message_plaintext.zeroize();
        if message.conversation != stored_message.conversation {
            return Err(AkratError::InvalidVault);
        }
        messages.push(message);
    }
    let result = VaultData {
        identities: stored.identities,
        contacts: stored.contacts,
        messages,
        conversation_keys,
        async_protocol_states: stored.async_protocol_states,
        mailbox_inboxes: stored.mailbox_inboxes,
        async_outbox: stored.async_outbox,
        pending_recipient_receipts: stored.pending_recipient_receipts,
    };
    validate_vault(&result)?;
    if envelope.version != FORMAT_VERSION {
        let mut migrated = result;
        save_vault(path, &mut migrated, passphrase)?;
        return Ok(migrated);
    }
    Ok(result)
}

fn ensure_conversation_keys(data: &mut VaultData) -> Result<(), AkratError> {
    let mut seen = std::collections::HashSet::new();
    for key in &data.conversation_keys {
        if key.conversation.is_empty() || !seen.insert(key.conversation.clone()) {
            return Err(AkratError::InvalidVault);
        }
    }
    for message in &data.messages {
        if !seen.contains(&message.conversation) {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut()).map_err(|_| AkratError::Random)?;
            data.conversation_keys.push(ConversationKey {
                conversation: message.conversation.clone(),
                key,
            });
            seen.insert(message.conversation.clone());
        }
    }
    Ok(())
}

fn validate_vault(data: &VaultData) -> Result<(), AkratError> {
    let mut identities = std::collections::HashSet::new();
    for identity in &data.identities {
        if identity.public_key.len() != 32
            || identity.private_key.len() != 32
            || identity.id != hex::encode(Sha256::digest(&identity.public_key))
            || identity.name.trim().is_empty()
            || !identities.insert(identity.id.as_str())
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut contacts = std::collections::HashSet::new();
    for contact in &data.contacts {
        if contact.public_key.len() != 32
            || contact.fingerprint != fingerprint(&contact.public_key)
            || (!contact.transport_id.is_empty()
                && contact.transport_id.parse::<iroh::EndpointId>().is_err())
            || !contacts.insert(contact.fingerprint.as_str())
        {
            return Err(AkratError::InvalidVault);
        }
        if contact.mailbox_replicas.len() > MAX_MAILBOX_REPLICAS
            || contact
                .mailbox_route
                .iter()
                .chain(contact.mailbox_replicas.iter())
                .any(|route| !valid_mailbox_route(route))
            || {
                let mut destinations = std::collections::HashSet::new();
                contact
                    .mailbox_route
                    .iter()
                    .chain(contact.mailbox_replicas.iter())
                    .any(|route| {
                        !destinations.insert((route.endpoint.as_str(), route.mailbox_id.as_str()))
                    })
            }
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut messages = std::collections::HashSet::new();
    for message in &data.messages {
        if message.id.is_empty()
            || message.text.len() > MAX_VAULT_SIZE
            || !messages.insert((message.conversation.as_str(), message.id.as_str()))
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut conversation_keys = std::collections::HashSet::new();
    for key in &data.conversation_keys {
        if key.conversation.is_empty() || !conversation_keys.insert(key.conversation.as_str()) {
            return Err(AkratError::InvalidVault);
        }
    }
    if data
        .messages
        .iter()
        .any(|message| !conversation_keys.contains(message.conversation.as_str()))
    {
        return Err(AkratError::InvalidVault);
    }
    let mut protocol_identity_ids = std::collections::HashSet::new();
    for state in &data.async_protocol_states {
        if !identities.contains(state.identity_id.as_str())
            || !protocol_identity_ids.insert(state.identity_id.as_str())
            || async_crypto::validate_state(&state.state).is_err()
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut inboxes = std::collections::HashSet::new();
    for inbox in &data.mailbox_inboxes {
        if !identities.contains(inbox.identity_id.as_str())
            || inbox.endpoint.is_empty()
            || inbox.endpoint.len() > 512
            || inbox.server_noise_public_key.len() != 32
            || inbox.server_signing_public_key.len() != 32
            || inbox.server_key_generation > 64
            || inbox.server_revocation_sequence > 64
            || inbox.mailbox_id.is_empty()
            || inbox.mailbox_id.len() > 128
            || inbox.write_capability.len() < 32
            || inbox.read_capability.len() < 32
            || inbox.bundle_capability.len() < 32
            || inbox.write_capability.len() > 256
            || inbox.read_capability.len() > 256
            || inbox.bundle_capability.len() > 256
            || !inboxes.insert((
                inbox.identity_id.as_str(),
                inbox.endpoint.as_str(),
                inbox.mailbox_id.as_str(),
            ))
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut outbox_ids = std::collections::HashSet::new();
    for item in &data.async_outbox {
        if item.envelope.is_empty()
            || item.envelope.len() > 256 * 1024
            || !data.messages.iter().any(|message| {
                message.outgoing
                    && message.conversation == item.conversation
                    && message.id == item.message_id
            })
            || !outbox_ids.insert((item.conversation.as_str(), item.message_id.as_str()))
        {
            return Err(AkratError::InvalidVault);
        }
    }
    Ok(())
}

fn valid_mailbox_route(route: &MailboxRoute) -> bool {
    !route.endpoint.is_empty()
        && route.endpoint.len() <= 512
        && route.server_noise_public_key.len() == 32
        && route.server_signing_public_key.len() == 32
        && route.server_key_generation <= 64
        && route.server_revocation_sequence <= 64
        && !route.mailbox_id.is_empty()
        && route.mailbox_id.len() <= 128
        && route.write_capability.len() >= 32
        && route.bundle_capability.len() >= 32
        && route.write_capability.len() <= 256
        && route.bundle_capability.len() <= 256
}

fn write_atomically(path: &Path, data: &[u8]) -> Result<(), AkratError> {
    write_atomically_with_interrupt(path, data, false)
}

fn write_atomically_with_interrupt(
    path: &Path,
    data: &[u8],
    interrupt_after_sync: bool,
) -> Result<(), AkratError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| AkratError::Random)?;
    let temporary = path.with_extension(format!("{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        if interrupt_after_sync {
            drop(file);
            return Err(std::io::Error::other("injected process interruption"));
        }
        drop(file);
        fs::rename(&temporary, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(AkratError::Io)
}

pub(crate) fn noise_params() -> Result<NoiseParams, AkratError> {
    NOISE_PROTOCOL.parse().map_err(|_| AkratError::Identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn encrypted_vault_round_trips_identity_contact_and_history() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let identity = Identity::generate("Alice".to_string()).expect("identity");
        let bob = Identity::generate("Bob".to_string()).expect("Bob");
        let mut data = VaultData {
            identities: vec![identity],
            contacts: vec![Contact {
                fingerprint: bob.fingerprint(),
                name: "Bob".to_string(),
                public_key: bob.public_key().to_vec(),
                transport_id: bob.transport_id(),
                legacy_address: "127.0.0.1:4000".to_string(),
                manually_verified: true,
                mailbox_route: None,
                mailbox_replicas: Vec::new(),
            }],
            messages: vec![
                StoredMessage {
                    conversation: "peer".to_string(),
                    id: "message-1".to_string(),
                    outgoing: false,
                    text: "hello".to_string(),
                    delivery: DeliveryState::Received,
                    timestamp: 42,
                    delivery_events: vec![DeliveryEvent {
                        timestamp: 43,
                        kind: DeliveryEventKind::AuthenticatedAndSaved,
                        actor: DeliveryActor::RecipientClient,
                        actor_fingerprint: Some("a1b2".into()),
                        actor_name: Some("Bob".into()),
                        receipt_sha256: Some("c3d4".into()),
                        receipt_bytes: Some(b"private receipt".to_vec()),
                        verified: true,
                    }],
                    received_ciphertext_sha256: None,
                },
                StoredMessage {
                    conversation: "peer".to_string(),
                    id: "queued-message".to_string(),
                    outgoing: true,
                    text: "stored while offline".to_string(),
                    delivery: DeliveryState::Queued,
                    timestamp: 43,
                    delivery_events: Vec::new(),
                    received_ciphertext_sha256: None,
                },
            ],
            conversation_keys: Vec::new(),
            async_protocol_states: Vec::new(),
            mailbox_inboxes: Vec::new(),
            async_outbox: Vec::new(),
            pending_recipient_receipts: Vec::new(),
        };
        save_vault(&path, &mut data, "correct horse battery staple").expect("save");
        let bytes = fs::read(&path).expect("read vault");
        assert!(!String::from_utf8_lossy(&bytes).contains("correct horse battery staple"));
        assert!(!String::from_utf8_lossy(&bytes).contains("hello"));
        assert!(!String::from_utf8_lossy(&bytes).contains("private receipt"));
        let loaded = load_vault(&path, "correct horse battery staple").expect("load");
        assert_eq!(loaded.identities.len(), 1);
        assert_eq!(loaded.identities[0].id, data.identities[0].id);
        assert_eq!(loaded.contacts[0].name, "Bob");
        assert_eq!(loaded.messages[0].text, "hello");
        assert_eq!(
            loaded.messages[0].delivery_events[0].kind,
            DeliveryEventKind::AuthenticatedAndSaved
        );
        assert_eq!(
            loaded.messages[0].delivery_events[0].actor_name.as_deref(),
            Some("Bob")
        );
        assert_eq!(
            loaded.messages[0].delivery_events[0]
                .receipt_bytes
                .as_deref(),
            Some(b"private receipt".as_slice())
        );
        assert_eq!(loaded.messages[1].delivery, DeliveryState::Queued);
        assert!(loaded.messages[1].delivery.needs_delivery());
    }

    #[tokio::test]
    async fn signal_prekeys_and_ratchet_state_are_persisted_inside_the_encrypted_vault() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let identity = Identity::generate("Bob".into()).expect("identity");
        let (bundle, state) = async_crypto::publish_bundle(&identity, &[])
            .await
            .expect("publish bundle");
        let mut vault = VaultData {
            async_protocol_states: vec![AsyncProtocolState {
                identity_id: identity.id.clone(),
                state: state.clone(),
            }],
            identities: vec![identity],
            ..VaultData::default()
        };
        save_vault(&path, &mut vault, "test phrase").expect("save vault");
        let encoded = fs::read(&path).expect("read vault");
        assert_eq!(
            serde_json::from_slice::<VaultEnvelope>(&encoded)
                .expect("envelope")
                .version,
            3
        );
        assert!(!encoded.windows(state.len()).any(|window| window == state));
        let loaded = load_vault(&path, "test phrase").expect("load vault");
        assert_eq!(loaded.async_protocol_states[0].state, state);
        assert_eq!(
            &bundle.identity_public_key[1..],
            loaded.identities[0].public_key()
        );
    }

    #[test]
    fn each_dm_has_a_stable_independent_storage_key_and_encrypted_records() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut data = VaultData {
            messages: vec![
                StoredMessage {
                    conversation: "alice:bob".into(),
                    id: "message-bob".into(),
                    outgoing: true,
                    text: "secret for Bob".into(),
                    delivery: DeliveryState::Sent,
                    timestamp: 10,
                    delivery_events: Vec::new(),
                    received_ciphertext_sha256: None,
                },
                StoredMessage {
                    conversation: "alice:carol".into(),
                    id: "message-carol".into(),
                    outgoing: false,
                    text: "secret for Carol".into(),
                    delivery: DeliveryState::Received,
                    timestamp: 11,
                    delivery_events: Vec::new(),
                    received_ciphertext_sha256: None,
                },
            ],
            ..VaultData::default()
        };

        save_vault(&path, &mut data, "vault passphrase").expect("save");
        assert_eq!(data.conversation_keys.len(), 2);
        assert_ne!(
            data.conversation_keys[0].key.as_ref(),
            data.conversation_keys[1].key.as_ref()
        );
        let original_keys = data
            .conversation_keys
            .iter()
            .map(|key| (key.conversation.clone(), *key.key))
            .collect::<std::collections::HashMap<_, _>>();

        let envelope: VaultEnvelope =
            serde_json::from_slice(&fs::read(&path).expect("read vault")).expect("envelope");
        assert_eq!(envelope.version, FORMAT_VERSION);
        let mut master_key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(b"vault passphrase", &envelope.salt, master_key.as_mut())
            .expect("derive vault key");
        let vault_cipher = Aes256Gcm::new_from_slice(master_key.as_ref()).expect("cipher");
        let vault_nonce = Nonce::try_from(envelope.nonce.as_slice()).expect("vault nonce");
        let inner = vault_cipher
            .decrypt(&vault_nonce, envelope.ciphertext.as_slice())
            .expect("decrypt outer vault");
        let stored: VaultStorageV3 = serde_json::from_slice(&inner).expect("stored vault");
        assert_eq!(stored.messages.len(), 2);
        for message in &stored.messages {
            let encoded = serde_json::to_vec(message).expect("encode record");
            assert!(!String::from_utf8_lossy(&encoded).contains("secret for"));
        }

        let mut loaded = load_vault(&path, "vault passphrase").expect("load");
        assert_eq!(loaded.messages[0].text, "secret for Bob");
        assert_eq!(loaded.messages[1].text, "secret for Carol");
        assert_eq!(loaded.conversation_keys.len(), 2);
        for key in &loaded.conversation_keys {
            assert_eq!(original_keys[&key.conversation], *key.key);
        }
        save_vault(&path, &mut loaded, "vault passphrase").expect("save again");
        let reopened = load_vault(&path, "vault passphrase").expect("reopen");
        for key in &reopened.conversation_keys {
            assert_eq!(original_keys[&key.conversation], *key.key);
        }
    }

    #[test]
    fn legacy_vault_migrates_to_per_conversation_encryption_on_unlock() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("legacy.akrat");
        let legacy = LegacyVaultData {
            identities: Vec::new(),
            contacts: Vec::new(),
            messages: vec![StoredMessage {
                conversation: "alice:bob".into(),
                id: "old-message".into(),
                outgoing: false,
                text: "legacy history".into(),
                delivery: DeliveryState::Received,
                timestamp: 12,
                delivery_events: Vec::new(),
                received_ciphertext_sha256: None,
            }],
        };
        let salt = [7u8; 16];
        let nonce_bytes = [9u8; 12];
        let mut master_key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(b"legacy passphrase", &salt, master_key.as_mut())
            .expect("derive vault key");
        let cipher = Aes256Gcm::new_from_slice(master_key.as_ref()).expect("cipher");
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce");
        let plaintext = serde_json::to_vec(&legacy).expect("serialize legacy data");
        let envelope = VaultEnvelope {
            version: LEGACY_FORMAT_VERSION,
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext: cipher
                .encrypt(&nonce, plaintext.as_slice())
                .expect("encrypt"),
        };
        fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("serialize envelope"),
        )
        .expect("write legacy vault");

        let migrated = load_vault(&path, "legacy passphrase").expect("migrate on unlock");
        assert_eq!(migrated.messages[0].text, "legacy history");
        assert_eq!(migrated.conversation_keys.len(), 1);
        let migrated_envelope: VaultEnvelope =
            serde_json::from_slice(&fs::read(&path).expect("read migrated vault"))
                .expect("migrated envelope");
        assert_eq!(migrated_envelope.version, FORMAT_VERSION);
    }

    #[test]
    fn version_two_vault_migrates_to_version_three_without_losing_identity() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let identity = Identity::generate("Version two identity".into()).expect("identity");
        let storage = VaultStorageV2 {
            identities: vec![identity.detached_copy()],
            contacts: Vec::new(),
            conversation_keys: Vec::new(),
            messages: Vec::new(),
        };
        let plaintext = serde_json::to_vec(&storage).expect("serialize v2");
        let salt = [7u8; 16];
        let nonce_bytes = [9u8; 12];
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::default()
            .hash_password_into(b"v2 migration phrase", &salt, key.as_mut())
            .expect("derive key");
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("cipher");
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce");
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .expect("encrypt");
        let envelope = VaultEnvelope {
            version: 2,
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };
        fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("encode envelope"),
        )
        .expect("write v2");
        let migrated = load_vault(&path, "v2 migration phrase").expect("migrate vault");
        assert_eq!(migrated.identities[0].id, identity.id);
        assert!(migrated.async_protocol_states.is_empty());
        let rewritten: VaultEnvelope =
            serde_json::from_slice(&fs::read(path).expect("read migrated vault"))
                .expect("parse migrated envelope");
        assert_eq!(rewritten.version, 3);
    }

    #[test]
    fn wrong_passphrase_and_tampering_fail_closed() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut data = VaultData::default();
        save_vault(&path, &mut data, "secret").expect("save");
        assert!(matches!(
            load_vault(&path, "wrong"),
            Err(AkratError::Authentication)
        ));
        let mut data = fs::read(&path).expect("read");
        let last = data.len() - 4;
        data[last] ^= 1;
        fs::write(&path, data).expect("tamper");
        assert!(load_vault(&path, "secret").is_err());
    }

    #[test]
    fn replacing_vault_preserves_the_latest_complete_state() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut data = VaultData::default();
        save_vault(&path, &mut data, "secret").expect("first save");
        data.identities
            .push(Identity::generate("Alice".to_string()).expect("identity"));
        save_vault(&path, &mut data, "secret").expect("replacement save");
        let reopened = load_vault(&path, "secret").expect("reopen");
        assert_eq!(reopened.identities.len(), 1);
    }

    #[test]
    fn interruption_after_temporary_file_sync_keeps_previous_vault() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut original = VaultData::default();
        save_vault(&path, &mut original, "secret").expect("initial save");
        let previous = fs::read(&path).expect("original bytes");
        assert!(write_atomically_with_interrupt(&path, b"incomplete replacement", true).is_err());
        assert_eq!(fs::read(&path).expect("preserved bytes"), previous);
        assert!(load_vault(&path, "secret").is_ok());
    }

    #[test]
    fn invitation_round_trips_and_rejects_changed_keys() {
        let identity = Identity::generate("Alice".to_string()).expect("identity");
        let invitation = Invitation::create(&identity).expect("invitation");
        let uri = invitation.to_uri().expect("uri");
        assert_eq!(Invitation::from_uri(&uri).expect("parse"), invitation);
        assert_eq!(
            identity.transport_id(),
            identity.detached_copy().transport_id()
        );
        assert_ne!(
            identity.transport_id(),
            Identity::generate("Bob".into())
                .expect("Bob")
                .transport_id()
        );
        assert!(!uri.contains("address"));
        assert!(Invitation::from_uri("akrat://invite/not-base64!").is_err());
    }

    #[test]
    fn legacy_ip_contact_can_be_loaded_without_becoming_a_network_route() {
        let identity = Identity::generate("Legacy contact".into()).expect("identity");
        let legacy = serde_json::json!({
            "fingerprint": identity.fingerprint(),
            "name": "Old peer",
            "public_key": identity.public_key(),
            "address": "10.0.0.4:47474",
            "manually_verified": true
        });
        let contact: Contact = serde_json::from_value(legacy).expect("migrate old contact");
        assert!(contact.transport_id.is_empty());
        assert_eq!(contact.legacy_address, "10.0.0.4:47474");
    }
}
