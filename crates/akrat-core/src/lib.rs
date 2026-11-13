pub mod async_crypto;
pub mod attachments;
#[cfg(feature = "markdown")]
pub mod markdown;
pub mod network;
pub use akrat_trust::{RelayIdentityPin, RelayTrustLevel};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{Builder, params::NoiseParams};
#[cfg(feature = "p2p")]
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(feature = "p2p")]
use std::sync::Arc;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u8 = 4;
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
    #[error("vault revision conflict: expected {expected}, found {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
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
        let secret = iroh_base::SecretKey::from_bytes(&private_key);
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_event: Option<GroupEventOutboxRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupEventOutboxRef {
    pub group_id: String,
    pub sequence: u64,
    pub event_sha256: String,
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
            .parse::<iroh_base::EndpointId>()
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
    pub revision: u64,
    pub identities: Vec<Identity>,
    pub contacts: Vec<Contact>,
    pub messages: Vec<StoredMessage>,
    pub groups: Vec<GroupState>,
    pub group_deliveries: Vec<GroupMessageDelivery>,
    pub attachments: Vec<StoredAttachment>,
    pub conversation_keys: Vec<ConversationKey>,
    pub async_protocol_states: Vec<AsyncProtocolState>,
    pub mailbox_inboxes: Vec<MailboxInbox>,
    pub async_outbox: Vec<AsyncOutboxItem>,
    pub pending_recipient_receipts: Vec<PendingRecipientReceipt>,
    pub relay_settings: RelaySettings,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RelaySettings {
    pub use_default_relays: bool,
    pub custom_relays: Vec<String>,
    pub identity_pins: Vec<RelayIdentityPin>,
    pub minimum_trust: RelayTrustLevel,
    pub operational_records: Vec<akrat_trust::RelayOperationalRecord>,
    pub verified_evidence: Vec<akrat_trust::RelayEquivocationEvidence>,
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            use_default_relays: true,
            custom_relays: Vec::new(),
            identity_pins: Vec::new(),
            minimum_trust: RelayTrustLevel::Unknown,
            operational_records: Vec::new(),
            verified_evidence: Vec::new(),
        }
    }
}

impl RelaySettings {
    #[cfg(feature = "p2p")]
    pub fn path_selector(&self) -> Arc<dyn iroh::endpoint::transports::PathSelector> {
        let favorites = self
            .operational_records
            .iter()
            .filter(|record| {
                record.disposition == akrat_trust::RelayDisposition::Favorite
                    && record.is_eligible()
                    && self
                        .custom_relays
                        .iter()
                        .any(|url| url == &record.relay_url)
            })
            .filter_map(|record| record.relay_url.parse::<iroh::RelayUrl>().ok())
            .collect();
        Arc::new(RelayPathSelector { favorites })
    }

    #[cfg(feature = "p2p")]
    pub fn relay_mode(&self) -> Result<iroh::RelayMode, String> {
        if self.custom_relays.len() > 16 {
            return Err("un maximum de 16 relais personnalisés est autorisé".into());
        }
        if self.identity_pins.len() > 16 {
            return Err("un maximum de 16 identités de relais peut être épinglé".into());
        }
        if self.minimum_trust >= RelayTrustLevel::ExecutionAttested {
            return Err(
                "l’attestation matérielle d’exécution n’est pas disponible dans cette version"
                    .into(),
            );
        }
        if self.operational_records.len() > 16
            || self.verified_evidence.len() > 64
            || self.operational_records.iter().any(|record| {
                !self
                    .custom_relays
                    .iter()
                    .any(|url| url == &record.relay_url)
            })
        {
            return Err("état local des relais incohérent ou trop volumineux".into());
        }
        let configured_relays = self
            .custom_relays
            .iter()
            .map(|value| {
                value
                    .trim()
                    .parse::<iroh::RelayUrl>()
                    .map_err(|_| format!("URL de relais Iroh invalide : {value}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for pin in &self.identity_pins {
            let pinned_url = pin
                .relay_url
                .parse::<iroh::RelayUrl>()
                .map_err(|_| format!("URL d’identité de relais invalide : {}", pin.relay_url))?;
            let public_key = hex::decode(&pin.public_key_hex)
                .map_err(|_| "clé publique épinglée invalide".to_string())?;
            if public_key.len() != 32
                || !akrat_trust::relay_identity_fingerprint(&public_key)
                    .eq_ignore_ascii_case(&pin.fingerprint)
                || !configured_relays.iter().any(|relay| relay == &pinned_url)
            {
                return Err("épinglage de relais incohérent ou invalide".into());
            }
        }
        let relays = configured_relays
            .into_iter()
            .filter(|relay| {
                self.operational_records
                    .iter()
                    .find(|record| {
                        record.relay_url.parse::<iroh::RelayUrl>().ok().as_ref() == Some(relay)
                    })
                    .is_none_or(akrat_trust::RelayOperationalRecord::is_eligible)
            })
            .collect::<Vec<_>>();
        if !relays.is_empty() {
            if self.minimum_trust >= RelayTrustLevel::IdentityVerified
                && relays.iter().any(|relay| {
                    !self.identity_pins.iter().any(|pin| {
                        pin.relay_url.parse::<iroh::RelayUrl>().ok().as_ref() == Some(relay)
                    })
                })
            {
                return Err(
                    "la politique exige une identité épinglée pour chaque relais personnalisé"
                        .into(),
                );
            }
            return Ok(iroh::RelayMode::custom(relays));
        }
        if !self.custom_relays.is_empty() {
            return Ok(iroh::RelayMode::Disabled);
        }
        if self.use_default_relays {
            if self.minimum_trust >= RelayTrustLevel::IdentityVerified {
                return Ok(iroh::RelayMode::Disabled);
            }
            Ok(iroh::RelayMode::Default)
        } else {
            Ok(iroh::RelayMode::Disabled)
        }
    }
}

#[derive(Debug)]
#[cfg(feature = "p2p")]
struct RelayPathSelector {
    favorites: HashSet<iroh::RelayUrl>,
}

#[cfg(feature = "p2p")]
impl RelayPathSelector {
    fn tier(&self, path: &iroh::endpoint::transports::FourTuple) -> u8 {
        match path {
            iroh::endpoint::transports::FourTuple::Ip { .. }
            | iroh::endpoint::transports::FourTuple::Custom { .. } => 0,
            iroh::endpoint::transports::FourTuple::Relay { url, .. }
                if self.favorites.contains(url) =>
            {
                1
            }
            iroh::endpoint::transports::FourTuple::Relay { .. } => 2,
        }
    }
}

#[cfg(feature = "p2p")]
impl iroh::endpoint::transports::PathSelector for RelayPathSelector {
    fn select(
        &self,
        context: &iroh::endpoint::transports::PathSelectionContext<'_>,
    ) -> iroh::endpoint::transports::PathSelection {
        let mut best: Option<(iroh::endpoint::transports::PathSelectionData<'_>, u8, u128)> = None;
        let mut current_score = None;
        for path in context.paths() {
            let Some(stats) = path.stats() else {
                continue;
            };
            let tier = self.tier(path.network_path());
            let rtt = stats.rtt.as_nanos();
            if Some(path.network_path()) == context.current() {
                current_score = Some((tier, rtt));
            }
            if best
                .as_ref()
                .is_none_or(|(_, best_tier, best_rtt)| (tier, rtt) < (*best_tier, *best_rtt))
            {
                best = Some((path, tier, rtt));
            }
        }
        let mut selection = iroh::endpoint::transports::PathSelection::none();
        let Some((best_path, best_tier, best_rtt)) = best else {
            return selection;
        };
        let should_switch = current_score.is_none_or(|(current_tier, current_rtt)| {
            best_tier < current_tier
                || (best_tier == current_tier
                    && best_rtt.saturating_add(std::time::Duration::from_millis(50).as_nanos())
                        <= current_rtt)
        });
        if should_switch {
            selection.set(&best_path);
        }
        selection
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StoredAttachment {
    pub conversation: String,
    pub message_id: String,
    pub manifest: attachments::AttachmentManifest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mailbox_frame_receipts: Vec<MailboxAttachmentFrameReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MailboxAttachmentFrameReceipt {
    pub frame_id: String,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupMessageDelivery {
    pub group_id: String,
    pub message_id: String,
    pub epoch: u64,
    pub sequence: u64,
    pub recipients: Vec<GroupRecipientDelivery>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GroupRecipientStatus {
    Pending,
    Sent,
    Deposited,
    Received,
    Unconfirmed,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupRecipientDelivery {
    pub fingerprint: String,
    pub status: GroupRecipientStatus,
    pub updated_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    pub fingerprint: String,
    pub public_key: Vec<u8>,
    pub display_name: String,
    pub role: GroupRole,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupChange {
    Create {
        name: String,
        creator_name: String,
    },
    Invite {
        member: GroupMember,
    },
    Accept,
    Remove {
        fingerprint: String,
    },
    Leave,
    Rename {
        name: String,
    },
    SetRole {
        fingerprint: String,
        role: GroupRole,
    },
    Rotate,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupEvent {
    pub version: u8,
    pub group_id: String,
    pub sequence: u64,
    pub epoch: u64,
    pub previous_event_sha256: Option<String>,
    pub actor_public_key: Vec<u8>,
    pub change: GroupChange,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupState {
    pub protocol_version: u8,
    pub group_id: String,
    pub name: String,
    pub creator_fingerprint: String,
    pub epoch: u64,
    pub sequence: u64,
    pub last_event_sha256: String,
    pub members: Vec<GroupMember>,
    pub events: Vec<GroupEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupMessage {
    pub version: u8,
    pub group_id: String,
    pub epoch: u64,
    pub sequence: u64,
    pub message_id: String,
    pub sender_public_key: Vec<u8>,
    pub timestamp: u64,
    pub text: String,
    #[serde(default)]
    pub has_attachment: bool,
}

impl GroupMessage {
    pub fn validate_for(&self, group: &GroupState, authenticated_peer_key: &[u8]) -> bool {
        let Ok(origin) = group.state_at_sequence(self.sequence) else {
            return false;
        };
        self.version == 1
            && self.group_id == group.group_id
            && self.epoch == origin.epoch
            && self.sender_public_key == authenticated_peer_key
            && self.message_id.len() <= 128
            && !self.message_id.is_empty()
            && self.text.len() <= 10 * 1024
            && origin.members.iter().any(|member| {
                member.accepted
                    && member.public_key == self.sender_public_key
                    && member.fingerprint == fingerprint(&self.sender_public_key)
            })
    }
}

#[derive(Serialize)]
struct GroupEventStatement<'a> {
    domain: &'static str,
    version: u8,
    group_id: &'a str,
    sequence: u64,
    epoch: u64,
    previous_event_sha256: &'a Option<String>,
    actor_public_key: &'a [u8],
    change: &'a GroupChange,
}

impl GroupEvent {
    pub fn signed(
        identity: &Identity,
        group_id: String,
        sequence: u64,
        epoch: u64,
        previous_event_sha256: Option<String>,
        change: GroupChange,
    ) -> Result<Self, AkratError> {
        let mut event = Self {
            version: 1,
            group_id,
            sequence,
            epoch,
            previous_event_sha256,
            actor_public_key: identity.public_key().to_vec(),
            change,
            signature: Vec::new(),
        };
        let statement = event.signing_bytes()?;
        event.signature = async_crypto::sign_identity_statement(identity, &statement)
            .map_err(|_| AkratError::InvalidIdentity)?;
        Ok(event)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, AkratError> {
        serde_json::to_vec(&GroupEventStatement {
            domain: "AKRAT/group-event/v1",
            version: self.version,
            group_id: &self.group_id,
            sequence: self.sequence,
            epoch: self.epoch,
            previous_event_sha256: &self.previous_event_sha256,
            actor_public_key: &self.actor_public_key,
            change: &self.change,
        })
        .map_err(|_| AkratError::Serialization)
    }

    pub fn digest(&self) -> Result<String, AkratError> {
        let bytes = serde_json::to_vec(self).map_err(|_| AkratError::Serialization)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn verify_signature(&self) -> Result<bool, AkratError> {
        if self.version != 1 || self.actor_public_key.len() != 32 || self.signature.is_empty() {
            return Ok(false);
        }
        async_crypto::verify_identity_statement(
            &self.actor_public_key,
            &self.signing_bytes()?,
            &self.signature,
        )
        .map_err(|_| AkratError::InvalidIdentity)
    }
}

impl GroupState {
    pub fn from_creation(event: &GroupEvent) -> Result<Self, AkratError> {
        if event.sequence != 0
            || event.epoch != 0
            || event.previous_event_sha256.is_some()
            || !event.verify_signature()?
            || event.group_id.is_empty()
            || event.group_id.len() > 128
        {
            return Err(AkratError::InvalidVault);
        }
        let GroupChange::Create { name, creator_name } = &event.change else {
            return Err(AkratError::InvalidVault);
        };
        validate_group_name(name)?;
        if creator_name.trim().is_empty() || creator_name.len() > 128 {
            return Err(AkratError::InvalidVault);
        }
        let fingerprint = fingerprint(&event.actor_public_key);
        let state = Self {
            protocol_version: 1,
            group_id: event.group_id.clone(),
            name: name.clone(),
            creator_fingerprint: fingerprint.clone(),
            epoch: 0,
            sequence: 0,
            last_event_sha256: event.digest()?,
            members: vec![GroupMember {
                fingerprint,
                public_key: event.actor_public_key.clone(),
                display_name: creator_name.clone(),
                role: GroupRole::Owner,
                accepted: true,
            }],
            events: vec![event.clone()],
        };
        Ok(state)
    }

    pub fn apply(&mut self, event: &GroupEvent) -> Result<(), AkratError> {
        if event.version != 1
            || event.group_id != self.group_id
            || Some(event.sequence) != self.sequence.checked_add(1)
            || event.previous_event_sha256.as_deref() != Some(self.last_event_sha256.as_str())
            || !event.verify_signature()?
        {
            return Err(AkratError::InvalidVault);
        }
        let actor_fingerprint = fingerprint(&event.actor_public_key);
        let actor = self
            .members
            .iter()
            .find(|member| {
                member.fingerprint == actor_fingerprint
                    && (member.accepted || matches!(&event.change, GroupChange::Accept))
            })
            .cloned()
            .ok_or(AkratError::InvalidVault)?;
        let owner_or_admin = matches!(actor.role, GroupRole::Owner | GroupRole::Admin);
        let epoch_change = matches!(
            &event.change,
            GroupChange::Accept
                | GroupChange::Remove { .. }
                | GroupChange::Leave
                | GroupChange::Rotate
        );
        let expected_epoch = self
            .epoch
            .checked_add(u64::from(epoch_change))
            .ok_or(AkratError::InvalidVault)?;
        if event.epoch != expected_epoch {
            return Err(AkratError::InvalidVault);
        }
        match &event.change {
            GroupChange::Create { .. } => return Err(AkratError::InvalidVault),
            GroupChange::Invite { member } => {
                if !owner_or_admin
                    || member.public_key.len() != 32
                    || member.fingerprint != fingerprint(&member.public_key)
                    || member.accepted
                    || member.role != GroupRole::Member
                    || member.display_name.len() > 128
                    || self
                        .members
                        .iter()
                        .any(|existing| existing.fingerprint == member.fingerprint)
                    || self.members.len() >= 256
                {
                    return Err(AkratError::InvalidVault);
                }
                self.members.push(member.clone());
            }
            GroupChange::Accept => {
                let member = self
                    .members
                    .iter_mut()
                    .find(|item| item.fingerprint == actor_fingerprint)
                    .ok_or(AkratError::InvalidVault)?;
                if member.accepted || member.role != GroupRole::Member {
                    return Err(AkratError::InvalidVault);
                }
                member.accepted = true;
            }
            GroupChange::Remove {
                fingerprint: target,
            } => {
                if !owner_or_admin
                    || target == &self.creator_fingerprint
                    || target == &actor_fingerprint
                {
                    return Err(AkratError::InvalidVault);
                }
                let position = self
                    .members
                    .iter()
                    .position(|member| &member.fingerprint == target)
                    .ok_or(AkratError::InvalidVault)?;
                if self.members[position].role == GroupRole::Owner {
                    return Err(AkratError::InvalidVault);
                }
                self.members.remove(position);
            }
            GroupChange::Leave => {
                if actor.role == GroupRole::Owner {
                    return Err(AkratError::InvalidVault);
                }
                self.members
                    .retain(|member| member.fingerprint != actor_fingerprint);
            }
            GroupChange::Rename { name } => {
                if !owner_or_admin {
                    return Err(AkratError::InvalidVault);
                }
                validate_group_name(name)?;
                self.name = name.clone();
            }
            GroupChange::SetRole {
                fingerprint: target,
                role,
            } => {
                if actor.role != GroupRole::Owner
                    || target == &self.creator_fingerprint
                    || *role == GroupRole::Owner
                {
                    return Err(AkratError::InvalidVault);
                }
                let member = self
                    .members
                    .iter_mut()
                    .find(|member| &member.fingerprint == target && member.accepted)
                    .ok_or(AkratError::InvalidVault)?;
                member.role = *role;
            }
            GroupChange::Rotate => {
                if !owner_or_admin {
                    return Err(AkratError::InvalidVault);
                }
            }
        }
        self.epoch = event.epoch;
        self.sequence = event.sequence;
        self.last_event_sha256 = event.digest()?;
        if self.events.len() >= 10_000 {
            return Err(AkratError::InvalidVault);
        }
        self.events.push(event.clone());
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AkratError> {
        if self.protocol_version != 1 || self.events.is_empty() || self.events.len() > 10_000 {
            return Err(AkratError::InvalidVault);
        }
        let mut replayed = Self::from_creation(&self.events[0])?;
        for event in self.events.iter().skip(1) {
            replayed.apply(event)?;
        }
        if replayed != *self {
            return Err(AkratError::InvalidVault);
        }
        Ok(())
    }

    pub fn state_at_sequence(&self, sequence: u64) -> Result<Self, AkratError> {
        let count = usize::try_from(sequence)
            .ok()
            .and_then(|sequence| sequence.checked_add(1))
            .ok_or(AkratError::InvalidVault)?;
        if count > self.events.len() {
            return Err(AkratError::InvalidVault);
        }
        let mut state = Self::from_creation(self.events.first().ok_or(AkratError::InvalidVault)?)?;
        for event in self.events.iter().take(count).skip(1) {
            state.apply(event)?;
        }
        Ok(state)
    }
}

fn validate_group_name(name: &str) -> Result<(), AkratError> {
    if name.trim().is_empty() || name.len() > 128 {
        return Err(AkratError::InvalidVault);
    }
    Ok(())
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
struct StoredGroupCiphertext {
    group_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAttachmentCiphertext {
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
    #[serde(default)]
    groups: Vec<StoredGroupCiphertext>,
    #[serde(default)]
    group_deliveries: Vec<GroupMessageDelivery>,
    #[serde(default)]
    attachments: Vec<StoredAttachmentCiphertext>,
    async_protocol_states: Vec<AsyncProtocolState>,
    #[serde(default)]
    mailbox_inboxes: Vec<MailboxInbox>,
    #[serde(default)]
    async_outbox: Vec<AsyncOutboxItem>,
    #[serde(default)]
    pending_recipient_receipts: Vec<PendingRecipientReceipt>,
    #[serde(default)]
    relay_settings: RelaySettings,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultStorageV4 {
    #[serde(default)]
    revision: u64,
    identities: Vec<Identity>,
    contacts: Vec<Contact>,
    conversation_keys: Vec<StoredConversationKey>,
    messages: Vec<StoredMessageCiphertext>,
    #[serde(default)]
    groups: Vec<StoredGroupCiphertext>,
    #[serde(default)]
    group_deliveries: Vec<GroupMessageDelivery>,
    #[serde(default)]
    attachments: Vec<StoredAttachmentCiphertext>,
    async_protocol_states: Vec<AsyncProtocolState>,
    #[serde(default)]
    mailbox_inboxes: Vec<MailboxInbox>,
    #[serde(default)]
    async_outbox: Vec<AsyncOutboxItem>,
    #[serde(default)]
    pending_recipient_receipts: Vec<PendingRecipientReceipt>,
    #[serde(default)]
    relay_settings: RelaySettings,
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
    let _lock = VaultFileLock::acquire(path)?;
    let actual_revision = if path.exists() {
        load_vault_inner(path, passphrase, false)?.revision
    } else {
        0
    };
    if data.revision != actual_revision {
        return Err(AkratError::RevisionConflict {
            expected: data.revision,
            actual: actual_revision,
        });
    }
    persist_vault_locked(path, data, passphrase, actual_revision)
}

pub fn mutate_vault<T>(
    path: &Path,
    passphrase: &str,
    mutation: impl FnOnce(&mut VaultData) -> Result<T, AkratError>,
) -> Result<T, AkratError> {
    let _lock = VaultFileLock::acquire(path)?;
    let mut data = if path.exists() {
        load_vault_inner(path, passphrase, false)?
    } else {
        VaultData::default()
    };
    let current_revision = data.revision;
    let result = mutation(&mut data)?;
    persist_vault_locked(path, &mut data, passphrase, current_revision)?;
    Ok(result)
}

pub struct VaultFileLock {
    file: File,
}

impl VaultFileLock {
    pub fn acquire(path: &Path) -> Result<Self, AkratError> {
        use fs2::FileExt;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let canonical_parent = parent.canonicalize()?;
        let file_name = path.file_name().ok_or(AkratError::InvalidVault)?;
        let lock_target = if path.exists() {
            path.canonicalize()?
        } else {
            canonical_parent.join(file_name)
        };
        let lock_path = lock_target.with_extension("akrat.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        file.lock_exclusive()?;
        Ok(Self { file })
    }
}

impl Drop for VaultFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn persist_vault_locked(
    path: &Path,
    data: &mut VaultData,
    passphrase: &str,
    current_revision: u64,
) -> Result<(), AkratError> {
    let next_revision = current_revision
        .checked_add(1)
        .ok_or(AkratError::InvalidVault)?;
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
    let mut encrypted_groups = Vec::with_capacity(data.groups.len());
    for group in &data.groups {
        let key_name = group_conversation_key(&group.group_id);
        let group_key = data
            .conversation_keys
            .iter()
            .find(|key| key.conversation == key_name)
            .ok_or(AkratError::InvalidVault)?;
        let cipher = Aes256Gcm::new_from_slice(group_key.key.as_ref())
            .map_err(|_| AkratError::Authentication)?;
        let mut group_nonce = [0u8; 12];
        getrandom::fill(&mut group_nonce).map_err(|_| AkratError::Random)?;
        let mut plaintext =
            Zeroizing::new(serde_json::to_vec(group).map_err(|_| AkratError::Serialization)?);
        let nonce =
            Nonce::try_from(group_nonce.as_slice()).map_err(|_| AkratError::Authentication)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: key_name.as_bytes(),
                },
            )
            .map_err(|_| AkratError::Authentication)?;
        plaintext.zeroize();
        encrypted_groups.push(StoredGroupCiphertext {
            group_id: group.group_id.clone(),
            nonce: group_nonce.to_vec(),
            ciphertext,
        });
    }
    let mut encrypted_attachments = Vec::with_capacity(data.attachments.len());
    for attachment in &data.attachments {
        let conversation_key = data
            .conversation_keys
            .iter()
            .find(|key| key.conversation == attachment.conversation)
            .ok_or(AkratError::InvalidVault)?;
        let cipher = Aes256Gcm::new_from_slice(conversation_key.key.as_ref())
            .map_err(|_| AkratError::Authentication)?;
        let mut attachment_nonce = [0u8; 12];
        getrandom::fill(&mut attachment_nonce).map_err(|_| AkratError::Random)?;
        let mut plaintext =
            Zeroizing::new(serde_json::to_vec(attachment).map_err(|_| AkratError::Serialization)?);
        let nonce =
            Nonce::try_from(attachment_nonce.as_slice()).map_err(|_| AkratError::Authentication)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: attachment.conversation.as_bytes(),
                },
            )
            .map_err(|_| AkratError::Authentication)?;
        plaintext.zeroize();
        encrypted_attachments.push(StoredAttachmentCiphertext {
            conversation: attachment.conversation.clone(),
            nonce: attachment_nonce.to_vec(),
            ciphertext,
        });
    }
    let storage = VaultStorageV4 {
        revision: next_revision,
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
        groups: encrypted_groups,
        group_deliveries: data.group_deliveries.clone(),
        attachments: encrypted_attachments,
        async_protocol_states: data.async_protocol_states.clone(),
        mailbox_inboxes: data.mailbox_inboxes.clone(),
        async_outbox: data.async_outbox.clone(),
        pending_recipient_receipts: data.pending_recipient_receipts.clone(),
        relay_settings: data.relay_settings.clone(),
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
    write_atomically(path, &encoded)?;
    data.revision = next_revision;
    Ok(())
}

pub fn load_vault(path: &Path, passphrase: &str) -> Result<VaultData, AkratError> {
    load_vault_inner(path, passphrase, true)
}

fn load_vault_inner(path: &Path, passphrase: &str, migrate: bool) -> Result<VaultData, AkratError> {
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
            revision: 0,
            identities: legacy.identities,
            contacts: legacy.contacts,
            messages: legacy.messages,
            groups: Vec::new(),
            group_deliveries: Vec::new(),
            attachments: Vec::new(),
            conversation_keys: Vec::new(),
            async_protocol_states: Vec::new(),
            mailbox_inboxes: Vec::new(),
            async_outbox: Vec::new(),
            pending_recipient_receipts: Vec::new(),
            relay_settings: RelaySettings::default(),
        };
        ensure_conversation_keys(&mut result)?;
        validate_vault(&result)?;
        // Upgrade in place atomically so the first unlock migrates old histories.
        if migrate {
            match save_vault(path, &mut result, passphrase) {
                Ok(()) => {}
                Err(AkratError::RevisionConflict { .. }) => {
                    return load_vault_inner(path, passphrase, false);
                }
                Err(error) => return Err(error),
            }
        }
        return Ok(result);
    }
    let (stored, revision): (VaultStorageV3, u64) = if envelope.version == 2 {
        let old: VaultStorageV2 =
            serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?;
        (
            VaultStorageV3 {
                identities: old.identities,
                contacts: old.contacts,
                conversation_keys: old.conversation_keys,
                messages: old.messages,
                groups: Vec::new(),
                group_deliveries: Vec::new(),
                attachments: Vec::new(),
                async_protocol_states: Vec::new(),
                mailbox_inboxes: Vec::new(),
                async_outbox: Vec::new(),
                pending_recipient_receipts: Vec::new(),
                relay_settings: RelaySettings::default(),
            },
            0,
        )
    } else if envelope.version == 3 {
        (
            serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?,
            0,
        )
    } else {
        let current: VaultStorageV4 =
            serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?;
        (
            VaultStorageV3 {
                identities: current.identities,
                contacts: current.contacts,
                conversation_keys: current.conversation_keys,
                messages: current.messages,
                groups: current.groups,
                group_deliveries: current.group_deliveries,
                attachments: current.attachments,
                async_protocol_states: current.async_protocol_states,
                mailbox_inboxes: current.mailbox_inboxes,
                async_outbox: current.async_outbox,
                pending_recipient_receipts: current.pending_recipient_receipts,
                relay_settings: current.relay_settings,
            },
            current.revision,
        )
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
    let mut groups = Vec::with_capacity(stored.groups.len());
    for stored_group in stored.groups {
        if stored_group.nonce.len() != 12 {
            return Err(AkratError::InvalidVault);
        }
        let key_name = group_conversation_key(&stored_group.group_id);
        let group_key = conversation_keys
            .iter()
            .find(|key| key.conversation == key_name)
            .ok_or(AkratError::InvalidVault)?;
        let cipher = Aes256Gcm::new_from_slice(group_key.key.as_ref())
            .map_err(|_| AkratError::InvalidVault)?;
        let nonce =
            Nonce::try_from(stored_group.nonce.as_slice()).map_err(|_| AkratError::InvalidVault)?;
        let mut group_plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: stored_group.ciphertext.as_slice(),
                        aad: key_name.as_bytes(),
                    },
                )
                .map_err(|_| AkratError::Authentication)?,
        );
        let group: GroupState =
            serde_json::from_slice(&group_plaintext).map_err(|_| AkratError::InvalidVault)?;
        group_plaintext.zeroize();
        if group.group_id != stored_group.group_id {
            return Err(AkratError::InvalidVault);
        }
        groups.push(group);
    }
    let mut attachments = Vec::with_capacity(stored.attachments.len());
    for stored_attachment in stored.attachments {
        if stored_attachment.nonce.len() != 12 {
            return Err(AkratError::InvalidVault);
        }
        let conversation_key = conversation_keys
            .iter()
            .find(|key| key.conversation == stored_attachment.conversation)
            .ok_or(AkratError::InvalidVault)?;
        let cipher = Aes256Gcm::new_from_slice(conversation_key.key.as_ref())
            .map_err(|_| AkratError::InvalidVault)?;
        let nonce = Nonce::try_from(stored_attachment.nonce.as_slice())
            .map_err(|_| AkratError::InvalidVault)?;
        let mut attachment_plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: stored_attachment.ciphertext.as_slice(),
                        aad: stored_attachment.conversation.as_bytes(),
                    },
                )
                .map_err(|_| AkratError::Authentication)?,
        );
        let attachment: StoredAttachment =
            serde_json::from_slice(&attachment_plaintext).map_err(|_| AkratError::InvalidVault)?;
        attachment_plaintext.zeroize();
        if attachment.conversation != stored_attachment.conversation {
            return Err(AkratError::InvalidVault);
        }
        attachments.push(attachment);
    }
    let result = VaultData {
        revision,
        identities: stored.identities,
        contacts: stored.contacts,
        messages,
        groups,
        group_deliveries: stored.group_deliveries,
        attachments,
        conversation_keys,
        async_protocol_states: stored.async_protocol_states,
        mailbox_inboxes: stored.mailbox_inboxes,
        async_outbox: stored.async_outbox,
        pending_recipient_receipts: stored.pending_recipient_receipts,
        relay_settings: stored.relay_settings,
    };
    validate_vault(&result)?;
    if envelope.version != FORMAT_VERSION && migrate {
        let mut migrated = result;
        match save_vault(path, &mut migrated, passphrase) {
            Ok(()) => {}
            Err(AkratError::RevisionConflict { .. }) => {
                return load_vault_inner(path, passphrase, false);
            }
            Err(error) => return Err(error),
        }
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
    for attachment in &data.attachments {
        if !seen.contains(&attachment.conversation) {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut()).map_err(|_| AkratError::Random)?;
            data.conversation_keys.push(ConversationKey {
                conversation: attachment.conversation.clone(),
                key,
            });
            seen.insert(attachment.conversation.clone());
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
    for group in &data.groups {
        let conversation = group_conversation_key(&group.group_id);
        if !seen.contains(&conversation) {
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(key.as_mut()).map_err(|_| AkratError::Random)?;
            data.conversation_keys.push(ConversationKey {
                conversation: conversation.clone(),
                key,
            });
            seen.insert(conversation);
        }
    }
    Ok(())
}

fn group_conversation_key(group_id: &str) -> String {
    format!("group:{group_id}")
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
    let mut group_ids = std::collections::HashSet::new();
    for group in &data.groups {
        group.validate()?;
        if !group_ids.insert(group.group_id.as_str()) {
            return Err(AkratError::InvalidVault);
        }
        if group.members.is_empty()
            || group.members.len() > 256
            || group.members.iter().any(|member| {
                member.public_key.len() != 32
                    || member.fingerprint != fingerprint(&member.public_key)
                    || member.display_name.len() > 128
            })
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut group_delivery_ids = std::collections::HashSet::new();
    for delivery in &data.group_deliveries {
        if !group_ids.contains(delivery.group_id.as_str())
            || delivery.message_id.is_empty()
            || delivery.recipients.len() > 255
            || delivery
                .recipients
                .iter()
                .any(|recipient| recipient.fingerprint.is_empty())
            || !group_delivery_ids
                .insert((delivery.group_id.as_str(), delivery.message_id.as_str()))
            || !data.messages.iter().any(|message| {
                message.conversation == format!("group:{}", delivery.group_id)
                    && message.id == delivery.message_id
                    && message.outgoing
            })
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut attachment_ids = std::collections::HashSet::new();
    for attachment in &data.attachments {
        attachments::validate_manifest(&attachment.manifest)
            .map_err(|_| AkratError::InvalidVault)?;
        let mut frame_ids = std::collections::HashSet::new();
        if attachment.message_id != attachment.manifest.message_id
            || !attachment_ids.insert(attachment.manifest.attachment_id.as_str())
            || attachment.mailbox_frame_receipts.len() > attachment.manifest.chunk_count as usize
            || attachment.mailbox_frame_receipts.iter().any(|receipt| {
                receipt.frame_id.is_empty()
                    || receipt.frame_id.len() > 128
                    || receipt.ciphertext_sha256.len() != 64
                    || hex::decode(&receipt.ciphertext_sha256).is_err()
                    || !frame_ids.insert(receipt.frame_id.as_str())
            })
            || !data.messages.iter().any(|message| {
                message.conversation == attachment.conversation
                    && message.id == attachment.message_id
            })
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut contacts = std::collections::HashSet::new();
    for contact in &data.contacts {
        if contact.public_key.len() != 32
            || contact.fingerprint != fingerprint(&contact.public_key)
            || (!contact.transport_id.is_empty()
                && contact
                    .transport_id
                    .parse::<iroh_base::EndpointId>()
                    .is_err())
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
        let direct_message_exists = data.messages.iter().any(|message| {
            message.outgoing
                && message.conversation == item.conversation
                && message.id == item.message_id
        });
        let group_message_exists = item.conversation.split_once(':').is_some_and(
            |(identity_id, recipient_fingerprint)| {
                identities.contains(identity_id)
                    && data.group_deliveries.iter().any(|delivery| {
                        delivery.message_id == item.message_id
                            && delivery
                                .recipients
                                .iter()
                                .any(|recipient| recipient.fingerprint == recipient_fingerprint)
                            && data.messages.iter().any(|message| {
                                message.outgoing
                                    && message.conversation
                                        == format!("group:{}", delivery.group_id)
                                    && message.id == item.message_id
                            })
                    })
            },
        );
        let group_event_exists = item.group_event.as_ref().is_some_and(|reference| {
            identities.contains(
                item.conversation
                    .split_once(':')
                    .map_or("", |(identity_id, _)| identity_id),
            ) && data
                .groups
                .iter()
                .find(|group| group.group_id == reference.group_id)
                .and_then(|group| group.events.get(reference.sequence as usize))
                .and_then(|event| event.digest().ok())
                .as_deref()
                == Some(reference.event_sha256.as_str())
        });
        let attachment_parent_exists = item.parent_message_id.as_ref().is_some_and(|parent_id| {
            item.attachment_index.is_some()
                && item.message_id
                    == format!(
                        "{parent_id}{:08x}",
                        item.attachment_index.unwrap_or_default()
                    )
                && data
                    .messages
                    .iter()
                    .any(|message| message.outgoing && message.id == *parent_id)
                && item.attachment_id.as_ref().is_some_and(|attachment_id| {
                    data.attachments.iter().any(|attachment| {
                        attachment.message_id == *parent_id
                            && attachment.manifest.attachment_id == *attachment_id
                    })
                })
                && item
                    .envelope_sha256
                    .as_ref()
                    .is_some_and(|digest| digest.len() == 64 && hex::decode(digest).is_ok())
                && item
                    .conversation
                    .split_once(':')
                    .is_some_and(|(identity_id, fingerprint)| {
                        identities.contains(identity_id)
                            && data.contacts.iter().any(|contact| {
                                contact.fingerprint == fingerprint && contact.manually_verified
                            })
                    })
        });
        if (item.envelope.is_empty() && item.attachment_id.is_none())
            || item.envelope.len() > 256 * 1024
            || item.parent_message_id.is_some() != item.attachment_index.is_some()
            || item.attachment_id.is_some() != item.envelope_sha256.is_some()
            || !(direct_message_exists
                || group_message_exists
                || group_event_exists
                || attachment_parent_exists)
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
    write_atomically_with_fault(path, data, WriteFault::None)
}

#[cfg(test)]
fn write_atomically_with_interrupt(
    path: &Path,
    data: &[u8],
    interrupt_after_sync: bool,
) -> Result<(), AkratError> {
    write_atomically_with_fault(
        path,
        data,
        if interrupt_after_sync {
            WriteFault::AfterSync
        } else {
            WriteFault::None
        },
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WriteFault {
    None,
    BeforeWrite,
    DuringWrite,
    AfterSync,
    BeforeReplace,
    AfterReplace,
}

fn write_atomically_with_fault(
    path: &Path,
    data: &[u8],
    fault: WriteFault,
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
        if fault == WriteFault::BeforeWrite {
            return Err(std::io::Error::other("injected interruption before write"));
        }
        if fault == WriteFault::DuringWrite {
            file.write_all(&data[..data.len() / 2])?;
            return Err(std::io::Error::other("injected interruption during write"));
        }
        file.write_all(data)?;
        file.sync_all()?;
        if fault == WriteFault::AfterSync {
            drop(file);
            return Err(std::io::Error::other("injected process interruption"));
        }
        let mut verification = Vec::with_capacity(data.len());
        File::open(&temporary)?.read_to_end(&mut verification)?;
        if verification != data {
            return Err(std::io::Error::other("temporary file verification failed"));
        }
        drop(file);
        if fault == WriteFault::BeforeReplace {
            return Err(std::io::Error::other(
                "injected interruption before replace",
            ));
        }
        if path.exists() {
            write_recovery_copy(path, &fs::read(path)?)?;
        }
        replace_file(&temporary, path)?;
        if fault == WriteFault::AfterReplace {
            return Err(std::io::Error::other("injected interruption after replace"));
        }
        #[cfg(not(windows))]
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            File::open(parent)?.sync_all()?;
        }
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(AkratError::Io)
}

fn write_recovery_copy(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let backup = path.with_extension("akrat.bak");
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| std::io::Error::other("random source failed"))?;
    let temporary = backup.with_extension(format!("{}.tmp", hex::encode(random)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        let mut verification = Vec::with_capacity(data.len());
        File::open(&temporary)?.read_to_end(&mut verification)?;
        if verification != data {
            return Err(std::io::Error::other("recovery copy verification failed"));
        }
        drop(file);
        replace_file(&temporary, &backup)?;
        #[cfg(not(windows))]
        if let Some(parent) = backup
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn noise_params() -> Result<NoiseParams, AkratError> {
    NOISE_PROTOCOL.parse().map_err(|_| AkratError::Identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    #[cfg(feature = "p2p")]
    fn relay_settings_are_validated_and_survive_vault_reopen() {
        let mut settings = RelaySettings::default();
        assert_eq!(
            settings.relay_mode().expect("default relay mode"),
            iroh::RelayMode::Default
        );
        settings.use_default_relays = false;
        assert_eq!(
            settings.relay_mode().expect("disabled relay mode"),
            iroh::RelayMode::Disabled
        );
        settings.custom_relays = vec!["https://relay.example.org".into()];
        assert!(matches!(
            settings.relay_mode().expect("custom relay mode"),
            iroh::RelayMode::Custom(_)
        ));
        settings.minimum_trust = RelayTrustLevel::IdentityVerified;
        assert!(settings.relay_mode().is_err());
        let public_key = [7; 32];
        settings.identity_pins = vec![RelayIdentityPin {
            relay_url: "https://relay.example.org".into(),
            public_key_hex: hex::encode(public_key),
            fingerprint: akrat_trust::relay_identity_fingerprint(&public_key),
        }];
        assert!(settings.relay_mode().is_ok());
        settings.identity_pins[0].fingerprint = "00".repeat(32);
        assert!(settings.relay_mode().is_err());
        settings.identity_pins.clear();
        settings.minimum_trust = RelayTrustLevel::Unknown;
        settings.custom_relays.clear();
        settings.use_default_relays = true;
        settings.minimum_trust = RelayTrustLevel::IdentityVerified;
        assert_eq!(
            settings.relay_mode().expect("strict direct-only mode"),
            iroh::RelayMode::Disabled
        );
        settings.minimum_trust = RelayTrustLevel::Unknown;
        settings.custom_relays = vec!["not a relay URL".into()];
        assert!(settings.relay_mode().is_err());

        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut data = VaultData {
            relay_settings: RelaySettings {
                use_default_relays: false,
                custom_relays: vec!["https://relay.example.org".into()],
                ..RelaySettings::default()
            },
            ..VaultData::default()
        };
        save_vault(&path, &mut data, "relay settings test phrase").expect("save vault");
        let restored = load_vault(&path, "relay settings test phrase").expect("restore vault");
        assert_eq!(restored.relay_settings, data.relay_settings);
    }

    #[test]
    #[cfg(feature = "p2p")]
    fn relay_path_tiers_keep_direct_paths_ahead_of_favorites_and_allowed_relays() {
        let favorite_url = "https://favorite.example.org"
            .parse::<iroh::RelayUrl>()
            .unwrap();
        let allowed_url = "https://allowed.example.org"
            .parse::<iroh::RelayUrl>()
            .unwrap();
        let selector = RelayPathSelector {
            favorites: HashSet::from([favorite_url.clone()]),
        };
        let direct = iroh::endpoint::transports::FourTuple::Ip {
            remote: "127.0.0.1:4242".parse().unwrap(),
            local: None,
        };
        let favorite = iroh::endpoint::transports::FourTuple::Relay {
            url: favorite_url,
            endpoint_id: iroh::EndpointId::from_bytes(&[1; 32]).unwrap(),
        };
        let allowed = iroh::endpoint::transports::FourTuple::Relay {
            url: allowed_url,
            endpoint_id: iroh::EndpointId::from_bytes(&[1; 32]).unwrap(),
        };
        assert!(selector.tier(&direct) < selector.tier(&favorite));
        assert!(selector.tier(&favorite) < selector.tier(&allowed));
    }

    #[test]
    #[cfg(feature = "p2p")]
    fn locally_quarantined_relay_is_excluded_without_falling_back_to_unknown_relays() {
        let relay = "https://relay.example.org".to_string();
        let alternate = "https://alternate.example.org".to_string();
        let mut settings = RelaySettings {
            use_default_relays: true,
            custom_relays: vec![relay.clone(), alternate.clone()],
            ..RelaySettings::default()
        };
        assert!(matches!(
            settings.relay_mode(),
            Ok(iroh::RelayMode::Custom(_))
        ));
        settings
            .operational_records
            .push(akrat_trust::RelayOperationalRecord {
                relay_url: alternate,
                disposition: akrat_trust::RelayDisposition::Quarantined,
                ..akrat_trust::RelayOperationalRecord::default()
            });
        let iroh::RelayMode::Custom(eligible) = settings.relay_mode().expect("eligible relay")
        else {
            panic!("one custom relay remains eligible");
        };
        assert!(eligible.contains(&relay.parse().expect("first relay URL")));
        assert!(
            !eligible.contains(
                &"https://alternate.example.org"
                    .parse()
                    .expect("alternate relay URL")
            )
        );
        settings
            .operational_records
            .push(akrat_trust::RelayOperationalRecord {
                relay_url: relay,
                disposition: akrat_trust::RelayDisposition::Blocked,
                ..akrat_trust::RelayOperationalRecord::default()
            });
        assert_eq!(
            settings.relay_mode().expect("quarantined relay excluded"),
            iroh::RelayMode::Disabled
        );
    }

    #[test]
    fn signed_group_membership_uses_chain_epoch_and_member_authorization() {
        let alice = Identity::generate("Alice".into()).expect("Alice identity");
        let bob = Identity::generate("Bob".into()).expect("Bob identity");
        let creation = GroupEvent::signed(
            &alice,
            "group-1".into(),
            0,
            0,
            None,
            GroupChange::Create {
                name: "Expédition".into(),
                creator_name: "Alice".into(),
            },
        )
        .expect("signed creation");
        let mut state = GroupState::from_creation(&creation).expect("create state");
        let bob_member = GroupMember {
            fingerprint: bob.fingerprint(),
            public_key: bob.public_key().to_vec(),
            display_name: "Bob".into(),
            role: GroupRole::Member,
            accepted: false,
        };
        let invite = GroupEvent::signed(
            &alice,
            "group-1".into(),
            1,
            0,
            Some(state.last_event_sha256.clone()),
            GroupChange::Invite { member: bob_member },
        )
        .expect("signed invitation");
        state.apply(&invite).expect("apply invitation");
        let acceptance = GroupEvent::signed(
            &bob,
            "group-1".into(),
            2,
            1,
            Some(state.last_event_sha256.clone()),
            GroupChange::Accept,
        )
        .expect("signed acceptance");
        state.apply(&acceptance).expect("apply acceptance");
        assert_eq!(state.epoch, 1);
        assert!(
            state
                .members
                .iter()
                .find(|member| member.fingerprint == bob.fingerprint())
                .unwrap()
                .accepted
        );
        state.validate().expect("replay signed chain");
        let forbidden = GroupEvent::signed(
            &bob,
            "group-1".into(),
            3,
            1,
            Some(state.last_event_sha256.clone()),
            GroupChange::Rename {
                name: "Falsification".into(),
            },
        )
        .expect("signed member event");
        assert!(matches!(
            state.apply(&forbidden),
            Err(AkratError::InvalidVault)
        ));
        let removal = GroupEvent::signed(
            &alice,
            "group-1".into(),
            3,
            2,
            Some(state.last_event_sha256.clone()),
            GroupChange::Remove {
                fingerprint: bob.fingerprint(),
            },
        )
        .expect("signed removal");
        state.apply(&removal).expect("apply removal");
        assert_eq!(state.epoch, 2);
        assert!(
            !state
                .members
                .iter()
                .any(|member| member.fingerprint == bob.fingerprint())
        );
        state.validate().expect("replay after removal");
        let historical = GroupMessage {
            version: 1,
            group_id: state.group_id.clone(),
            epoch: 1,
            sequence: 2,
            message_id: "historical-bob-message".into(),
            sender_public_key: bob.public_key().to_vec(),
            timestamp: 1,
            text: "sent before removal".into(),
            has_attachment: false,
        };
        assert!(historical.validate_for(&state, bob.public_key()));
        let after_removal = GroupMessage {
            sequence: 3,
            epoch: 2,
            message_id: "post-removal-bob-message".into(),
            ..historical
        };
        assert!(!after_removal.validate_for(&state, bob.public_key()));
    }

    #[test]
    fn group_state_is_persisted_with_its_own_local_storage_key() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let alice = Identity::generate("Alice".into()).expect("Alice identity");
        let creation = GroupEvent::signed(
            &alice,
            "group-persist".into(),
            0,
            0,
            None,
            GroupChange::Create {
                name: "Expédition".into(),
                creator_name: "Alice".into(),
            },
        )
        .expect("creation event");
        let group = GroupState::from_creation(&creation).expect("group state");
        let mut data = VaultData {
            revision: 0,
            identities: vec![alice],
            groups: vec![group],
            ..VaultData::default()
        };
        save_vault(&path, &mut data, "local group passphrase").expect("save");
        assert!(
            data.conversation_keys
                .iter()
                .any(|key| key.conversation == "group:group-persist")
        );
        let loaded = load_vault(&path, "local group passphrase").expect("load");
        assert_eq!(loaded.groups, data.groups);
        assert_eq!(loaded.groups[0].events.len(), 1);
    }

    #[test]
    fn v0_1_10_vault_storage_schema_migrates_without_losing_revision_or_messages() {
        #[derive(Serialize)]
        struct VaultStorageV10 {
            revision: u64,
            identities: Vec<Identity>,
            contacts: Vec<Contact>,
            conversation_keys: Vec<StoredConversationKey>,
            messages: Vec<StoredMessageCiphertext>,
            async_protocol_states: Vec<AsyncProtocolState>,
            mailbox_inboxes: Vec<MailboxInbox>,
            async_outbox: Vec<AsyncOutboxItem>,
            pending_recipient_receipts: Vec<PendingRecipientReceipt>,
        }

        let encoded = serde_json::to_vec(&VaultStorageV10 {
            revision: 9,
            identities: Vec::new(),
            contacts: Vec::new(),
            conversation_keys: Vec::new(),
            messages: Vec::new(),
            async_protocol_states: Vec::new(),
            mailbox_inboxes: Vec::new(),
            async_outbox: Vec::new(),
            pending_recipient_receipts: Vec::new(),
        })
        .expect("encode v0.1.10 storage schema");
        let migrated: VaultStorageV4 =
            serde_json::from_slice(&encoded).expect("decode v0.1.10 storage schema");
        assert_eq!(migrated.revision, 9);
        assert!(migrated.groups.is_empty());
        assert!(migrated.group_deliveries.is_empty());
        assert!(migrated.attachments.is_empty());
    }

    #[cfg(feature = "media-image")]
    #[test]
    fn attachment_manifest_and_content_key_are_encrypted_by_its_conversation_key() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut image = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(image::ImageBuffer::from_pixel(
            8,
            8,
            image::Rgba([1, 2, 3, 255]),
        ))
        .write_to(&mut image, image::ImageFormat::Png)
        .expect("encode sample image");
        let (manifest, _) = attachments::encrypt_image(
            &image.into_inner(),
            "00112233445566778899aabbccddeeff".into(),
            "image-message".into(),
            "dm:alice:bob".into(),
            "private-photo.png",
        )
        .expect("encrypted image");
        let mut data = VaultData {
            revision: 0,
            messages: vec![StoredMessage {
                conversation: "dm:alice:bob".into(),
                id: "image-message".into(),
                outgoing: true,
                text: "caption".into(),
                delivery: DeliveryState::Queued,
                timestamp: 1,
                delivery_events: Vec::new(),
                received_ciphertext_sha256: None,
            }],
            attachments: vec![StoredAttachment {
                conversation: "dm:alice:bob".into(),
                message_id: "image-message".into(),
                manifest: manifest.clone(),
                mailbox_frame_receipts: Vec::new(),
            }],
            ..VaultData::default()
        };
        save_vault(&path, &mut data, "attachment vault phrase").expect("save vault");
        let encoded = fs::read(&path).expect("read encrypted vault");
        let encoded_text = String::from_utf8_lossy(&encoded);
        assert!(!encoded_text.contains("private-photo.png"));
        assert!(!encoded_text.contains(&manifest.attachment_id));
        assert!(!encoded_text.contains(&hex::encode(&manifest.content_key)));
        let loaded = load_vault(&path, "attachment vault phrase").expect("load vault");
        assert_eq!(loaded.attachments.len(), 1);
        assert_eq!(loaded.attachments[0].manifest, manifest);
        assert!(
            loaded
                .conversation_keys
                .iter()
                .any(|key| key.conversation == "dm:alice:bob")
        );
    }

    #[test]
    fn encrypted_vault_round_trips_identity_contact_and_history() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let identity = Identity::generate("Alice".to_string()).expect("identity");
        let bob = Identity::generate("Bob".to_string()).expect("Bob");
        let mut data = VaultData {
            revision: 0,
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
            groups: Vec::new(),
            group_deliveries: Vec::new(),
            attachments: Vec::new(),
            conversation_keys: Vec::new(),
            async_protocol_states: Vec::new(),
            mailbox_inboxes: Vec::new(),
            async_outbox: Vec::new(),
            pending_recipient_receipts: Vec::new(),
            relay_settings: RelaySettings::default(),
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
            revision: 0,
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
            FORMAT_VERSION
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
            revision: 0,
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
        let stored: VaultStorageV4 = serde_json::from_slice(&inner).expect("stored vault");
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
    fn version_two_vault_migrates_to_version_four_without_losing_identity() {
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
        assert_eq!(rewritten.version, FORMAT_VERSION);
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
    fn stale_vault_write_is_rejected_and_transaction_retry_preserves_both_updates() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut initial = VaultData::default();
        save_vault(&path, &mut initial, "transaction phrase").expect("initial save");
        let mut first = load_vault(&path, "transaction phrase").expect("first snapshot");
        let mut stale = load_vault(&path, "transaction phrase").expect("stale snapshot");
        first
            .identities
            .push(Identity::generate("First".into()).expect("first identity"));
        stale
            .identities
            .push(Identity::generate("Stale".into()).expect("stale identity"));
        save_vault(&path, &mut first, "transaction phrase").expect("first commit");
        assert!(matches!(
            save_vault(&path, &mut stale, "transaction phrase"),
            Err(AkratError::RevisionConflict {
                expected: 1,
                actual: 2
            })
        ));
        mutate_vault(&path, "transaction phrase", |data| {
            data.identities.extend(stale.identities);
            Ok(())
        })
        .expect("retry against current revision");
        let loaded = load_vault(&path, "transaction phrase").expect("reopen");
        assert_eq!(loaded.identities.len(), 2);
        assert_eq!(loaded.revision, 3);
    }

    #[test]
    fn one_hundred_concurrent_vault_transactions_preserve_every_message() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = std::sync::Arc::new(directory.path().join("vault.akrat"));
        let mut initial = VaultData::default();
        initial.conversation_keys.push(ConversationKey {
            conversation: "concurrent-conversation".into(),
            key: Zeroizing::new([7; 32]),
        });
        save_vault(&path, &mut initial, "concurrent phrase").expect("initial save");
        let workers = (0..100)
            .map(|index| {
                let path = path.clone();
                std::thread::spawn(move || {
                    mutate_vault(&path, "concurrent phrase", |data| {
                        data.messages.push(StoredMessage {
                            conversation: "concurrent-conversation".into(),
                            id: format!("message-{index}"),
                            outgoing: true,
                            text: format!("message body {index}"),
                            delivery: DeliveryState::Queued,
                            timestamp: index,
                            delivery_events: Vec::new(),
                            received_ciphertext_sha256: None,
                        });
                        Ok(())
                    })
                    .expect("transaction");
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("worker");
        }
        let loaded = load_vault(&path, "concurrent phrase").expect("reload");
        assert_eq!(loaded.messages.len(), 100);
        assert_eq!(
            loaded
                .messages
                .iter()
                .map(|message| message.id.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            100
        );
    }

    #[test]
    fn concurrent_process_child() {
        let Ok(path) = std::env::var("AKRAT_PROCESS_VAULT") else {
            return;
        };
        let coordination = std::path::PathBuf::from(
            std::env::var("AKRAT_PROCESS_COORDINATION").expect("coordination directory"),
        );
        let name = std::env::var("AKRAT_PROCESS_IDENTITY").expect("identity name");
        std::fs::write(coordination.join(format!("ready-{name}")), b"ready")
            .expect("write readiness marker");
        for _ in 0..1000 {
            if coordination.join("start").exists() {
                mutate_vault(std::path::Path::new(&path), "process phrase", |data| {
                    data.identities
                        .push(Identity::generate(name.clone()).map_err(|_| AkratError::Identity)?);
                    Ok(())
                })
                .expect("cross-process transaction");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("parent did not release the child process");
    }

    #[test]
    fn simultaneous_processes_serialize_updates_for_one_vault() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut initial = VaultData::default();
        save_vault(&path, &mut initial, "process phrase").expect("initial save");
        let executable = std::env::current_exe().expect("test executable");
        let mut children = ["Process Alice", "Process Bob"]
            .into_iter()
            .map(|name| {
                std::process::Command::new(&executable)
                    .arg("--exact")
                    .arg("tests::concurrent_process_child")
                    .arg("--nocapture")
                    .env("AKRAT_PROCESS_VAULT", &path)
                    .env("AKRAT_PROCESS_COORDINATION", directory.path())
                    .env("AKRAT_PROCESS_IDENTITY", name)
                    .spawn()
                    .expect("spawn child process")
            })
            .collect::<Vec<_>>();
        for name in ["Process Alice", "Process Bob"] {
            let marker = directory.path().join(format!("ready-{name}"));
            for _ in 0..1000 {
                if marker.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(marker.exists(), "child process did not become ready");
        }
        std::fs::write(directory.path().join("start"), b"go").expect("release children");
        for child in &mut children {
            assert!(child.wait().expect("wait child").success());
        }
        let loaded = load_vault(&path, "process phrase").expect("reload after children");
        assert_eq!(loaded.identities.len(), 2);
        assert_eq!(loaded.revision, 3);
    }

    #[test]
    fn atomic_vault_replacement_preserves_old_or_new_data_and_keeps_a_recovery_copy() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("state.bin");
        let original = b"previous complete state";
        let replacement = b"next complete state";
        fs::write(&path, original).expect("write original");
        for fault in [
            WriteFault::BeforeWrite,
            WriteFault::DuringWrite,
            WriteFault::AfterSync,
            WriteFault::BeforeReplace,
        ] {
            assert!(write_atomically_with_fault(&path, replacement, fault).is_err());
            assert_eq!(fs::read(&path).expect("read after interruption"), original);
        }
        assert!(write_atomically_with_fault(&path, replacement, WriteFault::AfterReplace).is_err());
        assert_eq!(fs::read(&path).expect("read replaced file"), replacement);
        assert_eq!(
            fs::read(path.with_extension("akrat.bak")).expect("read recovery copy"),
            original
        );
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
