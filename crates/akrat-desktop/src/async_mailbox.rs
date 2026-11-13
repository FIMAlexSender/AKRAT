use akrat_core::attachments::{self, AttachmentChunk, AttachmentManifest};
use akrat_core::{
    AsyncOutboxItem, AsyncProtocolState, DeliveryActor, DeliveryEvent, DeliveryEventKind,
    DeliveryState, GroupChange, GroupEvent, GroupEventOutboxRef, GroupMessage,
    GroupRecipientStatus, GroupState, Identity, MailboxAttachmentFrameReceipt, MailboxInbox,
    MailboxRoute, PendingRecipientReceipt, StoredMessage, VaultData, async_crypto, load_vault,
    save_vault,
};
use akrat_mailbox::server::{self, Request, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub enum DeliveryPoll {
    Pending,
    Delivered,
    Expired,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AsyncEnvelope {
    version: u8,
    sender_public_key: Vec<u8>,
    ciphertext: WireAsyncCiphertext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAsyncCiphertext {
    version: u8,
    prekey: bool,
    #[serde(deserialize_with = "base64_or_array::deserialize")]
    bytes: Vec<u8>,
}

impl From<WireAsyncCiphertext> for async_crypto::AsyncCiphertext {
    fn from(wire: WireAsyncCiphertext) -> Self {
        Self {
            version: wire.version,
            prekey: wire.prekey,
            bytes: wire.bytes,
        }
    }
}

#[derive(Serialize)]
struct LegacyAsyncEnvelope<'a> {
    version: u8,
    sender_public_key: &'a [u8],
    ciphertext: &'a async_crypto::AsyncCiphertext,
}

#[derive(Serialize)]
struct CompactAsyncEnvelope {
    version: u8,
    sender_public_key: Vec<u8>,
    ciphertext: CompactAsyncCiphertext,
}

#[derive(Serialize)]
struct CompactAsyncCiphertext {
    version: u8,
    prekey: bool,
    #[serde(serialize_with = "base64_or_array::serialize")]
    bytes: Vec<u8>,
}

mod base64_or_array {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::{SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ByteVisitor;

        impl<'de> Visitor<'de> for ByteVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("base64 ciphertext or legacy byte array")
            }

            fn visit_str<E>(self, value: &str) -> Result<Vec<u8>, E>
            where
                E: serde::de::Error,
            {
                STANDARD.decode(value).map_err(E::custom)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Vec<u8>, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = sequence.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_any(ByteVisitor)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AsyncPlaintext {
    version: u8,
    message_id: String,
    sender_public_key: Vec<u8>,
    recipient_public_key: Vec<u8>,
    text: String,
    #[serde(default)]
    group_event: Option<GroupEvent>,
    #[serde(default)]
    group_message: Option<GroupMessage>,
    #[serde(default)]
    attachment: Option<MailboxAttachment>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MailboxAttachment {
    parent_message_id: String,
    manifest: AttachmentManifest,
    chunk: AttachmentChunk,
}

#[derive(Default)]
struct SendApplicationOptions {
    group_event: Option<GroupEvent>,
    group_message: Option<GroupMessage>,
    attachment: Option<MailboxAttachment>,
    preverified_bundle: Option<akrat_core::async_crypto::PublishedBundle>,
}

pub async fn send(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message_id: String,
) -> Result<(), String> {
    let data = load_vault(&path, &passphrase).map_err(|e| e.to_string())?;
    let attachment = data
        .attachments
        .iter()
        .find(|attachment| {
            attachment.message_id == message_id && attachment.conversation == conversation
        })
        .cloned();
    send_application(
        path.clone(),
        passphrase.clone(),
        conversation.clone(),
        message_id.clone(),
        SendApplicationOptions::default(),
    )
    .await?;
    if let Some(attachment) = attachment {
        let sidecar = attachments::attachment_sidecar_path(&path);
        let chunks = attachments::load_encrypted_chunks(&sidecar, &attachment.manifest)
            .map_err(|e| format!("image différée indisponible: {e}"))?;
        send_attachment_frames(
            path,
            passphrase,
            conversation,
            message_id,
            attachment.manifest,
            chunks,
        )
        .await?;
    }
    Ok(())
}

pub async fn send_attachment_frames(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    parent_message_id: String,
    manifest: AttachmentManifest,
    chunks: Vec<AttachmentChunk>,
) -> Result<(), String> {
    attachments::validate_manifest(&manifest).map_err(|error| error.to_string())?;
    if manifest.message_id != parent_message_id
        || (manifest.conversation_id != conversation
            && !manifest.conversation_id.starts_with("group:"))
        || chunks.len() != manifest.chunk_count as usize
        || parent_message_id.len() > 110
    {
        return Err("attachment does not match its message or conversation".into());
    }
    let data = load_vault(&path, &passphrase).map_err(|error| error.to_string())?;
    let needs_bundle = chunks.iter().any(|chunk| {
        let frame_id = format!("{parent_message_id}{:08x}", chunk.index);
        !data
            .async_outbox
            .iter()
            .any(|item| item.conversation == conversation && item.message_id == frame_id)
    });
    let bundle = if needs_bundle {
        Some(fetch_verified_bundle(&path, &passphrase, &conversation).await?)
    } else {
        None
    };
    for chunk in chunks {
        let frame_id = format!("{parent_message_id}{:08x}", chunk.index);
        let frame = MailboxAttachment {
            parent_message_id: parent_message_id.clone(),
            manifest: manifest.clone(),
            chunk,
        };
        send_application(
            path.clone(),
            passphrase.clone(),
            conversation.clone(),
            frame_id,
            SendApplicationOptions {
                attachment: Some(frame),
                preverified_bundle: bundle.clone(),
                ..SendApplicationOptions::default()
            },
        )
        .await?;
    }
    Ok(())
}

pub async fn send_group_event(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message_id: String,
    event: GroupEvent,
) -> Result<(), String> {
    send_application(
        path,
        passphrase,
        conversation,
        message_id,
        SendApplicationOptions {
            group_event: Some(event),
            ..SendApplicationOptions::default()
        },
    )
    .await
}

pub async fn send_group_message(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message: GroupMessage,
) -> Result<(), String> {
    send_application(
        path,
        passphrase,
        conversation,
        message.message_id.clone(),
        SendApplicationOptions {
            group_message: Some(message),
            ..SendApplicationOptions::default()
        },
    )
    .await
}

async fn send_application(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message_id: String,
    options: SendApplicationOptions,
) -> Result<(), String> {
    let SendApplicationOptions {
        group_event,
        group_message,
        attachment,
        preverified_bundle,
    } = options;
    let mut data = load_vault(&path, &passphrase).map_err(|e| e.to_string())?;
    let (identity_id, fingerprint) = conversation
        .split_once(':')
        .ok_or("conversation id invalid")?;
    let identity = data
        .identities
        .iter()
        .find(|i| i.id == identity_id)
        .ok_or("identity not found")?
        .detached_copy();
    let contact = data
        .contacts
        .iter()
        .find(|c| c.fingerprint == fingerprint && c.manually_verified)
        .ok_or("verified contact not found")?
        .clone();
    let route = contact
        .mailbox_route
        .clone()
        .ok_or("no asynchronous mailbox configured for this contact")?;
    let mut routes = vec![route];
    routes.extend(contact.mailbox_replicas.iter().cloned());
    let tracked_message_id = attachment.as_ref().map_or_else(
        || message_id.clone(),
        |frame| frame.parent_message_id.clone(),
    );
    let message_text = if group_message.is_some() || group_event.is_some() || attachment.is_some() {
        String::new()
    } else {
        data.messages
            .iter()
            .find(|m| m.conversation == conversation && m.id == message_id && m.outgoing)
            .ok_or("outgoing message not found")?
            .text
            .clone()
    };
    let envelope = if let Some(item) = data
        .async_outbox
        .iter()
        .find(|item| item.conversation == conversation && item.message_id == message_id)
    {
        if !item.envelope.is_empty() {
            item.envelope.clone()
        } else if let Some(attachment_id) = item.attachment_id.as_deref() {
            let envelope = attachments::load_mailbox_envelope(
                &attachments::attachment_sidecar_path(&path),
                attachment_id,
                &conversation,
                &message_id,
            )
            .map_err(|error| format!("saved attachment frame is unavailable: {error}"))?;
            if item.envelope_sha256.as_deref()
                != Some(hex::encode(Sha256::digest(&envelope)).as_str())
            {
                return Err("saved attachment frame failed its local digest check".into());
            }
            envelope
        } else {
            return Err("saved asynchronous ciphertext is missing".into());
        }
    } else {
        let bundle = if let Some(bundle) = preverified_bundle {
            bundle
        } else {
            let mut verified_bundle = None;
            for route in &routes {
                if let Ok(bundle) = fetch_bundle(&identity, route).await
                    && async_crypto::verify_bundle(&bundle, &contact.public_key).is_ok()
                {
                    verified_bundle = Some(bundle);
                    break;
                }
            }
            verified_bundle.ok_or("aucune Mailbox configurée ne fournit un bundle valide")?
        };
        let state = data
            .async_protocol_states
            .iter()
            .find(|state| state.identity_id == identity.id)
            .map(|state| state.state.as_slice())
            .unwrap_or_default();
        let associated_plaintext = serde_json::to_vec(&AsyncPlaintext {
            version: 1,
            message_id: message_id.clone(),
            sender_public_key: identity.public_key().to_vec(),
            recipient_public_key: contact.public_key.clone(),
            text: message_text,
            group_event: group_event.clone(),
            group_message: group_message.clone(),
            attachment: attachment.clone(),
        })
        .map_err(|e| e.to_string())?;
        let (ciphertext, next_state) = async_crypto::encrypt(
            &identity,
            state,
            &contact.public_key,
            &bundle,
            &associated_plaintext,
        )
        .await
        .map_err(|e| e.to_string())?;
        let envelope = if attachment.is_some() {
            serde_json::to_vec(&CompactAsyncEnvelope {
                version: 2,
                sender_public_key: identity.public_key().to_vec(),
                ciphertext: CompactAsyncCiphertext {
                    version: ciphertext.version,
                    prekey: ciphertext.prekey,
                    bytes: ciphertext.bytes,
                },
            })
        } else {
            serde_json::to_vec(&LegacyAsyncEnvelope {
                version: 1,
                sender_public_key: identity.public_key(),
                ciphertext: &ciphertext,
            })
        }
        .map_err(|e| e.to_string())?;
        if let Some(frame) = attachment.as_ref() {
            attachments::store_mailbox_envelope(
                &attachments::attachment_sidecar_path(&path),
                &frame.manifest.attachment_id,
                &conversation,
                &message_id,
                &envelope,
            )
            .map_err(|error| format!("unable to persist encrypted mailbox frame: {error}"))?;
        }
        if attachment.is_none()
            && let Some(message) = data.messages.iter_mut().find(|message| {
                message.conversation == conversation
                    && message.id == tracked_message_id
                    && message.outgoing
            })
        {
            message.record_delivery_event(DeliveryEvent {
                timestamp: now(),
                kind: DeliveryEventKind::Encrypted,
                actor: DeliveryActor::SenderClient,
                actor_fingerprint: None,
                actor_name: None,
                receipt_sha256: None,
                receipt_bytes: None,
                verified: true,
            });
        }
        upsert_state(&mut data, &identity.id, next_state);
        data.async_outbox.push(AsyncOutboxItem {
            conversation: conversation.clone(),
            message_id: message_id.clone(),
            envelope: if attachment.is_some() {
                Vec::new()
            } else {
                envelope.clone()
            },
            parent_message_id: attachment
                .as_ref()
                .map(|frame| frame.parent_message_id.clone()),
            attachment_index: attachment.as_ref().map(|frame| frame.chunk.index),
            attachment_id: attachment
                .as_ref()
                .map(|frame| frame.manifest.attachment_id.clone()),
            envelope_sha256: attachment
                .as_ref()
                .map(|_| hex::encode(Sha256::digest(&envelope))),
            group_event: group_event.as_ref().map(|event| GroupEventOutboxRef {
                group_id: event.group_id.clone(),
                sequence: event.sequence,
                event_sha256: event.digest().unwrap_or_default(),
            }),
        });
        save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
        envelope
    };
    let mut stored = 0usize;
    let mut failures = Vec::new();
    for route in &routes {
        let result = async {
            let (mut channel, server_identity, generation, revocation_sequence) = connect(
                &identity,
                &route.endpoint,
                &route.server_noise_public_key,
                &route.server_signing_public_key,
                route.server_key_generation,
                route.server_revocation_sequence,
            )
            .await?;
            if generation > route.server_key_generation
                || revocation_sequence > route.server_revocation_sequence
            {
                update_contact_route_generation(&mut data, route, generation, revocation_sequence);
                save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
            }
            let response = server::request(
                &mut channel,
                &Request::Deposit {
                    mailbox_id: route.mailbox_id.clone(),
                    write_capability: route.write_capability.clone(),
                    message_id: message_id.clone(),
                    ciphertext: STANDARD.encode(&envelope),
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            let Response::Deposit { receipt } = response else {
                return Err(format!("mailbox refused deposit: {response:?}"));
            };
            let valid = verify_deposit_receipt(&receipt, &server_identity)?;
            if !valid
                || receipt.mailbox_id != route.mailbox_id
                || receipt.message_id != message_id
                || receipt.ciphertext_sha256 != hex::encode(Sha256::digest(&envelope))
            {
                return Err("mailbox receipt did not authenticate the deposited ciphertext".into());
            }
            Ok::<_, String>(receipt)
        }
        .await;
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(error) => {
                failures.push(format!("{}: {error}", route.endpoint));
                continue;
            }
        };
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
        let receipt_digest = hex::encode(Sha256::digest(&receipt_bytes));
        if attachment.is_none()
            && let Some(message) = data.messages.iter_mut().find(|message| {
                message.conversation == conversation
                    && message.id == tracked_message_id
                    && message.outgoing
            })
        {
            message.delivery = DeliveryState::MailboxStored;
            if !message.delivery_events.iter().any(|event| {
                event.kind == DeliveryEventKind::Deposited
                    && event.receipt_sha256.as_deref() == Some(receipt_digest.as_str())
            }) {
                message.record_delivery_event(DeliveryEvent {
                    timestamp: receipt.accepted_at,
                    kind: DeliveryEventKind::Deposited,
                    actor: DeliveryActor::Mailbox,
                    actor_fingerprint: Some(receipt.server_fingerprint.clone()),
                    actor_name: Some(format!("Mailbox {}", receipt.mailbox_id)),
                    receipt_sha256: Some(receipt_digest),
                    receipt_bytes: Some(receipt_bytes),
                    verified: true,
                });
            }
        }
        stored += 1;
    }
    if stored == 0 {
        return Err(format!(
            "dépôt impossible sur les Mailbox autorisées : {}",
            failures.join("; ")
        ));
    }
    if let Some(group_message) = group_message {
        if let Some(delivery) = data.group_deliveries.iter_mut().find(|delivery| {
            delivery.group_id == group_message.group_id
                && delivery.message_id == group_message.message_id
        }) && let Some(recipient) = delivery
            .recipients
            .iter_mut()
            .find(|recipient| recipient.fingerprint == contact.fingerprint)
            && recipient.status != GroupRecipientStatus::Received
        {
            recipient.status = GroupRecipientStatus::Deposited;
            recipient.updated_at = now();
        }
        if let Some(message) = data.messages.iter_mut().find(|message| {
            message.conversation == format!("group:{}", group_message.group_id)
                && message.id == group_message.message_id
                && message.outgoing
                && message.delivery != DeliveryState::Acknowledged
        }) {
            message.delivery = DeliveryState::MailboxStored;
        }
    }
    if attachment.is_some() {
        for delivery in data
            .group_deliveries
            .iter_mut()
            .filter(|delivery| delivery.message_id == tracked_message_id)
        {
            if let Some(recipient) = delivery
                .recipients
                .iter_mut()
                .find(|recipient| recipient.fingerprint == contact.fingerprint)
                && recipient.status == GroupRecipientStatus::Pending
            {
                recipient.status = GroupRecipientStatus::Deposited;
                recipient.updated_at = now();
            }
        }
        if let Some(message) = data.messages.iter_mut().find(|message| {
            message.id == tracked_message_id
                && message.outgoing
                && message.conversation.starts_with("group:")
                && message.delivery != DeliveryState::Acknowledged
        }) {
            message.delivery = DeliveryState::MailboxStored;
        }
    }
    save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn poll_inbox(
    path: PathBuf,
    passphrase: String,
    inbox: MailboxInbox,
) -> Result<usize, String> {
    let mut data = load_vault(&path, &passphrase).map_err(|e| e.to_string())?;
    let mut inbox = data
        .mailbox_inboxes
        .iter()
        .find(|saved| {
            saved.identity_id == inbox.identity_id
                && saved.endpoint == inbox.endpoint
                && saved.mailbox_id == inbox.mailbox_id
        })
        .cloned()
        .unwrap_or(inbox);
    let identity = data
        .identities
        .iter()
        .find(|i| i.id == inbox.identity_id)
        .ok_or("inbox identity not found")?
        .detached_copy();
    let (mut channel, _, generation, revocation_sequence) = connect(
        &identity,
        &inbox.endpoint,
        &inbox.server_noise_public_key,
        &inbox.server_signing_public_key,
        inbox.server_key_generation,
        inbox.server_revocation_sequence,
    )
    .await?;
    if generation > inbox.server_key_generation
        || revocation_sequence > inbox.server_revocation_sequence
    {
        inbox.server_key_generation = generation;
        inbox.server_revocation_sequence = revocation_sequence;
        if let Some(saved) = data.mailbox_inboxes.iter_mut().find(|saved| {
            saved.identity_id == inbox.identity_id
                && saved.endpoint == inbox.endpoint
                && saved.mailbox_id == inbox.mailbox_id
        }) {
            saved.server_key_generation = generation;
            saved.server_revocation_sequence = revocation_sequence;
        }
        save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
    }
    let state = data
        .async_protocol_states
        .iter()
        .find(|state| state.identity_id == identity.id)
        .map(|state| state.state.as_slice())
        .unwrap_or_default();
    let (bundle, next_state) = async_crypto::publish_bundle(&identity, state)
        .await
        .map_err(|e| e.to_string())?;
    if state != next_state.as_slice() {
        upsert_state(&mut data, &identity.id, next_state);
        save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
    }
    match server::request(
        &mut channel,
        &Request::PublishBundle {
            mailbox_id: inbox.mailbox_id.clone(),
            write_capability: inbox.write_capability.clone(),
            bundle,
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        Response::BundlePublished => {}
        other => return Err(format!("pre-key publication failed: {other:?}")),
    }
    let mut received = 0usize;
    loop {
        let acknowledgements = send_pending_recipient_receipts(
            &path,
            &passphrase,
            &mut data,
            &identity,
            &inbox,
            &mut channel,
        )
        .await?;
        let response = server::request(
            &mut channel,
            &Request::Fetch {
                mailbox_id: inbox.mailbox_id.clone(),
                read_capability: inbox.read_capability.clone(),
                limit: 64,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        let envelopes = match response {
            Response::Fetch { envelopes } => envelopes,
            Response::Error { code } if code == "rate_limited" => break,
            other => return Err(format!("mailbox fetch failed: {other:?}")),
        };
        if envelopes.is_empty() {
            break;
        }
        let received_before_batch = received;
        for item in envelopes {
            if item.expires_at <= now() {
                continue;
            }
            let Ok(bytes) = STANDARD.decode(item.ciphertext) else {
                continue;
            };
            let Ok(envelope) = serde_json::from_slice::<AsyncEnvelope>(&bytes) else {
                continue;
            };
            if !matches!(envelope.version, 1 | 2) {
                continue;
            }
            if envelope.version == 1 && envelope.ciphertext.bytes.len() > 64 * 1024 {
                continue;
            }
            if envelope.version == 1 && envelope.ciphertext.version > 1 {
                continue;
            }
            let Some(contact) = data
                .contacts
                .iter()
                .find(|contact| {
                    contact.manually_verified && contact.public_key == envelope.sender_public_key
                })
                .cloned()
            else {
                continue;
            };
            let conversation = format!("{}:{}", identity.id, contact.fingerprint);
            let ciphertext_digest = hex::encode(Sha256::digest(&bytes));
            if data.attachments.iter().any(|attachment| {
                attachment.mailbox_frame_receipts.iter().any(|receipt| {
                    receipt.frame_id == item.message_id
                        && receipt.ciphertext_sha256 == ciphertext_digest
                })
            }) {
                if !data.pending_recipient_receipts.iter().any(|pending| {
                    pending.mailbox_id == inbox.mailbox_id
                        && pending.receipt.message_id == item.message_id
                }) && let Ok(receipt) = async_crypto::RecipientReceipt::create(
                    &identity,
                    &contact.public_key,
                    inbox.mailbox_id.clone(),
                    item.message_id.clone(),
                    ciphertext_digest,
                    now(),
                ) {
                    data.pending_recipient_receipts
                        .push(PendingRecipientReceipt {
                            mailbox_id: inbox.mailbox_id.clone(),
                            read_capability: inbox.read_capability.clone(),
                            receipt,
                        });
                    save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
                }
                continue;
            }
            if let Some(existing) = data.messages.iter().find(|message| {
                message.id == item.message_id
                    && !message.outgoing
                    && message.received_ciphertext_sha256.as_deref()
                        == Some(ciphertext_digest.as_str())
            }) {
                if !existing.delivery_events.iter().any(|event| {
                    event.kind == DeliveryEventKind::RecipientConfirmed
                        && event.actor_name.as_deref()
                            == Some(format!("{} · {}", identity.name, inbox.mailbox_id).as_str())
                }) && !data.pending_recipient_receipts.iter().any(|pending| {
                    pending.mailbox_id == inbox.mailbox_id
                        && pending.receipt.message_id == item.message_id
                }) {
                    let receipt = match async_crypto::RecipientReceipt::create(
                        &identity,
                        &contact.public_key,
                        inbox.mailbox_id.clone(),
                        item.message_id.clone(),
                        ciphertext_digest,
                        now(),
                    ) {
                        Ok(receipt) => receipt,
                        Err(_) => continue,
                    };
                    data.pending_recipient_receipts
                        .push(PendingRecipientReceipt {
                            mailbox_id: inbox.mailbox_id.clone(),
                            read_capability: inbox.read_capability.clone(),
                            receipt,
                        });
                    save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
                }
                continue;
            }
            let state = data
                .async_protocol_states
                .iter()
                .find(|state| state.identity_id == identity.id)
                .map(|state| state.state.as_slice())
                .unwrap_or_default();
            let encrypted_ciphertext: async_crypto::AsyncCiphertext = envelope.ciphertext.into();
            let Ok((plaintext, next_state)) =
                async_crypto::decrypt(&identity, state, &contact.public_key, &encrypted_ciphertext)
                    .await
            else {
                continue;
            };
            let Ok(payload) = serde_json::from_slice::<AsyncPlaintext>(&plaintext) else {
                continue;
            };
            if payload.version != 1
                || payload.message_id != item.message_id
                || payload.sender_public_key != envelope.sender_public_key
                || payload.recipient_public_key != identity.public_key()
            {
                continue;
            }
            if payload.group_event.is_some() && payload.group_message.is_some() {
                continue;
            }
            let mut stored_conversation = conversation.clone();
            let mut stored_text = payload.text.clone();
            let mut stored_timestamp = item.accepted_at;
            let mut attachment_frame = false;
            if let Some(event) = payload.group_event.as_ref() {
                let group_index = data
                    .groups
                    .iter()
                    .position(|group| group.group_id == event.group_id);
                let applied = if let Some(index) = group_index {
                    let group = &mut data.groups[index];
                    if event.sequence <= group.sequence {
                        group
                            .events
                            .get(event.sequence as usize)
                            .and_then(|existing| existing.digest().ok())
                            .as_deref()
                            == event.digest().ok().as_deref()
                    } else {
                        group.apply(event).is_ok() && group.validate().is_ok()
                    }
                } else if matches!(&event.change, GroupChange::Create { .. }) {
                    match GroupState::from_creation(event) {
                        Ok(group) => {
                            data.groups.push(group);
                            true
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                };
                if !applied {
                    continue;
                }
                stored_text.clear();
            }
            if let Some(group_message) = payload.group_message.as_ref() {
                let Some(group) = data
                    .groups
                    .iter()
                    .find(|group| group.group_id == group_message.group_id)
                else {
                    continue;
                };
                if !group
                    .members
                    .iter()
                    .any(|member| member.accepted && member.public_key == identity.public_key())
                    || !group_message.validate_for(group, &contact.public_key)
                {
                    continue;
                }
                stored_conversation = format!("group:{}", group_message.group_id);
                stored_text = group_message.text.clone();
                stored_timestamp = group_message.timestamp;
            }
            if let Some(frame) = payload.attachment.as_ref() {
                let attachment_conversation = frame.manifest.conversation_id.clone();
                let is_group_attachment = attachment_conversation.starts_with("group:");
                let authorized_group_attachment = attachment_conversation
                    .strip_prefix("group:")
                    .and_then(|group_id| {
                        data.groups.iter().find(|group| group.group_id == group_id)
                    })
                    .is_some_and(|group| {
                        group.members.iter().any(|member| {
                            member.accepted && member.public_key == identity.public_key()
                        }) && group.members.iter().any(|member| {
                            member.accepted && member.public_key == contact.public_key
                        })
                    });
                let authorized_direct_attachment = !is_group_attachment
                    && attachment_conversation.rsplit_once(':').is_some_and(
                        |(_, recipient_fingerprint)| {
                            recipient_fingerprint == identity.fingerprint()
                        },
                    );
                if attachment_conversation.starts_with("group:") && authorized_group_attachment {
                    stored_conversation = attachment_conversation;
                }
                if frame.parent_message_id.is_empty()
                    || frame.parent_message_id.len() > 128
                    || frame.manifest.message_id != frame.parent_message_id
                    || (is_group_attachment
                        && (frame.manifest.conversation_id != stored_conversation
                            || !authorized_group_attachment))
                    || (!is_group_attachment && !authorized_direct_attachment)
                    || frame.chunk.index >= frame.manifest.chunk_count
                    || item.message_id
                        != format!("{}{:08x}", frame.parent_message_id, frame.chunk.index)
                    || attachments::validate_encrypted_chunk(&frame.manifest, &frame.chunk).is_err()
                    || !data.messages.iter().any(|message| {
                        !message.outgoing
                            && message.id == frame.parent_message_id
                            && message.conversation == stored_conversation
                    })
                {
                    continue;
                }
                let attachment_index = data.attachments.iter().position(|attachment| {
                    attachment.message_id == frame.parent_message_id
                        && attachment.conversation == stored_conversation
                });
                if let Some(index) = attachment_index
                    && (data.attachments[index].manifest != frame.manifest
                        || data.attachments[index]
                            .mailbox_frame_receipts
                            .iter()
                            .any(|receipt| receipt.frame_id == item.message_id))
                {
                    continue;
                }
                if attachments::store_encrypted_chunks(
                    &attachments::attachment_sidecar_path(&path),
                    std::slice::from_ref(&frame.chunk),
                )
                .is_err()
                {
                    continue;
                }
                if let Some(index) = attachment_index {
                    data.attachments[index].mailbox_frame_receipts.push(
                        MailboxAttachmentFrameReceipt {
                            frame_id: item.message_id.clone(),
                            ciphertext_sha256: ciphertext_digest.clone(),
                        },
                    );
                } else {
                    data.attachments.push(akrat_core::StoredAttachment {
                        conversation: stored_conversation.clone(),
                        message_id: frame.parent_message_id.clone(),
                        manifest: frame.manifest.clone(),
                        mailbox_frame_receipts: vec![MailboxAttachmentFrameReceipt {
                            frame_id: item.message_id.clone(),
                            ciphertext_sha256: ciphertext_digest.clone(),
                        }],
                    });
                }
                let stored_attachment = data.attachments.iter().find(|attachment| {
                    attachment.message_id == frame.parent_message_id
                        && attachment.conversation == stored_conversation
                });
                if let Some(attachment) = stored_attachment
                    && attachment.mailbox_frame_receipts.len()
                        == attachment.manifest.chunk_count as usize
                {
                    match attachments::load_encrypted_chunks(
                        &attachments::attachment_sidecar_path(&path),
                        &attachment.manifest,
                    ) {
                        Ok(chunks)
                            if attachments::decrypt_image(&attachment.manifest, &chunks)
                                .is_ok() => {}
                        _ => continue,
                    }
                }
                attachment_frame = true;
            }
            if payload.group_event.is_none()
                && payload.group_message.is_none()
                && payload.attachment.is_none()
                && stored_text.is_empty()
            {
                continue;
            }
            let receipt = match async_crypto::RecipientReceipt::create(
                &identity,
                &contact.public_key,
                inbox.mailbox_id.clone(),
                item.message_id.clone(),
                ciphertext_digest.clone(),
                now(),
            ) {
                Ok(receipt) => receipt,
                Err(_) => continue,
            };
            let pending_receipt = PendingRecipientReceipt {
                mailbox_id: inbox.mailbox_id.clone(),
                read_capability: inbox.read_capability.clone(),
                receipt,
            };
            if let Some(old) = data.pending_recipient_receipts.iter_mut().find(|old| {
                old.mailbox_id == pending_receipt.mailbox_id
                    && old.receipt.message_id == pending_receipt.receipt.message_id
            }) {
                *old = pending_receipt.clone();
            } else {
                data.pending_recipient_receipts
                    .push(pending_receipt.clone());
            }
            upsert_state(&mut data, &identity.id, next_state);
            if payload.group_event.is_none() && !attachment_frame {
                let mut message = StoredMessage {
                    conversation: stored_conversation,
                    id: item.message_id.clone(),
                    outgoing: false,
                    text: stored_text,
                    delivery: DeliveryState::Received,
                    timestamp: stored_timestamp,
                    received_ciphertext_sha256: Some(ciphertext_digest),
                    delivery_events: vec![
                        DeliveryEvent {
                            timestamp: now(),
                            kind: DeliveryEventKind::Retrieved,
                            actor: DeliveryActor::Mailbox,
                            actor_fingerprint: Some(hex::encode(Sha256::digest(
                                &inbox.server_signing_public_key,
                            ))),
                            actor_name: Some(format!("Mailbox {}", inbox.mailbox_id)),
                            receipt_sha256: None,
                            receipt_bytes: None,
                            verified: false,
                        },
                        DeliveryEvent {
                            timestamp: now(),
                            kind: DeliveryEventKind::AuthenticatedAndSaved,
                            actor: DeliveryActor::RecipientClient,
                            actor_fingerprint: Some(identity.fingerprint()),
                            actor_name: Some(identity.name.clone()),
                            receipt_sha256: None,
                            receipt_bytes: None,
                            verified: true,
                        },
                    ],
                };
                if payload.group_message.is_some() {
                    message.record_delivery_event(DeliveryEvent {
                        timestamp: now(),
                        kind: DeliveryEventKind::AuthenticatedAndSaved,
                        actor: DeliveryActor::RecipientClient,
                        actor_fingerprint: Some(contact.fingerprint.clone()),
                        actor_name: Some(contact.name.clone()),
                        receipt_sha256: None,
                        receipt_bytes: None,
                        verified: true,
                    });
                }
                data.messages.push(message);
            }
            save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
            if send_recipient_receipt(&mut channel, &pending_receipt)
                .await
                .is_ok()
            {
                record_recipient_confirmation(&mut data, &identity, &pending_receipt)?;
                data.pending_recipient_receipts.retain(|old| {
                    !(old.mailbox_id == pending_receipt.mailbox_id
                        && old.receipt.message_id == pending_receipt.receipt.message_id)
                });
                save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
                received += 1;
            }
            data = load_vault(&path, &passphrase).map_err(|e| e.to_string())?;
        }
        let acknowledged_after_batch = send_pending_recipient_receipts(
            &path,
            &passphrase,
            &mut data,
            &identity,
            &inbox,
            &mut channel,
        )
        .await?;
        if received == received_before_batch
            && acknowledgements == 0
            && acknowledged_after_batch == 0
        {
            break;
        }
    }
    send_pending_recipient_receipts(
        &path,
        &passphrase,
        &mut data,
        &identity,
        &inbox,
        &mut channel,
    )
    .await?;
    Ok(received)
}

async fn send_pending_recipient_receipts(
    path: &Path,
    passphrase: &str,
    data: &mut VaultData,
    identity: &Identity,
    inbox: &MailboxInbox,
    channel: &mut akrat_core::network::SecureChannel<tokio::net::TcpStream>,
) -> Result<usize, String> {
    let pending = data
        .pending_recipient_receipts
        .iter()
        .filter(|item| item.mailbox_id == inbox.mailbox_id)
        .cloned()
        .collect::<Vec<_>>();
    let mut acknowledged = 0;
    for receipt in pending {
        if send_recipient_receipt(channel, &receipt).await.is_ok() {
            record_recipient_confirmation(data, identity, &receipt)?;
            data.pending_recipient_receipts.retain(|old| {
                !(old.mailbox_id == receipt.mailbox_id
                    && old.receipt.message_id == receipt.receipt.message_id)
            });
            save_vault(path, data, passphrase).map_err(|e| e.to_string())?;
            acknowledged += 1;
        }
    }
    Ok(acknowledged)
}

pub async fn poll_delivery_receipt(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message_id: String,
) -> Result<DeliveryPoll, String> {
    let mut data = load_vault(&path, &passphrase).map_err(|e| e.to_string())?;
    let (identity_id, fingerprint) = conversation
        .split_once(':')
        .ok_or("conversation id invalid")?;
    let identity = data
        .identities
        .iter()
        .find(|identity| identity.id == identity_id)
        .ok_or("identity not found")?
        .detached_copy();
    let contact = data
        .contacts
        .iter()
        .find(|contact| contact.fingerprint == fingerprint && contact.manually_verified)
        .ok_or("verified contact not found")?
        .clone();
    let route = contact
        .mailbox_route
        .clone()
        .ok_or("no mailbox route configured")?;
    let mut routes = vec![route];
    routes.extend(contact.mailbox_replicas.iter().cloned());
    let Some(outbox) = data
        .async_outbox
        .iter()
        .find(|item| item.conversation == conversation && item.message_id == message_id)
        .cloned()
    else {
        return Err("message ciphertext missing from encrypted outbox".into());
    };
    let expected_digest = if outbox.envelope.is_empty() {
        outbox
            .envelope_sha256
            .clone()
            .ok_or("saved attachment frame digest is missing")?
    } else {
        hex::encode(Sha256::digest(&outbox.envelope))
    };
    let tracked_message_id = outbox
        .parent_message_id
        .clone()
        .unwrap_or_else(|| message_id.clone());
    let mut expired_routes = 0usize;
    for route in &routes {
        let Ok((mut channel, server_identity, generation, revocation_sequence)) = connect(
            &identity,
            &route.endpoint,
            &route.server_noise_public_key,
            &route.server_signing_public_key,
            route.server_key_generation,
            route.server_revocation_sequence,
        )
        .await
        else {
            continue;
        };
        if generation > route.server_key_generation
            || revocation_sequence > route.server_revocation_sequence
        {
            update_contact_route_generation(&mut data, route, generation, revocation_sequence);
            save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
        }
        let response = match server::request(
            &mut channel,
            &Request::GetRecipientReceipt {
                mailbox_id: route.mailbox_id.clone(),
                write_capability: route.write_capability.clone(),
                message_id: message_id.clone(),
            },
        )
        .await
        {
            Ok(response) => response,
            Err(_) => continue,
        };
        match response {
            Response::RecipientReceipt {
                receipt: Some(receipt),
            } => {
                if !receipt.verify().map_err(|e| e.to_string())?
                    || receipt.mailbox_id != route.mailbox_id
                    || receipt.message_id != message_id
                    || receipt.sender_public_key != identity.public_key()
                    || receipt.recipient_public_key != contact.public_key
                    || receipt.ciphertext_sha256 != expected_digest
                {
                    return Err(
                        "recipient receipt does not match the sent message and verified identity"
                            .into(),
                    );
                }
                let receipt_bytes =
                    serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
                let receipt_digest = hex::encode(Sha256::digest(&receipt_bytes));
                data.async_outbox.retain(|item| {
                    !(item.conversation == conversation && item.message_id == message_id)
                });
                let siblings_pending = data.async_outbox.iter().any(|item| {
                    item.conversation == conversation
                        && item.parent_message_id.as_deref() == Some(tracked_message_id.as_str())
                });
                if !siblings_pending
                    && let Some(message) = data.messages.iter_mut().find(|message| {
                        message.conversation == conversation
                            && message.id == tracked_message_id
                            && message.outgoing
                    })
                    && !message.delivery_events.iter().any(|event| {
                        event.kind == DeliveryEventKind::RecipientConfirmed
                            && event.actor_fingerprint.as_deref()
                                == Some(contact.fingerprint.as_str())
                    })
                {
                    message.record_delivery_event(DeliveryEvent {
                        timestamp: receipt.received_at,
                        kind: DeliveryEventKind::RecipientConfirmed,
                        actor: DeliveryActor::RecipientClient,
                        actor_fingerprint: Some(contact.fingerprint.clone()),
                        actor_name: Some(format!("{} · {}", contact.name, route.mailbox_id)),
                        receipt_sha256: Some(receipt_digest.clone()),
                        receipt_bytes: Some(receipt_bytes.clone()),
                        verified: true,
                    });
                }
                if !siblings_pending {
                    mark_group_receipt(
                        &mut data,
                        &contact,
                        &tracked_message_id,
                        receipt.received_at,
                        &receipt_digest,
                        &receipt_bytes,
                    );
                }
                if !siblings_pending
                    && let Some(message) = data.messages.iter_mut().find(|message| {
                        message.conversation == conversation
                            && message.id == tracked_message_id
                            && message.outgoing
                    })
                {
                    message.delivery = DeliveryState::Acknowledged;
                }
                save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
                if let Some(attachment_id) = outbox.attachment_id.as_deref() {
                    attachments::remove_mailbox_envelope(
                        &attachments::attachment_sidecar_path(&path),
                        attachment_id,
                        &conversation,
                        &message_id,
                    )
                    .map_err(|error| error.to_string())?;
                }
                if outbox.parent_message_id.is_none() {
                    let attachment_ids = data
                        .async_outbox
                        .iter()
                        .filter(|item| {
                            item.conversation == conversation
                                && item.parent_message_id.as_deref() == Some(message_id.as_str())
                        })
                        .map(|item| item.message_id.clone())
                        .collect::<Vec<_>>();
                    for attachment_id in attachment_ids {
                        if matches!(
                            Box::pin(poll_delivery_receipt(
                                path.clone(),
                                passphrase.clone(),
                                conversation.clone(),
                                attachment_id,
                            ))
                            .await?,
                            DeliveryPoll::Pending | DeliveryPoll::Expired
                        ) {
                            return Ok(DeliveryPoll::Pending);
                        }
                    }
                }
                return Ok(DeliveryPoll::Delivered);
            }
            Response::RecipientReceipt { receipt: None } => {
                let response = match server::request(
                    &mut channel,
                    &Request::GetDeliveryFailure {
                        mailbox_id: route.mailbox_id.clone(),
                        write_capability: route.write_capability.clone(),
                        message_id: message_id.clone(),
                    },
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => continue,
                };
                let Response::DeliveryFailure {
                    failure: Some(failure),
                } = response
                else {
                    continue;
                };
                if !verify_delivery_failure(&failure, &server_identity)?
                    || failure.mailbox_id != route.mailbox_id
                    || failure.message_id != message_id
                    || failure.ciphertext_sha256 != expected_digest
                {
                    return Err("signed expiry event does not match the sent ciphertext".into());
                }
                let receipt_bytes = serde_json::to_vec(&failure).map_err(|e| e.to_string())?;
                let failure_digest = hex::encode(Sha256::digest(&receipt_bytes));
                if let Some(message) = data.messages.iter_mut().find(|message| {
                    message.conversation == conversation
                        && message.id == tracked_message_id
                        && message.outgoing
                }) && !message.delivery_events.iter().any(|event| {
                    event.kind == DeliveryEventKind::Expired
                        && event.receipt_sha256.as_deref() == Some(failure_digest.as_str())
                }) {
                    message.record_delivery_event(DeliveryEvent {
                        timestamp: failure.signed_at,
                        kind: DeliveryEventKind::Expired,
                        actor: DeliveryActor::Mailbox,
                        actor_fingerprint: Some(failure.server_fingerprint.clone()),
                        actor_name: Some(format!("Mailbox {}", failure.mailbox_id)),
                        receipt_sha256: Some(failure_digest),
                        receipt_bytes: Some(receipt_bytes),
                        verified: true,
                    });
                }
                expired_routes += 1;
            }
            _ => continue,
        }
    }
    if expired_routes == routes.len() {
        if let Some(message) = data.messages.iter_mut().find(|message| {
            message.conversation == conversation
                && message.id == tracked_message_id
                && message.outgoing
        }) {
            message.delivery = DeliveryState::Expired;
        }
        data.async_outbox
            .retain(|item| !(item.conversation == conversation && item.message_id == message_id));
        save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
        if let Some(attachment_id) = outbox.attachment_id.as_deref() {
            attachments::remove_mailbox_envelope(
                &attachments::attachment_sidecar_path(&path),
                attachment_id,
                &conversation,
                &message_id,
            )
            .map_err(|error| error.to_string())?;
        }
        return Ok(DeliveryPoll::Expired);
    }
    save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
    Ok(DeliveryPoll::Pending)
}

async fn send_recipient_receipt(
    channel: &mut akrat_core::network::SecureChannel<tokio::net::TcpStream>,
    pending: &PendingRecipientReceipt,
) -> Result<(), String> {
    match server::request(
        channel,
        &Request::Acknowledge {
            mailbox_id: pending.mailbox_id.clone(),
            read_capability: pending.read_capability.clone(),
            receipt: pending.receipt.clone(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        Response::Acknowledged => Ok(()),
        other => Err(format!("recipient receipt was refused: {other:?}")),
    }
}

fn record_recipient_confirmation(
    data: &mut VaultData,
    identity: &Identity,
    pending: &PendingRecipientReceipt,
) -> Result<(), String> {
    let receipt_bytes = serde_json::to_vec(&pending.receipt).map_err(|error| error.to_string())?;
    let receipt_digest = hex::encode(Sha256::digest(&receipt_bytes));
    let mailbox_label = format!("{} · {}", identity.name, pending.mailbox_id);
    let parent_message_id = data
        .attachments
        .iter()
        .find(|attachment| {
            attachment
                .mailbox_frame_receipts
                .iter()
                .any(|receipt| receipt.frame_id == pending.receipt.message_id)
        })
        .map(|attachment| attachment.message_id.as_str())
        .unwrap_or(&pending.receipt.message_id);
    if let Some(message) = data
        .messages
        .iter_mut()
        .find(|message| message.id == parent_message_id && !message.outgoing)
        && !message.delivery_events.iter().any(|event| {
            event.kind == DeliveryEventKind::RecipientConfirmed
                && event.actor_name.as_deref() == Some(mailbox_label.as_str())
        })
    {
        message.record_delivery_event(DeliveryEvent {
            timestamp: now(),
            kind: DeliveryEventKind::RecipientConfirmed,
            actor: DeliveryActor::RecipientClient,
            actor_fingerprint: Some(identity.fingerprint()),
            actor_name: Some(mailbox_label),
            receipt_sha256: Some(receipt_digest),
            receipt_bytes: Some(receipt_bytes),
            verified: true,
        });
    }
    Ok(())
}

fn mark_group_receipt(
    data: &mut VaultData,
    contact: &akrat_core::Contact,
    message_id: &str,
    timestamp: u64,
    receipt_digest: &str,
    receipt_bytes: &[u8],
) {
    let mut fully_received = false;
    for delivery in data
        .group_deliveries
        .iter_mut()
        .filter(|delivery| delivery.message_id == message_id)
    {
        if let Some(recipient) = delivery
            .recipients
            .iter_mut()
            .find(|recipient| recipient.fingerprint == contact.fingerprint)
        {
            recipient.status = GroupRecipientStatus::Received;
            recipient.updated_at = timestamp;
            fully_received = delivery
                .recipients
                .iter()
                .all(|recipient| recipient.status == GroupRecipientStatus::Received);
        }
    }
    for message in data.messages.iter_mut().filter(|message| {
        message.id == message_id && message.outgoing && message.conversation.starts_with("group:")
    }) {
        if !message.delivery_events.iter().any(|event| {
            event.kind == DeliveryEventKind::RecipientConfirmed
                && event.actor_fingerprint.as_deref() == Some(contact.fingerprint.as_str())
        }) {
            message.record_delivery_event(DeliveryEvent {
                timestamp,
                kind: DeliveryEventKind::RecipientConfirmed,
                actor: DeliveryActor::RecipientClient,
                actor_fingerprint: Some(contact.fingerprint.clone()),
                actor_name: Some(contact.name.clone()),
                receipt_sha256: Some(receipt_digest.to_owned()),
                receipt_bytes: Some(receipt_bytes.to_vec()),
                verified: true,
            });
        }
        if fully_received {
            message.delivery = DeliveryState::Acknowledged;
        }
    }
}

async fn fetch_bundle(
    identity: &Identity,
    route: &MailboxRoute,
) -> Result<akrat_core::async_crypto::PublishedBundle, String> {
    let (mut channel, _, _, _) = connect(
        identity,
        &route.endpoint,
        &route.server_noise_public_key,
        &route.server_signing_public_key,
        route.server_key_generation,
        route.server_revocation_sequence,
    )
    .await?;
    match server::request(
        &mut channel,
        &Request::GetBundle {
            mailbox_id: route.mailbox_id.clone(),
            bundle_capability: route.bundle_capability.clone(),
        },
    )
    .await
    .map_err(|e| e.to_string())?
    {
        Response::Bundle {
            bundle: Some(bundle),
        } => Ok(bundle),
        Response::Bundle { bundle: None } => {
            Err("recipient has not published a current pre-key bundle".into())
        }
        other => Err(format!("bundle retrieval failed: {other:?}")),
    }
}

async fn fetch_verified_bundle(
    path: &Path,
    passphrase: &str,
    conversation: &str,
) -> Result<akrat_core::async_crypto::PublishedBundle, String> {
    let data = load_vault(path, passphrase).map_err(|error| error.to_string())?;
    let (identity_id, fingerprint) = conversation
        .split_once(':')
        .ok_or("conversation id invalid")?;
    let identity = data
        .identities
        .iter()
        .find(|identity| identity.id == identity_id)
        .map(Identity::detached_copy)
        .ok_or("identity not found")?;
    let contact = data
        .contacts
        .iter()
        .find(|contact| contact.fingerprint == fingerprint && contact.manually_verified)
        .ok_or("contact is not verified")?;
    let mut routes = vec![
        contact
            .mailbox_route
            .as_ref()
            .ok_or("no asynchronous mailbox configured for this contact")?
            .clone(),
    ];
    routes.extend(contact.mailbox_replicas.iter().cloned());
    for route in routes {
        if let Ok(bundle) = fetch_bundle(&identity, &route).await
            && async_crypto::verify_bundle(&bundle, &contact.public_key).is_ok()
        {
            return Ok(bundle);
        }
    }
    Err("aucune Mailbox configurée ne fournit un bundle valide".into())
}

async fn connect(
    identity: &Identity,
    endpoint: &str,
    noise_key: &[u8],
    signing_root: &[u8],
    minimum_generation: u64,
    minimum_revocation_sequence: u64,
) -> Result<
    (
        akrat_core::network::SecureChannel<tokio::net::TcpStream>,
        akrat_mailbox::key_rotation::ServerIdentity,
        u64,
        u64,
    ),
    String,
> {
    let address: SocketAddr = tokio::net::lookup_host(endpoint)
        .await
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("mailbox endpoint did not resolve")?;
    let mut channel = server::connect(address, identity, noise_key)
        .await
        .map_err(|e| e.to_string())?;
    server::start(&mut channel)
        .await
        .map_err(|e| e.to_string())?;
    let response = server::request(&mut channel, &Request::ServerIdentity)
        .await
        .map_err(|error| error.to_string())?;
    let Response::ServerIdentity { identity } = response else {
        return Err(format!("server identity check failed: {response:?}"));
    };
    let pinned_root: [u8; 32] = signing_root
        .try_into()
        .map_err(|_| "invalid server continuity key".to_owned())?;
    identity
        .verify(
            &pinned_root,
            minimum_generation,
            minimum_revocation_sequence,
            now(),
        )
        .map_err(|error| error.to_string())?;
    Ok((
        channel,
        identity.clone(),
        identity.generation,
        identity.revocation_sequence,
    ))
}

fn verify_deposit_receipt(
    receipt: &akrat_mailbox::DepositReceipt,
    identity: &akrat_mailbox::key_rotation::ServerIdentity,
) -> Result<bool, String> {
    let Some(key) = identity.receipt_key_at(&receipt.server_fingerprint, receipt.accepted_at)
    else {
        return Ok(false);
    };
    akrat_mailbox::verify_receipt(receipt, &key).map_err(|error| error.to_string())
}

fn verify_delivery_failure(
    failure: &akrat_mailbox::DeliveryFailure,
    identity: &akrat_mailbox::key_rotation::ServerIdentity,
) -> Result<bool, String> {
    let Some(key) = identity.receipt_key_at(&failure.server_fingerprint, failure.signed_at) else {
        return Ok(false);
    };
    failure.verify(&key).map_err(|error| error.to_string())
}

fn update_contact_route_generation(
    data: &mut VaultData,
    route: &MailboxRoute,
    generation: u64,
    revocation_sequence: u64,
) {
    for contact in &mut data.contacts {
        if let Some(primary) = contact.mailbox_route.as_mut()
            && primary.endpoint == route.endpoint
            && primary.mailbox_id == route.mailbox_id
        {
            primary.server_key_generation = primary.server_key_generation.max(generation);
            primary.server_revocation_sequence =
                primary.server_revocation_sequence.max(revocation_sequence);
        }
        for replica in &mut contact.mailbox_replicas {
            if replica.endpoint == route.endpoint && replica.mailbox_id == route.mailbox_id {
                replica.server_key_generation = replica.server_key_generation.max(generation);
                replica.server_revocation_sequence =
                    replica.server_revocation_sequence.max(revocation_sequence);
            }
        }
    }
}

fn upsert_state(data: &mut VaultData, identity_id: &str, state: Vec<u8>) {
    if let Some(current) = data
        .async_protocol_states
        .iter_mut()
        .find(|item| item.identity_id == identity_id)
    {
        current.state = state;
    } else {
        data.async_protocol_states.push(AsyncProtocolState {
            identity_id: identity_id.into(),
            state,
        });
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use akrat_core::{
        Contact, GroupChange, GroupEvent, GroupMember, GroupMessage, GroupMessageDelivery,
        GroupRecipientDelivery, GroupRecipientStatus, GroupRole, GroupState, MailboxInbox,
        MailboxRoute, StoredAttachment,
    };
    use akrat_mailbox::{ServerSigner, Store, server::ServerConfig};
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    const PHRASE: &str = "desktop-mailbox-flow-test-phrase";
    const MESSAGE_ID: &str = "d35a4b0c0ffee123";
    const SECOND_MESSAGE_ID: &str = "d35a4b0c0ffee127";
    const EXPIRED_MESSAGE_ID: &str = "d35a4b0c0ffee124";
    const PARTIAL_RETRY_MESSAGE_ID: &str = "d35a4b0c0ffee125";
    const GROUP_MESSAGE_ID: &str = "d35a4b0c0ffee126";

    #[test]
    fn mailbox_envelopes_keep_legacy_messages_and_version_attachment_frames_compactly() {
        let ciphertext = async_crypto::AsyncCiphertext {
            version: 1,
            prekey: false,
            bytes: vec![0x5a; 8192],
        };
        let legacy = serde_json::to_vec(&LegacyAsyncEnvelope {
            version: 1,
            sender_public_key: &[7; 32],
            ciphertext: &ciphertext,
        })
        .expect("legacy envelope encoding");
        assert!(legacy.len() > 8192 * 3);
        let decoded_legacy: AsyncEnvelope =
            serde_json::from_slice(&legacy).expect("legacy envelope decoding");
        assert_eq!(decoded_legacy.version, 1);
        assert_eq!(decoded_legacy.ciphertext.bytes, ciphertext.bytes);

        let compact = serde_json::to_vec(&CompactAsyncEnvelope {
            version: 2,
            sender_public_key: vec![7; 32],
            ciphertext: CompactAsyncCiphertext {
                version: ciphertext.version,
                prekey: ciphertext.prekey,
                bytes: ciphertext.bytes.clone(),
            },
        })
        .expect("compact attachment envelope encoding");
        assert!(compact.len() < 12_000);
        let decoded_compact: AsyncEnvelope =
            serde_json::from_slice(&compact).expect("compact envelope decoding");
        assert_eq!(decoded_compact.version, 2);
        assert_eq!(decoded_compact.ciphertext.bytes, ciphertext.bytes);
    }

    #[test]
    fn maximum_new_attachment_chunk_fits_mailbox_deposit_and_fetch_frames() {
        let parent_message_id = "d35a4b0c0ffee127";
        let attachment_id = "102132435465768798a9bacbdcedfe0f";
        let manifest = AttachmentManifest {
            version: 1,
            attachment_id: attachment_id.into(),
            message_id: parent_message_id.into(),
            conversation_id: "alice-id:bob-fingerprint".into(),
            display_name: "image.png".into(),
            media_type: "image/png".into(),
            plaintext_size: attachments::ATTACHMENT_CHUNK_BYTES as u64,
            chunk_size: attachments::ATTACHMENT_CHUNK_BYTES as u32,
            chunk_count: 1,
            plaintext_sha256: "a4".repeat(32),
            content_key: vec![0x31; 32],
        };
        let chunk = AttachmentChunk {
            version: 1,
            attachment_id: attachment_id.into(),
            index: 0,
            nonce: vec![0x42; 12],
            ciphertext: vec![0x53; attachments::ATTACHMENT_CHUNK_BYTES + 16],
        };
        let plaintext = serde_json::to_vec(&AsyncPlaintext {
            version: 1,
            message_id: format!("{parent_message_id}00000000"),
            sender_public_key: vec![0x61; 32],
            recipient_public_key: vec![0x72; 32],
            text: String::new(),
            group_event: None,
            group_message: None,
            attachment: Some(MailboxAttachment {
                parent_message_id: parent_message_id.into(),
                manifest,
                chunk,
            }),
        })
        .expect("serialize attachment frame plaintext");
        let ciphertext = CompactAsyncEnvelope {
            version: 2,
            sender_public_key: vec![0x61; 32],
            ciphertext: CompactAsyncCiphertext {
                version: 1,
                prekey: false,
                bytes: vec![0x84; plaintext.len() + 512],
            },
        };
        let envelope = serde_json::to_vec(&ciphertext).expect("serialize compact ciphertext");
        assert!(envelope.len() <= akrat_mailbox::server::MAX_WIRE_ENVELOPE_BYTES);
        let request = serde_json::to_vec(&Request::Deposit {
            mailbox_id: "mailbox-id".into(),
            write_capability: "capability".into(),
            message_id: format!("{parent_message_id}00000000"),
            ciphertext: STANDARD.encode(&envelope),
        })
        .expect("serialize mailbox deposit");
        assert!(request.len() <= 60 * 1024);
        assert!(STANDARD.encode(&envelope).len() + 256 <= 60 * 1024);
    }

    struct ServerProcess(Child);

    impl ServerProcess {
        fn stop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    impl Drop for ServerProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    async fn mailbox_server_process() {
        let Ok(path) = std::env::var("AKRAT_DESKTOP_TEST_SERVER_CONFIG") else {
            return;
        };
        server::run(ServerConfig::load(path).expect("server config"))
            .await
            .expect("run mailbox server");
    }

    #[tokio::test]
    async fn desktop_helpers_deliver_offline_message_and_confirm_delivery() {
        if std::env::var_os("AKRAT_DESKTOP_TEST_SERVER_CONFIG").is_some() {
            return;
        }
        let directory = tempfile::tempdir().expect("test directory");
        let config_path = directory.path().join("mailbox.json");
        let address = StdTcpListener::bind("127.0.0.1:0")
            .expect("reserve server port")
            .local_addr()
            .expect("reserved server address");
        let mut config = ServerConfig::initialize(
            &config_path,
            "desktop-e2e".into(),
            address,
            directory.path().join("server-data"),
            1024 * 1024,
            8,
            512 * 1024,
            3600,
        )
        .expect("initialize mailbox");
        raise_test_rate_limits(&mut config);
        config.save(&config_path).expect("save test mailbox limits");
        std::fs::create_dir_all(&config.data_dir).expect("create mailbox data directory");
        let mut store = Store::open(
            config.data_dir.join("mailbox.sqlite3"),
            config.max_total_bytes,
            config.max_mailboxes,
        )
        .expect("mailbox store");
        let (mailbox_id, write_capability, read_capability, bundle_capability) = store
            .create_mailbox(512 * 1024, 3600)
            .expect("create Bob mailbox");
        drop(store);
        let signing_public_key = ServerSigner::from_bytes(
            &hex::decode(&config.signing_key_hex).expect("signing secret"),
        )
        .expect("server signer")
        .public_key()
        .to_vec();
        let mut server1 = start_server(&config_path);

        let config2_path = directory.path().join("mailbox-two.json");
        let address2 = StdTcpListener::bind("127.0.0.1:0")
            .expect("reserve second server port")
            .local_addr()
            .expect("reserved second server address");
        let mut config2 = ServerConfig::initialize(
            &config2_path,
            "desktop-e2e-two".into(),
            address2,
            directory.path().join("server-two-data"),
            1024 * 1024,
            8,
            512 * 1024,
            3600,
        )
        .expect("initialize second mailbox");
        raise_test_rate_limits(&mut config2);
        config2
            .save(&config2_path)
            .expect("save replicated mailbox test limits");
        std::fs::create_dir_all(&config2.data_dir).expect("create second mailbox data directory");
        let mut store2 = Store::open(
            config2.data_dir.join("mailbox.sqlite3"),
            config2.max_total_bytes,
            config2.max_mailboxes,
        )
        .expect("second mailbox store");
        let (mailbox_id2, write_capability2, read_capability2, bundle_capability2) = store2
            .create_mailbox(512 * 1024, 3600)
            .expect("create replicated Bob mailbox");
        drop(store2);
        let signing_public_key2 = ServerSigner::from_bytes(
            &hex::decode(&config2.signing_key_hex).expect("second signing secret"),
        )
        .expect("second server signer")
        .public_key()
        .to_vec();
        let _server2 = start_server(&config2_path);
        let alice = Identity::generate("Alice desktop test".into()).expect("Alice identity");
        let bob = Identity::generate("Bob desktop test".into()).expect("Bob identity");
        wait_for_server(address, &alice, config.noise_identity.public_key()).await;
        wait_for_server(address2, &alice, config2.noise_identity.public_key()).await;
        let bob_vault = directory.path().join("bob.akrat");
        let alice_vault = directory.path().join("alice.akrat");
        let bob_contact = Contact {
            fingerprint: bob.fingerprint(),
            name: "Bob".into(),
            public_key: bob.public_key().to_vec(),
            transport_id: bob.transport_id(),
            legacy_address: String::new(),
            manually_verified: true,
            mailbox_route: None,
            mailbox_replicas: Vec::new(),
        };
        let alice_contact = Contact {
            fingerprint: alice.fingerprint(),
            name: "Alice".into(),
            public_key: alice.public_key().to_vec(),
            transport_id: alice.transport_id(),
            legacy_address: String::new(),
            manually_verified: true,
            mailbox_route: None,
            mailbox_replicas: Vec::new(),
        };
        let mut bob_data = VaultData {
            revision: 0,
            identities: vec![bob.detached_copy()],
            contacts: vec![alice_contact],
            mailbox_inboxes: vec![
                MailboxInbox {
                    identity_id: bob.id.clone(),
                    endpoint: address.to_string(),
                    server_noise_public_key: config.noise_identity.public_key().to_vec(),
                    server_signing_public_key: signing_public_key.clone(),
                    server_key_generation: 0,
                    server_revocation_sequence: 0,
                    mailbox_id: mailbox_id.clone(),
                    write_capability: write_capability.clone(),
                    read_capability,
                    bundle_capability: bundle_capability.clone(),
                },
                MailboxInbox {
                    identity_id: bob.id.clone(),
                    endpoint: address2.to_string(),
                    server_noise_public_key: config2.noise_identity.public_key().to_vec(),
                    server_signing_public_key: signing_public_key2.clone(),
                    server_key_generation: 0,
                    server_revocation_sequence: 0,
                    mailbox_id: mailbox_id2.clone(),
                    write_capability: write_capability2.clone(),
                    read_capability: read_capability2,
                    bundle_capability: bundle_capability2.clone(),
                },
            ],
            ..VaultData::default()
        };
        save_vault(&bob_vault, &mut bob_data, PHRASE).expect("save Bob vault");
        let conversation = format!("{}:{}", alice.id, bob.fingerprint());
        let message = "Message déposé pendant que Bob est hors ligne.";
        let mut alice_data = VaultData {
            revision: 0,
            identities: vec![alice.detached_copy()],
            contacts: vec![Contact {
                mailbox_route: Some(MailboxRoute {
                    endpoint: address.to_string(),
                    server_noise_public_key: config.noise_identity.public_key().to_vec(),
                    server_signing_public_key: signing_public_key,
                    server_key_generation: 0,
                    server_revocation_sequence: 0,
                    mailbox_id,
                    write_capability,
                    bundle_capability,
                }),
                mailbox_replicas: vec![MailboxRoute {
                    endpoint: address2.to_string(),
                    server_noise_public_key: config2.noise_identity.public_key().to_vec(),
                    server_signing_public_key: signing_public_key2,
                    server_key_generation: 0,
                    server_revocation_sequence: 0,
                    mailbox_id: mailbox_id2.clone(),
                    write_capability: write_capability2,
                    bundle_capability: bundle_capability2,
                }],
                ..bob_contact
            }],
            messages: vec![
                StoredMessage {
                    conversation: conversation.clone(),
                    id: MESSAGE_ID.into(),
                    outgoing: true,
                    text: message.into(),
                    delivery: DeliveryState::Pending,
                    timestamp: now(),
                    delivery_events: Vec::new(),
                    received_ciphertext_sha256: None,
                },
                StoredMessage {
                    conversation: conversation.clone(),
                    id: SECOND_MESSAGE_ID.into(),
                    outgoing: true,
                    text: "Deuxième message concurrent.".into(),
                    delivery: DeliveryState::Pending,
                    timestamp: now(),
                    delivery_events: Vec::new(),
                    received_ciphertext_sha256: None,
                },
            ],
            ..VaultData::default()
        };
        let (direct_manifest, direct_chunks) = attachments::encrypt_image(
            include_bytes!("../assets/test-image.png"),
            "102132435465768798a9bacbdcedfe0f".into(),
            SECOND_MESSAGE_ID.into(),
            conversation.clone(),
            "akrat-logo.png",
        )
        .expect("prepare encrypted direct-message image");
        let direct_chunk_count = direct_manifest.chunk_count as usize;
        assert!(direct_chunk_count > 1);
        attachments::store_encrypted_chunks(
            &attachments::attachment_sidecar_path(&alice_vault),
            &direct_chunks,
        )
        .expect("persist encrypted direct-message image chunks");
        alice_data.attachments.push(StoredAttachment {
            conversation: conversation.clone(),
            message_id: SECOND_MESSAGE_ID.into(),
            manifest: direct_manifest,
            mailbox_frame_receipts: Vec::new(),
        });
        save_vault(&alice_vault, &mut alice_data, PHRASE).expect("save Alice vault");

        poll_inbox(
            bob_vault.clone(),
            PHRASE.into(),
            bob_data.mailbox_inboxes[0].clone(),
        )
        .await
        .expect("publish Bob pre-keys to the first Mailbox");
        poll_inbox(
            bob_vault.clone(),
            PHRASE.into(),
            bob_data.mailbox_inboxes[1].clone(),
        )
        .await
        .expect("publish Bob pre-keys to the replica Mailbox");
        let creation = GroupEvent::signed(
            &alice,
            "offline-group".into(),
            0,
            0,
            None,
            GroupChange::Create {
                name: "Offline group".into(),
                creator_name: "Alice".into(),
            },
        )
        .expect("group creation event");
        let mut group = GroupState::from_creation(&creation).expect("group creation");
        let invite = GroupEvent::signed(
            &alice,
            "offline-group".into(),
            1,
            0,
            Some(group.last_event_sha256.clone()),
            GroupChange::Invite {
                member: GroupMember {
                    fingerprint: bob.fingerprint(),
                    public_key: bob.public_key().to_vec(),
                    display_name: "Bob".into(),
                    role: GroupRole::Member,
                    accepted: false,
                },
            },
        )
        .expect("group invite event");
        group.apply(&invite).expect("apply group invite");
        let acceptance = GroupEvent::signed(
            &bob,
            "offline-group".into(),
            2,
            1,
            Some(group.last_event_sha256.clone()),
            GroupChange::Accept,
        )
        .expect("group acceptance event");
        group.apply(&acceptance).expect("apply group acceptance");
        alice_data.groups.push(group.clone());
        let group_conversation = "group:offline-group".to_string();
        alice_data.messages.push(StoredMessage {
            conversation: group_conversation.clone(),
            id: GROUP_MESSAGE_ID.into(),
            outgoing: true,
            text: "**Image caption follows**".into(),
            delivery: DeliveryState::Queued,
            timestamp: now(),
            delivery_events: Vec::new(),
            received_ciphertext_sha256: None,
        });
        let (group_manifest, group_chunks) = attachments::encrypt_image(
            include_bytes!("../assets/test-image.png"),
            "00112233445566778899aabbccddeeff".into(),
            GROUP_MESSAGE_ID.into(),
            group_conversation.clone(),
            "akrat-logo.png",
        )
        .expect("prepare encrypted group image");
        let group_chunk_count = group_manifest.chunk_count as usize;
        assert!(group_chunk_count > 1);
        attachments::store_encrypted_chunks(
            &attachments::attachment_sidecar_path(&alice_vault),
            &group_chunks,
        )
        .expect("persist encrypted group image chunks");
        alice_data.attachments.push(StoredAttachment {
            conversation: group_conversation.clone(),
            message_id: GROUP_MESSAGE_ID.into(),
            manifest: group_manifest.clone(),
            mailbox_frame_receipts: Vec::new(),
        });
        alice_data.group_deliveries.push(GroupMessageDelivery {
            group_id: group.group_id.clone(),
            message_id: GROUP_MESSAGE_ID.into(),
            epoch: group.epoch,
            sequence: group.sequence,
            recipients: vec![GroupRecipientDelivery {
                fingerprint: bob.fingerprint(),
                status: GroupRecipientStatus::Pending,
                updated_at: now(),
            }],
        });
        save_vault(&alice_vault, &mut alice_data, PHRASE).expect("persist offline group");
        let mut bob_stored =
            load_vault(&bob_vault, PHRASE).expect("reload Bob after bundle publication");
        bob_stored.groups.push(group.clone());
        save_vault(&bob_vault, &mut bob_stored, PHRASE).expect("persist Bob group state");
        let (first_send, second_send) = tokio::join!(
            send(
                alice_vault.clone(),
                PHRASE.into(),
                conversation.clone(),
                MESSAGE_ID.into(),
            ),
            send(
                alice_vault.clone(),
                PHRASE.into(),
                conversation.clone(),
                SECOND_MESSAGE_ID.into(),
            ),
        );
        assert_eq!(
            usize::from(first_send.is_ok()) + usize::from(second_send.is_ok()),
            1
        );
        let failed_message = if first_send.is_err() {
            MESSAGE_ID
        } else {
            SECOND_MESSAGE_ID
        };
        let stale_send = if first_send.is_err() {
            first_send.expect_err("first concurrent send conflict")
        } else {
            second_send.expect_err("second concurrent send conflict")
        };
        assert!(stale_send.contains("revision conflict"));
        send(
            alice_vault.clone(),
            PHRASE.into(),
            conversation.clone(),
            failed_message.into(),
        )
        .await
        .expect("retry the stale send using the current ratchet state");
        load_vault(&alice_vault, PHRASE).expect("reload Alice vault before group deposit");
        send_group_message(
            alice_vault.clone(),
            PHRASE.into(),
            conversation.clone(),
            GroupMessage {
                version: 1,
                group_id: group.group_id.clone(),
                epoch: group.epoch,
                sequence: group.sequence,
                message_id: GROUP_MESSAGE_ID.into(),
                sender_public_key: alice.public_key().to_vec(),
                timestamp: now(),
                text: "**Group delivery**\n\n| Peer | State |\n|---|---|\n| Bob | offline |".into(),
                has_attachment: true,
            },
        )
        .await
        .expect("deposit encrypted group message");
        send_attachment_frames(
            alice_vault.clone(),
            PHRASE.into(),
            conversation.clone(),
            GROUP_MESSAGE_ID.into(),
            group_manifest,
            group_chunks,
        )
        .await
        .expect("deposit end-to-end encrypted group image chunks");
        assert_eq!(
            mailbox_message_count(address, &alice, &config).await,
            3 + (group_chunk_count + direct_chunk_count) as u64
        );
        let alice_data = load_vault(&alice_vault, PHRASE).expect("reload Alice vault");
        for message_id in [MESSAGE_ID, SECOND_MESSAGE_ID] {
            let sent = alice_data
                .messages
                .iter()
                .find(|message| message.id == message_id)
                .expect("concurrent direct message remains in the vault");
            assert_eq!(sent.delivery, DeliveryState::MailboxStored);
            assert!(
                sent.delivery_events
                    .iter()
                    .any(|event| event.kind == DeliveryEventKind::Encrypted && event.verified)
            );
            assert_eq!(
                sent.delivery_events
                    .iter()
                    .filter(|event| {
                        event.kind == DeliveryEventKind::Deposited
                            && event.verified
                            && event.receipt_bytes.is_some()
                    })
                    .count(),
                2
            );
        }
        assert_eq!(
            alice_data.async_outbox.len(),
            3 + group_chunk_count + direct_chunk_count
        );
        let image_frames = alice_data
            .async_outbox
            .iter()
            .filter(|item| item.parent_message_id.as_deref() == Some(GROUP_MESSAGE_ID))
            .collect::<Vec<_>>();
        assert_eq!(image_frames.len(), group_chunk_count);
        assert!(image_frames.iter().all(|item| {
            item.envelope.is_empty()
                && item.attachment_id.as_deref() == Some("00112233445566778899aabbccddeeff")
                && item
                    .envelope_sha256
                    .as_ref()
                    .is_some_and(|digest| digest.len() == 64)
        }));
        assert_eq!(
            alice_data.group_deliveries[0].recipients[0].status,
            GroupRecipientStatus::Deposited
        );

        let (primary_poll, replica_poll) = tokio::join!(
            poll_inbox(
                bob_vault.clone(),
                PHRASE.into(),
                bob_data.mailbox_inboxes[0].clone(),
            ),
            poll_inbox(
                bob_vault.clone(),
                PHRASE.into(),
                bob_data.mailbox_inboxes[1].clone(),
            ),
        );
        assert_eq!(
            usize::from(primary_poll.is_ok()) + usize::from(replica_poll.is_ok()),
            1
        );
        let received = primary_poll
            .as_ref()
            .ok()
            .or_else(|| replica_poll.as_ref().ok())
            .expect("one concurrent poll commits");
        assert!(*received > 0);
        let mut received_total = *received;
        let conflict = primary_poll
            .as_ref()
            .err()
            .or_else(|| replica_poll.as_ref().err())
            .expect("stale mailbox poll is rejected");
        assert!(conflict.contains("revision conflict"));

        server1.stop();
        let mut pending_on_replica = mailbox_message_count(address2, &alice, &config2).await;
        for _ in 0..12 {
            if pending_on_replica == 0 {
                break;
            }
            received_total += poll_inbox(
                bob_vault.clone(),
                PHRASE.into(),
                bob_data.mailbox_inboxes[1].clone(),
            )
            .await
            .expect("resume and deduplicate envelopes from the surviving replica");
            pending_on_replica = mailbox_message_count(address2, &alice, &config2).await;
        }
        assert_eq!(pending_on_replica, 0, "replica inbox must be drained");
        assert_eq!(received_total, 3 + group_chunk_count + direct_chunk_count);
        assert!(matches!(
            poll_delivery_receipt(
                alice_vault.clone(),
                PHRASE.into(),
                conversation.clone(),
                MESSAGE_ID.into(),
            )
            .await
            .expect("verify Bob's receipt from the surviving replica"),
            DeliveryPoll::Delivered
        ));
        assert!(matches!(
            poll_delivery_receipt(
                alice_vault.clone(),
                PHRASE.into(),
                conversation.clone(),
                SECOND_MESSAGE_ID.into(),
            )
            .await
            .expect("verify concurrent message and attachment receipts"),
            DeliveryPoll::Delivered
        ));
        assert!(matches!(
            poll_delivery_receipt(
                alice_vault.clone(),
                PHRASE.into(),
                conversation.clone(),
                GROUP_MESSAGE_ID.into()
            )
            .await
            .expect("verify group receipt"),
            DeliveryPoll::Delivered
        ));

        let mut rotated_config = ServerConfig::load(&config_path).expect("load primary config");
        let old_receipt_key = rotated_config
            .receipt_signer()
            .expect("previous receipt key")
            .fingerprint();
        let new_receipt_key = rotated_config
            .rotate_receipt_key()
            .expect("rotate primary receipt key");
        rotated_config
            .save(&config_path)
            .expect("persist primary key rotation");
        let mut _restarted_server1 = start_server(&config_path);
        wait_for_server(address, &alice, config.noise_identity.public_key()).await;
        let mut duplicate_total = 0;
        while mailbox_message_count(address, &alice, &config).await > 0 {
            duplicate_total += poll_inbox(
                bob_vault.clone(),
                PHRASE.into(),
                bob_data.mailbox_inboxes[0].clone(),
            )
            .await
            .expect("acknowledge delayed copies without duplicating messages or images");
        }
        assert_eq!(duplicate_total, 0);
        let bob_data = load_vault(&bob_vault, PHRASE).expect("reload Bob vault");
        assert_eq!(bob_data.mailbox_inboxes[0].server_key_generation, 2);
        assert_eq!(bob_data.messages.len(), 3);
        let received_direct = bob_data
            .messages
            .iter()
            .find(|message| message.id == MESSAGE_ID)
            .expect("original direct message is retained");
        assert_eq!(received_direct.text, message);
        assert!(
            bob_data
                .messages
                .iter()
                .any(|message| message.conversation == group_conversation
                    && message.text.contains("Group delivery"))
        );
        let received_group_attachment = bob_data
            .attachments
            .iter()
            .find(|attachment| attachment.message_id == GROUP_MESSAGE_ID)
            .expect("offline group attachment manifest is saved");
        assert_eq!(
            received_group_attachment.mailbox_frame_receipts.len(),
            received_group_attachment.manifest.chunk_count as usize
        );
        let received_group_chunks = attachments::load_encrypted_chunks(
            &attachments::attachment_sidecar_path(&bob_vault),
            &received_group_attachment.manifest,
        )
        .expect("offline group chunks persist encrypted on disk");
        assert!(
            attachments::decrypt_image(&received_group_attachment.manifest, &received_group_chunks)
                .is_ok()
        );
        let received_direct_attachment = bob_data
            .attachments
            .iter()
            .find(|attachment| attachment.message_id == SECOND_MESSAGE_ID)
            .expect("offline direct-message attachment manifest is saved");
        assert_eq!(
            received_direct_attachment.mailbox_frame_receipts.len(),
            received_direct_attachment.manifest.chunk_count as usize
        );
        let received_direct_chunks = attachments::load_encrypted_chunks(
            &attachments::attachment_sidecar_path(&bob_vault),
            &received_direct_attachment.manifest,
        )
        .expect("offline direct-message chunks persist encrypted on disk");
        assert!(
            attachments::decrypt_image(
                &received_direct_attachment.manifest,
                &received_direct_chunks
            )
            .is_ok()
        );
        assert!(
            received_direct
                .delivery_events
                .iter()
                .any(|event| event.kind == DeliveryEventKind::Retrieved)
        );
        assert!(
            received_direct
                .delivery_events
                .iter()
                .any(
                    |event| event.kind == DeliveryEventKind::AuthenticatedAndSaved
                        && event.verified
                )
        );
        assert!(received_direct.delivery_events.iter().any(|event| {
            event.kind == DeliveryEventKind::RecipientConfirmed
                && event.verified
                && event.receipt_bytes.is_some()
        }));
        assert!(bob_data.pending_recipient_receipts.is_empty());
        assert_eq!(
            received_direct
                .delivery_events
                .iter()
                .filter(|event| event.kind == DeliveryEventKind::RecipientConfirmed)
                .count(),
            2
        );
        assert_eq!(mailbox_message_count(address, &alice, &config).await, 0);
        assert_eq!(mailbox_message_count(address2, &alice, &config2).await, 0);
        let alice_data = load_vault(&alice_vault, PHRASE).expect("reload delivered Alice vault");
        let acknowledged_direct = alice_data
            .messages
            .iter()
            .find(|message| message.id == MESSAGE_ID)
            .expect("original direct message remains in Alice's history");
        assert_eq!(acknowledged_direct.delivery, DeliveryState::Acknowledged);
        assert_eq!(
            alice_data.group_deliveries[0].recipients[0].status,
            GroupRecipientStatus::Received
        );
        assert_eq!(
            alice_data
                .messages
                .iter()
                .find(|message| message.id == GROUP_MESSAGE_ID)
                .unwrap()
                .delivery,
            DeliveryState::Acknowledged
        );
        assert!(acknowledged_direct.delivery_events.iter().any(|event| {
            event.kind == DeliveryEventKind::RecipientConfirmed
                && event.verified
                && event.receipt_bytes.is_some()
        }));
        assert!(alice_data.async_outbox.is_empty());
        assert!(
            attachments::load_mailbox_envelope(
                &attachments::attachment_sidecar_path(&alice_vault),
                "00112233445566778899aabbccddeeff",
                &conversation,
                &format!("{GROUP_MESSAGE_ID}00000000"),
            )
            .is_err()
        );

        let mut alice_data = load_vault(&alice_vault, PHRASE).expect("reload Alice vault");
        alice_data.messages.push(StoredMessage {
            conversation: conversation.clone(),
            id: PARTIAL_RETRY_MESSAGE_ID.into(),
            outgoing: true,
            text: "Reprise de la copie après indisponibilité.".into(),
            delivery: DeliveryState::Queued,
            timestamp: now(),
            delivery_events: Vec::new(),
            received_ciphertext_sha256: None,
        });
        save_vault(&alice_vault, &mut alice_data, PHRASE).expect("save partial retry message");
        _restarted_server1.stop();
        send(
            alice_vault.clone(),
            PHRASE.into(),
            conversation.clone(),
            PARTIAL_RETRY_MESSAGE_ID.into(),
        )
        .await
        .expect("deposit to the surviving replica when the primary is unavailable");
        let alice_data = load_vault(&alice_vault, PHRASE).expect("reload partial deposit");
        let partial_message = alice_data
            .messages
            .iter()
            .find(|message| message.id == PARTIAL_RETRY_MESSAGE_ID)
            .expect("partial retry message");
        assert_eq!(partial_message.delivery, DeliveryState::MailboxStored);
        assert_eq!(
            partial_message
                .delivery_events
                .iter()
                .filter(|event| event.kind == DeliveryEventKind::Deposited)
                .count(),
            1
        );
        assert_eq!(mailbox_message_count(address2, &alice, &config2).await, 1);
        let _restarted_server1 = start_server(&config_path);
        wait_for_server(address, &alice, config.noise_identity.public_key()).await;
        send(
            alice_vault.clone(),
            PHRASE.into(),
            conversation.clone(),
            PARTIAL_RETRY_MESSAGE_ID.into(),
        )
        .await
        .expect("retry deposit to the primary without changing the ciphertext");
        let alice_data = load_vault(&alice_vault, PHRASE).expect("reload replicated deposit");
        let partial_message = alice_data
            .messages
            .iter()
            .find(|message| message.id == PARTIAL_RETRY_MESSAGE_ID)
            .expect("replicated retry message");
        assert_eq!(
            partial_message
                .delivery_events
                .iter()
                .filter(|event| event.kind == DeliveryEventKind::Deposited)
                .count(),
            2
        );
        assert_eq!(
            alice_data.contacts[0]
                .mailbox_route
                .as_ref()
                .expect("primary route")
                .server_key_generation,
            2
        );
        assert_ne!(old_receipt_key, new_receipt_key);
        assert_eq!(mailbox_message_count(address, &alice, &config).await, 1);
        assert_eq!(mailbox_message_count(address2, &alice, &config2).await, 1);

        let mut alice_data = load_vault(&alice_vault, PHRASE).expect("reload Alice vault");
        alice_data.messages.push(StoredMessage {
            conversation: conversation.clone(),
            id: EXPIRED_MESSAGE_ID.into(),
            outgoing: true,
            text: "Ce message expire dans le scénario de test.".into(),
            delivery: DeliveryState::Pending,
            timestamp: now(),
            delivery_events: Vec::new(),
            received_ciphertext_sha256: None,
        });
        save_vault(&alice_vault, &mut alice_data, PHRASE).expect("save expiring message");
        send(
            alice_vault.clone(),
            PHRASE.into(),
            conversation.clone(),
            EXPIRED_MESSAGE_ID.into(),
        )
        .await
        .expect("deposit message that will expire");
        let connection = rusqlite::Connection::open(config.data_dir.join("mailbox.sqlite3"))
            .expect("open fixture mailbox database");
        connection
            .execute(
                "UPDATE envelopes SET expires_at=0 WHERE message_id=?1",
                [EXPIRED_MESSAGE_ID],
            )
            .expect("expire fixture envelope");
        drop(connection);
        let connection2 = rusqlite::Connection::open(config2.data_dir.join("mailbox.sqlite3"))
            .expect("open replica mailbox database");
        connection2
            .execute(
                "UPDATE envelopes SET expires_at=0 WHERE message_id=?1",
                [EXPIRED_MESSAGE_ID],
            )
            .expect("expire replica fixture envelope");
        drop(connection2);
        assert!(matches!(
            poll_delivery_receipt(
                alice_vault.clone(),
                PHRASE.into(),
                conversation,
                EXPIRED_MESSAGE_ID.into(),
            )
            .await
            .expect("verify signed expiration"),
            DeliveryPoll::Expired
        ));
        let alice_data = load_vault(&alice_vault, PHRASE).expect("reload expired Alice vault");
        assert!(alice_data.messages.iter().any(|message| {
            message.id == EXPIRED_MESSAGE_ID && message.delivery == DeliveryState::Expired
        }));
        assert!(
            !alice_data
                .async_outbox
                .iter()
                .any(|item| item.message_id == EXPIRED_MESSAGE_ID)
        );
    }

    async fn wait_for_server(address: SocketAddr, identity: &Identity, noise_key: &[u8]) {
        for _ in 0..100 {
            if let Ok(mut channel) = server::connect(address, identity, noise_key).await
                && server::start(&mut channel).await.is_ok()
                && matches!(
                    server::request(&mut channel, &Request::Health).await,
                    Ok(Response::Health { .. })
                )
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("separate mailbox process failed to start");
    }

    fn raise_test_rate_limits(config: &mut ServerConfig) {
        config.rate_limits.global_requests_per_minute = 100_000;
        config.rate_limits.global_burst = 10_000;
        config.rate_limits.source_requests_per_minute = 100_000;
        config.rate_limits.source_burst = 10_000;
        config.rate_limits.identity_requests_per_minute = 100_000;
        config.rate_limits.identity_burst = 10_000;
        config.rate_limits.mailbox_requests_per_minute = 100_000;
        config.rate_limits.mailbox_burst = 10_000;
    }

    fn start_server(config_path: &std::path::Path) -> ServerProcess {
        let child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("async_mailbox::tests::mailbox_server_process")
            .arg("--nocapture")
            .env("AKRAT_DESKTOP_TEST_SERVER_CONFIG", config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn separate mailbox process");
        ServerProcess(child)
    }

    async fn mailbox_message_count(
        address: SocketAddr,
        identity: &Identity,
        config: &ServerConfig,
    ) -> u64 {
        let mut channel = server::connect(address, identity, config.noise_identity.public_key())
            .await
            .expect("connect to mailbox server");
        server::start(&mut channel)
            .await
            .expect("start mailbox protocol");
        match server::request(&mut channel, &Request::Health)
            .await
            .expect("mailbox health")
        {
            Response::Health { messages, .. } => messages,
            other => panic!("unexpected mailbox health response: {other:?}"),
        }
    }
}
