use akrat_core::{
    AsyncOutboxItem, AsyncProtocolState, DeliveryActor, DeliveryEvent, DeliveryEventKind,
    DeliveryState, GroupChange, GroupEvent, GroupEventOutboxRef, GroupMessage,
    GroupRecipientStatus, GroupState, Identity, MailboxInbox, MailboxRoute,
    PendingRecipientReceipt, StoredMessage, VaultData, async_crypto, load_vault, save_vault,
};
use akrat_mailbox::server::{self, Request, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum DeliveryPoll {
    Pending,
    Delivered,
    Expired,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AsyncEnvelope {
    version: u8,
    sender_public_key: Vec<u8>,
    ciphertext: async_crypto::AsyncCiphertext,
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
}

pub async fn send(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message_id: String,
) -> Result<(), String> {
    send_application(path, passphrase, conversation, message_id, None, None).await
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
        Some(event),
        None,
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
        None,
        Some(message),
    )
    .await
}

async fn send_application(
    path: PathBuf,
    passphrase: String,
    conversation: String,
    message_id: String,
    group_event: Option<GroupEvent>,
    group_message: Option<GroupMessage>,
) -> Result<(), String> {
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
    let message_text = if group_message.is_some() || group_event.is_some() {
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
        item.envelope.clone()
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
        let bundle =
            verified_bundle.ok_or("aucune Mailbox configurée ne fournit un bundle valide")?;
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
        let envelope = serde_json::to_vec(&AsyncEnvelope {
            version: 1,
            sender_public_key: identity.public_key().to_vec(),
            ciphertext,
        })
        .map_err(|e| e.to_string())?;
        if let Some(message) = data.messages.iter_mut().find(|message| {
            message.conversation == conversation && message.id == message_id && message.outgoing
        }) {
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
            envelope: envelope.clone(),
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
        if let Some(message) = data.messages.iter_mut().find(|message| {
            message.conversation == conversation && message.id == message_id && message.outgoing
        }) {
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
    let Response::Fetch { envelopes } = response else {
        return Err(format!("mailbox fetch failed: {response:?}"));
    };
    let mut received = 0usize;
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
        if envelope.version != 1 {
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
        if let Some(existing) = data.messages.iter().find(|message| {
            message.id == item.message_id
                && !message.outgoing
                && message.received_ciphertext_sha256.as_deref() == Some(ciphertext_digest.as_str())
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
        let Ok((plaintext, next_state)) =
            async_crypto::decrypt(&identity, state, &contact.public_key, &envelope.ciphertext)
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
        if payload.group_event.is_none()
            && payload.group_message.is_none()
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
        if payload.group_event.is_none() {
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
    let pending = data
        .pending_recipient_receipts
        .iter()
        .filter(|item| item.mailbox_id == inbox.mailbox_id)
        .cloned()
        .collect::<Vec<_>>();
    for receipt in pending {
        if send_recipient_receipt(&mut channel, &receipt).await.is_ok() {
            record_recipient_confirmation(&mut data, &identity, &receipt)?;
            data.pending_recipient_receipts.retain(|old| {
                !(old.mailbox_id == receipt.mailbox_id
                    && old.receipt.message_id == receipt.receipt.message_id)
            });
            save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
        }
    }
    Ok(received)
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
    else {
        return Err("message ciphertext missing from encrypted outbox".into());
    };
    let expected_digest = hex::encode(Sha256::digest(&outbox.envelope));
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
                if let Some(message) = data.messages.iter_mut().find(|message| {
                    message.conversation == conversation
                        && message.id == message_id
                        && message.outgoing
                }) {
                    message.delivery = DeliveryState::Acknowledged;
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
                mark_group_receipt(
                    &mut data,
                    &contact,
                    &message_id,
                    receipt.received_at,
                    &receipt_digest,
                    &receipt_bytes,
                );
                data.async_outbox.retain(|item| {
                    !(item.conversation == conversation && item.message_id == message_id)
                });
                save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
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
                        && message.id == message_id
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
            message.conversation == conversation && message.id == message_id && message.outgoing
        }) {
            message.delivery = DeliveryState::Expired;
        }
        data.async_outbox
            .retain(|item| !(item.conversation == conversation && item.message_id == message_id));
        save_vault(&path, &mut data, &passphrase).map_err(|e| e.to_string())?;
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
    if let Some(message) = data
        .messages
        .iter_mut()
        .find(|message| message.id == pending.receipt.message_id && !message.outgoing)
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
        MailboxRoute,
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
        let config = ServerConfig::initialize(
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
        let config2 = ServerConfig::initialize(
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
                    mailbox_id: mailbox_id2,
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
            },
        )
        .await
        .expect("deposit encrypted group message");
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
        assert_eq!(alice_data.async_outbox.len(), 3);
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
        assert_eq!(*received, 3);
        let conflict = primary_poll
            .as_ref()
            .err()
            .or_else(|| replica_poll.as_ref().err())
            .expect("stale mailbox poll is rejected");
        assert!(conflict.contains("revision conflict"));

        server1.stop();
        let received = poll_inbox(
            bob_vault.clone(),
            PHRASE.into(),
            bob_data.mailbox_inboxes[1].clone(),
        )
        .await
        .expect("deduplicate and acknowledge the surviving replica");
        assert_eq!(received, 0);
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
            .expect("verify concurrent message receipt"),
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
        let duplicate = poll_inbox(
            bob_vault.clone(),
            PHRASE.into(),
            bob_data.mailbox_inboxes[0].clone(),
        )
        .await
        .expect("acknowledge the delayed copy without duplicating the message");
        assert_eq!(duplicate, 0);
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
