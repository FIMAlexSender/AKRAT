#![cfg_attr(all(windows, not(feature = "mobile")), windows_subsystem = "windows")]

mod async_mailbox;
mod runtime;
mod updater;
mod vault_catalog;

use akrat_core::attachments::{self, AttachmentChunk, AttachmentManifest};
use akrat_core::{
    Contact, DeliveryActor, DeliveryEvent, DeliveryEventKind, DeliveryState, GroupChange,
    GroupEvent, GroupMember, GroupMessage, GroupMessageDelivery, GroupRecipientDelivery,
    GroupRecipientStatus, GroupRole, GroupState, Identity, Invitation, MailboxInbox, MailboxRoute,
    RelaySettings, StoredAttachment, StoredMessage, VaultData, VaultFileLock, load_vault,
    markdown::TableAlignment,
    markdown::{MarkdownNode, MarkdownNodeKind, parse_markdown},
    save_vault,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use dioxus::prelude::*;
#[cfg(not(target_os = "android"))]
use directories::ProjectDirs;
use runtime::{SessionHandle, UiEvent};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const VAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const NOTICE_LIFETIME: Duration = Duration::from_secs(4);

const LOGO_DATA_URI: &str = concat!(
    "data:image/png;base64,",
    include_str!("../assets/akrat-logo.b64")
);

#[cfg(all(
    feature = "desktop",
    not(feature = "mobile"),
    not(any(target_os = "android", target_os = "ios"))
))]
fn main() {
    use dioxus_desktop::{Config, LogicalSize, WindowBuilder, tao::window::Icon};
    let icon = dioxus_desktop::icon_from_memory::<Icon>(include_bytes!("../assets/akrat-logo.png"))
        .expect("Le logo AKRAT doit être une image PNG valide");
    let window = WindowBuilder::new()
        .with_title("AKRAT · Messagerie P2P")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1000.0, 680.0))
        .with_window_icon(Some(icon.clone()));
    #[cfg(target_os = "windows")]
    let window = {
        use dioxus_desktop::tao::platform::windows::WindowBuilderExtWindows;
        window.with_taskbar_icon(Some(icon))
    };
    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_menu(None).with_window(window))
        .launch(App);
}

#[cfg(any(feature = "mobile", target_os = "android", target_os = "ios"))]
fn main() {
    dioxus::LaunchBuilder::mobile().launch(App);
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Messages,
    Network,
    Contacts,
    Identities,
    Settings,
}

#[derive(Clone, Copy, PartialEq)]
enum VaultGateTab {
    Existing,
    Create,
}

#[derive(Clone, Copy)]
struct VaultCreationSignals {
    path: Signal<PathBuf>,
    paths: Signal<Vec<PathBuf>>,
    path_input: Signal<String>,
    session_phrase: Signal<String>,
    vault: Signal<Option<VaultData>>,
    create_phrase: Signal<String>,
    confirm_phrase: Signal<String>,
    notice: Signal<String>,
}

struct GroupUiContext {
    path: PathBuf,
    passphrase: Signal<String>,
    vault: Signal<Option<VaultData>>,
    active_conversation: Signal<Option<String>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    notice: Signal<String>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
}

struct ImageActionContext {
    path: PathBuf,
    passphrase: Signal<String>,
    vault: Signal<Option<VaultData>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    notice: Signal<String>,
    trace: Signal<Vec<String>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
}

struct GroupManagementContext {
    path: PathBuf,
    passphrase: Signal<String>,
    vault: Signal<Option<VaultData>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
    notice: Signal<String>,
}

#[component]
fn App() -> Element {
    let catalog_state = use_hook(|| {
        let default = default_vault_path();
        let mut state = vault_catalog::load(&default);
        if let Some(selected) = vault_catalog::preferred_existing_path(&state.paths)
            && let Some(index) = state
                .paths
                .iter()
                .position(|candidate| candidate == &selected)
            && index > 0
        {
            let selected = state.paths.remove(index);
            state.paths.insert(0, selected);
            if let Err(error) = vault_catalog::save(&default, &state.paths) {
                state.warning = Some(match state.warning.take() {
                    Some(warning) => format!("{warning} {error}"),
                    None => format!(
                        "Sélection restaurée pour cette ouverture, mais impossible de la mémoriser : {error}"
                    ),
                });
            }
        }
        state
    });
    let startup_path = vault_catalog::preferred_existing_path(&catalog_state.paths)
        .unwrap_or_else(default_vault_path);
    let path = use_signal(|| startup_path.clone());
    let vault_paths = use_signal(|| catalog_state.paths.clone());
    let vault_path_input = use_signal(|| startup_path.display().to_string());
    let mut vault = use_signal(|| None::<VaultData>);
    let mut passphrase = use_signal(String::new);
    let identity_name = use_signal(String::new);
    let import_uri = use_signal(String::new);
    let contact_name = use_signal(String::new);
    let invitation_result = use_signal(String::new);
    let mut notice = use_signal(|| catalog_state.warning.clone().unwrap_or_default());
    let mut last_activity = use_signal(Instant::now);
    let mut update_status = use_signal(|| updater::UpdateStatus::Checking);
    let mut page = use_signal(|| Page::Messages);
    let mut sessions = use_signal(HashMap::<String, SessionHandle>::new);
    let mut listen_stops = use_signal(HashMap::<String, tokio::sync::watch::Sender<bool>>::new);
    let mut applied_network_contacts = use_signal(Vec::<Contact>::new);
    let mut applied_relay_settings = use_signal(RelaySettings::default);
    let mut active_conversation = use_signal(|| None::<String>);
    let draft = use_signal(String::new);
    let mut trace = use_signal(|| {
        vec![
            "Interface prête".to_string(),
            "Coffre local déverrouillé".to_string(),
        ]
    });
    let (sender, receiver) = use_hook(|| {
        let (sender, receiver) = mpsc::unbounded_channel::<UiEvent>();
        (
            sender,
            std::sync::Arc::new(tokio::sync::Mutex::new(receiver)),
        )
    });
    let event_sender = use_signal(|| sender);

    use_effect(move || {
        let snapshot = vault.read().as_ref().map(|data| {
            let retry_targets = data
                .messages
                .iter()
                .filter(|message| message.outgoing && message.delivery.needs_delivery())
                .filter_map(|message| {
                    let (identity_id, fingerprint) = message.conversation.split_once(':')?;
                    Some((identity_id.to_string(), fingerprint.to_string()))
                })
                .collect::<std::collections::HashSet<_>>();
            (
                data.identities
                    .iter()
                    .map(Identity::detached_copy)
                    .collect::<Vec<_>>(),
                data.contacts
                    .iter()
                    .filter(|contact| contact.manually_verified)
                    .cloned()
                    .collect::<Vec<_>>(),
                retry_targets,
                data.relay_settings.clone(),
            )
        });
        if let Some((identities, contacts, retry_targets, relay_settings)) = snapshot {
            let contacts_changed = *applied_network_contacts.read() != contacts;
            let relays_changed = *applied_relay_settings.read() != relay_settings;
            if relays_changed {
                for stop in listen_stops.read().values() {
                    let _ = stop.send(true);
                }
                listen_stops.write().clear();
            }
            let active = listen_stops.read().keys().cloned().collect::<Vec<_>>();
            for identity in &identities {
                if !active.contains(&identity.id) {
                    let stop = runtime::listen(
                        identity.detached_copy(),
                        contacts.clone(),
                        relay_settings.clone(),
                        event_sender.read().clone(),
                    );
                    listen_stops.write().insert(identity.id.clone(), stop);
                } else if contacts_changed {
                    runtime::update_contacts(&identity.id, contacts.clone());
                }
                for contact in &contacts {
                    if retry_targets.contains(&(identity.id.clone(), contact.fingerprint.clone())) {
                        runtime::connect(
                            identity.detached_copy(),
                            contact.clone(),
                            event_sender.read().clone(),
                        );
                    } else {
                        runtime::cancel_retry(&identity.id, &contact.fingerprint);
                    }
                }
            }
            if contacts_changed {
                applied_network_contacts.set(contacts);
            }
            if relays_changed {
                applied_relay_settings.set(relay_settings);
            }
        } else {
            let stops = listen_stops.read().values().cloned().collect::<Vec<_>>();
            for stop in stops {
                let _ = stop.send(true);
            }
            if !listen_stops.read().is_empty() {
                listen_stops.write().clear();
            }
            if !applied_network_contacts.read().is_empty() {
                applied_network_contacts.set(Vec::new());
            }
        }
    });

    use_future(move || async move {
        match updater::check_latest().await {
            Ok(Some(release)) if cfg!(target_os = "android") => {
                notice.set(format!(
                    "AKRAT v{} est disponible · Coffre > Mises à jour",
                    release.version
                ));
                update_status.set(updater::UpdateStatus::Available(release));
            }
            Ok(Some(release)) => {
                let version = release.version.clone();
                notice.set(format!("Installation de la mise à jour AKRAT v{version}…"));
                update_status.set(updater::UpdateStatus::Installing);
                match updater::install(release).await {
                    Ok(()) => {}
                    Err(error) => {
                        update_status.set(updater::UpdateStatus::Failed(error.clone()));
                        notice.set(format!("Mise à jour automatique impossible : {error}"));
                    }
                }
            }
            Ok(None) => update_status.set(updater::UpdateStatus::Current),
            Err(error) => update_status.set(updater::UpdateStatus::Failed(error)),
        }
    });

    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let (
                path_value,
                phrase,
                inboxes,
                queued_mailbox_messages,
                pending_receipts,
                queued_group_messages,
                group_receipts,
            ) = {
                let snapshot = vault.read();
                let Some(data) = snapshot.as_ref() else {
                    continue;
                };
                let mut queued_group_messages = Vec::new();
                let mut group_receipts = Vec::new();
                for delivery in &data.group_deliveries {
                    let Some(group) = data
                        .groups
                        .iter()
                        .find(|group| group.group_id == delivery.group_id)
                    else {
                        continue;
                    };
                    let Some(message) = data.messages.iter().find(|message| {
                        message.conversation == format!("group:{}", delivery.group_id)
                            && message.id == delivery.message_id
                            && message.outgoing
                    }) else {
                        continue;
                    };
                    let Some(identity) = data.identities.iter().find(|identity| {
                        group.members.iter().any(|member| {
                            member.accepted && member.public_key == identity.public_key()
                        })
                    }) else {
                        continue;
                    };
                    for recipient in &delivery.recipients {
                        let Some(contact) = data.contacts.iter().find(|contact| {
                            contact.fingerprint == recipient.fingerprint
                                && contact.manually_verified
                                && contact.mailbox_route.is_some()
                        }) else {
                            continue;
                        };
                        let direct_conversation =
                            format!("{}:{}", identity.id, contact.fingerprint);
                        if recipient.status == GroupRecipientStatus::Deposited {
                            group_receipts
                                .push((direct_conversation.clone(), delivery.message_id.clone()));
                        }
                        let retry_elapsed =
                            recipient.updated_at.saturating_add(60) <= now_seconds();
                        if group.members.iter().any(|member| {
                            member.accepted && member.fingerprint == recipient.fingerprint
                        }) && (recipient.status == GroupRecipientStatus::Pending
                            || (recipient.status == GroupRecipientStatus::Sent && retry_elapsed))
                        {
                            let attachment = data
                                .attachments
                                .iter()
                                .find(|attachment| {
                                    attachment.conversation == format!("group:{}", group.group_id)
                                        && attachment.message_id == message.id
                                })
                                .and_then(|attachment| {
                                    let sidecar =
                                        attachments::attachment_sidecar_path(&path.read());
                                    attachments::load_encrypted_chunks(
                                        &sidecar,
                                        &attachment.manifest,
                                    )
                                    .ok()
                                    .map(|chunks| (attachment.manifest.clone(), chunks))
                                });
                            queued_group_messages.push((
                                direct_conversation,
                                GroupMessage {
                                    version: 1,
                                    group_id: group.group_id.clone(),
                                    epoch: group.epoch,
                                    sequence: group.sequence,
                                    message_id: message.id.clone(),
                                    sender_public_key: identity.public_key().to_vec(),
                                    timestamp: message.timestamp,
                                    text: message.text.clone(),
                                    has_attachment: data.attachments.iter().any(|attachment| {
                                        attachment.conversation
                                            == format!("group:{}", group.group_id)
                                            && attachment.message_id == message.id
                                    }),
                                },
                                attachment,
                            ));
                        }
                    }
                }
                (
                    path.read().clone(),
                    passphrase.read().clone(),
                    data.mailbox_inboxes.clone(),
                    data.messages
                        .iter()
                        .filter(|message| {
                            message.outgoing
                                && matches!(
                                    message.delivery,
                                    DeliveryState::Queued | DeliveryState::MailboxStored
                                )
                                && message.conversation.split_once(':').is_some_and(
                                    |(_, fingerprint)| {
                                        data.contacts.iter().any(|contact| {
                                            contact.manually_verified
                                                && contact.fingerprint == fingerprint
                                                && contact.mailbox_route.is_some()
                                        })
                                    },
                                )
                        })
                        .map(|message| (message.conversation.clone(), message.id.clone()))
                        .collect::<Vec<_>>(),
                    data.messages
                        .iter()
                        .filter(|message| {
                            message.outgoing
                                && message.delivery == DeliveryState::MailboxStored
                                && !message.conversation.starts_with("group:")
                        })
                        .map(|message| (message.conversation.clone(), message.id.clone()))
                        .collect::<Vec<_>>(),
                    queued_group_messages,
                    group_receipts,
                )
            };
            let mut changed = false;
            for inbox in inboxes {
                if matches!(async_mailbox::poll_inbox(path_value.clone(), phrase.clone(), inbox).await, Ok(count) if count > 0)
                {
                    changed = true;
                }
            }
            for (conversation, message_id) in queued_mailbox_messages {
                if async_mailbox::send(path_value.clone(), phrase.clone(), conversation, message_id)
                    .await
                    .is_ok()
                {
                    changed = true;
                }
            }
            for (conversation, message_id) in pending_receipts {
                if matches!(
                    async_mailbox::poll_delivery_receipt(
                        path_value.clone(),
                        phrase.clone(),
                        conversation,
                        message_id
                    )
                    .await,
                    Ok(async_mailbox::DeliveryPoll::Delivered
                        | async_mailbox::DeliveryPoll::Expired,)
                ) {
                    changed = true;
                }
            }
            for (conversation, message, attachment) in queued_group_messages {
                let mut result = async_mailbox::send_group_message(
                    path_value.clone(),
                    phrase.clone(),
                    conversation.clone(),
                    message.clone(),
                )
                .await;
                if result.is_ok()
                    && let Some((manifest, chunks)) = attachment
                {
                    result = async_mailbox::send_attachment_frames(
                        path_value.clone(),
                        phrase.clone(),
                        conversation,
                        message.message_id,
                        manifest,
                        chunks,
                    )
                    .await;
                }
                if result.is_ok() {
                    changed = true;
                }
            }
            for (conversation, message_id) in group_receipts {
                if matches!(
                    async_mailbox::poll_delivery_receipt(
                        path_value.clone(),
                        phrase.clone(),
                        conversation,
                        message_id
                    )
                    .await,
                    Ok(async_mailbox::DeliveryPoll::Delivered
                        | async_mailbox::DeliveryPoll::Expired)
                ) {
                    changed = true;
                }
            }
            if changed && let Ok(data) = load_vault(&path_value, &phrase) {
                vault.set(Some(data));
            }
        }
    });

    use_future(move || {
        let receiver = receiver.clone();
        async move {
            loop {
                let event = receiver.lock().await.recv().await;
                let Some(event) = event else {
                    break;
                };
                match event {
                    UiEvent::Trace(line) => push_trace(&mut trace, line),
                    UiEvent::Ready {
                        conversation,
                        peer_name,
                        handle,
                    } => {
                        sessions
                            .write()
                            .insert(conversation.clone(), handle.clone());
                        active_conversation.set(Some(conversation.clone()));
                        page.set(Page::Messages);
                        push_trace(&mut trace, format!("Conversation active · {peer_name}"));
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(data) = load_vault(&vault_path, &phrase)
                            && let Some(conversation) = active_conversation.read().as_ref()
                        {
                            for message in data.messages.iter().filter(|message| {
                                message.conversation == *conversation
                                    && message.outgoing
                                    && message.delivery.needs_delivery()
                            }) {
                                let attachment = data.attachments.iter().find(|attachment| {
                                    attachment.conversation == message.conversation
                                        && attachment.message_id == message.id
                                });
                                let resumed = if let Some(attachment) = attachment {
                                    if let Ok(chunks) = attachments::load_encrypted_chunks(
                                        &attachments::attachment_sidecar_path(&vault_path),
                                        &attachment.manifest,
                                    ) {
                                        let mut all_queued = true;
                                        for chunk in chunks {
                                            if handle
                                                .send_attachment_chunk(
                                                    message.id.clone(),
                                                    attachment.manifest.clone(),
                                                    chunk,
                                                )
                                                .is_err()
                                            {
                                                all_queued = false;
                                                break;
                                            }
                                        }
                                        all_queued
                                    } else {
                                        false
                                    }
                                } else {
                                    handle
                                        .send_text(message.id.clone(), message.text.clone())
                                        .is_ok()
                                };
                                if resumed {
                                    push_trace(
                                        &mut trace,
                                        format!(
                                            "Reprise d’un message · {}",
                                            &message.id[..8.min(message.id.len())]
                                        ),
                                    );
                                }
                            }
                        }
                        sync_group_on_ready(&vault_path, &phrase, &conversation, &handle);
                    }
                    UiEvent::Transmitted { conversation, id } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            update_delivery(&mut data, &conversation, &id, DeliveryState::Sent);
                            if save_vault(&vault_path, &mut data, &phrase).is_ok() {
                                vault.set(Some(data));
                            }
                        }
                        push_trace(
                            &mut trace,
                            format!("Message {} chiffré et transmis", &id[..8.min(id.len())]),
                        );
                    }
                    UiEvent::Incoming {
                        conversation,
                        id,
                        text,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        let mut persisted = false;
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            if !data.messages.iter().any(|message| {
                                message.conversation == conversation
                                    && message.id == id
                                    && !message.outgoing
                            }) {
                                data.messages.push(runtime::received_message(
                                    conversation.clone(),
                                    id.clone(),
                                    text,
                                ));
                                persisted = save_vault(&vault_path, &mut data, &phrase).is_ok();
                                if persisted {
                                    vault.set(Some(data));
                                }
                            } else {
                                persisted = true;
                            }
                        }
                        if persisted {
                            if let Some(handle) = sessions.read().get(&conversation) {
                                let _ = handle.acknowledge(id.clone());
                            }
                            push_trace(
                                &mut trace,
                                format!(
                                    "Message authentifié, déchiffré et enregistré · {}",
                                    &id[..8.min(id.len())]
                                ),
                            );
                        } else {
                            push_trace(
                                &mut trace,
                                "Échec de sauvegarde · aucun accusé envoyé".into(),
                            );
                        }
                    }
                    UiEvent::IncomingGroupEvent {
                        conversation,
                        event,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        match apply_incoming_group_event(&vault_path, &phrase, &conversation, event)
                        {
                            Ok(data) => {
                                broadcast_group_events(&data, &sessions.read());
                                vault.set(Some(data));
                                push_trace(
                                    &mut trace,
                                    "Événement de groupe signé · état validé et enregistré".into(),
                                );
                            }
                            Err(error) => push_trace(
                                &mut trace,
                                format!("Événement de groupe refusé · {error}"),
                            ),
                        }
                    }
                    UiEvent::IncomingGroupMessage {
                        conversation,
                        message,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        match store_incoming_group_message(
                            &vault_path,
                            &phrase,
                            &conversation,
                            message.clone(),
                        ) {
                            Ok((data, accepted, own_public_key)) => {
                                vault.set(Some(data));
                                if accepted && !message.has_attachment {
                                    if let Some(handle) = sessions.read().get(&conversation) {
                                        let _ = handle.acknowledge_group_message(
                                            message.group_id,
                                            message.message_id,
                                            own_public_key,
                                        );
                                    }
                                    push_trace(
                                        &mut trace,
                                        "Message de groupe authentifié · enregistré dans le coffre"
                                            .into(),
                                    );
                                }
                            }
                            Err(error) => push_trace(
                                &mut trace,
                                format!("Message de groupe refusé · {error}"),
                            ),
                        }
                    }
                    UiEvent::IncomingRelayEvidence {
                        conversation,
                        evidence,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            let Some(pin) = data.relay_settings.identity_pins.iter().find(|pin| {
                                pin.relay_url == evidence.relay_url
                                    && pin
                                        .fingerprint
                                        .eq_ignore_ascii_case(&evidence.first.fingerprint)
                            }) else {
                                push_trace(
                                    &mut trace,
                                    format!(
                                        "Preuve reçue depuis {conversation} mais non enregistrée · identité de relais non épinglée sur cet appareil"
                                    ),
                                );
                                continue;
                            };
                            if akrat_trust::verify_relay_equivocation_evidence(
                                &evidence,
                                &pin.fingerprint,
                            )
                            .is_err()
                            {
                                push_trace(&mut trace, "Preuve partagée refusée · elle ne correspond pas à l’identité de relais épinglée".into());
                                continue;
                            }
                            if data.relay_settings.verified_evidence.contains(&evidence) {
                                push_trace(
                                    &mut trace,
                                    "Preuve de relais déjà connue · doublon ignoré".into(),
                                );
                                continue;
                            }
                            if data.relay_settings.verified_evidence.len() >= 64 {
                                push_trace(
                                    &mut trace,
                                    "Preuve vérifiée mais non conservée · limite locale atteinte"
                                        .into(),
                                );
                                continue;
                            }
                            data.relay_settings.verified_evidence.push(evidence.clone());
                            if save_vault(&vault_path, &mut data, &phrase).is_ok() {
                                vault.set(Some(data));
                                let forwarded = runtime::gossip_relay_evidence(
                                    &sessions.read(),
                                    &conversation,
                                    evidence,
                                );
                                push_trace(
                                    &mut trace,
                                    format!(
                                        "Preuve de relais vérifiée et enregistrée depuis {conversation} · propagée à {forwarded} autre(s) session(s) chiffrée(s) · décision locale inchangée"
                                    ),
                                );
                            } else {
                                push_trace(
                                    &mut trace,
                                    "Preuve vérifiée mais enregistrement impossible".into(),
                                );
                            }
                        }
                    }
                    UiEvent::IncomingAttachmentChunk {
                        conversation,
                        message_id,
                        manifest,
                        chunk,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        let group_id = manifest
                            .conversation_id
                            .strip_prefix("group:")
                            .map(str::to_string);
                        match store_incoming_attachment_chunk(
                            &vault_path,
                            &phrase,
                            &conversation,
                            &message_id,
                            manifest,
                            chunk,
                        ) {
                            Ok(Some(data)) => {
                                let local_key = conversation
                                    .split_once(':')
                                    .and_then(|(identity_id, _)| {
                                        data.identities
                                            .iter()
                                            .find(|identity| identity.id == identity_id)
                                    })
                                    .map(|identity| identity.public_key().to_vec());
                                vault.set(Some(data));
                                if let Some(handle) = sessions.read().get(&conversation) {
                                    if let (Some(group_id), Some(local_key)) = (group_id, local_key)
                                    {
                                        let _ = handle.acknowledge_group_message(
                                            group_id,
                                            message_id.clone(),
                                            local_key,
                                        );
                                    } else {
                                        let _ = handle.acknowledge(message_id.clone());
                                    }
                                }
                                push_trace(
                                    &mut trace,
                                    format!(
                                        "Image authentifiée et enregistrée · {}",
                                        &message_id[..8.min(message_id.len())]
                                    ),
                                );
                            }
                            Ok(None) => {}
                            Err(error) => {
                                push_trace(&mut trace, format!("Pièce jointe refusée · {error}"))
                            }
                        }
                    }
                    UiEvent::IncomingGroupAcknowledgement {
                        conversation,
                        group_id,
                        message_id,
                        recipient_public_key,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        match store_group_acknowledgement(
                            &vault_path,
                            &phrase,
                            &conversation,
                            &group_id,
                            &message_id,
                            &recipient_public_key,
                        ) {
                            Ok(data) => vault.set(Some(data)),
                            Err(error) => {
                                push_trace(&mut trace, format!("Accusé de groupe refusé · {error}"))
                            }
                        }
                    }
                    UiEvent::Acknowledged { conversation, id } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            update_delivery(
                                &mut data,
                                &conversation,
                                &id,
                                DeliveryState::Acknowledged,
                            );
                            if save_vault(&vault_path, &mut data, &phrase).is_ok() {
                                vault.set(Some(data));
                            }
                        }
                        push_trace(
                            &mut trace,
                            format!(
                                "Accusé authentifié · livraison confirmée · {}",
                                &id[..8.min(id.len())]
                            ),
                        );
                    }
                    UiEvent::MailboxResult {
                        conversation,
                        id,
                        result,
                    } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(data) = load_vault(&vault_path, &phrase) {
                            vault.set(Some(data));
                        }
                        match result {
                            Ok(()) => push_trace(
                                &mut trace,
                                format!(
                                    "Message chiffré et stocké dans la boîte · {}",
                                    &id[..8.min(id.len())]
                                ),
                            ),
                            Err(error) => push_trace(
                                &mut trace,
                                format!("Envoi différé en attente · {error}"),
                            ),
                        }
                        let _ = conversation;
                    }
                    UiEvent::Closed {
                        conversation,
                        reason,
                    } => {
                        sessions.write().remove(&conversation);
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            let pending = data
                                .messages
                                .iter()
                                .filter(|message| {
                                    message.conversation == conversation
                                        && message.outgoing
                                        && message.delivery.needs_delivery()
                                })
                                .map(|message| message.id.clone())
                                .collect::<Vec<_>>();
                            for message in &mut data.messages {
                                if message.conversation == conversation
                                    && message.outgoing
                                    && message.delivery.needs_delivery()
                                {
                                    message.delivery = DeliveryState::Queued;
                                }
                            }
                            if save_vault(&vault_path, &mut data, &phrase).is_ok() {
                                vault.set(Some(data));
                                for id in pending {
                                    start_async_mailbox_fallback(
                                        conversation.clone(),
                                        id,
                                        vault_path.clone(),
                                        phrase.clone(),
                                        event_sender,
                                    );
                                }
                            }
                        }
                        push_trace(&mut trace, format!("Session fermée · {reason}"));
                    }
                }
            }
        }
    });

    use_effect(move || {
        let current_notice = notice.read().clone();
        if !current_notice.is_empty() {
            spawn(async move {
                tokio::time::sleep(NOTICE_LIFETIME).await;
                if notice.read().as_str() == current_notice {
                    notice.set(String::new());
                }
            });
        }
    });

    use_future(move || async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if vault.read().is_some() && last_activity.read().elapsed() >= VAULT_IDLE_TIMEOUT {
                for stop in listen_stops.read().values() {
                    let _ = stop.send(true);
                }
                listen_stops.write().clear();
                let active_sessions = sessions.read().values().cloned().collect::<Vec<_>>();
                for session in active_sessions {
                    session.close();
                }
                sessions.write().clear();
                active_conversation.set(None);
                vault.set(None);
                runtime::wipe_string(&mut passphrase.write());
                last_activity.set(Instant::now());
                push_trace(
                    &mut trace,
                    "Coffre verrouillé après 5 minutes d’inactivité".into(),
                );
                notice.set("Coffre verrouillé après 5 minutes sans activité.".into());
            }
        }
    });

    let path_value = path.read().clone();
    let opened = vault.read().is_some();
    let identities = vault
        .read()
        .as_ref()
        .map(|v| v.identities.len())
        .unwrap_or(0);
    let contacts = vault.read().as_ref().map(|v| v.contacts.len()).unwrap_or(0);

    rsx! {
        document::Meta { name: "viewport", content: "width=device-width, initial-scale=1, viewport-fit=cover" }
        style { {CSS} }
        div { class: "app-frame",
            onpointerdown: move |_| last_activity.set(Instant::now()),
            onpointermove: move |_| last_activity.set(Instant::now()),
            onkeydown: move |_| last_activity.set(Instant::now()),
            oninput: move |_| last_activity.set(Instant::now()),
            onwheel: move |_| last_activity.set(Instant::now()),
            header { class: "topbar",
                div { class: "brand", img { class: "brand-mark", src: LOGO_DATA_URI, alt: "Logo AKRAT" } div { "AKRAT" span { class: "brand-sub", "MESSAGERIE P2P SÉCURISÉE" } } }
                div { class: "top-status", span { class: if opened { "status-dot live" } else { "status-dot" } } span { class: "lock-mark" } if opened { "Coffre déverrouillé" } else { "Coffre verrouillé" } }
            }
            if !opened {
                VaultGate { path, vault_paths, vault_path_input, passphrase, vault, notice }
            } else {
                div { class: "workspace",
                    aside { class: "sidebar",
                        div { class: "side-caption", "ESPACE" }
                        NavItem { label: "Conversations", icon: "messages", active: page() == Page::Messages, onclick: move |_| page.set(Page::Messages) }
                        NavItem { label: "Réseau", icon: "network", active: page() == Page::Network, onclick: move |_| page.set(Page::Network) }
                        NavItem { label: "Contacts", icon: "people", active: page() == Page::Contacts, onclick: move |_| page.set(Page::Contacts) }
                        NavItem { label: "Identités", icon: "identity", active: page() == Page::Identities, onclick: move |_| page.set(Page::Identities) }
                        NavItem { label: "Coffre", icon: "vault", active: page() == Page::Settings, onclick: move |_| page.set(Page::Settings) }
                        div { class: "side-bottom", div { class: "side-caption", "ÉTAT LOCAL" } div { class: "local-card", span { class: "status-dot live" } "Chiffré sur cet appareil" p { "{identities} identité(s) · {contacts} contact(s)" } } }
                    }
                    main { class: "content",
                        match page() {
                            Page::Messages => rsx! { ChatPage { vault, passphrase, path: path_value.clone(), active_conversation, sessions, draft, notice, trace, event_sender, on_setup: move |_| page.set(if identities == 0 { Page::Identities } else { Page::Contacts }) } },
                            Page::Network => rsx! { NetworkPage { vault, listen_stops, sessions, path: path_value.clone(), passphrase, notice } },
                            Page::Contacts => rsx! { ContactsPage { vault, passphrase, path: path_value.clone(), import_uri, contact_name, notice } },
                            Page::Identities => rsx! { IdentitiesPage { vault, passphrase, path: path_value, identity_name, invitation_result, notice } },
                            Page::Settings => rsx! { SettingsPage { path: path_value, notice, update_status,
                                on_check_updates: move |_| {
                                    update_status.set(updater::UpdateStatus::Checking);
                                    spawn(async move {
                                        match updater::check_latest().await {
                                            Ok(Some(release)) => update_status.set(updater::UpdateStatus::Available(release)),
                                            Ok(None) => update_status.set(updater::UpdateStatus::Current),
                                            Err(error) => update_status.set(updater::UpdateStatus::Failed(error)),
                                        }
                                    });
                                },
                                on_install_update: move |_| {
                                    let updater::UpdateStatus::Available(release) = update_status.read().clone() else { return; };
                                    update_status.set(updater::UpdateStatus::Installing);
                                    spawn(async move {
                                        match updater::install(release).await {
                                            Ok(()) => {},
                                            Err(error) => update_status.set(updater::UpdateStatus::Failed(error)),
                                        }
                                    });
                                },
                                on_lock: move |_| {
                                for stop in listen_stops.read().values() { let _ = stop.send(true); }
                                listen_stops.write().clear();
                                for session in sessions.read().values() { session.close(); }
                                sessions.write().clear();
                                active_conversation.set(None);
                                vault.set(None);
                                runtime::wipe_string(&mut passphrase.write());
                                notice.set("Coffre verrouillé · sessions réseau fermées.".into());
                                } } },
                        }
                    }
                    aside { class: "trace",
                        div { class: "trace-head", span { class: "trace-pulse" } "JOURNAL DU SYSTÈME" }
                        for (index, line) in trace.read().iter().enumerate().rev() { div { class: "trace-line", span { "{index:02}" } "{line}" } }
                        div { class: "trace-foot", "LES OPÉRATIONS IMPORTANTES APPARAÎTRONT ICI" }
                    }
                }
                if !notice().is_empty() { div { class: "toast", "{notice}" } }
            }
        }
    }
}

#[component]
fn VaultGate(
    mut path: Signal<PathBuf>,
    mut vault_paths: Signal<Vec<PathBuf>>,
    mut vault_path_input: Signal<String>,
    mut passphrase: Signal<String>,
    mut vault: Signal<Option<VaultData>>,
    mut notice: Signal<String>,
) -> Element {
    let selected_path = path.read().clone();
    let selected_exists = vault_paths
        .read()
        .iter()
        .any(|registered| registered == &selected_path)
        && selected_path.is_file();
    let selected_open_path = selected_path.clone();
    let selected_for_enter = selected_open_path.clone();
    let selected_for_button = selected_open_path.clone();
    let selected_name = selected_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("Coffre AKRAT")
        .to_string();
    let default_path = default_vault_path();
    let default_for_browse = default_path.clone();
    let default_for_create = default_path.clone();
    let default_for_create_enter = default_path.clone();
    let default_for_select = default_path.clone();
    let mut tab = use_signal(|| VaultGateTab::Existing);
    let mut new_vault_name = use_signal(|| {
        default_vault_path()
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("vault")
            .to_string()
    });
    let mut open_passphrase = use_signal(String::new);
    let mut create_passphrase = use_signal(String::new);
    let mut create_directory = use_signal(|| {
        default_vault_path()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .display()
            .to_string()
    });
    let mut show_open_passphrase = use_signal(|| false);
    let mut show_create_passphrase = use_signal(|| false);
    let mut confirm_passphrase = use_signal(String::new);
    let mut manage_path = use_signal(|| None::<PathBuf>);
    let mut manage_passphrase = use_signal(String::new);
    let mut rename_name = use_signal(String::new);
    let mut manage_verified = use_signal(|| false);
    let mut confirm_delete = use_signal(|| false);
    let creation_signals = VaultCreationSignals {
        path,
        paths: vault_paths,
        path_input: vault_path_input,
        session_phrase: passphrase,
        vault,
        create_phrase: create_passphrase,
        confirm_phrase: confirm_passphrase,
        notice,
    };

    rsx! {
        section { class: "gate vault-gate",
            div { class: "gate-kicker", "ESPACE PERSONNEL · CHIFFRÉ" }
            h1 { "Vos coffres" }
            p { class: "intro", "Ouvrez un coffre chiffré existant ou créez-en un nouveau. Chaque coffre garde ses propres identités, contacts et conversations." }
            div { class: "vault-tabs",
                button { class: if *tab.read() == VaultGateTab::Existing { "vault-tab active" } else { "vault-tab" }, onclick: move |_| { tab.set(VaultGateTab::Existing); notice.set(String::new()); }, "Ouvrir un coffre" }
                button { class: if *tab.read() == VaultGateTab::Create { "vault-tab active" } else { "vault-tab" }, onclick: move |_| { tab.set(VaultGateTab::Create); notice.set(String::new()); }, "Créer un coffre" }
            }
            if *tab.read() == VaultGateTab::Existing {
                section { class: "vault-manager panel",
                    div { class: "panel-title", "Coffres enregistrés · {vault_paths.read().len()}" }
                    if vault_paths.read().is_empty() { p { class: "quiet", "Aucun coffre enregistré. Parcourez vos fichiers ou créez-en un." } }
                    for entry in vault_paths.read().iter() {
                        {
                            let entry_path = entry.clone();
                            let entry_for_manage = entry.clone();
                            let entry_for_localize = entry.clone();
                            let entry_for_folder = entry.clone();
                            let entry_for_unlink = entry.clone();
                            let entry_for_verify = entry.clone();
                            let entry_for_rename = entry.clone();
                            let entry_for_delete = entry.clone();
                            let default_for_rename = default_path.clone();
                            let default_for_localize = default_path.clone();
                            let default_for_unlink = default_path.clone();
                            let default_for_delete = default_path.clone();
                            let default_for_entry_select = default_for_select.clone();
                            let is_selected = entry == &selected_path;
                            let exists = entry.is_file();
                            let label = entry.file_stem().and_then(|name| name.to_str()).unwrap_or("Coffre AKRAT").to_string();
                            let detail = entry.display().to_string();
                            let is_managing = manage_path.read().as_ref() == Some(entry);
                            rsx! {
                                div { class: if is_selected { "vault-entry selected" } else { "vault-entry" },
                                    button { class: "vault-entry-select", onclick: move |_| {
                                        let mut paths = vault_paths.read().clone();
                                        vault_catalog::select(&mut paths, &entry_path);
                                        match vault_catalog::save(&default_for_entry_select, &paths) {
                                            Ok(()) => { path.set(entry_path.clone()); vault_path_input.set(entry_path.display().to_string()); open_passphrase.set(String::new()); vault_paths.set(paths); notice.set(String::new()); },
                                            Err(error) => notice.set(error),
                                        }
                                    },
                                        span { class: "vault-entry-icon", aria_hidden: "true", svg { view_box: "0 0 24 24", width: "19", height: "19", fill: "none", stroke: "currentColor", stroke_width: "1.7", stroke_linecap: "round", stroke_linejoin: "round", path { d: "M4 7.5 12 3l8 4.5v12a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 19.5Z" } path { d: "M9 21v-7h6v7M4 8l8 4 8-4" } } }
                                        span { class: "vault-entry-copy",
                                            span { class: "vault-entry-title", strong { "{label}" } span { class: if exists { "vault-entry-status" } else { "vault-entry-status missing" }, if exists { "Présent" } else { "Introuvable" } } }
                                            span { class: "vault-entry-path", "{detail}" }
                                        }
                                    }
                                    button { class: "secondary compact vault-manage-button", onclick: move |_| {
                                        let name = entry_for_manage.file_stem().and_then(|value| value.to_str()).unwrap_or("vault").to_string();
                                        manage_path.set(Some(entry_for_manage.clone()));
                                        manage_passphrase.set(String::new());
                                        rename_name.set(name);
                                        manage_verified.set(false);
                                        confirm_delete.set(false);
                                        notice.set(String::new());
                                    }, "Gérer" }
                                }
                                if is_managing {
                                    section { class: "vault-management panel",
                                        div { class: "panel-title", "Gérer · {label}" }
                                        p { class: "vault-entry-path", "{detail}" }
                                        if !exists {
                                            p { class: "quiet", "Ce fichier est introuvable. Il peut être sur un disque externe temporairement déconnecté." }
                                            if cfg!(all(feature = "desktop", not(target_os = "android"), not(target_os = "ios"))) {
                                                button { class: "secondary", onclick: move |_| {
                                                    if let Some(found) = choose_existing_vault() {
                                                        let mut paths = vault_paths.read().clone();
                                                        if vault_catalog::replace(&mut paths, &entry_for_localize, found.clone()) {
                                                            match vault_catalog::save(&default_for_localize, &paths) {
                                                                Ok(()) => { if *path.read() == entry_for_localize { path.set(found.clone()); vault_path_input.set(found.display().to_string()); } vault_paths.set(paths); manage_path.set(None); notice.set("Emplacement du coffre mis à jour. Son fichier n’a pas été déplacé.".into()); },
                                                                Err(error) => notice.set(error),
                                                            }
                                                        }
                                                    }
                                                }, "Localiser le coffre…" }
                                            }
                                        } else {
                                            button { class: "secondary compact", onclick: move |_| open_vault_folder(&entry_for_folder), "Ouvrir le dossier" }
                                        }
                                        button { class: "secondary compact", onclick: move |_| {
                                            let mut paths = vault_paths.read().clone();
                                            vault_catalog::remove(&mut paths, &entry_for_unlink);
                                            match vault_catalog::save(&default_for_unlink, &paths) {
                                                Ok(()) => {
                                                    if *path.read() == entry_for_unlink {
                                                        let next = paths.iter().find(|candidate| candidate.is_file()).cloned().unwrap_or_else(default_vault_path);
                                                        path.set(next.clone()); vault_path_input.set(next.display().to_string()); open_passphrase.set(String::new());
                                                    }
                                                    vault_paths.set(paths); manage_path.set(None); manage_passphrase.set(String::new()); notice.set("Coffre dissocié. Son fichier et son contenu sont conservés.".into());
                                                },
                                                Err(error) => notice.set(error),
                                            }
                                        }, "Dissocier sans supprimer" }
                                        p { class: "quiet", "La phrase secrète confirme que ce coffre vous appartient." }
                                        label { "Phrase secrète de ce coffre" input { r#type: "password", value: "{manage_passphrase}", placeholder: "Phrase secrète actuelle", oninput: move |event| { manage_passphrase.set(event.value()); manage_verified.set(false); confirm_delete.set(false); } } }
                                        if !*manage_verified.read() {
                                            button { class: "secondary", onclick: move |_| {
                                                let phrase = manage_passphrase.read().clone();
                                                if phrase.is_empty() { notice.set("Saisissez la phrase secrète de ce coffre.".into()); return; }
                                                match load_vault(&entry_for_verify, &phrase) {
                                                    Ok(_) => { manage_verified.set(true); notice.set("Coffre vérifié. Vous pouvez le renommer ou le supprimer.".into()); },
                                                    Err(error) => notice.set(format!("Phrase secrète incorrecte ou coffre invalide : {error}")),
                                                }
                                            }, "Vérifier la phrase secrète" }
                                        } else {
                                            label { "Nouveau nom du fichier" input { value: "{rename_name}", placeholder: "Ex. Personnel", oninput: move |event| rename_name.set(event.value()) } }
                                            button { class: "secondary", onclick: move |_| {
                                                let phrase = manage_passphrase.read().clone();
                                                if let Err(error) = load_vault(&entry_for_rename, &phrase) { manage_verified.set(false); notice.set(format!("Vérification refusée : {error}")); return; }
                                                let existing = vault_paths.read().clone();
                                                let (renamed, paths) = match rename_vault_file(&default_for_rename, &existing, &entry_for_rename, &rename_name.read()) { Ok(result) => result, Err(error) => { notice.set(error); return; } };
                                                if *path.read() == entry_for_rename { path.set(renamed.clone()); vault_path_input.set(renamed.display().to_string()); }
                                                vault_paths.set(paths);
                                                manage_path.set(None);
                                                manage_passphrase.set(String::new());
                                                notice.set("Coffre renommé. Son contenu chiffré est inchangé.".into());
                                            }, "Renommer le coffre" }
                                            div { class: "vault-danger-zone",
                                                strong { "Supprimer le fichier du coffre" }
                                                if cfg!(all(feature = "desktop", not(target_os = "android"), not(target_os = "ios"))) {
                                                    p { "AKRAT essaie de placer le coffre dans la Corbeille. Cette action ne garantit pas l’effacement physique des données sur SSD." }
                                                } else {
                                                    p { "Le fichier privé sera supprimé de cet appareil. Cela ne garantit pas l’effacement physique des données sur mémoire flash." }
                                                }
                                                if !*confirm_delete.read() {
                                                    button { class: "danger-button", onclick: move |_| confirm_delete.set(true), "Supprimer…" }
                                                } else {
                                                    p { class: "delete-confirm-text", "Confirmez la suppression définitive de « {label} »." }
                                                    div { class: "gate-actions",
                                                        button { class: "secondary", onclick: move |_| confirm_delete.set(false), "Annuler" }
                                                        button { class: "danger-button", onclick: move |_| {
                                                            let phrase = manage_passphrase.read().clone();
                                                            let existing = vault_paths.read().clone();
                                                            let paths = match delete_vault_file(&default_for_delete, &existing, &entry_for_delete, &phrase) { Ok(paths) => paths, Err(error) => { manage_verified.set(false); confirm_delete.set(false); notice.set(error); return; } };
                                                            let fallback = paths.iter().find(|candidate| candidate.is_file()).cloned().unwrap_or_else(|| default_for_delete.clone());
                                                            if *path.read() == entry_for_delete { path.set(fallback.clone()); vault_path_input.set(fallback.display().to_string()); }
                                                            vault_paths.set(paths);
                                                            manage_path.set(None);
                                                            manage_passphrase.set(String::new());
                                                            confirm_delete.set(false);
                                                            notice.set("Coffre supprimé définitivement de cet appareil.".into());
                                                        }, "Confirmer la suppression" }
                                                    }
                                                }
                                            }
                                        }
                                        button { class: "vault-cancel-manage", onclick: move |_| { manage_path.set(None); manage_passphrase.set(String::new()); manage_verified.set(false); confirm_delete.set(false); }, "Fermer la gestion" }
                                    }
                                }
                            }
                        }
                    }
                }
                if selected_exists { p { class: "vault-selected-name", "Ouverture de · {selected_name}" } }
                label { "Phrase secrète" input { r#type: if *show_open_passphrase.read() { "text" } else { "password" }, value: "{open_passphrase}", placeholder: "Phrase secrète du coffre sélectionné", oninput: move |event| open_passphrase.set(event.value()), onkeydown: move |event| if event.key() == Key::Enter && selected_exists {
                    let phrase = open_passphrase.read().clone();
                    match load_vault(&selected_for_enter, &phrase) { Ok(data) => { passphrase.set(phrase); vault.set(Some(data)); notice.set("Coffre déverrouillé.".into()); }, Err(error) => notice.set(format!("Impossible de déverrouiller ce coffre : {error}")) }
                } } }
                button { class: "secondary compact", onclick: move |_| { let next = !*show_open_passphrase.read(); show_open_passphrase.set(next); }, if *show_open_passphrase.read() { "Masquer" } else { "Afficher" } }
                if selected_exists {
                    button { class: "primary gate-primary-action", onclick: move |_| {
                        let phrase = open_passphrase.read().clone();
                        match load_vault(&selected_for_button, &phrase) {
                            Ok(data) => { passphrase.set(phrase); vault.set(Some(data)); notice.set("Coffre déverrouillé.".into()); }
                            Err(error) => notice.set(format!("Impossible de déverrouiller ce coffre : {error}")),
                        }
                    }, "Déverrouiller le coffre sélectionné" }
                } else {
                    p { class: "quiet", "Choisissez un coffre présent ou parcourez vos fichiers pour en ajouter un." }
                }
                if cfg!(all(feature = "desktop", not(target_os = "android"), not(target_os = "ios"))) {
                    button { class: "secondary browse-vault-button", onclick: move |_| {
                        if let Some(chosen) = choose_existing_vault() {
                            let mut paths = vault_paths.read().clone();
                            vault_catalog::add(&mut paths, chosen.clone());
                            vault_catalog::select(&mut paths, &chosen);
                            match vault_catalog::save(&default_for_browse, &paths) {
                                Ok(()) => { vault_paths.set(paths); vault_path_input.set(chosen.display().to_string()); path.set(chosen); open_passphrase.set(String::new()); notice.set("Coffre ajouté à la liste.".into()); },
                                Err(error) => notice.set(error),
                            }
                        }
                    }, "Parcourir les fichiers pour trouver un coffre…" }
                }
                if cfg!(target_os = "android") {
                    label { class: "mobile-vault-import",
                        span { "Importer un coffre depuis le téléphone…" }
                        input { r#type: "file", accept: ".akrat,application/octet-stream", onchange: move |event| {
                            let Some(file) = event.files().into_iter().next() else { return; };
                            if file.size() > 16 * 1024 * 1024 { notice.set("Ce fichier dépasse la taille maximale de 16 Mio.".into()); return; }
                            let file_name = file.name();
                            let existing = vault_paths.read().clone();
                            let default_for_import = default_path.clone();
                            spawn(async move {
                                match file.read_bytes().await {
                                    Ok(bytes) => match import_vault_bytes(&default_for_import, &existing, &file_name, &bytes) {
                                        Ok((imported, paths)) => { vault_paths.set(paths); path.set(imported.clone()); vault_path_input.set(imported.display().to_string()); open_passphrase.set(String::new()); notice.set("Copie privée importée et sélectionnée. Saisissez sa phrase secrète.".into()); },
                                        Err(error) => notice.set(error),
                                    },
                                    Err(error) => notice.set(format!("Impossible de lire le fichier choisi : {error}")),
                                }
                            });
                        } }
                    }
                }
            } else {
                section { class: "panel vault-create-panel",
                    div { class: "panel-title", "Nouveau coffre chiffré" }
                    p { class: "quiet", "Choisissez un nom, un emplacement et une phrase secrète. La confirmation évite les erreurs de saisie." }
                    label { "Nom du coffre" input { value: "{new_vault_name}", placeholder: "Ex. Personnel", oninput: move |event| new_vault_name.set(event.value()) } }
                    label { "Dossier de destination" input { r#type: "text", value: "{create_directory}", placeholder: "Dossier où enregistrer le coffre", oninput: move |event| create_directory.set(event.value()) } }
                    if cfg!(all(feature = "desktop", not(target_os = "android"), not(target_os = "ios"))) {
                        button { class: "secondary browse-vault-button", onclick: move |_| {
                            if let Some(chosen) = choose_new_vault_directory() { create_directory.set(chosen.display().to_string()); }
                        }, "Choisir un emplacement…" }
                    }
                    label { "Phrase secrète · 12 caractères minimum" input { r#type: if *show_create_passphrase.read() { "text" } else { "password" }, value: "{create_passphrase}", placeholder: "Créer une phrase secrète", oninput: move |event| create_passphrase.set(event.value()) } }
                    label { "Confirmer la phrase secrète" input { r#type: if *show_create_passphrase.read() { "text" } else { "password" }, value: "{confirm_passphrase}", placeholder: "Saisir la même phrase secrète", oninput: move |event| confirm_passphrase.set(event.value()), onkeydown: move |event| if event.key() == Key::Enter {
                        let phrase = create_passphrase.read().clone();
                        let confirmation = confirm_passphrase.read().clone();
                        let folder = create_directory.read().clone();
                        let name = new_vault_name.read().clone();
                        let existing = vault_paths.read().clone();
                        let result = create_vault_file(&default_for_create_enter, &existing, &folder, &name, &phrase, &confirmation);
                        apply_created_vault(result, phrase, creation_signals);
                    } } }
                    button { class: "secondary compact", onclick: move |_| { let next = !*show_create_passphrase.read(); show_create_passphrase.set(next); }, if *show_create_passphrase.read() { "Masquer les phrases" } else { "Afficher la phrase" } }
                    button { class: "primary gate-primary-action", onclick: move |_| {
                        let phrase = create_passphrase.read().clone();
                        let confirmation = confirm_passphrase.read().clone();
                        let folder = create_directory.read().clone();
                        let name = new_vault_name.read().clone();
                        let existing = vault_paths.read().clone();
                        let result = create_vault_file(&default_for_create, &existing, &folder, &name, &phrase, &confirmation);
                        apply_created_vault(result, phrase, creation_signals);
                    }, "Créer et chiffrer le coffre" }
                }
            }
            p { class: "notice", "{notice}" }
            if *tab.read() == VaultGateTab::Existing { div { class: "path-note", "COFFRE SÉLECTIONNÉ · {selected_path.display()}" } }
        }
    }
}

fn create_vault_file(
    catalog_path: &Path,
    existing_paths: &[PathBuf],
    folder: &str,
    name: &str,
    passphrase: &str,
    confirmation: &str,
) -> Result<(PathBuf, Vec<PathBuf>, VaultData), String> {
    if passphrase.len() < 12 {
        return Err("La phrase secrète doit contenir au moins 12 caractères.".into());
    }
    if passphrase != confirmation {
        return Err("Les deux phrases secrètes ne correspondent pas.".into());
    }
    let folder = PathBuf::from(folder.trim());
    if !folder.is_dir() {
        return Err("Le dossier de destination n’existe pas ou n’est pas accessible.".into());
    }
    let destination = vault_path_with_name(&folder, name)?;
    if destination.exists() {
        return Err(
            "Un fichier existe déjà à cet emplacement. Choisissez un autre nom ou dossier.".into(),
        );
    }
    let mut data = VaultData::default();
    save_vault(&destination, &mut data, passphrase)
        .map_err(|error| format!("Création impossible : {error}"))?;
    let mut paths = existing_paths.to_vec();
    vault_catalog::add(&mut paths, destination.clone());
    if let Err(error) = vault_catalog::save(catalog_path, &paths) {
        return Err(format!(
            "Le coffre a été créé à {} mais son catalogue n’a pas pu être enregistré : {error}",
            destination.display()
        ));
    }
    Ok((destination, paths, data))
}

fn import_vault_bytes(
    default_path: &Path,
    existing_paths: &[PathBuf],
    source_name: &str,
    bytes: &[u8],
) -> Result<(PathBuf, Vec<PathBuf>), String> {
    const MAX_PORTABLE_VAULT_SIZE: usize = 16 * 1024 * 1024;
    if bytes.is_empty() || bytes.len() > MAX_PORTABLE_VAULT_SIZE {
        return Err(
            "Le fichier ne correspond pas à un coffre AKRAT valide ou dépasse 16 Mio.".into(),
        );
    }
    let directory = default_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("Dossier privé du coffre inaccessible : {error}"))?;
    let stem = Path::new(source_name)
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or("Nom de fichier de coffre invalide.")?;
    let mut suffix = 1u32;
    let destination = loop {
        let name = if suffix == 1 {
            stem.to_string()
        } else {
            format!("{stem} ({suffix})")
        };
        let candidate = vault_path_with_name(directory, &name)?;
        if !candidate.exists() && !existing_paths.iter().any(|path| path == &candidate) {
            break candidate;
        }
        suffix = suffix
            .checked_add(1)
            .ok_or("Impossible de générer un nom libre pour le coffre importé.")?;
    };
    let _destination_lock = VaultFileLock::acquire(&destination)
        .map_err(|error| format!("Verrouillage de l’emplacement importé impossible : {error}"))?;
    if destination.exists() {
        return Err("Un fichier existe déjà à l’emplacement choisi pour l’importation.".into());
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = directory.join(format!(".akrat-import-{}-{nonce}.tmp", std::process::id()));
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &destination)
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("Copie du coffre impossible : {error}"));
    }
    let mut paths = existing_paths.to_vec();
    vault_catalog::add(&mut paths, destination.clone());
    if let Err(error) = vault_catalog::save(default_path, &paths) {
        return Err(format!(
            "Le coffre a été copié dans {} mais son catalogue n’a pas pu être enregistré : {error}",
            destination.display()
        ));
    }
    Ok((destination, paths))
}

fn rename_vault_file(
    default_path: &Path,
    existing_paths: &[PathBuf],
    source: &Path,
    new_name: &str,
) -> Result<(PathBuf, Vec<PathBuf>), String> {
    if !source.is_file() {
        return Err("Le fichier du coffre est introuvable.".into());
    }
    if !existing_paths.iter().any(|path| path == source) {
        return Err("Ce coffre n’est plus enregistré dans le catalogue.".into());
    }
    let destination = vault_path_with_name(source, new_name)?;
    if destination == source {
        return Err("Ce coffre porte déjà ce nom.".into());
    }
    if destination.exists() {
        return Err("Un fichier existe déjà avec ce nom.".into());
    }
    let mut lock_paths = [source, destination.as_path()];
    lock_paths.sort_by_key(|path| path.to_string_lossy().to_lowercase());
    let _vault_locks = lock_paths
        .into_iter()
        .map(VaultFileLock::acquire)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Verrouillage du coffre impossible : {error}"))?;
    if !source.is_file() || destination.exists() {
        return Err("Le coffre a changé pendant sa préparation au renommage.".into());
    }
    let source_sidecar = akrat_core::attachments::attachment_sidecar_path(source);
    let destination_sidecar = akrat_core::attachments::attachment_sidecar_path(&destination);
    let source_backup = vault_backup_path(source);
    let destination_backup = vault_backup_path(&destination);
    if destination_sidecar.exists() {
        return Err("Un dossier de pièces jointes existe déjà avec ce nom.".into());
    }
    if destination_backup.exists() {
        return Err("Une sauvegarde existe déjà avec ce nom.".into());
    }
    let backup_moved = if source_backup.exists() {
        std::fs::rename(&source_backup, &destination_backup)
            .map_err(|error| format!("Déplacement de la sauvegarde impossible : {error}"))?;
        true
    } else {
        false
    };
    if source_sidecar.exists()
        && let Err(error) = std::fs::rename(&source_sidecar, &destination_sidecar)
    {
        if backup_moved {
            let _ = std::fs::rename(&destination_backup, &source_backup);
        }
        return Err(format!(
            "Déplacement des pièces jointes impossible : {error}"
        ));
    }
    if let Err(error) = std::fs::rename(source, &destination) {
        if source_sidecar.exists() || destination_sidecar.exists() {
            let _ = std::fs::rename(&destination_sidecar, &source_sidecar);
        }
        if backup_moved {
            let _ = std::fs::rename(&destination_backup, &source_backup);
        }
        return Err(format!("Renommage impossible : {error}"));
    }
    let paths = match vault_catalog::replace_and_save(default_path, source, destination.clone()) {
        Ok(paths) => paths,
        Err(error) => {
            let rollback = std::fs::rename(&destination, source);
            let sidecar_rollback = if destination_sidecar.exists() {
                std::fs::rename(&destination_sidecar, &source_sidecar)
            } else {
                Ok(())
            };
            let backup_rollback = if backup_moved && destination_backup.exists() {
                std::fs::rename(&destination_backup, &source_backup)
            } else {
                Ok(())
            };
            return Err(match rollback {
                Ok(()) if sidecar_rollback.is_ok() && backup_rollback.is_ok() => error,
                Ok(()) => format!(
                    "{error}. Retour auxiliaire impossible : {}",
                    sidecar_rollback
                        .err()
                        .or_else(|| backup_rollback.err())
                        .unwrap()
                ),
                Err(rollback_error) => format!(
                    "Catalogue non enregistré ({error}) et retour arrière impossible ({rollback_error})."
                ),
            });
        }
    };
    Ok((destination, paths))
}

fn delete_vault_file(
    default_path: &Path,
    existing_paths: &[PathBuf],
    source: &Path,
    passphrase: &str,
) -> Result<Vec<PathBuf>, String> {
    load_vault(source, passphrase).map_err(|error| format!("Suppression refusée : {error}"))?;
    let _vault_lock = VaultFileLock::acquire(source)
        .map_err(|error| format!("Verrouillage du coffre impossible : {error}"))?;
    load_vault(source, passphrase)
        .map_err(|error| format!("Suppression refusée après vérification : {error}"))?;
    let mut paths = existing_paths.to_vec();
    vault_catalog::remove(&mut paths, source);
    vault_catalog::save(default_path, &paths)
        .map_err(|error| format!("Liste des coffres impossible à mettre à jour : {error}"))?;
    if let Err(error) = move_vault_to_trash(source) {
        vault_catalog::add(&mut paths, source.to_path_buf());
        return match vault_catalog::save(default_path, &paths) {
            Ok(()) => Err(error),
            Err(catalog_error) => Err(format!(
                "{error}. Restauration du catalogue impossible : {catalog_error}"
            )),
        };
    }
    Ok(paths)
}

fn move_vault_to_trash(path: &Path) -> Result<(), String> {
    let sidecar = akrat_core::attachments::attachment_sidecar_path(path);
    let backup = vault_backup_path(path);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let bundle = parent.join(format!(".akrat-delete-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&bundle)
        .map_err(|error| format!("Préparation de la suppression impossible : {error}"))?;
    let staged_vault = bundle.join("vault.akrat");
    let staged_sidecar = bundle.join("vault.akrat.attachments");
    let staged_backup = bundle.join("vault.akrat.bak");
    std::fs::rename(path, &staged_vault).map_err(|error| {
        let _ = std::fs::remove_dir(&bundle);
        format!("Déplacement du coffre impossible : {error}")
    })?;
    if sidecar.exists()
        && let Err(error) = std::fs::rename(&sidecar, &staged_sidecar)
    {
        let rollback = std::fs::rename(&staged_vault, path);
        let _ = std::fs::remove_dir(&bundle);
        return Err(match rollback {
            Ok(()) => format!("Déplacement des pièces jointes impossible : {error}"),
            Err(rollback) => format!(
                "Déplacement des pièces jointes impossible : {error}; restauration du coffre impossible : {rollback}"
            ),
        });
    }
    if backup.exists()
        && let Err(error) = std::fs::rename(&backup, &staged_backup)
    {
        let sidecar_rollback = if staged_sidecar.exists() {
            std::fs::rename(&staged_sidecar, &sidecar)
        } else {
            Ok(())
        };
        let vault_rollback = std::fs::rename(&staged_vault, path);
        let _ = std::fs::remove_dir(&bundle);
        return Err(format!(
            "Déplacement de la sauvegarde impossible : {error}; restauration du coffre : {}; pièces jointes : {}",
            vault_rollback
                .err()
                .map_or_else(|| "réussie".into(), |error| error.to_string()),
            sidecar_rollback
                .err()
                .map_or_else(|| "réussie".into(), |error| error.to_string())
        ));
    }
    #[cfg(all(
        feature = "desktop",
        not(test),
        not(target_os = "android"),
        not(target_os = "ios")
    ))]
    let result = trash::delete(&bundle).map_err(|error| {
        format!("Impossible de placer le coffre et ses pièces jointes dans la Corbeille : {error}")
    });
    #[cfg(any(
        test,
        not(feature = "desktop"),
        target_os = "android",
        target_os = "ios"
    ))]
    let result = std::fs::remove_dir_all(&bundle).map_err(|error| {
        format!("Suppression du coffre et de ses pièces jointes impossible : {error}")
    });
    if let Err(error) = result {
        let sidecar_rollback = if staged_sidecar.exists() {
            std::fs::rename(&staged_sidecar, &sidecar)
        } else {
            Ok(())
        };
        let backup_rollback = if staged_backup.exists() {
            std::fs::rename(&staged_backup, &backup)
        } else {
            Ok(())
        };
        let vault_rollback = if staged_vault.exists() {
            std::fs::rename(&staged_vault, path)
        } else {
            Ok(())
        };
        let _ = std::fs::remove_dir(&bundle);
        return Err(match (vault_rollback, sidecar_rollback, backup_rollback) {
            (Ok(()), Ok(()), Ok(())) => error,
            (vault_result, sidecar_result, backup_result) => format!(
                "{error}. Restauration du coffre : {}; pièces jointes : {}; sauvegarde : {}",
                vault_result
                    .err()
                    .map_or_else(|| "réussie".into(), |value| value.to_string()),
                sidecar_result
                    .err()
                    .map_or_else(|| "réussie".into(), |value| value.to_string()),
                backup_result
                    .err()
                    .map_or_else(|| "réussie".into(), |value| value.to_string())
            ),
        });
    }
    Ok(())
}

fn vault_backup_path(path: &Path) -> PathBuf {
    path.with_extension("akrat.bak")
}

fn apply_created_vault(
    result: Result<(PathBuf, Vec<PathBuf>, VaultData), String>,
    phrase: String,
    mut signals: VaultCreationSignals,
) {
    match result {
        Ok((destination, paths, data)) => {
            signals.path.set(destination.clone());
            signals.path_input.set(destination.display().to_string());
            signals.paths.set(paths);
            signals.session_phrase.set(phrase);
            signals.vault.set(Some(data));
            signals.create_phrase.set(String::new());
            signals.confirm_phrase.set(String::new());
            signals
                .notice
                .set("Coffre créé et chiffré. Le réseau démarre automatiquement.".into());
        }
        Err(error) => signals.notice.set(error),
    }
}

fn vault_path_with_name(base_path: &Path, raw_name: &str) -> Result<PathBuf, String> {
    let name = raw_name.trim();
    let base_name = if name.to_ascii_lowercase().ends_with(".akrat") {
        &name[..name.len() - ".akrat".len()]
    } else {
        name
    };
    if base_name.is_empty()
        || base_name == "."
        || base_name == ".."
        || base_name
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
    {
        return Err("Choisissez un nom de coffre valide, sans séparateur de dossier.".into());
    }
    let parent = if base_path.is_dir() {
        base_path
    } else {
        base_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    };
    Ok(parent.join(format!("{base_name}.akrat")))
}

#[cfg(all(
    feature = "desktop",
    not(target_os = "android"),
    not(target_os = "ios")
))]
fn choose_existing_vault() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("Coffre AKRAT", &["akrat"])
        .pick_file()
}

#[cfg(all(
    feature = "desktop",
    not(target_os = "android"),
    not(target_os = "ios")
))]
fn choose_new_vault_directory() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_folder()
}

#[cfg(any(not(feature = "desktop"), target_os = "android", target_os = "ios"))]
fn choose_existing_vault() -> Option<PathBuf> {
    None
}

#[cfg(any(not(feature = "desktop"), target_os = "android", target_os = "ios"))]
fn choose_new_vault_directory() -> Option<PathBuf> {
    None
}

fn open_vault_folder(vault_path: &Path) {
    let Some(folder) = vault_path.parent() else {
        return;
    };
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(folder).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(folder).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(folder).spawn();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let _ = folder;
}

#[component]
fn NavItem(
    label: &'static str,
    icon: &'static str,
    active: bool,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    let glyph = match icon {
        "messages" => {
            rsx! { svg { view_box: "0 0 24 24", width: "22", height: "22", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", path { d: "M20 11.5a7.5 7.5 0 0 1-7.5 7.5H7l-3 2v-5.1a7.5 7.5 0 1 1 16-4.4Z" } path { d: "M8 11h.01M12 11h.01M16 11h.01" } } }
        }
        "network" => {
            rsx! { svg { view_box: "0 0 24 24", width: "22", height: "22", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", path { d: "M2.5 8.8a15 15 0 0 1 19 0M5.8 12.2a9.8 9.8 0 0 1 12.4 0M9.2 15.6a4.6 4.6 0 0 1 5.6 0" } circle { cx: "12", cy: "19", r: "1" } } }
        }
        "people" => {
            rsx! { svg { view_box: "0 0 24 24", width: "22", height: "22", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", circle { cx: "9", cy: "8", r: "3.5" } path { d: "M2.5 20v-1.3A6.5 6.5 0 0 1 9 12.2a6.5 6.5 0 0 1 6.5 6.5V20Z" } path { d: "M16 5.2a3.5 3.5 0 0 1 0 6.6M17 13a5.5 5.5 0 0 1 4.5 5.4V20h-3" } } }
        }
        _ => {
            rsx! { svg { view_box: "0 0 24 24", width: "22", height: "22", fill: "none", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round", rect { x: "4", y: "10", width: "16", height: "11", rx: "2" } path { d: "M8 10V7a4 4 0 0 1 8 0v3M12 14v3" } } }
        }
    };
    rsx! { button { class: if active { "nav-item active" } else { "nav-item" }, onclick, span { class: "nav-glyph", aria_hidden: "true", {glyph} } span { class: "nav-label", "{label}" } } }
}

#[component]
fn IdentitiesPage(
    vault: Signal<Option<VaultData>>,
    passphrase: Signal<String>,
    path: PathBuf,
    identity_name: Signal<String>,
    invitation_result: Signal<String>,
    notice: Signal<String>,
) -> Element {
    let identities = vault
        .read()
        .as_ref()
        .map(|data| {
            data.identities
                .iter()
                .map(|identity| {
                    (
                        identity.id.clone(),
                        identity.name.clone(),
                        identity.fingerprint(),
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut selected_identity = use_signal(|| {
        identities
            .first()
            .map(|(id, _, _)| id.clone())
            .unwrap_or_default()
    });
    let create_path = path.clone();
    rsx! {
        section { class: "page-scroll",
            div { class: "eyebrow", "VOTRE IDENTITÉ CRYPTOGRAPHIQUE" }
            h1 { "Identités" }
            p { class: "intro", "Une identité est votre présence cryptographique. Elle reste séparée de vos contacts et peut avoir sa propre invitation réseau." }
            section { class: "panel",
                div { class: "panel-title", "Créer une identité" }
                div { class: "form-row",
                    input { value: "{identity_name}", placeholder: "Nom de cette identité", oninput: move |e| identity_name.set(e.value()) }
                    button { class: "primary compact", onclick: move |_| {
                        let name = identity_name.read().trim().to_string();
                        let phrase = passphrase.read().clone();
                        if name.is_empty() { notice.set("Donnez un nom à l’identité.".into()); return; }
                        let mut data = match load_vault(&create_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                        match Identity::generate(name) {
                            Ok(identity) => {
                                data.identities.push(identity);
                                match save_vault(&create_path, &mut data, &phrase) {
                                    Ok(()) => { vault.set(Some(data)); identity_name.set(String::new()); notice.set("Nouvelle identité créée. Le réseau l’active automatiquement.".into()); },
                                    Err(error) => notice.set(format!("Enregistrement impossible : {error}")),
                                }
                            }
                            Err(error) => notice.set(format!("Création impossible : {error}")),
                        }
                    }, "Créer" }
                }
            }
            section { class: "panel contacts-panel",
                div { class: "panel-title", "Identités locales · {identities.len()}" }
                if identities.is_empty() { p { class: "quiet", "Aucune identité pour le moment." } }
                for (_id, name, fingerprint) in identities.iter() {
                    div { class: "record", div { class: "record-icon", "◇" } div { class: "record-main", strong { "{name}" } span { class: "fingerprint", "{fingerprint}" } } }
                }
            }
            if !identities.is_empty() {
                section { class: "panel",
                    div { class: "panel-title", "Partager une invitation" }
                    label { "Identité à présenter"
                        select { class: "select-field", value: "{selected_identity}", onchange: move |e| selected_identity.set(e.value()),
                            option { value: "", "Choisir une identité" }
                            for (id, name, _) in identities.iter() { option { value: "{id}", "{name}" } }
                        }
                    }
                    button { class: "secondary", onclick: move |_| {
                        let selected = selected_identity.read().clone();
                        let identity = vault.read().as_ref().and_then(|data| data.identities.iter().find(|item| item.id == selected || selected.is_empty()).map(Identity::detached_copy));
                        match identity.and_then(|identity| Invitation::create(&identity).ok()) {
                            Some(invitation) => match invitation.to_uri() { Ok(uri) => { invitation_result.set(uri); notice.set("Invitation créée · partagez-la par un canal sûr.".into()); }, Err(error) => notice.set(format!("Invitation impossible : {error}")) },
                            None => notice.set("Choisissez une identité.".into()),
                        }
                    }, "Générer l’invitation" }
                    if !invitation_result.read().is_empty() {
                        textarea { class: "invite-text", readonly: true, value: "{invitation_result}", spellcheck: false }
                        button { class: "secondary copy-invite", onclick: move |_| {
                            let invitation = invitation_result.read().clone();
                            async move { if copy_to_clipboard(invitation).await { notice.set("Invitation copiée.".into()); } else { notice.set("Copie impossible · maintenez le doigt sur le lien pour le sélectionner.".into()); } }
                        }, "Copier l’invitation" }
                    }
                }
            }
        }
    }
}

#[component]
fn ContactsPage(
    vault: Signal<Option<VaultData>>,
    passphrase: Signal<String>,
    path: PathBuf,
    import_uri: Signal<String>,
    contact_name: Signal<String>,
    notice: Signal<String>,
) -> Element {
    let contacts = vault
        .read()
        .as_ref()
        .map(|data| data.contacts.clone())
        .unwrap_or_default();
    let import_path = path.clone();
    rsx! {
        section { class: "page-scroll",
            div { class: "eyebrow", "CARNET DE CONFIANCE" }
            h1 { "Contacts" }
            p { class: "intro", "Importez une invitation puis comparez l’empreinte avec la personne par un canal indépendant. Le réseau accepte uniquement les contacts vérifiés." }
            section { class: "panel",
                div { class: "panel-title", "Ajouter un contact" }
                label { "Nom à afficher" input { value: "{contact_name}", placeholder: "Ex. Camille", oninput: move |e| contact_name.set(e.value()) } }
                label { "Invitation reçue" textarea { value: "{import_uri}", placeholder: "akrat://invite/…", oninput: move |e| import_uri.set(e.value()) } }
                button { class: "primary", onclick: move |_| {
                    let phrase = passphrase.read().clone();
                    let uri = import_uri.read().clone();
                    let name = contact_name.read().trim().to_string();
                    if name.is_empty() { notice.set("Donnez un nom au contact.".into()); return; }
                    match Invitation::from_uri(&uri) {
                        Ok(invitation) => {
                            let mut data = match load_vault(&import_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                            let updated = if let Some(contact) = data.contacts.iter_mut().find(|contact| contact.fingerprint == invitation.fingerprint) {
                                contact.name = name;
                                contact.public_key = invitation.public_key;
                                contact.transport_id = invitation.transport_id;
                                contact.legacy_address.clear();
                                contact.manually_verified = false;
                                true
                            } else {
                                data.contacts.push(Contact { fingerprint: invitation.fingerprint, name, public_key: invitation.public_key, transport_id: invitation.transport_id, legacy_address: String::new(), manually_verified: false, mailbox_route: None, mailbox_replicas: Vec::new() });
                                false
                            };
                            match save_vault(&import_path, &mut data, &phrase) {
                                Ok(()) => { vault.set(Some(data)); import_uri.set(String::new()); contact_name.set(String::new()); notice.set(if updated { "Invitation actualisée · comparez de nouveau l’empreinte avant de vérifier le contact.".into() } else { "Invitation importée · comparez l’empreinte avant de vérifier le contact.".into() }); },
                                Err(error) => notice.set(format!("Enregistrement impossible : {error}")),
                            }
                        }
                        Err(error) => notice.set(format!("Invitation invalide : {error}")),
                    }
                }, "Importer le contact" }
            }
            section { class: "panel contacts-panel",
                div { class: "panel-title", "Carnet · {contacts.len()} contact(s)" }
                if contacts.is_empty() { p { class: "quiet", "Les contacts importés apparaîtront ici." } }
                for contact in contacts { ContactRow { contact, vault, passphrase, path: path.clone(), notice } }
            }
        }
    }
}

#[component]
fn ContactRow(
    contact: Contact,
    vault: Signal<Option<VaultData>>,
    passphrase: Signal<String>,
    path: PathBuf,
    notice: Signal<String>,
) -> Element {
    let verified = contact.manually_verified;
    let fp = contact.fingerprint.clone();
    let verify_path = path.clone();
    let transport_id = contact.transport_id.clone();
    let mut endpoint = use_signal(|| {
        contact
            .mailbox_route
            .as_ref()
            .map(|r| r.endpoint.clone())
            .unwrap_or_default()
    });
    let mut noise_key = use_signal(|| {
        contact
            .mailbox_route
            .as_ref()
            .map(|r| hex::encode(&r.server_noise_public_key))
            .unwrap_or_default()
    });
    let mut signing_key = use_signal(|| {
        contact
            .mailbox_route
            .as_ref()
            .map(|r| hex::encode(&r.server_signing_public_key))
            .unwrap_or_default()
    });
    let mut mailbox_id = use_signal(|| {
        contact
            .mailbox_route
            .as_ref()
            .map(|r| r.mailbox_id.clone())
            .unwrap_or_default()
    });
    let mut write_capability = use_signal(|| {
        contact
            .mailbox_route
            .as_ref()
            .map(|r| r.write_capability.clone())
            .unwrap_or_default()
    });
    let mut bundle_capability = use_signal(|| {
        contact
            .mailbox_route
            .as_ref()
            .map(|r| r.bundle_capability.clone())
            .unwrap_or_default()
    });
    let mut replica_endpoint = use_signal(String::new);
    let mut replica_noise_key = use_signal(String::new);
    let mut replica_signing_key = use_signal(String::new);
    let mut replica_mailbox_id = use_signal(String::new);
    let mut replica_write_capability = use_signal(String::new);
    let mut replica_bundle_capability = use_signal(String::new);
    let route_fp = fp.clone();
    let replicas_fp = fp.clone();
    let replicas_path = path.clone();
    rsx! { section { class: "contact-record",
        div { class: "contact-row", div { class: "record-icon", "⌁" } div { class: "record-main", strong { "{contact.name}" } span { class: "fingerprint", "{contact.fingerprint}" } span { class: "quiet", if transport_id.is_empty() { "Ancienne invitation · à réimporter" } else { "Identité réseau stable · itinérance" } } } if verified { span { class: "verified", "VÉRIFIÉ" } } else { button { class: "secondary compact", onclick: move |_| {
        let phrase = passphrase.read().clone(); let mut d = match load_vault(&verify_path, &phrase) { Ok(d) => d, Err(e) => { notice.set(format!("Coffre inaccessible : {e}")); return; } };
        if let Some(item) = d.contacts.iter_mut().find(|c| c.fingerprint == fp) { item.manually_verified = true; }
        match save_vault(&verify_path, &mut d, &phrase) { Ok(()) => { vault.set(Some(d)); notice.set("Contact marqué comme vérifié. Confirmez son empreinte avec lui en personne ou par un canal sûr.".into()); }, Err(e) => notice.set(format!("Enregistrement impossible : {e}")) }
    }, "Empreinte comparée hors AKRAT" } } }
        if verified {
            div { class: "mailbox-route-form",
                strong { "Boîte différée de ce contact" }
                p { class: "quiet", "Ces informations sont fournies par le contact. L’empreinte Noise du serveur doit être vérifiée par un canal sûr." }
                label { "Serveur · hôte:port" input { value: "{endpoint}", placeholder: "mail.example.net:47475", oninput: move |e| endpoint.set(e.value()) } }
                label { "Clé publique Noise du serveur · hex" input { value: "{noise_key}", placeholder: "64 caractères hexadécimaux", oninput: move |e| noise_key.set(e.value()) } }
                label { "Clé de signature du serveur · hex" input { value: "{signing_key}", placeholder: "64 caractères hexadécimaux", oninput: move |e| signing_key.set(e.value()) } }
                label { "Identifiant de boîte" input { value: "{mailbox_id}", oninput: move |e| mailbox_id.set(e.value()) } }
                label { "Capacité de dépôt" input { r#type: "password", value: "{write_capability}", oninput: move |e| write_capability.set(e.value()) } }
                label { "Capacité de lecture des préclés" input { r#type: "password", value: "{bundle_capability}", oninput: move |e| bundle_capability.set(e.value()) } }
                button { class: "secondary compact", onclick: move |_| {
                    let phrase = passphrase.read().clone();
                    let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                    let endpoint_value = endpoint.read().trim().to_string();
                    let key = match hex::decode(noise_key.read().trim()) { Ok(key) if key.len() == 32 => key, _ => { notice.set("La clé Noise doit contenir 32 octets en hexadécimal.".into()); return; } };
                    let signing = match hex::decode(signing_key.read().trim()) { Ok(key) if key.len() == 32 => key, _ => { notice.set("La clé de signature doit contenir 32 octets en hexadécimal.".into()); return; } };
                    let mailbox_value = mailbox_id.read().trim().to_string();
                    let write_value = write_capability.read().trim().to_string();
                    let bundle_value = bundle_capability.read().trim().to_string();
                    if endpoint_value.is_empty() || mailbox_value.is_empty() || write_value.is_empty() || bundle_value.is_empty() { notice.set("Complétez les paramètres de la boîte.".into()); return; }
                    if let Some(item) = data.contacts.iter_mut().find(|item| item.fingerprint == route_fp) {
                        item.mailbox_route = Some(MailboxRoute { endpoint: endpoint_value, server_noise_public_key: key, server_signing_public_key: signing, server_key_generation: 0, server_revocation_sequence: 0, mailbox_id: mailbox_value, write_capability: write_value, bundle_capability: bundle_value });
                    }
                    match save_vault(&path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Boîte différée enregistrée dans le coffre chiffré.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                }, "Enregistrer la boîte" }
                div { class: "mailbox-replicas",
                    strong { "Copies autorisées · {contact.mailbox_replicas.len()}/{akrat_core::MAX_MAILBOX_REPLICAS}" }
                    p { class: "quiet", "AKRAT dépose le même ciphertext sur chaque boîte choisie. La boîte personnelle correspondante doit aussi être enregistrée dans Réseau sur l’appareil du contact." }
                    for route in contact.mailbox_replicas.iter() {
                        div { class: "mailbox-replica-row",
                            span { "{route.endpoint} · boîte {route.mailbox_id}" }
                            button { class: "secondary compact", onclick: {
                                let endpoint = route.endpoint.clone();
                                let mailbox = route.mailbox_id.clone();
                                let fingerprint = replicas_fp.clone();
                                let route_path = replicas_path.clone();
                                move |_| {
                                    let phrase = passphrase.read().clone();
                                    let mut data = match load_vault(&route_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                                    if let Some(item) = data.contacts.iter_mut().find(|item| item.fingerprint == fingerprint) {
                                        item.mailbox_replicas.retain(|route| route.endpoint != endpoint || route.mailbox_id != mailbox);
                                    }
                                    match save_vault(&route_path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Copie de boîte retirée de cette route.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                                }
                            }, "Retirer" }
                        }
                    }
                    if contact.mailbox_replicas.len() < akrat_core::MAX_MAILBOX_REPLICAS {
                        label { "Serveur de copie · hôte:port" input { value: "{replica_endpoint}", placeholder: "mail.example.net:47475", oninput: move |e| replica_endpoint.set(e.value()) } }
                        label { "Clé publique Noise · hex" input { value: "{replica_noise_key}", oninput: move |e| replica_noise_key.set(e.value()) } }
                        label { "Clé de signature · hex" input { value: "{replica_signing_key}", oninput: move |e| replica_signing_key.set(e.value()) } }
                        label { "Identifiant de boîte" input { value: "{replica_mailbox_id}", oninput: move |e| replica_mailbox_id.set(e.value()) } }
                        label { "Capacité de dépôt" input { r#type: "password", value: "{replica_write_capability}", oninput: move |e| replica_write_capability.set(e.value()) } }
                        label { "Capacité de lecture des préclés" input { r#type: "password", value: "{replica_bundle_capability}", oninput: move |e| replica_bundle_capability.set(e.value()) } }
                        button { class: "secondary compact", onclick: {
                            let route_path = replicas_path.clone();
                            let fingerprint = replicas_fp.clone();
                            move |_| {
                            let phrase = passphrase.read().clone();
                            let mut data = match load_vault(&route_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                            let endpoint_value = replica_endpoint.read().trim().to_string();
                            let noise = match hex::decode(replica_noise_key.read().trim()) { Ok(key) if key.len() == 32 => key, _ => { notice.set("La clé Noise de la copie doit contenir 32 octets en hexadécimal.".into()); return; } };
                            let signing = match hex::decode(replica_signing_key.read().trim()) { Ok(key) if key.len() == 32 => key, _ => { notice.set("La clé de signature de la copie doit contenir 32 octets en hexadécimal.".into()); return; } };
                            let mailbox = replica_mailbox_id.read().trim().to_string();
                            let write = replica_write_capability.read().trim().to_string();
                            let bundle = replica_bundle_capability.read().trim().to_string();
                            if endpoint_value.is_empty() || mailbox.is_empty() || write.is_empty() || bundle.is_empty() { notice.set("Complétez les paramètres de la Mailbox de copie.".into()); return; }
                            let Some(item) = data.contacts.iter_mut().find(|item| item.fingerprint == fingerprint) else { notice.set("Contact introuvable.".into()); return; };
                            if item.mailbox_route.as_ref().is_some_and(|route| route.endpoint == endpoint_value && route.mailbox_id == mailbox)
                                || item.mailbox_replicas.iter().any(|route| route.endpoint == endpoint_value && route.mailbox_id == mailbox)
                            { notice.set("Cette boîte figure déjà dans les routes de copie.".into()); return; }
                            item.mailbox_replicas.push(MailboxRoute { endpoint: endpoint_value, server_noise_public_key: noise, server_signing_public_key: signing, server_key_generation: 0, server_revocation_sequence: 0, mailbox_id: mailbox, write_capability: write, bundle_capability: bundle });
                            match save_vault(&route_path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); replica_endpoint.set(String::new()); replica_noise_key.set(String::new()); replica_signing_key.set(String::new()); replica_mailbox_id.set(String::new()); replica_write_capability.set(String::new()); replica_bundle_capability.set(String::new()); notice.set("Boîte de copie ajoutée aux destinations autorisées.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                        } }, "Ajouter une copie" }
                    }
                }
            }
        }
    } }
}

#[component]
fn NetworkPage(
    vault: Signal<Option<VaultData>>,
    listen_stops: Signal<HashMap<String, tokio::sync::watch::Sender<bool>>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    path: PathBuf,
    passphrase: Signal<String>,
    notice: Signal<String>,
) -> Element {
    let identities = vault
        .read()
        .as_ref()
        .map(|v| {
            v.identities
                .iter()
                .map(|i| (i.id.clone(), i.name.clone()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let online_ids = listen_stops.read().keys().cloned().collect::<Vec<_>>();
    let mut selected_identity = use_signal(|| {
        identities
            .first()
            .map(|item| item.0.clone())
            .unwrap_or_default()
    });
    let mut endpoint = use_signal(String::new);
    let mut noise_key = use_signal(String::new);
    let mut signing_key = use_signal(String::new);
    let mut mailbox_id = use_signal(String::new);
    let mut write_capability = use_signal(String::new);
    let mut read_capability = use_signal(String::new);
    let mut bundle_capability = use_signal(String::new);
    let mut relay_url_input = use_signal(String::new);
    let mut relay_fingerprint_input = use_signal(String::new);
    let mut evidence_input = use_signal(String::new);
    let relay_settings = vault
        .read()
        .as_ref()
        .map(|data| data.relay_settings.clone())
        .unwrap_or_default();
    let configured_minimum_trust = relay_settings.minimum_trust;
    let inbox_path = path.clone();
    let relay_path = path.clone();
    let relay_rows = relay_settings
        .custom_relays
        .iter()
        .enumerate()
        .map(|(index, url)| {
            let record = relay_settings
                .operational_records
                .iter()
                .find(|record| record.relay_url == *url);
            let disposition = record.map_or("allowed", |record| match record.disposition {
                akrat_trust::RelayDisposition::Allowed => "allowed",
                akrat_trust::RelayDisposition::Favorite => "favorite",
                akrat_trust::RelayDisposition::Monitor => "monitor",
                akrat_trust::RelayDisposition::Quarantined => "quarantined",
                akrat_trust::RelayDisposition::Blocked => "blocked",
            });
            let measurements = record.map_or_else(
                || "Disponibilité non mesurée".to_string(),
                |record| {
                    let availability = record
                        .availability_percent()
                        .map_or_else(|| "—".to_string(), |value| format!("{value}%"));
                    let latency = record
                        .latency_ewma_ms
                        .map_or_else(|| "—".to_string(), |value| format!("{value} ms"));
                    format!(
                                    "Service HTTP {availability} · latence moyenne {latency} · {} succès / {} échecs · {} identité(s) refusée(s)",
                        record.successful_checks,
                                    record.failed_checks,
                                    record.identity_verification_failures
                    )
                },
            );
            (index, url.clone(), disposition, measurements)
        })
        .collect::<Vec<_>>();
    rsx! {
        section { class: "page-scroll",
            div { class: "eyebrow", "RÉSEAU PAIR À PAIR" }
            h1 { "Réseau" }
            p { class: "intro", "AKRAT prépare automatiquement vos identités à recevoir des connexions. Votre identifiant réseau reste le même quand vous changez de Wi-Fi ou passez en réseau mobile." }
            section { class: "panel network-panel",
                div { class: "panel-title", "Disponibilité de vos identités" }
                if identities.is_empty() {
                    p { class: "quiet", "Créez une identité pour rendre AKRAT joignable." }
                } else {
                    for (id, name) in identities.iter() {
                        div { class: "network-identity",
                            span { class: if online_ids.contains(id) { "status-dot live" } else { "status-dot" } }
                            div { class: "record-main", strong { "{name}" } span { class: "quiet", if online_ids.contains(id) { "Service démarré · relais dans le journal" } else { "Démarrage du service réseau…" } } }
                        }
                    }
                }
            }
            section { class: "panel mailbox-inbox-form",
                div { class: "panel-title", "Relais P2P" }
                p { class: "quiet", "Iroh tente d’abord la connexion directe et utilise ensuite les relais configurés. Le relais transporte des paquets chiffrés de bout en bout. Les relais personnalisés remplacent les relais publics par défaut." }
                p { class: "quiet", "Quand plusieurs chemins sont disponibles, AKRAT garde la connexion directe prioritaire, puis préfère un relais marqué Favori aux relais simplement autorisés. Si le favori devient indisponible, un autre relais autorisé peut prendre le relais." }
                label { "Niveau de confiance minimum" select {
                    value: "{relay_settings.minimum_trust as u8}",
                    onchange: {
                        let path = relay_path.clone();
                        move |event: Event<FormData>| {
                            let Ok(level) = event.value().parse::<u8>() else { return; };
                            let trust = match level { 0 => akrat_core::RelayTrustLevel::Unknown, 1 => akrat_core::RelayTrustLevel::IdentityVerified, 2 => akrat_core::RelayTrustLevel::DistributionVerified, _ => { notice.set("L’attestation matérielle d’exécution n’est pas disponible dans cette version.".into()); return; } };
                            let phrase = passphrase.read().clone();
                            let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                            data.relay_settings.minimum_trust = trust;
                            if let Err(error) = data.relay_settings.relay_mode() { notice.set(error); return; }
                            match save_vault(&path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Politique de confiance mise à jour.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                        }
                    },
                    option { value: "0", "0 · Autoriser les relais non vérifiés" }
                    option { value: "1", "1 · Exiger une identité épinglée" }
                    option { value: "2", "2 · Exiger une distribution AKRAT signée" }
                    option { value: "3", disabled: true, "3 · Exécution attestée · indisponible" }
                } }
                p { class: "quiet", "Le niveau 1 vérifie l’identité Ed25519 épinglée. Le niveau 2 vérifie aussi une attestation de release signée qui lie le dépôt, le tag, le commit, le protocole et l’empreinte du binaire déclaré. Cela n’atteste pas le code réellement exécuté. Le niveau 3 reste indisponible." }
                if relay_settings.custom_relays.is_empty() {
                    p { class: "network-identity", if relay_settings.minimum_trust >= akrat_core::RelayTrustLevel::IdentityVerified { "Mode strict · relais non épinglés désactivés · connexions directes seulement" } else if relay_settings.use_default_relays { "Relais publics Iroh activés" } else { "Relais désactivés · connexions directes seulement" } }
                } else {
                    for (index, url, disposition, measurements) in relay_rows.clone() {
                        div { class: "network-identity",
                            div { class: "record-main",
                                strong { "{url}" }
                                span { class: "quiet", "{measurements}" }
                                label { "Décision locale" select {
                                    value: "{disposition}",
                                    onchange: {
                                        let path = relay_path.clone();
                                        let url = url.clone();
                                        move |event: Event<FormData>| {
                                            let disposition = match event.value().as_str() {
                                                "allowed" => akrat_trust::RelayDisposition::Allowed,
                                                "favorite" => akrat_trust::RelayDisposition::Favorite,
                                                "monitor" => akrat_trust::RelayDisposition::Monitor,
                                                "quarantined" => akrat_trust::RelayDisposition::Quarantined,
                                                "blocked" => akrat_trust::RelayDisposition::Blocked,
                                                _ => return,
                                            };
                                            let phrase = passphrase.read().clone();
                                            let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                                            let Some(record) = data.relay_settings.operational_records.iter_mut().find(|record| record.relay_url == url) else {
                                                data.relay_settings.operational_records.push(akrat_trust::RelayOperationalRecord { relay_url: url.clone(), disposition, ..akrat_trust::RelayOperationalRecord::default() });
                                                match save_vault(&path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Décision locale enregistrée.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                                                return;
                                            };
                                            record.disposition = disposition;
                                            match save_vault(&path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Décision locale enregistrée. Les services réseau redémarrent.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                                        }
                                    },
                                    option { value: "allowed", "Autorisé" }
                                    option { value: "favorite", "Favori" }
                                    option { value: "monitor", "Sous surveillance" }
                                    option { value: "quarantined", "Quarantaine" }
                                    option { value: "blocked", "Bloqué" }
                                } }
                            }
                            button { class: "secondary compact", onclick: {
                                let path = relay_path.clone();
                                move |_| {
                                    let phrase = passphrase.read().clone();
                                    let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                                    let removed = if index < data.relay_settings.custom_relays.len() { Some(data.relay_settings.custom_relays.remove(index)) } else { None };
                                    if let Some(url) = removed {
                                        data.relay_settings.identity_pins.retain(|pin| pin.relay_url != url);
                                        data.relay_settings.operational_records.retain(|record| record.relay_url != url);
                                    }
                                    if data.relay_settings.custom_relays.is_empty() { data.relay_settings.use_default_relays = true; }
                                    match save_vault(&path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Relais retiré. Les services réseau redémarrent.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                                }
                            }, "Retirer" }
                            button { class: "secondary compact", onclick: {
                                let path = relay_path.clone();
                                let url = url.clone();
                                let expected_fingerprint = relay_settings.identity_pins.iter()
                                    .find(|pin| pin.relay_url == url)
                                    .map(|pin| pin.fingerprint.clone());
                                move |_| {
                                    let Some(expected_fingerprint) = expected_fingerprint.clone() else {
                                        notice.set("Épinglez d’abord l’identité cryptographique attendue pour mesurer ce relais.".into());
                                        return;
                                    };
                                    let phrase = passphrase.read().clone();
                                    let task_path = path.clone();
                                    let task_url = url.clone();
                                    spawn(async move {
                                        let started = std::time::Instant::now();
                                        let mut health_url = match reqwest::Url::parse(&task_url) {
                                            Ok(url) => url,
                                            Err(_) => { notice.set("URL de relais invalide.".into()); return; }
                                        };
                                        if health_url.set_scheme("http").is_err() || health_url.set_port(Some(8090)).is_err() {
                                            notice.set("Adresse de vérification du relais invalide.".into());
                                            return;
                                        }
                                        health_url.set_path("/health");
                                        health_url.set_query(None);
                                        health_url.set_fragment(None);
                                        let health_succeeded = match reqwest::Client::builder()
                                            .connect_timeout(std::time::Duration::from_secs(5))
                                            .timeout(std::time::Duration::from_secs(8))
                                            .build()
                                        {
                                            Ok(client) => client.get(health_url).send().await.is_ok_and(|response| response.status().is_success()),
                                            Err(_) => false,
                                        };
                                        let health_elapsed = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
                                        let result = akrat_trust::verify_remote_relay_identity_with_trust(
                                            &task_url,
                                            &expected_fingerprint,
                                            configured_minimum_trust,
                                        ).await;
                                        let mut data = match load_vault(&task_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                                        let record = if let Some(record) = data.relay_settings.operational_records.iter_mut().find(|record| record.relay_url == task_url) {
                                            record
                                        } else {
                                            data.relay_settings.operational_records.push(akrat_trust::RelayOperationalRecord { relay_url: task_url.clone(), ..akrat_trust::RelayOperationalRecord::default() });
                                            data.relay_settings.operational_records.last_mut().expect("record just inserted")
                                        };
                                        record.record_check(health_succeeded, health_succeeded.then_some(health_elapsed), chrono::Utc::now().timestamp().max(0) as u64);
                                        record.record_identity_verification(result.is_ok());
                                        match save_vault(&task_path, &mut data, &phrase) {
                                            Ok(()) => {
                                                vault.set(Some(data));
                                                match result {
                                                    Ok(_) => notice.set(format!("Identité vérifiée · service HTTP joignable en {health_elapsed} ms.")),
                                                    Err(error) if health_succeeded => notice.set(format!("Service joignable · identité ou provenance refusée, pas une preuve de malveillance : {error}")),
                                                    Err(error) => notice.set(format!("Service HTTP indisponible · ce résultat n’établit pas une faute : {error}")),
                                                }
                                            }
                                            Err(error) => notice.set(format!("Enregistrement impossible : {error}")),
                                        }
                                    });
                                }
                            }, "Tester" }
                        }
                    }
                }
                label { "URL du relais Iroh · HTTPS" input { value: "{relay_url_input}", placeholder: "https://relay.example.org", oninput: move |e| relay_url_input.set(e.value()) } }
                label { "Empreinte Ed25519 attendue · 64 caractères hexadécimaux, à comparer avec l’opérateur" input { value: "{relay_fingerprint_input}", placeholder: "Empreinte fournie hors bande", oninput: move |e| relay_fingerprint_input.set(e.value()) } }
                button { class: "secondary", onclick: {
                    let path = relay_path.clone();
                    move |_| {
                        let value = relay_url_input.read().trim().to_string();
                        if value.is_empty() { notice.set("Saisissez une URL de relais.".into()); return; }
                        let expected_fingerprint = relay_fingerprint_input.read().trim().to_string();
                        let phrase = passphrase.read().clone();
                        let task_path = path.clone();
                        spawn(async move {
                            let canonical = match value.parse::<iroh::RelayUrl>() { Ok(url) => url.to_string(), Err(_) => { notice.set("URL de relais Iroh invalide.".into()); return; } };
                            let pin = if expected_fingerprint.is_empty() { None } else {
                                match akrat_trust::verify_remote_relay_identity_with_trust(&canonical, &expected_fingerprint, configured_minimum_trust).await {
                                    Ok(pin) => Some(pin),
                                    Err(error) => { notice.set(format!("Identité du relais refusée : {error}")); return; }
                                }
                            };
                            let mut data = match load_vault(&task_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                            if data.relay_settings.custom_relays.contains(&canonical) { notice.set("Ce relais figure déjà dans la liste.".into()); return; }
                            data.relay_settings.custom_relays.push(canonical.clone());
                            if let Some(pin) = pin { data.relay_settings.identity_pins.push(pin); }
                            data.relay_settings.use_default_relays = false;
                            if let Err(error) = data.relay_settings.relay_mode() { data.relay_settings.custom_relays.pop(); notice.set(error); return; }
                            match save_vault(&task_path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); relay_url_input.set(String::new()); relay_fingerprint_input.set(String::new()); notice.set("Relais ajouté. Les identités réseau redémarrent avec cette configuration.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                        });
                    }
                }, "Ajouter ce relais" }
                if !relay_settings.custom_relays.is_empty() {
                    button { class: "secondary", onclick: {
                        let path = relay_path.clone();
                        move |_| {
                            let phrase = passphrase.read().clone();
                            let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                            data.relay_settings.custom_relays.clear();
                            data.relay_settings.identity_pins.clear();
                            data.relay_settings.operational_records.clear();
                            data.relay_settings.use_default_relays = true;
                            match save_vault(&path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Relais publics Iroh réactivés.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                        }
                    }, "Revenir aux relais publics Iroh" }
                }
            }
            section { class: "panel mailbox-inbox-form",
                div { class: "panel-title", "Preuves cryptographiques partagées" }
                p { class: "quiet", "Collez une preuve JSON reçue d’un autre participant. AKRAT ne retient que deux déclarations Ed25519 contradictoires liées au même relais et au même défi frais. Une panne réseau seule ne constitue pas une faute." }
                label { "Preuve d’équivoque · JSON, 64 Kio maximum" textarea { value: "{evidence_input}", rows: "5", oninput: move |event| evidence_input.set(event.value()) } }
                button { class: "secondary", onclick: {
                    let path = relay_path.clone();
                    move |_| {
                        let bytes = evidence_input.read().as_bytes().to_vec();
                        let untrusted: akrat_trust::RelayEquivocationEvidence = match serde_json::from_slice(&bytes) {
                            Ok(evidence) if bytes.len() <= akrat_trust::MAX_RELAY_EVIDENCE_JSON_BYTES => evidence,
                            _ => { notice.set("Preuve JSON invalide ou supérieure à 64 Kio.".into()); return; }
                        };
                        let phrase = passphrase.read().clone();
                        let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                        let Some(pin) = data.relay_settings.identity_pins.iter().find(|pin| pin.relay_url == untrusted.relay_url) else {
                            notice.set("Cette preuve concerne un relais sans identité épinglée dans ce coffre. Vérifiez et épinglez son identité avant d’évaluer la preuve.".into());
                            return;
                        };
                        let evidence = match akrat_trust::parse_and_verify_relay_equivocation_evidence(&bytes, &pin.fingerprint) {
                            Ok(evidence) => evidence,
                            Err(error) => { notice.set(format!("Preuve cryptographique refusée : {error}")); return; }
                        };
                        let url = evidence.relay_url.clone();
                        if !data.relay_settings.verified_evidence.contains(&evidence) {
                            if data.relay_settings.verified_evidence.len() >= 64 {
                                notice.set("Le coffre contient déjà la limite de 64 preuves vérifiées.".into());
                                return;
                            }
                            data.relay_settings.verified_evidence.push(evidence);
                        }
                        if let Some(record) = data.relay_settings.operational_records.iter_mut().find(|record| record.relay_url == url) {
                            record.disposition = akrat_trust::RelayDisposition::Quarantined;
                        } else {
                            data.relay_settings.operational_records.push(akrat_trust::RelayOperationalRecord {
                                relay_url: url,
                                disposition: akrat_trust::RelayDisposition::Quarantined,
                                ..akrat_trust::RelayOperationalRecord::default()
                            });
                        }
                        match save_vault(&path, &mut data, &phrase) {
                            Ok(()) => { vault.set(Some(data)); evidence_input.set(String::new()); notice.set("Preuve vérifiée indépendamment, conservée dans le coffre et relais mis en quarantaine sur cet appareil.".into()); }
                            Err(error) => notice.set(format!("Enregistrement impossible : {error}")),
                        }
                    }
                }, "Vérifier la preuve et mettre en quarantaine" }
                if let Some(evidence) = relay_settings.verified_evidence.last() {
                    p { class: "quiet", "{relay_settings.verified_evidence.len()} preuve(s) vérifiée(s). Dernière preuve : {evidence.relay_url} · observée le {evidence.observed_at_unix_seconds}." }
                    button { class: "secondary compact", onclick: {
                        let serialized = serde_json::to_string_pretty(evidence).unwrap_or_default();
                        move |_| {
                            let value = serialized.clone();
                            spawn(async move { if copy_to_clipboard(value).await { notice.set("Preuve copiée pour partage.".into()); } else { notice.set("Copie impossible · sélectionnez la preuve dans votre coffre.".into()); } });
                        }
                    }, "Copier la dernière preuve vérifiée" }
                    button { class: "secondary compact", onclick: {
                        let evidence = evidence.clone();
                        let sessions = sessions;
                        move |_| {
                            let recipients = sessions.read().values().cloned().collect::<Vec<_>>();
                            if recipients.is_empty() {
                                notice.set("Aucun contact vérifié n’a une session active pour recevoir cette preuve.".into());
                                return;
                            }
                            let sent = recipients.iter().filter(|session| session.send_relay_evidence(evidence.clone()).is_ok()).count();
                            notice.set(format!("Preuve vérifiée mise en file sur {sent} session(s) chiffrée(s). Chaque destinataire la vérifiera et décidera localement."));
                        }
                    }, "Partager avec les contacts connectés" }
                }
            }
            section { class: "panel mailbox-inbox-form",
                div { class: "panel-title", "Boîte personnelle · messages différés" }
                p { class: "quiet", "Quand le coffre est déverrouillé, AKRAT publie automatiquement vos préclés et relève cette boîte toutes les 15 secondes." }
                if !identities.is_empty() {
                    label { "Identité concernée" select { value: "{selected_identity}", onchange: move |e| selected_identity.set(e.value()), for (id, name) in identities.iter() { option { value: "{id}", "{name}" } } } }
                    label { "Serveur · hôte:port" input { value: "{endpoint}", placeholder: "mail.example.net:47475", oninput: move |e| endpoint.set(e.value()) } }
                    label { "Clé publique Noise du serveur · hex" input { value: "{noise_key}", oninput: move |e| noise_key.set(e.value()) } }
                    label { "Clé de signature du serveur · hex" input { value: "{signing_key}", oninput: move |e| signing_key.set(e.value()) } }
                    label { "Identifiant de boîte" input { value: "{mailbox_id}", oninput: move |e| mailbox_id.set(e.value()) } }
                    label { "Capacité de dépôt · publication des préclés" input { r#type: "password", value: "{write_capability}", oninput: move |e| write_capability.set(e.value()) } }
                    label { "Capacité de récupération" input { r#type: "password", value: "{read_capability}", oninput: move |e| read_capability.set(e.value()) } }
                    label { "Capacité de lecture des préclés" input { r#type: "password", value: "{bundle_capability}", oninput: move |e| bundle_capability.set(e.value()) } }
                    button { class: "primary", onclick: move |_| {
                        let phrase = passphrase.read().clone();
                        let mut data = match load_vault(&inbox_path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                        let endpoint_value = endpoint.read().trim().to_string();
                        let decode_key = |value: String| -> Result<Vec<u8>, ()> { match hex::decode(value.trim()) { Ok(key) if key.len() == 32 => Ok(key), _ => Err(()) } };
                        let noise = match decode_key(noise_key.read().clone()) { Ok(key) => key, Err(()) => { notice.set("La clé Noise doit contenir 32 octets en hexadécimal.".into()); return; } };
                        let signing = match decode_key(signing_key.read().clone()) { Ok(key) => key, Err(()) => { notice.set("La clé de signature doit contenir 32 octets en hexadécimal.".into()); return; } };
                        let mailbox_value = mailbox_id.read().trim().to_string();
                        let write_value = write_capability.read().trim().to_string();
                        let read_value = read_capability.read().trim().to_string();
                        let bundle_value = bundle_capability.read().trim().to_string();
                        if endpoint_value.is_empty() || mailbox_value.is_empty() || write_value.is_empty() || read_value.is_empty() || bundle_value.is_empty() { notice.set("Complétez tous les paramètres de la boîte.".into()); return; }
                        let identity_id = selected_identity.read().clone();
                        data.mailbox_inboxes.retain(|item| item.identity_id != identity_id || item.endpoint != endpoint_value || item.mailbox_id != mailbox_value);
                        data.mailbox_inboxes.push(MailboxInbox { identity_id, endpoint: endpoint_value, server_noise_public_key: noise, server_signing_public_key: signing, server_key_generation: 0, server_revocation_sequence: 0, mailbox_id: mailbox_value, write_capability: write_value, read_capability: read_value, bundle_capability: bundle_value });
                        match save_vault(&inbox_path, &mut data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Boîte personnelle enregistrée dans le coffre chiffré.".into()); }, Err(error) => notice.set(format!("Enregistrement impossible : {error}")) }
                    }, "Enregistrer la boîte personnelle" }
                }
                if let Some(inboxes) = vault.read().as_ref().map(|data| data.mailbox_inboxes.clone()) {
                    for inbox in inboxes { div { class: "mailbox-route-summary", "{inbox.endpoint} · boîte {inbox.mailbox_id} · relève automatique active quand le coffre est ouvert" } }
                }
            }
            div { class: "callout", strong { "Comment AKRAT vous trouve" } p { "L’application annonce votre identifiant réseau stable au service de découverte, tente une liaison directe puis utilise un relais chiffré si nécessaire. Les deux appareils doivent être allumés, connectés à Internet et avoir AKRAT ouvert." } }
        }
    }
}

async fn copy_to_clipboard(text: String) -> bool {
    let mut eval = document::eval(
        r#"
        const text = await dioxus.recv();
        let copied = false;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                copied = true;
            }
        } catch (_) {}
        if (!copied) {
            const field = document.createElement('textarea');
            field.value = text;
            field.setAttribute('readonly', '');
            field.style.position = 'fixed';
            field.style.opacity = '0';
            field.style.fontSize = '16px';
            document.body.appendChild(field);
            field.focus();
            field.select();
            field.setSelectionRange(0, field.value.length);
            try { copied = document.execCommand('copy'); } catch (_) {}
            field.remove();
        }
        dioxus.send(copied);
        "#,
    );
    if eval.send(text).is_err() {
        return false;
    }
    eval.recv::<bool>().await.unwrap_or(false)
}

#[component]
fn ChatPage(
    vault: Signal<Option<VaultData>>,
    passphrase: Signal<String>,
    path: PathBuf,
    mut active_conversation: Signal<Option<String>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    draft: Signal<String>,
    notice: Signal<String>,
    mut trace: Signal<Vec<String>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
    on_setup: EventHandler<MouseEvent>,
) -> Element {
    let stored = vault.read();
    let mut show_group_form = use_signal(|| false);
    let mut group_name_draft = use_signal(String::new);
    let mut group_identity_choice = use_signal(String::new);
    let mut group_contact_choices = use_signal(Vec::<String>::new);
    let mut conversation_items = Vec::<(String, String, String, u64, bool)>::new();
    let mut group_contacts = Vec::<(String, String)>::new();
    if let Some(data) = stored.as_ref() {
        for identity in &data.identities {
            for contact in data
                .contacts
                .iter()
                .filter(|contact| contact.manually_verified)
            {
                let key = format!("{}:{}", identity.id, contact.fingerprint);
                let latest = data
                    .messages
                    .iter()
                    .filter(|message| message.conversation == key)
                    .max_by_key(|message| message.timestamp);
                let preview = latest
                    .map(|message| message.text.chars().take(54).collect::<String>())
                    .unwrap_or_else(|| "Commencer une conversation".into());
                let timestamp = latest.map(|message| message.timestamp).unwrap_or_default();
                let connected = sessions.read().contains_key(&key);
                conversation_items.push((
                    key,
                    format!("{} · {}", contact.name, identity.name),
                    preview,
                    timestamp,
                    connected,
                ));
            }
        }
        group_contacts = data
            .contacts
            .iter()
            .filter(|contact| contact.manually_verified)
            .map(|contact| (contact.fingerprint.clone(), contact.name.clone()))
            .collect();
        for group in data.groups.iter().filter(|group| {
            group.members.iter().any(|member| {
                data.identities
                    .iter()
                    .any(|identity| member.public_key == identity.public_key())
            })
        }) {
            let key = format!("group:{}", group.group_id);
            let latest = data
                .messages
                .iter()
                .filter(|message| message.conversation == key)
                .max_by_key(|message| message.timestamp);
            let preview = latest
                .map(|message| message.text.chars().take(54).collect::<String>())
                .unwrap_or_else(|| {
                    format!(
                        "{} membre(s) · époque {}",
                        group
                            .members
                            .iter()
                            .filter(|member| member.accepted)
                            .count(),
                        group.epoch
                    )
                });
            let timestamp = latest.map(|message| message.timestamp).unwrap_or_default();
            let connected = group
                .members
                .iter()
                .filter(|member| member.accepted && member.fingerprint != group.creator_fingerprint)
                .any(|member| {
                    data.identities.iter().any(|identity| {
                        sessions
                            .read()
                            .contains_key(&format!("{}:{}", identity.id, member.fingerprint))
                    })
                });
            conversation_items.push((
                key,
                format!("{} · Groupe", group.name),
                preview,
                timestamp,
                connected,
            ));
        }
    }
    conversation_items.sort_by_key(|item| std::cmp::Reverse(item.3));
    let conversation = active_conversation
        .read()
        .clone()
        .or_else(|| conversation_items.first().map(|item| item.0.clone()));
    let mut messages = conversation
        .as_ref()
        .and_then(|key| {
            stored.as_ref().map(|v| {
                v.messages
                    .iter()
                    .filter(|m| &m.conversation == key)
                    .cloned()
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();
    messages.sort_by_key(|message| message.timestamp);
    let active_group_id = conversation
        .as_deref()
        .and_then(|key| key.strip_prefix("group:").map(str::to_string));
    let active_group = active_group_id.as_deref().and_then(|group_id| {
        stored
            .as_ref()?
            .groups
            .iter()
            .find(|group| group.group_id == group_id)
    });
    let peer_name = active_group
        .map(|group| group.name.clone())
        .or_else(|| {
            conversation
                .as_ref()
                .and_then(|key| key.split_once(':').map(|(_, fp)| fp))
                .and_then(|fp| {
                    stored
                        .as_ref()?
                        .contacts
                        .iter()
                        .find(|c| c.fingerprint == fp)
                        .map(|c| c.name.clone())
                })
        })
        .unwrap_or_else(|| "Conversation".into());
    let connected = conversation.as_ref().is_some_and(|key| {
        if let Some(group_id) = key.strip_prefix("group:") {
            stored
                .as_ref()
                .and_then(|data| data.groups.iter().find(|group| group.group_id == group_id))
                .is_some_and(|group| {
                    group.members.iter().any(|member| {
                        member.accepted
                            && stored.as_ref().is_some_and(|data| {
                                data.identities.iter().any(|identity| {
                                    sessions.read().contains_key(&format!(
                                        "{}:{}",
                                        identity.id, member.fingerprint
                                    ))
                                })
                            })
                    })
                })
        } else {
            sessions.read().contains_key(key)
        }
    });
    let group_pending = active_group.is_some_and(|group| {
        stored.as_ref().is_some_and(|data| {
            group.members.iter().any(|member| {
                !member.accepted
                    && data
                        .identities
                        .iter()
                        .any(|identity| identity.public_key() == member.public_key)
            })
        })
    });
    let connect_conversation = conversation.clone();
    let input_conversation = conversation.clone();
    let button_conversation = conversation.clone();
    let input_path = path.clone();
    let button_path = path.clone();
    let image_path = path.clone();
    let image_conversation = conversation.clone().unwrap_or_default();
    let group_create_path = path.clone();
    let group_accept_path = path.clone();
    let group_connect_path = path.clone();
    let group_accept_id = active_group_id.clone();
    let group_connect_id = active_group_id.clone();
    use_effect(move || {
        let selected = active_conversation.read().clone();
        let count = vault
            .read()
            .as_ref()
            .map(|data| {
                data.messages
                    .iter()
                    .filter(|message| selected.as_ref() == Some(&message.conversation))
                    .count()
            })
            .unwrap_or_default();
        let _ = (selected, count);
        let _ = document::eval(
            "requestAnimationFrame(() => { const list = document.querySelector('.message-list'); if (list) list.scrollTop = list.scrollHeight; });",
        );
    });
    rsx! {
        section { class: "chat-layout",
            aside { class: "conversation-list",
                div { class: "conversation-list-head", strong { "Conversations" } div { class: "conversation-list-actions", button { class: "icon-button", title: "Ajouter un contact", onclick: on_setup, "+" } button { class: "icon-button", title: "Créer un groupe", onclick: move |_| { let next = !*show_group_form.read(); show_group_form.set(next); }, "G+" } } }
                if *show_group_form.read() {
                    div { class: "group-create-panel",
                        strong { "Nouveau groupe" }
                        input { value: "{group_name_draft}", placeholder: "Nom du groupe", oninput: move |e| group_name_draft.set(e.value()) }
                        if let Some(data) = stored.as_ref() {
                            label { class: "group-field-label", "Identité du groupe" }
                            select { value: "{group_identity_choice}", onchange: move |e| group_identity_choice.set(e.value()),
                                for identity in data.identities.iter() { option { value: "{identity.id}", "{identity.name}" } }
                            }
                        }
                        label { class: "group-field-label", "Inviter des contacts vérifiés" }
                        if group_contacts.is_empty() { p { class: "quiet", "Vérifiez d’abord un contact dans Identités & contacts." } }
                        for (fingerprint, contact_name) in group_contacts.iter() {
                            label { class: "group-contact-choice",
                                input { r#type: "checkbox", checked: group_contact_choices.read().contains(fingerprint), onclick: { let fingerprint = fingerprint.clone(); move |_| { let mut choices = group_contact_choices.write(); if choices.contains(&fingerprint) { choices.retain(|choice| choice != &fingerprint); } else { choices.push(fingerprint.clone()); } } } }
                                span { "{contact_name}" }
                            }
                        }
                        button { class: "primary", onclick: move |_| {
                            let name = group_name_draft.read().trim().to_string();
                            let identity_id = group_identity_choice.read().clone();
                            let selected_contacts = group_contact_choices.read().clone();
                            if create_group_action(name, identity_id, selected_contacts, GroupUiContext { path: group_create_path.clone(), passphrase, vault, active_conversation, sessions, notice, event_sender }) {
                                show_group_form.set(false);
                                group_name_draft.set(String::new());
                                group_contact_choices.set(Vec::new());
                            }
                        }, "Créer et inviter" }
                    }
                }
                if conversation_items.is_empty() { p { class: "quiet conversation-empty", "Ajoutez puis vérifiez un contact pour commencer." } }
                for (key, title, preview, timestamp, online) in conversation_items.iter() {
                    button {
                        class: if conversation.as_ref() == Some(key) { "conversation-item selected" } else { "conversation-item" },
                        onclick: { let key = key.clone(); move |_| active_conversation.set(Some(key.clone())) },
                        span { class: if *online { "status-dot live" } else { "status-dot" } }
                        span { class: "conversation-item-copy", strong { "{title}" } span { "{preview}" } }
                        if *timestamp > 0 { span { class: "conversation-date", "{format_timestamp(*timestamp)}" } }
                    }
                }
            }
            main { class: "chat-stage",
                if conversation.is_some() {
                    div { class: "chat-head",
                        div { class: "chat-head-copy", div { class: "eyebrow", if active_group_id.is_some() { "GROUPE · FAN-OUT CHIFFRÉ PAIRWISE" } else { "MESSAGERIE CHIFFRÉE · NOISE XX" } } h1 { "{peer_name}" } span { class: if connected { "verified" } else { "quiet" }, if connected { "MEMBRE JOIGNABLE" } else { "HORS LIGNE" } } }
                        if active_group_id.is_some() {
                            if group_pending {
                                button { class: "primary compact", onclick: move |_| if let Some(id) = group_accept_id.clone() { accept_group_invitation(id, group_accept_path.clone(), passphrase, vault, sessions, event_sender, notice) }, "Accepter l’invitation" }
                            }
                            button { class: "secondary compact", onclick: move |_| if let Some(id) = group_connect_id.clone() { connect_group_members(id, group_connect_path.clone(), passphrase, event_sender) }, "Connecter le groupe" }
                        } else if !connected {
                            button { class: "secondary compact", onclick: move |_| {
                                if let Some(key) = connect_conversation.clone() {
                                    let Some((identity_id, fingerprint)) = key.split_once(':') else { notice.set("Conversation invalide.".into()); return; };
                                    let identity = vault.read().as_ref().and_then(|data| data.identities.iter().find(|item| item.id == identity_id).map(Identity::detached_copy));
                                    let contact = vault.read().as_ref().and_then(|data| data.contacts.iter().find(|item| item.fingerprint == fingerprint && item.manually_verified).cloned());
                                    match (identity, contact) {
                                        (Some(identity), Some(contact)) => runtime::connect(identity, contact, event_sender.read().clone()),
                                        _ => notice.set("Vérifiez ce contact et l’identité associée.".into()),
                                    }
                                }
                            }, "Se connecter" }
                        }
                    }
                    if let Some(group) = active_group.cloned() {
                        GroupAdminPanel {
                            group,
                            path: path.clone(),
                            passphrase,
                            vault,
                            sessions,
                            event_sender,
                            notice,
                        }
                    }
                    div { class: "message-list", id: "message-list",
                        if messages.is_empty() { div { class: "chat-empty", "Conversation prête · envoyez le premier message." } }
                        for message in messages {
                            MessageCard {
                                message,
                                draft,
                                path: path.clone(),
                                passphrase,
                                vault,
                                sessions,
                                notice,
                                trace,
                                event_sender,
                            }
                        }
                    }
                    div { class: "composer",
                        label { class: "attachment-picker", title: "Joindre une image", "＋ Image"
                            input { r#type: "file", accept: "image/png,image/jpeg,image/webp", onchange: move |event| {
                                let Some(file) = event.files().into_iter().next() else { return; };
                                if file.size() > attachments::MAX_ATTACHMENT_BYTES as u64 { notice.set("Image limitée à 16 Mio.".into()); return; }
                                let name = file.name();
                                let path = image_path.clone();
                                let conversation = image_conversation.clone();
                                spawn(async move {
                                    match file.read_bytes().await {
                                        Ok(bytes) => send_image_action(conversation, name, bytes.to_vec(), ImageActionContext { path, passphrase, vault, sessions, notice, trace, event_sender }),
                                        Err(error) => notice.set(format!("Lecture de l’image impossible : {error}")),
                                    }
                                });
                            } }
                        }
                        textarea {
                            value: "{draft}", placeholder: "Écrire un message… · Entrée pour envoyer",
                            oninput: move |e| draft.set(e.value()),
                            onkeydown: move |event| if event.key() == Key::Enter && !event.modifiers().shift() {
                                event.prevent_default();
                                    if let Some(key) = input_conversation.clone() { if key.starts_with("group:") { submit_group_message(key, draft, GroupUiContext { path: input_path.clone(), passphrase, vault, active_conversation, sessions, notice, event_sender }); } else { submit_message(key, draft, input_path.clone(), passphrase, vault, sessions, notice, trace, event_sender); } }
                            }
                        }
                        button { class: "primary", onclick: move |_| if let Some(key) = button_conversation.clone() { if key.starts_with("group:") { submit_group_message(key, draft, GroupUiContext { path: button_path.clone(), passphrase, vault, active_conversation, sessions, notice, event_sender }); } else { submit_message(key, draft, button_path.clone(), passphrase, vault, sessions, notice, trace, event_sender); } }, if connected { "Envoyer" } else { "Mettre en file" } }
                    }
                } else {
                    div { class: "chat-empty-state",
                        div { class: "message-illustration", span { class: "bubble bubble-back" } span { class: "bubble bubble-front", span { "•••" } } }
                        div { class: "eyebrow", "MESSAGERIE PAIR À PAIR" }
                        h1 { "La parole circule." }
                        p { "Choisissez un contact dans la liste ou ajoutez une nouvelle personne." }
                        button { class: "primary empty-action", onclick: on_setup, "Ajouter un contact" }
                    }
                }
            }
        }
    }
}

#[component]
fn GroupAdminPanel(
    group: GroupState,
    path: PathBuf,
    passphrase: Signal<String>,
    vault: Signal<Option<VaultData>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
    notice: Signal<String>,
) -> Element {
    let mut rename_draft = use_signal(|| group.name.clone());
    let local_member = vault.read().as_ref().and_then(|data| {
        data.identities.iter().find_map(|identity| {
            group
                .members
                .iter()
                .find(|member| member.accepted && member.public_key == identity.public_key())
                .map(|member| (identity.fingerprint(), member.role))
        })
    });
    let can_manage = local_member
        .as_ref()
        .is_some_and(|(_, role)| matches!(role, GroupRole::Owner | GroupRole::Admin));
    let is_owner = local_member
        .as_ref()
        .is_some_and(|(_, role)| *role == GroupRole::Owner);
    let can_leave = local_member
        .as_ref()
        .is_some_and(|(_, role)| *role != GroupRole::Owner);
    let group_id = group.group_id.clone();
    let group_id_for_rename = group_id.clone();
    let path_for_rename = path.clone();
    let path_for_remove = path.clone();
    let path_for_role = path.clone();
    let path_for_leave = path.clone();
    rsx! {
        details { class: "group-admin-panel",
            summary { "Membres et administration · {group.members.len()}" }
            if can_manage {
                div { class: "group-admin-rename",
                    input { value: "{rename_draft}", maxlength: "64", placeholder: "Nom du groupe", oninput: move |event| rename_draft.set(event.value()) }
                    button { class: "secondary compact", onclick: move |_| {
                        apply_group_change_action(group_id_for_rename.clone(), GroupChange::Rename { name: rename_draft.read().trim().to_string() }, GroupManagementContext { path: path_for_rename.clone(), passphrase, vault, sessions, event_sender, notice });
                    }, "Renommer" }
                }
            }
            div { class: "group-admin-members",
                for member in group.members.iter() {
                    div { class: "group-admin-member",
                        div { strong { "{member.display_name}" } span { "{member.role:?} · " if member.accepted { "accepté" } else { "invité" } } }
                        if can_manage && member.accepted && member.role != GroupRole::Owner {
                            if is_owner {
                                button { class: "secondary compact", onclick: { let fingerprint = member.fingerprint.clone(); let role = if member.role == GroupRole::Admin { GroupRole::Member } else { GroupRole::Admin }; let group_id = group_id.clone(); let path = path_for_role.clone(); move |_| {
                                    apply_group_change_action(group_id.clone(), GroupChange::SetRole { fingerprint: fingerprint.clone(), role }, GroupManagementContext { path: path.clone(), passphrase, vault, sessions, event_sender, notice });
                                } }, if member.role == GroupRole::Admin { "Rétrograder" } else { "Promouvoir admin" } }
                            }
                            button { class: "secondary compact danger", onclick: { let fingerprint = member.fingerprint.clone(); let group_id = group_id.clone(); let path = path_for_remove.clone(); move |_| {
                                apply_group_change_action(group_id.clone(), GroupChange::Remove { fingerprint: fingerprint.clone() }, GroupManagementContext { path: path.clone(), passphrase, vault, sessions, event_sender, notice });
                            } }, "Retirer" }
                        }
                    }
                }
            }
            if can_leave {
                button { class: "secondary compact danger", onclick: move |_| {
                    apply_group_change_action(group_id.clone(), GroupChange::Leave, GroupManagementContext { path: path_for_leave.clone(), passphrase, vault, sessions, event_sender, notice });
                }, "Quitter le groupe" }
            }
        }
    }
}

#[component]
fn MessageCard(
    message: StoredMessage,
    mut draft: Signal<String>,
    path: PathBuf,
    passphrase: Signal<String>,
    mut vault: Signal<Option<VaultData>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    mut notice: Signal<String>,
    mut trace: Signal<Vec<String>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
) -> Element {
    let short_id = message.id.chars().take(8).collect::<String>();
    let outgoing = message.outgoing;
    let group_delivery_rows = vault
        .read()
        .as_ref()
        .and_then(|data| {
            let group_id = message.conversation.strip_prefix("group:")?;
            let group = data
                .groups
                .iter()
                .find(|group| group.group_id == group_id)?;
            let delivery = data.group_deliveries.iter().find(|delivery| {
                delivery.group_id == group_id && delivery.message_id == message.id
            })?;
            Some(
                delivery
                    .recipients
                    .iter()
                    .map(|recipient| {
                        let name = group
                            .members
                            .iter()
                            .find(|member| member.fingerprint == recipient.fingerprint)
                            .map(|member| member.display_name.clone())
                            .unwrap_or_else(|| recipient.fingerprint.chars().take(12).collect());
                        (name, recipient_status_label(recipient.status).to_string())
                    })
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap_or_default();
    let status = match message.delivery {
        DeliveryState::Pending => "EN ATTENTE",
        DeliveryState::Queued => "DANS LA FILE",
        DeliveryState::Sent => "TRANSMIS · ACCUSÉ EN ATTENTE",
        DeliveryState::MailboxStored => "STOCKÉ EN BOÎTE · EN ATTENTE DU DESTINATAIRE",
        DeliveryState::Received => "REÇU",
        DeliveryState::Acknowledged => "REMIS",
        DeliveryState::Unconfirmed => "NON CONFIRMÉ",
        DeliveryState::Expired => "EXPIRÉ · RENVOI DISPONIBLE",
    };
    let steps = match message.delivery {
        DeliveryState::Pending => vec![
            "Enregistré dans le coffre local",
            "En attente de transmission",
        ],
        DeliveryState::Queued => vec![
            "Enregistré et chiffré dans le coffre local",
            "Tentatives de connexion P2P automatiques",
        ],
        DeliveryState::Sent => vec![
            "Enregistré dans le coffre local",
            "Chiffré et transmis",
            "Accusé authentifié en attente",
        ],
        DeliveryState::MailboxStored => vec![
            "Chiffré de bout en bout avec PQXDH / Double Ratchet",
            "Dépôt confirmé par une boîte aux lettres",
            "En attente de récupération par le destinataire",
        ],
        DeliveryState::Received => vec![
            "Reçu sur le canal chiffré",
            "Authentifié et déchiffré",
            "Enregistré dans le coffre local",
            "Accusé chiffré envoyé",
        ],
        DeliveryState::Acknowledged => vec![
            "Enregistré dans le coffre local",
            "Chiffré et transmis",
            "Accusé authentifié · remis",
        ],
        DeliveryState::Unconfirmed => vec![
            "Enregistré dans le coffre local",
            "État de transmission incertain",
        ],
        DeliveryState::Expired => vec![
            "La boîte a signé l'expiration du ciphertext",
            "Le destinataire n'a pas confirmé la livraison",
            "Un renvoi peut être déclenché depuis le message",
        ],
    };
    rsx! {
        div { class: if outgoing { "message outgoing" } else { "message incoming" },
            if let Some(image_data) = message_attachment_data(&path, &message, &vault) {
                img { class: "message-attachment", src: "data:image/png;base64,{image_data}", alt: "Image jointe · {message.id}" }
            }
            div { class: "message-markdown", MarkdownNodeView { node: parse_markdown(&message.text).unwrap_or_else(|_| MarkdownNode { kind: MarkdownNodeKind::Text(message.text.clone()), children: Vec::new() }) } }
            div { class: "message-meta", span { class: "message-time", "{format_timestamp(message.timestamp)}" } span { class: "message-status", "{status}" } }
            if outgoing && message.delivery == DeliveryState::Expired {
                button { class: "secondary compact", onclick: move |_| {
                    draft.set(message.text.clone());
                    submit_message(
                        message.conversation.clone(),
                        draft,
                        path.clone(),
                        passphrase,
                        vault,
                        sessions,
                        notice,
                        trace,
                        event_sender,
                    );
                }, "Renvoyer" }
            }
            details { class: "message-details",
                summary { "Détails techniques · {short_id}" }
                div { class: "message-steps", for (index, step) in steps.iter().enumerate() { div { class: "message-step", span { "0{index}" } "{step}" } } }
                h4 { class: "delivery-timeline-title", "Parcours du message" }
                if message.delivery_events.is_empty() {
                    p { class: "quiet delivery-timeline-empty", "Aucun événement de livraison conservé pour cet ancien message." }
                } else {
                    div { class: "delivery-timeline",
                        for event in message.delivery_events.iter() {
                            div { class: "delivery-event",
                                span { class: if event.verified { "delivery-event-mark verified" } else { "delivery-event-mark" }, if event.verified { "✓" } else { "·" } }
                                div { class: "delivery-event-body",
                                    strong { "{delivery_event_label(event.kind)}" }
                                    span { class: "delivery-event-meta", "{delivery_actor_label(event.actor, event.actor_name.as_deref())} · {format_timestamp(event.timestamp)}" }
                                    if let Some(fingerprint) = event.actor_fingerprint.as_deref() {
                                        span { class: "delivery-event-proof", "Empreinte · {fingerprint}" }
                                    }
                                    if let Some(receipt) = event.receipt_sha256.as_deref() {
                                        details { class: "delivery-event-receipt",
                                            summary { if event.verified { "Reçu vérifié" } else { "Détails du reçu" } }
                                            code { "SHA-256 · {receipt}" }
                                            if let Some(bytes) = event.receipt_bytes.as_deref() {
                                                code { "{format_receipt(bytes)}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if !group_delivery_rows.is_empty() {
                    h4 { class: "delivery-timeline-title", "Livraison par membre" }
                    div { class: "group-delivery-list", for (name, status) in group_delivery_rows.iter() { div { span { "{name}" } strong { "{status}" } } } }
                }
            }
        }
    }
}

fn recipient_status_label(status: GroupRecipientStatus) -> &'static str {
    match status {
        GroupRecipientStatus::Pending => "En attente",
        GroupRecipientStatus::Sent => "Transmis",
        GroupRecipientStatus::Deposited => "Déposé sur Mailbox",
        GroupRecipientStatus::Received => "Reçu",
        GroupRecipientStatus::Unconfirmed => "Non confirmé",
        GroupRecipientStatus::Expired => "Expiré",
    }
}

#[component]
fn MarkdownNodeView(node: MarkdownNode) -> Element {
    let children = node.children;
    match node.kind {
        MarkdownNodeKind::Document | MarkdownNodeKind::Unsupported => {
            rsx! { for child in children { MarkdownNodeView { node: child } } }
        }
        MarkdownNodeKind::Text(text) => rsx! { span { "{text}" } },
        MarkdownNodeKind::InlineCode(text) => {
            rsx! { code { class: "markdown-inline-code", "{text}" } }
        }
        MarkdownNodeKind::Paragraph => {
            rsx! { p { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Heading(level) => match level {
            1 => rsx! { h1 { for child in children { MarkdownNodeView { node: child } } } },
            2 => rsx! { h2 { for child in children { MarkdownNodeView { node: child } } } },
            3 => rsx! { h3 { for child in children { MarkdownNodeView { node: child } } } },
            4 => rsx! { h4 { for child in children { MarkdownNodeView { node: child } } } },
            5 => rsx! { h5 { for child in children { MarkdownNodeView { node: child } } } },
            _ => rsx! { h6 { for child in children { MarkdownNodeView { node: child } } } },
        },
        MarkdownNodeKind::Quote => {
            rsx! { blockquote { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::CodeBlock(language) => {
            let class = language
                .map(|value| {
                    format!(
                        "markdown-code language-{}",
                        value
                            .chars()
                            .filter(|character| character.is_ascii_alphanumeric()
                                || *character == '-'
                                || *character == '_')
                            .take(32)
                            .collect::<String>()
                    )
                })
                .unwrap_or_else(|| "markdown-code".into());
            rsx! { pre { class: "{class}", code { for child in children { MarkdownNodeView { node: child } } } } }
        }
        MarkdownNodeKind::List(Some(_)) => {
            rsx! { ol { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::List(None) => {
            rsx! { ul { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Item => {
            rsx! { li { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Table(alignments) => {
            rsx! { MarkdownTableView { nodes: children, alignments } }
        }
        MarkdownNodeKind::TableHead => {
            rsx! { thead { tr { for child in children { MarkdownNodeView { node: child } } } } }
        }
        MarkdownNodeKind::TableRow => {
            rsx! { tr { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Emphasis => {
            rsx! { em { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Strong => {
            rsx! { strong { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Underline => {
            rsx! { u { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Strike => {
            rsx! { del { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Spoiler => rsx! { MarkdownSpoiler { nodes: children } },
        MarkdownNodeKind::Link(Some(url)) => {
            rsx! { a { href: "{url}", target: "_blank", rel: "noopener noreferrer", for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::Link(None) => {
            rsx! { span { class: "markdown-link-blocked", for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::TableCell => {
            rsx! { td { for child in children { MarkdownNodeView { node: child } } } }
        }
        MarkdownNodeKind::SoftBreak => rsx! { span { " " } },
        MarkdownNodeKind::HardBreak => rsx! { br {} },
        MarkdownNodeKind::Rule => rsx! { hr {} },
        MarkdownNodeKind::Task(checked) => {
            rsx! { input { r#type: "checkbox", checked, disabled: true } }
        }
    }
}

#[component]
fn MarkdownSpoiler(nodes: Vec<MarkdownNode>) -> Element {
    let mut revealed = use_signal(|| false);
    rsx! {
        button {
            class: if revealed() { "markdown-spoiler revealed" } else { "markdown-spoiler" },
            r#type: "button",
            aria_label: if revealed() { "Masquer le spoiler" } else { "Révéler le spoiler" },
            onclick: move |_| revealed.toggle(),
            if revealed() {
                for child in nodes { MarkdownNodeView { node: child } }
            } else {
                "Spoiler · révéler"
            }
        }
    }
}

#[component]
fn MarkdownTableView(nodes: Vec<MarkdownNode>, alignments: Vec<TableAlignment>) -> Element {
    rsx! {
        div { class: "markdown-table-scroll",
            table {
                for child in nodes {
                    match child.kind {
                        MarkdownNodeKind::TableHead => rsx! {
                            thead { tr {
                                for (index, cell) in child.children.into_iter().enumerate() {
                                    MarkdownTableCell { node: cell, alignment: alignments.get(index).copied().unwrap_or(TableAlignment::None), header: true }
                                }
                            } }
                        },
                        MarkdownNodeKind::TableRow => rsx! {
                            tbody { tr {
                                for (index, cell) in child.children.into_iter().enumerate() {
                                    MarkdownTableCell { node: cell, alignment: alignments.get(index).copied().unwrap_or(TableAlignment::None), header: false }
                                }
                            } }
                        },
                        _ => rsx! { MarkdownNodeView { node: child } },
                    }
                }
            }
        }
    }
}

#[component]
fn MarkdownTableCell(node: MarkdownNode, alignment: TableAlignment, header: bool) -> Element {
    let style = match alignment {
        TableAlignment::None => "text-align: left",
        TableAlignment::Left => "text-align: left",
        TableAlignment::Center => "text-align: center",
        TableAlignment::Right => "text-align: right",
    };
    let children = node.children;
    if header {
        rsx! { th { style: "{style}", for child in children { MarkdownNodeView { node: child } } } }
    } else {
        rsx! { td { style: "{style}", for child in children { MarkdownNodeView { node: child } } } }
    }
}

fn format_timestamp(timestamp: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp.min(i64::MAX as u64) as i64, 0)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%d/%m/%Y · %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| "Heure inconnue".into())
}

fn delivery_event_label(kind: DeliveryEventKind) -> &'static str {
    match kind {
        DeliveryEventKind::SavedLocally => "Message enregistré localement",
        DeliveryEventKind::Encrypted => "Message chiffré",
        DeliveryEventKind::SentDirectly => "Message transmis directement",
        DeliveryEventKind::Deposited => "Dépôt accepté par la Mailbox",
        DeliveryEventKind::Retrieved => "Enveloppe récupérée",
        DeliveryEventKind::AuthenticatedAndSaved => "Message authentifié et enregistré",
        DeliveryEventKind::RecipientConfirmed => "Réception confirmée par le destinataire",
        DeliveryEventKind::Expired => "Expiration attestée par la Mailbox",
    }
}

fn delivery_actor_label(actor: DeliveryActor, name: Option<&str>) -> String {
    match (actor, name) {
        (DeliveryActor::SenderClient, Some(name)) => format!("{name} · expéditeur"),
        (DeliveryActor::RecipientClient, Some(name)) => format!("{name} · destinataire"),
        (DeliveryActor::Mailbox, Some(name)) => name.to_owned(),
        (DeliveryActor::SenderClient, None) => "Client expéditeur".into(),
        (DeliveryActor::RecipientClient, None) => "Client destinataire".into(),
        (DeliveryActor::Mailbox, None) => "Mailbox".into(),
    }
}

fn format_receipt(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn apply_incoming_group_event(
    path: &Path,
    passphrase: &str,
    direct_conversation: &str,
    event: GroupEvent,
) -> Result<VaultData, String> {
    let (identity_id, contact_fingerprint) = direct_conversation
        .split_once(':')
        .ok_or("conversation identity is invalid")?;
    let mut data = load_vault(path, passphrase).map_err(|error| error.to_string())?;
    let _contact = data
        .contacts
        .iter()
        .find(|contact| contact.fingerprint == contact_fingerprint && contact.manually_verified)
        .ok_or("group event arrived through an unverified contact")?;
    let existing = data
        .groups
        .iter()
        .position(|group| group.group_id == event.group_id);
    if let Some(index) = existing {
        let group = &mut data.groups[index];
        if event.sequence <= group.sequence {
            let existing_event = group
                .events
                .get(event.sequence as usize)
                .ok_or("group event sequence is invalid")?;
            if existing_event.digest().map_err(|error| error.to_string())?
                != event.digest().map_err(|error| error.to_string())?
            {
                return Err("group event conflicts with the accepted history".into());
            }
            return Ok(data);
        }
        group.apply(&event).map_err(|error| error.to_string())?;
        group.validate().map_err(|error| error.to_string())?;
    } else {
        let group = GroupState::from_creation(&event).map_err(|error| error.to_string())?;
        data.groups.push(group);
    }
    let _ = identity_id;
    save_vault(path, &mut data, passphrase).map_err(|error| error.to_string())?;
    Ok(data)
}

fn store_incoming_group_message(
    path: &Path,
    passphrase: &str,
    direct_conversation: &str,
    incoming: GroupMessage,
) -> Result<(VaultData, bool, Vec<u8>), String> {
    let (identity_id, contact_fingerprint) = direct_conversation
        .split_once(':')
        .ok_or("conversation identity is invalid")?;
    let mut data = load_vault(path, passphrase).map_err(|error| error.to_string())?;
    let contact = data
        .contacts
        .iter()
        .find(|contact| contact.fingerprint == contact_fingerprint && contact.manually_verified)
        .ok_or("sender is not a verified contact")?;
    if incoming.sender_public_key != contact.public_key {
        return Err("sender identity does not match the authenticated P2P session".into());
    }
    let identity = data
        .identities
        .iter()
        .find(|identity| identity.id == identity_id)
        .ok_or("local identity was not found")?;
    let own_key = identity.public_key().to_vec();
    let group = data
        .groups
        .iter()
        .find(|group| group.group_id == incoming.group_id)
        .ok_or("group is unknown")?;
    if !group
        .members
        .iter()
        .any(|member| member.accepted && member.public_key == own_key)
    {
        return Err("local identity is not an accepted group member".into());
    }
    if !incoming.validate_for(group, &contact.public_key) {
        return Err("message does not match the authenticated group epoch and membership".into());
    }
    let conversation = format!("group:{}", incoming.group_id);
    let duplicate = data
        .messages
        .iter()
        .any(|message| message.conversation == conversation && message.id == incoming.message_id);
    if !duplicate {
        let mut message =
            runtime::received_message(conversation, incoming.message_id, incoming.text);
        message.timestamp = incoming.timestamp;
        message.record_delivery_event(DeliveryEvent {
            timestamp: incoming.timestamp,
            kind: DeliveryEventKind::AuthenticatedAndSaved,
            actor: DeliveryActor::RecipientClient,
            actor_fingerprint: Some(contact.fingerprint.clone()),
            actor_name: Some(contact.name.clone()),
            receipt_sha256: None,
            receipt_bytes: None,
            verified: true,
        });
        data.messages.push(message);
    }
    save_vault(path, &mut data, passphrase).map_err(|error| error.to_string())?;
    Ok((data, true, own_key))
}

fn store_incoming_attachment_chunk(
    path: &Path,
    passphrase: &str,
    conversation: &str,
    message_id: &str,
    manifest: AttachmentManifest,
    chunk: AttachmentChunk,
) -> Result<Option<VaultData>, String> {
    if manifest.message_id != message_id || !message_id.is_ascii() {
        return Err("la pièce jointe ne correspond pas au message".into());
    }
    attachments::validate_manifest(&manifest).map_err(|error| error.to_string())?;
    if chunk.attachment_id != manifest.attachment_id || chunk.index >= manifest.chunk_count {
        return Err("fragment de pièce jointe invalide".into());
    }
    let mut data = load_vault(path, passphrase).map_err(|error| error.to_string())?;
    let identity = data
        .identities
        .iter()
        .find(|identity| {
            identity.id
                == conversation
                    .split_once(':')
                    .map(|(id, _)| id)
                    .unwrap_or_default()
        })
        .ok_or("identité locale introuvable")?;
    let stored_conversation =
        if let Some(group_id) = manifest.conversation_id.strip_prefix("group:") {
            let group = data
                .groups
                .iter()
                .find(|group| group.group_id == group_id)
                .ok_or("groupe de la pièce jointe inconnu")?;
            if !group.members.iter().any(|member| {
                member.accepted
                    && member.fingerprint
                        == conversation
                            .split_once(':')
                            .map(|(_, fingerprint)| fingerprint)
                            .unwrap_or_default()
            }) || !group
                .members
                .iter()
                .any(|member| member.accepted && member.public_key == identity.public_key())
            {
                return Err("l’expéditeur ou le destinataire n’appartient pas au groupe".into());
            }
            format!("group:{group_id}")
        } else {
            conversation.to_string()
        };
    let parent_exists = data.messages.iter().any(|message| {
        message.conversation == stored_conversation && message.id == message_id && !message.outgoing
    });
    if stored_conversation.starts_with("group:") && !parent_exists {
        return Err("message de groupe parent absent du coffre".into());
    }
    if data
        .attachments
        .iter()
        .any(|item| item.manifest.attachment_id == manifest.attachment_id)
    {
        return Ok(Some(data));
    }
    let sidecar = attachments::attachment_sidecar_path(path);
    attachments::store_encrypted_chunks(&sidecar, std::slice::from_ref(&chunk))
        .map_err(|error| error.to_string())?;
    let chunks = match attachments::load_encrypted_chunks(&sidecar, &manifest) {
        Ok(chunks) => chunks,
        Err(attachments::AttachmentError::Io(_)) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut plaintext =
        attachments::decrypt_image(&manifest, &chunks).map_err(|error| error.to_string())?;
    use zeroize::Zeroize;
    let (mut sanitized, _) = attachments::sanitize_image(&plaintext)
        .map_err(|error| format!("image invalide: {error}"))?;
    sanitized.zeroize();
    plaintext.zeroize();
    if !parent_exists {
        data.messages.push(runtime::received_message(
            stored_conversation.clone(),
            message_id.to_string(),
            format!("Image · {}", manifest.display_name),
        ));
    }
    data.attachments.push(StoredAttachment {
        conversation: stored_conversation,
        message_id: message_id.to_string(),
        manifest,
        mailbox_frame_receipts: Vec::new(),
    });
    save_vault(path, &mut data, passphrase).map_err(|error| error.to_string())?;
    Ok(Some(data))
}

fn message_attachment_data(
    path: &Path,
    message: &StoredMessage,
    vault: &Signal<Option<VaultData>>,
) -> Option<String> {
    let manifest = vault
        .read()
        .as_ref()?
        .attachments
        .iter()
        .find(|item| item.conversation == message.conversation && item.message_id == message.id)?
        .manifest
        .clone();
    let sidecar = attachments::attachment_sidecar_path(path);
    let chunks = attachments::load_encrypted_chunks(&sidecar, &manifest).ok()?;
    let mut image = attachments::decrypt_image(&manifest, &chunks).ok()?;
    let encoded = STANDARD.encode(&image);
    use zeroize::Zeroize;
    image.zeroize();
    Some(encoded)
}

fn send_image_action(
    conversation: String,
    display_name: String,
    bytes: Vec<u8>,
    context: ImageActionContext,
) {
    let ImageActionContext {
        path,
        passphrase,
        vault,
        sessions,
        notice,
        trace,
        event_sender,
    } = context;
    let mut vault = vault;
    let mut notice = notice;
    let mut trace = trace;
    if conversation.starts_with("group:") {
        send_group_image_action(
            conversation,
            display_name,
            bytes,
            ImageActionContext {
                path,
                passphrase,
                vault,
                sessions,
                notice,
                trace,
                event_sender,
            },
        );
        return;
    }
    let session = sessions.read().get(&conversation).cloned();
    let message_id = match runtime::message_id() {
        Ok(id) => id,
        Err(error) => {
            notice.set(error);
            return;
        }
    };
    let (manifest, chunks) = match attachments::encrypt_image(
        &bytes,
        message_id.clone(),
        message_id.clone(),
        conversation.clone(),
        &display_name,
    ) {
        Ok(value) => value,
        Err(error) => {
            notice.set(format!("Image refusée : {error}"));
            return;
        }
    };
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(format!("Coffre inaccessible : {error}"));
            return;
        }
    };
    let sidecar = attachments::attachment_sidecar_path(&path);
    if let Err(error) = attachments::store_encrypted_chunks(&sidecar, &chunks) {
        notice.set(format!("Enregistrement chiffré impossible : {error}"));
        return;
    }
    let mut outgoing = runtime::new_message(
        conversation.clone(),
        message_id.clone(),
        format!("Image · {}", manifest.display_name),
    );
    if session.is_none() {
        outgoing.delivery = DeliveryState::Queued;
    }
    data.messages.push(outgoing);
    data.attachments.push(StoredAttachment {
        conversation: conversation.clone(),
        message_id: message_id.clone(),
        manifest: manifest.clone(),
        mailbox_frame_receipts: Vec::new(),
    });
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(format!("Coffre non modifié : {error}"));
        return;
    }
    vault.set(Some(data));
    if let Some(session) = session {
        for chunk in chunks {
            if let Err(error) =
                session.send_attachment_chunk(message_id.clone(), manifest.clone(), chunk)
            {
                notice.set(format!(
                    "Transfert interrompu après enregistrement local : {error}"
                ));
                return;
            }
        }
        if let Ok(mut data) = load_vault(&path, &phrase) {
            update_delivery(&mut data, &conversation, &message_id, DeliveryState::Sent);
            if save_vault(&path, &mut data, &phrase).is_ok() {
                vault.set(Some(data));
            }
        }
        push_trace(
            &mut trace,
            format!(
                "Image assainie, chiffrée par fragments et transmise · {}",
                &message_id[..8.min(message_id.len())]
            ),
        );
        notice.set("Image chiffrée et envoyée sur la session active.".into());
    } else {
        start_retry_for_conversation(&conversation, vault, event_sender);
        notice.set(
            "Image chiffrée dans le coffre · tentative P2P lancée. Elle partira à la reconnexion."
                .into(),
        );
    }
}

fn send_group_image_action(
    conversation: String,
    display_name: String,
    bytes: Vec<u8>,
    context: ImageActionContext,
) {
    let ImageActionContext {
        path,
        passphrase,
        vault,
        sessions,
        notice,
        trace,
        event_sender,
    } = context;
    let mut vault = vault;
    let mut notice = notice;
    let mut trace = trace;
    let event_sender = event_sender.read().clone();
    let group_id = conversation.trim_start_matches("group:");
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(format!("Coffre inaccessible : {error}"));
            return;
        }
    };
    let Some(group) = data
        .groups
        .iter()
        .find(|group| group.group_id == group_id)
        .cloned()
    else {
        notice.set("Groupe introuvable.".into());
        return;
    };
    let Some(identity) = data
        .identities
        .iter()
        .find(|identity| {
            group
                .members
                .iter()
                .any(|member| member.accepted && member.public_key == identity.public_key())
        })
        .map(Identity::detached_copy)
    else {
        notice.set("Aucune identité locale ne participe au groupe.".into());
        return;
    };
    let recipients = group
        .members
        .iter()
        .filter(|member| member.accepted && member.fingerprint != identity.fingerprint())
        .collect::<Vec<_>>();
    if recipients.is_empty() {
        notice.set("Le groupe n’a aucun autre membre accepté.".into());
        return;
    }
    let peers = {
        let handles = sessions.read();
        recipients
            .iter()
            .map(|member| {
                let key = format!("{}:{}", identity.id, member.fingerprint);
                handles.get(&key).cloned()
            })
            .collect::<Vec<_>>()
    };
    let message_id = match runtime::message_id() {
        Ok(id) => id,
        Err(error) => {
            notice.set(error);
            return;
        }
    };
    let (manifest, chunks) = match attachments::encrypt_image(
        &bytes,
        message_id.clone(),
        message_id.clone(),
        conversation.clone(),
        &display_name,
    ) {
        Ok(value) => value,
        Err(error) => {
            notice.set(format!("Image refusée : {error}"));
            return;
        }
    };
    let sidecar = attachments::attachment_sidecar_path(&path);
    if let Err(error) = attachments::store_encrypted_chunks(&sidecar, &chunks) {
        notice.set(format!("Enregistrement chiffré impossible : {error}"));
        return;
    }
    let caption = format!("Image · {}", manifest.display_name);
    let mut stored =
        runtime::new_message(conversation.clone(), message_id.clone(), caption.clone());
    stored.delivery = DeliveryState::Queued;
    data.messages.push(stored);
    data.attachments.push(StoredAttachment {
        conversation: conversation.clone(),
        message_id: message_id.clone(),
        manifest: manifest.clone(),
        mailbox_frame_receipts: Vec::new(),
    });
    data.group_deliveries.push(GroupMessageDelivery {
        group_id: group.group_id.clone(),
        message_id: message_id.clone(),
        epoch: group.epoch,
        sequence: group.sequence,
        recipients: recipients
            .iter()
            .map(|member| GroupRecipientDelivery {
                fingerprint: member.fingerprint.clone(),
                status: GroupRecipientStatus::Pending,
                updated_at: now_seconds(),
            })
            .collect(),
    });
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(format!("Sauvegarde impossible : {error}"));
        return;
    }
    vault.set(Some(data));
    let payload = GroupMessage {
        version: 1,
        group_id: group.group_id,
        epoch: group.epoch,
        sequence: group.sequence,
        message_id: message_id.clone(),
        sender_public_key: identity.public_key().to_vec(),
        timestamp: now_seconds(),
        text: caption,
        has_attachment: true,
    };
    let mut direct_recipients = Vec::new();
    let mut mailbox_recipients = Vec::new();
    for (member, peer) in recipients.iter().zip(peers) {
        let mut direct_ok = false;
        if let Some(handle) = peer
            && handle.send_group_message(payload.clone()).is_ok()
        {
            direct_ok = chunks.iter().cloned().all(|chunk| {
                handle
                    .send_attachment_chunk(message_id.clone(), manifest.clone(), chunk)
                    .is_ok()
            });
        }
        if direct_ok {
            direct_recipients.push(member.fingerprint.clone());
            continue;
        }
        let route_key = format!("{}:{}", identity.id, member.fingerprint);
        mailbox_recipients.push((route_key, member.fingerprint.clone()));
    }
    for (route_key, fingerprint) in mailbox_recipients {
        let event_sender = event_sender.clone();
        let path = path.clone();
        let phrase = phrase.clone();
        let message = payload.clone();
        let manifest = manifest.clone();
        let chunks = chunks.clone();
        let message_id = message_id.clone();
        spawn(async move {
            let result = async {
                async_mailbox::send_group_message(
                    path.clone(),
                    phrase.clone(),
                    route_key.clone(),
                    message,
                )
                .await?;
                async_mailbox::send_attachment_frames(
                    path,
                    phrase,
                    route_key.clone(),
                    message_id.clone(),
                    manifest,
                    chunks,
                )
                .await
            }
            .await;
            let _ = event_sender.send(UiEvent::MailboxResult {
                conversation: route_key,
                id: message_id,
                result,
            });
            let _ = fingerprint;
        });
    }
    if let Ok(mut data) = load_vault(&path, &phrase) {
        if let Some(delivery) = data
            .group_deliveries
            .iter_mut()
            .find(|delivery| delivery.group_id == group_id && delivery.message_id == message_id)
        {
            for recipient in &mut delivery.recipients {
                if direct_recipients.contains(&recipient.fingerprint) {
                    recipient.status = GroupRecipientStatus::Sent;
                }
                recipient.updated_at = now_seconds();
            }
        }
        if let Some(message) = data.messages.iter_mut().find(|message| {
            message.conversation == conversation && message.id == message_id && message.outgoing
        }) {
            message.delivery = if direct_recipients.len() == recipients.len() {
                DeliveryState::Sent
            } else {
                DeliveryState::Queued
            };
        }
        if save_vault(&path, &mut data, &phrase).is_ok() {
            vault.set(Some(data));
        }
    }
    push_trace(
        &mut trace,
        format!(
            "Image de groupe chiffrée et fragmentée · {}",
            &message_id[..8.min(message_id.len())]
        ),
    );
    notice.set(format!(
        "Image chiffrée · {} membre(s) par P2P, {} en attente de Mailbox.",
        direct_recipients.len(),
        recipients.len().saturating_sub(direct_recipients.len())
    ));
}

fn store_group_acknowledgement(
    path: &Path,
    passphrase: &str,
    direct_conversation: &str,
    group_id: &str,
    message_id: &str,
    recipient_public_key: &[u8],
) -> Result<VaultData, String> {
    let (_, contact_fingerprint) = direct_conversation
        .split_once(':')
        .ok_or("conversation identity is invalid")?;
    let mut data = load_vault(path, passphrase).map_err(|error| error.to_string())?;
    let contact = data
        .contacts
        .iter()
        .find(|contact| contact.fingerprint == contact_fingerprint && contact.manually_verified)
        .ok_or("acknowledging identity is not verified")?;
    if contact.public_key != recipient_public_key {
        return Err("acknowledgement identity does not match its authenticated session".into());
    }
    let expected = data
        .group_deliveries
        .iter_mut()
        .find(|delivery| delivery.group_id == group_id && delivery.message_id == message_id)
        .ok_or("group delivery record is unknown")?;
    let recipient = expected
        .recipients
        .iter_mut()
        .find(|recipient| recipient.fingerprint == contact_fingerprint)
        .ok_or("this contact was not a recipient of the message")?;
    recipient.status = GroupRecipientStatus::Received;
    recipient.updated_at = now_seconds();
    let fully_received = expected
        .recipients
        .iter()
        .all(|recipient| recipient.status == GroupRecipientStatus::Received);
    let stored = data
        .messages
        .iter_mut()
        .find(|message| {
            message.conversation == format!("group:{group_id}")
                && message.id == message_id
                && message.outgoing
        })
        .ok_or("group message is unknown")?;
    if !stored.delivery_events.iter().any(|event| {
        event.kind == DeliveryEventKind::RecipientConfirmed
            && event.actor_fingerprint.as_deref() == Some(contact_fingerprint)
    }) {
        stored.record_delivery_event(DeliveryEvent {
            timestamp: now_seconds(),
            kind: DeliveryEventKind::RecipientConfirmed,
            actor: DeliveryActor::RecipientClient,
            actor_fingerprint: Some(contact.fingerprint.clone()),
            actor_name: Some(contact.name.clone()),
            receipt_sha256: None,
            receipt_bytes: None,
            verified: true,
        });
    }
    stored.delivery = if fully_received {
        DeliveryState::Acknowledged
    } else {
        DeliveryState::Sent
    };
    save_vault(path, &mut data, passphrase).map_err(|error| error.to_string())?;
    Ok(data)
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn submit_group_message(conversation: String, mut draft: Signal<String>, context: GroupUiContext) {
    let GroupUiContext {
        path,
        passphrase,
        mut vault,
        sessions,
        mut notice,
        event_sender,
        ..
    } = context;
    let Some(group_id) = conversation.strip_prefix("group:").map(str::to_string) else {
        return;
    };
    let text = draft.read().trim().to_string();
    if text.is_empty() {
        return;
    }
    if text.len() > 10 * 1024 {
        notice.set("Message limité à 10 Kio.".into());
        return;
    }
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(format!("Coffre inaccessible : {error}"));
            return;
        }
    };
    let Some(group) = data.groups.iter().find(|group| group.group_id == group_id) else {
        notice.set("Groupe introuvable.".into());
        return;
    };
    let Some(identity) = data
        .identities
        .iter()
        .find(|identity| {
            group
                .members
                .iter()
                .any(|member| member.accepted && member.public_key == identity.public_key())
        })
        .map(Identity::detached_copy)
    else {
        notice.set("Aucune identité locale ne participe à ce groupe.".into());
        return;
    };
    let recipients = group
        .members
        .iter()
        .filter(|member| member.accepted && member.fingerprint != identity.fingerprint())
        .map(|member| GroupRecipientDelivery {
            fingerprint: member.fingerprint.clone(),
            status: GroupRecipientStatus::Pending,
            updated_at: now_seconds(),
        })
        .collect::<Vec<_>>();
    if recipients.is_empty() {
        notice.set("Ce groupe n’a pas encore d’autre membre accepté.".into());
        return;
    }
    let group_state = group.clone();
    let id = match runtime::message_id() {
        Ok(id) => id,
        Err(error) => {
            notice.set(error);
            return;
        }
    };
    let mut message = runtime::new_message(conversation, id.clone(), text);
    message.delivery = DeliveryState::Queued;
    data.messages.push(message);
    data.group_deliveries.push(GroupMessageDelivery {
        group_id: group_id.clone(),
        message_id: id,
        epoch: group_state.epoch,
        sequence: group_state.sequence,
        recipients,
    });
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(format!("Sauvegarde impossible : {error}"));
        return;
    }
    vault.set(load_vault(&path, &phrase).ok());
    draft.set(String::new());
    let event_tx = event_sender.read().clone();
    for member in group_state
        .members
        .iter()
        .filter(|member| member.accepted && member.fingerprint != identity.fingerprint())
    {
        let Some(contact) = data
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == member.fingerprint && contact.manually_verified)
            .cloned()
        else {
            continue;
        };
        let direct_conversation = format!("{}:{}", identity.id, member.fingerprint);
        if let Some(handle) = sessions.read().get(&direct_conversation) {
            sync_group_on_ready(&path, &phrase, &direct_conversation, handle);
        } else {
            runtime::connect(identity.detached_copy(), contact, event_tx.clone());
        }
    }
    notice.set("Message enregistré · envoi pairwise lancé vers les membres acceptés.".into());
}

fn create_group_action(
    name: String,
    selected_identity: String,
    selected_contacts: Vec<String>,
    context: GroupUiContext,
) -> bool {
    let GroupUiContext {
        path,
        passphrase,
        mut vault,
        mut active_conversation,
        event_sender,
        mut notice,
        sessions,
    } = context;
    if name.trim().is_empty() || selected_contacts.is_empty() {
        notice.set("Indiquez un nom et sélectionnez au moins un contact vérifié.".into());
        return false;
    }
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(format!("Coffre inaccessible : {error}"));
            return false;
        }
    };
    let identity = data
        .identities
        .iter()
        .find(|identity| identity.id == selected_identity)
        .or_else(|| data.identities.first())
        .map(Identity::detached_copy);
    let Some(identity) = identity else {
        notice.set("Créez d’abord une identité.".into());
        return false;
    };
    let group_id = match runtime::message_id() {
        Ok(id) => id,
        Err(error) => {
            notice.set(error);
            return false;
        }
    };
    let creation = match GroupEvent::signed(
        &identity,
        group_id.clone(),
        0,
        0,
        None,
        GroupChange::Create {
            name: name.trim().to_string(),
            creator_name: identity.name.clone(),
        },
    ) {
        Ok(event) => event,
        Err(error) => {
            notice.set(error.to_string());
            return false;
        }
    };
    let mut group = match GroupState::from_creation(&creation) {
        Ok(group) => group,
        Err(error) => {
            notice.set(error.to_string());
            return false;
        }
    };
    for fingerprint in selected_contacts {
        let Some(contact) = data
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == fingerprint && contact.manually_verified)
        else {
            continue;
        };
        if group
            .members
            .iter()
            .any(|member| member.fingerprint == contact.fingerprint)
        {
            continue;
        }
        let member = GroupMember {
            fingerprint: contact.fingerprint.clone(),
            public_key: contact.public_key.clone(),
            display_name: contact.name.clone(),
            role: GroupRole::Member,
            accepted: false,
        };
        let invite = match GroupEvent::signed(
            &identity,
            group_id.clone(),
            group.sequence.saturating_add(1),
            group.epoch,
            Some(group.last_event_sha256.clone()),
            GroupChange::Invite { member },
        ) {
            Ok(event) => event,
            Err(error) => {
                notice.set(error.to_string());
                return false;
            }
        };
        if group.apply(&invite).is_err() {
            notice.set("Impossible d’appliquer l’invitation signée.".into());
            return false;
        }
    }
    if group.members.len() < 2 {
        notice.set("Sélectionnez au moins un contact distinct de l’identité propriétaire.".into());
        return false;
    }
    data.groups.push(group);
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(format!("Enregistrement impossible : {error}"));
        return false;
    }
    vault.set(load_vault(&path, &phrase).ok());
    active_conversation.set(Some(format!("group:{group_id}")));
    notice.set("Groupe créé · invitations en attente de connexion des contacts.".into());
    let event_tx = event_sender.read().clone();
    for member in data
        .groups
        .iter()
        .find(|group| group.group_id == group_id)
        .into_iter()
        .flat_map(|group| group.members.iter().filter(|member| !member.accepted))
    {
        if let Some(contact) = data
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == member.fingerprint)
            .cloned()
        {
            let direct_conversation = format!("{}:{}", identity.id, member.fingerprint);
            if let Some(handle) = sessions.read().get(&direct_conversation) {
                for event in data
                    .groups
                    .iter()
                    .find(|group| group.group_id == group_id)
                    .into_iter()
                    .flat_map(|group| group.events.iter())
                {
                    let _ = handle.send_group_event(event.clone());
                }
            } else {
                start_async_group_event_fallback(
                    path.clone(),
                    phrase.clone(),
                    direct_conversation,
                    data.groups
                        .iter()
                        .find(|group| group.group_id == group_id)
                        .map(|group| group.events.clone())
                        .unwrap_or_default(),
                    event_sender,
                );
            }
            runtime::connect(identity.detached_copy(), contact, event_tx.clone());
        }
    }
    true
}

fn connect_group_members(
    group_id: String,
    path: PathBuf,
    passphrase: Signal<String>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
) {
    let phrase = passphrase.read().clone();
    let Ok(data) = load_vault(&path, &phrase) else {
        return;
    };
    let Some(group) = data.groups.iter().find(|group| group.group_id == group_id) else {
        return;
    };
    let Some(identity) = data
        .identities
        .iter()
        .find(|identity| {
            group
                .members
                .iter()
                .any(|member| member.accepted && member.public_key == identity.public_key())
        })
        .map(Identity::detached_copy)
    else {
        return;
    };
    let event_tx = event_sender.read().clone();
    for member in group
        .members
        .iter()
        .filter(|member| member.fingerprint != identity.fingerprint())
    {
        if let Some(contact) = data
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == member.fingerprint && contact.manually_verified)
            .cloned()
        {
            runtime::connect(identity.detached_copy(), contact, event_tx.clone());
        }
    }
}

fn apply_group_change_action(
    group_id: String,
    change: GroupChange,
    context: GroupManagementContext,
) {
    let GroupManagementContext {
        path,
        passphrase,
        vault,
        sessions,
        event_sender,
        notice,
    } = context;
    let mut vault = vault;
    let mut notice = notice;
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(format!("Coffre inaccessible : {error}"));
            return;
        }
    };
    let Some(group_index) = data
        .groups
        .iter()
        .position(|group| group.group_id == group_id)
    else {
        notice.set("Groupe introuvable.".into());
        return;
    };
    let group = &data.groups[group_index];
    let actor = data.identities.iter().find(|identity| {
        group.members.iter().any(|member| {
            member.accepted
                && member.public_key == identity.public_key()
                && match &change {
                    GroupChange::Leave => true,
                    GroupChange::SetRole { .. } => member.role == GroupRole::Owner,
                    _ => matches!(member.role, GroupRole::Owner | GroupRole::Admin),
                }
        })
    });
    let Some(actor) = actor.map(Identity::detached_copy) else {
        notice.set("Aucune identité locale autorisée à gérer ce groupe.".into());
        return;
    };
    let former_members = group.members.clone();
    let sequence = group.sequence.saturating_add(1);
    let epoch = group.epoch.saturating_add(u64::from(matches!(
        &change,
        GroupChange::Remove { .. } | GroupChange::Leave | GroupChange::Rotate
    )));
    let previous = group.last_event_sha256.clone();
    let event = match GroupEvent::signed(
        &actor,
        group_id.clone(),
        sequence,
        epoch,
        Some(previous),
        change,
    ) {
        Ok(event) => event,
        Err(error) => {
            notice.set(error.to_string());
            return;
        }
    };
    let group = &mut data.groups[group_index];
    if let Err(error) = group.apply(&event).and_then(|()| group.validate()) {
        notice.set(format!("Modification du groupe refusée : {error}"));
        return;
    }
    let updated = group.clone();
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(format!("Enregistrement impossible : {error}"));
        return;
    }
    vault.set(load_vault(&path, &phrase).ok());
    let event_tx = event_sender.read().clone();
    let mut notified = 0usize;
    for member in former_members
        .iter()
        .filter(|member| member.fingerprint != actor.fingerprint())
    {
        let Some(contact) = data
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == member.fingerprint && contact.manually_verified)
            .cloned()
        else {
            continue;
        };
        let direct_conversation = format!("{}:{}", actor.id, member.fingerprint);
        if let Some(handle) = sessions.read().get(&direct_conversation) {
            for group_event in &updated.events {
                let _ = handle.send_group_event(group_event.clone());
            }
        } else {
            start_async_group_event_fallback(
                path.clone(),
                phrase.clone(),
                direct_conversation,
                updated.events.clone(),
                event_sender,
            );
            runtime::connect(actor.detached_copy(), contact, event_tx.clone());
        }
        notified += 1;
    }
    notice.set(format!(
        "Groupe mis à jour · événement signé transmis à {notified} membre(s)."
    ));
}

fn accept_group_invitation(
    group_id: String,
    path: PathBuf,
    passphrase: Signal<String>,
    mut vault: Signal<Option<VaultData>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
    mut notice: Signal<String>,
) {
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(error.to_string());
            return;
        }
    };
    let group_index = match data
        .groups
        .iter()
        .position(|group| group.group_id == group_id)
    {
        Some(index) => index,
        None => return,
    };
    let identity = data
        .identities
        .iter()
        .find(|identity| {
            data.groups[group_index]
                .members
                .iter()
                .any(|member| !member.accepted && member.public_key == identity.public_key())
        })
        .map(Identity::detached_copy);
    let Some(identity) = identity else {
        notice.set("Aucune invitation ne correspond à une identité locale.".into());
        return;
    };
    let group = &mut data.groups[group_index];
    let event = match GroupEvent::signed(
        &identity,
        group.group_id.clone(),
        group.sequence.saturating_add(1),
        group.epoch.saturating_add(1),
        Some(group.last_event_sha256.clone()),
        GroupChange::Accept,
    ) {
        Ok(event) => event,
        Err(error) => {
            notice.set(error.to_string());
            return;
        }
    };
    if let Err(error) = group.apply(&event) {
        notice.set(error.to_string());
        return;
    }
    let group_snapshot = group.clone();
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(error.to_string());
        return;
    }
    vault.set(load_vault(&path, &phrase).ok());
    let event_tx = event_sender.read().clone();
    for member in group_snapshot
        .members
        .iter()
        .filter(|member| member.accepted && member.fingerprint != identity.fingerprint())
    {
        let Some(contact) = data
            .contacts
            .iter()
            .find(|contact| contact.fingerprint == member.fingerprint)
            .cloned()
        else {
            continue;
        };
        let key = format!("{}:{}", identity.id, member.fingerprint);
        if let Some(handle) = sessions.read().get(&key) {
            for group_event in &group_snapshot.events {
                let _ = handle.send_group_event(group_event.clone());
            }
        } else {
            start_async_group_event_fallback(
                path.clone(),
                phrase.clone(),
                key,
                group_snapshot.events.clone(),
                event_sender,
            );
            runtime::connect(identity.detached_copy(), contact, event_tx.clone());
        }
    }
    notice.set("Invitation acceptée · rotation d’époque appliquée.".into());
}

fn sync_group_on_ready(
    path: &Path,
    passphrase: &str,
    direct_conversation: &str,
    handle: &SessionHandle,
) {
    let Ok((identity_id, contact_fingerprint)) = direct_conversation.split_once(':').ok_or(())
    else {
        return;
    };
    let Ok(mut data) = load_vault(path, passphrase) else {
        return;
    };
    let Some(identity) = data
        .identities
        .iter()
        .find(|identity| identity.id == identity_id)
        .map(Identity::detached_copy)
    else {
        return;
    };
    for group in data.groups.iter().filter(|group| {
        group
            .members
            .iter()
            .any(|member| member.fingerprint == contact_fingerprint)
    }) {
        for event in &group.events {
            let _ = handle.send_group_event(event.clone());
        }
        let is_accepted = group
            .members
            .iter()
            .any(|member| member.fingerprint == contact_fingerprint && member.accepted);
        if !is_accepted {
            continue;
        }
        let pending = data
            .group_deliveries
            .iter()
            .filter(|delivery| {
                delivery.group_id == group.group_id
                    && delivery.recipients.iter().any(|recipient| {
                        recipient.fingerprint == contact_fingerprint
                            && recipient.status != GroupRecipientStatus::Received
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        for delivery in pending {
            let Some(message) = data
                .messages
                .iter()
                .find(|message| {
                    message.conversation == format!("group:{}", delivery.group_id)
                        && message.id == delivery.message_id
                        && message.outgoing
                })
                .cloned()
            else {
                continue;
            };
            let outgoing = GroupMessage {
                version: 1,
                group_id: group.group_id.clone(),
                epoch: delivery.epoch,
                sequence: delivery.sequence,
                message_id: message.id.clone(),
                sender_public_key: identity.public_key().to_vec(),
                timestamp: message.timestamp,
                text: message.text,
                has_attachment: data.attachments.iter().any(|attachment| {
                    attachment.conversation == format!("group:{}", group.group_id)
                        && attachment.message_id == delivery.message_id
                }),
            };
            let mut delivered = handle.send_group_message(outgoing).is_ok();
            if delivered
                && let Some(attachment) = data.attachments.iter().find(|attachment| {
                    attachment.conversation == format!("group:{}", delivery.group_id)
                        && attachment.message_id == delivery.message_id
                })
            {
                match attachments::load_encrypted_chunks(
                    &attachments::attachment_sidecar_path(path),
                    &attachment.manifest,
                ) {
                    Ok(chunks) => {
                        for chunk in chunks {
                            if handle
                                .send_attachment_chunk(
                                    delivery.message_id.clone(),
                                    attachment.manifest.clone(),
                                    chunk,
                                )
                                .is_err()
                            {
                                delivered = false;
                                break;
                            }
                        }
                    }
                    Err(_) => delivered = false,
                }
            }
            if delivered
                && let Some(saved) = data.group_deliveries.iter_mut().find(|saved| {
                    saved.group_id == delivery.group_id && saved.message_id == delivery.message_id
                })
                && let Some(recipient) = saved
                    .recipients
                    .iter_mut()
                    .find(|recipient| recipient.fingerprint == contact_fingerprint)
            {
                recipient.status = GroupRecipientStatus::Sent;
                recipient.updated_at = now_seconds();
            }
        }
    }
    let _ = save_vault(path, &mut data, passphrase);
}

fn broadcast_group_events(data: &VaultData, sessions: &HashMap<String, SessionHandle>) {
    for group in &data.groups {
        for identity in data.identities.iter().filter(|identity| {
            group
                .members
                .iter()
                .any(|member| member.accepted && member.public_key == identity.public_key())
        }) {
            for member in group
                .members
                .iter()
                .filter(|member| member.fingerprint != identity.fingerprint())
            {
                let key = format!("{}:{}", identity.id, member.fingerprint);
                if let Some(handle) = sessions.get(&key) {
                    for event in &group.events {
                        let _ = handle.send_group_event(event.clone());
                    }
                }
            }
        }
    }
}

fn start_async_group_event_fallback(
    path: PathBuf,
    passphrase: String,
    direct_conversation: String,
    events: Vec<GroupEvent>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
) {
    if events.is_empty() {
        return;
    }
    let sender = event_sender.read().clone();
    spawn(async move {
        let mut last_id = String::new();
        let mut failure = None;
        for event in events {
            let Ok(message_id) = runtime::message_id() else {
                failure = Some("identifiant d’invitation impossible".to_string());
                break;
            };
            last_id = message_id.clone();
            if let Err(error) = async_mailbox::send_group_event(
                path.clone(),
                passphrase.clone(),
                direct_conversation.clone(),
                message_id,
                event,
            )
            .await
            {
                failure = Some(error);
            }
        }
        let _ = sender.send(UiEvent::MailboxResult {
            conversation: direct_conversation,
            id: last_id,
            result: failure.map_or(Ok(()), Err),
        });
    });
}

#[allow(clippy::too_many_arguments)]
fn submit_message(
    conversation: String,
    mut draft: Signal<String>,
    path: PathBuf,
    passphrase: Signal<String>,
    mut vault: Signal<Option<VaultData>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    mut notice: Signal<String>,
    mut trace: Signal<Vec<String>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
) {
    let text = draft.read().trim().to_string();
    if text.is_empty() {
        return;
    }
    if text.len() > 10 * 1024 {
        notice.set("Message limité à 10 Kio.".into());
        return;
    }
    let id = match runtime::message_id() {
        Ok(id) => id,
        Err(error) => {
            notice.set(format!("Identifiant impossible : {error}"));
            return;
        }
    };
    let phrase = passphrase.read().clone();
    let mut data = match load_vault(&path, &phrase) {
        Ok(data) => data,
        Err(error) => {
            notice.set(format!("Coffre inaccessible : {error}"));
            return;
        }
    };
    data.messages.push(runtime::new_message(
        conversation.clone(),
        id.clone(),
        text.clone(),
    ));
    if let Err(error) = save_vault(&path, &mut data, &phrase) {
        notice.set(format!("Sauvegarde impossible : {error}"));
        return;
    }
    vault.set(Some(data));
    draft.set(String::new());
    push_trace(
        &mut trace,
        "Message enregistré dans le coffre · attente d’envoi chiffré".into(),
    );
    match sessions
        .read()
        .get(&conversation)
        .cloned()
        .map(|session| session.send_text(id.clone(), text))
    {
        Some(Ok(())) => {}
        Some(Err(error)) => {
            update_message_status(
                &path,
                &phrase,
                vault,
                (&conversation, &id),
                DeliveryState::Queued,
                &mut notice,
                format!("Message gardé dans la file locale : {error}"),
            );
            push_trace(
                &mut trace,
                "Message conservé · reconnexion P2P automatique lancée".into(),
            );
            start_retry_for_conversation(&conversation, vault, event_sender);
            start_async_mailbox_fallback(conversation, id, path, phrase, event_sender);
        }
        None => {
            update_message_status(
                &path,
                &phrase,
                vault,
                (&conversation, &id),
                DeliveryState::Queued,
                &mut notice,
                "Message gardé dans la file locale · AKRAT réessaie automatiquement.".into(),
            );
            push_trace(
                &mut trace,
                "Message conservé · reconnexion P2P automatique lancée".into(),
            );
            start_retry_for_conversation(&conversation, vault, event_sender);
            start_async_mailbox_fallback(conversation, id, path, phrase, event_sender);
        }
    }
}

fn start_async_mailbox_fallback(
    conversation: String,
    id: String,
    path: PathBuf,
    passphrase: String,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
) {
    let sender = event_sender.read().clone();
    spawn(async move {
        let result = async_mailbox::send(path, passphrase, conversation.clone(), id.clone()).await;
        let _ = sender.send(UiEvent::MailboxResult {
            conversation,
            id,
            result,
        });
    });
}

fn start_retry_for_conversation(
    conversation: &str,
    vault: Signal<Option<VaultData>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
) {
    let Some((identity_id, fingerprint)) = conversation.split_once(':') else {
        return;
    };
    let (identity, contact) = {
        let snapshot = vault.read();
        let Some(data) = snapshot.as_ref() else {
            return;
        };
        (
            data.identities
                .iter()
                .find(|identity| identity.id == identity_id)
                .map(Identity::detached_copy),
            data.contacts
                .iter()
                .find(|contact| contact.fingerprint == fingerprint && contact.manually_verified)
                .cloned(),
        )
    };
    if let (Some(identity), Some(contact)) = (identity, contact) {
        runtime::connect(identity, contact, event_sender.read().clone());
    }
}

fn push_trace(trace: &mut Signal<Vec<String>>, line: String) {
    let mut items = trace.write();
    items.push(line);
    let extra = items.len().saturating_sub(80);
    if extra > 0 {
        items.drain(0..extra);
    }
}

fn update_delivery(data: &mut VaultData, conversation: &str, id: &str, state: DeliveryState) {
    if let Some(message) = data
        .messages
        .iter_mut()
        .find(|m| m.conversation == conversation && m.id == id && m.outgoing)
    {
        message.delivery = state;
        if state == DeliveryState::Sent
            && !message
                .delivery_events
                .iter()
                .any(|event| event.kind == DeliveryEventKind::SentDirectly)
        {
            message.record_delivery_event(akrat_core::DeliveryEvent {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or_default(),
                kind: DeliveryEventKind::SentDirectly,
                actor: DeliveryActor::SenderClient,
                actor_fingerprint: None,
                actor_name: None,
                receipt_sha256: None,
                receipt_bytes: None,
                verified: false,
            });
        }
    }
}

fn update_message_status(
    path: &Path,
    passphrase: &str,
    mut vault: Signal<Option<VaultData>>,
    message_key: (&str, &str),
    status: DeliveryState,
    notice: &mut Signal<String>,
    message: String,
) {
    if let Ok(mut data) = load_vault(path, passphrase) {
        update_delivery(&mut data, message_key.0, message_key.1, status);
        if save_vault(path, &mut data, passphrase).is_ok() {
            vault.set(Some(data));
        }
    }
    notice.set(message);
}

#[component]
fn SettingsPage(
    path: PathBuf,
    notice: Signal<String>,
    update_status: Signal<updater::UpdateStatus>,
    on_check_updates: EventHandler<MouseEvent>,
    on_install_update: EventHandler<MouseEvent>,
    on_lock: EventHandler<MouseEvent>,
) -> Element {
    let current_version = env!("CARGO_PKG_VERSION");
    let update_view = match update_status.read().clone() {
        updater::UpdateStatus::Checking => {
            rsx! { p { class: "quiet", "Recherche de mises à jour…" } }
        }
        updater::UpdateStatus::Current => {
            rsx! { p { class: "quiet", "AKRAT est à jour · v{current_version}" } }
        }
        updater::UpdateStatus::Available(release) => rsx! {
            div { class: "update-ready",
                strong { "AKRAT v{release.version} est disponible" }
                if cfg!(target_os = "android") {
                    p { class: "quiet", "Téléchargez la mise à jour depuis GitHub. Android vous demandera de confirmer son installation." }
                    a { class: "secondary update-link", href: "{release.download_url}", target: "_blank", "Télécharger l’APK" }
                    p { class: "copy-hint", "Android demande une confirmation. Les APK de test n’ont pas encore de signature stable ; une mise à jour peut être refusée par-dessus une ancienne installation. Ne désinstallez pas AKRAT si le coffre contient des données importantes." }
                } else {
                    p { class: "quiet", "AKRAT installe automatiquement les mises à jour au lancement, vérifie leur empreinte SHA-256, puis redémarre. Le coffre reste chiffré." }
                    button { class: "primary", onclick: on_install_update, "Installer et redémarrer" }
                }
                a { class: "release-link", href: "{release.release_url}", target: "_blank", "Voir la release sur GitHub" }
            }
        },
        updater::UpdateStatus::Installing => {
            rsx! { p { class: "quiet", "Téléchargement, vérification et installation en cours…" } }
        }
        updater::UpdateStatus::Failed(error) => {
            rsx! { p { class: "update-error", "Mise à jour indisponible : {error}" } }
        }
    };
    rsx! { section { class: "page-scroll",
        div { class: "eyebrow", "STOCKAGE LOCAL" } h1 { "Votre coffre" }
        p { class: "intro", "Les clés privées, contacts et messages sont conservés dans un fichier chiffré par votre phrase secrète." }
        section { class: "panel settings-panel", div { class: "panel-title", "Emplacement" } p { class: "fingerprint", "{path.display()}" } div { class: "crypto-note", "Chiffrement du coffre : Argon2id + AES-256-GCM. Une phrase secrète perdue ne peut pas être récupérée." } div { class: "crypto-note", "Verrouillage automatique après 5 minutes sans toucher l’application. Les sessions réseau sont fermées en même temps." } button { class: "secondary", onclick: on_lock, "Verrouiller et choisir un autre coffre" } }
        section { class: "panel settings-panel", div { class: "panel-title", "Mises à jour" } {update_view} button { class: "secondary update-check", onclick: on_check_updates, "Rechercher à nouveau" } }
        p { class: "quiet", "{notice}" }
    } }
}

fn default_vault_path() -> PathBuf {
    if let Some(path) = std::env::var_os("AKRAT_VAULT_PATH") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "android")]
    {
        return PathBuf::from("/data/user/0/org.akrat.app/files/vault.akrat");
    }
    #[cfg(not(target_os = "android"))]
    ProjectDirs::from("org", "Akrat", "AKRAT")
        .map(|dirs| dirs.data_local_dir().join("vault.akrat"))
        .unwrap_or_else(|| PathBuf::from("vault.akrat"))
}

const CSS: &str = include_str!("../assets/theme.css");

#[cfg(test)]
mod vault_manager_tests {
    use super::*;

    #[test]
    fn incoming_image_is_saved_and_acked_only_after_all_chunks_authenticate() {
        let directory = tempfile::tempdir().unwrap();
        let vault_path = directory.path().join("receiver.akrat");
        let identity = Identity::generate("Receiver".into()).unwrap();
        let conversation = format!("{}:remote", identity.id);
        let mut data = VaultData::default();
        data.identities.push(identity);
        save_vault(&vault_path, &mut data, "test passphrase").unwrap();
        let message_id = runtime::message_id().unwrap();
        let (manifest, chunks) = attachments::encrypt_image(
            include_bytes!("../assets/akrat-logo.png"),
            message_id.clone(),
            message_id.clone(),
            "remote:receiver".into(),
            "logo.png",
        )
        .unwrap();
        assert!(chunks.len() > 1);
        for chunk in &chunks[..chunks.len() - 1] {
            assert!(
                store_incoming_attachment_chunk(
                    &vault_path,
                    "test passphrase",
                    &conversation,
                    &message_id,
                    manifest.clone(),
                    chunk.clone(),
                )
                .unwrap()
                .is_none()
            );
        }
        let complete = store_incoming_attachment_chunk(
            &vault_path,
            "test passphrase",
            &conversation,
            &message_id,
            manifest.clone(),
            chunks.last().unwrap().clone(),
        )
        .unwrap()
        .expect("complete image");
        assert_eq!(complete.attachments.len(), 1);
        assert!(complete.messages.iter().any(|message| {
            message.id == message_id && message.conversation == conversation && !message.outgoing
        }));
        let restored = attachments::load_encrypted_chunks(
            &attachments::attachment_sidecar_path(&vault_path),
            &manifest,
        )
        .unwrap();
        assert_eq!(
            attachments::decrypt_image(&manifest, &restored)
                .unwrap()
                .len(),
            manifest.plaintext_size as usize
        );
    }

    #[test]
    fn generated_name_has_one_extension_and_rejects_invalid_names() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            vault_path_with_name(directory.path(), "Personnel").unwrap(),
            directory.path().join("Personnel.akrat")
        );
        assert_eq!(
            vault_path_with_name(directory.path(), "Personnel.akrat").unwrap(),
            directory.path().join("Personnel.akrat")
        );
        assert!(vault_path_with_name(directory.path(), "../private").is_err());
    }

    #[test]
    fn creation_requires_matching_phrase_and_never_overwrites() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("vaults");
        std::fs::create_dir(&destination).unwrap();
        let default = directory.path().join("default.akrat");
        let mismatch = create_vault_file(
            &default,
            &[],
            destination.to_str().unwrap(),
            "Personnel",
            "this is a sufficiently long phrase",
            "a different phrase completely",
        );
        assert!(mismatch.is_err());
        assert!(!destination.join("Personnel.akrat").exists());

        let (created_path, paths, data) = create_vault_file(
            &default,
            &[],
            destination.to_str().unwrap(),
            "Personnel.akrat",
            "this is a sufficiently long phrase",
            "this is a sufficiently long phrase",
        )
        .unwrap();
        assert_eq!(created_path, destination.join("Personnel.akrat"));
        assert_eq!(paths, vec![created_path.clone()]);
        assert!(data.identities.is_empty());
        assert!(load_vault(&created_path, "this is a sufficiently long phrase").is_ok());

        let collision = create_vault_file(
            &default,
            &paths,
            destination.to_str().unwrap(),
            "Personnel",
            "this is a sufficiently long phrase",
            "this is a sufficiently long phrase",
        );
        assert!(collision.is_err());
        assert!(load_vault(&created_path, "this is a sufficiently long phrase").is_ok());
    }

    #[test]
    fn rename_preserves_encrypted_file_and_delete_requires_the_passphrase() {
        let directory = tempfile::tempdir().unwrap();
        let vault_directory = directory.path().join("vaults");
        std::fs::create_dir(&vault_directory).unwrap();
        let default = directory.path().join("default.akrat");
        let phrase = "this is a sufficiently long phrase";
        let (original, paths, _) = create_vault_file(
            &default,
            &[],
            vault_directory.to_str().unwrap(),
            "Original",
            phrase,
            phrase,
        )
        .unwrap();
        let original_sidecar = akrat_core::attachments::attachment_sidecar_path(&original);
        std::fs::create_dir_all(&original_sidecar).unwrap();
        std::fs::write(original_sidecar.join("encrypted.chunk"), b"ciphertext").unwrap();
        let mut refreshed = load_vault(&original, phrase).unwrap();
        save_vault(&original, &mut refreshed, phrase).unwrap();
        let bytes_before = std::fs::read(&original).unwrap();
        let mut stale_session = load_vault(&original, phrase).unwrap();
        let id_before = vault_catalog::id_for_path(&default, &original).unwrap();

        let (renamed, paths) = rename_vault_file(&default, &paths, &original, "Personnel").unwrap();
        assert_eq!(renamed, vault_directory.join("Personnel.akrat"));
        assert!(!original.exists());
        assert_eq!(std::fs::read(&renamed).unwrap(), bytes_before);
        assert!(load_vault(&renamed, phrase).is_ok());
        let renamed_sidecar = akrat_core::attachments::attachment_sidecar_path(&renamed);
        assert_eq!(
            std::fs::read(renamed_sidecar.join("encrypted.chunk")).unwrap(),
            b"ciphertext"
        );
        assert!(!original_sidecar.exists());
        let renamed_backup = vault_backup_path(&renamed);
        assert!(renamed_backup.exists());
        assert!(!vault_backup_path(&original).exists());
        assert!(load_vault(&renamed_backup, phrase).is_ok());
        assert!(save_vault(&original, &mut stale_session, phrase).is_err());
        assert!(!original.exists());
        let id_after = vault_catalog::id_for_path(&default, &renamed).unwrap();
        assert_eq!(id_before, id_after);

        assert!(delete_vault_file(&default, &paths, &renamed, "incorrect phrase").is_err());
        assert!(renamed.is_file());
        let remaining = delete_vault_file(&default, &paths, &renamed, phrase).unwrap();
        assert!(remaining.is_empty());
        assert!(!renamed.exists());
        assert!(!renamed_sidecar.exists());
        assert!(!renamed_backup.exists());
    }

    #[test]
    fn portable_import_copies_ciphertext_and_avoids_name_collisions() {
        let directory = tempfile::tempdir().unwrap();
        let source_folder = directory.path().join("source");
        std::fs::create_dir(&source_folder).unwrap();
        let source = source_folder.join("Personnel.akrat");
        let phrase = "this is a sufficiently long phrase";
        let mut data = VaultData::default();
        save_vault(&source, &mut data, phrase).unwrap();
        let bytes = std::fs::read(&source).unwrap();
        let default = directory.path().join("app-private-default.akrat");

        let (first, paths) = import_vault_bytes(&default, &[], "Personnel.akrat", &bytes).unwrap();
        assert_eq!(first.file_name().unwrap(), "Personnel.akrat");
        assert_eq!(std::fs::read(&first).unwrap(), bytes);
        assert!(load_vault(&first, phrase).is_ok());

        let (second, paths) =
            import_vault_bytes(&default, &paths, "Personnel.akrat", &bytes).unwrap();
        assert_eq!(second.file_name().unwrap(), "Personnel (2).akrat");
        assert_ne!(first, second);
        assert_eq!(paths.len(), 2);
    }
}
