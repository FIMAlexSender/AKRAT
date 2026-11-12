#![cfg_attr(all(windows, not(feature = "mobile")), windows_subsystem = "windows")]

mod async_mailbox;
mod runtime;
mod updater;
mod vault_catalog;

use akrat_core::{
    Contact, DeliveryActor, DeliveryEventKind, DeliveryState, Identity, Invitation, MailboxInbox,
    MailboxRoute, StoredMessage, VaultData, load_vault, save_vault,
};
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

#[component]
fn App() -> Element {
    let path = use_signal(default_vault_path);
    let vault_paths = use_signal(|| vault_catalog::load(&default_vault_path()));
    let vault_path_input = use_signal(|| default_vault_path().display().to_string());
    let mut vault = use_signal(|| None::<VaultData>);
    let mut passphrase = use_signal(String::new);
    let identity_name = use_signal(String::new);
    let import_uri = use_signal(String::new);
    let contact_name = use_signal(String::new);
    let invitation_result = use_signal(String::new);
    let mut notice = use_signal(String::new);
    let mut last_activity = use_signal(Instant::now);
    let mut update_status = use_signal(|| updater::UpdateStatus::Checking);
    let mut page = use_signal(|| Page::Messages);
    let mut sessions = use_signal(HashMap::<String, SessionHandle>::new);
    let mut listen_stops = use_signal(HashMap::<String, tokio::sync::watch::Sender<bool>>::new);
    let mut applied_network_contacts = use_signal(Vec::<Contact>::new);
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
            )
        });
        if let Some((identities, contacts, retry_targets)) = snapshot {
            let contacts_changed = *applied_network_contacts.read() != contacts;
            let active = listen_stops.read().keys().cloned().collect::<Vec<_>>();
            for identity in &identities {
                if !active.contains(&identity.id) {
                    let stop = runtime::listen(
                        identity.detached_copy(),
                        contacts.clone(),
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
            let (path_value, phrase, inboxes, queued_mailbox_messages, pending_receipts) = {
                let snapshot = vault.read();
                let Some(data) = snapshot.as_ref() else {
                    continue;
                };
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
                            message.outgoing && message.delivery == DeliveryState::MailboxStored
                        })
                        .map(|message| (message.conversation.clone(), message.id.clone()))
                        .collect::<Vec<_>>(),
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
                        active_conversation.set(Some(conversation));
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
                                if handle
                                    .send_text(message.id.clone(), message.text.clone())
                                    .is_ok()
                                {
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
                            Page::Network => rsx! { NetworkPage { vault, listen_stops, path: path_value.clone(), passphrase, notice } },
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
    let selected_exists = selected_path.is_file();
    let selected_open_path = selected_path.clone();
    let default_path = default_vault_path();
    let default_for_browse = default_path.clone();
    let default_for_create = default_path.clone();
    let mut tab = use_signal(|| VaultGateTab::Existing);
    let mut new_vault_name = use_signal(|| {
        default_vault_path()
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("vault")
            .to_string()
    });
    let mut confirm_passphrase = use_signal(String::new);
    let mut manage_path = use_signal(|| None::<PathBuf>);
    let mut manage_passphrase = use_signal(String::new);
    let mut rename_name = use_signal(String::new);
    let mut manage_verified = use_signal(|| false);
    let mut confirm_delete = use_signal(|| false);

    rsx! {
        section { class: "gate vault-gate",
            div { class: "gate-kicker", "ESPACE PERSONNEL · CHIFFRÉ" }
            h1 { "Vos coffres" }
            p { class: "intro", "Ouvrez un coffre chiffré existant ou créez-en un nouveau. Chaque coffre garde ses propres identités, contacts et conversations." }
            div { class: "vault-tabs",
                button { class: if *tab.read() == VaultGateTab::Existing { "vault-tab active" } else { "vault-tab" }, onclick: move |_| { tab.set(VaultGateTab::Existing); notice.set(String::new()); }, "Ouvrir un coffre" }
                button { class: if *tab.read() == VaultGateTab::Create { "vault-tab active" } else { "vault-tab" }, onclick: move |_| {
                    tab.set(VaultGateTab::Create);
                    passphrase.set(String::new());
                    confirm_passphrase.set(String::new());
                    let current_path = path.read().clone();
                    vault_path_input.set(current_path.display().to_string());
                    if let Some(stem) = current_path.file_stem().and_then(|name| name.to_str()) { new_vault_name.set(stem.to_string()); }
                    notice.set(String::new());
                }, "Créer un coffre" }
            }
            if *tab.read() == VaultGateTab::Existing {
                section { class: "vault-manager panel",
                    div { class: "panel-title", "Coffres enregistrés · {vault_paths.read().len()}" }
                    if vault_paths.read().is_empty() { p { class: "quiet", "Aucun coffre enregistré. Parcourez vos fichiers ou créez-en un." } }
                    for entry in vault_paths.read().iter() {
                        {
                            let entry_path = entry.clone();
                            let entry_for_manage = entry.clone();
                            let entry_for_verify = entry.clone();
                            let entry_for_rename = entry.clone();
                            let entry_for_delete = entry.clone();
                            let default_for_rename = default_path.clone();
                            let default_for_delete = default_path.clone();
                            let is_selected = entry == &selected_path;
                            let exists = entry.is_file();
                            let label = entry.file_stem().and_then(|name| name.to_str()).unwrap_or("Coffre AKRAT").to_string();
                            let detail = entry.display().to_string();
                            let is_managing = manage_path.read().as_ref() == Some(entry);
                            rsx! {
                                div { class: if is_selected { "vault-entry selected" } else { "vault-entry" },
                                    button { class: "vault-entry-select", onclick: move |_| {
                                        path.set(entry_path.clone());
                                        vault_path_input.set(entry_path.display().to_string());
                                        passphrase.set(String::new());
                                        notice.set(String::new());
                                    },
                                        span { class: "vault-entry-title", strong { "{label}" } span { class: "vault-entry-status", if exists { "Présent" } else { "Introuvable" } } }
                                        span { class: "vault-entry-path", "{detail}" }
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
                                                let renamed = match vault_path_with_name(&entry_for_rename, &rename_name.read()) { Ok(path) => path, Err(error) => { notice.set(error); return; } };
                                                if renamed == entry_for_rename { notice.set("Ce coffre porte déjà ce nom.".into()); return; }
                                                if renamed.exists() { notice.set("Un fichier existe déjà avec ce nom.".into()); return; }
                                                if let Err(error) = std::fs::rename(&entry_for_rename, &renamed) { notice.set(format!("Renommage impossible : {error}")); return; }
                                                let mut paths = vault_paths.read().clone();
                                                if !vault_catalog::replace(&mut paths, &entry_for_rename, renamed.clone()) {
                                                    let _ = std::fs::rename(&renamed, &entry_for_rename);
                                                    notice.set("Ce coffre n’est plus dans la liste. Réessayez.".into());
                                                    return;
                                                }
                                                if let Err(error) = vault_catalog::save(&default_for_rename, &paths) {
                                                    let rollback = std::fs::rename(&renamed, &entry_for_rename);
                                                    notice.set(match rollback { Ok(()) => format!("Liste des coffres non enregistrée : {error}"), Err(rollback_error) => format!("Liste non enregistrée ({error}) et retour arrière impossible ({rollback_error}).") });
                                                    return;
                                                }
                                                if *path.read() == entry_for_rename { path.set(renamed.clone()); vault_path_input.set(renamed.display().to_string()); }
                                                vault_paths.set(paths);
                                                manage_path.set(None);
                                                manage_passphrase.set(String::new());
                                                notice.set("Coffre renommé. Son contenu chiffré est inchangé.".into());
                                            }, "Renommer le coffre" }
                                            div { class: "vault-danger-zone",
                                                strong { "Supprimer le fichier du coffre" }
                                                p { "Cette action efface ce coffre et tout son historique de cet appareil." }
                                                if !*confirm_delete.read() {
                                                    button { class: "danger-button", onclick: move |_| confirm_delete.set(true), "Supprimer…" }
                                                } else {
                                                    p { class: "delete-confirm-text", "Confirmez la suppression définitive de « {label} »." }
                                                    div { class: "gate-actions",
                                                        button { class: "secondary", onclick: move |_| confirm_delete.set(false), "Annuler" }
                                                        button { class: "danger-button", onclick: move |_| {
                                                            let phrase = manage_passphrase.read().clone();
                                                            if let Err(error) = load_vault(&entry_for_delete, &phrase) { manage_verified.set(false); confirm_delete.set(false); notice.set(format!("Suppression refusée : {error}")); return; }
                                                            let mut paths = vault_paths.read().clone();
                                                            vault_catalog::remove(&mut paths, &entry_for_delete);
                                                            if paths.is_empty() { paths.push(default_for_delete.clone()); }
                                                            if let Err(error) = vault_catalog::save(&default_for_delete, &paths) { notice.set(format!("Liste des coffres impossible à mettre à jour : {error}")); return; }
                                                            if let Err(error) = std::fs::remove_file(&entry_for_delete) {
                                                                let _ = vault_catalog::add(&mut paths, entry_for_delete.clone());
                                                                let _ = vault_catalog::save(&default_for_delete, &paths);
                                                                notice.set(format!("Suppression impossible : {error}"));
                                                                return;
                                                            }
                                                            let fallback = paths.first().cloned().unwrap_or_else(|| default_for_delete.clone());
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
                label { "Phrase secrète" input { r#type: "password", value: "{passphrase}", placeholder: "Phrase secrète du coffre sélectionné", oninput: move |event| passphrase.set(event.value()) } }
                if selected_exists {
                    button { class: "primary gate-primary-action", onclick: move |_| {
                        let phrase = passphrase.read().clone();
                        match load_vault(&selected_open_path, &phrase) {
                            Ok(data) => { vault.set(Some(data)); notice.set("Coffre déverrouillé.".into()); }
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
                            match vault_catalog::save(&default_for_browse, &paths) {
                                Ok(()) => { vault_paths.set(paths); path.set(chosen); passphrase.set(String::new()); notice.set("Coffre ajouté à la liste.".into()); },
                                Err(error) => notice.set(error),
                            }
                        }
                    }, "Parcourir les fichiers pour trouver un coffre…" }
                }
            } else {
                section { class: "panel vault-create-panel",
                    div { class: "panel-title", "Nouveau coffre chiffré" }
                    p { class: "quiet", "Choisissez un nom, un emplacement et une phrase secrète. La confirmation évite les erreurs de saisie." }
                    label { "Nom du coffre" input { value: "{new_vault_name}", placeholder: "Ex. Personnel", oninput: move |event| new_vault_name.set(event.value()) } }
                    label { "Fichier de destination" input { r#type: "text", value: "{vault_path_input}", placeholder: "Chemin du fichier .akrat", oninput: move |event| vault_path_input.set(event.value()) } }
                    if cfg!(all(feature = "desktop", not(target_os = "android"), not(target_os = "ios"))) {
                        button { class: "secondary browse-vault-button", onclick: move |_| {
                            if let Some(chosen) = choose_new_vault_path() {
                                vault_path_input.set(chosen.display().to_string());
                                new_vault_name.set(chosen.file_stem().and_then(|name| name.to_str()).unwrap_or("vault").to_string());
                            }
                        }, "Choisir un emplacement…" }
                    }
                    label { "Phrase secrète · 12 caractères minimum" input { r#type: "password", value: "{passphrase}", placeholder: "Créer une phrase secrète", oninput: move |event| passphrase.set(event.value()) } }
                    label { "Confirmer la phrase secrète" input { r#type: "password", value: "{confirm_passphrase}", placeholder: "Saisir la même phrase secrète", oninput: move |event| confirm_passphrase.set(event.value()) } }
                    button { class: "primary gate-primary-action", onclick: move |_| {
                        let phrase = passphrase.read().clone();
                        let confirmation = confirm_passphrase.read().clone();
                        if phrase.len() < 12 { notice.set("La phrase secrète doit contenir au moins 12 caractères.".into()); return; }
                        if phrase != confirmation { notice.set("Les deux phrases secrètes ne correspondent pas.".into()); return; }
                        let base = PathBuf::from(vault_path_input.read().trim());
                        let destination = match vault_path_with_name(&base, &new_vault_name.read()) { Ok(path) => path, Err(error) => { notice.set(error); return; } };
                        if destination.exists() { notice.set("Un fichier existe déjà à cet emplacement. Choisissez un autre nom ou dossier.".into()); return; }
                        let mut data = VaultData::default();
                        if let Err(error) = save_vault(&destination, &mut data, &phrase) { notice.set(format!("Création impossible : {error}")); return; }
                        let mut paths = vault_paths.read().clone();
                        vault_catalog::add(&mut paths, destination.clone());
                        if let Err(error) = vault_catalog::save(&default_for_create, &paths) {
                            let _ = std::fs::remove_file(&destination);
                            notice.set(format!("Impossible d’enregistrer le coffre dans la liste : {error}"));
                            return;
                        }
                        path.set(destination.clone());
                        vault_path_input.set(destination.display().to_string());
                        vault_paths.set(paths);
                        vault.set(Some(data));
                        confirm_passphrase.set(String::new());
                        notice.set("Coffre créé et chiffré. Le réseau démarre automatiquement.".into());
                    }, "Créer et chiffrer le coffre" }
                }
            }
            p { class: "notice", "{notice}" }
            if *tab.read() == VaultGateTab::Existing { div { class: "path-note", "COFFRE SÉLECTIONNÉ · {selected_path.display()}" } }
        }
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
fn choose_new_vault_path() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter("Coffre AKRAT", &["akrat"])
        .set_file_name("vault.akrat")
        .save_file()
}

#[cfg(any(not(feature = "desktop"), target_os = "android", target_os = "ios"))]
fn choose_existing_vault() -> Option<PathBuf> {
    None
}

#[cfg(any(not(feature = "desktop"), target_os = "android", target_os = "ios"))]
fn choose_new_vault_path() -> Option<PathBuf> {
    None
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
    let inbox_path = path.clone();
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
    let mut conversation_items = Vec::<(String, String, String, u64, bool)>::new();
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
    let peer_name = conversation
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
        .unwrap_or_else(|| "Conversation".into());
    let connected = conversation
        .as_ref()
        .is_some_and(|key| sessions.read().contains_key(key));
    let connect_conversation = conversation.clone();
    let input_conversation = conversation.clone();
    let button_conversation = conversation.clone();
    let input_path = path.clone();
    let button_path = path.clone();
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
                div { class: "conversation-list-head", strong { "Conversations" } button { class: "icon-button", title: "Ajouter un contact", onclick: on_setup, "+" } }
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
                        div { class: "chat-head-copy", div { class: "eyebrow", "MESSAGERIE CHIFFRÉE · NOISE XX" } h1 { "{peer_name}" } span { class: if connected { "verified" } else { "quiet" }, if connected { "SESSION ACTIVE" } else { "HORS LIGNE" } } }
                        if !connected {
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
                        textarea {
                            value: "{draft}", placeholder: "Écrire un message… · Entrée pour envoyer",
                            oninput: move |e| draft.set(e.value()),
                            onkeydown: move |event| if event.key() == Key::Enter && !event.modifiers().shift() {
                                event.prevent_default();
                                    if let Some(key) = input_conversation.clone() { submit_message(key, draft, input_path.clone(), passphrase, vault, sessions, notice, trace, event_sender); }
                            }
                        }
                        button { class: "primary", onclick: move |_| if let Some(key) = button_conversation.clone() { submit_message(key, draft, button_path.clone(), passphrase, vault, sessions, notice, trace, event_sender); }, if connected { "Envoyer" } else { "Mettre en file" } }
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
            p { "{message.text}" }
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
            }
        }
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
