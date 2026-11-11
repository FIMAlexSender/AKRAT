#![cfg_attr(all(windows, not(feature = "mobile")), windows_subsystem = "windows")]

mod runtime;
mod updater;
mod vault_catalog;

use akrat_core::{
    Contact, DeliveryState, Identity, Invitation, StoredMessage, VaultData, load_vault, save_vault,
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
        .with_title("AKRAT · Réseau direct")
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
    People,
    Settings,
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
    let invitation_address = use_signal(|| "127.0.0.1:47474".to_string());
    let invitation_result = use_signal(String::new);
    let mut notice = use_signal(String::new);
    let mut last_activity = use_signal(Instant::now);
    let mut update_status = use_signal(|| updater::UpdateStatus::Checking);
    let mut page = use_signal(|| Page::Messages);
    let mut sessions = use_signal(HashMap::<String, SessionHandle>::new);
    let mut listen_stop = use_signal(|| None::<tokio::sync::watch::Sender<bool>>);
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
                        if let Ok(data) = load_vault(&vault_path, &phrase) {
                            if let Some(conversation) = active_conversation.read().as_ref() {
                                for message in data.messages.iter().filter(|message| {
                                    message.conversation == *conversation
                                        && message.outgoing
                                        && matches!(
                                            message.delivery,
                                            DeliveryState::Pending
                                                | DeliveryState::Sent
                                                | DeliveryState::Unconfirmed
                                        )
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
                    }
                    UiEvent::Transmitted { conversation, id } => {
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            update_delivery(&mut data, &conversation, &id, DeliveryState::Sent);
                            if save_vault(&vault_path, &data, &phrase).is_ok() {
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
                                persisted = save_vault(&vault_path, &data, &phrase).is_ok();
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
                            if save_vault(&vault_path, &data, &phrase).is_ok() {
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
                    UiEvent::Closed {
                        conversation,
                        reason,
                    } => {
                        sessions.write().remove(&conversation);
                        let phrase = passphrase.read().clone();
                        let vault_path = path.read().clone();
                        if let Ok(mut data) = load_vault(&vault_path, &phrase) {
                            for message in &mut data.messages {
                                if message.conversation == conversation
                                    && message.outgoing
                                    && matches!(
                                        message.delivery,
                                        DeliveryState::Pending | DeliveryState::Sent
                                    )
                                {
                                    message.delivery = DeliveryState::Unconfirmed;
                                }
                            }
                            if save_vault(&vault_path, &data, &phrase).is_ok() {
                                vault.set(Some(data));
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
                if let Some(stop) = listen_stop.read().as_ref() {
                    let _ = stop.send(true);
                }
                listen_stop.set(None);
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
                        NavItem { label: "Identités & contacts", icon: "people", active: page() == Page::People, onclick: move |_| page.set(Page::People) }
                        NavItem { label: "Coffre", icon: "vault", active: page() == Page::Settings, onclick: move |_| page.set(Page::Settings) }
                        div { class: "side-bottom", div { class: "side-caption", "ÉTAT LOCAL" } div { class: "local-card", span { class: "status-dot live" } "Chiffré sur cet appareil" p { "{identities} identité(s) · {contacts} contact(s)" } } }
                    }
                    main { class: "content",
                        match page() {
                            Page::Messages => rsx! { ChatPage { vault, passphrase, path: path_value.clone(), active_conversation, sessions, draft, notice, trace, setup_label: (if identities == 0 { "Créer une identité" } else { "Ajouter un contact" }).to_string(), on_setup: move |_| page.set(if identities == 0 { Page::People } else { Page::Network }) } },
                            Page::Network => rsx! { NetworkPage { notice, invitation_address, invitation_result, vault, event_sender, listen_stop } },
                            Page::People => rsx! { PeoplePage { vault, passphrase, path: path_value, identity_name, import_uri, contact_name, notice } },
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
                                if let Some(stop) = listen_stop.read().as_ref() { let _ = stop.send(true); }
                                listen_stop.set(None);
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
    let selected_create_path = selected_path.clone();
    let default_path = default_vault_path();

    rsx! {
        section { class: "gate vault-gate",
            div { class: "gate-kicker", "ESPACE PERSONNEL · CHIFFRÉ" }
            h1 { "Vos échanges restent" br {} em { "chez vous." } }
            p { "Chaque coffre garde ses propres identités, contacts et conversations. Choisissez où le conserver, puis déverrouillez-le avec sa phrase secrète." }

            section { class: "vault-manager panel",
                div { class: "panel-title", "Vos coffres" }
                if vault_paths.read().is_empty() {
                    p { class: "quiet", "Aucun coffre enregistré. Ajoutez un emplacement ci-dessous." }
                }
                for entry in vault_paths.read().iter() {
                    {
                        let entry_path = entry.clone();
                        let path_to_remove = entry.clone();
                        let default_for_remove = default_path.clone();
                        let selected = entry == &selected_path;
                        let exists = entry.is_file();
                        let label = entry.file_name().and_then(|name| name.to_str()).unwrap_or("Coffre AKRAT").to_string();
                        let detail = entry.display().to_string();
                        rsx! {
                            div { class: if selected { "vault-entry selected" } else { "vault-entry" },
                                button { class: "vault-entry-select", onclick: move |_| {
                                    path.set(entry_path.clone());
                                    vault_path_input.set(entry_path.display().to_string());
                                    notice.set(String::new());
                                },
                                    strong { "{label}" }
                                    span { "{detail}" }
                                    small { if exists { "Coffre présent · à déverrouiller" } else { "Emplacement prêt · aucun fichier pour l’instant" } }
                                }
                                button { class: "vault-entry-remove", title: "Retirer de la liste sans supprimer le fichier", onclick: move |_| {
                                    let mut paths = vault_paths.read().clone();
                                    vault_catalog::remove(&mut paths, &path_to_remove);
                                    if paths.is_empty() { paths.push(default_for_remove.clone()); }
                                    match vault_catalog::save(&default_for_remove, &paths) {
                                        Ok(()) => {
                                            if path_to_remove == *path.read() {
                                                let fallback = paths[0].clone();
                                                path.set(fallback.clone());
                                                vault_path_input.set(fallback.display().to_string());
                                            }
                                            vault_paths.set(paths);
                                            notice.set("Coffre retiré de la liste. Son fichier n’a pas été supprimé.".into());
                                        }
                                        Err(error) => notice.set(error),
                                    }
                                }, "Retirer" }
                            }
                        }
                    }
                }
            }

            label { "Phrase secrète du coffre sélectionné" input { r#type: "password", value: "{passphrase}", placeholder: "Au moins 12 caractères", oninput: move |e| passphrase.set(e.value()) } }

            div { class: "vault-location",
                label { "Emplacement du coffre" input { r#type: "text", value: "{vault_path_input}", placeholder: "Chemin complet vers vault.akrat", oninput: move |e| vault_path_input.set(e.value()) } }
                if cfg!(all(feature = "desktop", not(target_os = "android"), not(target_os = "ios"))) {
                    div { class: "vault-location-actions",
                        button { class: "secondary", onclick: move |_| {
                            if let Some(chosen) = choose_existing_vault() {
                                vault_path_input.set(chosen.display().to_string());
                            }
                        }, "Ajouter un coffre existant…" }
                        button { class: "secondary", onclick: move |_| {
                            if let Some(chosen) = choose_new_vault_path() {
                                vault_path_input.set(chosen.display().to_string());
                            }
                        }, "Choisir où créer…" }
                    }
                }
                button { class: "secondary", onclick: move |_| {
                    let raw = vault_path_input.read().trim().to_string();
                    if raw.is_empty() { notice.set("Indiquez un emplacement pour le coffre.".into()); return; }
                    let chosen = PathBuf::from(raw);
                    if chosen.is_dir() { notice.set("Choisissez un fichier (par exemple vault.akrat), pas un dossier.".into()); return; }
                    path.set(chosen.clone());
                    let mut paths = vault_paths.read().clone();
                    vault_catalog::add(&mut paths, chosen);
                    match vault_catalog::save(&default_path, &paths) {
                        Ok(()) => { vault_paths.set(paths); notice.set("Emplacement ajouté à la liste.".into()); }
                        Err(error) => notice.set(error),
                    }
                }, "Ajouter cet emplacement" }
            }

            div { class: "gate-actions",
                if selected_exists {
                    button { class: "primary", onclick: move |_| {
                        let phrase = passphrase.read().clone();
                        match load_vault(&selected_open_path, &phrase) {
                            Ok(data) => { vault.set(Some(data)); notice.set("Coffre déverrouillé.".into()); }
                            Err(error) => notice.set(format!("Impossible de déverrouiller ce coffre : {error}")),
                        }
                    }, "Déverrouiller ce coffre" }
                } else {
                    button { class: "primary", onclick: move |_| {
                        let phrase = passphrase.read().clone();
                        if phrase.len() < 12 { notice.set("Choisissez une phrase secrète d’au moins 12 caractères.".into()); return; }
                        if selected_create_path.exists() { notice.set("Cet emplacement existe déjà et n’est pas un fichier de coffre. Choisissez un autre nom.".into()); return; }
                        let data = VaultData::default();
                        match save_vault(&selected_create_path, &data, &phrase) {
                            Ok(()) => { vault.set(Some(data)); notice.set("Coffre créé et chiffré à cet emplacement.".into()); }
                            Err(error) => notice.set(format!("Création impossible : {error}")),
                        }
                    }, "Créer un coffre ici" }
                }
            }
            p { class: "notice", "{notice}" }
            div { class: "path-note", "COFFRE SÉLECTIONNÉ · {selected_path.display()}" }
        }
    }
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
fn PeoplePage(
    vault: Signal<Option<VaultData>>,
    passphrase: Signal<String>,
    path: PathBuf,
    identity_name: Signal<String>,
    import_uri: Signal<String>,
    contact_name: Signal<String>,
    notice: Signal<String>,
) -> Element {
    let identity_path = path.clone();
    let import_path = path.clone();
    let data = vault.read();
    let identities = data
        .as_ref()
        .map(|v| {
            v.identities
                .iter()
                .map(|i| (i.id.clone(), i.name.clone(), i.fingerprint()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let contacts = data
        .as_ref()
        .map(|v| v.contacts.clone())
        .unwrap_or_default();
    rsx! { section { class: "page-scroll",
        div { class: "eyebrow", "VOTRE CARNET DE CONFIANCE" } h1 { "Identités & contacts" }
        p { class: "intro", "Chaque identité a sa propre clé. Vérifiez l’empreinte d’un contact par un canal indépendant avant de lui faire confiance." }
        div { class: "two-col",
            section { class: "panel", div { class: "panel-title", "Identités locales" }
                div { class: "form-row", input { value: "{identity_name}", placeholder: "Nom de cette identité", oninput: move |e| identity_name.set(e.value()) } button { class: "primary compact", onclick: move |_| {
                    let name = identity_name.read().trim().to_string();
                    let phrase = passphrase.read().clone();
                    if name.is_empty() { notice.set("Donnez un nom à l’identité.".into()); return; }
                    let mut d = match load_vault(&identity_path, &phrase) { Ok(d) => d, Err(e) => { notice.set(format!("Coffre inaccessible : {e}")); return; } };
                    match Identity::generate(name) { Ok(identity) => { d.identities.push(identity); match save_vault(&identity_path, &d, &phrase) { Ok(()) => { vault.set(Some(d)); identity_name.set(String::new()); notice.set("Nouvelle identité créée et enregistrée dans le coffre.".into()); }, Err(e) => notice.set(format!("Enregistrement impossible : {e}")) } }, Err(e) => notice.set(format!("Création impossible : {e}")) }
                }, "Créer" } }
                if identities.is_empty() { p { class: "quiet", "Aucune identité pour le moment." } }
                for (_id, name, fingerprint) in identities { div { class: "record", div { class: "record-icon", "◇" } div { class: "record-main", strong { "{name}" } span { class: "fingerprint", "{fingerprint}" } } } }
            }
            section { class: "panel", div { class: "panel-title", "Importer une invitation" }
                label { "Nom à afficher" input { value: "{contact_name}", placeholder: "Ex. Camille", oninput: move |e| contact_name.set(e.value()) } }
                label { "Lien d’invitation" textarea { value: "{import_uri}", placeholder: "akrat://invite/…", oninput: move |e| import_uri.set(e.value()) } }
                button { class: "secondary", onclick: move |_| {
                    let phrase = passphrase.read().clone(); let uri = import_uri.read().clone(); let name = contact_name.read().trim().to_string();
                    if name.is_empty() { notice.set("Donnez un nom au contact.".into()); return; }
                    match Invitation::from_uri(&uri) { Ok(invitation) => {
                        let mut d = match load_vault(&import_path, &phrase) { Ok(d) => d, Err(e) => { notice.set(format!("Coffre inaccessible : {e}")); return; } };
                        if d.contacts.iter().any(|c| c.fingerprint == invitation.fingerprint) { notice.set("Ce contact est déjà importé.".into()); return; }
                        d.contacts.push(Contact { fingerprint: invitation.fingerprint, name, public_key: invitation.public_key, address: invitation.address, manually_verified: false });
                        match save_vault(&import_path, &d, &phrase) { Ok(()) => { vault.set(Some(d)); import_uri.set(String::new()); contact_name.set(String::new()); notice.set("Invitation importée. Vérifiez l’empreinte avant toute connexion.".into()); }, Err(e) => notice.set(format!("Enregistrement impossible : {e}")) }
                    }, Err(e) => notice.set(format!("Invitation invalide : {e}")) }
                }, "Importer le contact" }
            }
        }
        section { class: "panel contacts-panel", div { class: "panel-title", "Contacts · {contacts.len()}" }
            if contacts.is_empty() { p { class: "quiet", "Les contacts importés apparaîtront ici." } }
            for contact in contacts { ContactRow { contact, vault, passphrase, path: path.clone(), notice } }
        }
    } }
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
    rsx! { div { class: "contact-row", div { class: "record-icon", "⌁" } div { class: "record-main", strong { "{contact.name}" } span { class: "fingerprint", "{contact.fingerprint}" } span { class: "quiet", "{contact.address}" } } if verified { span { class: "verified", "VÉRIFIÉ" } } else { button { class: "secondary compact", onclick: move |_| {
        let phrase = passphrase.read().clone(); let mut d = match load_vault(&path, &phrase) { Ok(d) => d, Err(e) => { notice.set(format!("Coffre inaccessible : {e}")); return; } };
        if let Some(item) = d.contacts.iter_mut().find(|c| c.fingerprint == fp) { item.manually_verified = true; }
        match save_vault(&path, &d, &phrase) { Ok(()) => { vault.set(Some(d)); notice.set("Contact marqué comme vérifié. Confirmez son empreinte avec lui en personne ou par un canal sûr.".into()); }, Err(e) => notice.set(format!("Enregistrement impossible : {e}")) }
    }, "Empreinte comparée hors AKRAT" } } } }
}

#[component]
fn NetworkPage(
    notice: Signal<String>,
    invitation_address: Signal<String>,
    invitation_result: Signal<String>,
    vault: Signal<Option<VaultData>>,
    event_sender: Signal<mpsc::UnboundedSender<UiEvent>>,
    mut listen_stop: Signal<Option<tokio::sync::watch::Sender<bool>>>,
) -> Element {
    let identities = vault
        .read()
        .as_ref()
        .map(|v| {
            v.identities
                .iter()
                .map(|i| (i.id.clone(), i.name.clone(), i.detached_copy()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let contacts = vault
        .read()
        .as_ref()
        .map(|v| {
            v.contacts
                .iter()
                .filter(|c| c.manually_verified)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut selected = use_signal(String::new);
    let mut selected_contact = use_signal(String::new);
    let mut listen_address = use_signal(|| "0.0.0.0:47474".to_string());
    rsx! {
        section { class: "page-scroll",
            div { class: "eyebrow", "CONNEXION DIRECTE" }
            h1 { "Réseau" }
            p { class: "intro", "Les connexions sont directes et authentifiées. Seuls les contacts dont l’empreinte a été vérifiée peuvent établir une session." }
            section { class: "panel network-panel",
                div { class: "panel-title", "Préparer une invitation" }
                if identities.is_empty() {
                    p { class: "quiet", "Créez d’abord une identité dans Identités & contacts." }
                } else {
                    label { "Identité" }
                    select { value: "{selected}", onchange: move |e| selected.set(e.value()),
                        option { value: "", "Choisir une identité" }
                        for (id, name, _) in identities.iter() { option { value: "{id}", "{name}" } }
                    }
                    label { "Adresse joignable de cet ordinateur" }
                    input { value: "{invitation_address}", placeholder: "192.168.1.20:47474", oninput: move |e| invitation_address.set(e.value()) }
                    button { class: "primary", onclick: move |_| {
                        let id = selected.read().clone();
                        let address = invitation_address.read().clone();
                        if id.is_empty() { notice.set("Choisissez une identité.".into()); return; }
                        let item = vault.read().as_ref().and_then(|v| v.identities.iter().find(|i| i.id == id).map(Identity::detached_copy));
                        match item.and_then(|identity| Invitation::create(&identity, address).ok()) {
                            Some(invite) => match invite.to_uri() { Ok(uri) => { invitation_result.set(uri); notice.set("Invitation créée. Partagez-la avec votre contact.".into()); }, Err(e) => notice.set(format!("Création impossible : {e}")) },
                            None => notice.set("Adresse invalide. Utilisez une IP et un port joignables.".into())
                        }
                    }, "Générer une invitation" }
                    if !invitation_result().is_empty() {
                        label { class: "invitation-label", "À transmettre au contact" }
                        textarea { class: "invite-text", readonly: true, value: "{invitation_result}", spellcheck: false }
                        button { class: "secondary copy-invite", onclick: move |_| {
                            let invitation = invitation_result.read().clone();
                            async move {
                                if copy_to_clipboard(invitation).await {
                                    notice.set("Invitation copiée. Collez-la dans votre messagerie sur le téléphone.".into());
                                } else {
                                    notice.set("Copie impossible. Maintenez le doigt sur le lien pour le sélectionner et le copier.".into());
                                }
                            }
                        }, "Copier l’invitation" }
                        p { class: "copy-hint", "Vous pouvez aussi maintenir le doigt sur le texte pour le sélectionner." }
                    }
                }
            }
            section { class: "panel network-panel",
                div { class: "panel-title", "Écoute et connexions" }
                label { "Adresse d’écoute" }
                input { value: "{listen_address}", placeholder: "0.0.0.0:47474", oninput: move |e| listen_address.set(e.value()) }
                if listen_stop.read().is_some() {
                    button { class: "secondary", onclick: move |_| {
                        if let Some(stop) = listen_stop.read().as_ref() { let _ = stop.send(true); }
                        listen_stop.set(None); notice.set("Arrêt de l’écoute demandé.".into());
                    }, "Arrêter l’écoute" }
                } else {
                    button { class: "secondary", onclick: move |_| {
                        let identity_id = selected.read().clone();
                        let local_identity = vault.read().as_ref().and_then(|v| v.identities.iter().find(|i| i.id == identity_id).map(Identity::detached_copy));
                        let verified = vault.read().as_ref().map(|v| v.contacts.iter().filter(|c| c.manually_verified).cloned().collect::<Vec<_>>()).unwrap_or_default();
                        match local_identity { Some(identity) => { let stop = runtime::listen(identity, verified, listen_address.read().clone(), event_sender.read().clone()); listen_stop.set(Some(stop)); }, None => notice.set("Choisissez une identité avant de démarrer l’écoute.".into()) }
                    }, "Démarrer l’écoute" }
                }
                if contacts.is_empty() {
                    p { class: "quiet", "Aucun contact vérifié ne peut encore se connecter." }
                } else {
                    label { "Contacter une personne" }
                    select { value: "{selected_contact}", onchange: move |e| selected_contact.set(e.value()),
                        option { value: "", "Choisir un contact vérifié" }
                        for contact in contacts.iter() { option { value: "{contact.fingerprint}", "{contact.name} · {contact.fingerprint}" } }
                    }
                    button { class: "primary", onclick: move |_| {
                        let identity_id = selected.read().clone(); let fp = selected_contact.read().clone();
                        if identity_id.is_empty() || fp.is_empty() { notice.set("Choisissez une identité et un contact vérifié.".into()); return; }
                        let identity = vault.read().as_ref().and_then(|v| v.identities.iter().find(|i| i.id == identity_id).map(Identity::detached_copy));
                        let contact = vault.read().as_ref().and_then(|v| v.contacts.iter().find(|c| c.fingerprint == fp && c.manually_verified).cloned());
                        match (identity, contact) { (Some(identity), Some(contact)) => runtime::connect(identity, contact, event_sender.read().clone()), _ => notice.set("Identité ou contact vérifié introuvable.".into()) }
                    }, "Établir une session chiffrée" }
                }
            }
            div { class: "callout", strong { "Une invitation ne suffit pas à établir la confiance." } p { "Comparez l’empreinte complète avec la personne, puis marquez son contact comme vérifié." } }
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
    active_conversation: Signal<Option<String>>,
    sessions: Signal<HashMap<String, SessionHandle>>,
    draft: Signal<String>,
    notice: Signal<String>,
    mut trace: Signal<Vec<String>>,
    setup_label: String,
    on_setup: EventHandler<MouseEvent>,
) -> Element {
    let conversation = active_conversation.read().clone();
    let stored = vault.read();
    let messages = conversation
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
    let has_messages = !messages.is_empty();
    rsx! { section { class: "chat-stage",
        if let Some(key) = conversation {
            div { class: "chat-head", div { class: "eyebrow", "SESSION DIRECTE · NOISE XX" } h1 { "{peer_name}" } span { class: if connected { "verified" } else { "quiet" }, if connected { "CANAL CHIFFRÉ ACTIF" } else { "HORS LIGNE · MESSAGES EN ATTENTE" } } }
            div { class: "message-list",
                if !has_messages { div { class: "chat-empty", "Le canal est prêt. Envoyez le premier message." } }
                for message in messages { MessageCard { message } }
            }
            div { class: "composer", textarea { value: "{draft}", placeholder: "Écrire un message…", oninput: move |e| draft.set(e.value()), onkeydown: move |e| if e.key() == Key::Enter && !e.modifiers().shift() { e.prevent_default(); } } button { class: "primary", disabled: !connected, onclick: move |_| {
                let text = draft.read().trim().to_string(); if text.is_empty() { return; }
                if text.len() > 10 * 1024 { notice.set("Message limité à 10 Kio.".into()); return; }
                let id = match runtime::message_id() { Ok(id) => id, Err(error) => { notice.set(format!("Identifiant impossible : {error}")); return; } };
                let phrase = passphrase.read().clone();
                let mut data = match load_vault(&path, &phrase) { Ok(data) => data, Err(error) => { notice.set(format!("Coffre inaccessible : {error}")); return; } };
                data.messages.push(runtime::new_message(key.clone(), id.clone(), text.clone()));
                if let Err(error) = save_vault(&path, &data, &phrase) { notice.set(format!("Sauvegarde impossible : {error}")); return; }
                vault.set(Some(data)); draft.set(String::new());
                push_trace(&mut trace, "Message enregistré dans le coffre · attente d’envoi chiffré".into());
                match sessions.read().get(&key).cloned().map(|session| session.send_text(id.clone(), text)) { Some(Ok(())) => {}, Some(Err(error)) => update_message_status(&path, &phrase, vault, (&key, &id), DeliveryState::Unconfirmed, &mut notice, error), None => update_message_status(&path, &phrase, vault, (&key, &id), DeliveryState::Unconfirmed, &mut notice, "Session hors ligne".into()) }
            }, "Envoyer" } }
        } else {
            div { class: "chat-empty-state",
                div { class: "message-illustration", span { class: "bubble bubble-back" } span { class: "bubble bubble-front", span { "•••" } } }
                div { class: "eyebrow", "MESSAGERIE PAIR À PAIR" }
                h1 { "La parole circule." }
                p { "Choisissez un contact vérifié dans Réseau pour établir une session directe. Les étapes apparaîtront dans le journal." }
                button { class: "primary empty-action", onclick: on_setup, span { class: "lock-mark" } "{setup_label}" }
            }
        }
    } }
}

#[component]
fn MessageCard(message: StoredMessage) -> Element {
    let outgoing = message.outgoing;
    let status = match message.delivery {
        DeliveryState::Pending => "EN ATTENTE",
        DeliveryState::Sent => "TRANSMIS · ACCUSÉ EN ATTENTE",
        DeliveryState::Received => "REÇU",
        DeliveryState::Acknowledged => "REMIS",
        DeliveryState::Unconfirmed => "NON CONFIRMÉ",
    };
    rsx! { div { class: if outgoing { "message outgoing" } else { "message incoming" }, p { "{message.text}" } span { "{status}" } } }
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
        if save_vault(path, &data, passphrase).is_ok() {
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
