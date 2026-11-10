mod runtime;

use akrat_core::{
    Contact, DeliveryState, Identity, Invitation, StoredMessage, VaultData, load_vault, save_vault,
};
use dioxus::prelude::*;
use directories::ProjectDirs;
use runtime::{SessionHandle, UiEvent};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

fn main() {
    use dioxus_desktop::{Config, LogicalSize, WindowBuilder};
    let window = WindowBuilder::new()
        .with_title("AKRAT · Réseau direct")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(1000.0, 680.0));
    dioxus::LaunchBuilder::desktop()
        .with_cfg(Config::new().with_window(window))
        .launch(App);
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
    let mut vault = use_signal(|| None::<VaultData>);
    let mut passphrase = use_signal(String::new);
    let identity_name = use_signal(String::new);
    let import_uri = use_signal(String::new);
    let contact_name = use_signal(String::new);
    let invitation_address = use_signal(|| "127.0.0.1:47474".to_string());
    let invitation_result = use_signal(String::new);
    let mut notice = use_signal(String::new);
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

    let path_value = path.read().clone();
    let create_path = path_value.clone();
    let open_path = path_value.clone();
    let opened = vault.read().is_some();
    let identities = vault
        .read()
        .as_ref()
        .map(|v| v.identities.len())
        .unwrap_or(0);
    let contacts = vault.read().as_ref().map(|v| v.contacts.len()).unwrap_or(0);

    rsx! {
        style { {CSS} }
        div { class: "app-frame",
            header { class: "topbar",
                div { class: "brand", span { class: "brand-mark", "A" } div { "AKRAT" span { class: "brand-sub", "RÉSEAU DIRECT · LOCAL D’ABORD" } } }
                div { class: "top-status", span { class: if opened { "status-dot live" } else { "status-dot" } } if opened { "Coffre déverrouillé" } else { "Coffre verrouillé" } }
            }
            if !opened {
                section { class: "gate",
                    div { class: "gate-kicker", "ESPACE PERSONNEL · CHIFFRÉ" }
                    h1 { "Vos échanges restent" br {} em { "chez vous." } }
                    p { "Le coffre AKRAT garde vos identités, contacts et conversations sur cet ordinateur, protégés par votre phrase secrète." }
                    label { "Phrase secrète" input { r#type: "password", value: "{passphrase}", placeholder: "Au moins une phrase que vous seul connaissez", oninput: move |e| passphrase.set(e.value()) } }
                    div { class: "gate-actions",
                        button { class: "primary", onclick: move |_| {
                            let phrase = passphrase.read().clone();
                            if phrase.len() < 12 { notice.set("Choisissez une phrase secrète d’au moins 12 caractères.".into()); return; }
                            if create_path.exists() { notice.set("Un coffre existe déjà à cet emplacement. Déverrouillez-le.".into()); return; }
                            let data = VaultData::default();
                            match save_vault(&create_path, &data, &phrase) { Ok(()) => { vault.set(Some(data)); notice.set("Coffre créé et chiffré sur cet appareil.".into()); }, Err(e) => notice.set(format!("Création impossible : {e}")) }
                        }, "Créer mon coffre" }
                        button { class: "secondary", onclick: move |_| {
                            let phrase = passphrase.read().clone();
                            match load_vault(&open_path, &phrase) { Ok(data) => { vault.set(Some(data)); notice.set("Coffre déverrouillé.".into()); }, Err(e) => notice.set(format!("Impossible d’ouvrir le coffre : {e}")) }
                        }, "Déverrouiller" }
                    }
                    p { class: "notice", "{notice}" }
                    div { class: "path-note", "COFFRE LOCAL · {path_value.display()}" }
                }
            } else {
                div { class: "workspace",
                    aside { class: "sidebar",
                        div { class: "side-caption", "ESPACE" }
                        NavItem { label: "Conversations", glyph: "◌", active: page() == Page::Messages, onclick: move |_| page.set(Page::Messages) }
                        NavItem { label: "Réseau", glyph: "⌁", active: page() == Page::Network, onclick: move |_| page.set(Page::Network) }
                        NavItem { label: "Identités & contacts", glyph: "◇", active: page() == Page::People, onclick: move |_| page.set(Page::People) }
                        NavItem { label: "Coffre", glyph: "▤", active: page() == Page::Settings, onclick: move |_| page.set(Page::Settings) }
                        div { class: "side-bottom", div { class: "side-caption", "ÉTAT LOCAL" } div { class: "local-card", span { class: "status-dot live" } "Chiffré sur cet appareil" p { "{identities} identité(s) · {contacts} contact(s)" } } }
                    }
                    main { class: "content",
                        match page() {
                            Page::Messages => rsx! { ChatPage { vault, passphrase, path: path_value.clone(), active_conversation, sessions, draft, notice, trace } },
                            Page::Network => rsx! { NetworkPage { notice, invitation_address, invitation_result, vault, event_sender, listen_stop } },
                            Page::People => rsx! { PeoplePage { vault, passphrase, path: path_value, identity_name, import_uri, contact_name, notice } },
                            Page::Settings => rsx! { SettingsPage { path: path_value, notice, on_lock: move |_| {
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
fn NavItem(
    label: &'static str,
    glyph: &'static str,
    active: bool,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    rsx! { button { class: if active { "nav-item active" } else { "nav-item" }, onclick, span { class: "nav-glyph", "{glyph}" } "{label}" } }
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
                    if !invitation_result().is_empty() { label { "À transmettre au contact" } textarea { readonly: true, value: "{invitation_result}" } }
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
            div { class: "chat-empty-state", div { class: "eyebrow", "MESSAGERIE PAIR À PAIR" } h1 { "La parole circule." } p { "Choisissez un contact vérifié dans Réseau pour établir une session directe. Les étapes apparaîtront dans le journal." } }
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
    on_lock: EventHandler<MouseEvent>,
) -> Element {
    rsx! { section { class: "page-scroll",
        div { class: "eyebrow", "STOCKAGE LOCAL" } h1 { "Votre coffre" }
        p { class: "intro", "Les clés privées, contacts et messages sont conservés dans un fichier chiffré par votre phrase secrète." }
        section { class: "panel settings-panel", div { class: "panel-title", "Emplacement" } p { class: "fingerprint", "{path.display()}" } div { class: "crypto-note", "Chiffrement du coffre : Argon2id + AES-256-GCM. Une phrase secrète perdue ne peut pas être récupérée." } button { class: "secondary", onclick: on_lock, "Verrouiller le coffre" } }
        p { class: "quiet", "{notice}" }
    } }
}

fn default_vault_path() -> PathBuf {
    if let Some(path) = std::env::var_os("AKRAT_VAULT_PATH") {
        return PathBuf::from(path);
    }
    ProjectDirs::from("org", "Akrat", "AKRAT")
        .map(|dirs| dirs.data_local_dir().join("vault.akrat"))
        .unwrap_or_else(|| PathBuf::from("vault.akrat"))
}

const CSS: &str = r#"
*{box-sizing:border-box} body{margin:0;background:#111210;color:#e9e6dc;font-family:Segoe UI,Arial,sans-serif;overflow:hidden} button,input,textarea,select{font:inherit} button{cursor:pointer}.app-frame{height:100vh;display:flex;flex-direction:column;background:#111210}.topbar{height:68px;border-bottom:1px solid #30312c;display:flex;align-items:center;justify-content:space-between;padding:0 28px;flex-shrink:0}.brand{display:flex;gap:12px;align-items:center;font:700 16px 'Trebuchet MS',sans-serif;letter-spacing:.13em}.brand-mark{width:31px;height:31px;display:grid;place-items:center;background:#c6f36b;color:#111;font-size:18px;transform:rotate(-4deg)}.brand-sub{display:block;color:#777a70;font:9px Consolas,monospace;letter-spacing:.12em;margin-top:3px}.top-status,.side-caption,.eyebrow,.trace-head,.trace-foot,.gate-kicker{font:10px Consolas,monospace;letter-spacing:.12em;color:#999b91}.top-status{display:flex;align-items:center;gap:8px}.status-dot,.trace-pulse{display:inline-block;width:7px;height:7px;border-radius:50%;background:#7c8075}.status-dot.live,.trace-pulse{background:#b6eb62;box-shadow:0 0 10px #b6eb6250}.workspace{display:grid;grid-template-columns:200px minmax(0,1fr) minmax(220px,250px);flex:1;min-height:0}.sidebar{border-right:1px solid #30312c;padding:24px 14px;display:flex;flex-direction:column;gap:6px}.side-caption{padding:8px 10px 10px}.nav-item{border:0;background:transparent;color:#a8a99f;text-align:left;padding:12px 11px;border-radius:5px;display:flex;align-items:center;gap:12px;font-size:13px}.nav-item:hover,.nav-item.active{background:#262720;color:#eff0e5}.nav-item.active{box-shadow:inset 2px 0 #c6f36b}.nav-glyph{font-size:19px;color:#c6f36b;width:18px;text-align:center}.side-bottom{margin-top:auto}.local-card{border:1px solid #37392f;border-radius:5px;padding:13px;font-size:11px;color:#c5c7bc}.local-card p{color:#777a70;font:10px Consolas,monospace;margin:9px 0 0}.trace{border-left:1px solid #30312c;padding:22px 18px;background:#151612}.trace-head{display:flex;gap:9px;align-items:center;padding-bottom:19px;border-bottom:1px solid #30312c;font-size:9px}.trace-line{font:10px Consolas,monospace;color:#c2c4b9;padding:13px 0;border-bottom:1px solid #262720}.trace-line span{color:#797c72;margin-right:10px}.trace-line.muted{color:#777a70}.trace-foot{font-size:8px;line-height:1.7;margin-top:auto;padding-top:22px}.trace{display:flex;flex-direction:column;overflow:auto}.content{min-width:0;overflow:auto}.page-scroll{max-width:940px;margin:0 auto;padding:50px 54px}.eyebrow{color:#b6eb62;font-size:9px;margin-bottom:15px}h1,h2{font-family:'Trebuchet MS',Segoe UI,sans-serif;margin:0;letter-spacing:-.04em}h1{font-size:38px;font-weight:500}h2{font-size:19px}.intro{max-width:650px;color:#a0a297;font-size:14px;line-height:1.7;margin:13px 0 28px}.empty-card,.panel{background:#191a16;border:1px solid #36382f;border-radius:6px}.primary,.secondary{border-radius:4px;padding:12px 16px;border:1px solid #c6f36b;background:#c6f36b;color:#181a14;font-weight:700;font-size:12px}.secondary{background:transparent;color:#d9dacd;border-color:#54564b}.primary:hover{background:#d7ff8d}.secondary:hover{border-color:#c6f36b}.compact{padding:9px 13px}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{padding:20px;margin-bottom:16px}.panel-title{font:10px Consolas,monospace;letter-spacing:.1em;color:#bfc1b5;text-transform:uppercase;padding-bottom:15px;border-bottom:1px solid #32342c;margin-bottom:16px}.form-row{display:flex;gap:8px}label{display:block;color:#a6a89c;font-size:11px;margin:13px 0}input,textarea,select{display:block;width:100%;margin-top:7px;background:#11120f;border:1px solid #3c3e35;color:#e9e6dc;padding:11px 12px;border-radius:4px;outline:none;font-size:12px}input:focus,textarea:focus,select:focus{border-color:#a9d85b}textarea{min-height:74px;resize:vertical;font:10px Consolas,monospace;line-height:1.5}.form-row input{margin:0}.quiet{font-size:11px;color:#83857a}.record,.contact-row{display:flex;align-items:center;gap:12px;padding:13px 0;border-bottom:1px solid #2c2e27}.record-icon{flex:0 0 34px;height:34px;display:grid;place-items:center;border:1px solid #4b4d3e;color:#c6f36b;border-radius:4px;font-size:18px}.record-main{min-width:0;display:flex;flex:1;flex-direction:column;gap:5px}.record-main strong{font-size:12px;color:#e3e2d8}.fingerprint{font:9px Consolas,monospace;color:#a6a89c;overflow-wrap:anywhere}.verified{color:#b6eb62;font:9px Consolas,monospace;letter-spacing:.08em}.contacts-panel{margin-top:2px}.network-panel{max-width:610px}.callout{max-width:610px;border-left:2px solid #c6f36b;background:#1a1b17;padding:14px 17px;color:#d4d5ca;font-size:12px}.callout p{color:#92948a;margin-bottom:0;line-height:1.6}.settings-panel{max-width:660px}.crypto-note{border:1px solid #36382f;padding:13px;color:#a7a99d;font-size:11px;line-height:1.6;margin:18px 0}.gate{width:min(480px,calc(100% - 40px));margin:auto;padding:44px 0}.gate h1{font-size:48px;line-height:1.04;margin:20px 0}.gate h1 em{font-style:normal;color:#c6f36b}.gate>p:not(.notice){color:#a0a297;line-height:1.7;font-size:14px;margin-bottom:28px}.gate-actions{display:flex;gap:9px}.gate-actions button{flex:1}.path-note{font:9px Consolas,monospace;color:#676a60;margin-top:30px;overflow-wrap:anywhere}.notice{color:#c6f36b;font-size:11px;min-height:18px}.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#272920;border:1px solid #515541;border-radius:5px;padding:12px 18px;font-size:12px;color:#e6ebd7;box-shadow:0 12px 40px #0008;max-width:80vw}.gate input{padding:14px}.gate .notice{margin-top:15px}.chat-stage{height:100%;min-height:0;display:flex;flex-direction:column;padding:36px 42px}.chat-head{border-bottom:1px solid #30312c;padding-bottom:20px}.chat-head .eyebrow{margin-bottom:10px}.chat-head h1{font-size:28px;display:inline-block;margin-right:16px}.message-list{flex:1;overflow:auto;display:flex;flex-direction:column;gap:12px;padding:22px 4px}.message{max-width:75%;padding:12px 15px;border-radius:7px;background:#20211c;border:1px solid #37392f}.message.outgoing{align-self:flex-end;background:#282d20;border-color:#4f5b39}.message p{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 8px;font-size:13px;line-height:1.55}.message span{font:8px Consolas,monospace;color:#a3ab8e;letter-spacing:.06em}.chat-empty,.chat-empty-state{margin:auto;text-align:center;color:#96988e;font-size:13px}.chat-empty-state{max-width:560px}.chat-empty-state h1{font-size:44px;color:#e9e6dc;margin:12px}.chat-empty-state p{line-height:1.7}.composer{display:flex;gap:10px;align-items:end;border-top:1px solid #30312c;padding-top:15px}.composer textarea{min-height:54px;max-height:130px;margin:0}.composer button:disabled{opacity:.4;cursor:not-allowed}
"#;
