use akrat_core::{
    Contact, Conversation, IdentityTrust, MessageDelivery, MessageDirection, StoredMessage,
};
use akrat_crypto::create_identity;
use akrat_crypto::session::Session;
use akrat_network::{
    ListenerEvent, ListenerHandle, MAX_SESSION_TEXT_SIZE, PendingPeer, SessionEvent, SessionHandle,
    connect, initiate_session, start_listener, start_message_session,
};
use akrat_protocol::Invitation;
use akrat_storage::{
    VaultData, VaultKey, append_message, load_vault_data_with_key, remove_conversation,
    save_vault_data_and_key, save_vault_data_with_key,
};
use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, WindowBuilder};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

const STYLE: &str = include_str!("style.css");

#[derive(Clone, Copy)]
struct AppState {
    vault: Signal<VaultData>,
    unlocked: Signal<bool>,
    passphrase: Signal<Zeroizing<String>>,
    vault_key: Signal<Option<VaultKey>>,
    selected_identity_id: Signal<Option<String>>,
    network_sender: Signal<mpsc::Sender<AppNetworkEvent>>,
    network_receiver: Signal<Option<mpsc::Receiver<AppNetworkEvent>>>,
    listener: Signal<Option<ListenerHandle>>,
    listener_identity_id: Signal<Option<String>>,
    listener_status: Signal<String>,
    pending_peers: Signal<Vec<PendingPeer>>,
    active_sessions: Signal<HashMap<String, ActiveSession>>,
    connecting_peers: Signal<HashSet<String>>,
    outbound_cancellations: Signal<HashMap<String, watch::Sender<bool>>>,
    selected_conversation_id: Signal<Option<String>>,
    connection_error: Signal<Option<String>>,
    invitation_uri: Signal<Option<String>>,
}

struct ActiveSession {
    handle: SessionHandle,
    conversation_id: String,
    local_identity_id: String,
    remote_identity_id: String,
}

enum AppNetworkEvent {
    Listener(ListenerEvent),
    OutboundReady {
        stream: std::net::TcpStream,
        session: Session,
        local_identity_id: String,
        peer_identity_id: String,
        peer_public_key: Vec<u8>,
        remote_address: String,
    },
    OutboundFailed {
        peer_identity_id: String,
        problem: String,
    },
    Session {
        session_id: String,
        event: SessionEvent,
    },
}

fn main() {
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_window(
                WindowBuilder::new()
                    .with_title("AKRAT")
                    .with_inner_size(LogicalSize::new(1200.0, 800.0))
                    .with_min_inner_size(LogicalSize::new(760.0, 560.0)),
            ),
        )
        .launch(App);
}

#[component]
fn App() -> Element {
    let (network_sender, network_receiver) = mpsc::channel(128);
    let app_state = AppState {
        vault: use_signal(VaultData::default),
        unlocked: use_signal(|| false),
        passphrase: use_signal(|| Zeroizing::new(String::new())),
        vault_key: use_signal(|| None),
        selected_identity_id: use_signal(|| None),
        network_sender: use_signal(|| network_sender),
        network_receiver: use_signal(|| Some(network_receiver)),
        listener: use_signal(|| None),
        listener_identity_id: use_signal(|| None),
        listener_status: use_signal(|| "Arrêtée".to_string()),
        pending_peers: use_signal(Vec::new),
        active_sessions: use_signal(HashMap::new),
        connecting_peers: use_signal(HashSet::new),
        outbound_cancellations: use_signal(HashMap::new),
        selected_conversation_id: use_signal(|| None),
        connection_error: use_signal(|| None),
        invitation_uri: use_signal(|| None),
    };
    use_context_provider(|| app_state);
    let mut network_state = use_context::<AppState>();
    use_future(move || async move {
        let Some(mut receiver) = network_state.network_receiver.write().take() else {
            return;
        };
        while let Some(event) = receiver.recv().await {
            handle_network_event(&mut network_state, event);
        }
    });
    let mut section = use_signal(|| "Identités".to_string());
    let links = ["Identités", "Conversations", "Connexion", "Paramètres"];

    rsx! {
        style { "{STYLE}" }
        main { class: "shell",
            aside { class: "sidebar",
                div { class: "brand",
                    div { class: "brand-mark", "A" }
                    div { class: "brand-copy",
                        strong { "AKRAT" }
                        span { "MESSAGERIE PRIVÉE" }
                    }
                }
                div { class: "workspace-label", "ESPACE LOCAL" }
                nav { class: "navigation",
                    for link in links {
                        button {
                            class: if section() == link { "nav-item selected" } else { "nav-item" },
                            onclick: move |_| section.set(link.to_string()),
                            span { class: "nav-icon", "{icon_for(link)}" }
                            span { "{link}" }
                        }
                    }
                }
                div { class: "sidebar-bottom",
                    div { class: "status-line",
                        span { class: if app_state.listener.read().is_some() || !app_state.active_sessions.read().is_empty() { "status-dot" } else { "status-dot offline" } }
                        span { "{application_status(&app_state)}" }
                    }
                    div { class: "version", "VERSION 0.1.2 · EXPÉRIMENTAL" }
                }
            }
            section { class: "main-panel",
                header { class: "topbar",
                    div { class: "breadcrumb", "AKRAT", span { "/" }, strong { "{section()}" } }
                    div { class: "topbar-right",
                        span { class: "local-badge", "●  STOCKAGE LOCAL" }
                        button { class: "avatar", "U" }
                    }
                }
                div { class: "content",
                    if section() == "Identités" {
                        IdentityView {}
                    } else if section() == "Conversations" {
                        ConversationView {}
                    } else if section() == "Connexion" {
                        ConnectionView {}
                    } else {
                        SettingsView {}
                    }
                }
            }
        }
    }
}

#[component]
fn IdentityView() -> Element {
    let mut app_state = use_context::<AppState>();
    let path = vault_path();
    let mut vault_exists = use_signal(|| path.as_ref().is_ok_and(|value| value.exists()));
    let mut name = use_signal(String::new);
    let mut confirmation = use_signal(|| Zeroizing::new(String::new()));
    let mut error = use_signal(|| None::<String>);

    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "VOTRE ESPACE" }
            h1 { "Identités" }
            p { "Des identités cryptographiques indépendantes, contrôlées localement." }
        }
        if (app_state.unlocked)() {
            div { class: "notice",
                div { class: "notice-symbol", "✓" }
                div {
                    strong { "Coffre déverrouillé" }
                    p { "Les clés privées sont chargées en mémoire. Elles seront effacées de l'état de l'application au verrouillage." }
                }
            }
            div { class: "section-title",
                div { h2 { "Toutes les identités" } p { "Identités stockées dans votre coffre local chiffré." } }
                button {
                    class: "primary-button",
                    onclick: move |_| {
                        let identity = create_identity(format!("Identité {}", app_state.vault.read().identities.len() + 1));
                        match identity {
                            Ok(identity) => {
                                let identity_id = identity.public.id.clone();
                                app_state.vault.write().identities.push(Arc::new(identity));
                                let result = path.as_ref().map_err(|error| error.clone()).and_then(|vault_path| {
                                    persist_vault(vault_path, &app_state.vault.read(), &app_state)
                                        .map_err(|error| error.to_string())
                                });
                                if let Err(message) = result {
                                    app_state.vault.write().identities.pop();
                                    error.set(Some(message));
                                } else {
                                    if app_state.selected_identity_id.read().is_none() {
                                        app_state.selected_identity_id.set(Some(identity_id));
                                    }
                                    error.set(None);
                                }
                            }
                            Err(problem) => error.set(Some(problem.to_string()))
                        }
                    },
                    span { "+" } "Créer une identité"
                }
            }
            div { class: "identity-list",
                for identity in app_state.vault.read().identities.iter() {
                    IdentityCard {
                        identity_id: identity.public.id.clone(),
                        display_name: identity.public.display_name.clone(),
                        fingerprint: identity.public.fingerprint.clone(),
                        public_key: hex_public_key(&identity.public.public_key),
                    }
                }
            }
            button {
                class: "lock-button",
                onclick: move |_| {
                    stop_listener_ui(&mut app_state);
                    for active in app_state.active_sessions.read().values() {
                        let _ = active.handle.close();
                    }
                    for cancellation in app_state.outbound_cancellations.read().values() {
                        let _ = cancellation.send(true);
                    }
                    app_state.outbound_cancellations.write().clear();
                    app_state.active_sessions.write().clear();
                    app_state.pending_peers.write().clear();
                    app_state.connecting_peers.write().clear();
                    app_state.selected_conversation_id.set(None);
                    app_state.vault.set(VaultData::default());
                    app_state.vault_key.set(None);
                    app_state.passphrase.set(Zeroizing::new(String::new()));
                    app_state.selected_identity_id.set(None);
                    app_state.unlocked.set(false);
                },
                "Verrouiller le coffre"
            }
        } else if vault_exists() {
            div { class: "vault-form",
                div { class: "vault-form-heading",
                    div { class: "card-icon", "◇" }
                    h2 { "Déverrouiller le coffre" }
                    p { "Entrez la phrase secrète qui protège vos identités." }
                }
                label { class: "field-label", "PHRASE SECRÈTE" }
                input {
                    class: "text-field",
                    r#type: "password",
                    autocomplete: "current-password",
                    placeholder: "Au moins 12 caractères",
                    oninput: move |event| app_state.passphrase.set(Zeroizing::new(event.value()))
                }
                button {
                    class: "primary-button form-submit",
                    onclick: move |_| {
                        let result = path.as_ref().map_err(|error| error.clone()).and_then(|vault_path| {
                            load_vault_data_with_key(vault_path, app_state.passphrase.read().as_str()).map_err(|error| error.to_string())
                        });
                        match result {
                            Ok((mut records, key)) => {
                                let mut stale_delivery = false;
                                for conversation in &mut records.conversations {
                                    for message in &mut conversation.messages {
                                        if matches!(message.delivery, MessageDelivery::Pending | MessageDelivery::Transmitted) {
                                            message.delivery = MessageDelivery::Unconfirmed;
                                            stale_delivery = true;
                                        }
                                    }
                                }
                                if stale_delivery {
                                    if let Ok(vault_path) = &path {
                                        if let Err(problem) = save_vault_data_with_key(vault_path, &records, &key) {
                                            error.set(Some(format!("L'historique est ouvert, mais l'état de reprise n'a pas pu être enregistré : {problem}")));
                                        }
                                    }
                                }
                                let selected = records
                                    .preferred_identity_id
                                    .clone()
                                    .filter(|preferred| records.identities.iter().any(|identity| identity.public.id == *preferred))
                                    .or_else(|| records.identities.first().map(|identity| identity.public.id.clone()));
                                app_state.selected_identity_id.set(selected.clone());
                                app_state.vault.write().preferred_identity_id = selected;
                                app_state.vault.set(records);
                                app_state.vault_key.set(Some(key));
                                app_state.passphrase.set(Zeroizing::new(String::new()));
                                app_state.unlocked.set(true);
                                error.set(None);
                            }
                            Err(_) => error.set(Some("Impossible d'ouvrir le coffre. Vérifiez la phrase secrète et le fichier.".to_string()))
                        }
                    },
                    "Déverrouiller"
                }
            }
        } else {
            div { class: "vault-form",
                div { class: "vault-form-heading",
                    div { class: "card-icon", "◇" }
                    h2 { "Créer votre coffre local" }
                    p { "Le coffre protège vos identités sur cet appareil. Choisissez une phrase secrète longue et unique." }
                }
                label { class: "field-label", "NOM DE LA PREMIÈRE IDENTITÉ" }
                input {
                    class: "text-field",
                    r#type: "text",
                    placeholder: "Personnel",
                    value: "{name}",
                    oninput: move |event| name.set(event.value())
                }
                label { class: "field-label field-label-spaced", "PHRASE SECRÈTE DU COFFRE" }
                input {
                    class: "text-field",
                    r#type: "password",
                    autocomplete: "new-password",
                    placeholder: "Au moins 12 caractères",
                    oninput: move |event| app_state.passphrase.set(Zeroizing::new(event.value()))
                }
                label { class: "field-label field-label-spaced", "CONFIRMER LA PHRASE SECRÈTE" }
                input {
                    class: "text-field",
                    r#type: "password",
                    autocomplete: "new-password",
                    placeholder: "Saisissez-la à nouveau",
                    oninput: move |event| confirmation.set(Zeroizing::new(event.value()))
                }
                button {
                    class: "primary-button form-submit",
                    onclick: move |_| {
                        if app_state.passphrase.read().len() < 12 {
                            error.set(Some("La phrase secrète doit contenir au moins 12 caractères.".to_string()));
                        } else if app_state.passphrase.read().as_str() != confirmation.read().as_str() {
                            error.set(Some("Les deux phrases secrètes ne correspondent pas.".to_string()));
                        } else if name.read().trim().is_empty() {
                            error.set(Some("Donnez un nom à votre première identité.".to_string()));
                        } else {
                            let result = create_identity(name.read().trim().to_string())
                                .map_err(|problem| problem.to_string())
                                .and_then(|identity| {
                                    let identity_id = identity.public.id.clone();
                                    let records = VaultData {
                                        identities: vec![Arc::new(identity)],
                                        contacts: Vec::new(),
                                        conversations: Vec::new(),
                                        preferred_identity_id: Some(identity_id.clone()),
                                    };
                                    path.as_ref().map_err(|problem| problem.clone()).and_then(|vault_path| {
                                        save_vault_data_and_key(vault_path, &records, app_state.passphrase.read().as_str())
                                            .map(|key| (records, identity_id, key))
                                            .map_err(|problem| problem.to_string())
                                    })
                                });
                            match result {
                                Ok((records, identity_id, key)) => {
                                    app_state.vault.set(records);
                                    app_state.selected_identity_id.set(Some(identity_id));
                                    app_state.vault_key.set(Some(key));
                                    app_state.passphrase.set(Zeroizing::new(String::new()));
                                    vault_exists.set(true);
                                    app_state.unlocked.set(true);
                                    error.set(None);
                                }
                                Err(message) => error.set(Some(message))
                            }
                        }
                    },
                    "Créer le coffre et l'identité"
                }
            }
        }
        if let Some(message) = error() {
            div { class: "error-banner", "{message}" }
        }
        div { class: "security-note",
            span { class: "lock-icon", "◇" }
            span { strong { "Coffre local chiffré" } " · Les sessions réseau restent expérimentales." }
        }
    }
}

#[component]
fn IdentityCard(
    identity_id: String,
    display_name: String,
    fingerprint: String,
    public_key: String,
) -> Element {
    let mut app_state = use_context::<AppState>();
    let selected = app_state.selected_identity_id.read().as_deref() == Some(identity_id.as_str());
    let identity_id_for_click = identity_id.clone();
    let path = vault_path();
    let mut error = use_signal(|| None::<String>);

    rsx! {
        article { class: "identity-card",
            div { class: "identity-card-top",
                div { class: "identity-glyph", "◈" }
                div { class: "identity-copy",
                    strong { "{display_name}" }
                    span { "{identity_id}" }
                }
                button {
                    class: if selected { "active-badge" } else { "select-identity" },
                    onclick: move |_| {
                        let previous = app_state.vault.read().preferred_identity_id.clone();
                        app_state.vault.write().preferred_identity_id = Some(identity_id_for_click.clone());
                        let result = path.as_ref().map_err(|problem| problem.clone()).and_then(|vault_path| {
                            persist_vault(vault_path, &app_state.vault.read(), &app_state)
                                .map_err(|problem| problem.to_string())
                        });
                        match result {
                            Ok(()) => {
                                app_state.selected_identity_id.set(Some(identity_id_for_click.clone()));
                                error.set(None);
                            }
                            Err(problem) => {
                                app_state.vault.write().preferred_identity_id = previous;
                                error.set(Some(problem));
                            }
                        }
                    },
                    if selected { "IDENTITÉ ACTIVE" } else { "Utiliser pour les nouvelles connexions" }
                }
            }
            div { class: "fingerprint-label", "EMPREINTE COMPLÈTE · COMPARER PAR UN CANAL INDÉPENDANT" }
            code { class: "fingerprint", "{fingerprint}" }
            div { class: "identity-key-label", "CLÉ PUBLIQUE ED25519" }
            code { class: "public-key", "{public_key}" }
            if let Some(message) = error() {
                div { class: "error-banner", "{message}" }
            }
        }
    }
}

fn vault_path() -> Result<PathBuf, String> {
    let root = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| "Le répertoire de données local Windows est indisponible.".to_string())?;
    Ok(PathBuf::from(root).join("AKRAT").join("identities.vault"))
}

fn hex_public_key(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn local_route_addresses(port: u16) -> Vec<String> {
    if port == 0 {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0")
        && socket.connect("1.1.1.1:53").is_ok()
        && let Ok(local) = socket.local_addr()
        && !local.ip().is_unspecified()
    {
        addresses.push(std::net::SocketAddr::new(local.ip(), port).to_string());
    }
    if let Ok(socket) = std::net::UdpSocket::bind("[::]:0")
        && socket.connect("[2606:4700:4700::1111]:53").is_ok()
        && let Ok(local) = socket.local_addr()
        && !local.ip().is_unspecified()
        && !local.ip().is_loopback()
    {
        addresses.push(std::net::SocketAddr::new(local.ip(), port).to_string());
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

#[component]
fn ConnectionView() -> Element {
    let mut app_state = use_context::<AppState>();
    let mut invitation_text = use_signal(String::new);
    let mut listen_port = use_signal(|| "49444".to_string());
    let mut advertised_address = use_signal(String::new);
    let mut invitation = use_signal(|| None::<Invitation>);
    let mut error = use_signal(|| None::<String>);

    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "RÉSEAU DIRECT" }
            h1 { "Connexion" }
            p { "Importez une invitation, comparez l'empreinte par un canal indépendant, puis établissez une connexion directe." }
        }
        div { class: "connection-card listener-card",
            div { class: "card-icon", "⌁" }
            h2 { "Écoute entrante · IPv4 et IPv6" }
            p { "L'adresse d'écoute reste locale. Pour des pairs hors réseau local, configurez le pare-feu et redirigez le port sur votre routeur. Le CGNAT peut empêcher les connexions directes." }
            div { class: "setting-row listener-status",
                div { strong { "État" } p { "L'identité sélectionnée au démarrage signe les nouvelles connexions." } }
                span { class: "setting-value quiet", "{(app_state.listener_status)()}" }
            }
            label { class: "field-label", "PORT TCP" }
            input {
                class: "text-field",
                r#type: "number",
                min: "1",
                max: "65535",
                value: "{listen_port}",
                oninput: move |event| listen_port.set(event.value())
            }
            if app_state.listener.read().is_some() {
                button { class: "secondary-button form-submit", onclick: move |_| stop_listener_ui(&mut app_state), "Arrêter l'écoute" }
            } else {
                button {
                    class: "primary-button form-submit",
                    onclick: move |_| {
                        match listen_port.read().parse::<u16>() {
                            Ok(port) if port > 0 => match start_listener_ui(&mut app_state, port) {
                                Ok(()) => { error.set(None); }
                                Err(problem) => error.set(Some(problem)),
                            },
                            _ => error.set(Some("Entrez un port TCP compris entre 1 et 65535.".to_string())),
                        }
                    },
                    "Démarrer l'écoute"
                }
            }
            label { class: "field-label field-label-spaced", "ADRESSE À ANNONCER DANS L'INVITATION" }
            div { class: "address-suggestions",
                for address in local_route_addresses(listen_port.read().parse::<u16>().unwrap_or(0)) {
                    button {
                        class: "address-chip",
                        onclick: move |_| advertised_address.set(address.clone()),
                        "Utiliser {address}"
                    }
                }
                span { "Adresses locales détectées. Pour Internet, entrez l'IP publique avec redirection TCP du port." }
            }
            input {
                class: "text-field",
                placeholder: "Ex. 192.168.1.25:49444 ou votre IP publique redirigée",
                value: "{advertised_address}",
                oninput: move |event| advertised_address.set(event.value())
            }
            button {
                class: "secondary-button form-submit",
                disabled: app_state.listener.read().is_none(),
                onclick: move |_| {
                    match make_invitation(&app_state, advertised_address.read().as_str()) {
                        Ok(uri) => { app_state.invitation_uri.set(Some(uri)); error.set(None); }
                        Err(problem) => error.set(Some(problem)),
                    }
                },
                "Créer mon invitation"
            }
            if let Some(uri) = (app_state.invitation_uri)() {
                textarea { class: "text-field invitation-input", readonly: true, value: "{uri}" }
                button {
                    class: "secondary-button form-submit",
                    onclick: move |_| {
                        match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(uri.clone())) {
                            Ok(()) => error.set(None),
                            Err(problem) => error.set(Some(format!("Impossible de copier l'invitation : {problem}"))),
                        }
                    },
                    "Copier l'invitation"
                }
            }
        }
        div { class: "connection-card",
            div { class: "card-icon", "↔" }
            h2 { "Importer une invitation AKRAT" }
            p { "Une invitation fournit une adresse et une clé publique. Elle ne prouve pas à elle seule l'identité de la personne." }
            textarea {
                class: "text-field invitation-input",
                placeholder: "akrat://v1/…",
                value: "{invitation_text}",
                oninput: move |event| invitation_text.set(event.value())
            }
            button {
                class: "primary-button",
                onclick: move |_| {
                    match Invitation::from_uri(invitation_text.read().as_str()) {
                        Ok(parsed) => {
                            invitation.set(Some(parsed));
                            error.set(None);
                        }
                        Err(problem) => {
                            invitation.set(None);
                            error.set(Some(format!("Invitation invalide : {problem}")));
                        }
                    }
                },
                "Valider l'invitation"
            }
            if let Some(parsed) = invitation() {
                InvitationContactForm { invitation: parsed }
            }
        }
        if (app_state.unlocked)() && !app_state.vault.read().contacts.is_empty() {
            div { class: "section-title",
                div { h2 { "Contacts" } p { "La confiance est conservée dans votre coffre local." } }
            }
            div { class: "contact-list",
                for contact in &app_state.vault.read().contacts {
                    ContactCard { contact: contact.clone() }
                }
            }
        }
        if !app_state.pending_peers.read().is_empty() {
            div { class: "section-title", div { h2 { "Demandes entrantes" } p { "Comparez chaque empreinte avant d'ouvrir le canal de messagerie." } } }
            div { class: "contact-list",
                for (index, peer) in app_state.pending_peers.read().iter().enumerate() {
                    if let Ok(key) = <[u8; 32]>::try_from(peer.peer_public_key.as_slice()) {
                        PendingPeerCard {
                            index,
                            identity_id: peer.peer_identity_id.clone(),
                            public_key: key,
                            remote_address: peer.remote_address.to_string(),
                        }
                    }
                }
            }
        }
        if !app_state.active_sessions.read().is_empty() {
            div { class: "section-title", div { h2 { "Sessions actives" } p { "Canaux chiffrés; l'état de confiance reste lié au contact." } } }
            div { class: "contact-list",
                for (session_id, active) in app_state.active_sessions.read().iter() {
                    button {
                        class: "contact-card active-session-card",
                        onclick: { let conversation_id = active.conversation_id.clone(); move |_| app_state.selected_conversation_id.set(Some(conversation_id.clone())) },
                        strong { "{active.remote_identity_id}" }
                        code { class: "public-key", "Session {session_id}" }
                        span { class: "active-badge", "CANAL CHIFFRÉ ACTIF" }
                    }
                }
            }
        }
        if !(app_state.unlocked)() {
            div { class: "notice", "Déverrouillez le coffre pour enregistrer des contacts." }
        }
        if let Some(message) = error() {
            div { class: "error-banner", "{message}" }
        }
        if let Some(message) = (app_state.connection_error)() {
            div { class: "error-banner", "{message}" }
        }
    }
}

#[component]
fn ContactCard(contact: Contact) -> Element {
    let mut app_state = use_context::<AppState>();
    let mut manual_address = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let verified = contact.trust == IdentityTrust::ManuallyVerified && !contact.blocked;
    let has_address = !contact.addresses.is_empty();
    let address_contact = contact.clone();
    let mut address_state = app_state;

    rsx! {
        article { class: "contact-card",
            strong { "{contact.display_name}" }
            code { class: "public-key", "{contact.id}" }
            code { class: "fingerprint", "{contact.fingerprint}" }
            span { class: if verified { "active-badge" } else { "setting-value pending" },
                if contact.blocked { "BLOQUÉ" } else if verified { "VÉRIFIÉ MANUELLEMENT" } else { "CONNU · NON VÉRIFIÉ" }
            }
            if has_address {
                for address in &contact.addresses {
                    code { class: "public-key", "{address}" }
                }
            }
            label { class: "field-label field-label-spaced", "AJOUTER UNE ADRESSE IP:PORT" }
            div { class: "address-entry",
                input {
                    class: "text-field",
                    placeholder: "192.168.1.20:49444 ou [2001:db8::1]:49444",
                    value: "{manual_address}",
                    oninput: move |event| manual_address.set(event.value())
                }
                button {
                    class: "secondary-button",
                    onclick: move |_| {
                        let address = manual_address.read().clone();
                        match save_contact_address(&mut address_state, &address_contact, &address) {
                            Ok(()) => { manual_address.set(String::new()); error.set(None); }
                            Err(problem) => error.set(Some(problem)),
                        }
                    },
                    "Enregistrer"
                }
            }
            button {
                class: "primary-button form-submit",
                disabled: !verified || !has_address || app_state.connecting_peers.read().contains(&contact.id),
                onclick: move |_| {
                    if let Err(problem) = start_outbound_connection(&mut app_state, contact.clone()) {
                        error.set(Some(problem));
                    } else {
                        error.set(None);
                    }
                },
                if app_state.connecting_peers.read().contains(&contact.id) { "Connexion en cours…" } else if verified && has_address { "Se connecter" } else { "Vérification ou adresse requise" }
            }
            if let Some(message) = error() {
                div { class: "error-banner", "{message}" }
            }
        }
    }
}

fn save_contact_address(
    app_state: &mut AppState,
    contact: &Contact,
    value: &str,
) -> Result<(), String> {
    if !(app_state.unlocked)() {
        return Err("Déverrouillez le coffre pour modifier le contact.".to_string());
    }
    let address = value
        .trim()
        .parse::<std::net::SocketAddr>()
        .map_err(|_| "Entrez une adresse IP suivie du port TCP.".to_string())?;
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err("Cette adresse ou ce port ne peut pas être utilisé.".to_string());
    }
    let before = app_state.vault.read().contacts.clone();
    let mut vault = app_state.vault.write();
    let Some(stored) = vault
        .contacts
        .iter_mut()
        .find(|stored| stored.id == contact.id)
    else {
        return Err("Le contact n'existe plus dans le coffre.".to_string());
    };
    if !stored.addresses.contains(&address.to_string()) {
        if stored.addresses.len() >= 8 {
            return Err("La limite de huit adresses par contact est atteinte.".to_string());
        }
        stored.addresses.push(address.to_string());
        stored.addresses.sort();
    }
    drop(vault);
    if let Err(problem) = save_current_vault(app_state) {
        app_state.vault.write().contacts = before;
        return Err(problem);
    }
    Ok(())
}

#[component]
fn PendingPeerCard(
    index: usize,
    identity_id: String,
    public_key: [u8; 32],
    remote_address: String,
) -> Element {
    let mut app_state = use_context::<AppState>();
    let mut fingerprint = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let expected = fingerprint_for(&public_key);
    let public_key_hex = hex_public_key(&public_key);

    rsx! {
        article { class: "contact-card pending-peer-card",
            strong { "Nouvelle identité · {remote_address}" }
            code { class: "public-key", "{identity_id}" }
            code { class: "public-key", "{public_key_hex}" }
            div { class: "fingerprint-label", "EMPREINTE COMPLÈTE · COMPARER HORS BANDE" }
            code { class: "fingerprint", "{expected}" }
            input {
                class: "text-field",
                placeholder: "Saisissez l'empreinte vérifiée auprès du correspondant",
                value: "{fingerprint}",
                oninput: move |event| fingerprint.set(event.value())
            }
            button {
                class: "primary-button form-submit",
                disabled: fingerprint.read().trim().to_ascii_uppercase() != expected,
                onclick: move |_| match approve_pending_peer(&mut app_state, index, fingerprint.read().as_str()) {
                    Ok(()) => error.set(None),
                    Err(problem) => error.set(Some(problem)),
                },
                "Confirmer l'identité et ouvrir la conversation"
            }
            if let Some(message) = error() {
                div { class: "error-banner", "{message}" }
            }
        }
    }
}

#[component]
fn ConversationView() -> Element {
    let app_state = use_context::<AppState>();
    let mut search = use_signal(String::new);
    let conversations = app_state.vault.read().conversations.clone();
    let contacts = app_state.vault.read().contacts.clone();
    let selected_id = app_state.selected_conversation_id.read().clone();
    let selected = conversations
        .iter()
        .find(|conversation| Some(&conversation.id) == selected_id.as_ref())
        .cloned();

    rsx! {
        div { class: "page-heading compact-heading",
            div { class: "eyebrow", "MESSAGERIE PRIVÉE" }
            h1 { "Conversations" }
            p { "Chaque historique appartient à une paire précise d'identités locale et distante." }
        }
        if !(app_state.unlocked)() {
            EmptyView { title: "Coffre verrouillé", detail: "Déverrouillez le coffre pour consulter les conversations locales." }
        } else if conversations.is_empty() {
            EmptyView { title: "Aucune conversation", detail: "Ajoutez un contact vérifié et établissez une session depuis l'écran Connexion." }
        } else {
            div { class: "conversation-layout",
                aside { class: "conversation-sidebar",
                    input {
                        class: "text-field search-field",
                        placeholder: "Rechercher dans les conversations",
                        value: "{search}",
                        oninput: move |event| search.set(event.value())
                    }
                    for conversation in conversations.iter().filter(|conversation| {
                        let term = search.read().to_lowercase();
                        term.is_empty()
                            || contact_display_name(&contacts, &conversation.remote_identity_id)
                                .to_lowercase()
                                .contains(&term)
                    }) {
                        ConversationListRow {
                            conversation_id: conversation.id.clone(),
                            display_name: contact_display_name(&contacts, &conversation.remote_identity_id),
                            identity_id: conversation.local_identity_id.clone(),
                            selected: Some(&conversation.id) == selected_id.as_ref(),
                        }
                    }
                }
                if let Some(conversation) = selected {
                    ConversationPanel { conversation, contacts }
                }
            }
        }
    }
}

#[component]
fn ConversationPanel(conversation: Conversation, contacts: Vec<Contact>) -> Element {
    let mut app_state = use_context::<AppState>();
    let mut search = use_signal(String::new);
    let mut draft = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut confirm_delete = use_signal(|| false);
    let contact_name = contact_display_name(&contacts, &conversation.remote_identity_id);
    let contact_trust = contacts
        .iter()
        .find(|contact| contact.id == conversation.remote_identity_id)
        .map(|contact| contact.trust.clone());
    let local_name = app_state
        .vault
        .read()
        .identities
        .iter()
        .find(|identity| identity.public.id == conversation.local_identity_id)
        .map(|identity| identity.public.display_name.clone())
        .unwrap_or_else(|| "Identité archivée".to_string());
    let active = app_state
        .active_sessions
        .read()
        .values()
        .any(|session| session.conversation_id == conversation.id);
    let conversation_id = conversation.id.clone();
    let conversation_id_for_delete = conversation.id.clone();

    rsx! {
        main { class: "chat-panel",
            header { class: "chat-header",
                div {
                    strong { "{contact_name}" }
                    span { "Depuis : {local_name}" }
                }
                div { class: "chat-security",
                    span { class: if active { "status-dot" } else { "status-dot offline" } }
                    span { if active { "Session chiffrée active" } else { "Hors ligne · historique local" } }
                    if let Some(trust) = contact_trust {
                        span { class: if trust == IdentityTrust::ManuallyVerified { "trust-verified" } else { "trust-unverified" },
                            if trust == IdentityTrust::ManuallyVerified { "Identité vérifiée manuellement" } else { "Identité non vérifiée" }
                        }
                    }
                }
            }
            div { class: "chat-toolbar",
                input {
                    class: "text-field search-field",
                    placeholder: "Filtrer les messages",
                    value: "{search}",
                    oninput: move |event| search.set(event.value())
                }
                if confirm_delete() {
                    button {
                        class: "danger-button",
                        onclick: move |_| match delete_local_conversation(&mut app_state, &conversation_id_for_delete) {
                            Ok(()) => { confirm_delete.set(false); error.set(None); }
                            Err(problem) => error.set(Some(problem)),
                        },
                        "Confirmer la suppression"
                    }
                    button { class: "secondary-button", onclick: move |_| confirm_delete.set(false), "Annuler" }
                } else {
                    button { class: "secondary-button", onclick: move |_| confirm_delete.set(true), "Supprimer l'historique" }
                }
            }
            div { class: "message-list",
                for message in conversation.messages.iter().filter(|message| search.read().trim().is_empty() || message.text.to_lowercase().contains(&search.read().to_lowercase())) {
                    MessageBubble { message: message.clone(), conversation_id: conversation.id.clone() }
                }
            }
            if !active {
                div { class: "offline-note", "Aucune session active. Revenez à Connexion pour rétablir le canal avec une nouvelle négociation de clés." }
            }
            div { class: "message-composer",
                textarea {
                    class: "text-field composer-input",
                    placeholder: if active { "Écrivez un message…" } else { "Connectez-vous avant d'envoyer un message" },
                    disabled: !active,
                    value: "{draft}",
                    oninput: move |event| draft.set(event.value())
                }
                button {
                    class: "primary-button",
                    disabled: !active || draft.read().trim().is_empty(),
                    onclick: move |_| {
                        let text = draft.read().clone();
                        match send_message_to_conversation(&mut app_state, &conversation_id, text) {
                            Ok(()) => { draft.set(String::new()); error.set(None); }
                            Err(problem) => error.set(Some(problem)),
                        }
                    },
                    "Envoyer"
                }
            }
            if let Some(message) = error() {
                div { class: "error-banner", "{message}" }
            }
        }
    }
}

fn contact_display_name(contacts: &[Contact], identity_id: &str) -> String {
    contacts
        .iter()
        .find(|contact| contact.id == identity_id)
        .map(|contact| contact.display_name.clone())
        .unwrap_or_else(|| "Contact inconnu".to_string())
}

#[component]
fn ConversationListRow(
    conversation_id: String,
    display_name: String,
    identity_id: String,
    selected: bool,
) -> Element {
    let mut app_state = use_context::<AppState>();
    rsx! {
        button {
            class: if selected { "conversation-row selected" } else { "conversation-row" },
            onclick: move |_| app_state.selected_conversation_id.set(Some(conversation_id.clone())),
            strong { "{display_name}" }
            span { "Identité locale · {&identity_id[..8.min(identity_id.len())]}" }
        }
    }
}

#[component]
fn MessageBubble(message: StoredMessage, conversation_id: String) -> Element {
    let mut app_state = use_context::<AppState>();
    let outgoing = message.direction == MessageDirection::Outgoing;
    let retryable = outgoing
        && matches!(
            message.delivery,
            MessageDelivery::Failed | MessageDelivery::Unconfirmed | MessageDelivery::Transmitted
        );
    let message_id = message.id.clone();
    rsx! {
        article { class: if outgoing { "message-bubble outgoing" } else { "message-bubble incoming" },
            p { "{message.text}" }
            span { "{message_status(&message.delivery)} · {message.sent_at_unix}" }
            if retryable {
                button {
                    class: "retry-button",
                    onclick: move |_| {
                        if let Err(problem) = retry_message(&mut app_state, &conversation_id, &message_id) {
                            app_state.connection_error.set(Some(problem));
                        }
                    },
                    "Renvoyer"
                }
            }
        }
    }
}

fn message_status(delivery: &MessageDelivery) -> &'static str {
    match delivery {
        MessageDelivery::Pending => "En cours d'envoi",
        MessageDelivery::Transmitted => "Transmis · en attente de confirmation",
        MessageDelivery::Acknowledged => "Reçu et confirmé par le pair",
        MessageDelivery::Received => "Reçu et authentifié",
        MessageDelivery::Failed => "Échec d'envoi",
        MessageDelivery::Unconfirmed => "Livraison non confirmée · renvoi possible",
    }
}

fn make_invitation(app_state: &AppState, address: &str) -> Result<String, String> {
    if app_state.listener.read().is_none()
        || !(app_state.listener_status)().starts_with("À l'écoute sur")
    {
        return Err(
            "Attendez que l'écoute confirme son démarrage avant de créer une invitation."
                .to_string(),
        );
    }
    let identity_id = app_state
        .listener_identity_id
        .read()
        .clone()
        .ok_or_else(|| "L'identité d'écoute n'est plus disponible.".to_string())?;
    let identity = app_state
        .vault
        .read()
        .identities
        .iter()
        .find(|identity| identity.public.id == identity_id)
        .cloned()
        .ok_or_else(|| "L'identité d'écoute n'existe plus dans le coffre.".to_string())?;
    let address = address
        .trim()
        .parse::<std::net::SocketAddr>()
        .map_err(|_| {
            "Indiquez une adresse IP et un port, par exemple 192.168.1.25:49444.".to_string()
        })?;
    let public_key: [u8; 32] = identity
        .public
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| "La clé publique locale est invalide.".to_string())?;
    Invitation::new(vec![address], public_key)
        .and_then(|invitation| invitation.to_uri())
        .map_err(|problem| problem.to_string())
}

#[component]
fn InvitationContactForm(invitation: Invitation) -> Element {
    let mut app_state = use_context::<AppState>();
    let mut fingerprint_text = use_signal(String::new);
    let mut contact_name = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut notice = use_signal(|| None::<String>);
    let path = vault_path();
    let unverified_path = path.clone();
    let verified_path = path.clone();
    let expected_fingerprint = fingerprint_for(&invitation.public_key);
    let verified_fingerprint = expected_fingerprint.clone();
    let unverified_invitation = invitation.clone();
    let verified_invitation = invitation.clone();

    rsx! {
        div { class: "invitation-preview",
            div { class: "fingerprint-label", "IDENTITÉ DISTANTE" }
            code { class: "public-key", "{invitation.identity_id}" }
            div { class: "fingerprint-label", "EMPREINTE À COMPARER HORS BANDE" }
            code { class: "fingerprint", "{expected_fingerprint}" }
            div { class: "fingerprint-label", "ADRESSES DE CONNEXION" }
            for address in &invitation.addresses {
                code { class: "public-key", "{address}" }
            }
            label { class: "field-label field-label-spaced", "NOM LOCAL DU CONTACT" }
            input {
                class: "text-field",
                placeholder: "Nom affiché sur cet appareil",
                value: "{contact_name}",
                oninput: move |event| contact_name.set(event.value())
            }
            label { class: "field-label field-label-spaced", "EMPREINTE COMPARÉE PAR UN CANAL INDÉPENDANT" }
            input {
                class: "text-field",
                placeholder: "Saisissez l'empreinte affichée par le correspondant",
                value: "{fingerprint_text}",
                oninput: move |event| fingerprint_text.set(event.value())
            }
            div { class: "button-row",
                button {
                    class: "secondary-button",
                    onclick: move |_| {
                        match import_contact(&mut app_state, &unverified_path, unverified_invitation.clone(), contact_name.read().clone(), false) {
                            Ok(()) => { notice.set(Some("Contact ajouté comme connu, non vérifié.".to_string())); error.set(None); }
                            Err(problem) => error.set(Some(problem))
                        }
                    },
                    "Ajouter sans vérification"
                }
                button {
                    class: "primary-button",
                    disabled: fingerprint_text.read().trim().to_ascii_uppercase() != expected_fingerprint,
                    onclick: move |_| {
                        if fingerprint_text.read().trim().eq_ignore_ascii_case(&verified_fingerprint) {
                            match import_contact(&mut app_state, &verified_path, verified_invitation.clone(), contact_name.read().clone(), true) {
                                Ok(()) => { notice.set(Some("Empreinte comparée et contact marqué vérifié.".to_string())); error.set(None); }
                                Err(problem) => error.set(Some(problem))
                            }
                        } else {
                            error.set(Some("L'empreinte saisie ne correspond pas.".to_string()));
                        }
                    },
                    "J'ai comparé : marquer vérifié"
                }
            }
            if let Some(message) = notice() {
                div { class: "notice", "{message}" }
            }
            if let Some(message) = error() {
                div { class: "error-banner", "{message}" }
            }
        }
    }
}

fn import_contact(
    app_state: &mut AppState,
    path: &Result<PathBuf, String>,
    invitation: Invitation,
    display_name: String,
    manually_verified: bool,
) -> Result<(), String> {
    if !(app_state.unlocked)() {
        return Err("Déverrouillez d'abord votre coffre.".to_string());
    }
    let previous = app_state.vault.read().contacts.clone();
    let now = unix_time();
    {
        let mut vault = app_state.vault.write();
        if let Some(contact) = vault
            .contacts
            .iter_mut()
            .find(|contact| contact.id == invitation.identity_id)
        {
            if contact.public_key != invitation.public_key {
                return Err("La clé de cette identité a changé. L'ancien contact est conservé et la connexion est bloquée.".to_string());
            }
            contact.addresses = invitation
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect();
            if !display_name.trim().is_empty() {
                contact.display_name = display_name.trim().to_string();
            }
            if manually_verified {
                contact.trust = IdentityTrust::ManuallyVerified;
            }
        } else {
            vault.contacts.push(Contact {
                id: invitation.identity_id,
                display_name: if display_name.trim().is_empty() {
                    "Contact".to_string()
                } else {
                    display_name.trim().to_string()
                },
                public_key: invitation.public_key.to_vec(),
                fingerprint: fingerprint_for(&invitation.public_key),
                addresses: invitation
                    .addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                trust: if manually_verified {
                    IdentityTrust::ManuallyVerified
                } else {
                    IdentityTrust::KnownUnverified
                },
                blocked: false,
                created_at_unix: now,
                last_seen_at_unix: None,
            });
        }
    }
    let result = path
        .as_ref()
        .map_err(|problem| problem.clone())
        .and_then(|vault_path| {
            persist_vault(vault_path, &app_state.vault.read(), app_state)
                .map_err(|problem| problem.to_string())
        });
    if let Err(problem) = result {
        app_state.vault.write().contacts = previous;
        return Err(problem);
    }
    Ok(())
}

fn handle_network_event(app_state: &mut AppState, event: AppNetworkEvent) {
    match event {
        AppNetworkEvent::Listener(ListenerEvent::Bound(address)) => {
            app_state
                .listener_status
                .set(format!("À l'écoute sur {address}"));
        }
        AppNetworkEvent::Listener(ListenerEvent::Pending(peer)) => {
            if (app_state.unlocked)()
                && app_state.listener.read().is_some()
                && app_state.pending_peers.read().len() < 16
            {
                app_state.pending_peers.write().push(*peer);
            }
        }
        AppNetworkEvent::Listener(ListenerEvent::Failed(problem)) => {
            let readable = readable_network_problem(&problem);
            if (app_state.listener_status)().starts_with("Démarrage") {
                app_state.listener.write().take();
                app_state.listener_identity_id.set(None);
                app_state
                    .listener_status
                    .set(format!("Échec de l'écoute : {readable}"));
            }
            app_state.connection_error.set(Some(readable));
        }
        AppNetworkEvent::Listener(ListenerEvent::Rejected(problem)) => {
            app_state.connection_error.set(Some(format!(
                "Connexion entrante rejetée avant authentification : {problem}"
            )));
        }
        AppNetworkEvent::Listener(ListenerEvent::Stopped) => {
            app_state.listener_status.set("Arrêtée".to_string());
        }
        AppNetworkEvent::OutboundReady {
            stream,
            session,
            local_identity_id,
            peer_identity_id,
            peer_public_key,
            remote_address,
        } => {
            app_state.connecting_peers.write().remove(&peer_identity_id);
            app_state
                .outbound_cancellations
                .write()
                .remove(&peer_identity_id);
            let result = activate_connection(
                app_state,
                stream,
                session,
                &local_identity_id,
                &peer_identity_id,
                &peer_public_key,
                &remote_address,
            );
            if let Err(problem) = result {
                app_state.connection_error.set(Some(problem));
            }
        }
        AppNetworkEvent::OutboundFailed {
            peer_identity_id,
            problem,
        } => {
            app_state.connecting_peers.write().remove(&peer_identity_id);
            app_state
                .outbound_cancellations
                .write()
                .remove(&peer_identity_id);
            app_state
                .connection_error
                .set(Some(readable_network_problem(&problem)));
        }
        AppNetworkEvent::Session { session_id, event } => {
            handle_session_event(app_state, session_id, event);
        }
    }
}

fn readable_network_problem(problem: &str) -> String {
    let normalized = problem.to_ascii_lowercase();
    if normalized.contains("protocol version or cryptographic suite is unsupported") {
        "Le correspondant utilise une version incompatible du protocole. Mettez AKRAT à jour des deux côtés, puis reconnectez le contact déjà vérifié; les historiques locaux restent disponibles.".to_string()
    } else if normalized.contains("10048") || normalized.contains("address already in use") {
        "Ce port TCP est déjà utilisé. Choisissez un autre port ou arrêtez le service qui l'occupe."
            .to_string()
    } else if normalized.contains("10013")
        || normalized.contains("permission denied")
        || normalized.contains("access is denied")
    {
        "Windows ou le pare-feu bloque cette opération réseau. Vérifiez les règles d'accès pour AKRAT.".to_string()
    } else if normalized.contains("10061") || normalized.contains("actively refused") {
        "La connexion a été refusée. Vérifiez que le correspondant écoute sur ce port et que le pare-feu l'autorise.".to_string()
    } else if normalized.contains("10060")
        || normalized.contains("timed out")
        || normalized.contains("timeout")
    {
        "La connexion a expiré. Vérifiez l'adresse, le port, le pare-feu et la redirection du routeur; le CGNAT peut empêcher l'accès direct.".to_string()
    } else if normalized.contains("10051")
        || normalized.contains("10065")
        || normalized.contains("network is unreachable")
        || normalized.contains("no route")
    {
        "Aucune route réseau n'est disponible vers cette adresse. Vérifiez votre connexion et l'adresse du correspondant.".to_string()
    } else {
        problem.to_string()
    }
}

fn handle_session_event(app_state: &mut AppState, session_id: String, event: SessionEvent) {
    let active = app_state
        .active_sessions
        .read()
        .get(&session_id)
        .map(|active| {
            (
                active.handle.clone(),
                active.conversation_id.clone(),
                active.local_identity_id.clone(),
                active.remote_identity_id.clone(),
            )
        });
    let Some((handle, conversation_id, local_identity_id, remote_identity_id)) = active else {
        return;
    };
    match event {
        SessionEvent::Received { message_id, text } => {
            let message = StoredMessage {
                id: message_id.clone(),
                sender_identity_id: remote_identity_id,
                sent_at_unix: unix_time(),
                direction: MessageDirection::Incoming,
                delivery: MessageDelivery::Received,
                text,
            };
            let appended = {
                let mut vault = app_state.vault.write();
                append_message(&mut vault, &conversation_id, message)
            };
            let result = appended
                .map_err(|problem| problem.to_string())
                .and_then(|_| save_current_vault(app_state));
            match result {
                Ok(()) => {
                    if let Err(problem) = handle.confirm_received(message_id) {
                        app_state.connection_error.set(Some(problem.to_string()));
                    }
                }
                Err(problem) => app_state.connection_error.set(Some(problem)),
            }
        }
        SessionEvent::Transmitted { message_id } => {
            update_message_delivery(
                app_state,
                &conversation_id,
                &message_id,
                MessageDelivery::Transmitted,
            );
        }
        SessionEvent::Acknowledged { message_id } => {
            update_message_delivery(
                app_state,
                &conversation_id,
                &message_id,
                MessageDelivery::Acknowledged,
            );
        }
        SessionEvent::Closed => {
            mark_session_messages_uncertain(app_state, &conversation_id);
            app_state.active_sessions.write().remove(&session_id);
        }
        SessionEvent::Failed(problem) => {
            mark_session_messages_uncertain(app_state, &conversation_id);
            app_state.active_sessions.write().remove(&session_id);
            app_state.connection_error.set(Some(problem));
        }
    }
    let _ = local_identity_id;
}

fn mark_session_messages_uncertain(app_state: &mut AppState, conversation_id: &str) {
    let mut changed = false;
    if let Some(conversation) = app_state
        .vault
        .write()
        .conversations
        .iter_mut()
        .find(|conversation| conversation.id == conversation_id)
    {
        for message in &mut conversation.messages {
            if message.direction == MessageDirection::Outgoing
                && matches!(
                    message.delivery,
                    MessageDelivery::Pending | MessageDelivery::Transmitted
                )
            {
                message.delivery = MessageDelivery::Unconfirmed;
                changed = true;
            }
        }
    }
    if changed && let Err(problem) = save_current_vault(app_state) {
        app_state.connection_error.set(Some(problem));
    }
}

fn update_message_delivery(
    app_state: &mut AppState,
    conversation_id: &str,
    message_id: &str,
    delivery: MessageDelivery,
) {
    let mut found = false;
    if let Some(conversation) = app_state
        .vault
        .write()
        .conversations
        .iter_mut()
        .find(|conversation| conversation.id == conversation_id)
    {
        if let Some(message) = conversation
            .messages
            .iter_mut()
            .find(|message| message.id == message_id)
        {
            message.delivery = delivery;
            found = true;
        }
    }
    if found && let Err(problem) = save_current_vault(app_state) {
        app_state.connection_error.set(Some(problem));
    }
}

fn save_current_vault(app_state: &AppState) -> Result<(), String> {
    let path = vault_path()?;
    persist_vault(&path, &app_state.vault.read(), app_state).map_err(|problem| problem.to_string())
}

fn persist_vault(
    path: &std::path::Path,
    data: &VaultData,
    app_state: &AppState,
) -> Result<(), akrat_storage::VaultError> {
    let key = app_state
        .vault_key
        .read()
        .clone()
        .ok_or(akrat_storage::VaultError::SessionKeyUnavailable)?;
    save_vault_data_with_key(path, data, &key)
}

fn send_message_to_conversation(
    app_state: &mut AppState,
    conversation_id: &str,
    text: String,
) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("Saisissez un message avant l'envoi.".to_string());
    }
    if text.len() > MAX_SESSION_TEXT_SIZE {
        return Err("Le message dépasse la limite expérimentale de 10 Kio.".to_string());
    }
    let active = app_state
        .active_sessions
        .read()
        .iter()
        .find(|(_, active)| active.conversation_id == conversation_id)
        .map(|(session_id, active)| (session_id.clone(), active.handle.clone()));
    let Some((_, handle)) = active else {
        return Err("Aucune session active pour cette conversation.".to_string());
    };
    let (local_identity_id, remote_identity_id) = app_state
        .vault
        .read()
        .conversations
        .iter()
        .find(|conversation| conversation.id == conversation_id)
        .map(|conversation| {
            (
                conversation.local_identity_id.clone(),
                conversation.remote_identity_id.clone(),
            )
        })
        .ok_or_else(|| "La conversation n'existe plus.".to_string())?;
    let message_id = new_id()?;
    let message = StoredMessage {
        id: message_id.clone(),
        sender_identity_id: local_identity_id,
        sent_at_unix: unix_time(),
        direction: MessageDirection::Outgoing,
        delivery: MessageDelivery::Pending,
        text: text.clone(),
    };
    let appended = {
        let mut vault = app_state.vault.write();
        append_message(&mut vault, conversation_id, message)
    }
    .map_err(|problem| problem.to_string())?;
    if !appended {
        return Err("Un identifiant de message existe déjà.".to_string());
    }
    if let Err(problem) = save_current_vault(app_state) {
        app_state
            .vault
            .write()
            .conversations
            .iter_mut()
            .find(|conversation| conversation.id == conversation_id)
            .map(|conversation| conversation.messages.pop());
        return Err(problem);
    }
    if let Err(problem) = handle.send_text(message_id.clone(), text) {
        if let Some(message) = app_state
            .vault
            .write()
            .conversations
            .iter_mut()
            .find(|conversation| conversation.id == conversation_id)
            .and_then(|conversation| {
                conversation
                    .messages
                    .iter_mut()
                    .find(|message| message.id == message_id)
            })
        {
            message.delivery = MessageDelivery::Failed;
        }
        let _ = save_current_vault(app_state);
        return Err(problem.to_string());
    }
    let _ = remote_identity_id;
    Ok(())
}

fn retry_message(
    app_state: &mut AppState,
    conversation_id: &str,
    message_id: &str,
) -> Result<(), String> {
    let (text, delivery) = app_state
        .vault
        .read()
        .conversations
        .iter()
        .find(|conversation| conversation.id == conversation_id)
        .and_then(|conversation| {
            conversation
                .messages
                .iter()
                .find(|message| message.id == message_id)
                .map(|message| (message.text.clone(), message.delivery.clone()))
        })
        .ok_or_else(|| "Le message à renvoyer n'existe plus.".to_string())?;
    if !matches!(
        &delivery,
        MessageDelivery::Failed | MessageDelivery::Unconfirmed | MessageDelivery::Transmitted
    ) {
        return Err("Ce message ne peut pas être renvoyé dans son état actuel.".to_string());
    }
    let handle = app_state
        .active_sessions
        .read()
        .values()
        .find(|active| active.conversation_id == conversation_id)
        .map(|active| active.handle.clone())
        .ok_or_else(|| "Reconnectez-vous à ce contact avant de renvoyer le message.".to_string())?;
    if let Some(message) = app_state
        .vault
        .write()
        .conversations
        .iter_mut()
        .find(|conversation| conversation.id == conversation_id)
        .and_then(|conversation| {
            conversation
                .messages
                .iter_mut()
                .find(|message| message.id == message_id)
        })
    {
        message.delivery = MessageDelivery::Pending;
    }
    if let Err(problem) = save_current_vault(app_state) {
        if let Some(message) = app_state
            .vault
            .write()
            .conversations
            .iter_mut()
            .find(|conversation| conversation.id == conversation_id)
            .and_then(|conversation| {
                conversation
                    .messages
                    .iter_mut()
                    .find(|message| message.id == message_id)
            })
        {
            message.delivery = delivery;
        }
        return Err(problem);
    }
    if let Err(problem) = handle.send_text(message_id.to_string(), text) {
        if let Some(message) = app_state
            .vault
            .write()
            .conversations
            .iter_mut()
            .find(|conversation| conversation.id == conversation_id)
            .and_then(|conversation| {
                conversation
                    .messages
                    .iter_mut()
                    .find(|message| message.id == message_id)
            })
        {
            message.delivery = MessageDelivery::Failed;
        }
        let _ = save_current_vault(app_state);
        return Err(problem.to_string());
    }
    Ok(())
}

fn delete_local_conversation(
    app_state: &mut AppState,
    conversation_id: &str,
) -> Result<(), String> {
    let old_conversations = app_state.vault.read().conversations.clone();
    if !remove_conversation(&mut app_state.vault.write(), conversation_id) {
        return Err("La conversation n'existe plus.".to_string());
    }
    if let Err(problem) = save_current_vault(app_state) {
        app_state.vault.write().conversations = old_conversations;
        return Err(problem);
    }
    let session_ids: Vec<_> = app_state
        .active_sessions
        .read()
        .iter()
        .filter(|(_, active)| active.conversation_id == conversation_id)
        .map(|(session_id, active)| (session_id.clone(), active.handle.clone()))
        .collect();
    for (session_id, handle) in session_ids {
        let _ = handle.close();
        app_state.active_sessions.write().remove(&session_id);
    }
    app_state.selected_conversation_id.set(None);
    Ok(())
}

fn activate_connection(
    app_state: &mut AppState,
    stream: std::net::TcpStream,
    session: Session,
    local_identity_id: &str,
    peer_identity_id: &str,
    peer_public_key: &[u8],
    remote_address: &str,
) -> Result<(), String> {
    let session_id = hex::encode(session.session_id());
    let backup_conversations = app_state.vault.read().conversations.clone();
    let backup_contacts = app_state.vault.read().contacts.clone();
    let conversation_id = {
        let mut vault = app_state.vault.write();
        let contact = vault
            .contacts
            .iter_mut()
            .find(|contact| contact.id == peer_identity_id)
            .ok_or_else(|| "Le correspondant n'est pas enregistré dans le coffre.".to_string())?;
        if contact.public_key != peer_public_key {
            return Err(
                "La clé du correspondant ne correspond plus au contact enregistré.".to_string(),
            );
        }
        contact.last_seen_at_unix = Some(unix_time());
        if let Some(conversation) = vault.conversations.iter().find(|conversation| {
            conversation.local_identity_id == local_identity_id
                && conversation.remote_identity_id == peer_identity_id
        }) {
            conversation.id.clone()
        } else {
            let id = new_id().map_err(|problem| problem.to_string())?;
            vault.conversations.push(Conversation {
                id: id.clone(),
                local_identity_id: local_identity_id.to_string(),
                remote_identity_id: peer_identity_id.to_string(),
                created_at_unix: unix_time(),
                messages: Vec::new(),
            });
            id
        }
    };
    if app_state
        .active_sessions
        .read()
        .values()
        .any(|active| active.conversation_id == conversation_id)
    {
        app_state.vault.write().conversations = backup_conversations;
        app_state.vault.write().contacts = backup_contacts;
        return Err("Une session est déjà active pour cette paire d'identités.".to_string());
    }
    if let Err(problem) = save_current_vault(app_state) {
        app_state.vault.write().conversations = backup_conversations;
        app_state.vault.write().contacts = backup_contacts;
        return Err(problem);
    }
    let (handle, events) = start_message_session(stream, session);
    bridge_session_events(
        session_id.clone(),
        events,
        app_state.network_sender.read().clone(),
    );
    app_state.active_sessions.write().insert(
        session_id,
        ActiveSession {
            handle,
            conversation_id: conversation_id.clone(),
            local_identity_id: local_identity_id.to_string(),
            remote_identity_id: peer_identity_id.to_string(),
        },
    );
    app_state
        .selected_conversation_id
        .set(Some(conversation_id));
    app_state.connection_error.set(None);
    let _ = remote_address;
    Ok(())
}

fn start_listener_ui(app_state: &mut AppState, port: u16) -> Result<(), String> {
    if app_state.listener.read().is_some() {
        return Err("L'écoute est déjà active.".to_string());
    }
    let local_identity_id = app_state
        .selected_identity_id
        .read()
        .clone()
        .ok_or_else(|| {
            "Créez et sélectionnez une identité avant de démarrer l'écoute.".to_string()
        })?;
    let identity = app_state
        .vault
        .read()
        .identities
        .iter()
        .find(|identity| identity.public.id == local_identity_id)
        .cloned()
        .ok_or_else(|| "L'identité sélectionnée n'existe pas dans le coffre.".to_string())?;
    let (listener_sender, mut listener_events) = mpsc::channel(32);
    let application_sender = app_state.network_sender.read().clone();
    std::thread::spawn(move || {
        while let Some(event) = listener_events.blocking_recv() {
            if application_sender
                .blocking_send(AppNetworkEvent::Listener(event))
                .is_err()
            {
                break;
            }
        }
    });
    let address = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let handle = start_listener(address, identity, listener_sender);
    app_state.listener_identity_id.set(Some(local_identity_id));
    app_state
        .listener_status
        .set("Démarrage de l'écoute…".to_string());
    app_state.listener.set(Some(handle));
    Ok(())
}

fn stop_listener_ui(app_state: &mut AppState) {
    if let Some(listener) = app_state.listener.write().take() {
        listener.stop();
    }
    app_state.listener_identity_id.set(None);
    app_state.pending_peers.write().clear();
    app_state.invitation_uri.set(None);
    app_state.listener_status.set("Arrêtée".to_string());
}

fn start_outbound_connection(app_state: &mut AppState, contact: Contact) -> Result<(), String> {
    if contact.trust != IdentityTrust::ManuallyVerified || contact.blocked {
        return Err(
            "Vérifiez manuellement l'empreinte et débloquez le contact avant de vous connecter."
                .to_string(),
        );
    }
    if app_state.connecting_peers.read().contains(&contact.id) {
        return Err("Une connexion à ce contact est déjà en cours.".to_string());
    }
    let local_identity_id = app_state
        .selected_identity_id
        .read()
        .clone()
        .ok_or_else(|| "Sélectionnez d'abord une identité locale.".to_string())?;
    let identity = app_state
        .vault
        .read()
        .identities
        .iter()
        .find(|identity| identity.public.id == local_identity_id)
        .cloned()
        .ok_or_else(|| "L'identité sélectionnée n'existe pas dans le coffre.".to_string())?;
    let addresses = contact
        .addresses
        .iter()
        .filter_map(|address| address.parse::<std::net::SocketAddr>().ok())
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err("Cette invitation ne contient aucune adresse de connexion valide.".to_string());
    }
    let peer_public_key = contact.public_key.clone();
    let peer_identity_id = contact.id.clone();
    let peer_identity_id_for_event = peer_identity_id.clone();
    let peer_public_key_for_event = peer_public_key.clone();
    let sender = app_state.network_sender.read().clone();
    let local_identity_id_for_event = local_identity_id.clone();
    let peer_identity_id_for_failure = peer_identity_id.clone();
    app_state
        .connecting_peers
        .write()
        .insert(peer_identity_id.clone());
    let (cancellation_sender, mut cancellation_receiver) = watch::channel(false);
    app_state
        .outbound_cancellations
        .write()
        .insert(peer_identity_id.clone(), cancellation_sender);
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(problem) => {
                let _ = sender.blocking_send(AppNetworkEvent::OutboundFailed {
                    peer_identity_id: peer_identity_id_for_failure,
                    problem: problem.to_string(),
                });
                return;
            }
        };
        let result = runtime.block_on(async move {
            let connection = async move {
                let mut last_problem = "Aucune adresse de connexion n'a répondu.".to_string();
                for address in addresses {
                    let result = async {
                        let stream = connect(address)
                            .await
                            .map_err(|problem| problem.to_string())?;
                        let (stream, pending) =
                            initiate_session(stream, &identity, Some(&peer_public_key))
                                .await
                                .map_err(|problem| problem.to_string())?;
                        let session = pending
                            .verify_peer_identity(&peer_identity_id, &peer_public_key)
                            .map_err(|problem| problem.to_string())?;
                        let stream = stream.into_std().map_err(|problem| problem.to_string())?;
                        Ok::<_, String>((stream, session, address.to_string()))
                    }
                    .await;
                    match result {
                        Ok(ready) => return Ok(ready),
                        Err(problem) => last_problem = problem,
                    }
                }
                Err(last_problem)
            };
            tokio::select! {
                _ = cancellation_receiver.changed() => {
                    Err("Connexion annulée lors du verrouillage du coffre.".to_string())
                }
                result = connection => result,
            }
        });
        match result {
            Ok((stream, session, remote_address)) => {
                let _ = runtime.block_on(sender.send(AppNetworkEvent::OutboundReady {
                    stream,
                    session,
                    local_identity_id: local_identity_id_for_event,
                    peer_identity_id: peer_identity_id_for_event,
                    peer_public_key: peer_public_key_for_event,
                    remote_address,
                }));
            }
            Err(problem) => {
                let _ = runtime.block_on(sender.send(AppNetworkEvent::OutboundFailed {
                    peer_identity_id: peer_identity_id_for_failure,
                    problem,
                }));
            }
        }
    });
    Ok(())
}

fn approve_pending_peer(
    app_state: &mut AppState,
    index: usize,
    typed_fingerprint: &str,
) -> Result<(), String> {
    let (peer_id, peer_key, remote_address) = app_state
        .pending_peers
        .read()
        .get(index)
        .map(|peer| {
            (
                peer.peer_identity_id.clone(),
                peer.peer_public_key.clone(),
                peer.remote_address.to_string(),
            )
        })
        .ok_or_else(|| "Cette demande de connexion n'est plus disponible.".to_string())?;
    let public_key: [u8; 32] = peer_key
        .as_slice()
        .try_into()
        .map_err(|_| "La clé publique du pair est invalide.".to_string())?;
    let expected_fingerprint = fingerprint_for(&public_key);
    if !typed_fingerprint
        .trim()
        .eq_ignore_ascii_case(&expected_fingerprint)
    {
        return Err("L'empreinte ne correspond pas; la connexion reste en attente.".to_string());
    }
    let local_identity_id = app_state
        .listener_identity_id
        .read()
        .clone()
        .ok_or_else(|| "L'écoute a été arrêtée avant la validation du pair.".to_string())?;
    let previous_contacts = app_state.vault.read().contacts.clone();
    {
        let mut vault = app_state.vault.write();
        if let Some(contact) = vault
            .contacts
            .iter_mut()
            .find(|contact| contact.id == peer_id)
        {
            if contact.public_key != peer_key {
                return Err("La clé de cette identité a changé. La confiance existante est conservée et la connexion est bloquée.".to_string());
            }
            if contact.blocked {
                return Err("Ce contact est bloqué.".to_string());
            }
            contact.trust = IdentityTrust::ManuallyVerified;
        } else {
            vault.contacts.push(Contact {
                id: peer_id.clone(),
                display_name: format!("Contact {}", &peer_id[..8]),
                public_key: peer_key.clone(),
                fingerprint: expected_fingerprint,
                addresses: Vec::new(),
                trust: IdentityTrust::ManuallyVerified,
                blocked: false,
                created_at_unix: unix_time(),
                last_seen_at_unix: Some(unix_time()),
            });
        }
    }
    if let Err(problem) = save_current_vault(app_state) {
        app_state.vault.write().contacts = previous_contacts;
        return Err(problem);
    }
    let pending = app_state.pending_peers.write().remove(index);
    let (stream, session) = pending
        .verify_peer_identity(&peer_id, &peer_key)
        .map_err(|problem| problem.to_string())?;
    activate_connection(
        app_state,
        stream,
        session,
        &local_identity_id,
        &peer_id,
        &peer_key,
        &remote_address,
    )
}

fn bridge_session_events(
    session_id: String,
    mut events: mpsc::Receiver<SessionEvent>,
    sender: mpsc::Sender<AppNetworkEvent>,
) {
    std::thread::spawn(move || {
        while let Some(event) = events.blocking_recv() {
            let finished = matches!(event, SessionEvent::Closed | SessionEvent::Failed(_));
            if sender
                .blocking_send(AppNetworkEvent::Session {
                    session_id: session_id.clone(),
                    event,
                })
                .is_err()
                || finished
            {
                break;
            }
        }
    });
}

fn new_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|problem| problem.to_string())?;
    Ok(hex::encode(bytes))
}

fn fingerprint_for(public_key: &[u8; 32]) -> String {
    Sha256::digest(public_key)
        .chunks(2)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(":")
        .to_uppercase()
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[component]
fn SettingsView() -> Element {
    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "APPLICATION" }
            h1 { "Paramètres" }
            p { "Préférences et informations locales." }
        }
        div { class: "settings-card",
            div { class: "setting-row",
                div { strong { "Version" } p { "Version 0.1.2 · messagerie directe expérimentale." } }
                span { class: "setting-value", "0.1.2" }
            }
            div { class: "setting-row",
                div { strong { "Réseau" } p { "TCP direct IPv4/IPv6 selon votre réseau; aucun relais." } }
                span { class: "setting-value quiet", "PAIR-À-PAIR DIRECT" }
            }
            div { class: "setting-row",
                div { strong { "État de sécurité" } p { "Handshake hybride et AES-256-GCM intégrés; clés de contact à vérifier hors bande. Aucun Double Ratchet." } }
                span { class: "setting-value pending", "EXPÉRIMENTAL" }
            }
        }
    }
}

#[component]
fn EmptyView(title: String, detail: String) -> Element {
    rsx! {
        div { class: "empty-state",
            div { class: "empty-art",
                div { class: "art-orbit orbit-one" }
                div { class: "art-orbit orbit-two" }
                div { class: "art-core", "A" }
                div { class: "art-star star-one", "✳" }
                div { class: "art-star star-two", "✦" }
            }
            h3 { "{title}" }
            p { "{detail}" }
        }
    }
}

fn icon_for(label: &str) -> &'static str {
    match label {
        "Identités" => "◈",
        "Conversations" => "▤",
        "Connexion" => "⌁",
        _ => "⚙",
    }
}

fn application_status(app_state: &AppState) -> String {
    let sessions = app_state.active_sessions.read().len();
    if sessions > 0 {
        format!("{sessions} session(s) chiffrée(s)")
    } else if app_state.listener.read().is_some() {
        "Écoute TCP active".to_string()
    } else {
        "Hors ligne · coffre local".to_string()
    }
}
