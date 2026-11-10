use akrat_core::PrivateIdentity;
use akrat_crypto::create_identity;
use akrat_storage::{load_vault, save_vault};
use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, WindowBuilder};
use std::path::PathBuf;
use zeroize::Zeroizing;

const STYLE: &str = include_str!("style.css");

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
                        span { class: "status-dot" }
                        span { "Aucun service distant" }
                    }
                    div { class: "version", "VERSION 0.1.0 · APERÇU TECHNIQUE" }
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
                        EmptyView { title: "Aucune conversation", detail: "La création et la consultation des conversations ne sont pas encore intégrées à l'application." }
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
    let path = vault_path();
    let mut vault_exists = use_signal(|| path.as_ref().is_ok_and(|value| value.exists()));
    let mut unlocked = use_signal(|| false);
    let mut identities = use_signal(Vec::<PrivateIdentity>::new);
    let mut name = use_signal(String::new);
    let mut secret = use_signal(|| Zeroizing::new(String::new()));
    let mut confirmation = use_signal(|| Zeroizing::new(String::new()));
    let mut error = use_signal(|| None::<String>);

    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "VOTRE ESPACE" }
            h1 { "Identités" }
            p { "Des identités cryptographiques indépendantes, contrôlées localement." }
        }
        if unlocked() {
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
                        let identity = create_identity(format!("Identité {}", identities.read().len() + 1));
                        match identity {
                            Ok(identity) => {
                                identities.write().push(identity);
                                let result = path.as_ref().map_err(|error| error.clone()).and_then(|vault_path| {
                                    save_vault(vault_path, &identities.read(), secret.read().as_str())
                                        .map_err(|error| error.to_string())
                                });
                                if let Err(message) = result {
                                    identities.write().pop();
                                    error.set(Some(message));
                                } else {
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
                for identity in identities.read().iter() {
                    article { class: "identity-card",
                        div { class: "identity-card-top",
                            div { class: "identity-glyph", "◈" }
                            div { class: "identity-copy",
                                strong { "{identity.public.display_name}" }
                                span { "{identity.public.id}" }
                            }
                            span { class: "active-badge", "ACTIVE" }
                        }
                        div { class: "fingerprint-label", "EMPREINTE PUBLIQUE" }
                        code { class: "fingerprint", "{identity.public.fingerprint}" }
                        div { class: "identity-key-label", "CLÉ PUBLIQUE ED25519" }
                        code { class: "public-key", "{hex_public_key(&identity.public.public_key)}" }
                    }
                }
            }
            button {
                class: "lock-button",
                onclick: move |_| {
                    identities.set(Vec::new());
                    secret.set(Zeroizing::new(String::new()));
                    unlocked.set(false);
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
                    oninput: move |event| secret.set(Zeroizing::new(event.value()))
                }
                button {
                    class: "primary-button form-submit",
                    onclick: move |_| {
                        let result = path.as_ref().map_err(|error| error.clone()).and_then(|vault_path| {
                            load_vault(vault_path, secret.read().as_str()).map_err(|error| error.to_string())
                        });
                        match result {
                            Ok(records) => { identities.set(records); unlocked.set(true); error.set(None); }
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
                    oninput: move |event| secret.set(Zeroizing::new(event.value()))
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
                        if secret.read().len() < 12 {
                            error.set(Some("La phrase secrète doit contenir au moins 12 caractères.".to_string()));
                        } else if secret.read().as_str() != confirmation.read().as_str() {
                            error.set(Some("Les deux phrases secrètes ne correspondent pas.".to_string()));
                        } else if name.read().trim().is_empty() {
                            error.set(Some("Donnez un nom à votre première identité.".to_string()));
                        } else {
                            let result = create_identity(name.read().trim().to_string())
                                .map_err(|problem| problem.to_string())
                                .and_then(|identity| {
                                    path.as_ref().map_err(|problem| problem.clone()).and_then(|vault_path| {
                                        save_vault(
                                            vault_path,
                                            std::slice::from_ref(&identity),
                                            secret.read().as_str(),
                                        )
                                            .map_err(|problem| problem.to_string())
                                            .map(|_| identity)
                                    })
                                });
                            match result {
                                Ok(identity) => {
                                    identities.set(vec![identity]);
                                    vault_exists.set(true);
                                    unlocked.set(true);
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
            span { strong { "Chiffrement local actif" } " · La messagerie réseau n'est pas intégrée à l'application." }
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

#[component]
fn ConnectionView() -> Element {
    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "RÉSEAU DIRECT" }
            h1 { "Connexion" }
            p { "Les connexions directes seront configurées ici lorsqu'elles seront intégrées à l'application." }
        }
        div { class: "connection-card",
            div { class: "card-icon", "↔" }
            h2 { "Écoute et invitations non intégrées" }
            p { "Le moteur TCP et le handshake expérimental sont testés dans les bibliothèques Rust. L'interface ne lance pas d'écoute et n'accepte pas de connexions." }
            div { class: "feature-row", span { "Intégration à l'application à venir" } }
            div { class: "feature-list",
                div { span { "01" } "Écoute sur une adresse choisie" }
                div { span { "02" } "Invitation avec identité publique" }
                div { span { "03" } "Connexion directe authentifiée" }
            }
        }
    }
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
                div { strong { "Version" } p { "Version de développement de la fondation." } }
                span { class: "setting-value", "0.1.0" }
            }
            div { class: "setting-row",
                div { strong { "Réseau" } p { "Aucun service distant configuré." } }
                span { class: "setting-value quiet", "PAIR-À-PAIR DIRECT" }
            }
            div { class: "setting-row",
                div { strong { "État de sécurité" } p { "Le moteur de session expérimental n'est pas connecté à la messagerie de l'application." } }
                span { class: "setting-value pending", "NON DISPONIBLE" }
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
