use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, WindowBuilder};

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
                        EmptyView { title: "Aucune conversation", detail: "Les conversations apparaîtront ici après l'implémentation du protocole et du stockage local." }
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
    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "VOTRE ESPACE" }
            h1 { "Identités" }
            p { "Des identités cryptographiques indépendantes, contrôlées localement." }
        }
        div { class: "notice",
            div { class: "notice-symbol", "i" }
            div {
                strong { "Fondation en cours" }
                p { "Aucune identité n'a été créée. Le coffre local n'est pas encore disponible dans cette version de développement." }
            }
        }
        div { class: "section-title",
            div { h2 { "Toutes les identités" } p { "Les identités seront stockées uniquement sur cet appareil." } }
            button { class: "primary-button disabled", disabled: true, span { "+" } "Créer une identité" }
        }
        EmptyView { title: "Aucune identité pour le moment", detail: "La création sera activée avec le coffre chiffré et la génération réelle des clés." }
        div { class: "security-note",
            span { class: "lock-icon", "◇" }
            span { strong { "La sécurité passe avant tout" } " · Les fonctionnalités cryptographiques restent désactivées tant que leur implémentation n'est pas disponible." }
        }
    }
}

#[component]
fn ConnectionView() -> Element {
    rsx! {
        div { class: "page-heading",
            div { class: "eyebrow", "RÉSEAU DIRECT" }
            h1 { "Connexion" }
            p { "Les connexions seront établies directement par adresse IP et port." }
        }
        div { class: "connection-card",
            div { class: "card-icon", "↔" }
            h2 { "Écoute et invitations indisponibles" }
            p { "Le transport réseau n'est pas encore implémenté. Cette application n'ouvre aucun port et ne prétend pas accepter de connexions." }
            div { class: "feature-row", span { "À venir dans les prochaines phases" } }
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
                div { strong { "État de sécurité" } p { "Aucun chiffrement de messages n'est encore disponible." } }
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
