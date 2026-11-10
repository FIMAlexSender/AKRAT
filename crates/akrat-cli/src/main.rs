use akrat_core::network::{self, ChannelReceiver, ChannelSender, SecureChannel};
use akrat_core::{
    Contact, DeliveryState, Identity, Invitation, StoredMessage, VaultData, load_vault, save_vault,
};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, BufReader};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "akrat", version, about = "Messagerie directe pair à pair")]
struct Args {
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Créer ou vérifier le coffre chiffré local")]
    Vault {
        #[command(subcommand)]
        action: VaultCommand,
    },
    #[command(about = "Créer ou lister les identités locales")]
    Identity {
        #[command(subcommand)]
        action: IdentityCommand,
    },
    #[command(about = "Importer, vérifier ou lister les contacts")]
    Contact {
        #[command(subcommand)]
        action: ContactCommand,
    },
    #[command(about = "Créer une invitation publique pour une adresse réseau")]
    Invite {
        identity: String,
        #[arg(long)]
        address: SocketAddr,
    },
    #[command(about = "Écouter et accepter les contacts déjà vérifiés")]
    Listen {
        identity: String,
        #[arg(long, default_value = "0.0.0.0:47474")]
        bind: SocketAddr,
    },
    #[command(about = "Se connecter à un contact déjà vérifié")]
    Connect {
        identity: String,
        fingerprint: String,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    Create,
    Check,
}

#[derive(Subcommand)]
enum IdentityCommand {
    Create { name: String },
    List,
}

#[derive(Subcommand)]
enum ContactCommand {
    Import { invitation: String, name: String },
    List,
    Verify { fingerprint: String },
}

#[derive(Serialize, Deserialize)]
enum WireMessage {
    Text { id: String, text: String },
    Acknowledgement { id: String },
    Close,
}

#[tokio::main]
async fn main() {
    if let Err(problem) = run().await {
        eprintln!("Erreur: {problem}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let path = match args.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };
    match args.command {
        Command::Vault {
            action: VaultCommand::Create,
        } => {
            if path.exists() {
                return Err("un coffre existe déjà à cet emplacement".into());
            }
            let passphrase = new_passphrase()?;
            save_vault(&path, &VaultData::default(), &passphrase)?;
            println!("Coffre créé et verrouillé : {}", path.display());
        }
        Command::Vault {
            action: VaultCommand::Check,
        } => {
            let (data, _) = unlock(&path)?;
            println!(
                "Coffre ouvert : {} identité(s), {} contact(s), {} message(s).",
                data.identities.len(),
                data.contacts.len(),
                data.messages.len()
            );
        }
        Command::Identity {
            action: IdentityCommand::Create { name },
        } => {
            let (mut data, passphrase) = unlock(&path)?;
            let identity = Identity::generate(name)?;
            println!("Identité créée : {}", identity.name);
            println!("Empreinte publique : {}", identity.fingerprint());
            data.identities.push(identity);
            save_vault(&path, &data, &passphrase)?;
        }
        Command::Identity {
            action: IdentityCommand::List,
        } => {
            let (data, _) = unlock(&path)?;
            for identity in &data.identities {
                println!(
                    "{}  {}  {}",
                    identity.id,
                    identity.name,
                    identity.fingerprint()
                );
            }
        }
        Command::Contact {
            action: ContactCommand::Import { invitation, name },
        } => {
            let invitation = Invitation::from_uri(&invitation)?;
            let (mut data, passphrase) = unlock(&path)?;
            if let Some(contact) = data
                .contacts
                .iter_mut()
                .find(|item| item.fingerprint == invitation.fingerprint)
            {
                contact.address = invitation.address;
                contact.name = name;
                contact.manually_verified = false;
            } else {
                data.contacts.push(Contact {
                    fingerprint: invitation.fingerprint.clone(),
                    name,
                    public_key: invitation.public_key,
                    address: invitation.address,
                    manually_verified: false,
                });
            }
            save_vault(&path, &data, &passphrase)?;
            println!(
                "Contact importé comme non vérifié : {}",
                invitation.fingerprint
            );
        }
        Command::Contact {
            action: ContactCommand::List,
        } => {
            let (data, _) = unlock(&path)?;
            for contact in &data.contacts {
                let trust = if contact.manually_verified {
                    "vérifié manuellement"
                } else {
                    "non vérifié"
                };
                println!(
                    "{}  {}  {}  {}",
                    contact.fingerprint, contact.name, contact.address, trust
                );
            }
        }
        Command::Contact {
            action: ContactCommand::Verify { fingerprint },
        } => {
            let (mut data, passphrase) = unlock(&path)?;
            let canonical =
                canonical_fingerprint(&fingerprint).ok_or("format d'empreinte invalide")?;
            let contact = data
                .contacts
                .iter_mut()
                .find(|item| {
                    canonical_fingerprint(&item.fingerprint).as_deref() == Some(&canonical)
                })
                .ok_or("contact introuvable")?;
            println!("Compare cette empreinte avec la personne par un autre canal :");
            println!("{}", contact.fingerprint);
            let typed = rpassword::prompt_password("Retape l'empreinte complète : ")?;
            if !typed
                .chars()
                .filter(|character| character.is_ascii_hexdigit())
                .collect::<String>()
                .eq_ignore_ascii_case(&canonical)
            {
                return Err("l'empreinte saisie ne correspond pas".into());
            }
            contact.manually_verified = true;
            save_vault(&path, &data, &passphrase)?;
            println!("Identité vérifiée manuellement et enregistrée dans le coffre.");
        }
        Command::Invite { identity, address } => {
            let (data, _) = unlock(&path)?;
            let local = find_identity(&data, &identity)?;
            println!("Partage cette invitation avec ton correspondant :");
            println!(
                "{}",
                Invitation::create(local, address.to_string())?.to_uri()?
            );
            println!(
                "L'invitation contient une clé publique et une adresse, jamais la clé privée."
            );
        }
        Command::Listen { identity, bind } => {
            listen(&path, &identity, bind).await?;
        }
        Command::Connect {
            identity,
            fingerprint,
        } => {
            connect_and_chat(&path, &identity, &fingerprint).await?;
        }
    }
    Ok(())
}

fn unlock(path: &Path) -> Result<(VaultData, Zeroizing<String>), Box<dyn Error>> {
    if !path.exists() {
        return Err("aucun coffre à cet emplacement; exécute akrat vault create".into());
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password("Phrase secrète du coffre : ")?);
    let data = load_vault(path, &passphrase)?;
    Ok((data, passphrase))
}

fn new_passphrase() -> Result<Zeroizing<String>, Box<dyn Error>> {
    let passphrase = Zeroizing::new(rpassword::prompt_password("Nouvelle phrase secrète : ")?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Répète la phrase secrète : ")?);
    if passphrase.len() < 12 || *passphrase != *confirmation {
        return Err("les phrases doivent correspondre et contenir au moins 12 caractères".into());
    }
    Ok(passphrase)
}

fn default_vault_path() -> Result<PathBuf, Box<dyn Error>> {
    let directory =
        ProjectDirs::from("org", "AKRAT", "AKRAT").ok_or("dossier utilisateur indisponible")?;
    std::fs::create_dir_all(directory.data_local_dir())?;
    Ok(directory.data_local_dir().join("vault.akrat"))
}

async fn listen(path: &Path, identity_id: &str, bind: SocketAddr) -> Result<(), Box<dyn Error>> {
    let (mut data, passphrase) = unlock(path)?;
    let local_identity = find_identity(&data, identity_id)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("Écoute TCP démarrée sur {}.", listener.local_addr()?);
    println!("Les connexions seront acceptées uniquement pour les contacts vérifiés.");
    loop {
        let (stream, address) = listener.accept().await?;
        println!("Connexion TCP depuis {address}; négociation cryptographique en cours.");
        let pending = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            network::respond(stream, local_identity),
        )
        .await
        {
            Ok(Ok(pending)) => pending,
            Ok(Err(problem)) => {
                println!("Connexion refusée pendant la négociation : {problem}");
                continue;
            }
            Err(_) => {
                println!("Négociation expirée.");
                continue;
            }
        };
        let peer_fingerprint = pending.fingerprint();
        println!("Empreinte distante reçue : {peer_fingerprint}");
        let Some(contact) = data
            .contacts
            .iter()
            .find(|item| item.fingerprint == peer_fingerprint && item.manually_verified)
        else {
            println!("Contact inconnu ou non vérifié; aucun message accepté.");
            continue;
        };
        let contact_name = contact.name.clone();
        let expected = contact.public_key.clone();
        let channel = pending.verify_peer(&expected)?;
        println!("Identité confirmée; canal chiffré établi avec {contact_name}.");
        let conversation = format!("{identity_id}:{peer_fingerprint}");
        chat(channel, &mut data, path, &passphrase, &conversation).await?;
        return Ok(());
    }
}

async fn connect_and_chat(
    path: &Path,
    identity_id: &str,
    fingerprint_input: &str,
) -> Result<(), Box<dyn Error>> {
    let (mut data, passphrase) = unlock(path)?;
    let canonical =
        canonical_fingerprint(fingerprint_input).ok_or("format d'empreinte invalide")?;
    let (contact_name, address, peer_key, conversation) = {
        let contact = data
            .contacts
            .iter()
            .find(|item| {
                canonical_fingerprint(&item.fingerprint).as_deref() == Some(&canonical)
                    && item.manually_verified
            })
            .ok_or("contact absent du coffre ou non vérifié")?;
        (
            contact.name.clone(),
            contact.address.parse::<SocketAddr>()?,
            contact.public_key.clone(),
            format!("{identity_id}:{}", contact.fingerprint),
        )
    };
    let local_identity = find_identity(&data, identity_id)?;
    println!("Connexion TCP vers {address}.");
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        network::connect(address),
    )
    .await??;
    println!("Connexion établie; négociation cryptographique en cours.");
    let pending = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        network::initiate(stream, local_identity),
    )
    .await??;
    let channel = pending.verify_peer(&peer_key)?;
    println!("Empreinte vérifiée; canal chiffré établi avec {contact_name}.");
    chat(channel, &mut data, path, &passphrase, &conversation).await
}

async fn chat<S>(
    channel: SecureChannel<S>,
    data: &mut VaultData,
    path: &Path,
    passphrase: &str,
    conversation: &str,
) -> Result<(), Box<dyn Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sender, mut receiver) = channel.split();
    let pending = data
        .messages
        .iter()
        .filter(|message| {
            message.conversation == conversation
                && message.outgoing
                && matches!(
                    message.delivery,
                    DeliveryState::Pending | DeliveryState::Unconfirmed | DeliveryState::Sent
                )
        })
        .map(|message| (message.id.clone(), message.text.clone()))
        .collect::<Vec<_>>();
    for (id, text) in pending {
        let packet = serde_json::to_vec(&WireMessage::Text {
            id: id.clone(),
            text,
        })?;
        if let Err(problem) = sender.send(&packet).await {
            update_delivery(data, conversation, &id, DeliveryState::Unconfirmed);
            save_vault(path, data, passphrase)?;
            return Err(problem.into());
        }
        update_delivery(data, conversation, &id, DeliveryState::Sent);
        save_vault(path, data, passphrase)?;
        println!("↻ retransmission logique {id} chiffrée dans la session actuelle");
    }
    println!("Historique local :");
    for message in data
        .messages
        .iter()
        .filter(|message| message.conversation == conversation)
    {
        let direction = if message.outgoing { "moi" } else { "pair" };
        println!("[{direction} · {:?}] {}", message.delivery, message.text);
    }
    println!("Écris un message puis Entrée. /quit ferme la session.");
    let result = chat_loop(
        &mut sender,
        &mut receiver,
        data,
        path,
        passphrase,
        conversation,
    )
    .await;
    for message in data.messages.iter_mut().filter(|message| {
        message.conversation == conversation
            && message.outgoing
            && matches!(
                message.delivery,
                DeliveryState::Pending | DeliveryState::Sent
            )
    }) {
        message.delivery = DeliveryState::Unconfirmed;
    }
    save_vault(path, data, passphrase)?;
    println!("Session fermée; une reconnexion établira de nouvelles clés.");
    result
}

async fn chat_loop<S>(
    sender: &mut ChannelSender<S>,
    receiver: &mut ChannelReceiver<S>,
    data: &mut VaultData,
    path: &Path,
    passphrase: &str,
    conversation: &str,
) -> Result<(), Box<dyn Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut stdin = BufReader::new(tokio::io::stdin());
    loop {
        let mut line = String::new();
        tokio::select! {
            result = stdin.read_line(&mut line) => {
                if result? == 0 || line.trim_end() == "/quit" {
                    let packet = serde_json::to_vec(&WireMessage::Close)?;
                    let _ = sender.send(&packet).await;
                    return Ok(());
                }
                let text = line.trim_end().to_string();
                if text.trim().is_empty() { continue; }
                if text.len() > 10 * 1024 { println!("Message trop long; limite de 10 Kio."); continue; }
                let id = new_message_id()?;
                data.messages.push(StoredMessage {
                    conversation: conversation.to_string(),
                    id: id.clone(),
                    outgoing: true,
                    text: text.clone(),
                    delivery: DeliveryState::Pending,
                    timestamp: unix_time(),
                });
                save_vault(path, data, passphrase)?;
                println!("Message enregistré localement; chiffrement et envoi.");
                let packet = serde_json::to_vec(&WireMessage::Text { id: id.clone(), text })?;
                if let Err(problem) = sender.send(&packet).await {
                    update_delivery(data, conversation, &id, DeliveryState::Unconfirmed);
                    save_vault(path, data, passphrase)?;
                    return Err(problem.into());
                }
                update_delivery(data, conversation, &id, DeliveryState::Sent);
                save_vault(path, data, passphrase)?;
                println!("Message transmis; attente d'un accusé authentifié.");
            }
            result = receiver.receive() => {
                let plaintext = result?;
                let packet: WireMessage = serde_json::from_slice(&plaintext)?;
                match packet {
                    WireMessage::Text { id, text } => {
                        if store_incoming(data, conversation, &id, &text)? {
                            save_vault(path, data, passphrase)?;
                            println!("Message authentifié, déchiffré et enregistré : {text}");
                        } else {
                            println!("Doublon logique ignoré; historique inchangé.");
                        }
                        let packet = serde_json::to_vec(&WireMessage::Acknowledgement { id })?;
                        sender.send(&packet).await?;
                    }
                    WireMessage::Acknowledgement { id } => {
                        if update_delivery(data, conversation, &id, DeliveryState::Acknowledged) {
                            save_vault(path, data, passphrase)?;
                            println!("Accusé authentifié; livraison confirmée dans le coffre.");
                        }
                    }
                    WireMessage::Close => return Ok(()),
                }
            }
        }
    }
}

fn update_delivery(
    data: &mut VaultData,
    conversation: &str,
    id: &str,
    state: DeliveryState,
) -> bool {
    if let Some(message) = data.messages.iter_mut().find(|message| {
        message.conversation == conversation && message.id == id && message.outgoing
    }) {
        message.delivery = state;
        true
    } else {
        false
    }
}

fn store_incoming(
    data: &mut VaultData,
    conversation: &str,
    id: &str,
    text: &str,
) -> Result<bool, Box<dyn Error>> {
    if id.len() != 32
        || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || text.trim().is_empty()
        || text.len() > 10 * 1024
    {
        return Err("message reçu invalide".into());
    }
    if data.messages.iter().any(|message| {
        message.conversation == conversation && message.id == id && !message.outgoing
    }) {
        return Ok(false);
    }
    data.messages.push(StoredMessage {
        conversation: conversation.to_string(),
        id: id.to_ascii_lowercase(),
        outgoing: false,
        text: text.to_string(),
        delivery: DeliveryState::Received,
        timestamp: unix_time(),
    });
    Ok(true)
}

fn find_identity<'a>(data: &'a VaultData, id: &str) -> Result<&'a Identity, Box<dyn Error>> {
    data.identities
        .iter()
        .find(|identity| identity.id == id)
        .ok_or_else(|| "identité introuvable".into())
}

fn canonical_fingerprint(value: &str) -> Option<String> {
    let mut normalized = String::with_capacity(64);
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            normalized.push(character.to_ascii_uppercase());
        } else if !matches!(character, ' ' | ':' | '-') {
            return None;
        }
    }
    (normalized.len() == 64).then_some(normalized)
}

fn new_message_id() -> Result<String, Box<dyn Error>> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)?;
    Ok(hex::encode(random))
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{canonical_fingerprint, store_incoming, update_delivery};
    use akrat_core::{DeliveryState, StoredMessage, VaultData};

    #[test]
    fn incoming_retransmission_is_deduplicated_before_acknowledgement() {
        let mut data = VaultData::default();
        assert!(
            store_incoming(
                &mut data,
                "alice:bob",
                "00112233445566778899aabbccddeeff",
                "hello"
            )
            .expect("first receive")
        );
        assert!(
            !store_incoming(
                &mut data,
                "alice:bob",
                "00112233445566778899aabbccddeeff",
                "hello"
            )
            .expect("duplicate")
        );
        assert_eq!(data.messages.len(), 1);
    }

    #[test]
    fn invalid_incoming_message_is_not_added_to_history() {
        let mut data = VaultData::default();
        assert!(store_incoming(&mut data, "alice:bob", "invalid", "hello").is_err());
        assert!(data.messages.is_empty());
    }

    #[test]
    fn acknowledgements_only_change_the_matching_outgoing_message() {
        let mut data = VaultData {
            identities: Vec::new(),
            contacts: Vec::new(),
            messages: vec![StoredMessage {
                conversation: "alice:bob".to_string(),
                id: "logical-id".to_string(),
                outgoing: true,
                text: "hello".to_string(),
                delivery: DeliveryState::Unconfirmed,
                timestamp: 1,
            }],
        };
        assert!(!update_delivery(
            &mut data,
            "alice:carol",
            "logical-id",
            DeliveryState::Acknowledged
        ));
        assert_eq!(data.messages[0].delivery, DeliveryState::Unconfirmed);
        assert!(update_delivery(
            &mut data,
            "alice:bob",
            "logical-id",
            DeliveryState::Acknowledged
        ));
        assert_eq!(data.messages[0].delivery, DeliveryState::Acknowledged);
    }

    #[test]
    fn fingerprint_normalization_rejects_unexpected_characters() {
        let key = "A1".repeat(32);
        assert_eq!(canonical_fingerprint(&key).as_deref(), Some(key.as_str()));
        assert!(canonical_fingerprint(&format!("{key}G")).is_none());
        assert!(canonical_fingerprint("ABCD").is_none());
    }
}
