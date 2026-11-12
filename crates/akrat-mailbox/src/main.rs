use akrat_mailbox::registry::{LocalRegistry, TrustStatus};
use akrat_mailbox::server::FederationPeer;
use akrat_mailbox::server::{Request, Response, ServerConfig};
use akrat_mailbox::{Store, server};
use clap::{Parser, Subcommand};
use sha2::Digest;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "akrat-mailbox",
    version,
    about = "Serveur autonome de boîtes aux lettres AKRAT"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "127.0.0.1:47475")]
        bind: SocketAddr,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long,default_value_t=10 * 1024 * 1024 * 1024)]
        max_total_bytes: u64,
        #[arg(long, default_value_t = 10000)]
        max_mailboxes: u64,
        #[arg(long,default_value_t=10 * 1024 * 1024)]
        mailbox_quota: u64,
        #[arg(long,default_value_t=30 * 24 * 3600)]
        retention_seconds: u64,
    },
    Serve,
    Status,
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    Mailbox {
        #[command(subcommand)]
        command: MailboxCommand,
    },
    Health,
    Federation {
        #[command(subcommand)]
        command: FederationCommand,
    },
    Limits {
        #[command(subcommand)]
        command: LimitsCommand,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    Show,
    Rotate,
    Revoke {
        fingerprint: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand)]
enum LimitsCommand {
    Show,
    Set {
        #[arg(long)]
        global_per_minute: Option<u32>,
        #[arg(long)]
        global_burst: Option<u32>,
        #[arg(long)]
        source_per_minute: Option<u32>,
        #[arg(long)]
        source_burst: Option<u32>,
        #[arg(long)]
        identity_per_minute: Option<u32>,
        #[arg(long)]
        identity_burst: Option<u32>,
        #[arg(long)]
        mailbox_per_minute: Option<u32>,
        #[arg(long)]
        mailbox_burst: Option<u32>,
        #[arg(long)]
        max_connections_per_source: Option<u32>,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    Show,
    Name { value: String },
    Description { value: String },
    Operator { value: String },
    HostName { value: String },
    Endpoint { value: String },
    ClearEndpoint,
}

#[derive(Subcommand)]
enum FederationCommand {
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    Nodes,
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    Add {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        noise_key: String,
        #[arg(long)]
        signing_key: String,
    },
    Remove {
        #[arg(long)]
        fingerprint: String,
    },
    List,
}

#[derive(Subcommand)]
enum NodeCommand {
    Approve { fingerprint: String },
    Block { fingerprint: String },
}

#[derive(Subcommand)]
enum MailboxCommand {
    Create {
        #[arg(long)]
        quota_bytes: Option<u64>,
        #[arg(long)]
        retention_seconds: Option<u64>,
    },
}

fn default_config_path() -> PathBuf {
    directories::ProjectDirs::from("org", "akrat", "akrat-mailbox")
        .map(|dirs| dirs.config_dir().join("server.json"))
        .unwrap_or_else(|| PathBuf::from("akrat-mailbox.json"))
}

fn config_path(cli: &Cli) -> PathBuf {
    cli.config.clone().unwrap_or_else(default_config_path)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let path = config_path(&cli);
    match cli.command {
        Command::Init {
            name,
            bind,
            data_dir,
            max_total_bytes,
            max_mailboxes,
            mailbox_quota,
            retention_seconds,
        } => {
            if path.exists() {
                return Err(format!("configuration already exists: {}", path.display()).into());
            }
            let name = match name {
                Some(name) => name,
                None => prompt("Nom du serveur", "AKRAT Mailbox")?,
            };
            let data_dir = data_dir.unwrap_or_else(|| {
                path.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join("data")
            });
            ServerConfig::initialize(
                &path,
                name,
                bind,
                data_dir,
                max_total_bytes,
                max_mailboxes,
                mailbox_quota,
                retention_seconds,
            )?;
            println!("Configuration initialisée : {}", path.display());
            println!("Protégez ce fichier : il contient les clés privées du serveur.");
        }
        Command::Serve => {
            let config = ServerConfig::load(&path)?;
            server::run(config).await?;
        }
        Command::Status => {
            let config = ServerConfig::load(&path)?;
            let store = Store::open(
                config.data_dir.join("mailbox.sqlite3"),
                config.max_total_bytes,
                config.max_mailboxes,
            )?;
            let (mailboxes, messages, stored_bytes) = store.status()?;
            println!("{} · état réseau non vérifié", config.name);
            println!("Adresse d'écoute configurée : {}", config.bind);
            println!(
                "Empreinte racine de continuité : {}",
                config.server_fingerprint()?
            );
            println!(
                "Clé publique Noise : {}",
                hex::encode(config.noise_identity.public_key())
            );
            let signer = config.receipt_signer()?;
            println!(
                "Clé racine de continuité : {}",
                config.root_signer()?.fingerprint()
            );
            println!(
                "Clé publique racine à épingler : {}",
                hex::encode(config.root_signer()?.public_key())
            );
            println!(
                "Clé publique de signature des reçus : {}",
                hex::encode(signer.public_key())
            );
            println!(
                "Boîtes : {mailboxes} · enveloppes : {messages} · stockage : {stored_bytes} octets"
            );
        }
        Command::Limits { command } => {
            let mut config = ServerConfig::load(&path)?;
            match command {
                LimitsCommand::Show => {
                    println!("{}", serde_json::to_string_pretty(&config.rate_limits)?)
                }
                LimitsCommand::Set {
                    global_per_minute,
                    global_burst,
                    source_per_minute,
                    source_burst,
                    identity_per_minute,
                    identity_burst,
                    mailbox_per_minute,
                    mailbox_burst,
                    max_connections_per_source,
                } => {
                    let limits = &mut config.rate_limits;
                    if let Some(value) = global_per_minute {
                        limits.global_requests_per_minute = value;
                    }
                    if let Some(value) = global_burst {
                        limits.global_burst = value;
                    }
                    if let Some(value) = source_per_minute {
                        limits.source_requests_per_minute = value;
                    }
                    if let Some(value) = source_burst {
                        limits.source_burst = value;
                    }
                    if let Some(value) = identity_per_minute {
                        limits.identity_requests_per_minute = value;
                    }
                    if let Some(value) = identity_burst {
                        limits.identity_burst = value;
                    }
                    if let Some(value) = mailbox_per_minute {
                        limits.mailbox_requests_per_minute = value;
                    }
                    if let Some(value) = mailbox_burst {
                        limits.mailbox_burst = value;
                    }
                    if let Some(value) = max_connections_per_source {
                        limits.max_connections_per_source = value;
                    }
                    limits.validate()?;
                    config.save(&path)?;
                    println!(
                        "Limites enregistrées. Redémarrez le serveur pour appliquer la configuration."
                    );
                }
            }
        }
        Command::Key { command } => {
            let mut config = ServerConfig::load(&path)?;
            match command {
                KeyCommand::Show => {
                    println!(
                        "Racine de continuité · {}",
                        config.root_signer()?.fingerprint()
                    );
                    println!(
                        "Clé publique racine · {}",
                        hex::encode(config.root_signer()?.public_key())
                    );
                    println!(
                        "Clé active des reçus · {}",
                        config.receipt_signer()?.fingerprint()
                    );
                    println!(
                        "Clé publique active · {}",
                        hex::encode(config.receipt_signer()?.public_key())
                    );
                    println!("Génération · {}", config.key_transitions.len());
                    println!(
                        "Transitions · {} · Révocations · {}",
                        config.key_transitions.len(),
                        config.key_revocations.len()
                    );
                }
                KeyCommand::Rotate => {
                    let fingerprint = config.rotate_receipt_key()?;
                    let generation = config.key_transitions.len();
                    config.save(&path)?;
                    println!(
                        "Rotation authentifiée préparée · génération {generation} · {fingerprint}"
                    );
                    println!("Redémarrez le serveur pour commencer à signer avec la nouvelle clé.");
                }
                KeyCommand::Revoke {
                    fingerprint,
                    reason,
                } => {
                    config.revoke_receipt_key(fingerprint.clone(), reason)?;
                    config.save(&path)?;
                    println!("Révocation authentifiée enregistrée · {fingerprint}");
                    println!(
                        "Les clients appliqueront la révocation au prochain échange d'identité serveur."
                    );
                }
            }
        }
        Command::Profile { command } => {
            let mut config = ServerConfig::load(&path)?;
            match command {
                ProfileCommand::Show => {
                    println!("Nom public : {}", config.name);
                    println!("Description : {}", value_or_dash(&config.description));
                    println!("Hébergeur : {}", value_or_dash(&config.operator));
                    println!("Pseudonyme : {}", value_or_dash(&config.host_name));
                    println!(
                        "Endpoint fédéré : {}",
                        config.public_endpoint.as_deref().unwrap_or("non configuré")
                    );
                    println!("Identité serveur : {}", config.server_fingerprint()?);
                }
                ProfileCommand::Name { value } => {
                    config.name = bounded_profile_value(value, "nom", 128, false)?;
                }
                ProfileCommand::Description { value } => {
                    config.description = bounded_profile_value(value, "description", 280, true)?;
                }
                ProfileCommand::Operator { value } => {
                    config.operator = bounded_profile_value(value, "hébergeur", 128, true)?;
                }
                ProfileCommand::HostName { value } => {
                    config.host_name = bounded_profile_value(value, "pseudonyme", 128, true)?;
                }
                ProfileCommand::Endpoint { value } => {
                    let endpoint = value.trim().to_owned();
                    if endpoint.is_empty() || endpoint.len() > 512 {
                        return Err("endpoint invalide".into());
                    }
                    config.public_endpoint = Some(endpoint);
                }
                ProfileCommand::ClearEndpoint => config.public_endpoint = None,
            }
            config.save(&path)?;
            println!("Profil enregistré dans {}", path.display());
            if config.public_endpoint.is_some() {
                println!("Redémarrez le service pour propager le profil dans la fédération.");
            }
        }
        Command::Health => {
            let config = ServerConfig::load(&path)?;
            let local_address = if config.bind.ip().is_unspecified() {
                if config.bind.is_ipv4() {
                    SocketAddr::from(([127, 0, 0, 1], config.bind.port()))
                } else {
                    SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], config.bind.port()))
                }
            } else {
                config.bind
            };
            let mut channel = server::connect(
                local_address,
                &config.noise_identity,
                config.noise_identity.public_key(),
            )
            .await?;
            server::start(&mut channel).await?;
            match server::request(&mut channel, &Request::Health).await? {
                Response::Health {
                    name,
                    fingerprint,
                    mailboxes,
                    messages,
                    stored_bytes,
                } => println!(
                    "OK · {name} · signature {fingerprint} · {mailboxes} boîtes · {messages} enveloppes · {stored_bytes} octets"
                ),
                Response::Error { code } => {
                    return Err(format!("health check refused: {code}").into());
                }
                _ => return Err("invalid health response".into()),
            }
        }
        Command::Federation { command } => {
            let mut config = ServerConfig::load(&path)?;
            let registry_path = config.data_dir.join("federation.sqlite3");
            let mut registry = LocalRegistry::open(registry_path)?;
            match command {
                FederationCommand::Peer { command } => match command {
                    PeerCommand::Add {
                        endpoint,
                        noise_key,
                        signing_key,
                    } => {
                        if endpoint.is_empty() || endpoint.len() > 512 {
                            return Err("invalid federation peer endpoint".into());
                        }
                        let noise_bytes = hex::decode(&noise_key)?;
                        let signing_bytes = hex::decode(&signing_key)?;
                        let noise_public_key: [u8; 32] = noise_bytes
                            .try_into()
                            .map_err(|_| "Noise key must be 32 bytes")?;
                        let signing_public_key: [u8; 32] = signing_bytes
                            .try_into()
                            .map_err(|_| "signing key must be 32 bytes")?;
                        let fingerprint = registry.add_trusted_source(&signing_public_key)?;
                        if !config.federation_peers.iter().any(|peer| {
                            peer.signing_public_key_hex == hex::encode(signing_public_key)
                        }) {
                            config.federation_peers.push(FederationPeer {
                                endpoint,
                                noise_public_key_hex: hex::encode(noise_public_key),
                                signing_public_key_hex: hex::encode(signing_public_key),
                            });
                            config.save(&path)?;
                        }
                        println!("Source fédérée épinglée explicitement · {fingerprint}");
                    }
                    PeerCommand::Remove { fingerprint } => {
                        let before = config.federation_peers.len();
                        config.federation_peers.retain(|peer| {
                            hex::decode(&peer.signing_public_key_hex).map_or(true, |key| {
                                hex::encode(sha2::Sha256::digest(key)) != fingerprint
                            })
                        });
                        if before == config.federation_peers.len() {
                            return Err("federation peer not found".into());
                        }
                        registry.remove_trusted_source(&fingerprint)?;
                        config.save(&path)?;
                        println!("Source fédérée retirée · {fingerprint}");
                    }
                    PeerCommand::List => {
                        if config.federation_peers.is_empty() {
                            println!("Aucune source fédérée configurée.");
                        }
                        for peer in &config.federation_peers {
                            let key = hex::decode(&peer.signing_public_key_hex)?;
                            println!(
                                "{} · {} · Noise {}",
                                hex::encode(sha2::Sha256::digest(key)),
                                peer.endpoint,
                                peer.noise_public_key_hex
                            );
                        }
                    }
                },
                FederationCommand::Nodes => {
                    for (node, status) in registry.known_nodes()? {
                        let display_name = if node.name.is_empty() {
                            &node.operator
                        } else {
                            &node.name
                        };
                        println!(
                            "{} · {:?} · {} · {}",
                            node.node_fingerprint, status, display_name, node.endpoint
                        );
                    }
                }
                FederationCommand::Node { command } => {
                    let (fingerprint, status) = match command {
                        NodeCommand::Approve { fingerprint } => {
                            (fingerprint, TrustStatus::Approved)
                        }
                        NodeCommand::Block { fingerprint } => (fingerprint, TrustStatus::Blocked),
                    };
                    registry.set_trust(&fingerprint, status)?;
                    println!("Nœud {} · {:?}", fingerprint, status);
                }
            }
        }
        Command::Mailbox {
            command:
                MailboxCommand::Create {
                    quota_bytes,
                    retention_seconds,
                },
        } => {
            let config = ServerConfig::load(&path)?;
            let mut store = Store::open(
                config.data_dir.join("mailbox.sqlite3"),
                config.max_total_bytes,
                config.max_mailboxes,
            )?;
            let (id, write, read, bundle) = store.create_mailbox(
                quota_bytes.unwrap_or(config.default_mailbox_quota),
                retention_seconds.unwrap_or(config.default_retention_seconds),
            )?;
            println!("Boîte créée · identifiant : {id}");
            println!("Capacité de dépôt · conserver ce secret : {write}");
            println!("Capacité de récupération · transmettre au destinataire : {read}");
            println!(
                "Capacité de lecture des préclés · transmettre aux expéditeurs autorisés : {bundle}"
            );
            println!(
                "Les capacités ne sont pas stockées en clair par le serveur ; leur perte ne peut pas être réparée."
            );
        }
    }
    Ok(())
}

fn prompt(label: &str, default: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{label} [{default}] : ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

fn bounded_profile_value(
    value: String,
    label: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = value.trim().to_owned();
    if (!allow_empty && value.is_empty()) || value.len() > maximum {
        return Err(format!("{label} invalide (limite de {maximum} octets)").into());
    }
    Ok(value)
}

fn value_or_dash(value: &str) -> &str {
    if value.is_empty() { "—" } else { value }
}
