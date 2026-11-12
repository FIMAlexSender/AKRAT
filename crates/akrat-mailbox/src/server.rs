use crate::abuse::{RateLimitConfig, RateLimiter};
use crate::key_rotation::{KeyRevocation, KeyTransition, MAX_KEY_EVENTS, ServerIdentity};
use crate::{DepositReceipt, Envelope, MailboxError, ServerSigner, Store};
use akrat_core::{Identity, network};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_WIRE_ENVELOPE_BYTES: usize = 40 * 1024;
const ALPN_MARKER: &[u8] = b"AKRAT-MAILBOX/2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub version: u8,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub host_name: String,
    #[serde(default)]
    pub public_endpoint: Option<String>,
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub max_total_bytes: u64,
    pub max_mailboxes: u64,
    pub default_mailbox_quota: u64,
    pub default_retention_seconds: u64,
    pub noise_identity: Identity,
    pub signing_key_hex: String,
    #[serde(default)]
    pub receipt_signing_key_hex: String,
    #[serde(default)]
    pub key_transitions: Vec<KeyTransition>,
    #[serde(default)]
    pub key_revocations: Vec<KeyRevocation>,
    #[serde(default)]
    pub federation_peers: Vec<FederationPeer>,
    #[serde(default)]
    pub rate_limits: RateLimitConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeer {
    pub endpoint: String,
    pub noise_public_key_hex: String,
    pub signing_public_key_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Deposit {
        mailbox_id: String,
        write_capability: String,
        message_id: String,
        ciphertext: String,
    },
    Fetch {
        mailbox_id: String,
        read_capability: String,
        limit: usize,
    },
    Acknowledge {
        mailbox_id: String,
        read_capability: String,
        receipt: akrat_core::async_crypto::RecipientReceipt,
    },
    GetRecipientReceipt {
        mailbox_id: String,
        write_capability: String,
        message_id: String,
    },
    GetDeliveryFailure {
        mailbox_id: String,
        write_capability: String,
        message_id: String,
    },
    PublishBundle {
        mailbox_id: String,
        write_capability: String,
        bundle: akrat_core::async_crypto::PublishedBundle,
    },
    GetBundle {
        mailbox_id: String,
        bundle_capability: String,
    },
    FederationAnnounce {
        announcement: crate::registry::NodeAnnouncement,
    },
    FederationSnapshot,
    FederationChanges {
        after_sequence: u64,
    },
    FederationImport {
        snapshot: crate::registry::RegistrySnapshot,
    },
    FederationImportDelta {
        delta: crate::registry::RegistryDelta,
    },
    ServerIdentity,
    Health,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Deposit {
        receipt: DepositReceipt,
    },
    Fetch {
        envelopes: Vec<WireEnvelope>,
    },
    Acknowledged,
    RecipientReceipt {
        receipt: Option<akrat_core::async_crypto::RecipientReceipt>,
    },
    DeliveryFailure {
        failure: Option<crate::DeliveryFailure>,
    },
    BundlePublished,
    Bundle {
        bundle: Option<akrat_core::async_crypto::PublishedBundle>,
    },
    FederationAnnouncementAccepted,
    FederationSnapshot {
        snapshot: crate::registry::RegistrySnapshot,
    },
    FederationSnapshotImported {
        imported: usize,
    },
    FederationDelta {
        delta: crate::registry::RegistryDelta,
    },
    FederationDeltaImported {
        cursor: u64,
        imported: usize,
    },
    Health {
        name: String,
        fingerprint: String,
        mailboxes: u64,
        messages: u64,
        stored_bytes: u64,
    },
    ServerIdentity {
        identity: ServerIdentity,
    },
    Error {
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEnvelope {
    pub message_id: String,
    pub ciphertext: String,
    pub accepted_at: u64,
    pub expires_at: u64,
}

impl ServerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        path: impl AsRef<Path>,
        name: String,
        bind: SocketAddr,
        data_dir: PathBuf,
        max_total_bytes: u64,
        max_mailboxes: u64,
        default_mailbox_quota: u64,
        default_retention_seconds: u64,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if name.trim().is_empty()
            || name.len() > 128
            || max_total_bytes == 0
            || max_mailboxes == 0
            || default_mailbox_quota == 0
            || default_retention_seconds == 0
            || default_retention_seconds > crate::MAX_RETENTION_SECONDS
        {
            return Err("invalid configuration limits".into());
        }
        let root_signer = ServerSigner::generate()?;
        let receipt_signer = ServerSigner::generate()?;
        let created_at = crate::registry::unix_now()?;
        let initial_transition = KeyTransition::create(
            &root_signer,
            &root_signer,
            &receipt_signer,
            1,
            String::new(),
            created_at,
        );
        let config = Self {
            version: 1,
            name,
            description: String::new(),
            operator: String::new(),
            host_name: String::new(),
            public_endpoint: None,
            bind,
            data_dir,
            max_total_bytes,
            max_mailboxes,
            default_mailbox_quota,
            default_retention_seconds,
            noise_identity: Identity::generate("AKRAT Mailbox".into())?,
            signing_key_hex: hex::encode(root_signer.secret_bytes()),
            receipt_signing_key_hex: hex::encode(receipt_signer.secret_bytes()),
            key_transitions: vec![initial_transition],
            key_revocations: Vec::new(),
            federation_peers: Vec::new(),
            rate_limits: RateLimitConfig::default(),
        };
        config.save(path)?;
        Ok(config)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let serialized = serde_json::to_vec_pretty(self)?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, serialized)?;
        restrict_file(&temporary)?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        let valid_key =
            matches!(hex::decode(&config.signing_key_hex),Ok(bytes) if bytes.len() == 32);
        let valid_receipt_key = config.receipt_signing_key_hex.is_empty()
            || matches!(hex::decode(&config.receipt_signing_key_hex), Ok(bytes) if bytes.len() == 32);
        if config.version != 1
            || config.name.trim().is_empty()
            || config.name.len() > 128
            || config.description.len() > 280
            || config.operator.len() > 128
            || config.host_name.len() > 128
            || config.public_endpoint.as_ref().is_some_and(|endpoint| {
                endpoint.is_empty() || endpoint.len() > 512
            })
            || config.noise_identity.public_key().len() != 32
            || !valid_key
            || !valid_receipt_key
            || config.key_transitions.len() > MAX_KEY_EVENTS
            || config.key_revocations.len() > MAX_KEY_EVENTS
            || config.federation_peers.len() > 64
            || config.federation_peers.iter().any(|peer| {
                peer.endpoint.is_empty()
                    || peer.endpoint.len() > 512
                    || !matches!(hex::decode(&peer.noise_public_key_hex), Ok(key) if key.len() == 32)
                    || !matches!(hex::decode(&peer.signing_public_key_hex), Ok(key) if key.len() == 32)
            })
            || config.rate_limits.validate().is_err()
        {
            return Err("unsupported or invalid server configuration".into());
        }
        let root = config.root_signer()?;
        let active = config.receipt_signer()?;
        let identity = config.server_identity(&root, &active);
        identity
            .verify(&root.public_key(), 0, 0, crate::registry::unix_now()?)
            .map_err(|_| "invalid server signing-key continuity history")?;
        Ok(config)
    }

    pub fn server_fingerprint(&self) -> Result<String, MailboxError> {
        Ok(self.root_signer()?.fingerprint())
    }

    pub fn root_signer(&self) -> Result<ServerSigner, MailboxError> {
        ServerSigner::from_bytes(
            &hex::decode(&self.signing_key_hex).map_err(|_| MailboxError::InvalidKey)?,
        )
    }

    pub fn receipt_signer(&self) -> Result<ServerSigner, MailboxError> {
        let value = if self.receipt_signing_key_hex.is_empty() {
            &self.signing_key_hex
        } else {
            &self.receipt_signing_key_hex
        };
        ServerSigner::from_bytes(&hex::decode(value).map_err(|_| MailboxError::InvalidKey)?)
    }

    pub fn server_identity(&self, root: &ServerSigner, active: &ServerSigner) -> ServerIdentity {
        ServerIdentity {
            root_public_key: hex::encode(root.public_key()),
            active_public_key: hex::encode(active.public_key()),
            generation: self.key_transitions.len() as u64,
            revocation_sequence: self.key_revocations.last().map_or(0, |item| item.sequence),
            transitions: self.key_transitions.clone(),
            revocations: self.key_revocations.clone(),
        }
    }

    pub fn rotate_receipt_key(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        if self.key_transitions.len() >= MAX_KEY_EVENTS {
            return Err(
                "server key history is full; export or archive the history before rotating".into(),
            );
        }
        let root = self.root_signer()?;
        let previous = self.receipt_signer()?;
        let next = ServerSigner::generate()?;
        let previous_hash = self
            .key_transitions
            .last()
            .map_or_else(String::new, |item| item.digest());
        let transition = KeyTransition::create(
            &root,
            &previous,
            &next,
            self.key_transitions.len() as u64 + 1,
            previous_hash,
            crate::registry::unix_now()?,
        );
        let fingerprint = next.fingerprint();
        self.key_transitions.push(transition);
        self.receipt_signing_key_hex = hex::encode(next.secret_bytes());
        Ok(fingerprint)
    }

    pub fn revoke_receipt_key(
        &mut self,
        fingerprint: String,
        reason: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.key_revocations.len() >= MAX_KEY_EVENTS {
            return Err("server revocation history is full".into());
        }
        let reason = reason.trim().to_owned();
        if reason.is_empty() || reason.len() > 256 {
            return Err("revocation reason must contain 1 to 256 bytes".into());
        }
        let root = self.root_signer()?;
        let active = self.receipt_signer()?;
        if fingerprint == root.fingerprint() {
            return Err("the continuity root cannot be revoked from this configuration; re-pin it out of band if compromised".into());
        }
        if fingerprint == active.fingerprint() {
            return Err("rotate the active receipt key before revoking it".into());
        }
        let history = self.server_identity(&root, &active);
        let public = history
            .verify(&root.public_key(), 0, 0, crate::registry::unix_now()?)
            .map_err(|_| "server key history is invalid")?;
        if !public
            .iter()
            .any(|key| hex::encode(sha2::Sha256::digest(key)) == fingerprint)
            || self
                .key_revocations
                .iter()
                .any(|item| item.key_fingerprint == fingerprint)
        {
            return Err("server signing key fingerprint is unknown or already revoked".into());
        }
        let sequence = self
            .key_revocations
            .last()
            .map_or(1, |item| item.sequence.saturating_add(1));
        self.key_revocations.push(KeyRevocation::create(
            &root,
            fingerprint,
            sequence,
            crate::registry::unix_now()?,
            reason,
        ));
        Ok(())
    }
}

pub async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(&config.data_dir)?;
    let db_path = config.data_dir.join("mailbox.sqlite3");
    let store = Store::open(db_path, config.max_total_bytes, config.max_mailboxes)?;
    let store = Arc::new(Mutex::new(store));
    let signer = Arc::new(config.receipt_signer()?);
    let listener = TcpListener::bind(config.bind).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let rate_limiter = Arc::new(RateLimiter::new(config.rate_limits.clone()));
    let config = Arc::new(config);
    let expiry_store = store.clone();
    let expiry_signer = signer.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Ok(mut guard) = expiry_store.lock() {
                let _ = guard.expire(&expiry_signer);
            }
        }
    });
    let registry = Arc::new(Mutex::new(crate::registry::LocalRegistry::open(
        config.data_dir.join("federation.sqlite3"),
    )?));
    if let Ok(mut registry) = registry.lock() {
        for peer in &config.federation_peers {
            let public_key: [u8; 32] = hex::decode(&peer.signing_public_key_hex)?
                .try_into()
                .map_err(|_| "invalid peer signing key")?;
            registry.add_trusted_source(&public_key)?;
        }
        publish_self_announcement(&config, &mut registry)?;
    }
    let federation_config = config.clone();
    let federation_registry = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            synchronize_federation(&federation_config, &federation_registry).await;
        }
    });
    println!(
        "AKRAT Mailbox '{}' écoute sur {}",
        config.name,
        listener.local_addr()?
    );
    println!(
        "Empreinte serveur · Noise {}",
        hex::encode(config.noise_identity.public_key())
    );
    println!(
        "Empreinte d'identité · Ed25519 {}",
        config.server_fingerprint()?
    );
    println!("Empreinte des reçus · Ed25519 {}", signer.fingerprint());
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            signal = wait_shutdown_signal() => {
                signal?;
                break;
            }
            accepted = listener.accept() => {
                let (stream,remote) = accepted?;
                let permit = match permits.clone().try_acquire_owned() { Ok(permit) => permit, Err(_) => { drop(stream); continue; } };
                let source_permit = match rate_limiter.try_acquire_source(remote.ip()) { Some(permit) => permit, None => { drop(stream); continue; } };
                let store = store.clone();
                let signer = signer.clone();
                let config = config.clone();
                let registry = registry.clone();
                let rate_limiter = rate_limiter.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _source_permit = source_permit;
                    let _ = handle(stream,remote,store,signer,config,registry,rate_limiter).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    drop(listener);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await?;
    println!("Arrêt propre du service.");
    Ok(())
}

fn publish_self_announcement(
    config: &ServerConfig,
    registry: &mut crate::registry::LocalRegistry,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(endpoint) = config.public_endpoint.as_ref() else {
        return Ok(());
    };
    let signer = ServerSigner::from_bytes(&hex::decode(&config.signing_key_hex)?)?;
    let now = crate::registry::unix_now()?;
    let fingerprint = signer.fingerprint();
    if registry
        .known_nodes()?
        .into_iter()
        .map(|(announcement, _)| announcement)
        .find(|announcement| announcement.node_fingerprint == fingerprint)
        .is_some_and(|announcement| {
            announcement.version == 3
                && announcement.name == config.name
                && announcement.description == config.description
                && announcement.operator == config.operator
                && announcement.host_name == config.host_name
                && announcement.endpoint == *endpoint
                && announcement.noise_public_key == hex::encode(config.noise_identity.public_key())
                && announcement
                    .server_identity
                    .as_ref()
                    .is_some_and(|identity| {
                        identity.generation == config.key_transitions.len() as u64
                            && identity.revocation_sequence
                                == config
                                    .key_revocations
                                    .last()
                                    .map_or(0, |item| item.sequence)
                            && identity.active_public_key
                                == config.receipt_signer().map_or_else(
                                    |_| String::new(),
                                    |signer| hex::encode(signer.public_key()),
                                )
                    })
                && announcement.expires_at > now.saturating_add(24 * 60 * 60)
        })
    {
        return Ok(());
    }
    let sequence = registry.next_sequence(&fingerprint)?;
    let root = config.root_signer()?;
    let active = config.receipt_signer()?;
    let identity = config.server_identity(&root, &active);
    let announcement = crate::registry::NodeAnnouncement::create_profile_with_identity(
        &root,
        config.noise_identity.public_key(),
        endpoint.clone(),
        config.operator.clone(),
        config.name.clone(),
        config.description.clone(),
        config.host_name.clone(),
        1,
        1,
        vec![
            "mailbox".into(),
            "async-messaging".into(),
            "registry".into(),
        ],
        config.max_total_bytes,
        sequence,
        now,
        now.saturating_add(crate::registry::MAX_ANNOUNCEMENT_LIFETIME),
        identity,
    )?;
    registry.publish_announcement(&announcement, now)?;
    println!(
        "Annonce fédérée publiée · {} · {}",
        announcement.name, announcement.node_fingerprint
    );
    Ok(())
}

async fn synchronize_federation(
    config: &ServerConfig,
    registry: &Arc<Mutex<crate::registry::LocalRegistry>>,
) {
    for peer in &config.federation_peers {
        let Ok(remote_signing_key): Result<[u8; 32], _> = hex::decode(&peer.signing_public_key_hex)
            .and_then(|key| {
                key.try_into()
                    .map_err(|_| hex::FromHexError::InvalidStringLength)
            })
        else {
            continue;
        };
        let Ok(remote_noise_key) = hex::decode(&peer.noise_public_key_hex) else {
            continue;
        };
        let Ok(addresses) = tokio::net::lookup_host(&peer.endpoint).await else {
            continue;
        };
        let Some(address) = addresses.into_iter().next() else {
            continue;
        };
        let Ok(Ok(pending)) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let stream = TcpStream::connect(address).await?;
            network::initiate(stream, &config.noise_identity).await
        })
        .await
        else {
            continue;
        };
        let Ok(mut channel) = pending.verify_peer(&remote_noise_key) else {
            continue;
        };
        let local_signer = match hex::decode(&config.signing_key_hex)
            .map_err(|_| ())
            .and_then(|key| ServerSigner::from_bytes(&key).map_err(|_| ()))
        {
            Ok(signer) => signer,
            Err(()) => continue,
        };
        let remote_fingerprint = hex::encode(sha2::Sha256::digest(remote_signing_key));
        let exchange = async {
            channel
                .send(ALPN_MARKER)
                .await
                .map_err(|error| error.to_string())?;
            for _ in 0..64 {
                let cursor = registry
                    .lock()
                    .map_err(|_| "registry unavailable")?
                    .federation_cursor(&remote_fingerprint)
                    .map_err(|error| error.to_string())?;
                let delta = match request(
                    &mut channel,
                    &Request::FederationChanges {
                        after_sequence: cursor,
                    },
                )
                .await
                .map_err(|error| error.to_string())?
                {
                    Response::FederationDelta { delta } => delta,
                    _ => return Err("peer did not return federation changes".to_owned()),
                };
                let has_more = delta.has_more;
                let next_cursor = delta.cursor;
                registry
                    .lock()
                    .map_err(|_| "registry unavailable")?
                    .import_delta(&delta, crate::registry::unix_now().unwrap_or_default())
                    .map_err(|error| error.to_string())?;
                if !has_more || next_cursor == cursor {
                    break;
                }
            }
            for _ in 0..64 {
                let cursor = registry
                    .lock()
                    .map_err(|_| "registry unavailable")?
                    .outbound_cursor(&remote_fingerprint)
                    .map_err(|error| error.to_string())?;
                let delta = registry
                    .lock()
                    .map_err(|_| "registry unavailable")?
                    .signed_delta(
                        &local_signer,
                        cursor,
                        crate::registry::unix_now().unwrap_or_default(),
                    )
                    .map_err(|error| error.to_string())?;
                if delta.cursor == cursor {
                    break;
                }
                let next_cursor = delta.cursor;
                match request(&mut channel, &Request::FederationImportDelta { delta })
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Response::FederationDeltaImported { cursor, .. } if cursor == next_cursor => {
                        registry
                            .lock()
                            .map_err(|_| "registry unavailable")?
                            .set_outbound_cursor(&remote_fingerprint, cursor)
                            .map_err(|error| error.to_string())?;
                    }
                    _ => return Err("peer rejected federation changes".to_owned()),
                }
            }
            Ok::<(), String>(())
        };
        match tokio::time::timeout(std::time::Duration::from_secs(10), exchange).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("Fédération · {} · {error}", peer.endpoint),
            Err(_) => eprintln!("Fédération · {} · délai dépassé", peer.endpoint),
        }
    }
}

#[cfg(unix)]
async fn wait_shutdown_signal() -> std::io::Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

async fn handle(
    stream: TcpStream,
    remote: SocketAddr,
    store: Arc<Mutex<Store>>,
    signer: Arc<ServerSigner>,
    config: Arc<ServerConfig>,
    registry: Arc<Mutex<crate::registry::LocalRegistry>>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pending = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        network::respond(stream, &config.noise_identity),
    )
    .await??;
    let peer_key = pending.remote_public_key().to_vec();
    let mut channel = pending.verify_peer(&peer_key)?;
    let marker =
        tokio::time::timeout(std::time::Duration::from_secs(15), channel.receive()).await??;
    if marker.as_slice() != ALPN_MARKER {
        return Err("invalid protocol marker".into());
    }
    loop {
        let request = match tokio::time::timeout(
            std::time::Duration::from_secs(120),
            channel.receive(),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) | Err(_) => break,
        };
        if request.len() > 60 * 1024 {
            break;
        }
        let parsed_request = serde_json::from_slice::<Request>(&request);
        if !rate_limiter.allow_request(
            remote.ip(),
            &peer_key,
            parsed_request.as_ref().ok(),
            request.len(),
        ) {
            let bytes = serde_json::to_vec(&Response::Error {
                code: "rate_limited".into(),
            })?;
            channel.send(&bytes).await?;
            break;
        }
        let response = match parsed_request {
            Ok(request) => dispatch(request, &store, &signer, &config, &registry),
            Err(_) => Response::Error {
                code: "invalid_request".into(),
            },
        };
        let bytes = serde_json::to_vec(&response)?;
        if bytes.len() > 60 * 1024 {
            break;
        }
        channel.send(&bytes).await?;
    }
    Ok(())
}

fn dispatch(
    request: Request,
    store: &Arc<Mutex<Store>>,
    signer: &ServerSigner,
    config: &ServerConfig,
    registry: &Arc<Mutex<crate::registry::LocalRegistry>>,
) -> Response {
    let mut guard = match store.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return Response::Error {
                code: "storage_unavailable".into(),
            };
        }
    };
    match request {
        Request::Deposit {
            mailbox_id,
            write_capability,
            message_id,
            ciphertext,
        } => {
            let bytes = match STANDARD.decode(ciphertext) {
                Ok(bytes) if bytes.len() <= MAX_WIRE_ENVELOPE_BYTES => bytes,
                _ => {
                    return Response::Error {
                        code: "invalid_envelope".into(),
                    };
                }
            };
            match guard.deposit(&mailbox_id, &write_capability, &message_id, &bytes, signer) {
                Ok(receipt) => Response::Deposit { receipt },
                Err(error) => error_response(error),
            }
        }
        Request::Fetch {
            mailbox_id,
            read_capability,
            limit,
        } => match guard.fetch(&mailbox_id, &read_capability, limit) {
            Ok(items) => {
                let mut envelopes = Vec::new();
                for item in items {
                    let candidate = to_wire(item);
                    envelopes.push(candidate);
                    let response = Response::Fetch {
                        envelopes: envelopes.clone(),
                    };
                    if serde_json::to_vec(&response).map_or(true, |bytes| bytes.len() > 60 * 1024) {
                        envelopes.pop();
                        break;
                    }
                }
                Response::Fetch { envelopes }
            }
            Err(error) => error_response(error),
        },
        Request::Acknowledge {
            mailbox_id,
            read_capability,
            receipt,
        } => match guard.acknowledge_with_receipt(&mailbox_id, &read_capability, &receipt) {
            Ok(()) => Response::Acknowledged,
            Err(error) => error_response(error),
        },
        Request::GetRecipientReceipt {
            mailbox_id,
            write_capability,
            message_id,
        } => match guard.get_recipient_receipt(&mailbox_id, &write_capability, &message_id) {
            Ok(receipt) => Response::RecipientReceipt { receipt },
            Err(error) => error_response(error),
        },
        Request::GetDeliveryFailure {
            mailbox_id,
            write_capability,
            message_id,
        } => match guard
            .expire(signer)
            .and_then(|_| guard.get_delivery_failure(&mailbox_id, &write_capability, &message_id))
        {
            Ok(failure) => Response::DeliveryFailure { failure },
            Err(error) => error_response(error),
        },
        Request::PublishBundle {
            mailbox_id,
            write_capability,
            bundle,
        } => match guard.publish_bundle(&mailbox_id, &write_capability, &bundle) {
            Ok(()) => Response::BundlePublished,
            Err(error) => error_response(error),
        },
        Request::GetBundle {
            mailbox_id,
            bundle_capability,
        } => match guard.get_bundle(&mailbox_id, &bundle_capability) {
            Ok(bundle) => Response::Bundle { bundle },
            Err(error) => error_response(error),
        },
        Request::FederationAnnounce { announcement } => match registry.lock() {
            Ok(mut registry) => match registry.publish_announcement(
                &announcement,
                crate::registry::unix_now().unwrap_or_default(),
            ) {
                Ok(()) => Response::FederationAnnouncementAccepted,
                Err(_) => Response::Error {
                    code: "invalid_announcement".into(),
                },
            },
            Err(_) => Response::Error {
                code: "registry_unavailable".into(),
            },
        },
        Request::FederationSnapshot => match (config.root_signer(), registry.lock()) {
            (Ok(root), Ok(mut registry)) => match registry
                .signed_snapshot(&root, crate::registry::unix_now().unwrap_or_default())
            {
                Ok(snapshot) => Response::FederationSnapshot { snapshot },
                Err(_) => Response::Error {
                    code: "registry_unavailable".into(),
                },
            },
            _ => Response::Error {
                code: "registry_unavailable".into(),
            },
        },
        Request::FederationChanges { after_sequence } => {
            match (config.root_signer(), registry.lock()) {
                (Ok(root), Ok(registry)) => match registry.signed_delta(
                    &root,
                    after_sequence,
                    crate::registry::unix_now().unwrap_or_default(),
                ) {
                    Ok(delta) => Response::FederationDelta { delta },
                    Err(_) => Response::Error {
                        code: "registry_unavailable".into(),
                    },
                },
                _ => Response::Error {
                    code: "registry_unavailable".into(),
                },
            }
        }
        Request::FederationImport { snapshot } => match registry.lock() {
            Ok(mut registry) => match registry
                .import_snapshot(&snapshot, crate::registry::unix_now().unwrap_or_default())
            {
                Ok(imported) => Response::FederationSnapshotImported { imported },
                Err(crate::registry::RegistryError::Untrusted) => Response::Error {
                    code: "untrusted_federation_source".into(),
                },
                Err(_) => Response::Error {
                    code: "invalid_federation_snapshot".into(),
                },
            },
            Err(_) => Response::Error {
                code: "registry_unavailable".into(),
            },
        },
        Request::FederationImportDelta { delta } => match registry.lock() {
            Ok(mut registry) => {
                let cursor = delta.cursor;
                match registry.import_delta(&delta, crate::registry::unix_now().unwrap_or_default())
                {
                    Ok(imported) => Response::FederationDeltaImported { cursor, imported },
                    Err(crate::registry::RegistryError::Untrusted) => Response::Error {
                        code: "untrusted_federation_source".into(),
                    },
                    Err(_) => Response::Error {
                        code: "invalid_federation_delta".into(),
                    },
                }
            }
            Err(_) => Response::Error {
                code: "registry_unavailable".into(),
            },
        },
        Request::Health => match guard.status() {
            Ok((mailboxes, messages, stored_bytes)) => Response::Health {
                name: config.name.clone(),
                fingerprint: config
                    .server_fingerprint()
                    .unwrap_or_else(|_| signer.fingerprint()),
                mailboxes,
                messages,
                stored_bytes,
            },
            Err(error) => error_response(error),
        },
        Request::ServerIdentity => match (config.root_signer(), config.receipt_signer()) {
            (Ok(root), Ok(active)) => Response::ServerIdentity {
                identity: config.server_identity(&root, &active),
            },
            _ => Response::Error {
                code: "identity_unavailable".into(),
            },
        },
    }
}

fn error_response(error: MailboxError) -> Response {
    let code = match error {
        MailboxError::Unauthorized => "unauthorized",
        MailboxError::Quota => "quota_exceeded",
        MailboxError::NotFound => "not_found",
        MailboxError::Conflict => "message_conflict",
        MailboxError::InvalidEnvelope => "invalid_envelope",
        _ => "storage_unavailable",
    };
    Response::Error { code: code.into() }
}

fn to_wire(value: Envelope) -> WireEnvelope {
    WireEnvelope {
        message_id: value.message_id,
        ciphertext: STANDARD.encode(value.bytes),
        accepted_at: value.accepted_at,
        expires_at: value.expires_at,
    }
}

fn restrict_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub async fn connect(
    address: SocketAddr,
    identity: &Identity,
    expected_noise_public_key: &[u8],
) -> Result<akrat_core::network::SecureChannel<TcpStream>, Box<dyn std::error::Error>> {
    let stream = TcpStream::connect(address).await?;
    let pending = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        network::initiate(stream, identity),
    )
    .await??;
    let channel = pending.verify_peer(expected_noise_public_key)?;
    Ok(channel)
}

pub async fn request(
    channel: &mut akrat_core::network::SecureChannel<TcpStream>,
    request: &Request,
) -> Result<Response, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > 60 * 1024 {
        return Err("request exceeds maximum frame size".into());
    }
    channel.send(&bytes).await?;
    let response = channel.receive().await?;
    Ok(serde_json::from_slice(&response)?)
}

pub async fn start(
    channel: &mut akrat_core::network::SecureChannel<TcpStream>,
) -> Result<(), Box<dyn std::error::Error>> {
    channel.send(ALPN_MARKER).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{make_receipt, verify_receipt};
    use akrat_core::{
        AsyncProtocolState, DeliveryState, Identity, StoredMessage, VaultData, load_vault,
        save_vault,
    };
    use sha2::Digest;

    #[test]
    fn key_rotation_survives_restart_preserves_receipt_history_and_applies_revocation() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("server.json");
        let mut config = ServerConfig::initialize(
            &path,
            "rotation-test".into(),
            "127.0.0.1:47475".parse().expect("bind address"),
            directory.path().join("data"),
            1024 * 1024,
            4,
            64 * 1024,
            3600,
        )
        .expect("initialize");
        let root = config.root_signer().expect("root");
        let previous = config.receipt_signer().expect("initial receipt key");
        let previous_fingerprint = previous.fingerprint();
        let now = crate::registry::unix_now().expect("time");
        let digest = sha2::Sha256::digest(b"retained receipt");
        let previous_receipt = make_receipt(
            &previous,
            "mailbox-test",
            "message-test",
            &digest,
            now,
            now + 3600,
        );
        assert!(verify_receipt(&previous_receipt, &previous.public_key()).expect("old receipt"));

        let rotated_fingerprint = config.rotate_receipt_key().expect("rotate");
        config.save(&path).expect("persist rotation");
        let mut loaded = ServerConfig::load(&path).expect("load rotated server");
        assert_eq!(
            loaded.server_fingerprint().expect("stable root"),
            root.fingerprint()
        );
        assert_eq!(
            loaded.receipt_signer().expect("active key").fingerprint(),
            rotated_fingerprint
        );
        let identity = loaded.server_identity(
            &loaded.root_signer().expect("root"),
            &loaded.receipt_signer().expect("active"),
        );
        let accepted_keys = identity
            .verify(&root.public_key(), 1, 0, now)
            .expect("verify continuity after restart");
        assert!(accepted_keys.contains(&previous.public_key()));
        assert!(accepted_keys.contains(&loaded.receipt_signer().expect("active").public_key()));
        assert!(
            verify_receipt(&previous_receipt, &previous.public_key())
                .expect("old receipt remains valid")
        );

        loaded
            .revoke_receipt_key(previous_fingerprint.clone(), "compromised test key".into())
            .expect("revoke old key");
        loaded.save(&path).expect("persist revocation");
        let mut loaded = ServerConfig::load(&path).expect("load revocation");
        let identity = loaded.server_identity(
            &loaded.root_signer().expect("root"),
            &loaded.receipt_signer().expect("active"),
        );
        let accepted_keys = identity
            .verify(&root.public_key(), 1, 1, now)
            .expect("verify revocation after restart");
        assert!(!accepted_keys.contains(&previous.public_key()));
        assert!(accepted_keys.contains(&loaded.receipt_signer().expect("active").public_key()));
        assert!(
            loaded
                .revoke_receipt_key(rotated_fingerprint, "active key".into())
                .is_err()
        );
    }

    #[test]
    fn interrupted_or_forged_key_rotation_does_not_replace_trusted_configuration() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("server.json");
        let mut config = ServerConfig::initialize(
            &path,
            "rotation-interruption-test".into(),
            "127.0.0.1:47475".parse().expect("bind address"),
            directory.path().join("data"),
            1024 * 1024,
            4,
            64 * 1024,
            3600,
        )
        .expect("initialize");
        let old_active = config
            .receipt_signer()
            .expect("initial active")
            .fingerprint();
        config.rotate_receipt_key().expect("prepare rotation");
        let still_persisted = ServerConfig::load(&path).expect("old config remains valid");
        assert_eq!(
            still_persisted
                .receipt_signer()
                .expect("old active")
                .fingerprint(),
            old_active
        );

        config.key_transitions[1].new_public_key =
            hex::encode(ServerSigner::generate().expect("forged key").public_key());
        config.save(&path).expect("write corrupted history");
        assert!(ServerConfig::load(&path).is_err());
    }

    #[test]
    fn public_profile_is_signed_persisted_and_renames_without_changing_identity() {
        let directory = tempfile::tempdir().expect("directory");
        let config = ServerConfig {
            version: 1,
            name: "Le Refuge".into(),
            description: "Boîte communautaire".into(),
            operator: "Collectif".into(),
            host_name: "Équipe locale".into(),
            public_endpoint: Some("mail.example.test:47475".into()),
            bind: "127.0.0.1:0".parse().expect("address"),
            data_dir: directory.path().to_path_buf(),
            max_total_bytes: 1024 * 1024,
            max_mailboxes: 4,
            default_mailbox_quota: 1024,
            default_retention_seconds: 3600,
            noise_identity: Identity::generate("server".into()).expect("server identity"),
            signing_key_hex: hex::encode(ServerSigner::generate().expect("signer").secret_bytes()),
            receipt_signing_key_hex: String::new(),
            key_transitions: Vec::new(),
            key_revocations: Vec::new(),
            federation_peers: Vec::new(),
            rate_limits: RateLimitConfig::default(),
        };
        let fingerprint = config.server_fingerprint().expect("server fingerprint");
        let mut registry =
            crate::registry::LocalRegistry::open(directory.path().join("federation.sqlite3"))
                .expect("registry");
        publish_self_announcement(&config, &mut registry).expect("publish initial profile");
        let first = registry
            .known_nodes()
            .expect("known nodes")
            .into_iter()
            .next()
            .expect("local announcement")
            .0;
        assert_eq!(first.name, "Le Refuge");
        assert!(
            first
                .verify(crate::registry::unix_now().expect("time"))
                .is_ok()
        );

        let mut renamed = config;
        renamed.name = "La Citadelle".into();
        publish_self_announcement(&renamed, &mut registry).expect("publish renamed profile");
        let updated = registry
            .known_nodes()
            .expect("known nodes")
            .into_iter()
            .next()
            .expect("renamed announcement")
            .0;
        assert_eq!(updated.name, "La Citadelle");
        assert_eq!(updated.sequence, first.sequence + 1);
        assert_eq!(updated.node_fingerprint, fingerprint);
        assert!(
            updated
                .verify(crate::registry::unix_now().expect("time"))
                .is_ok()
        );
        assert_eq!(
            updated
                .server_identity
                .as_ref()
                .expect("federated key continuity")
                .generation,
            0
        );
        let mut rotated = renamed;
        rotated.rotate_receipt_key().expect("rotate receipt signer");
        publish_self_announcement(&rotated, &mut registry).expect("publish federated key rotation");
        let rotated_announcement = registry
            .known_nodes()
            .expect("known nodes after rotation")
            .into_iter()
            .next()
            .expect("rotated local announcement")
            .0;
        let identity = rotated_announcement
            .server_identity
            .as_ref()
            .expect("federated rotation chain");
        assert_eq!(identity.generation, 1);
        assert_eq!(
            identity.active_public_key,
            hex::encode(rotated.receipt_signer().unwrap().public_key())
        );
        assert!(
            rotated_announcement
                .verify(crate::registry::unix_now().expect("time"))
                .is_ok()
        );
        let older = updated;
        assert!(matches!(
            registry.publish_announcement(&older, crate::registry::unix_now().expect("time")),
            Err(crate::registry::RegistryError::Rollback)
        ));
    }

    #[tokio::test]
    async fn offline_pqxdh_message_survives_mailbox_deposit_and_recipient_restart() {
        let directory = tempfile::tempdir().expect("directory");
        let config = ServerConfig {
            version: 1,
            name: "test-node".into(),
            description: String::new(),
            operator: String::new(),
            host_name: String::new(),
            public_endpoint: None,
            bind: "127.0.0.1:0".parse().expect("address"),
            data_dir: directory.path().to_path_buf(),
            max_total_bytes: 1024 * 1024,
            max_mailboxes: 4,
            default_mailbox_quota: 1024,
            default_retention_seconds: 3600,
            noise_identity: Identity::generate("server".into()).expect("server identity"),
            signing_key_hex: hex::encode(ServerSigner::generate().expect("signer").secret_bytes()),
            receipt_signing_key_hex: String::new(),
            key_transitions: Vec::new(),
            key_revocations: Vec::new(),
            federation_peers: Vec::new(),
            rate_limits: RateLimitConfig::default(),
        };
        let store = Store::open(
            directory.path().join("db.sqlite3"),
            config.max_total_bytes,
            config.max_mailboxes,
        )
        .expect("store");
        let store = Arc::new(Mutex::new(store));
        let signer = Arc::new(
            ServerSigner::from_bytes(&hex::decode(&config.signing_key_hex).expect("key"))
                .expect("signer"),
        );
        let (mailbox_id, write_capability, read_capability, bundle_capability) = store
            .lock()
            .expect("lock")
            .create_mailbox(64 * 1024, 3600)
            .expect("mailbox");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server_config = Arc::new(config);
        let server_public = server_config.noise_identity.public_key().to_vec();
        let task_config = server_config.clone();
        let server_store = store.clone();
        let server_signer = signer.clone();
        let registry_path = directory.path().join("test-registry.sqlite3");
        let task = tokio::spawn(async move {
            let (stream, remote) = listener.accept().await.expect("accept");
            let registry = Arc::new(Mutex::new(
                crate::registry::LocalRegistry::open(registry_path).expect("registry"),
            ));
            handle(
                stream,
                remote,
                server_store,
                server_signer,
                task_config,
                registry,
                Arc::new(RateLimiter::new(RateLimitConfig::default())),
            )
            .await
            .expect("server");
        });
        let client = Identity::generate("client".into()).expect("client identity");
        let mut channel = connect(address, &client, &server_public)
            .await
            .expect("pinned connection");
        start(&mut channel).await.expect("protocol start");
        let bob = Identity::generate("Bob mailbox client".into()).expect("Bob identity");
        let (bundle, bob_protocol_state) = akrat_core::async_crypto::publish_bundle(&bob, &[])
            .await
            .expect("Bob pre-key bundle");
        let bob_vault = directory.path().join("bob-vault.akrat");
        let mut bob_data = VaultData {
            identities: vec![bob.detached_copy()],
            async_protocol_states: vec![AsyncProtocolState {
                identity_id: bob.id.clone(),
                state: bob_protocol_state,
            }],
            ..VaultData::default()
        };
        save_vault(&bob_vault, &mut bob_data, "Bob test phrase").expect("persist Bob keys");
        let result = request(
            &mut channel,
            &Request::PublishBundle {
                mailbox_id: mailbox_id.clone(),
                write_capability: write_capability.clone(),
                bundle: bundle.clone(),
            },
        )
        .await
        .expect("publish over the network");
        assert!(matches!(result, Response::BundlePublished));
        let result = request(
            &mut channel,
            &Request::GetBundle {
                mailbox_id: mailbox_id.clone(),
                bundle_capability: bundle_capability.clone(),
            },
        )
        .await
        .expect("fetch bundle over the network");
        let bundle = match result {
            Response::Bundle {
                bundle: Some(value),
            } => value,
            other => panic!("unexpected bundle response: {other:?}"),
        };
        let message_text = b"This message was encrypted while Bob was offline.";
        let (ciphertext, _alice_state) = akrat_core::async_crypto::encrypt(
            &client,
            &[],
            bob.public_key(),
            &bundle,
            message_text,
        )
        .await
        .expect("Alice encrypts for Bob");
        drop(bob);
        let ciphertext = serde_json::to_vec(&ciphertext).expect("serialize ciphertext");
        assert!(
            !ciphertext
                .windows(message_text.len())
                .any(|window| window == message_text)
        );
        let result = request(
            &mut channel,
            &Request::Deposit {
                mailbox_id: mailbox_id.clone(),
                write_capability: write_capability.clone(),
                message_id: "0123456789abcdef".into(),
                ciphertext: STANDARD.encode(&ciphertext),
            },
        )
        .await
        .expect("deposit");
        let receipt = match result {
            Response::Deposit { receipt } => receipt,
            other => panic!("unexpected response: {other:?}"),
        };
        assert!(
            crate::verify_receipt(&receipt, &signer.public_key()).expect("receipt verification")
        );
        let result = request(
            &mut channel,
            &Request::Fetch {
                mailbox_id: mailbox_id.clone(),
                read_capability: read_capability.clone(),
                limit: 8,
            },
        )
        .await
        .expect("fetch");
        let encrypted = match result {
            Response::Fetch { mut envelopes } => {
                assert_eq!(envelopes.len(), 1);
                STANDARD
                    .decode(envelopes.remove(0).ciphertext)
                    .expect("decode")
            }
            other => panic!("unexpected response: {other:?}"),
        };
        let signal_message: akrat_core::async_crypto::AsyncCiphertext =
            serde_json::from_slice(&encrypted).expect("parse signal ciphertext");
        let mut bob_data = load_vault(&bob_vault, "Bob test phrase").expect("Bob returns online");
        let bob = bob_data.identities[0].detached_copy();
        let bob_state = bob_data.async_protocol_states[0].state.clone();
        let (plaintext, updated_bob_state) = akrat_core::async_crypto::decrypt(
            &bob,
            &bob_state,
            client.public_key(),
            &signal_message,
        )
        .await
        .expect("Bob authenticates and decrypts");
        assert_eq!(plaintext, message_text);
        bob_data.async_protocol_states[0].state = updated_bob_state;
        bob_data.messages.push(StoredMessage {
            conversation: format!("{}:{}", bob.id, client.fingerprint()),
            id: "0123456789abcdef".into(),
            outgoing: false,
            text: String::from_utf8(plaintext).expect("UTF-8 message"),
            delivery: DeliveryState::Received,
            timestamp: 1,
            delivery_events: Vec::new(),
            received_ciphertext_sha256: None,
        });
        save_vault(&bob_vault, &mut bob_data, "Bob test phrase")
            .expect("persist authenticated message before acknowledgement");
        assert_eq!(
            load_vault(&bob_vault, "Bob test phrase")
                .expect("reopen Bob vault")
                .messages[0]
                .text,
            String::from_utf8_lossy(message_text)
        );
        let result = request(
            &mut channel,
            &Request::Acknowledge {
                mailbox_id: mailbox_id.clone(),
                read_capability: read_capability.clone(),
                receipt: akrat_core::async_crypto::RecipientReceipt::create(
                    &bob,
                    client.public_key(),
                    mailbox_id.clone(),
                    "0123456789abcdef".into(),
                    hex::encode(sha2::Sha256::digest(&encrypted)),
                    crate::registry::unix_now().expect("system time"),
                )
                .expect("signed recipient receipt"),
            },
        )
        .await
        .expect("acknowledge after persistence");
        assert!(matches!(result, Response::Acknowledged));
        let result = request(
            &mut channel,
            &Request::GetRecipientReceipt {
                mailbox_id: mailbox_id.clone(),
                write_capability: write_capability.clone(),
                message_id: "0123456789abcdef".into(),
            },
        )
        .await
        .expect("query recipient receipt");
        let returned = match result {
            Response::RecipientReceipt {
                receipt: Some(receipt),
            } => receipt,
            other => panic!("unexpected recipient receipt response: {other:?}"),
        };
        assert!(returned.verify().expect("recipient signature"));
        assert_eq!(returned.recipient_public_key, bob.public_key());
        assert_eq!(returned.sender_public_key, client.public_key());
        let result = request(
            &mut channel,
            &Request::Fetch {
                mailbox_id,
                read_capability,
                limit: 8,
            },
        )
        .await
        .expect("confirm mailbox cleanup");
        assert!(matches!(result, Response::Fetch { envelopes } if envelopes.is_empty()));
        drop(channel);
        task.await.expect("server task");
    }
}
