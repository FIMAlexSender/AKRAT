use akrat_core::network::{self, SecureChannel};
use akrat_core::{Contact, DeliveryState, Identity, StoredMessage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::sync::{Mutex, mpsc, watch};
use zeroize::Zeroize;

const IROH_ALPN: &[u8] = b"akrat-chat/0.1";
static SERVICES: OnceLock<StdMutex<HashMap<String, (u64, mpsc::UnboundedSender<ServiceCommand>)>>> =
    OnceLock::new();
static NEXT_SERVICE_ID: AtomicU64 = AtomicU64::new(1);

enum ServiceCommand {
    Dial(Contact, mpsc::UnboundedSender<UiEvent>),
    UpdateContacts(Vec<Contact>),
    Stop,
}

#[derive(Clone, Debug)]
pub struct SessionHandle {
    commands: mpsc::UnboundedSender<SessionCommand>,
}

impl SessionHandle {
    pub fn send_text(&self, id: String, text: String) -> Result<(), String> {
        self.commands
            .send(SessionCommand::Text { id, text })
            .map_err(|_| "La session est fermée".to_string())
    }

    pub fn acknowledge(&self, id: String) -> Result<(), String> {
        self.commands
            .send(SessionCommand::Acknowledge { id })
            .map_err(|_| "La session est fermée".to_string())
    }

    pub fn close(&self) {
        let _ = self.commands.send(SessionCommand::Close);
    }
}

enum SessionCommand {
    Text { id: String, text: String },
    Acknowledge { id: String },
    Close,
}

#[derive(Clone, Debug)]
pub enum UiEvent {
    Trace(String),
    Ready {
        conversation: String,
        peer_name: String,
        handle: SessionHandle,
    },
    Transmitted {
        conversation: String,
        id: String,
    },
    Incoming {
        conversation: String,
        id: String,
        text: String,
    },
    Acknowledged {
        conversation: String,
        id: String,
    },
    Closed {
        conversation: String,
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
enum WireMessage {
    Text { id: String, text: String },
    Acknowledgement { id: String },
    Close,
}

pub fn connect(identity: Identity, contact: Contact, events: mpsc::UnboundedSender<UiEvent>) {
    if contact.transport_id.is_empty() {
        let _ = events.send(UiEvent::Trace("Ce contact utilise une ancienne invitation. Demandez-lui une nouvelle invitation réseau.".into()));
        return;
    }
    let registry = SERVICES.get_or_init(|| StdMutex::new(HashMap::new()));
    let sender = registry
        .lock()
        .ok()
        .and_then(|services| services.get(&identity.id).map(|(_, sender)| sender.clone()));
    match sender.and_then(|sender| {
        sender
            .send(ServiceCommand::Dial(contact, events.clone()))
            .ok()
    }) {
        Some(()) => {}
        None => {
            let _ = events.send(UiEvent::Trace(
                "Activez d’abord la disponibilité P2P de cette identité dans Réseau.".into(),
            ));
        }
    }
}

pub fn update_contacts(identity_id: &str, contacts: Vec<Contact>) {
    let registry = SERVICES.get_or_init(|| StdMutex::new(HashMap::new()));
    if let Some(sender) = registry
        .lock()
        .ok()
        .and_then(|services| services.get(identity_id).map(|(_, sender)| sender.clone()))
    {
        let _ = sender.send(ServiceCommand::UpdateContacts(contacts));
    }
}

pub fn listen(
    identity: Identity,
    contacts: Vec<Contact>,
    events: mpsc::UnboundedSender<UiEvent>,
) -> watch::Sender<bool> {
    let (stop, mut stopped) = watch::channel(false);
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let service_id = NEXT_SERVICE_ID.fetch_add(1, Ordering::Relaxed);
    let registry = SERVICES.get_or_init(|| StdMutex::new(HashMap::new()));
    if let Ok(mut services) = registry.lock() {
        if let Some((_, previous)) =
            services.insert(identity.id.clone(), (service_id, commands.clone()))
        {
            let _ = previous.send(ServiceCommand::Stop);
        }
    }
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = events.send(UiEvent::Trace(format!(
                    "Runtime réseau impossible : {error}"
                )));
                return;
            }
        };
        runtime.block_on(async move {
            let mut contacts = contacts;
            let transport_key_bytes = identity.transport_private_key();
            let transport_key = iroh::SecretKey::from_bytes(&transport_key_bytes);
            let endpoint = match iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                .secret_key(transport_key)
                .alpns(vec![IROH_ALPN.to_vec()])
                .bind()
                .await
            {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = events.send(UiEvent::Trace(format!("Initialisation du réseau P2P impossible : {error}")));
                    remove_service(&identity.id, service_id);
                    return;
                }
            };
            let transport_id = endpoint.id().to_string();
            let _ = events.send(UiEvent::Trace(format!("Identité réseau P2P active · {}", short_id(&transport_id))));
            let online_endpoint = endpoint.clone();
            let online_events = events.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(std::time::Duration::from_secs(20), online_endpoint.online()).await {
                    Ok(()) => { let _ = online_events.send(UiEvent::Trace("Relais P2P prêt · recherche par identité réseau active".into())); }
                    Err(_) => { let _ = online_events.send(UiEvent::Trace("Relais P2P indisponible pour le moment · vérifiez l’accès Internet".into())); }
                }
            });
            let handshake_slots = Arc::new(tokio::sync::Semaphore::new(8));
            loop {
                tokio::select! {
                    changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { break; },
                    command = command_rx.recv() => match command {
                        Some(ServiceCommand::Dial(contact, command_events)) => {
                            let endpoint = endpoint.clone();
                            let identity = identity.detached_copy();
                            tokio::spawn(async move { dial_contact(endpoint, identity, contact, command_events).await; });
                        }
                        Some(ServiceCommand::UpdateContacts(updated)) => contacts = updated,
                        Some(ServiceCommand::Stop) | None => break,
                    },
                    accepted = endpoint.accept() => match accepted {
                        Some(incoming) => {
                            let connection = match incoming.await {
                                Ok(connection) => connection,
                                Err(error) => { let _ = events.send(UiEvent::Trace(format!("Connexion P2P entrante refusée : {error}"))); continue; }
                            };
                            let remote_id = connection.remote_id().to_string();
                            let Some(contact) = contacts.iter().find(|c| c.manually_verified && c.transport_id == remote_id).cloned() else {
                                let _ = events.send(UiEvent::Trace(format!("Pair refusé · identité réseau inconnue ou non vérifiée · {}", short_id(&remote_id))));
                                connection.close(1u8.into(), b"unverified peer");
                                continue;
                            };
                            let _ = events.send(UiEvent::Trace(format!("Pair reconnu · {} · canal Noise XX", contact.name)));
                            let permit = match handshake_slots.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    let _ = events.send(UiEvent::Trace("Connexion refusée · trop de négociations simultanées".into()));
                                    connection.close(1u8.into(), b"busy");
                                    continue;
                                }
                            };
                            let identity = identity.detached_copy();
                            let events = events.clone();
                            tokio::spawn(async move {
                                accept_contact(connection, identity, contact, events).await;
                                drop(permit);
                            });
                        }
                        None => break,
                    }
                }
            }
            endpoint.close().await;
            remove_service(&identity.id, service_id);
            let _ = events.send(UiEvent::Trace("Disponibilité P2P arrêtée".into()));
        });
    });
    stop
}

fn remove_service(identity_id: &str, service_id: u64) {
    if let Some(registry) = SERVICES.get() {
        if let Ok(mut services) = registry.lock() {
            if services
                .get(identity_id)
                .is_some_and(|(id, _)| *id == service_id)
            {
                services.remove(identity_id);
            }
        }
    }
}

fn short_id(id: &str) -> String {
    id.chars().take(16).collect()
}

async fn dial_contact(
    endpoint: iroh::Endpoint,
    identity: Identity,
    contact: Contact,
    events: mpsc::UnboundedSender<UiEvent>,
) {
    let remote_id = match contact.transport_id.parse::<iroh::EndpointId>() {
        Ok(id) => id,
        Err(error) => {
            let _ = events.send(UiEvent::Trace(format!(
                "Identité réseau invalide : {error}"
            )));
            return;
        }
    };
    let _ = events.send(UiEvent::Trace(format!(
        "Recherche du pair par identité réseau · {}",
        short_id(&contact.transport_id)
    )));
    let connection = match tokio::time::timeout(
        std::time::Duration::from_secs(90),
        endpoint.connect(remote_id, IROH_ALPN),
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            let _ = events.send(UiEvent::Trace(format!(
                "Pair injoignable · recherche P2P/direct et relais : {error}"
            )));
            return;
        }
        Err(_) => {
            let _ = events.send(UiEvent::Trace(
                "Recherche P2P expirée après 90 secondes · vérifiez que le contact est en ligne"
                    .into(),
            ));
            return;
        }
    };
    let _ = events.send(UiEvent::Trace(
        "Transport P2P établi · vérification de l’identité AKRAT".into(),
    ));
    let stream = match iroh_stream(connection, false).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = events.send(UiEvent::Trace(format!("Flux P2P indisponible : {error}")));
            return;
        }
    };
    let pending = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        network::initiate(stream, &identity),
    )
    .await
    {
        Ok(Ok(pending)) => pending,
        Ok(Err(error)) => {
            let _ = events.send(UiEvent::Trace(format!(
                "Négociation Noise refusée : {error}"
            )));
            return;
        }
        Err(_) => {
            let _ = events.send(UiEvent::Trace(
                "Négociation Noise expirée après 30 secondes".into(),
            ));
            return;
        }
    };
    let _ = events.send(UiEvent::Trace(format!(
        "Empreinte distante : {}",
        pending.fingerprint()
    )));
    let channel = match pending.verify_peer(&contact.public_key) {
        Ok(channel) => channel,
        Err(error) => {
            let _ = events.send(UiEvent::Trace(format!("Empreinte refusée : {error}")));
            return;
        }
    };
    let conversation = format!("{}:{}", identity.id, contact.fingerprint);
    start_session(channel, conversation, contact.name, events).await;
}

async fn accept_contact(
    connection: iroh::endpoint::Connection,
    identity: Identity,
    contact: Contact,
    events: mpsc::UnboundedSender<UiEvent>,
) {
    let stream = match iroh_stream(connection, true).await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = events.send(UiEvent::Trace(format!(
                "Flux P2P entrant indisponible : {error}"
            )));
            return;
        }
    };
    let pending = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        network::respond(stream, &identity),
    )
    .await
    {
        Ok(Ok(pending)) => pending,
        Ok(Err(error)) => {
            let _ = events.send(UiEvent::Trace(format!(
                "Connexion entrante refusée : {error}"
            )));
            return;
        }
        Err(_) => {
            let _ = events.send(UiEvent::Trace("Négociation entrante expirée".into()));
            return;
        }
    };
    let _ = events.send(UiEvent::Trace(format!(
        "Empreinte entrante · {}",
        pending.fingerprint()
    )));
    let channel = match pending.verify_peer(&contact.public_key) {
        Ok(channel) => channel,
        Err(error) => {
            let _ = events.send(UiEvent::Trace(format!("Empreinte refusée : {error}")));
            return;
        }
    };
    let _ = events.send(UiEvent::Trace(format!(
        "Identité de {} reconnue et vérifiée",
        contact.name
    )));
    let conversation = format!("{}:{}", identity.id, contact.fingerprint);
    start_session(channel, conversation, contact.name, events).await;
}

async fn iroh_stream(
    connection: iroh::endpoint::Connection,
    incoming: bool,
) -> Result<IrohStream, String> {
    let (send, receive) = if incoming {
        connection
            .accept_bi()
            .await
            .map_err(|error| error.to_string())?
    } else {
        connection
            .open_bi()
            .await
            .map_err(|error| error.to_string())?
    };
    Ok(IrohStream { send, receive })
}

struct IrohStream {
    send: iroh::endpoint::SendStream,
    receive: iroh::endpoint::RecvStream,
}

impl tokio::io::AsyncRead for IrohStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.receive).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for IrohStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        <iroh::endpoint::SendStream as tokio::io::AsyncWrite>::poll_write(
            std::pin::Pin::new(&mut self.send),
            context,
            buffer,
        )
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        <iroh::endpoint::SendStream as tokio::io::AsyncWrite>::poll_flush(
            std::pin::Pin::new(&mut self.send),
            context,
        )
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        <iroh::endpoint::SendStream as tokio::io::AsyncWrite>::poll_shutdown(
            std::pin::Pin::new(&mut self.send),
            context,
        )
    }
}

async fn start_session<S>(
    channel: SecureChannel<S>,
    conversation: String,
    peer_name: String,
    events: mpsc::UnboundedSender<UiEvent>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let handle = SessionHandle { commands };
    let _ = events.send(UiEvent::Trace(format!(
        "Canal chiffré établi · {peer_name}"
    )));
    let _ = events.send(UiEvent::Ready {
        conversation: conversation.clone(),
        peer_name,
        handle,
    });
    let (sender, receiver) = channel.split();
    let sender = Arc::new(Mutex::new(sender));
    let mut receiver = receiver;
    loop {
        tokio::select! {
            command = command_rx.recv() => match command {
                Some(SessionCommand::Text { id, text }) => {
                    let packet = match serde_json::to_vec(&WireMessage::Text { id: id.clone(), text }) { Ok(packet) => packet, Err(error) => { let _ = events.send(UiEvent::Trace(format!("Sérialisation impossible : {error}"))); continue; } };
                    let result = sender.lock().await.send(&packet).await;
                    match result { Ok(()) => { let _ = events.send(UiEvent::Transmitted { conversation: conversation.clone(), id }); }, Err(error) => { let _ = events.send(UiEvent::Closed { conversation: conversation.clone(), reason: error.to_string() }); return; } }
                }
                Some(SessionCommand::Acknowledge { id }) => {
                    let packet = match serde_json::to_vec(&WireMessage::Acknowledgement { id }) { Ok(packet) => packet, Err(_) => continue };
                    if let Err(error) = sender.lock().await.send(&packet).await { let _ = events.send(UiEvent::Closed { conversation: conversation.clone(), reason: error.to_string() }); return; }
                    let _ = events.send(UiEvent::Trace("Accusé chiffré et envoyé après sauvegarde locale".into()));
                }
                Some(SessionCommand::Close) => {
                    let packet = serde_json::to_vec(&WireMessage::Close).unwrap_or_default();
                    let _ = sender.lock().await.send(&packet).await;
                    let _ = events.send(UiEvent::Closed { conversation: conversation.clone(), reason: "Session fermée localement".into() });
                    return;
                }
                None => {
                    let _ = events.send(UiEvent::Closed { conversation: conversation.clone(), reason: "Session fermée localement".into() }); return;
                }
            },
            received = receiver.receive() => match received {
                Ok(plaintext) => match serde_json::from_slice::<WireMessage>(&plaintext) {
                    Ok(WireMessage::Text { id, text }) => {
                        let _ = events.send(UiEvent::Trace("Paquet reçu · authentification AEAD et déchiffrement réussis".into()));
                        let _ = events.send(UiEvent::Incoming { conversation: conversation.clone(), id, text });
                    }
                    Ok(WireMessage::Acknowledgement { id }) => { let _ = events.send(UiEvent::Acknowledged { conversation: conversation.clone(), id }); }
                    Ok(WireMessage::Close) => { let _ = events.send(UiEvent::Closed { conversation: conversation.clone(), reason: "Le pair a fermé la session".into() }); return; }
                    Err(error) => { let _ = events.send(UiEvent::Trace(format!("Paquet applicatif invalide : {error}"))); }
                },
                Err(error) => { let _ = events.send(UiEvent::Closed { conversation: conversation.clone(), reason: error.to_string() }); return; }
            }
        }
    }
}

pub fn message_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(hex::encode(bytes))
}

pub fn wipe_string(value: &mut String) {
    value.zeroize();
}

pub fn new_message(conversation: String, id: String, text: String) -> StoredMessage {
    StoredMessage {
        conversation,
        id,
        outgoing: true,
        text,
        delivery: DeliveryState::Pending,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
    }
}

pub fn received_message(conversation: String, id: String, text: String) -> StoredMessage {
    StoredMessage {
        conversation,
        id,
        outgoing: false,
        text,
        delivery: DeliveryState::Received,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionHandle, UiEvent, start_session};
    use akrat_core::Identity;
    use akrat_core::network;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn session_actor_delivers_messages_and_authenticated_acknowledgements() {
        let alice = Identity::generate("Alice UI test".into()).expect("Alice identity");
        let bob = Identity::generate("Bob UI test".into()).expect("Bob identity");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("listener address");
        let bob_copy = bob.detached_copy();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            network::respond(stream, &bob_copy)
                .await
                .expect("Bob handshake")
        });
        let stream = TcpStream::connect(address).await.expect("connect");
        let alice_pending = network::initiate(stream, &alice)
            .await
            .expect("Alice handshake");
        let alice_channel = alice_pending
            .verify_peer(bob.public_key())
            .expect("verify Bob");
        let bob_pending = server.await.expect("server task");
        let bob_channel = bob_pending
            .verify_peer(alice.public_key())
            .expect("verify Alice");

        let (alice_events, mut alice_rx) = tokio::sync::mpsc::unbounded_channel();
        let (bob_events, mut bob_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(start_session(
            alice_channel,
            "alice:bob".into(),
            "Bob".into(),
            alice_events,
        ));
        tokio::spawn(start_session(
            bob_channel,
            "bob:alice".into(),
            "Alice".into(),
            bob_events,
        ));
        let alice = take_ready(&mut alice_rx).await;
        let bob = take_ready(&mut bob_rx).await;
        alice
            .send_text("message-1".into(), "Salut, Bob.".into())
            .expect("queue text");

        let incoming = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let event = bob_rx.recv().await.expect("incoming event");
                if matches!(&event, UiEvent::Incoming { .. }) {
                    break event;
                }
            }
        })
        .await
        .expect("incoming timeout");
        assert!(
            matches!(incoming, UiEvent::Incoming { ref id, ref text, .. } if id == "message-1" && text == "Salut, Bob.")
        );
        bob.acknowledge("message-1".into())
            .expect("queue acknowledgement");

        let acknowledged = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let event = alice_rx.recv().await.expect("acknowledgement event");
                if matches!(&event, UiEvent::Acknowledged { .. }) {
                    break event;
                }
            }
        })
        .await
        .expect("acknowledgement timeout");
        assert!(matches!(acknowledged, UiEvent::Acknowledged { ref id, .. } if id == "message-1"));
        alice.close();
        bob.close();
    }

    #[tokio::test]
    async fn iroh_transport_connects_by_peer_id_and_keeps_noise_identity_pinned() {
        let alice = Identity::generate("Alice P2P test".into()).expect("Alice identity");
        let bob = Identity::generate("Bob P2P test".into()).expect("Bob identity");
        let bob_key = bob.public_key().to_vec();
        let alice_key = alice.public_key().to_vec();

        let bob_transport_key = bob.transport_private_key();
        let bob_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .clear_address_lookup()
            .relay_mode(iroh::endpoint::RelayMode::Disabled)
            .secret_key(iroh::SecretKey::from_bytes(&bob_transport_key))
            .alpns(vec![b"akrat-chat/0.1".to_vec()])
            .bind()
            .await
            .expect("Bob P2P endpoint");
        let bob_udp = bob_endpoint
            .bound_sockets()
            .into_iter()
            .find(|address| address.is_ipv4())
            .expect("Bob IPv4 UDP socket");
        let bob_addr = iroh::EndpointAddr::new(bob_endpoint.id())
            .with_ip_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, bob_udp.port())));

        let bob_server = tokio::spawn(async move {
            let incoming = bob_endpoint
                .accept()
                .await
                .expect("incoming P2P connection");
            let connection = incoming.await.expect("P2P handshake");
            let stream = super::iroh_stream(connection, true)
                .await
                .expect("incoming P2P stream");
            let pending = network::respond(stream, &bob).await.expect("Bob Noise XX");
            let mut channel = pending.verify_peer(&alice_key).expect("pin Alice");
            assert_eq!(
                channel.receive().await.expect("Alice message").as_slice(),
                b"hello over P2P"
            );
            channel.send(b"reply over P2P").await.expect("Bob reply");
            assert_eq!(
                channel
                    .receive()
                    .await
                    .expect("Alice acknowledgement")
                    .as_slice(),
                b"reply received"
            );
        });

        let alice_transport_key = alice.transport_private_key();
        let alice_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .clear_address_lookup()
            .relay_mode(iroh::endpoint::RelayMode::Disabled)
            .secret_key(iroh::SecretKey::from_bytes(&alice_transport_key))
            .alpns(vec![b"akrat-chat/0.1".to_vec()])
            .bind()
            .await
            .expect("Alice P2P endpoint");
        let connection = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            alice_endpoint.connect(bob_addr, b"akrat-chat/0.1"),
        )
        .await
        .expect("local direct P2P connection timed out")
        .expect("local direct P2P connection");
        let stream = super::iroh_stream(connection, false)
            .await
            .expect("outgoing P2P stream");
        let pending = network::initiate(stream, &alice)
            .await
            .expect("Alice Noise XX");
        let mut channel = pending.verify_peer(&bob_key).expect("pin Bob");
        channel
            .send(b"hello over P2P")
            .await
            .expect("Alice message");
        assert_eq!(
            channel.receive().await.expect("Bob reply").as_slice(),
            b"reply over P2P"
        );
        channel
            .send(b"reply received")
            .await
            .expect("Alice acknowledgement");
        bob_server.await.expect("Bob P2P task");
        alice_endpoint.close().await;
    }

    async fn take_ready(
        receiver: &mut tokio::sync::mpsc::UnboundedReceiver<UiEvent>,
    ) -> SessionHandle {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match receiver.recv().await.expect("ready event") {
                    UiEvent::Ready { handle, .. } => break handle,
                    UiEvent::Trace(_) => continue,
                    other => panic!("expected ready event, got {other:?}"),
                }
            }
        })
        .await
        .expect("ready timeout")
    }
}
