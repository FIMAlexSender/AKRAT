use akrat_core::network::{self, SecureChannel};
use akrat_core::{Contact, DeliveryState, Identity, StoredMessage};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, watch};
use zeroize::Zeroize;

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
            let address = match contact.address.parse::<SocketAddr>() {
                Ok(address) => address,
                Err(error) => {
                    let _ = events.send(UiEvent::Trace(format!("Adresse invalide : {error}")));
                    return;
                }
            };
            let _ = events.send(UiEvent::Trace(format!("Connexion TCP vers {address}")));
            let stream = match tokio::time::timeout(
                std::time::Duration::from_secs(20),
                network::connect(address),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    let _ = events.send(UiEvent::Trace(format!("Connexion impossible : {error}")));
                    return;
                }
                Err(_) => {
                    let _ =
                        events.send(UiEvent::Trace("Connexion expirée après 20 secondes".into()));
                    return;
                }
            };
            let _ = events.send(UiEvent::Trace("TCP établi · négociation Noise XX".into()));
            let pending = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                network::initiate(stream, &identity),
            )
            .await
            {
                Ok(Ok(pending)) => pending,
                Ok(Err(error)) => {
                    let _ = events.send(UiEvent::Trace(format!("Négociation refusée : {error}")));
                    return;
                }
                Err(_) => {
                    let _ = events.send(UiEvent::Trace(
                        "Négociation expirée après 30 secondes".into(),
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
        });
    });
}

pub fn listen(
    identity: Identity,
    contacts: Vec<Contact>,
    bind: String,
    events: mpsc::UnboundedSender<UiEvent>,
) -> watch::Sender<bool> {
    let (stop, mut stopped) = watch::channel(false);
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
            let address = match bind.parse::<SocketAddr>() {
                Ok(address) => address,
                Err(error) => {
                    let _ = events.send(UiEvent::Trace(format!("Adresse d’écoute invalide : {error}")));
                    return;
                }
            };
            let listener = match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = events.send(UiEvent::Trace(format!("Écoute impossible : {error}")));
                    return;
                }
            };
            match listener.local_addr() {
                Ok(local) => { let _ = events.send(UiEvent::Trace(format!("Écoute TCP active sur {local}"))); }
                Err(error) => { let _ = events.send(UiEvent::Trace(format!("Adresse d’écoute indisponible : {error}"))); }
            }
            let handshake_slots = Arc::new(tokio::sync::Semaphore::new(8));
            loop {
                tokio::select! {
                    changed = stopped.changed() => if changed.is_err() || *stopped.borrow() { break; },
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => {
                            let _ = events.send(UiEvent::Trace(format!("Connexion entrante depuis {peer} · vérification")));
                            let permit = match handshake_slots.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    let _ = events.send(UiEvent::Trace("Connexion refusée · trop de négociations simultanées".into()));
                                    drop(stream);
                                    continue;
                                }
                            };
                            let identity = identity.detached_copy();
                            let contacts = contacts.clone();
                            let events = events.clone();
                            std::thread::spawn(move || {
                                let worker_runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                                    Ok(runtime) => runtime,
                                    Err(error) => { let _ = events.send(UiEvent::Trace(format!("Runtime de session impossible : {error}"))); return; }
                                };
                                worker_runtime.block_on(async move {
                                    let pending = match tokio::time::timeout(std::time::Duration::from_secs(30), network::respond(stream, &identity)).await {
                                        Ok(Ok(pending)) => pending,
                                        Ok(Err(error)) => { let _ = events.send(UiEvent::Trace(format!("Connexion entrante refusée : {error}"))); return; }
                                        Err(_) => { let _ = events.send(UiEvent::Trace("Négociation entrante expirée".into())); return; }
                                    };
                                    let _ = events.send(UiEvent::Trace(format!("Empreinte entrante · {}", pending.fingerprint())));
                                    let Some(contact) = contacts.iter().find(|c| c.manually_verified && c.public_key == pending.remote_public_key()).cloned() else {
                                        let _ = events.send(UiEvent::Trace("Pair refusé · identité inconnue ou non vérifiée".into()));
                                        return;
                                    };
                                    let _ = events.send(UiEvent::Trace(format!("Identité de {} reconnue et vérifiée", contact.name)));
                                    let channel = match pending.verify_peer(&contact.public_key) { Ok(channel) => channel, Err(error) => { let _ = events.send(UiEvent::Trace(format!("Empreinte refusée : {error}"))); return; } };
                                    let conversation = format!("{}:{}", identity.id, contact.fingerprint);
                                    drop(permit);
                                    start_session(channel, conversation, contact.name, events).await;
                                });
                            });
                        }
                        Err(error) => { let _ = events.send(UiEvent::Trace(format!("Erreur d’écoute : {error}"))); break; }
                    }
                }
            }
            let _ = events.send(UiEvent::Trace("Écoute TCP arrêtée".into()));
        });
    });
    stop
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
    use tokio::net::TcpListener;

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
        let stream = network::connect(address).await.expect("connect");
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
