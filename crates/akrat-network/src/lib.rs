use akrat_core::PrivateIdentity;
use akrat_crypto::session::{Session, SessionError, respond_to_handshake, start_handshake};
use akrat_protocol::{
    EncryptedMessage, FrameError, HandshakeFrame, MAX_FRAME_SIZE, SessionPayload, decode_frame,
    encode_frame,
};
use serde::{Serialize, de::DeserializeOwned};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::{Duration, timeout};

pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_SESSION_TEXT_SIZE: usize = 10 * 1024;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network operation timed out")]
    Timeout,
    #[error("network I/O failed")]
    Io(#[from] std::io::Error),
    #[error("protocol frame is invalid")]
    Frame(#[from] FrameError),
    #[error("cryptographic handshake failed")]
    Handshake(#[from] SessionError),
    #[error("unexpected protocol message")]
    UnexpectedMessage,
    #[error("peer identity does not match the expected key")]
    PeerKeyMismatch,
    #[error("network queue is full or closed")]
    Backpressure,
    #[error("session payload is invalid")]
    InvalidPayload,
}

pub struct UnverifiedSession {
    session: Session,
    pub peer_identity_id: String,
    pub peer_public_key: Vec<u8>,
}

impl UnverifiedSession {
    pub fn verify_peer_identity(
        self,
        expected_identity_id: &str,
        expected_public_key: &[u8],
    ) -> Result<Session, NetworkError> {
        if self.peer_identity_id != expected_identity_id
            || self.peer_public_key != expected_public_key
        {
            return Err(NetworkError::PeerKeyMismatch);
        }
        Ok(self.session)
    }
}

pub enum SessionCommand {
    SendText { message_id: String, text: String },
    ConfirmReceived { message_id: String },
    Close,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SessionEvent {
    Transmitted { message_id: String },
    Received { message_id: String, text: String },
    Acknowledged { message_id: String },
    Closed,
    Failed(String),
}

#[derive(Clone)]
pub struct SessionHandle {
    commands: mpsc::Sender<SessionCommand>,
}

pub struct PendingPeer {
    stream: std::net::TcpStream,
    unverified: UnverifiedSession,
    pub peer_identity_id: String,
    pub peer_public_key: Vec<u8>,
    pub remote_address: SocketAddr,
}

impl PendingPeer {
    pub fn verify_peer_identity(
        self,
        expected_identity_id: &str,
        expected_public_key: &[u8],
    ) -> Result<(std::net::TcpStream, Session), NetworkError> {
        let session = self
            .unverified
            .verify_peer_identity(expected_identity_id, expected_public_key)?;
        Ok((self.stream, session))
    }
}

pub enum ListenerEvent {
    Bound(SocketAddr),
    Pending(Box<PendingPeer>),
    Failed(String),
    Rejected(String),
    Stopped,
}

pub struct ListenerHandle {
    shutdown: watch::Sender<bool>,
}

impl ListenerHandle {
    pub fn stop(&self) {
        let _ = self.shutdown.send(true);
    }
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

impl SessionHandle {
    pub fn send_text(&self, message_id: String, text: String) -> Result<(), NetworkError> {
        if !valid_message_id(&message_id)
            || text.len() > MAX_SESSION_TEXT_SIZE
            || text.trim().is_empty()
        {
            return Err(NetworkError::InvalidPayload);
        }
        self.commands
            .try_send(SessionCommand::SendText { message_id, text })
            .map_err(|_| NetworkError::Backpressure)
    }

    pub fn confirm_received(&self, message_id: String) -> Result<(), NetworkError> {
        if !valid_message_id(&message_id) {
            return Err(NetworkError::InvalidPayload);
        }
        self.commands
            .try_send(SessionCommand::ConfirmReceived { message_id })
            .map_err(|_| NetworkError::Backpressure)
    }

    pub fn close(&self) -> Result<(), NetworkError> {
        self.commands
            .try_send(SessionCommand::Close)
            .map_err(|_| NetworkError::Backpressure)
    }
}

pub async fn bind(address: SocketAddr) -> Result<TcpListener, NetworkError> {
    TcpListener::bind(address).await.map_err(NetworkError::Io)
}

pub fn start_listener(
    address: SocketAddr,
    identity: std::sync::Arc<PrivateIdentity>,
    events: mpsc::Sender<ListenerEvent>,
) -> ListenerHandle {
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = events.blocking_send(ListenerEvent::Failed(error.to_string()));
                return;
            }
        };
        runtime.block_on(async move {
            let listener = match bind_dual_stack(address.port()) {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = events.send(ListenerEvent::Failed(error.to_string())).await;
                    return;
                }
            };
            let bound_address = match listener.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    let _ = events.send(ListenerEvent::Failed(error.to_string())).await;
                    return;
                }
            };
            if events.send(ListenerEvent::Bound(bound_address)).await.is_err() {
                return;
            }
            let handshakes = std::sync::Arc::new(Semaphore::new(32));
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    result = listener.accept() => {
                        let (stream, remote_address) = match result {
                            Ok(connection) => connection,
                            Err(error) => {
                                let _ = events.send(ListenerEvent::Failed(error.to_string())).await;
                                continue;
                            }
                        };
                        let permit = match handshakes.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                drop(stream);
                                continue;
                            }
                        };
                        let identity = identity.clone();
                        let events = events.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            match respond_session(stream, &identity, None).await {
                                Ok((stream, unverified)) => {
                                    let peer_identity_id = unverified.peer_identity_id.clone();
                                    let peer_public_key = unverified.peer_public_key.clone();
                                    match stream.into_std() {
                                        Ok(stream) => {
                                            let pending = PendingPeer {
                                                stream,
                                                unverified,
                                                peer_identity_id,
                                                peer_public_key,
                                                remote_address,
                                            };
                                            let _ = events.send(ListenerEvent::Pending(Box::new(pending))).await;
                                        }
                                        Err(error) => {
                                            let _ = events.send(ListenerEvent::Failed(error.to_string())).await;
                                        }
                                    }
                                }
                                Err(error) => {
                                    let _ = events.send(ListenerEvent::Rejected(error.to_string())).await;
                                }
                            }
                        });
                    }
                }
            }
            let _ = events.send(ListenerEvent::Stopped).await;
        });
    });
    ListenerHandle { shutdown }
}

fn bind_dual_stack(port: u16) -> Result<TcpListener, NetworkError> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(NetworkError::Io)?;
    socket.set_only_v6(false).map_err(NetworkError::Io)?;
    socket.set_reuse_address(true).map_err(NetworkError::Io)?;
    socket
        .bind(&socket2::SockAddr::from(SocketAddr::V6(
            std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port, 0, 0),
        )))
        .map_err(NetworkError::Io)?;
    socket.listen(128).map_err(NetworkError::Io)?;
    socket.set_nonblocking(true).map_err(NetworkError::Io)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).map_err(NetworkError::Io)
}

pub async fn connect(address: SocketAddr) -> Result<TcpStream, NetworkError> {
    timeout(DEFAULT_IO_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(NetworkError::Io)
}

pub async fn accept(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), NetworkError> {
    timeout(DEFAULT_IO_TIMEOUT, listener.accept())
        .await
        .map_err(|_| NetworkError::Timeout)?
        .map_err(NetworkError::Io)
}

pub async fn send_frame<W, T>(writer: &mut W, message: &T) -> Result<(), NetworkError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = encode_frame(message)?;
    let length = u32::try_from(frame.len()).map_err(|_| FrameError::TooLarge)?;
    timeout(DEFAULT_IO_TIMEOUT, async {
        writer.write_all(&length.to_be_bytes()).await?;
        writer.write_all(&frame).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| NetworkError::Timeout)??;
    Ok(())
}

pub async fn receive_frame<R, T>(reader: &mut R) -> Result<T, NetworkError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    timeout(DEFAULT_IO_TIMEOUT, receive_frame_inner(reader))
        .await
        .map_err(|_| NetworkError::Timeout)?
}

async fn receive_frame_inner<R, T>(reader: &mut R) -> Result<T, NetworkError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length = [0; 4];
    reader.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(NetworkError::Frame(FrameError::TooLarge));
    }
    let mut frame = vec![0; length];
    reader.read_exact(&mut frame).await?;
    decode_frame(&frame).map_err(NetworkError::Frame)
}

pub fn start_message_session(
    stream: std::net::TcpStream,
    session: Session,
) -> (SessionHandle, mpsc::Receiver<SessionEvent>) {
    let (command_tx, command_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(64);
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                let _ = event_tx.blocking_send(SessionEvent::Failed(error.to_string()));
                return;
            }
        };
        runtime.block_on(async move {
            match TcpStream::from_std(stream) {
                Ok(stream) => run_message_session(stream, session, command_rx, event_tx).await,
                Err(error) => {
                    let _ = event_tx.send(SessionEvent::Failed(error.to_string())).await;
                }
            }
        });
    });
    (
        SessionHandle {
            commands: command_tx,
        },
        event_rx,
    )
}

async fn run_message_session(
    stream: TcpStream,
    mut session: Session,
    mut commands: mpsc::Receiver<SessionCommand>,
    events: mpsc::Sender<SessionEvent>,
) {
    let (mut reader, mut writer) = stream.into_split();
    enum Next {
        Command(Option<SessionCommand>),
        Incoming(Result<EncryptedMessage, NetworkError>),
    }
    loop {
        let next = tokio::select! {
            command = commands.recv() => Next::Command(command),
            incoming = receive_frame_inner::<_, EncryptedMessage>(&mut reader) => Next::Incoming(incoming),
        };
        match next {
            Next::Command(Some(SessionCommand::SendText { message_id, text })) => {
                let payload = SessionPayload::Text {
                    message_id: message_id.clone(),
                    text,
                };
                match encrypt_payload(&mut session, &payload) {
                    Ok(message) => match send_frame(&mut writer, &message).await {
                        Ok(()) => {
                            if events
                                .send(SessionEvent::Transmitted { message_id })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(error) => {
                            let _ = events.send(SessionEvent::Failed(error.to_string())).await;
                            break;
                        }
                    },
                    Err(error) => {
                        let _ = events.send(SessionEvent::Failed(error.to_string())).await;
                        break;
                    }
                }
            }
            Next::Command(Some(SessionCommand::ConfirmReceived { message_id })) => {
                let payload = SessionPayload::Acknowledgement { message_id };
                match encrypt_payload(&mut session, &payload) {
                    Ok(message) => {
                        if let Err(error) = send_frame(&mut writer, &message).await {
                            let _ = events.send(SessionEvent::Failed(error.to_string())).await;
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = events.send(SessionEvent::Failed(error.to_string())).await;
                        break;
                    }
                }
            }
            Next::Command(Some(SessionCommand::Close)) | Next::Command(None) => {
                if let Ok(message) = encrypt_payload(&mut session, &SessionPayload::Close) {
                    let _ = send_frame(&mut writer, &message).await;
                }
                let _ = writer.shutdown().await;
                let _ = events.send(SessionEvent::Closed).await;
                break;
            }
            Next::Incoming(Ok(message)) => {
                let plaintext = match session.decrypt(&message) {
                    Ok(plaintext) => plaintext,
                    Err(error) => {
                        let _ = events.send(SessionEvent::Failed(error.to_string())).await;
                        break;
                    }
                };
                let payload: SessionPayload = match serde_json::from_slice(&plaintext) {
                    Ok(payload) => payload,
                    Err(_) => {
                        let _ = events
                            .send(SessionEvent::Failed(
                                "session payload is invalid".to_string(),
                            ))
                            .await;
                        break;
                    }
                };
                let event = match payload {
                    SessionPayload::Text { message_id, text }
                        if valid_message_id(&message_id) && text.len() <= MAX_SESSION_TEXT_SIZE =>
                    {
                        Some(SessionEvent::Received { message_id, text })
                    }
                    SessionPayload::Acknowledgement { message_id }
                        if valid_message_id(&message_id) =>
                    {
                        Some(SessionEvent::Acknowledged { message_id })
                    }
                    SessionPayload::Close => {
                        let _ = events.send(SessionEvent::Closed).await;
                        break;
                    }
                    _ => {
                        let _ = events
                            .send(SessionEvent::Failed(
                                "session payload is invalid".to_string(),
                            ))
                            .await;
                        break;
                    }
                };
                if let Some(event) = event
                    && events.send(event).await.is_err()
                {
                    break;
                }
            }
            Next::Incoming(Err(error)) => {
                let _ = events.send(SessionEvent::Failed(error.to_string())).await;
                break;
            }
        }
    }
}

fn encrypt_payload(
    session: &mut Session,
    payload: &SessionPayload,
) -> Result<EncryptedMessage, NetworkError> {
    let plaintext = serde_json::to_vec(payload).map_err(|_| NetworkError::InvalidPayload)?;
    session
        .encrypt(&plaintext)
        .map_err(|_| NetworkError::InvalidPayload)
}

fn valid_message_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub async fn initiate_session(
    mut stream: TcpStream,
    identity: &PrivateIdentity,
    expected_peer_public_key: Option<&[u8]>,
) -> Result<(TcpStream, UnverifiedSession), NetworkError> {
    let (hello, pending) = start_handshake(identity)?;
    send_frame(&mut stream, &HandshakeFrame::Hello(hello)).await?;
    let response = match receive_frame(&mut stream).await? {
        HandshakeFrame::Response(response) => response,
        _ => return Err(NetworkError::UnexpectedMessage),
    };
    let peer_identity_id = response.identity_id.clone();
    let peer_public_key = response.signing_public_key.clone();
    let (finish, session) = pending.complete(identity, &response, expected_peer_public_key)?;
    send_frame(&mut stream, &HandshakeFrame::Finish(finish)).await?;
    Ok((
        stream,
        UnverifiedSession {
            session,
            peer_identity_id,
            peer_public_key,
        },
    ))
}

pub async fn respond_session(
    mut stream: TcpStream,
    identity: &PrivateIdentity,
    expected_peer_public_key: Option<&[u8]>,
) -> Result<(TcpStream, UnverifiedSession), NetworkError> {
    let hello = match receive_frame(&mut stream).await? {
        HandshakeFrame::Hello(hello) => hello,
        _ => return Err(NetworkError::UnexpectedMessage),
    };
    if expected_peer_public_key.is_some_and(|expected| expected != hello.signing_public_key) {
        return Err(NetworkError::PeerKeyMismatch);
    }
    let peer_identity_id = hello.identity_id.clone();
    let peer_public_key = hello.signing_public_key.clone();
    let (response, pending) = respond_to_handshake(identity, &hello)?;
    send_frame(&mut stream, &HandshakeFrame::Response(response)).await?;
    let finish = match receive_frame(&mut stream).await? {
        HandshakeFrame::Finish(finish) => finish,
        _ => return Err(NetworkError::UnexpectedMessage),
    };
    let session = pending.accept_finish(&finish)?;
    Ok((
        stream,
        UnverifiedSession {
            session,
            peer_identity_id,
            peer_public_key,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ListenerEvent, NetworkError, SessionEvent, accept, bind, connect, initiate_session,
        receive_frame, respond_session, send_frame, start_listener, start_message_session,
    };
    use akrat_crypto::create_identity;
    use akrat_protocol::EncryptedMessage;
    use tokio::io::AsyncWriteExt;

    fn message(sequence: u64, sender: &str, recipient: &str) -> EncryptedMessage {
        EncryptedMessage {
            session_id: vec![7; 16],
            sender_id: sender.to_string(),
            recipient_id: recipient.to_string(),
            sequence,
            nonce: vec![0; 12],
            ciphertext: vec![sequence as u8; 32],
        }
    }

    #[tokio::test]
    async fn localhost_tcp_transports_multiple_frames_both_directions() {
        let listener = bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept(&listener).await.expect("accept");
            let received: EncryptedMessage = receive_frame(&mut stream).await.expect("receive");
            assert_eq!(received.sequence, 0);
            send_frame(&mut stream, &message(1, "bob", "alice"))
                .await
                .expect("send reply");
        });
        let mut client = connect(address).await.expect("connect");
        send_frame(&mut client, &message(0, "alice", "bob"))
            .await
            .expect("send");
        let reply: EncryptedMessage = receive_frame(&mut client).await.expect("receive reply");
        assert_eq!(reply.sequence, 1);
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn oversized_length_is_rejected_before_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        writer
            .write_all(&((akrat_protocol::MAX_FRAME_SIZE as u32) + 1).to_be_bytes())
            .await
            .expect("write length");
        let result: Result<EncryptedMessage, NetworkError> = receive_frame(&mut reader).await;
        assert!(matches!(result, Err(NetworkError::Frame(_))));
    }

    #[tokio::test]
    async fn localhost_hybrid_handshake_and_encrypted_messages_work_both_ways() {
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let bob = create_identity("Bob".to_string()).expect("Bob identity");
        let alice_id = alice.public.id.clone();
        let bob_id = bob.public.id.clone();
        let alice_key = alice.public.public_key.clone();
        let bob_key = bob.public.public_key.clone();
        let listener = bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let (stream, _) = accept(&listener).await.expect("accept");
            let (mut stream, unverified) = respond_session(stream, &bob, Some(&alice_key))
                .await
                .expect("handshake responder");
            let mut session = unverified
                .verify_peer_identity(&alice_id, &alice_key)
                .expect("peer identity confirmation");
            let incoming: EncryptedMessage = receive_frame(&mut stream).await.expect("frame");
            assert_eq!(session.decrypt(&incoming).expect("decrypt"), b"hello Bob");
            let reply = session.encrypt(b"hello Alice").expect("encrypt");
            send_frame(&mut stream, &reply).await.expect("reply");
        });
        let stream = connect(address).await.expect("connect");
        let (mut stream, unverified) = initiate_session(stream, &alice, Some(&bob_key))
            .await
            .expect("handshake initiator");
        let mut session = unverified
            .verify_peer_identity(&bob_id, &bob_key)
            .expect("peer identity confirmation");
        let outgoing = session.encrypt(b"hello Bob").expect("encrypt");
        send_frame(&mut stream, &outgoing).await.expect("send");
        let reply: EncryptedMessage = receive_frame(&mut stream).await.expect("reply");
        assert_eq!(session.decrypt(&reply).expect("decrypt"), b"hello Alice");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn responder_rejects_a_changed_known_peer_key() {
        let bob = create_identity("Bob".to_string()).expect("Bob identity");
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let other = create_identity("Other".to_string()).expect("other identity");
        let listener = bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let (stream, _) = accept(&listener).await.expect("accept");
            respond_session(stream, &bob, Some(&other.public.public_key)).await
        });
        let stream = connect(address).await.expect("connect");
        assert!(matches!(
            initiate_session(stream, &alice, None).await,
            Err(NetworkError::Io(_))
        ));
        assert!(matches!(
            server.await.expect("server task"),
            Err(NetworkError::PeerKeyMismatch)
        ));
    }

    #[tokio::test]
    async fn encrypted_session_actor_handles_text_and_delivery_acknowledgements() {
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let bob = create_identity("Bob".to_string()).expect("Bob identity");
        let alice_id = alice.public.id.clone();
        let bob_id = bob.public.id.clone();
        let alice_key = alice.public.public_key.clone();
        let bob_key = bob.public.public_key.clone();
        let listener = bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            let (stream, _) = accept(&listener).await.expect("accept");
            let (stream, pending) = respond_session(stream, &bob, Some(&alice_key))
                .await
                .expect("responder handshake");
            let session = pending
                .verify_peer_identity(&alice_id, &alice_key)
                .expect("initiator identity");
            let (handle, mut events) =
                start_message_session(stream.into_std().expect("convert accepted stream"), session);
            let incoming_id = match events.recv().await.expect("incoming event") {
                SessionEvent::Received { message_id, text } => {
                    assert_eq!(text, "Alice to Bob");
                    message_id
                }
                event => panic!("unexpected event: {event:?}"),
            };
            handle
                .confirm_received(incoming_id.clone())
                .expect("ack incoming");
            handle
                .send_text(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                    "Bob to Alice".to_string(),
                )
                .expect("send reply");
            let mut saw_reply_transmitted = false;
            while !saw_reply_transmitted {
                match tokio::time::timeout(std::time::Duration::from_secs(3), events.recv())
                    .await
                    .expect("server event timeout")
                    .expect("server session event")
                {
                    SessionEvent::Transmitted { message_id }
                        if message_id == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" =>
                    {
                        saw_reply_transmitted = true;
                    }
                    SessionEvent::Acknowledged { message_id } if message_id == incoming_id => {}
                    event => panic!("unexpected event: {event:?}"),
                }
            }
            (handle, events)
        });
        let stream = connect(address).await.expect("connect");
        let (stream, pending) = initiate_session(stream, &alice, Some(&bob_key))
            .await
            .expect("initiator handshake");
        let session = pending
            .verify_peer_identity(&bob_id, &bob_key)
            .expect("responder identity");
        let (handle, mut events) =
            start_message_session(stream.into_std().expect("convert client stream"), session);
        handle
            .send_text(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "Alice to Bob".to_string(),
            )
            .expect("send text");
        let mut saw_transmitted = false;
        let mut saw_acknowledged = false;
        let mut reply_id = None;
        while !(saw_transmitted && saw_acknowledged && reply_id.is_some()) {
            match tokio::time::timeout(std::time::Duration::from_secs(3), events.recv())
                .await
                .expect("client event timeout")
                .expect("client session event")
            {
                SessionEvent::Transmitted { message_id }
                    if message_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" =>
                {
                    saw_transmitted = true;
                }
                SessionEvent::Acknowledged { message_id }
                    if message_id == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" =>
                {
                    saw_acknowledged = true;
                }
                SessionEvent::Received { message_id, text } => {
                    assert_eq!(text, "Bob to Alice");
                    reply_id = Some(message_id);
                }
                event => panic!("unexpected event: {event:?}"),
            }
        }
        let reply_id = reply_id.expect("reply identifier");
        handle.confirm_received(reply_id).expect("ack reply");
        let (server_handle, mut server_events) = server.await.expect("server task");
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(3), server_events.recv())
                .await
                .expect("acknowledgement timeout"),
            Some(SessionEvent::Acknowledged { message_id })
                if message_id == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        handle.close().expect("close client");
        server_handle.close().expect("close server");
    }

    #[tokio::test]
    async fn dual_stack_listener_accepts_ipv4_and_stops_cleanly() {
        let bob = std::sync::Arc::new(create_identity("Bob".to_string()).expect("Bob identity"));
        let alice = create_identity("Alice".to_string()).expect("Alice identity");
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(16);
        let listener = start_listener(
            "0.0.0.0:0".parse().expect("bind address"),
            bob.clone(),
            event_tx,
        );
        let bound = match tokio::time::timeout(std::time::Duration::from_secs(3), event_rx.recv())
            .await
            .expect("bound event timeout")
            .expect("bound event")
        {
            ListenerEvent::Bound(address) => address,
            _ => panic!("listener failed to bind"),
        };
        let stream = connect(
            format!("127.0.0.1:{}", bound.port())
                .parse()
                .expect("IPv4 address"),
        )
        .await
        .expect("IPv4 connect");
        let (stream, client_pending) =
            initiate_session(stream, &alice, Some(&bob.public.public_key))
                .await
                .expect("initiator handshake");
        let client = match event_rx.recv().await.expect("pending peer") {
            ListenerEvent::Pending(peer) => peer,
            _ => panic!("expected a pending peer"),
        };
        let (server_stream, server_session) = client
            .verify_peer_identity(&alice.public.id, &alice.public.public_key)
            .expect("confirm Alice");
        let client_session = client_pending
            .verify_peer_identity(&bob.public.id, &bob.public.public_key)
            .expect("confirm Bob");
        assert_eq!(server_session.session_id(), client_session.session_id());
        drop((stream, server_stream));
        listener.stop();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(3), event_rx.recv())
                .await
                .expect("stop timeout"),
            Some(ListenerEvent::Stopped)
        ));
    }
}
