use akrat_core::PrivateIdentity;
use akrat_crypto::session::{Session, SessionError, respond_to_handshake, start_handshake};
use akrat_protocol::{FrameError, HandshakeFrame, MAX_FRAME_SIZE, decode_frame, encode_frame};
use serde::{Serialize, de::DeserializeOwned};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

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

pub async fn bind(address: SocketAddr) -> Result<TcpListener, NetworkError> {
    TcpListener::bind(address).await.map_err(NetworkError::Io)
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
    timeout(DEFAULT_IO_TIMEOUT, async {
        let mut length = [0; 4];
        reader.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_FRAME_SIZE {
            return Err(NetworkError::Frame(FrameError::TooLarge));
        }
        let mut frame = vec![0; length];
        reader.read_exact(&mut frame).await?;
        decode_frame(&frame).map_err(NetworkError::Frame)
    })
    .await
    .map_err(|_| NetworkError::Timeout)?
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
        NetworkError, accept, bind, connect, initiate_session, receive_frame, respond_session,
        send_frame,
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
}
