use crate::{AkratError, Identity, fingerprint, noise_params};
use snow::{Builder, HandshakeState, TransportState};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const MAX_PACKET_SIZE: usize = 64 * 1024;
const PROTOCOL_MARKER: &[u8] = b"AKRAT/1";

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("network operation failed")]
    Io(#[from] std::io::Error),
    #[error("Noise handshake or authentication failed")]
    Handshake,
    #[error("peer identity fingerprint does not match the expected contact")]
    PeerMismatch,
    #[error("network frame is invalid or too large")]
    InvalidFrame,
    #[error("encrypted message authentication failed")]
    Authentication,
    #[error("cryptographic identity is invalid")]
    Identity(#[from] AkratError),
}

pub struct PendingChannel<S> {
    stream: S,
    transport: TransportState,
    remote_public_key: Vec<u8>,
    handshake_hash: Vec<u8>,
}

impl<S> PendingChannel<S> {
    pub fn remote_public_key(&self) -> &[u8] {
        &self.remote_public_key
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.remote_public_key)
    }

    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    pub fn verify_peer(self, expected_public_key: &[u8]) -> Result<SecureChannel<S>, NetworkError> {
        if self.remote_public_key != expected_public_key {
            return Err(NetworkError::PeerMismatch);
        }
        Ok(SecureChannel {
            stream: self.stream,
            transport: self.transport,
        })
    }
}

pub struct SecureChannel<S> {
    stream: S,
    transport: TransportState,
}

pub struct ChannelSender<S> {
    stream: tokio::io::WriteHalf<S>,
    transport: Arc<Mutex<TransportState>>,
}

pub struct ChannelReceiver<S> {
    stream: tokio::io::ReadHalf<S>,
    transport: Arc<Mutex<TransportState>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SecureChannel<S> {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), NetworkError> {
        if plaintext.len() > MAX_PACKET_SIZE - 16 {
            return Err(NetworkError::InvalidFrame);
        }
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let length = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| NetworkError::Authentication)?;
        write_frame(&mut self.stream, &ciphertext[..length]).await
    }

    pub async fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, NetworkError> {
        let ciphertext = read_frame(&mut self.stream).await?;
        let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
        let length = self
            .transport
            .read_message(&ciphertext, plaintext.as_mut_slice())
            .map_err(|_| NetworkError::Authentication)?;
        plaintext.truncate(length);
        Ok(plaintext)
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub fn split(self) -> (ChannelSender<S>, ChannelReceiver<S>) {
        let (reader, writer) = tokio::io::split(self.stream);
        let transport = Arc::new(Mutex::new(self.transport));
        (
            ChannelSender {
                stream: writer,
                transport: transport.clone(),
            },
            ChannelReceiver {
                stream: reader,
                transport,
            },
        )
    }
}

impl<S: AsyncWrite + Unpin> ChannelSender<S> {
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), NetworkError> {
        if plaintext.len() > MAX_PACKET_SIZE - 16 {
            return Err(NetworkError::InvalidFrame);
        }
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let mut transport = self.transport.lock().await;
        let length = transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(|_| NetworkError::Authentication)?;
        write_frame(&mut self.stream, &ciphertext[..length]).await
    }
}

impl<S: AsyncRead + Unpin> ChannelReceiver<S> {
    pub async fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, NetworkError> {
        let ciphertext = read_frame(&mut self.stream).await?;
        let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
        let mut transport = self.transport.lock().await;
        let length = transport
            .read_message(&ciphertext, plaintext.as_mut_slice())
            .map_err(|_| NetworkError::Authentication)?;
        plaintext.truncate(length);
        Ok(plaintext)
    }
}

pub async fn initiate<S>(
    mut stream: S,
    identity: &Identity,
) -> Result<PendingChannel<S>, NetworkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = Builder::new(noise_params()?)
        .local_private_key(identity.private_key())
        .map_err(|_| NetworkError::Handshake)?
        .build_initiator()
        .map_err(|_| NetworkError::Handshake)?;
    let mut payload = vec![0u8; MAX_PACKET_SIZE];
    let mut message = vec![0u8; MAX_PACKET_SIZE];
    let length = handshake
        .write_message(PROTOCOL_MARKER, &mut message)
        .map_err(|_| NetworkError::Handshake)?;
    write_frame(&mut stream, &message[..length]).await?;
    let incoming = read_frame(&mut stream).await?;
    let payload_length = handshake
        .read_message(&incoming, &mut payload)
        .map_err(|_| NetworkError::Handshake)?;
    if payload[..payload_length] != *PROTOCOL_MARKER {
        return Err(NetworkError::Handshake);
    }
    let length = handshake
        .write_message(PROTOCOL_MARKER, &mut message)
        .map_err(|_| NetworkError::Handshake)?;
    write_frame(&mut stream, &message[..length]).await?;
    finish_handshake(stream, handshake)
}

pub async fn respond<S>(
    mut stream: S,
    identity: &Identity,
) -> Result<PendingChannel<S>, NetworkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut handshake = Builder::new(noise_params()?)
        .local_private_key(identity.private_key())
        .map_err(|_| NetworkError::Handshake)?
        .build_responder()
        .map_err(|_| NetworkError::Handshake)?;
    let mut payload = vec![0u8; MAX_PACKET_SIZE];
    let mut message = vec![0u8; MAX_PACKET_SIZE];
    let incoming = read_frame(&mut stream).await?;
    let payload_length = handshake
        .read_message(&incoming, &mut payload)
        .map_err(|_| NetworkError::Handshake)?;
    if payload[..payload_length] != *PROTOCOL_MARKER {
        return Err(NetworkError::Handshake);
    }
    let length = handshake
        .write_message(PROTOCOL_MARKER, &mut message)
        .map_err(|_| NetworkError::Handshake)?;
    write_frame(&mut stream, &message[..length]).await?;
    let incoming = read_frame(&mut stream).await?;
    let payload_length = handshake
        .read_message(&incoming, &mut payload)
        .map_err(|_| NetworkError::Handshake)?;
    if payload[..payload_length] != *PROTOCOL_MARKER {
        return Err(NetworkError::Handshake);
    }
    finish_handshake(stream, handshake)
}

fn finish_handshake<S>(
    stream: S,
    handshake: HandshakeState,
) -> Result<PendingChannel<S>, NetworkError> {
    if !handshake.is_handshake_finished() {
        return Err(NetworkError::Handshake);
    }
    let remote_public_key = handshake
        .get_remote_static()
        .ok_or(NetworkError::Handshake)?
        .to_vec();
    let handshake_hash = handshake.get_handshake_hash().to_vec();
    let transport = handshake
        .into_transport_mode()
        .map_err(|_| NetworkError::Handshake)?;
    Ok(PendingChannel {
        stream,
        transport,
        remote_public_key,
        handshake_hash,
    })
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), NetworkError> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET_SIZE || bytes.len() > u32::MAX as usize {
        return Err(NetworkError::InvalidFrame);
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, NetworkError> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_PACKET_SIZE {
        return Err(NetworkError::InvalidFrame);
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub async fn connect(address: SocketAddr) -> Result<tokio::net::TcpStream, NetworkError> {
    Ok(tokio::net::TcpStream::connect(address).await?)
}

#[cfg(test)]
mod tests {
    use super::{NetworkError, connect, initiate, respond};
    use crate::Identity;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn noise_xx_authenticates_pins_and_encrypts_bidirectionally() {
        let alice = Identity::generate("Alice".to_string()).expect("Alice");
        let bob = Identity::generate("Bob".to_string()).expect("Bob");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let bob_key = bob.public_key().to_vec();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let pending = respond(stream, &bob).await.expect("handshake");
            let alice_key = pending.remote_public_key().to_vec();
            let mut channel = pending.verify_peer(&alice_key).expect("pin");
            let received = channel.receive().await.expect("receive");
            assert_eq!(received.as_slice(), b"hello Bob");
            channel.send(b"hello Alice").await.expect("reply");
        });
        let stream = connect(address).await.expect("connect");
        let pending = initiate(stream, &alice).await.expect("handshake");
        assert_eq!(pending.remote_public_key(), bob_key);
        let mut channel = pending.verify_peer(&bob_key).expect("pin");
        channel.send(b"hello Bob").await.expect("send");
        let received = channel.receive().await.expect("receive");
        assert_eq!(received.as_slice(), b"hello Alice");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn noise_xx_rejects_a_changed_contact_key() {
        let alice = Identity::generate("Alice".to_string()).expect("Alice");
        let bob = Identity::generate("Bob".to_string()).expect("Bob");
        let expected = Identity::generate("Other".to_string()).expect("Other");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            respond(stream, &bob).await.expect("handshake");
        });
        let stream = connect(address).await.expect("connect");
        let pending = initiate(stream, &alice).await.expect("handshake");
        assert!(matches!(
            pending.verify_peer(expected.public_key()),
            Err(NetworkError::PeerMismatch)
        ));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn oversized_network_frame_is_rejected_before_body_read() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer
            .write_all(&((64 * 1024 + 1) as u32).to_be_bytes())
            .await
            .expect("length");
        assert!(matches!(
            super::read_frame(&mut reader).await,
            Err(NetworkError::InvalidFrame)
        ));
    }

    async fn established_pair() -> (
        super::SecureChannel<tokio::net::TcpStream>,
        super::SecureChannel<tokio::net::TcpStream>,
    ) {
        let alice = std::sync::Arc::new(Identity::generate("Alice".to_string()).expect("Alice"));
        let bob = std::sync::Arc::new(Identity::generate("Bob".to_string()).expect("Bob"));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let server_bob = bob.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            respond(stream, &server_bob).await.expect("handshake")
        });
        let stream = connect(address).await.expect("connect");
        let pending = initiate(stream, &alice).await.expect("handshake");
        let alice_channel = pending.verify_peer(bob.public_key()).expect("verify Bob");
        let pending = server.await.expect("server task");
        let bob_channel = pending
            .verify_peer(alice.public_key())
            .expect("verify Alice");
        (alice_channel, bob_channel)
    }

    #[tokio::test]
    async fn authentication_failure_does_not_advance_nonce_and_old_session_ciphertext_fails() {
        let (mut alice, mut bob) = established_pair().await;
        let mut old_ciphertext = vec![0u8; 64];
        let length = alice
            .transport
            .write_message(b"old", &mut old_ciphertext)
            .expect("encrypt");
        old_ciphertext.truncate(length);
        let mut corrupted = old_ciphertext.clone();
        corrupted[length - 1] ^= 1;
        let mut plaintext = vec![0u8; 64];
        assert!(
            bob.transport
                .read_message(&corrupted, &mut plaintext)
                .is_err()
        );
        let opened = bob
            .transport
            .read_message(&old_ciphertext, &mut plaintext)
            .expect("valid ciphertext after rejected forgery");
        assert_eq!(&plaintext[..opened], b"old");

        let (_, mut new_bob) = established_pair().await;
        assert!(
            new_bob
                .transport
                .read_message(&old_ciphertext, &mut plaintext)
                .is_err()
        );
    }
}
