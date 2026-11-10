pub mod network;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{Builder, params::NoiseParams};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const FORMAT_VERSION: u8 = 1;
const MAX_VAULT_SIZE: usize = 16 * 1024 * 1024;
const NOISE_PROTOCOL: &str = "Noise_XX_25519_AESGCM_SHA256";

#[derive(Debug, Error)]
pub enum AkratError {
    #[error("vault file is invalid or from an unsupported version")]
    InvalidVault,
    #[error("vault authentication failed")]
    Authentication,
    #[error("vault serialization failed")]
    Serialization,
    #[error("random number generation failed")]
    Random,
    #[error("cryptographic identity could not be created")]
    Identity,
    #[error("identity or invitation is invalid")]
    InvalidIdentity,
    #[error("I/O operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub name: String,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Identity {
    pub fn generate(name: String) -> Result<Self, AkratError> {
        if name.trim().is_empty() || name.len() > 128 {
            return Err(AkratError::InvalidIdentity);
        }
        let builder = Builder::new(noise_params()?);
        let keypair = builder
            .generate_keypair()
            .map_err(|_| AkratError::Identity)?;
        let id = hex::encode(Sha256::digest(&keypair.public));
        Ok(Self {
            id,
            name,
            public_key: keypair.public,
            private_key: keypair.private,
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }

    pub(crate) fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub fingerprint: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub address: String,
    pub manually_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u8,
    pub fingerprint: String,
    pub public_key: Vec<u8>,
    pub address: String,
}

impl Invitation {
    pub fn create(identity: &Identity, address: String) -> Result<Self, AkratError> {
        let address = address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| AkratError::InvalidIdentity)?;
        if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
            return Err(AkratError::InvalidIdentity);
        }
        Ok(Self {
            version: FORMAT_VERSION,
            fingerprint: identity.fingerprint(),
            public_key: identity.public_key().to_vec(),
            address: address.to_string(),
        })
    }

    pub fn to_uri(&self) -> Result<String, AkratError> {
        let encoded = serde_json::to_vec(self).map_err(|_| AkratError::Serialization)?;
        Ok(format!(
            "akrat://invite/{}",
            URL_SAFE_NO_PAD.encode(encoded)
        ))
    }

    pub fn from_uri(uri: &str) -> Result<Self, AkratError> {
        if uri.len() > 4096 {
            return Err(AkratError::InvalidIdentity);
        }
        let payload = uri
            .strip_prefix("akrat://invite/")
            .ok_or(AkratError::InvalidIdentity)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| AkratError::InvalidIdentity)?;
        let invitation: Self =
            serde_json::from_slice(&bytes).map_err(|_| AkratError::InvalidIdentity)?;
        let address = invitation
            .address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| AkratError::InvalidIdentity)?;
        if invitation.version != FORMAT_VERSION
            || invitation.public_key.len() != 32
            || invitation.fingerprint != fingerprint(&invitation.public_key)
            || address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
        {
            return Err(AkratError::InvalidIdentity);
        }
        Ok(invitation)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StoredMessage {
    pub conversation: String,
    pub id: String,
    pub outgoing: bool,
    pub text: String,
    pub delivery: DeliveryState,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum DeliveryState {
    Pending,
    Sent,
    Received,
    Acknowledged,
    Unconfirmed,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultData {
    pub identities: Vec<Identity>,
    pub contacts: Vec<Contact>,
    pub messages: Vec<StoredMessage>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEnvelope {
    version: u8,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

pub fn fingerprint(public_key: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key))
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn save_vault(path: &Path, data: &VaultData, passphrase: &str) -> Result<(), AkratError> {
    validate_vault(data)?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| AkratError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| AkratError::Random)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, key.as_mut())
        .map_err(|_| AkratError::Authentication)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AkratError::Authentication)?;
    let mut plaintext =
        Zeroizing::new(serde_json::to_vec(data).map_err(|_| AkratError::Serialization)?);
    if plaintext.len() > MAX_VAULT_SIZE {
        return Err(AkratError::InvalidVault);
    }
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| AkratError::Authentication)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| AkratError::Authentication)?;
    plaintext.zeroize();
    let envelope = VaultEnvelope {
        version: FORMAT_VERSION,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|_| AkratError::Serialization)?;
    write_atomically(path, &encoded)
}

pub fn load_vault(path: &Path, passphrase: &str) -> Result<VaultData, AkratError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_VAULT_SIZE as u64 {
        return Err(AkratError::InvalidVault);
    }
    let mut encoded = Vec::new();
    file.take((MAX_VAULT_SIZE + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_VAULT_SIZE {
        return Err(AkratError::InvalidVault);
    }
    let envelope: VaultEnvelope =
        serde_json::from_slice(&encoded).map_err(|_| AkratError::InvalidVault)?;
    if envelope.version != FORMAT_VERSION
        || envelope.salt.len() != 16
        || envelope.nonce.len() != 12
        || envelope.ciphertext.len() < 16
    {
        return Err(AkratError::InvalidVault);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &envelope.salt, key.as_mut())
        .map_err(|_| AkratError::Authentication)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| AkratError::Authentication)?;
    let nonce = Nonce::try_from(envelope.nonce.as_slice()).map_err(|_| AkratError::InvalidVault)?;
    let plaintext = cipher
        .decrypt(&nonce, envelope.ciphertext.as_slice())
        .map_err(|_| AkratError::Authentication)?;
    let mut plaintext = Zeroizing::new(plaintext);
    let result = serde_json::from_slice(&plaintext).map_err(|_| AkratError::InvalidVault)?;
    plaintext.zeroize();
    validate_vault(&result)?;
    Ok(result)
}

fn validate_vault(data: &VaultData) -> Result<(), AkratError> {
    let mut identities = std::collections::HashSet::new();
    for identity in &data.identities {
        if identity.public_key.len() != 32
            || identity.private_key.len() != 32
            || identity.id != hex::encode(Sha256::digest(&identity.public_key))
            || identity.name.trim().is_empty()
            || !identities.insert(identity.id.as_str())
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut contacts = std::collections::HashSet::new();
    for contact in &data.contacts {
        if contact.public_key.len() != 32
            || contact.fingerprint != fingerprint(&contact.public_key)
            || contact.address.parse::<std::net::SocketAddr>().is_err()
            || !contacts.insert(contact.fingerprint.as_str())
        {
            return Err(AkratError::InvalidVault);
        }
    }
    let mut messages = std::collections::HashSet::new();
    for message in &data.messages {
        if message.id.is_empty()
            || message.text.len() > MAX_VAULT_SIZE
            || !messages.insert((message.conversation.as_str(), message.id.as_str()))
        {
            return Err(AkratError::InvalidVault);
        }
    }
    Ok(())
}

fn write_atomically(path: &Path, data: &[u8]) -> Result<(), AkratError> {
    write_atomically_with_interrupt(path, data, false)
}

fn write_atomically_with_interrupt(
    path: &Path,
    data: &[u8],
    interrupt_after_sync: bool,
) -> Result<(), AkratError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| AkratError::Random)?;
    let temporary = path.with_extension(format!("{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        if interrupt_after_sync {
            drop(file);
            return Err(std::io::Error::other("injected process interruption"));
        }
        drop(file);
        fs::rename(&temporary, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(AkratError::Io)
}

pub(crate) fn noise_params() -> Result<NoiseParams, AkratError> {
    NOISE_PROTOCOL.parse().map_err(|_| AkratError::Identity)
}

#[cfg(test)]
mod tests {
    use super::{
        AkratError, Contact, DeliveryState, Identity, Invitation, StoredMessage, VaultData,
        load_vault, save_vault, write_atomically_with_interrupt,
    };
    use std::fs;

    #[test]
    fn encrypted_vault_round_trips_identity_contact_and_history() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let identity = Identity::generate("Alice".to_string()).expect("identity");
        let bob = Identity::generate("Bob".to_string()).expect("Bob");
        let data = VaultData {
            identities: vec![identity],
            contacts: vec![Contact {
                fingerprint: bob.fingerprint(),
                name: "Bob".to_string(),
                public_key: bob.public_key().to_vec(),
                address: "127.0.0.1:4000".to_string(),
                manually_verified: true,
            }],
            messages: vec![StoredMessage {
                conversation: "peer".to_string(),
                id: "message-1".to_string(),
                outgoing: false,
                text: "hello".to_string(),
                delivery: DeliveryState::Received,
                timestamp: 42,
            }],
        };
        save_vault(&path, &data, "correct horse battery staple").expect("save");
        let bytes = fs::read(&path).expect("read vault");
        assert!(!String::from_utf8_lossy(&bytes).contains("correct horse battery staple"));
        assert!(!String::from_utf8_lossy(&bytes).contains("hello"));
        let loaded = load_vault(&path, "correct horse battery staple").expect("load");
        assert_eq!(loaded.identities.len(), 1);
        assert_eq!(loaded.identities[0].id, data.identities[0].id);
        assert_eq!(loaded.contacts[0].name, "Bob");
        assert_eq!(loaded.messages[0].text, "hello");
    }

    #[test]
    fn wrong_passphrase_and_tampering_fail_closed() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        save_vault(&path, &VaultData::default(), "secret").expect("save");
        assert!(matches!(
            load_vault(&path, "wrong"),
            Err(AkratError::Authentication)
        ));
        let mut data = fs::read(&path).expect("read");
        let last = data.len() - 4;
        data[last] ^= 1;
        fs::write(&path, data).expect("tamper");
        assert!(load_vault(&path, "secret").is_err());
    }

    #[test]
    fn replacing_vault_preserves_the_latest_complete_state() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let mut data = VaultData::default();
        save_vault(&path, &data, "secret").expect("first save");
        data.identities
            .push(Identity::generate("Alice".to_string()).expect("identity"));
        save_vault(&path, &data, "secret").expect("replacement save");
        let reopened = load_vault(&path, "secret").expect("reopen");
        assert_eq!(reopened.identities.len(), 1);
    }

    #[test]
    fn interruption_after_temporary_file_sync_keeps_previous_vault() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("vault.akrat");
        let original = VaultData::default();
        save_vault(&path, &original, "secret").expect("initial save");
        let previous = fs::read(&path).expect("original bytes");
        assert!(write_atomically_with_interrupt(&path, b"incomplete replacement", true).is_err());
        assert_eq!(fs::read(&path).expect("preserved bytes"), previous);
        assert!(load_vault(&path, "secret").is_ok());
    }

    #[test]
    fn invitation_round_trips_and_rejects_changed_keys() {
        let identity = Identity::generate("Alice".to_string()).expect("identity");
        let invitation =
            Invitation::create(&identity, "127.0.0.1:4000".to_string()).expect("invitation");
        let uri = invitation.to_uri().expect("uri");
        assert_eq!(Invitation::from_uri(&uri).expect("parse"), invitation);
        assert!(Invitation::from_uri("akrat://invite/not-base64!").is_err());
    }
}
