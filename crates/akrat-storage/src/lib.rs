use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use akrat_core::{Contact, Conversation, MessageDirection, PrivateIdentity, StoredMessage};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 1;
const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
const AAD: &[u8] = b"AKRAT-VAULT-V1";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("invalid or unsupported vault file")]
    InvalidFile,
    #[error("vault is too large")]
    TooLarge,
    #[error("passphrase must not be empty")]
    EmptyPassphrase,
    #[error("passphrase is too long")]
    PassphraseTooLong,
    #[error("secure random generation failed")]
    Random,
    #[error("vault authentication failed")]
    Authentication,
    #[error("vault encoding failed")]
    Encoding,
    #[error("vault data is inconsistent")]
    InconsistentData,
    #[error("vault KDF failed")]
    KeyDerivation,
    #[error("vault is locked")]
    SessionKeyUnavailable,
    #[error("vault file operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Default, Deserialize, Serialize)]
pub struct VaultData {
    pub identities: Vec<Arc<PrivateIdentity>>,
    pub contacts: Vec<Contact>,
    pub conversations: Vec<Conversation>,
    #[serde(default)]
    pub preferred_identity_id: Option<String>,
}

#[derive(Serialize)]
struct VaultDataRef<'a> {
    identities: Vec<&'a PrivateIdentity>,
    contacts: &'a [Contact],
    conversations: &'a [Conversation],
    preferred_identity_id: &'a Option<String>,
}

#[derive(Deserialize, Serialize)]
struct VaultEnvelope {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct VaultKey {
    salt: [u8; 16],
    key: Arc<Zeroizing<[u8; 32]>>,
}

pub fn seal_identities(
    identities: &[PrivateIdentity],
    passphrase: &str,
) -> Result<Vec<u8>, VaultError> {
    let mut seen = HashSet::new();
    if identities.iter().any(|identity| {
        !valid_private_identity(identity) || !seen.insert(identity.public.id.as_str())
    }) {
        return Err(VaultError::InconsistentData);
    }
    seal_serializable(
        &VaultDataRef {
            identities: identities.iter().collect(),
            contacts: &[],
            conversations: &[],
            preferred_identity_id: &None,
        },
        passphrase,
    )
}

pub fn seal_vault_data(data: &VaultData, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    validate_vault_data(data)?;
    seal_serializable(
        &VaultDataRef {
            identities: data.identities.iter().map(Arc::as_ref).collect(),
            contacts: &data.contacts,
            conversations: &data.conversations,
            preferred_identity_id: &data.preferred_identity_id,
        },
        passphrase,
    )
}

fn seal_serializable<T: Serialize>(data: &T, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    if passphrase.is_empty() {
        return Err(VaultError::EmptyPassphrase);
    }
    if passphrase.len() > 1024 {
        return Err(VaultError::PassphraseTooLong);
    }
    let plaintext = Zeroizing::new(serde_json::to_vec(data).map_err(|_| VaultError::Encoding)?);
    if plaintext.len() > MAX_FILE_SIZE {
        return Err(VaultError::TooLarge);
    }

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut salt).map_err(|_| VaultError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::KeyDerivation)?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| VaultError::InvalidFile)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|_| VaultError::Authentication)?;
    let envelope = VaultEnvelope {
        version: FORMAT_VERSION,
        salt,
        nonce: nonce.into(),
        ciphertext,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|_| VaultError::Encoding)?;
    if encoded.len() > MAX_FILE_SIZE {
        return Err(VaultError::TooLarge);
    }
    Ok(encoded)
}

pub fn open_identities(
    encoded: &[u8],
    passphrase: &str,
) -> Result<Vec<PrivateIdentity>, VaultError> {
    open_vault_data(encoded, passphrase)?
        .identities
        .into_iter()
        .map(|identity| Arc::try_unwrap(identity).map_err(|_| VaultError::InconsistentData))
        .collect()
}

pub fn open_vault_data(encoded: &[u8], passphrase: &str) -> Result<VaultData, VaultError> {
    open_vault_data_with_key(encoded, passphrase).map(|(data, _)| data)
}

pub fn open_vault_data_with_key(
    encoded: &[u8],
    passphrase: &str,
) -> Result<(VaultData, VaultKey), VaultError> {
    if passphrase.is_empty() {
        return Err(VaultError::EmptyPassphrase);
    }
    if passphrase.len() > 1024 {
        return Err(VaultError::PassphraseTooLong);
    }
    if encoded.len() > MAX_FILE_SIZE {
        return Err(VaultError::TooLarge);
    }
    let envelope: VaultEnvelope =
        serde_json::from_slice(encoded).map_err(|_| VaultError::InvalidFile)?;
    if envelope.version != FORMAT_VERSION || envelope.ciphertext.len() < 16 {
        return Err(VaultError::InvalidFile);
    }
    let key = Arc::new(derive_key(passphrase, &envelope.salt)?);
    let cipher =
        Aes256Gcm::new_from_slice(key.as_ref().as_ref()).map_err(|_| VaultError::KeyDerivation)?;
    let nonce = Nonce::try_from(envelope.nonce.as_slice()).map_err(|_| VaultError::InvalidFile)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope.ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| VaultError::Authentication)?,
    );
    match serde_json::from_slice::<VaultData>(&plaintext) {
        Ok(data) => {
            validate_vault_data(&data)?;
            Ok((
                data,
                VaultKey {
                    salt: envelope.salt,
                    key,
                },
            ))
        }
        Err(_) => {
            let identities: Vec<PrivateIdentity> =
                serde_json::from_slice(&plaintext).map_err(|_| VaultError::InvalidFile)?;
            let data = VaultData {
                identities: identities.into_iter().map(Arc::new).collect(),
                ..VaultData::default()
            };
            validate_vault_data(&data)?;
            Ok((
                data,
                VaultKey {
                    salt: envelope.salt,
                    key,
                },
            ))
        }
    }
}

pub fn save_vault(
    path: &Path,
    identities: &[PrivateIdentity],
    passphrase: &str,
) -> Result<(), VaultError> {
    let encoded = seal_identities(identities, passphrase)?;
    save_encoded(path, &encoded)
}

pub fn save_vault_data(path: &Path, data: &VaultData, passphrase: &str) -> Result<(), VaultError> {
    let encoded = seal_vault_data(data, passphrase)?;
    save_encoded(path, &encoded)
}

pub fn save_vault_data_and_key(
    path: &Path,
    data: &VaultData,
    passphrase: &str,
) -> Result<VaultKey, VaultError> {
    if passphrase.is_empty() {
        return Err(VaultError::EmptyPassphrase);
    }
    if passphrase.len() > 1024 {
        return Err(VaultError::PassphraseTooLong);
    }
    validate_vault_data(data)?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| VaultError::Random)?;
    let key = VaultKey {
        salt,
        key: Arc::new(derive_key(passphrase, &salt)?),
    };
    let encoded = encode_vault_data_with_key(data, &key)?;
    save_encoded(path, &encoded)?;
    Ok(key)
}

pub fn save_vault_data_with_key(
    path: &Path,
    data: &VaultData,
    key: &VaultKey,
) -> Result<(), VaultError> {
    let encoded = encode_vault_data_with_key(data, key)?;
    save_encoded(path, &encoded)
}

fn encode_vault_data_with_key(data: &VaultData, key: &VaultKey) -> Result<Vec<u8>, VaultError> {
    validate_vault_data(data)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&VaultDataRef {
            identities: data.identities.iter().map(Arc::as_ref).collect(),
            contacts: &data.contacts,
            conversations: &data.conversations,
            preferred_identity_id: &data.preferred_identity_id,
        })
        .map_err(|_| VaultError::Encoding)?,
    );
    if plaintext.len() > MAX_FILE_SIZE {
        return Err(VaultError::TooLarge);
    }
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| VaultError::Random)?;
    let cipher = Aes256Gcm::new_from_slice(key.key.as_ref().as_ref())
        .map_err(|_| VaultError::KeyDerivation)?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| VaultError::InvalidFile)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| VaultError::Authentication)?;
    let envelope = VaultEnvelope {
        version: FORMAT_VERSION,
        salt: key.salt,
        nonce: nonce.into(),
        ciphertext,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|_| VaultError::Encoding)?;
    if encoded.len() > MAX_FILE_SIZE {
        return Err(VaultError::TooLarge);
    }
    Ok(encoded)
}

fn save_encoded(path: &Path, encoded: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|_| VaultError::Random)?;
    let temporary_path = path.with_extension(format!("akrat-{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)?;
    let write_result = (|| {
        file.write_all(encoded)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)?;
        Ok::<(), std::io::Error>(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result.map_err(VaultError::Io)
}

pub fn load_vault(path: &Path, passphrase: &str) -> Result<Vec<PrivateIdentity>, VaultError> {
    load_vault_data(path, passphrase)?
        .identities
        .into_iter()
        .map(|identity| Arc::try_unwrap(identity).map_err(|_| VaultError::InconsistentData))
        .collect()
}

pub fn load_vault_data(path: &Path, passphrase: &str) -> Result<VaultData, VaultError> {
    load_vault_data_with_key(path, passphrase).map(|(data, _)| data)
}

pub fn load_vault_data_with_key(
    path: &Path,
    passphrase: &str,
) -> Result<(VaultData, VaultKey), VaultError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_FILE_SIZE as u64 {
        return Err(VaultError::TooLarge);
    }
    let mut encoded = Vec::new();
    file.take((MAX_FILE_SIZE + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_FILE_SIZE {
        return Err(VaultError::TooLarge);
    }
    open_vault_data_with_key(&encoded, passphrase)
}

pub fn append_message(
    data: &mut VaultData,
    conversation_id: &str,
    message: StoredMessage,
) -> Result<bool, VaultError> {
    let Some(conversation) = data
        .conversations
        .iter_mut()
        .find(|conversation| conversation.id == conversation_id)
    else {
        return Err(VaultError::InconsistentData);
    };
    if conversation
        .messages
        .iter()
        .any(|existing| existing.id == message.id)
    {
        return Ok(false);
    }
    let sender_matches = match message.direction {
        MessageDirection::Outgoing => message.sender_identity_id == conversation.local_identity_id,
        MessageDirection::Incoming => message.sender_identity_id == conversation.remote_identity_id,
    };
    if !sender_matches || message.text.len() > 64 * 1024 {
        return Err(VaultError::InconsistentData);
    }
    conversation.messages.push(message);
    validate_vault_data(data)?;
    Ok(true)
}

pub fn remove_conversation(data: &mut VaultData, conversation_id: &str) -> bool {
    let original_len = data.conversations.len();
    data.conversations
        .retain(|conversation| conversation.id != conversation_id);
    data.conversations.len() != original_len
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| VaultError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::KeyDerivation)?;
    Ok(key)
}

fn validate_vault_data(data: &VaultData) -> Result<(), VaultError> {
    let mut identity_ids = HashSet::new();
    for identity in &data.identities {
        if !valid_private_identity(identity) || !identity_ids.insert(identity.public.id.as_str()) {
            return Err(VaultError::InconsistentData);
        }
    }
    if data
        .preferred_identity_id
        .as_ref()
        .is_some_and(|preferred| !identity_ids.contains(preferred.as_str()))
    {
        return Err(VaultError::InconsistentData);
    }

    let mut contacts = HashSet::new();
    for contact in &data.contacts {
        if !valid_public_identity(&contact.id, &contact.public_key)
            || contact.fingerprint != fingerprint_for_key(&contact.public_key)
            || !contacts.insert(contact.id.as_str())
            || contact.addresses.len() > 8
            || contact.addresses.iter().any(|address| {
                address.parse::<std::net::SocketAddr>().is_err()
                    || address.parse::<std::net::SocketAddr>().is_ok_and(|parsed| {
                        parsed.to_string() != *address
                            || parsed.port() == 0
                            || parsed.ip().is_unspecified()
                            || parsed.ip().is_multicast()
                            || matches!(parsed.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
                    })
            })
        {
            return Err(VaultError::InconsistentData);
        }
    }

    let mut conversations = HashSet::new();
    for conversation in &data.conversations {
        if !conversations.insert(conversation.id.as_str())
            || !identity_ids.contains(conversation.local_identity_id.as_str())
            || !contacts.contains(conversation.remote_identity_id.as_str())
        {
            return Err(VaultError::InconsistentData);
        }
        let mut message_ids = HashSet::new();
        for message in &conversation.messages {
            let sender_matches = match message.direction {
                akrat_core::MessageDirection::Outgoing => {
                    message.sender_identity_id == conversation.local_identity_id
                }
                akrat_core::MessageDirection::Incoming => {
                    message.sender_identity_id == conversation.remote_identity_id
                }
            };
            if !sender_matches
                || message.text.len() > 64 * 1024
                || !message_ids.insert(message.id.as_str())
            {
                return Err(VaultError::InconsistentData);
            }
        }
    }
    Ok(())
}

fn valid_public_identity(identity_id: &str, public_key: &[u8]) -> bool {
    public_key.len() == 32 && hex::encode(Sha256::digest(public_key)) == identity_id
}

fn valid_private_identity(identity: &PrivateIdentity) -> bool {
    if !valid_public_identity(&identity.public.id, &identity.public.public_key) {
        return false;
    }
    if identity.public.fingerprint != fingerprint_for_key(&identity.public.public_key) {
        return false;
    }
    let signature = identity.sign(b"AKRAT-VAULT-IDENTITY-CHECK-V1");
    akrat_crypto::verify(
        &identity.public.public_key,
        b"AKRAT-VAULT-IDENTITY-CHECK-V1",
        &signature,
    )
    .is_ok()
}

fn fingerprint_for_key(public_key: &[u8]) -> String {
    Sha256::digest(public_key)
        .chunks_exact(2)
        .map(|chunk| format!("{:02X}{:02X}", chunk[0], chunk[1]))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::{
        VaultData, VaultError, append_message, load_vault, load_vault_data,
        load_vault_data_with_key, open_identities, open_vault_data, remove_conversation,
        save_vault, save_vault_data, save_vault_data_and_key, save_vault_data_with_key,
        seal_identities, seal_vault_data,
    };
    use akrat_core::{
        Contact, Conversation, IdentityTrust, MessageDelivery, MessageDirection, StoredMessage,
    };
    use akrat_crypto::create_identity;
    use std::sync::Arc;

    #[test]
    fn vault_round_trip_and_wrong_secret_rejection() {
        let identities = vec![create_identity("Personnel".to_string()).expect("identity")];
        let encoded = seal_identities(&identities, "correct horse battery staple").expect("seal");
        let decoded = open_identities(&encoded, "correct horse battery staple").expect("open");

        assert_eq!(decoded[0].public, identities[0].public);
        let signature = akrat_crypto::sign(&decoded[0], b"vault persistence check");
        assert!(
            akrat_crypto::verify(
                &identities[0].public.public_key,
                b"vault persistence check",
                &signature
            )
            .is_ok()
        );
        assert!(matches!(
            open_identities(&encoded, "wrong password"),
            Err(VaultError::Authentication)
        ));
    }

    #[test]
    fn encoded_vault_does_not_contain_identity_fields_or_passphrase() {
        let identity = create_identity("Secret Identity Label".to_string()).expect("identity");
        let encoded = seal_identities(&[identity], "a private passphrase").expect("seal");

        assert!(!String::from_utf8_lossy(&encoded).contains("Secret Identity Label"));
        assert!(!String::from_utf8_lossy(&encoded).contains("a private passphrase"));
    }

    #[test]
    fn modified_vault_is_rejected() {
        let identity = create_identity("Tamper test".to_string()).expect("identity");
        let mut encoded = seal_identities(&[identity], "tamper test passphrase").expect("seal");
        let last = encoded.len() - 1;
        encoded[last] ^= 1;

        assert!(matches!(
            open_identities(&encoded, "tamper test passphrase"),
            Err(VaultError::InvalidFile) | Err(VaultError::Authentication)
        ));
    }

    #[test]
    fn vault_file_round_trip() {
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).expect("random");
        let path = std::env::temp_dir().join(format!("akrat-test-{}.vault", hex::encode(random)));
        let identities = vec![create_identity("Persistent".to_string()).expect("identity")];

        save_vault(&path, &identities, "file vault passphrase").expect("save");
        save_vault(&path, &identities, "file vault passphrase").expect("replace");
        let loaded = load_vault(&path, "file vault passphrase").expect("load");
        assert_eq!(loaded[0].public, identities[0].public);
        assert!(matches!(
            load_vault(&path, "wrong passphrase"),
            Err(VaultError::Authentication)
        ));
        std::fs::remove_file(path).expect("remove test vault");
    }

    #[test]
    fn contacts_and_conversations_are_persisted_only_inside_the_encrypted_vault() {
        let identity = create_identity("Personnel".to_string()).expect("identity");
        let remote = create_identity("Remote".to_string()).expect("remote identity");
        let local_id = identity.public.id.clone();
        let remote_id = remote.public.id.clone();
        let data = VaultData {
            identities: vec![Arc::new(identity)],
            contacts: vec![Contact {
                id: remote.public.id.clone(),
                display_name: "Bob local label".to_string(),
                public_key: remote.public.public_key.clone(),
                fingerprint: remote.public.fingerprint.clone(),
                addresses: vec!["192.0.2.44:49444".to_string()],
                trust: IdentityTrust::ManuallyVerified,
                blocked: false,
                created_at_unix: 100,
                last_seen_at_unix: Some(110),
            }],
            conversations: vec![Conversation {
                id: "conversation-1".to_string(),
                local_identity_id: local_id,
                remote_identity_id: remote_id.clone(),
                created_at_unix: 100,
                messages: vec![StoredMessage {
                    id: "message-1".to_string(),
                    sender_identity_id: remote_id.clone(),
                    sent_at_unix: 101,
                    direction: MessageDirection::Incoming,
                    delivery: MessageDelivery::Received,
                    text: "private conversation text".to_string(),
                }],
            }],
            preferred_identity_id: None,
        };
        let encoded = seal_vault_data(&data, "conversation vault passphrase").expect("seal");
        assert!(!String::from_utf8_lossy(&encoded).contains("private conversation text"));
        let decoded = open_vault_data(&encoded, "conversation vault passphrase").expect("open");
        assert_eq!(decoded.contacts, data.contacts);
        assert_eq!(decoded.conversations, data.conversations);
        assert_eq!(decoded.identities[0].public, data.identities[0].public);

        let mut random = [0u8; 8];
        getrandom::fill(&mut random).expect("random");
        let path = std::env::temp_dir().join(format!("akrat-data-{}.vault", hex::encode(random)));
        save_vault_data(&path, &data, "conversation vault passphrase").expect("save");
        let loaded = load_vault_data(&path, "conversation vault passphrase").expect("load");
        assert_eq!(loaded.conversations, data.conversations);
        std::fs::remove_file(path).expect("remove vault");

        let mut working_copy = VaultData {
            identities: data.identities.clone(),
            contacts: data.contacts.clone(),
            conversations: data.conversations.clone(),
            preferred_identity_id: data.preferred_identity_id.clone(),
        };
        let repeated = working_copy.conversations[0].messages[0].clone();
        assert!(!append_message(&mut working_copy, "conversation-1", repeated).expect("dedupe"));
        let new_message = StoredMessage {
            id: "message-2".to_string(),
            sender_identity_id: remote_id.clone(),
            sent_at_unix: 102,
            direction: MessageDirection::Incoming,
            delivery: MessageDelivery::Received,
            text: "another private message".to_string(),
        };
        assert!(
            append_message(&mut working_copy, "conversation-1", new_message.clone())
                .expect("append")
        );
        assert!(!append_message(&mut working_copy, "conversation-1", new_message).expect("dedupe"));
        assert!(remove_conversation(&mut working_copy, "conversation-1"));
        assert!(!remove_conversation(&mut working_copy, "conversation-1"));

        let identities = open_identities(
            &seal_vault_data(&data, "identity-only passphrase").expect("seal"),
            "identity-only passphrase",
        )
        .expect("open identity-only API");
        assert_eq!(identities.len(), 1);
    }

    #[test]
    fn cached_vault_key_rewrites_and_reopens() {
        let identity = create_identity("Cached key".to_string()).expect("identity");
        let data = VaultData {
            identities: vec![Arc::new(identity)],
            ..VaultData::default()
        };
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).expect("random");
        let path = std::env::temp_dir().join(format!("akrat-cache-{}.vault", hex::encode(random)));
        let created_key = save_vault_data_and_key(&path, &data, "cached key test passphrase")
            .expect("initial save and key derivation");
        let (loaded, key) = load_vault_data_with_key(&path, "cached key test passphrase")
            .expect("unlock and derive key");
        assert_eq!(created_key.salt, key.salt);
        save_vault_data_with_key(&path, &loaded, &key).expect("rewrite using cached key");
        let reopened = load_vault_data(&path, "cached key test passphrase").expect("reopen");
        assert_eq!(reopened.identities.len(), 1);
        std::fs::remove_file(path).expect("remove test vault");
    }
}
