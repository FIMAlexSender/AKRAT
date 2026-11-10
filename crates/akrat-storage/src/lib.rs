use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use akrat_core::{Contact, Conversation, PrivateIdentity};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
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
    #[error("vault file operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Default, Deserialize, Serialize)]
pub struct VaultData {
    pub identities: Vec<PrivateIdentity>,
    pub contacts: Vec<Contact>,
    pub conversations: Vec<Conversation>,
}

#[derive(Serialize)]
struct VaultDataRef<'a> {
    identities: &'a [PrivateIdentity],
    contacts: &'a [Contact],
    conversations: &'a [Conversation],
}

#[derive(Deserialize, Serialize)]
struct VaultEnvelope {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
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
            identities,
            contacts: &[],
            conversations: &[],
        },
        passphrase,
    )
}

pub fn seal_vault_data(data: &VaultData, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    validate_vault_data(data)?;
    seal_serializable(
        &VaultDataRef {
            identities: &data.identities,
            contacts: &data.contacts,
            conversations: &data.conversations,
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
    Ok(open_vault_data(encoded, passphrase)?.identities)
}

pub fn open_vault_data(encoded: &[u8], passphrase: &str) -> Result<VaultData, VaultError> {
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
    let key = derive_key(passphrase, &envelope.salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| VaultError::KeyDerivation)?;
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
            Ok(data)
        }
        Err(_) => {
            let identities: Vec<PrivateIdentity> =
                serde_json::from_slice(&plaintext).map_err(|_| VaultError::InvalidFile)?;
            let data = VaultData {
                identities,
                ..VaultData::default()
            };
            validate_vault_data(&data)?;
            Ok(data)
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
    Ok(load_vault_data(path, passphrase)?.identities)
}

pub fn load_vault_data(path: &Path, passphrase: &str) -> Result<VaultData, VaultError> {
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
    open_vault_data(&encoded, passphrase)
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

    let mut contacts = HashSet::new();
    for contact in &data.contacts {
        if !valid_public_identity(&contact.id, &contact.public_key)
            || !contacts.insert(contact.id.as_str())
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
    let signature = identity.sign(b"AKRAT-VAULT-IDENTITY-CHECK-V1");
    akrat_crypto::verify(
        &identity.public.public_key,
        b"AKRAT-VAULT-IDENTITY-CHECK-V1",
        &signature,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::{
        VaultData, VaultError, load_vault, load_vault_data, open_identities, open_vault_data,
        save_vault, save_vault_data, seal_identities, seal_vault_data,
    };
    use akrat_core::{
        Contact, Conversation, IdentityTrust, MessageDelivery, MessageDirection, StoredMessage,
    };
    use akrat_crypto::create_identity;

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
            identities: vec![identity],
            contacts: vec![Contact {
                id: remote.public.id.clone(),
                display_name: "Bob local label".to_string(),
                public_key: remote.public.public_key.clone(),
                fingerprint: remote.public.fingerprint.clone(),
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
                    sender_identity_id: remote_id,
                    sent_at_unix: 101,
                    direction: MessageDirection::Incoming,
                    delivery: MessageDelivery::Received,
                    text: "private conversation text".to_string(),
                }],
            }],
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

        let identities = open_identities(
            &seal_identities(&data.identities, "identity-only passphrase").expect("seal"),
            "identity-only passphrase",
        )
        .expect("open identity-only API");
        assert_eq!(identities.len(), 1);
    }
}
