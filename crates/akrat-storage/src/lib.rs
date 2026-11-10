use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use akrat_core::PrivateIdentity;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
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
    #[error("vault KDF failed")]
    KeyDerivation,
    #[error("vault file operation failed")]
    Io(#[from] std::io::Error),
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
    if passphrase.is_empty() {
        return Err(VaultError::EmptyPassphrase);
    }
    if passphrase.len() > 1024 {
        return Err(VaultError::PassphraseTooLong);
    }
    let plaintext =
        Zeroizing::new(serde_json::to_vec(identities).map_err(|_| VaultError::Encoding)?);
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
    let identities: Vec<PrivateIdentity> =
        serde_json::from_slice(&plaintext).map_err(|_| VaultError::InvalidFile)?;
    Ok(identities)
}

pub fn save_vault(
    path: &Path,
    identities: &[PrivateIdentity],
    passphrase: &str,
) -> Result<(), VaultError> {
    let encoded = seal_identities(identities, passphrase)?;
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
        file.write_all(&encoded)?;
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
    open_identities(&encoded, passphrase)
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

#[cfg(test)]
mod tests {
    use super::{VaultError, load_vault, open_identities, save_vault, seal_identities};
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
}
