use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use image::{ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_ATTACHMENT_BYTES: usize = 16 * 1024 * 1024;
pub const ATTACHMENT_CHUNK_BYTES: usize = 32 * 1024;
pub const MAX_ATTACHMENT_CHUNKS: usize = MAX_ATTACHMENT_BYTES.div_ceil(ATTACHMENT_CHUNK_BYTES);
pub const MAX_IMAGE_DIMENSION: u32 = 8_192;
const MAX_IMAGE_PIXELS: u64 = 32_000_000;
const MAX_DECODE_ALLOCATION: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentManifest {
    pub version: u8,
    pub attachment_id: String,
    pub message_id: String,
    pub conversation_id: String,
    pub display_name: String,
    pub media_type: String,
    pub plaintext_size: u64,
    pub chunk_size: u32,
    pub chunk_count: u32,
    pub plaintext_sha256: String,
    pub content_key: Vec<u8>,
}

impl Drop for AttachmentManifest {
    fn drop(&mut self) {
        self.content_key.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttachmentChunk {
    pub version: u8,
    pub attachment_id: String,
    pub index: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum AttachmentError {
    #[error("image or attachment exceeds configured size limits")]
    TooLarge,
    #[error("image type, dimensions, or encoded data are invalid")]
    InvalidImage,
    #[error("attachment manifest or chunk is invalid")]
    InvalidTransfer,
    #[error("attachment authentication or integrity check failed")]
    Authentication,
    #[error("random number generation failed")]
    Random,
    #[error("attachment storage operation failed")]
    Io(#[from] std::io::Error),
    #[error("attachment encoding failed")]
    Encoding,
}

pub fn sanitize_image(input: &[u8]) -> Result<(Vec<u8>, String), AttachmentError> {
    if input.is_empty() || input.len() > MAX_ATTACHMENT_BYTES {
        return Err(AttachmentError::TooLarge);
    }
    let mut reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|_| AttachmentError::InvalidImage)?;
    let format = reader.format().ok_or(AttachmentError::InvalidImage)?;
    match format {
        ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP => {}
        _ => return Err(AttachmentError::InvalidImage),
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOCATION);
    reader.limits(limits);
    let decoded = reader.decode().map_err(|_| AttachmentError::InvalidImage)?;
    if decoded.width() == 0
        || decoded.height() == 0
        || u64::from(decoded.width()) * u64::from(decoded.height()) > MAX_IMAGE_PIXELS
    {
        return Err(AttachmentError::TooLarge);
    }
    let mut normalized = Cursor::new(Vec::new());
    decoded
        .write_to(&mut normalized, ImageFormat::Png)
        .map_err(|_| AttachmentError::Encoding)?;
    let bytes = normalized.into_inner();
    if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(AttachmentError::TooLarge);
    }
    Ok((bytes, "image/png".into()))
}

pub fn encrypt_image(
    input: &[u8],
    attachment_id: String,
    message_id: String,
    conversation_id: String,
    display_name: &str,
) -> Result<(AttachmentManifest, Vec<AttachmentChunk>), AttachmentError> {
    validate_id(&attachment_id)?;
    if message_id.is_empty()
        || message_id.len() > 128
        || conversation_id.is_empty()
        || conversation_id.len() > 256
    {
        return Err(AttachmentError::InvalidTransfer);
    }
    let safe_name = sanitize_display_name(display_name)?;
    let (sanitized, media_type) = sanitize_image(input)?;
    let plaintext = Zeroizing::new(sanitized);
    let chunk_count = plaintext.len().div_ceil(ATTACHMENT_CHUNK_BYTES);
    if chunk_count == 0 || chunk_count > MAX_ATTACHMENT_CHUNKS {
        return Err(AttachmentError::TooLarge);
    }
    let mut content_key = Zeroizing::new([0u8; 32]);
    getrandom::fill(content_key.as_mut()).map_err(|_| AttachmentError::Random)?;
    let manifest = AttachmentManifest {
        version: 1,
        attachment_id: attachment_id.clone(),
        message_id,
        conversation_id,
        display_name: safe_name,
        media_type,
        plaintext_size: plaintext.len() as u64,
        chunk_size: ATTACHMENT_CHUNK_BYTES as u32,
        chunk_count: chunk_count as u32,
        plaintext_sha256: hex::encode(Sha256::digest(plaintext.as_slice())),
        content_key: content_key.to_vec(),
    };
    validate_manifest(&manifest)?;
    let cipher = Aes256Gcm::new_from_slice(content_key.as_ref())
        .map_err(|_| AttachmentError::Authentication)?;
    let mut chunks = Vec::with_capacity(chunk_count);
    for (index, part) in plaintext.chunks(ATTACHMENT_CHUNK_BYTES).enumerate() {
        let mut nonce_bytes = [0u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|_| AttachmentError::Random)?;
        let nonce =
            Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| AttachmentError::Authentication)?;
        let aad = chunk_aad(&manifest, index as u32);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: part,
                    aad: &aad,
                },
            )
            .map_err(|_| AttachmentError::Authentication)?;
        chunks.push(AttachmentChunk {
            version: 1,
            attachment_id: attachment_id.clone(),
            index: index as u32,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        });
    }
    Ok((manifest, chunks))
}

pub fn decrypt_image(
    manifest: &AttachmentManifest,
    chunks: &[AttachmentChunk],
) -> Result<Vec<u8>, AttachmentError> {
    validate_manifest(manifest)?;
    if chunks.len() != manifest.chunk_count as usize {
        return Err(AttachmentError::InvalidTransfer);
    }
    let mut ordered: Vec<Option<&AttachmentChunk>> = vec![None; manifest.chunk_count as usize];
    for chunk in chunks {
        if chunk.version != 1
            || chunk.attachment_id != manifest.attachment_id
            || chunk.index >= manifest.chunk_count
            || chunk.nonce.len() != 12
            || chunk.ciphertext.len() > ATTACHMENT_CHUNK_BYTES + 16
            || ordered[chunk.index as usize].replace(chunk).is_some()
        {
            return Err(AttachmentError::InvalidTransfer);
        }
    }
    let key: [u8; 32] = manifest
        .content_key
        .as_slice()
        .try_into()
        .map_err(|_| AttachmentError::InvalidTransfer)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| AttachmentError::Authentication)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(manifest.plaintext_size as usize));
    for (index, maybe_chunk) in ordered.into_iter().enumerate() {
        let chunk = maybe_chunk.ok_or(AttachmentError::InvalidTransfer)?;
        let nonce = Nonce::try_from(chunk.nonce.as_slice())
            .map_err(|_| AttachmentError::InvalidTransfer)?;
        let aad = chunk_aad(manifest, index as u32);
        let mut block = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: chunk.ciphertext.as_slice(),
                        aad: &aad,
                    },
                )
                .map_err(|_| AttachmentError::Authentication)?,
        );
        let expected_len = if index + 1 == manifest.chunk_count as usize {
            manifest.plaintext_size as usize - index * manifest.chunk_size as usize
        } else {
            manifest.chunk_size as usize
        };
        if block.len() != expected_len {
            return Err(AttachmentError::InvalidTransfer);
        }
        plaintext.extend_from_slice(&block);
        block.zeroize();
    }
    if plaintext.len() != manifest.plaintext_size as usize
        || hex::encode(Sha256::digest(plaintext.as_slice())) != manifest.plaintext_sha256
    {
        return Err(AttachmentError::Authentication);
    }
    Ok(plaintext.to_vec())
}

pub fn attachment_sidecar_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".attachments");
    vault_path.with_file_name(name)
}

pub fn store_encrypted_chunks(
    sidecar: &Path,
    chunks: &[AttachmentChunk],
) -> Result<(), AttachmentError> {
    if chunks.is_empty() || chunks.len() > MAX_ATTACHMENT_CHUNKS {
        return Err(AttachmentError::InvalidTransfer);
    }
    let attachment_id = &chunks[0].attachment_id;
    validate_id(attachment_id)?;
    let directory = sidecar.join(attachment_id);
    fs::create_dir_all(&directory)?;
    for chunk in chunks {
        if chunk.attachment_id != *attachment_id
            || chunk.ciphertext.len() > ATTACHMENT_CHUNK_BYTES + 16
            || chunk.nonce.len() != 12
        {
            return Err(AttachmentError::InvalidTransfer);
        }
        let path = directory.join(format!("{:08}.chunk", chunk.index));
        let mut bytes = serde_json::to_vec(chunk).map_err(|_| AttachmentError::Encoding)?;
        let temporary = directory.join(format!("{:08}.chunk.tmp", chunk.index));
        let mut file = File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        bytes.zeroize();
    }
    Ok(())
}

pub fn load_encrypted_chunks(
    sidecar: &Path,
    manifest: &AttachmentManifest,
) -> Result<Vec<AttachmentChunk>, AttachmentError> {
    validate_manifest(manifest)?;
    let directory = sidecar.join(&manifest.attachment_id);
    let mut chunks = Vec::with_capacity(manifest.chunk_count as usize);
    for index in 0..manifest.chunk_count {
        let path = directory.join(format!("{index:08}.chunk"));
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take((ATTACHMENT_CHUNK_BYTES + 4096) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > ATTACHMENT_CHUNK_BYTES + 4096 {
            return Err(AttachmentError::TooLarge);
        }
        let chunk: AttachmentChunk =
            serde_json::from_slice(&bytes).map_err(|_| AttachmentError::InvalidTransfer)?;
        bytes.zeroize();
        chunks.push(chunk);
    }
    Ok(chunks)
}

pub fn remove_stored_attachment(
    sidecar: &Path,
    attachment_id: &str,
) -> Result<(), AttachmentError> {
    validate_id(attachment_id)?;
    let directory = sidecar.join(attachment_id);
    if directory.exists() {
        fs::remove_dir_all(directory)?;
    }
    Ok(())
}

pub fn validate_manifest(manifest: &AttachmentManifest) -> Result<(), AttachmentError> {
    if manifest.version != 1
        || validate_id(&manifest.attachment_id).is_err()
        || manifest.message_id.is_empty()
        || manifest.message_id.len() > 128
        || manifest.conversation_id.is_empty()
        || manifest.conversation_id.len() > 256
        || manifest.display_name.is_empty()
        || manifest.display_name.len() > 128
        || manifest.display_name.contains(['/', '\\', ':'])
        || manifest.media_type != "image/png"
        || manifest.plaintext_size == 0
        || manifest.plaintext_size > MAX_ATTACHMENT_BYTES as u64
        || manifest.chunk_size as usize != ATTACHMENT_CHUNK_BYTES
        || manifest.chunk_count == 0
        || manifest.chunk_count as usize > MAX_ATTACHMENT_CHUNKS
        || manifest.chunk_count as usize
            != (manifest.plaintext_size as usize).div_ceil(manifest.chunk_size as usize)
        || manifest.content_key.len() != 32
        || manifest.plaintext_sha256.len() != 64
        || hex::decode(&manifest.plaintext_sha256).is_err()
    {
        return Err(AttachmentError::InvalidTransfer);
    }
    Ok(())
}

fn chunk_aad(manifest: &AttachmentManifest, index: u32) -> Vec<u8> {
    format!(
        "AKRAT/attachment/v1\0{}\0{}\0{}\0{}\0{}\0{}",
        manifest.attachment_id,
        manifest.message_id,
        manifest.conversation_id,
        manifest.plaintext_size,
        manifest.chunk_count,
        index,
    )
    .into_bytes()
}

fn validate_id(id: &str) -> Result<(), AttachmentError> {
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AttachmentError::InvalidTransfer);
    }
    Ok(())
}

fn sanitize_display_name(name: &str) -> Result<String, AttachmentError> {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned = leaf
        .chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect::<String>();
    if cleaned.trim().is_empty() {
        return Err(AttachmentError::InvalidTransfer);
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{DynamicImage, ImageBuffer, ImageFormat, Rgba};

    fn sample_png() -> Vec<u8> {
        let image =
            DynamicImage::ImageRgba8(ImageBuffer::from_pixel(32, 24, Rgba([10, 20, 30, 255])));
        let mut output = Cursor::new(Vec::new());
        image
            .write_to(&mut output, ImageFormat::Png)
            .expect("encode PNG");
        output.into_inner()
    }

    #[test]
    fn chunk_encryption_round_trips_and_rejects_tampering_and_order_changes() {
        let image = sample_png();
        let (manifest, chunks) = encrypt_image(
            &image,
            "00112233445566778899aabbccddeeff".into(),
            "message-1".into(),
            "group:test".into(),
            "photo.png",
        )
        .expect("encrypt");
        let decrypted = decrypt_image(&manifest, &chunks).expect("decrypt");
        assert_eq!(decrypted, image);
        let mut changed = chunks.clone();
        changed[0].ciphertext[0] ^= 1;
        assert!(matches!(
            decrypt_image(&manifest, &changed),
            Err(AttachmentError::Authentication)
        ));
        let mut reordered = chunks.clone();
        reordered[0].index = 1;
        assert!(decrypt_image(&manifest, &reordered).is_err());
    }

    #[test]
    fn filenames_are_reduced_to_safe_leaf_names_and_types_are_normalized() {
        let image = sample_png();
        let (manifest, _) = encrypt_image(
            &image,
            "00112233445566778899aabbccddeeff".into(),
            "message-1".into(),
            "dm:test".into(),
            "C:\\Users\\Alice\\photo.png",
        )
        .expect("encrypt");
        assert_eq!(manifest.display_name, "photo.png");
        assert_eq!(manifest.media_type, "image/png");
        assert!(sanitize_image(b"not an image").is_err());
    }

    #[test]
    fn sidecar_contains_only_encrypted_chunks_and_restores_after_vault_move() {
        let directory = tempfile::tempdir().expect("temp directory");
        let image = sample_png();
        let (manifest, chunks) = encrypt_image(
            &image,
            "00112233445566778899aabbccddeeff".into(),
            "message-1".into(),
            "dm:test".into(),
            "photo.png",
        )
        .expect("encrypt");
        let sidecar = directory.path().join("vault.akrat.attachments");
        store_encrypted_chunks(&sidecar, &chunks).expect("save chunks");
        let files = load_encrypted_chunks(&sidecar, &manifest).expect("load encrypted chunks");
        assert_eq!(decrypt_image(&manifest, &files).expect("decrypt"), image);
        let encoded = fs::read(sidecar.join(&manifest.attachment_id).join("00000000.chunk"))
            .expect("read encrypted file");
        assert!(
            !encoded
                .windows(image.len().min(16))
                .any(|window| window == &image[..image.len().min(16)])
        );
    }

    #[test]
    fn oversized_manifests_and_bad_chunk_counts_fail_closed() {
        let image = sample_png();
        let (mut manifest, chunks) = encrypt_image(
            &image,
            "00112233445566778899aabbccddeeff".into(),
            "message-1".into(),
            "dm:test".into(),
            "photo.png",
        )
        .expect("encrypt");
        manifest.plaintext_size = MAX_ATTACHMENT_BYTES as u64 + 1;
        assert!(decrypt_image(&manifest, &chunks).is_err());
    }
}
