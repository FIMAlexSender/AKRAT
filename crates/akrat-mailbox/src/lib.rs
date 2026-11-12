use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
pub const MAX_BATCH_ITEMS: usize = 128;
pub const MAX_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_TOMBSTONES_PER_MAILBOX: i64 = 10_000;
const MAX_TOMBSTONES_TOTAL: i64 = 100_000;
const MAX_RECEIPTS_PER_MAILBOX: i64 = 10_000;
const MAX_RECEIPTS_TOTAL: i64 = 100_000;
const SCHEMA_VERSION: i64 = 5;
pub mod abuse;
pub mod key_rotation;
pub mod registry;
pub mod server;

#[derive(Debug, Error)]
pub enum MailboxError {
    #[error("storage operation failed")]
    Storage(#[from] rusqlite::Error),
    #[error("mailbox authentication failed")]
    Unauthorized,
    #[error("mailbox quota exceeded")]
    Quota,
    #[error("envelope is invalid or too large")]
    InvalidEnvelope,
    #[error("mailbox or message was not found")]
    NotFound,
    #[error("message id was reused with different content")]
    Conflict,
    #[error("invalid server signing key")]
    InvalidKey,
    #[error("configured storage limit is outside supported bounds")]
    InvalidLimit,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DepositReceipt {
    pub version: u8,
    pub server_fingerprint: String,
    pub mailbox_id: String,
    pub message_id: String,
    pub ciphertext_sha256: String,
    pub accepted_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryFailure {
    pub version: u8,
    pub server_fingerprint: String,
    pub mailbox_id: String,
    pub message_id: String,
    pub ciphertext_sha256: String,
    pub expires_at: u64,
    pub signed_at: u64,
    pub signature: String,
}

impl DeliveryFailure {
    fn create(
        signer: &ServerSigner,
        mailbox_id: &str,
        message_id: &str,
        ciphertext_digest: &[u8],
        expires_at: u64,
        signed_at: u64,
    ) -> Self {
        let mut failure = Self {
            version: 1,
            server_fingerprint: signer.fingerprint(),
            mailbox_id: mailbox_id.into(),
            message_id: message_id.into(),
            ciphertext_sha256: hex::encode(ciphertext_digest),
            expires_at,
            signed_at,
            signature: String::new(),
        };
        failure.signature =
            hex::encode(signer.0.sign(&delivery_failure_bytes(&failure)).to_bytes());
        failure
    }

    pub fn verify(&self, public_key: &[u8; 32]) -> Result<bool, MailboxError> {
        if self.version != 1
            || self.server_fingerprint != hex::encode(Sha256::digest(public_key))
            || !valid_id(&self.message_id)
            || self.mailbox_id.is_empty()
            || self.mailbox_id.len() > 128
            || self.ciphertext_sha256.len() != 64
            || hex::decode(&self.ciphertext_sha256).is_err()
            || self.signed_at < self.expires_at
            || self.signed_at > now()?.saturating_add(300)
        {
            return Ok(false);
        }
        let signature = Signature::from_slice(
            &hex::decode(&self.signature).map_err(|_| MailboxError::InvalidKey)?,
        )
        .map_err(|_| MailboxError::InvalidKey)?;
        let key = VerifyingKey::from_bytes(public_key).map_err(|_| MailboxError::InvalidKey)?;
        key.verify(&delivery_failure_bytes(self), &signature)
            .map(|_| true)
            .or(Ok(false))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub message_id: String,
    pub bytes: Vec<u8>,
    pub accepted_at: u64,
    pub expires_at: u64,
}

#[derive(Clone)]
pub struct ServerSigner(SigningKey);

impl ServerSigner {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MailboxError> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| MailboxError::InvalidKey)?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    pub fn generate() -> Result<Self, MailboxError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| MailboxError::InvalidKey)?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.public_key()))
    }

    pub fn sign_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        self.0.sign(bytes).to_bytes().to_vec()
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(
        path: impl AsRef<Path>,
        max_total_bytes: u64,
        max_mailboxes: u64,
    ) -> Result<Self, MailboxError> {
        if max_total_bytes == 0
            || max_mailboxes == 0
            || max_total_bytes > i64::MAX as u64
            || max_mailboxes > i64::MAX as u64
        {
            return Err(MailboxError::InvalidLimit);
        }
        let connection = Connection::open(path)?;
        let user_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if user_version > SCHEMA_VERSION {
            return Err(MailboxError::Quota);
        }
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS mailboxes (
                 id TEXT PRIMARY KEY,
                 write_hash BLOB NOT NULL,
                 read_hash BLOB NOT NULL,
                 bundle_hash BLOB,
                 quota_bytes INTEGER NOT NULL,
                 retention_seconds INTEGER NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS envelopes (
                 mailbox_id TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
                 message_id TEXT NOT NULL,
                 digest BLOB NOT NULL,
                 payload BLOB NOT NULL,
                 accepted_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 PRIMARY KEY(mailbox_id, message_id)
             );
             CREATE TABLE IF NOT EXISTS tombstones (
                 mailbox_id TEXT NOT NULL,
                 message_id TEXT NOT NULL,
                 digest BLOB NOT NULL,
                 removed_at INTEGER NOT NULL,
                 PRIMARY KEY(mailbox_id, message_id)
             );
             CREATE TABLE IF NOT EXISTS published_bundles (
                 mailbox_id TEXT PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
                 bundle BLOB NOT NULL,
                 updated_at INTEGER NOT NULL,
                 one_time_prekey_id INTEGER,
                 one_time_used INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS delivery_receipts (
                 mailbox_id TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
                 message_id TEXT NOT NULL,
                 receipt BLOB NOT NULL,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY(mailbox_id,message_id)
             );
             CREATE TABLE IF NOT EXISTS delivery_failures (
                 mailbox_id TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
                 message_id TEXT NOT NULL,
                 failure BLOB NOT NULL,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY(mailbox_id,message_id)
             );
             CREATE INDEX IF NOT EXISTS envelopes_expiry ON envelopes(expires_at);
             ",
        )?;
        let mailbox_columns = {
            let mut statement = connection.prepare("PRAGMA table_info(mailboxes)")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
            rows.collect::<Result<std::collections::HashSet<_>, _>>()?
        };
        if !mailbox_columns.contains("bundle_hash") {
            connection.execute("ALTER TABLE mailboxes ADD COLUMN bundle_hash BLOB", [])?;
        }
        let bundle_columns = {
            let mut statement = connection.prepare("PRAGMA table_info(published_bundles)")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
            rows.collect::<Result<std::collections::HashSet<_>, _>>()?
        };
        if !bundle_columns.contains("one_time_prekey_id") {
            connection.execute(
                "ALTER TABLE published_bundles ADD COLUMN one_time_prekey_id INTEGER",
                [],
            )?;
        }
        if !bundle_columns.contains("one_time_used") {
            connection.execute(
                "ALTER TABLE published_bundles ADD COLUMN one_time_used INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        connection.execute(
            "UPDATE published_bundles SET one_time_prekey_id=CAST(json_extract(bundle,'$.one_time_prekey_id') AS INTEGER) WHERE one_time_prekey_id IS NULL",
            [],
        )?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        connection.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('max_total_bytes', ?1), ('max_mailboxes', ?2)", params![max_total_bytes as i64, max_mailboxes as i64])?;
        let existing_total: i64 = connection.query_row(
            "SELECT value FROM settings WHERE key='max_total_bytes'",
            [],
            |row| row.get(0),
        )?;
        let existing_count: i64 = connection.query_row(
            "SELECT value FROM settings WHERE key='max_mailboxes'",
            [],
            |row| row.get(0),
        )?;
        if existing_total != max_total_bytes as i64 || existing_count != max_mailboxes as i64 {
            return Err(MailboxError::Quota);
        }
        Ok(Self { connection })
    }

    pub fn create_mailbox(
        &mut self,
        quota_bytes: u64,
        retention_seconds: u64,
    ) -> Result<(String, String, String, String), MailboxError> {
        if quota_bytes == 0
            || retention_seconds == 0
            || retention_seconds > MAX_RETENTION_SECONDS
            || quota_bytes > i64::MAX as u64
            || retention_seconds > i64::MAX as u64
        {
            return Err(MailboxError::InvalidLimit);
        }
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM mailboxes", [], |r| r.get(0))?;
        let maximum: i64 = self.connection.query_row(
            "SELECT value FROM settings WHERE key='max_mailboxes'",
            [],
            |r| r.get(0),
        )?;
        if count >= maximum {
            return Err(MailboxError::Quota);
        }
        let id = random_token()?;
        let write_cap = random_token()?;
        let read_cap = random_token()?;
        let bundle_cap = random_token()?;
        self.connection.execute("INSERT INTO mailboxes(id,write_hash,read_hash,bundle_hash,quota_bytes,retention_seconds,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![id, capability_hash(&write_cap), capability_hash(&read_cap), capability_hash(&bundle_cap), quota_bytes as i64, retention_seconds as i64, now()? as i64])?;
        Ok((id, write_cap, read_cap, bundle_cap))
    }

    pub fn publish_bundle(
        &mut self,
        mailbox_id: &str,
        write_capability: &str,
        bundle: &akrat_core::async_crypto::PublishedBundle,
    ) -> Result<(), MailboxError> {
        let encoded = serde_json::to_vec(bundle).map_err(|_| MailboxError::InvalidEnvelope)?;
        if encoded.is_empty()
            || encoded.len() > 16 * 1024
            || bundle.identity_public_key.len() != 33
            || akrat_core::async_crypto::verify_bundle(bundle, &bundle.identity_public_key[1..])
                .is_err()
        {
            return Err(MailboxError::InvalidEnvelope);
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let expected_hash: Option<Vec<u8>> = tx
            .query_row(
                "SELECT write_hash FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |row| row.get(0),
            )
            .optional()?;
        let expected_hash = expected_hash.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&expected_hash, &capability_hash(write_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        tx.execute(
            "INSERT INTO published_bundles(mailbox_id,bundle,updated_at,one_time_prekey_id,one_time_used) VALUES(?1,?2,?3,?4,0) ON CONFLICT(mailbox_id) DO UPDATE SET bundle=excluded.bundle,updated_at=excluded.updated_at,one_time_used=CASE WHEN published_bundles.one_time_prekey_id IS excluded.one_time_prekey_id THEN published_bundles.one_time_used ELSE 0 END,one_time_prekey_id=excluded.one_time_prekey_id",
            params![mailbox_id, encoded, now()? as i64, bundle.one_time_prekey_id.map(i64::from)],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_bundle(
        &mut self,
        mailbox_id: &str,
        bundle_capability: &str,
    ) -> Result<Option<akrat_core::async_crypto::PublishedBundle>, MailboxError> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let bundle_hash: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT bundle_hash FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bundle_hash) = bundle_hash else {
            return Err(MailboxError::NotFound);
        };
        let Some(bundle_hash) = bundle_hash else {
            return Err(MailboxError::Unauthorized);
        };
        if !constant_eq(&bundle_hash, &capability_hash(bundle_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let row: Option<(Vec<u8>, Option<i64>, i64)> = tx
            .query_row(
                "SELECT bundle,one_time_prekey_id,one_time_used FROM published_bundles WHERE mailbox_id=?1",
                [mailbox_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((encoded, one_time_id, one_time_used)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let mut bundle: akrat_core::async_crypto::PublishedBundle =
            serde_json::from_slice(&encoded).map_err(|_| MailboxError::InvalidEnvelope)?;
        if bundle.expires_at <= now()? {
            tx.execute(
                "DELETE FROM published_bundles WHERE mailbox_id=?1",
                [mailbox_id],
            )?;
            tx.commit()?;
            return Ok(None);
        }
        if one_time_used != 0 {
            bundle.one_time_prekey_id = None;
            bundle.one_time_prekey_public = None;
        } else if one_time_id.is_some() {
            tx.execute(
                "UPDATE published_bundles SET one_time_used=1 WHERE mailbox_id=?1",
                [mailbox_id],
            )?;
        }
        tx.commit()?;
        Ok(Some(bundle))
    }

    pub fn deposit(
        &mut self,
        mailbox_id: &str,
        write_capability: &str,
        message_id: &str,
        bytes: &[u8],
        signer: &ServerSigner,
    ) -> Result<DepositReceipt, MailboxError> {
        if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES || !valid_id(message_id) {
            return Err(MailboxError::InvalidEnvelope);
        }
        self.expire(signer)?;
        let tx = self.connection.transaction()?;
        let row: Option<(Vec<u8>, i64, i64)> = tx
            .query_row(
                "SELECT write_hash, quota_bytes, retention_seconds FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let (expected, quota, retention) = row.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&expected, &capability_hash(write_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let digest = Sha256::digest(bytes).to_vec();
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM envelopes WHERE mailbox_id=?1 AND message_id=?2",
                params![mailbox_id, message_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != digest {
                return Err(MailboxError::Conflict);
            }
            let (accepted_at, expires_at): (i64,i64) = tx.query_row("SELECT accepted_at,expires_at FROM envelopes WHERE mailbox_id=?1 AND message_id=?2", params![mailbox_id,message_id], |r| Ok((r.get(0)?,r.get(1)?)))?;
            tx.commit()?;
            return Ok(make_receipt(
                signer,
                mailbox_id,
                message_id,
                &digest,
                accepted_at as u64,
                expires_at as u64,
            ));
        }
        let gone: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM tombstones WHERE mailbox_id=?1 AND message_id=?2",
                params![mailbox_id, message_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(gone) = gone {
            return if gone == digest {
                Err(MailboxError::NotFound)
            } else {
                Err(MailboxError::Conflict)
            };
        }
        let tombstones: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tombstones WHERE mailbox_id=?1",
            [mailbox_id],
            |r| r.get(0),
        )?;
        let all_tombstones: i64 =
            tx.query_row("SELECT COUNT(*) FROM tombstones", [], |r| r.get(0))?;
        if tombstones >= MAX_TOMBSTONES_PER_MAILBOX || all_tombstones >= MAX_TOMBSTONES_TOTAL {
            return Err(MailboxError::Quota);
        }
        let used: i64 = tx.query_row(
            "SELECT COALESCE(SUM(length(payload)),0) FROM envelopes WHERE mailbox_id=?1",
            [mailbox_id],
            |r| r.get(0),
        )?;
        let total: i64 = tx.query_row(
            "SELECT COALESCE(SUM(length(payload)),0) FROM envelopes",
            [],
            |r| r.get(0),
        )?;
        let max_total: i64 = tx.query_row(
            "SELECT value FROM settings WHERE key='max_total_bytes'",
            [],
            |r| r.get(0),
        )?;
        if used.saturating_add(bytes.len() as i64) > quota
            || total.saturating_add(bytes.len() as i64) > max_total
        {
            return Err(MailboxError::Quota);
        }
        let accepted_at = now()?;
        let expires_at = accepted_at.saturating_add(retention as u64);
        tx.execute("INSERT INTO envelopes(mailbox_id,message_id,digest,payload,accepted_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6)", params![mailbox_id,message_id,digest,bytes,accepted_at as i64,expires_at as i64])?;
        tx.commit()?;
        Ok(make_receipt(
            signer,
            mailbox_id,
            message_id,
            &Sha256::digest(bytes),
            accepted_at,
            expires_at,
        ))
    }

    pub fn fetch(
        &self,
        mailbox_id: &str,
        read_capability: &str,
        limit: usize,
    ) -> Result<Vec<Envelope>, MailboxError> {
        if limit == 0 || limit > MAX_BATCH_ITEMS {
            return Err(MailboxError::InvalidEnvelope);
        }
        let expected: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT read_hash FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |r| r.get(0),
            )
            .optional()?;
        let expected = expected.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&expected, &capability_hash(read_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let mut statement = self.connection.prepare("SELECT message_id,payload,accepted_at,expires_at FROM envelopes WHERE mailbox_id=?1 AND expires_at>?2 ORDER BY accepted_at,message_id LIMIT ?3")?;
        let rows = statement.query_map(params![mailbox_id, now()? as i64, limit as i64], |r| {
            Ok(Envelope {
                message_id: r.get(0)?,
                bytes: r.get(1)?,
                accepted_at: r.get::<_, i64>(2)? as u64,
                expires_at: r.get::<_, i64>(3)? as u64,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(MailboxError::Storage)
    }

    pub fn acknowledge(
        &mut self,
        mailbox_id: &str,
        read_capability: &str,
        message_id: &str,
    ) -> Result<(), MailboxError> {
        if !valid_id(message_id) {
            return Err(MailboxError::InvalidEnvelope);
        }
        let tx = self.connection.transaction()?;
        let expected: Option<Vec<u8>> = tx
            .query_row(
                "SELECT read_hash FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |r| r.get(0),
            )
            .optional()?;
        let expected = expected.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&expected, &capability_hash(read_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let row: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM envelopes WHERE mailbox_id=?1 AND message_id=?2",
                params![mailbox_id, message_id],
                |r| r.get(0),
            )
            .optional()?;
        let digest = row.ok_or(MailboxError::NotFound)?;
        let tombstones: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tombstones WHERE mailbox_id=?1",
            [mailbox_id],
            |r| r.get(0),
        )?;
        let all_tombstones: i64 =
            tx.query_row("SELECT COUNT(*) FROM tombstones", [], |r| r.get(0))?;
        if tombstones >= MAX_TOMBSTONES_PER_MAILBOX || all_tombstones >= MAX_TOMBSTONES_TOTAL {
            return Err(MailboxError::Quota);
        }
        let timestamp = now()? as i64;
        tx.execute(
            "DELETE FROM envelopes WHERE mailbox_id=?1 AND message_id=?2",
            params![mailbox_id, message_id],
        )?;
        tx.execute("INSERT OR REPLACE INTO tombstones(mailbox_id,message_id,digest,removed_at) VALUES(?1,?2,?3,?4)", params![mailbox_id,message_id,digest,timestamp])?;
        tx.commit()?;
        Ok(())
    }

    pub fn acknowledge_with_receipt(
        &mut self,
        mailbox_id: &str,
        read_capability: &str,
        receipt: &akrat_core::async_crypto::RecipientReceipt,
    ) -> Result<(), MailboxError> {
        if !valid_id(&receipt.message_id)
            || receipt.mailbox_id != mailbox_id
            || !receipt
                .verify()
                .map_err(|_| MailboxError::InvalidEnvelope)?
            || receipt.received_at > now()?.saturating_add(300)
        {
            return Err(MailboxError::InvalidEnvelope);
        }
        let encoded = serde_json::to_vec(receipt).map_err(|_| MailboxError::InvalidEnvelope)?;
        if encoded.len() > 4096 {
            return Err(MailboxError::InvalidEnvelope);
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let auth: Option<(Vec<u8>, i64)> = tx
            .query_row(
                "SELECT read_hash,retention_seconds FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (read_hash, _retention) = auth.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&read_hash, &capability_hash(read_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT receipt FROM delivery_receipts WHERE mailbox_id=?1 AND message_id=?2",
                params![mailbox_id, receipt.message_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == encoded {
                tx.commit()?;
                return Ok(());
            }
            return Err(MailboxError::Conflict);
        }
        let envelope: Option<(Vec<u8>, i64, i64)> = tx.query_row(
            "SELECT digest,accepted_at,expires_at FROM envelopes WHERE mailbox_id=?1 AND message_id=?2",
            params![mailbox_id, receipt.message_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        let (digest, accepted_at, expires_at) = envelope.ok_or(MailboxError::NotFound)?;
        let now = now()?;
        if expires_at as u64 <= now
            || receipt.received_at < accepted_at as u64
            || receipt.ciphertext_sha256 != hex::encode(&digest)
        {
            return Err(MailboxError::InvalidEnvelope);
        }
        let mailbox_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM delivery_receipts WHERE mailbox_id=?1",
            [mailbox_id],
            |row| row.get(0),
        )?;
        let total_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM delivery_receipts", [], |row| {
                row.get(0)
            })?;
        if mailbox_count >= MAX_RECEIPTS_PER_MAILBOX || total_count >= MAX_RECEIPTS_TOTAL {
            return Err(MailboxError::Quota);
        }
        let tombstones: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tombstones WHERE mailbox_id=?1",
            [mailbox_id],
            |row| row.get(0),
        )?;
        let all_tombstones: i64 =
            tx.query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))?;
        if tombstones >= MAX_TOMBSTONES_PER_MAILBOX || all_tombstones >= MAX_TOMBSTONES_TOTAL {
            return Err(MailboxError::Quota);
        }
        tx.execute("INSERT INTO delivery_receipts(mailbox_id,message_id,receipt,created_at) VALUES(?1,?2,?3,?4)", params![mailbox_id, receipt.message_id, encoded, now as i64])?;
        tx.execute(
            "DELETE FROM envelopes WHERE mailbox_id=?1 AND message_id=?2",
            params![mailbox_id, receipt.message_id],
        )?;
        tx.execute("INSERT OR REPLACE INTO tombstones(mailbox_id,message_id,digest,removed_at) VALUES(?1,?2,?3,?4)", params![mailbox_id, receipt.message_id, digest, now as i64])?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_recipient_receipt(
        &self,
        mailbox_id: &str,
        write_capability: &str,
        message_id: &str,
    ) -> Result<Option<akrat_core::async_crypto::RecipientReceipt>, MailboxError> {
        if !valid_id(message_id) {
            return Err(MailboxError::InvalidEnvelope);
        }
        let write_hash: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT write_hash FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |row| row.get(0),
            )
            .optional()?;
        let write_hash = write_hash.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&write_hash, &capability_hash(write_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT receipt FROM delivery_receipts WHERE mailbox_id=?1 AND message_id=?2",
                params![mailbox_id, message_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| MailboxError::InvalidEnvelope))
            .transpose()
    }

    pub fn get_delivery_failure(
        &self,
        mailbox_id: &str,
        write_capability: &str,
        message_id: &str,
    ) -> Result<Option<DeliveryFailure>, MailboxError> {
        let write_hash: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT write_hash FROM mailboxes WHERE id=?1",
                [mailbox_id],
                |row| row.get(0),
            )
            .optional()?;
        let write_hash = write_hash.ok_or(MailboxError::NotFound)?;
        if !constant_eq(&write_hash, &capability_hash(write_capability)) {
            return Err(MailboxError::Unauthorized);
        }
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT failure FROM delivery_failures WHERE mailbox_id=?1 AND message_id=?2",
                params![mailbox_id, message_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| MailboxError::InvalidEnvelope))
            .transpose()
    }

    pub fn expire(&mut self, signer: &ServerSigner) -> Result<usize, MailboxError> {
        let tx = self.connection.transaction()?;
        let timestamp = now()? as i64;
        tx.execute(
            "DELETE FROM delivery_receipts WHERE created_at<?1",
            [timestamp.saturating_sub(30 * 24 * 3600)],
        )?;
        tx.execute(
            "DELETE FROM delivery_failures WHERE created_at<?1",
            [timestamp.saturating_sub(30 * 24 * 3600)],
        )?;
        tx.execute(
            "DELETE FROM tombstones WHERE removed_at<?1",
            [timestamp.saturating_sub(30 * 24 * 3600)],
        )?;
        let mut expired_by_mailbox = std::collections::BTreeMap::<String, i64>::new();
        {
            let mut statement = tx.prepare(
                "SELECT mailbox_id,COUNT(*) FROM envelopes WHERE expires_at<=?1 GROUP BY mailbox_id",
            )?;
            let rows = statement.query_map([timestamp], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (mailbox_id, count) = row?;
                expired_by_mailbox.insert(mailbox_id, count);
            }
        }
        let current_total: i64 =
            tx.query_row("SELECT COUNT(*) FROM tombstones", [], |row| row.get(0))?;
        let expected_total = expired_by_mailbox.values().sum::<i64>();
        let mut exceeds_limit = current_total.saturating_add(expected_total) > MAX_TOMBSTONES_TOTAL;
        for (mailbox_id, additions) in &expired_by_mailbox {
            let current: i64 = tx.query_row(
                "SELECT COUNT(*) FROM tombstones WHERE mailbox_id=?1",
                [mailbox_id],
                |row| row.get(0),
            )?;
            if current.saturating_add(*additions) > MAX_TOMBSTONES_PER_MAILBOX {
                exceeds_limit = true;
            }
        }
        if exceeds_limit {
            tx.commit()?;
            return Err(MailboxError::Quota);
        }
        let expired_rows = {
            let mut statement = tx.prepare(
                "SELECT mailbox_id,message_id,digest,expires_at FROM envelopes WHERE expires_at<=?1",
            )?;
            let rows = statement.query_map([timestamp], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut total_failures: i64 =
            tx.query_row("SELECT COUNT(*) FROM delivery_failures", [], |row| {
                row.get(0)
            })?;
        let mut failure_counts = std::collections::BTreeMap::<String, i64>::new();
        {
            let mut statement = tx
                .prepare("SELECT mailbox_id,COUNT(*) FROM delivery_failures GROUP BY mailbox_id")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (mailbox_id, count) = row?;
                failure_counts.insert(mailbox_id, count);
            }
        }
        for (mailbox_id, message_id, digest, expires_at) in &expired_rows {
            let mailbox_failures = failure_counts.entry(mailbox_id.clone()).or_default();
            if total_failures >= MAX_RECEIPTS_TOTAL || *mailbox_failures >= MAX_RECEIPTS_PER_MAILBOX
            {
                continue;
            }
            let failure = DeliveryFailure::create(
                signer,
                mailbox_id,
                message_id,
                digest,
                *expires_at as u64,
                timestamp as u64,
            );
            let added = tx.execute(
                "INSERT OR IGNORE INTO delivery_failures(mailbox_id,message_id,failure,created_at) VALUES(?1,?2,?3,?4)",
                params![mailbox_id, message_id, serde_json::to_vec(&failure).map_err(|_| MailboxError::InvalidEnvelope)?, timestamp],
            )?;
            total_failures += added as i64;
            *mailbox_failures += added as i64;
        }
        let changed = tx.execute("INSERT OR REPLACE INTO tombstones(mailbox_id,message_id,digest,removed_at) SELECT mailbox_id,message_id,digest,?1 FROM envelopes WHERE expires_at<=?1", [timestamp])?;
        tx.execute("DELETE FROM envelopes WHERE expires_at<=?1", [timestamp])?;
        tx.commit()?;
        Ok(changed)
    }

    pub fn status(&self) -> Result<(u64, u64, u64), MailboxError> {
        let boxes: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM mailboxes", [], |r| r.get(0))?;
        let messages: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))?;
        let bytes: i64 = self.connection.query_row(
            "SELECT COALESCE(SUM(length(payload)),0) FROM envelopes",
            [],
            |r| r.get(0),
        )?;
        Ok((boxes as u64, messages as u64, bytes as u64))
    }
}

pub fn verify_receipt(
    receipt: &DepositReceipt,
    public_key: &[u8; 32],
) -> Result<bool, MailboxError> {
    if receipt.version != 1 || receipt.server_fingerprint != hex::encode(Sha256::digest(public_key))
    {
        return Ok(false);
    }
    let signature_bytes = hex::decode(&receipt.signature).map_err(|_| MailboxError::InvalidKey)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| MailboxError::InvalidKey)?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| MailboxError::InvalidKey)?;
    key.verify(&receipt_bytes(receipt), &signature)
        .map(|_| true)
        .or(Ok(false))
}

fn make_receipt(
    signer: &ServerSigner,
    mailbox_id: &str,
    message_id: &str,
    digest: &[u8],
    accepted_at: u64,
    expires_at: u64,
) -> DepositReceipt {
    let mut receipt = DepositReceipt {
        version: 1,
        server_fingerprint: signer.fingerprint(),
        mailbox_id: mailbox_id.into(),
        message_id: message_id.into(),
        ciphertext_sha256: hex::encode(digest),
        accepted_at,
        expires_at,
        signature: String::new(),
    };
    receipt.signature = hex::encode(signer.0.sign(&receipt_bytes(&receipt)).to_bytes());
    receipt
}

fn receipt_bytes(receipt: &DepositReceipt) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AKRAT/mailbox-receipt/v1\0");
    for value in [
        &receipt.server_fingerprint,
        &receipt.mailbox_id,
        &receipt.message_id,
        &receipt.ciphertext_sha256,
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&receipt.accepted_at.to_be_bytes());
    bytes.extend_from_slice(&receipt.expires_at.to_be_bytes());
    bytes
}

fn delivery_failure_bytes(failure: &DeliveryFailure) -> Vec<u8> {
    let mut bytes = b"AKRAT/delivery-failure/v1\0".to_vec();
    for value in [
        &failure.server_fingerprint,
        &failure.mailbox_id,
        &failure.message_id,
        &failure.ciphertext_sha256,
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&failure.expires_at.to_be_bytes());
    bytes.extend_from_slice(&failure.signed_at.to_be_bytes());
    bytes
}

fn capability_hash(value: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"AKRAT/mailbox-capability/v1\0");
    hash.update(value.as_bytes());
    hash.finalize().to_vec()
}

fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn random_token() -> Result<String, MailboxError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| MailboxError::InvalidKey)?;
    Ok(hex::encode(bytes))
}

fn valid_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
}

fn now() -> Result<u64, MailboxError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| MailboxError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (
        Store,
        tempfile::TempDir,
        ServerSigner,
        String,
        String,
        String,
        String,
    ) {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("mailbox.sqlite3");
        let mut store = Store::open(path, 1024 * 1024, 8).expect("store");
        let (id, write, read, bundle) = store.create_mailbox(1024, 60).expect("mailbox");
        (
            store,
            directory,
            ServerSigner::generate().expect("signer"),
            id,
            write,
            read,
            bundle,
        )
    }

    #[test]
    fn stores_opaque_envelope_and_signs_receipt() {
        let (mut store, _directory, signer, id, write, read, _) = setup();
        let ciphertext = [0xA5; 64];
        let receipt = store
            .deposit(&id, &write, "0123456789abcdef", &ciphertext, &signer)
            .expect("deposit");
        assert!(verify_receipt(&receipt, &signer.public_key()).expect("verify"));
        let fetched = store.fetch(&id, &read, 8).expect("fetch");
        assert_eq!(fetched[0].bytes, ciphertext);
        assert!(store.fetch(&id, "00", 8).is_err());
    }

    #[test]
    fn retries_are_idempotent_and_conflicts_are_rejected() {
        let (mut store, _directory, signer, id, write, _read, _) = setup();
        let first = store
            .deposit(&id, &write, "0123456789abcdef", b"opaque", &signer)
            .expect("first");
        let retry = store
            .deposit(&id, &write, "0123456789abcdef", b"opaque", &signer)
            .expect("retry");
        assert_eq!(first, retry);
        assert!(matches!(
            store.deposit(&id, &write, "0123456789abcdef", b"different", &signer),
            Err(MailboxError::Conflict)
        ));
    }

    #[test]
    fn quotas_acknowledgement_and_expiry_are_enforced() {
        let (mut store, _directory, signer, id, write, read, _) = setup();
        assert!(matches!(
            store.deposit(&id, &write, "0123456789abcdef", &[1; 1025], &signer),
            Err(MailboxError::Quota)
        ));
        store
            .deposit(&id, &write, "0123456789abcdef", b"opaque", &signer)
            .expect("deposit");
        store
            .acknowledge(&id, &read, "0123456789abcdef")
            .expect("ack");
        assert!(matches!(
            store.deposit(&id, &write, "0123456789abcdef", b"opaque", &signer),
            Err(MailboxError::NotFound)
        ));
        assert_eq!(store.status().expect("status").1, 0);
    }

    #[test]
    fn expired_envelopes_are_removed_and_cannot_be_replayed_as_new() {
        let (mut store, _directory, signer, id, write, _read, _) = setup();
        store
            .deposit(&id, &write, "0123456789abcdef", b"opaque", &signer)
            .expect("deposit");
        store
            .connection
            .execute("UPDATE envelopes SET expires_at=0", [])
            .expect("expire fixture");
        assert_eq!(store.expire(&signer).expect("cleanup"), 1);
        assert_eq!(store.status().expect("status").1, 0);
        let failure = store
            .get_delivery_failure(&id, &write, "0123456789abcdef")
            .expect("failure query")
            .expect("signed expiry event");
        assert!(
            failure
                .verify(&signer.public_key())
                .expect("failure signature")
        );
        assert!(matches!(
            store.deposit(&id, &write, "0123456789abcdef", b"opaque", &signer),
            Err(MailboxError::NotFound)
        ));
    }

    #[test]
    fn mailbox_records_persist_after_reopening_database() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("mailbox.sqlite3");
        let signer = ServerSigner::generate().expect("signer");
        let (id, read) = {
            let mut store = Store::open(&path, 1024 * 1024, 8).expect("store");
            let (id, write, read, _) = store.create_mailbox(1024, 60).expect("mailbox");
            store
                .deposit(&id, &write, "0123456789abcdef", b"opaque", &signer)
                .expect("deposit");
            (id, read)
        };
        let reopened = Store::open(&path, 1024 * 1024, 8).expect("reopen");
        assert_eq!(
            reopened.fetch(&id, &read, 8).expect("fetch")[0].bytes,
            b"opaque"
        );
    }

    #[tokio::test]
    async fn only_the_write_capability_can_publish_a_valid_signed_bundle() {
        let (mut store, _directory, _signer, id, write, read, bundle_cap) = setup();
        let bob = akrat_core::Identity::generate("Bob".into()).expect("identity");
        let (bundle, _state) = akrat_core::async_crypto::publish_bundle(&bob, &[])
            .await
            .expect("bundle");
        assert!(matches!(
            store.publish_bundle(&id, "wrong-capability", &bundle),
            Err(MailboxError::Unauthorized)
        ));
        store
            .publish_bundle(&id, &write, &bundle)
            .expect("publish bundle");
        assert!(matches!(
            store.get_bundle(&id, "wrong-capability"),
            Err(MailboxError::Unauthorized)
        ));
        store
            .publish_bundle(&id, &write, &bundle)
            .expect("publish bundle");
        assert!(matches!(
            store.get_bundle(&id, &write),
            Err(MailboxError::Unauthorized)
        ));
        assert!(matches!(
            store.get_bundle(&id, &read),
            Err(MailboxError::Unauthorized)
        ));
        assert_eq!(
            store.get_bundle(&id, &bundle_cap).expect("load bundle"),
            Some(bundle.clone())
        );
        let consumed = store
            .get_bundle(&id, &bundle_cap)
            .expect("load consumed bundle")
            .expect("bundle");
        assert_eq!(consumed.one_time_prekey_id, None);
        assert_eq!(consumed.one_time_prekey_public, None);
        assert_eq!(consumed.signed_prekey_id, bundle.signed_prekey_id);
    }
}
