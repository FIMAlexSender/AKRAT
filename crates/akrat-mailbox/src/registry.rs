use crate::ServerSigner;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_ANNOUNCEMENTS: usize = 512;
pub const MAX_ANNOUNCEMENT_LIFETIME: u64 = 30 * 24 * 3600;
pub const MAX_DELTA_ANNOUNCEMENTS: usize = 12;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NodeAnnouncement {
    pub version: u8,
    pub node_fingerprint: String,
    pub signing_public_key: String,
    pub noise_public_key: String,
    pub endpoint: String,
    pub operator: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub host_name: String,
    #[serde(default)]
    pub server_identity: Option<crate::key_rotation::ServerIdentity>,
    pub protocol_min: u16,
    pub protocol_max: u16,
    pub capabilities: Vec<String>,
    pub max_storage_bytes: u64,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Discovered,
    Verified,
    Approved,
    Blocked,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub version: u8,
    pub source_fingerprint: String,
    pub sequence: u64,
    pub generated_at: u64,
    pub announcements: Vec<NodeAnnouncement>,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryDelta {
    pub version: u8,
    pub source_fingerprint: String,
    pub after_sequence: u64,
    pub cursor: u64,
    pub has_more: bool,
    pub generated_at: u64,
    pub announcements: Vec<NodeAnnouncement>,
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry storage failed")]
    Storage(#[from] rusqlite::Error),
    #[error("signature, version, timestamp, or announcement is invalid")]
    Invalid,
    #[error("registry snapshot is older than the locally accepted snapshot")]
    Rollback,
    #[error("server is not locally trusted for this operation")]
    Untrusted,
}

pub struct LocalRegistry {
    connection: Connection,
}

impl NodeAnnouncement {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        signer: &ServerSigner,
        noise_public_key: &[u8],
        endpoint: String,
        operator: String,
        protocol_min: u16,
        protocol_max: u16,
        capabilities: Vec<String>,
        max_storage_bytes: u64,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, RegistryError> {
        let public_key = signer.public_key();
        let mut value = Self {
            version: 1,
            node_fingerprint: hex::encode(Sha256::digest(public_key)),
            signing_public_key: hex::encode(public_key),
            noise_public_key: hex::encode(noise_public_key),
            endpoint,
            operator,
            name: String::new(),
            description: String::new(),
            host_name: String::new(),
            server_identity: None,
            protocol_min,
            protocol_max,
            capabilities,
            max_storage_bytes,
            sequence,
            issued_at,
            expires_at,
            signature: String::new(),
        };
        value.validate(issued_at)?;
        value.signature = hex::encode(
            signer
                .signing_key()
                .sign(&announcement_bytes(&value))
                .to_bytes(),
        );
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_profile(
        signer: &ServerSigner,
        noise_public_key: &[u8],
        endpoint: String,
        operator: String,
        name: String,
        description: String,
        host_name: String,
        protocol_min: u16,
        protocol_max: u16,
        capabilities: Vec<String>,
        max_storage_bytes: u64,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, RegistryError> {
        let mut value = Self::create(
            signer,
            noise_public_key,
            endpoint,
            operator,
            protocol_min,
            protocol_max,
            capabilities,
            max_storage_bytes,
            sequence,
            issued_at,
            expires_at,
        )?;
        value.version = 2;
        value.name = name;
        value.description = description;
        value.host_name = host_name;
        value.validate(issued_at)?;
        value.signature = hex::encode(
            signer
                .signing_key()
                .sign(&announcement_bytes(&value))
                .to_bytes(),
        );
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_profile_with_identity(
        signer: &ServerSigner,
        noise_public_key: &[u8],
        endpoint: String,
        operator: String,
        name: String,
        description: String,
        host_name: String,
        protocol_min: u16,
        protocol_max: u16,
        capabilities: Vec<String>,
        max_storage_bytes: u64,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        server_identity: crate::key_rotation::ServerIdentity,
    ) -> Result<Self, RegistryError> {
        let mut value = Self::create_profile(
            signer,
            noise_public_key,
            endpoint,
            operator,
            name,
            description,
            host_name,
            protocol_min,
            protocol_max,
            capabilities,
            max_storage_bytes,
            sequence,
            issued_at,
            expires_at,
        )?;
        value.version = 3;
        value.server_identity = Some(server_identity);
        value.validate(issued_at)?;
        value.signature = hex::encode(
            signer
                .signing_key()
                .sign(&announcement_bytes(&value))
                .to_bytes(),
        );
        Ok(value)
    }

    pub fn verify(&self, now: u64) -> Result<(), RegistryError> {
        self.validate(now)?;
        let public_bytes =
            hex::decode(&self.signing_public_key).map_err(|_| RegistryError::Invalid)?;
        let public: [u8; 32] = public_bytes
            .try_into()
            .map_err(|_| RegistryError::Invalid)?;
        let key = VerifyingKey::from_bytes(&public).map_err(|_| RegistryError::Invalid)?;
        let signature = Signature::from_slice(
            &hex::decode(&self.signature).map_err(|_| RegistryError::Invalid)?,
        )
        .map_err(|_| RegistryError::Invalid)?;
        key.verify(&announcement_bytes(self), &signature)
            .map_err(|_| RegistryError::Invalid)
    }

    fn validate(&self, now: u64) -> Result<(), RegistryError> {
        let fingerprint =
            hex::decode(&self.signing_public_key).map_err(|_| RegistryError::Invalid)?;
        let noise = hex::decode(&self.noise_public_key).map_err(|_| RegistryError::Invalid)?;
        if !matches!(self.version, 1..=3)
            || fingerprint.len() != 32
            || noise.len() != 32
            || self.node_fingerprint != hex::encode(Sha256::digest(&fingerprint))
            || self.endpoint.is_empty()
            || self.endpoint.len() > 512
            || self.operator.len() > 128
            || (self.version == 1
                && (!self.name.is_empty()
                    || !self.description.is_empty()
                    || !self.host_name.is_empty()))
            || (self.version == 2
                && (self.name.trim().is_empty()
                    || self.name.len() > 128
                    || self.description.len() > 280
                    || self.host_name.len() > 128))
            || (self.version < 3 && self.server_identity.is_some())
            || (self.version == 3
                && self.server_identity.as_ref().is_none_or(|identity| {
                    let Ok(root) = <[u8; 32]>::try_from(fingerprint.as_slice()) else {
                        return true;
                    };
                    identity.verify(&root, 0, 0, now).is_err()
                }))
            || self.protocol_min == 0
            || self.protocol_min > self.protocol_max
            || self.capabilities.len() > 32
            || self.capabilities.iter().any(|item| {
                item.is_empty()
                    || item.len() > 64
                    || !item
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.max_storage_bytes == 0
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_ANNOUNCEMENT_LIFETIME
            || self.issued_at > now.saturating_add(300)
            || self.expires_at <= now
        {
            return Err(RegistryError::Invalid);
        }
        Ok(())
    }
}

impl RegistrySnapshot {
    pub fn sign(
        signer: &ServerSigner,
        sequence: u64,
        generated_at: u64,
        announcements: Vec<NodeAnnouncement>,
    ) -> Result<Self, RegistryError> {
        if sequence == 0
            || sequence > i64::MAX as u64
            || generated_at > i64::MAX as u64
            || announcements.len() > MAX_ANNOUNCEMENTS
        {
            return Err(RegistryError::Invalid);
        }
        let source_fingerprint = signer.fingerprint();
        let mut snapshot = Self {
            version: 1,
            source_fingerprint,
            sequence,
            generated_at,
            announcements,
            signature: String::new(),
        };
        snapshot.signature = hex::encode(
            signer
                .signing_key()
                .sign(&snapshot_bytes(&snapshot))
                .to_bytes(),
        );
        Ok(snapshot)
    }

    pub fn verify(&self, trusted_source_key: &[u8; 32], now: u64) -> Result<(), RegistryError> {
        if self.version != 1
            || self.sequence == 0
            || self.sequence > i64::MAX as u64
            || self.generated_at > i64::MAX as u64
            || self.announcements.len() > MAX_ANNOUNCEMENTS
            || self.generated_at > now.saturating_add(300)
            || now.saturating_sub(self.generated_at) > MAX_ANNOUNCEMENT_LIFETIME
            || self.source_fingerprint != hex::encode(Sha256::digest(trusted_source_key))
        {
            return Err(RegistryError::Invalid);
        }
        let key =
            VerifyingKey::from_bytes(trusted_source_key).map_err(|_| RegistryError::Invalid)?;
        let signature = Signature::from_slice(
            &hex::decode(&self.signature).map_err(|_| RegistryError::Invalid)?,
        )
        .map_err(|_| RegistryError::Invalid)?;
        key.verify(&snapshot_bytes(self), &signature)
            .map_err(|_| RegistryError::Invalid)?;
        let mut fingerprints = std::collections::HashSet::new();
        for item in &self.announcements {
            item.verify(now)?;
            if !fingerprints.insert(item.node_fingerprint.as_str()) {
                return Err(RegistryError::Invalid);
            }
        }
        Ok(())
    }
}

impl RegistryDelta {
    fn sign(
        signer: &ServerSigner,
        after_sequence: u64,
        cursor: u64,
        has_more: bool,
        generated_at: u64,
        announcements: Vec<NodeAnnouncement>,
    ) -> Self {
        let mut delta = Self {
            version: 1,
            source_fingerprint: signer.fingerprint(),
            after_sequence,
            cursor,
            has_more,
            generated_at,
            announcements,
            signature: String::new(),
        };
        delta.signature = hex::encode(signer.signing_key().sign(&delta_bytes(&delta)).to_bytes());
        delta
    }

    pub fn verify(&self, trusted_source_key: &[u8; 32], now: u64) -> Result<(), RegistryError> {
        if self.version != 1
            || self.source_fingerprint != hex::encode(Sha256::digest(trusted_source_key))
            || self.cursor < self.after_sequence
            || self.after_sequence > i64::MAX as u64
            || self.cursor > i64::MAX as u64
            || self.announcements.len() > MAX_DELTA_ANNOUNCEMENTS
            || self.generated_at > now.saturating_add(300)
            || now.saturating_sub(self.generated_at) > MAX_ANNOUNCEMENT_LIFETIME
            || (self.cursor == self.after_sequence
                && (!self.announcements.is_empty() || self.has_more))
        {
            return Err(RegistryError::Invalid);
        }
        let key =
            VerifyingKey::from_bytes(trusted_source_key).map_err(|_| RegistryError::Invalid)?;
        let signature = Signature::from_slice(
            &hex::decode(&self.signature).map_err(|_| RegistryError::Invalid)?,
        )
        .map_err(|_| RegistryError::Invalid)?;
        key.verify(&delta_bytes(self), &signature)
            .map_err(|_| RegistryError::Invalid)?;
        let mut fingerprints = std::collections::HashSet::new();
        for announcement in &self.announcements {
            announcement.verify(now)?;
            if !fingerprints.insert(announcement.node_fingerprint.as_str()) {
                return Err(RegistryError::Invalid);
            }
        }
        Ok(())
    }
}

impl LocalRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let connection = Connection::open(path)?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS trusted_sources(fingerprint TEXT PRIMARY KEY, public_key BLOB NOT NULL); CREATE TABLE IF NOT EXISTS accepted_snapshots(fingerprint TEXT PRIMARY KEY, sequence INTEGER NOT NULL, generated_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS known_nodes(fingerprint TEXT PRIMARY KEY, announcement BLOB NOT NULL, trust_status TEXT NOT NULL, observed_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS registry_meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS registry_changes(sequence INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL, announcement BLOB NOT NULL); CREATE TABLE IF NOT EXISTS federation_cursors(fingerprint TEXT PRIMARY KEY, sequence INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS federation_outbound_cursors(fingerprint TEXT PRIMARY KEY, sequence INTEGER NOT NULL);")?;
        connection.execute("INSERT INTO registry_changes(fingerprint,announcement) SELECT fingerprint,announcement FROM known_nodes WHERE NOT EXISTS(SELECT 1 FROM registry_changes)", [])?;
        Ok(Self { connection })
    }

    pub fn add_trusted_source(&mut self, public_key: &[u8; 32]) -> Result<String, RegistryError> {
        let fingerprint = hex::encode(Sha256::digest(public_key));
        self.connection.execute(
            "INSERT OR IGNORE INTO trusted_sources(fingerprint,public_key) VALUES(?1,?2)",
            params![fingerprint, public_key.as_slice()],
        )?;
        Ok(fingerprint)
    }

    pub fn remove_trusted_source(&mut self, fingerprint: &str) -> Result<(), RegistryError> {
        self.connection.execute(
            "DELETE FROM trusted_sources WHERE fingerprint=?1",
            [fingerprint],
        )?;
        Ok(())
    }

    pub fn next_sequence(&self, fingerprint: &str) -> Result<u64, RegistryError> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT announcement FROM known_nodes WHERE fingerprint=?1",
                [fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        match encoded {
            Some(encoded) => {
                let announcement: NodeAnnouncement =
                    serde_json::from_slice(&encoded).map_err(|_| RegistryError::Invalid)?;
                announcement
                    .sequence
                    .checked_add(1)
                    .filter(|sequence| *sequence <= i64::MAX as u64)
                    .ok_or(RegistryError::Invalid)
            }
            None => Ok(1),
        }
    }

    pub fn signed_delta(
        &self,
        signer: &ServerSigner,
        after_sequence: u64,
        now: u64,
    ) -> Result<RegistryDelta, RegistryError> {
        if after_sequence > i64::MAX as u64 {
            return Err(RegistryError::Invalid);
        }
        let mut statement = self.connection.prepare(
            "SELECT sequence,announcement FROM registry_changes WHERE sequence>?1 ORDER BY sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![after_sequence as i64, (MAX_DELTA_ANNOUNCEMENTS + 1) as i64],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        let mut changes = Vec::new();
        for row in rows {
            let (sequence, encoded) = row?;
            let announcement: NodeAnnouncement =
                serde_json::from_slice(&encoded).map_err(|_| RegistryError::Invalid)?;
            changes.push((sequence as u64, announcement));
        }
        let has_more = changes.len() > MAX_DELTA_ANNOUNCEMENTS;
        changes.truncate(MAX_DELTA_ANNOUNCEMENTS);
        let cursor = changes
            .last()
            .map_or(after_sequence, |(sequence, _)| *sequence);
        // A node can publish several updates between syncs. Keep only its
        // newest announcement in each page: receivers reject duplicate
        // fingerprints within a signed delta.
        let mut latest_by_fingerprint = std::collections::HashMap::new();
        for (sequence, announcement) in changes {
            latest_by_fingerprint.insert(
                announcement.node_fingerprint.clone(),
                (sequence, announcement),
            );
        }
        let mut latest: Vec<_> = latest_by_fingerprint.into_values().collect();
        latest.sort_by_key(|(sequence, _)| *sequence);
        let announcements = latest
            .into_iter()
            .map(|(_, item)| item)
            .filter(|item| item.verify(now).is_ok())
            .collect();
        Ok(RegistryDelta::sign(
            signer,
            after_sequence,
            cursor,
            has_more,
            now,
            announcements,
        ))
    }

    pub fn federation_cursor(&self, fingerprint: &str) -> Result<u64, RegistryError> {
        self.connection
            .query_row(
                "SELECT sequence FROM federation_cursors WHERE fingerprint=?1",
                [fingerprint],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|value| value.unwrap_or_default() as u64)
            .map_err(RegistryError::Storage)
    }

    pub fn outbound_cursor(&self, fingerprint: &str) -> Result<u64, RegistryError> {
        self.connection
            .query_row(
                "SELECT sequence FROM federation_outbound_cursors WHERE fingerprint=?1",
                [fingerprint],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map(|value| value.unwrap_or_default() as u64)
            .map_err(RegistryError::Storage)
    }

    pub fn set_outbound_cursor(
        &self,
        fingerprint: &str,
        sequence: u64,
    ) -> Result<(), RegistryError> {
        self.connection.execute(
            "INSERT INTO federation_outbound_cursors(fingerprint,sequence) VALUES(?1,?2) ON CONFLICT(fingerprint) DO UPDATE SET sequence=excluded.sequence",
            params![fingerprint, sequence as i64],
        )?;
        Ok(())
    }

    pub fn import_delta(
        &mut self,
        delta: &RegistryDelta,
        now: u64,
    ) -> Result<usize, RegistryError> {
        let key_bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT public_key FROM trusted_sources WHERE fingerprint=?1",
                [&delta.source_fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        let key_bytes = key_bytes.ok_or(RegistryError::Untrusted)?;
        let key: [u8; 32] = key_bytes.try_into().map_err(|_| RegistryError::Invalid)?;
        delta.verify(&key, now)?;
        let current = self.federation_cursor(&delta.source_fingerprint)?;
        if current != delta.after_sequence {
            return Err(RegistryError::Rollback);
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut imported = 0;
        for announcement in &delta.announcements {
            let existing: Option<(i64, String)> = tx.query_row(
                "SELECT CAST(json_extract(announcement,'$.sequence') AS INTEGER),trust_status FROM known_nodes WHERE fingerprint=?1",
                [&announcement.node_fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            if existing
                .as_ref()
                .is_some_and(|(sequence, _)| *sequence >= announcement.sequence as i64)
            {
                continue;
            }
            let encoded = serde_json::to_vec(announcement).map_err(|_| RegistryError::Invalid)?;
            let trust = existing.map_or("discovered".to_owned(), |(_, trust)| trust);
            tx.execute(
                "INSERT INTO known_nodes(fingerprint,announcement,trust_status,observed_at) VALUES(?1,?2,?3,?4) ON CONFLICT(fingerprint) DO UPDATE SET announcement=excluded.announcement,observed_at=excluded.observed_at",
                params![announcement.node_fingerprint, encoded, trust, now as i64],
            )?;
            tx.execute(
                "INSERT INTO registry_changes(fingerprint,announcement) VALUES(?1,?2)",
                params![
                    announcement.node_fingerprint,
                    serde_json::to_vec(announcement).map_err(|_| RegistryError::Invalid)?
                ],
            )?;
            imported += 1;
        }
        tx.execute(
            "INSERT INTO federation_cursors(fingerprint,sequence) VALUES(?1,?2) ON CONFLICT(fingerprint) DO UPDATE SET sequence=excluded.sequence",
            params![delta.source_fingerprint, delta.cursor as i64],
        )?;
        tx.commit()?;
        Ok(imported)
    }

    pub fn known_nodes(&self) -> Result<Vec<(NodeAnnouncement, TrustStatus)>, RegistryError> {
        let mut statement = self
            .connection
            .prepare("SELECT announcement,trust_status FROM known_nodes ORDER BY fingerprint")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut nodes = Vec::new();
        for row in rows {
            let (encoded, status) = row?;
            let announcement =
                serde_json::from_slice(&encoded).map_err(|_| RegistryError::Invalid)?;
            let status = match status.as_str() {
                "discovered" => TrustStatus::Discovered,
                "verified" => TrustStatus::Verified,
                "approved" => TrustStatus::Approved,
                "blocked" => TrustStatus::Blocked,
                _ => return Err(RegistryError::Invalid),
            };
            nodes.push((announcement, status));
        }
        Ok(nodes)
    }

    pub fn publish_announcement(
        &mut self,
        announcement: &NodeAnnouncement,
        now: u64,
    ) -> Result<(), RegistryError> {
        announcement.verify(now)?;
        let existing: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT announcement FROM known_nodes WHERE fingerprint=?1",
                [&announcement.node_fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(encoded) = existing {
            let old: NodeAnnouncement =
                serde_json::from_slice(&encoded).map_err(|_| RegistryError::Invalid)?;
            if old.sequence >= announcement.sequence {
                return Err(RegistryError::Rollback);
            }
        } else {
            let count: i64 =
                self.connection
                    .query_row("SELECT COUNT(*) FROM known_nodes", [], |row| row.get(0))?;
            if count >= MAX_ANNOUNCEMENTS as i64 {
                return Err(RegistryError::Invalid);
            }
        }
        self.connection.execute(
            "INSERT INTO known_nodes(fingerprint,announcement,trust_status,observed_at) VALUES(?1,?2,'discovered',?3) ON CONFLICT(fingerprint) DO UPDATE SET announcement=excluded.announcement,observed_at=excluded.observed_at",
            params![announcement.node_fingerprint, serde_json::to_vec(announcement).map_err(|_| RegistryError::Invalid)?, now as i64],
        )?;
        self.connection.execute(
            "INSERT INTO registry_changes(fingerprint,announcement) VALUES(?1,?2)",
            params![
                announcement.node_fingerprint,
                serde_json::to_vec(announcement).map_err(|_| RegistryError::Invalid)?
            ],
        )?;
        Ok(())
    }

    pub fn signed_snapshot(
        &mut self,
        signer: &ServerSigner,
        now: u64,
    ) -> Result<RegistrySnapshot, RegistryError> {
        let mut statement = self
            .connection
            .prepare("SELECT announcement FROM known_nodes ORDER BY fingerprint LIMIT ?1")?;
        let rows =
            statement.query_map([MAX_ANNOUNCEMENTS as i64], |row| row.get::<_, Vec<u8>>(0))?;
        let mut announcements = Vec::new();
        for row in rows {
            let announcement: NodeAnnouncement =
                serde_json::from_slice(&row?).map_err(|_| RegistryError::Invalid)?;
            if announcement.verify(now).is_ok() {
                announcements.push(announcement);
            }
        }
        let sequence: i64 = self.connection.query_row(
            "INSERT INTO registry_meta(key,value) VALUES('snapshot_sequence',1) ON CONFLICT(key) DO UPDATE SET value=value+1 RETURNING value",
            [],
            |row| row.get(0),
        )?;
        RegistrySnapshot::sign(signer, sequence as u64, now, announcements)
    }

    pub fn import_snapshot(
        &mut self,
        snapshot: &RegistrySnapshot,
        now: u64,
    ) -> Result<usize, RegistryError> {
        let key_bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT public_key FROM trusted_sources WHERE fingerprint=?1",
                [&snapshot.source_fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        let key_bytes = key_bytes.ok_or(RegistryError::Untrusted)?;
        let key: [u8; 32] = key_bytes.try_into().map_err(|_| RegistryError::Invalid)?;
        snapshot.verify(&key, now)?;
        let accepted: Option<i64> = self
            .connection
            .query_row(
                "SELECT sequence FROM accepted_snapshots WHERE fingerprint=?1",
                [&snapshot.source_fingerprint],
                |row| row.get(0),
            )
            .optional()?;
        if accepted.is_some_and(|sequence| sequence >= snapshot.sequence as i64) {
            return Err(RegistryError::Rollback);
        }
        let tx = self.connection.transaction()?;
        for announcement in &snapshot.announcements {
            let existing: Option<i64> = tx.query_row("SELECT CAST(json_extract(announcement,'$.sequence') AS INTEGER) FROM known_nodes WHERE fingerprint=?1", [&announcement.node_fingerprint], |row| row.get(0)).optional()?;
            if existing.is_some_and(|sequence| sequence >= announcement.sequence as i64) {
                continue;
            }
            tx.execute("INSERT INTO known_nodes(fingerprint,announcement,trust_status,observed_at) VALUES(?1,?2,'discovered',?3) ON CONFLICT(fingerprint) DO UPDATE SET announcement=excluded.announcement,observed_at=excluded.observed_at",params![announcement.node_fingerprint,serde_json::to_vec(announcement).map_err(|_| RegistryError::Invalid)?,now as i64])?;
            tx.execute(
                "INSERT INTO registry_changes(fingerprint,announcement) VALUES(?1,?2)",
                params![
                    announcement.node_fingerprint,
                    serde_json::to_vec(announcement).map_err(|_| RegistryError::Invalid)?
                ],
            )?;
        }
        tx.execute("INSERT INTO accepted_snapshots(fingerprint,sequence,generated_at) VALUES(?1,?2,?3) ON CONFLICT(fingerprint) DO UPDATE SET sequence=excluded.sequence,generated_at=excluded.generated_at",params![snapshot.source_fingerprint,snapshot.sequence as i64,snapshot.generated_at as i64])?;
        let count = snapshot.announcements.len();
        tx.commit()?;
        Ok(count)
    }

    pub fn set_trust(
        &mut self,
        node_fingerprint: &str,
        status: TrustStatus,
    ) -> Result<(), RegistryError> {
        let status = match status {
            TrustStatus::Discovered => "discovered",
            TrustStatus::Verified => "verified",
            TrustStatus::Approved => "approved",
            TrustStatus::Blocked => "blocked",
        };
        let changed = self.connection.execute(
            "UPDATE known_nodes SET trust_status=?1 WHERE fingerprint=?2",
            params![status, node_fingerprint],
        )?;
        if changed != 1 {
            return Err(RegistryError::Invalid);
        }
        Ok(())
    }

    pub fn trust_status(&self, node_fingerprint: &str) -> Result<TrustStatus, RegistryError> {
        let status: String = self.connection.query_row(
            "SELECT trust_status FROM known_nodes WHERE fingerprint=?1",
            [node_fingerprint],
            |row| row.get(0),
        )?;
        match status.as_str() {
            "discovered" => Ok(TrustStatus::Discovered),
            "verified" => Ok(TrustStatus::Verified),
            "approved" => Ok(TrustStatus::Approved),
            "blocked" => Ok(TrustStatus::Blocked),
            _ => Err(RegistryError::Invalid),
        }
    }
}

fn announcement_bytes(value: &NodeAnnouncement) -> Vec<u8> {
    let mut out = b"AKRAT/federation-announcement/v1\0".to_vec();
    for text in [
        &value.node_fingerprint,
        &value.signing_public_key,
        &value.noise_public_key,
        &value.endpoint,
        &value.operator,
    ] {
        push_text(&mut out, text);
    }
    if value.version >= 2 {
        push_text(&mut out, &value.name);
        push_text(&mut out, &value.description);
        push_text(&mut out, &value.host_name);
    }
    if value.version >= 3 {
        let identity = serde_json::to_vec(&value.server_identity)
            .expect("server identity serialization is infallible");
        out.extend_from_slice(&(identity.len() as u32).to_be_bytes());
        out.extend_from_slice(&identity);
    }
    out.extend_from_slice(&value.version.to_be_bytes());
    out.extend_from_slice(&value.protocol_min.to_be_bytes());
    out.extend_from_slice(&value.protocol_max.to_be_bytes());
    out.extend_from_slice(&(value.capabilities.len() as u32).to_be_bytes());
    for capability in &value.capabilities {
        push_text(&mut out, capability);
    }
    out.extend_from_slice(&value.max_storage_bytes.to_be_bytes());
    out.extend_from_slice(&value.sequence.to_be_bytes());
    out.extend_from_slice(&value.issued_at.to_be_bytes());
    out.extend_from_slice(&value.expires_at.to_be_bytes());
    out
}

fn snapshot_bytes(value: &RegistrySnapshot) -> Vec<u8> {
    let mut out = b"AKRAT/federation-snapshot/v1\0".to_vec();
    push_text(&mut out, &value.source_fingerprint);
    out.extend_from_slice(&value.version.to_be_bytes());
    out.extend_from_slice(&value.sequence.to_be_bytes());
    out.extend_from_slice(&value.generated_at.to_be_bytes());
    out.extend_from_slice(&(value.announcements.len() as u32).to_be_bytes());
    for announcement in &value.announcements {
        push_bytes(&mut out, &announcement_bytes(announcement));
        push_text(&mut out, &announcement.signature);
    }
    out
}

fn delta_bytes(value: &RegistryDelta) -> Vec<u8> {
    let mut out = b"AKRAT/federation-delta/v1\0".to_vec();
    push_text(&mut out, &value.source_fingerprint);
    out.extend_from_slice(&value.version.to_be_bytes());
    out.extend_from_slice(&value.after_sequence.to_be_bytes());
    out.extend_from_slice(&value.cursor.to_be_bytes());
    out.push(u8::from(value.has_more));
    out.extend_from_slice(&value.generated_at.to_be_bytes());
    out.extend_from_slice(&(value.announcements.len() as u32).to_be_bytes());
    for announcement in &value.announcements {
        push_bytes(&mut out, &announcement_bytes(announcement));
        push_text(&mut out, &announcement.signature);
    }
    out
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    push_bytes(out, text.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub fn unix_now() -> Result<u64, RegistryError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| RegistryError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announcement(signer: &ServerSigner, noise: &ServerSigner, now: u64) -> NodeAnnouncement {
        NodeAnnouncement::create(
            signer,
            &noise.public_key(),
            "mail.example:47475".into(),
            "community node".into(),
            1,
            1,
            vec!["deposit".into(), "fetch".into()],
            10_000,
            1,
            now,
            now + 3600,
        )
        .expect("announcement")
    }

    #[test]
    fn signed_snapshot_requires_local_source_trust_and_never_auto_approves_nodes() {
        let now = 1_800_000_000;
        let source = ServerSigner::generate().expect("source");
        let node = ServerSigner::generate().expect("node");
        let noise = ServerSigner::generate().expect("noise");
        let announced = announcement(&node, &noise, now);
        let snapshot =
            RegistrySnapshot::sign(&source, 1, now, vec![announced.clone()]).expect("snapshot");
        let directory = tempfile::tempdir().expect("directory");
        let mut registry =
            LocalRegistry::open(directory.path().join("registry.sqlite3")).expect("registry");
        assert!(matches!(
            registry.import_snapshot(&snapshot, now),
            Err(RegistryError::Untrusted)
        ));
        registry
            .add_trusted_source(&source.public_key())
            .expect("pin source");
        registry.import_snapshot(&snapshot, now).expect("import");
        assert_eq!(
            registry
                .trust_status(&announced.node_fingerprint)
                .expect("trust"),
            TrustStatus::Discovered
        );
        assert!(matches!(
            registry.import_snapshot(&snapshot, now),
            Err(RegistryError::Rollback)
        ));
    }

    #[test]
    fn signatures_tampering_expiry_and_wrong_pin_are_rejected() {
        let now = 1_800_000_000;
        let source = ServerSigner::generate().expect("source");
        let node = ServerSigner::generate().expect("node");
        let noise = ServerSigner::generate().expect("noise");
        let mut item = announcement(&node, &noise, now);
        item.endpoint = "attacker.invalid".into();
        assert!(item.verify(now).is_err());
        let good = announcement(&node, &noise, now);
        let snapshot = RegistrySnapshot::sign(&source, 1, now, vec![good]).expect("snapshot");
        let other = ServerSigner::generate().expect("other");
        assert!(snapshot.verify(&other.public_key(), now).is_err());
        assert!(
            snapshot
                .verify(&source.public_key(), now + MAX_ANNOUNCEMENT_LIFETIME + 1)
                .is_err()
        );
    }

    #[test]
    fn signed_federation_deltas_page_changes_and_reject_replay() {
        let now = 1_800_000_000;
        let source = ServerSigner::generate().expect("source signer");
        let noise = ServerSigner::generate().expect("noise signer");
        let directory = tempfile::tempdir().expect("directory");
        let mut source_registry =
            LocalRegistry::open(directory.path().join("source.sqlite3")).expect("source registry");
        let mut receiver = LocalRegistry::open(directory.path().join("receiver.sqlite3"))
            .expect("receiver registry");
        receiver
            .add_trusted_source(&source.public_key())
            .expect("explicit source trust");
        for index in 0..14 {
            let node = ServerSigner::generate().expect("node signer");
            let announcement = NodeAnnouncement::create(
                &node,
                &noise.public_key(),
                format!("node-{index}.example:47475"),
                format!("operator-{index}"),
                1,
                1,
                vec!["mailbox".into()],
                100_000,
                1,
                now,
                now + 3600,
            )
            .expect("announcement");
            source_registry
                .publish_announcement(&announcement, now)
                .expect("publish announcement");
        }
        let first = source_registry
            .signed_delta(&source, 0, now)
            .expect("first delta");
        assert_eq!(first.announcements.len(), MAX_DELTA_ANNOUNCEMENTS);
        assert!(first.has_more);
        receiver
            .import_delta(&first, now)
            .expect("import first page");
        assert!(matches!(
            receiver.import_delta(&first, now),
            Err(RegistryError::Rollback)
        ));
        let second = source_registry
            .signed_delta(&source, first.cursor, now)
            .expect("second delta");
        assert!(!second.has_more);
        receiver
            .import_delta(&second, now)
            .expect("import final page");
        assert_eq!(receiver.known_nodes().expect("nodes").len(), 14);
        assert_eq!(
            receiver
                .federation_cursor(&source.fingerprint())
                .expect("cursor"),
            second.cursor
        );
    }

    #[test]
    fn signed_federation_delta_keeps_only_latest_announcement_per_node() {
        let now = 1_800_000_000;
        let source = ServerSigner::generate().expect("source signer");
        let node = ServerSigner::generate().expect("node signer");
        let noise = ServerSigner::generate().expect("noise signer");
        let directory = tempfile::tempdir().expect("directory");
        let mut registry =
            LocalRegistry::open(directory.path().join("source.sqlite3")).expect("source registry");
        for (sequence, name) in [(1, "old"), (2, "new")] {
            let announcement = NodeAnnouncement::create_profile(
                &node,
                &noise.public_key(),
                "node.example:47475".into(),
                "operator".into(),
                name.into(),
                String::new(),
                String::new(),
                1,
                1,
                vec!["mailbox".into()],
                100_000,
                sequence,
                now,
                now + 3600,
            )
            .expect("announcement");
            registry
                .publish_announcement(&announcement, now)
                .expect("publish announcement");
        }

        let delta = registry
            .signed_delta(&source, 0, now)
            .expect("signed delta");
        assert_eq!(delta.announcements.len(), 1);
        assert_eq!(delta.announcements[0].sequence, 2);
        assert_eq!(delta.announcements[0].name, "new");
        delta
            .verify(&source.public_key(), now)
            .expect("valid delta");
    }
}
