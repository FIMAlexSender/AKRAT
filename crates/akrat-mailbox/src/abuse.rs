use crate::server::{MAX_CONNECTIONS, Request};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_SOURCE_BUCKETS: usize = 4096;
const MAX_IDENTITY_BUCKETS: usize = 8192;
const MAX_MAILBOX_BUCKETS: usize = 8192;
const BUCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub global_requests_per_minute: u32,
    pub global_burst: u32,
    pub source_requests_per_minute: u32,
    pub source_burst: u32,
    pub identity_requests_per_minute: u32,
    pub identity_burst: u32,
    pub mailbox_requests_per_minute: u32,
    pub mailbox_burst: u32,
    pub max_connections_per_source: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            global_requests_per_minute: 6000,
            global_burst: 1000,
            source_requests_per_minute: 1200,
            source_burst: 120,
            identity_requests_per_minute: 300,
            identity_burst: 60,
            mailbox_requests_per_minute: 600,
            mailbox_burst: 120,
            max_connections_per_source: 8,
        }
    }
}

impl RateLimitConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        let values = [
            self.global_requests_per_minute,
            self.global_burst,
            self.source_requests_per_minute,
            self.source_burst,
            self.identity_requests_per_minute,
            self.identity_burst,
            self.mailbox_requests_per_minute,
            self.mailbox_burst,
        ];
        if values.iter().any(|value| *value == 0 || *value > 1_000_000)
            || self.max_connections_per_source == 0
            || self.max_connections_per_source as usize > MAX_CONNECTIONS
        {
            return Err(
                "rate limits must be between 1 and 1,000,000 and per-source connections must not exceed the global connection limit",
            );
        }
        Ok(())
    }
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl Bucket {
    fn new(capacity: u32, now: Instant) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: now,
            last_used: now,
        }
    }

    fn take(&mut self, cost: f64, per_minute: u32, capacity: u32, now: Instant) -> bool {
        self.tokens = self.available(per_minute, capacity, now);
        self.last_refill = now;
        self.last_used = now;
        if self.tokens + f64::EPSILON < cost {
            return false;
        }
        self.tokens -= cost;
        true
    }

    fn available(&self, per_minute: u32, capacity: u32, now: Instant) -> f64 {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        (self.tokens + elapsed * per_minute as f64 / 60.0).min(capacity as f64)
    }

    fn permits(&self, cost: f64, per_minute: u32, capacity: u32, now: Instant) -> bool {
        self.available(per_minute, capacity, now) + f64::EPSILON >= cost
    }
}

struct SourceState {
    bucket: Bucket,
    connections: u32,
}

struct State {
    global: Bucket,
    sources: HashMap<IpAddr, SourceState>,
    identities: HashMap<[u8; 32], Bucket>,
    mailboxes: HashMap<String, Bucket>,
}

pub struct RateLimiter {
    config: RateLimitConfig,
    state: Mutex<State>,
}

pub struct ConnectionPermit {
    limiter: Arc<RateLimiter>,
    source: IpAddr,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let now = Instant::now();
        Self {
            state: Mutex::new(State {
                global: Bucket::new(config.global_burst, now),
                sources: HashMap::new(),
                identities: HashMap::new(),
                mailboxes: HashMap::new(),
            }),
            config,
        }
    }

    pub fn try_acquire_source(self: &Arc<Self>, source: IpAddr) -> Option<ConnectionPermit> {
        let now = Instant::now();
        let mut state = self.state.lock().ok()?;
        evict_idle(&mut state, now);
        if !state.sources.contains_key(&source) && state.sources.len() >= MAX_SOURCE_BUCKETS {
            return None;
        }
        let entry = state.sources.entry(source).or_insert_with(|| SourceState {
            bucket: Bucket::new(self.config.source_burst, now),
            connections: 0,
        });
        if entry.connections >= self.config.max_connections_per_source
            || !entry.bucket.take(
                1.0,
                self.config.source_requests_per_minute,
                self.config.source_burst,
                now,
            )
        {
            return None;
        }
        entry.connections += 1;
        Some(ConnectionPermit {
            limiter: self.clone(),
            source,
        })
    }

    pub fn allow_request(
        &self,
        source: IpAddr,
        client_public_key: &[u8],
        request: Option<&Request>,
        frame_bytes: usize,
    ) -> bool {
        let now = Instant::now();
        let client_id: [u8; 32] = Sha256::digest(client_public_key).into();
        let cost = request_cost(request, frame_bytes);
        let mailbox_id = request.and_then(Request::mailbox_id).map(str::to_owned);
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        evict_idle(&mut state, now);
        if !state.global.permits(
            cost,
            self.config.global_requests_per_minute,
            self.config.global_burst,
            now,
        ) {
            return false;
        }
        if !state.sources.contains_key(&source) && state.sources.len() >= MAX_SOURCE_BUCKETS {
            return false;
        }
        if !state.identities.contains_key(&client_id)
            && state.identities.len() >= MAX_IDENTITY_BUCKETS
        {
            return false;
        }
        if !state.sources.get(&source).is_none_or(|entry| {
            entry.bucket.permits(
                cost,
                self.config.source_requests_per_minute,
                self.config.source_burst,
                now,
            )
        }) {
            return false;
        }
        if !state.identities.get(&client_id).is_none_or(|bucket| {
            bucket.permits(
                cost,
                self.config.identity_requests_per_minute,
                self.config.identity_burst,
                now,
            )
        }) {
            return false;
        }
        if let Some(mailbox_id) = mailbox_id.as_ref() {
            if !state.mailboxes.contains_key(mailbox_id)
                && state.mailboxes.len() >= MAX_MAILBOX_BUCKETS
            {
                return false;
            }
            if !state.mailboxes.get(mailbox_id).is_none_or(|bucket| {
                bucket.permits(
                    cost,
                    self.config.mailbox_requests_per_minute,
                    self.config.mailbox_burst,
                    now,
                )
            }) {
                return false;
            }
        }
        state.global.take(
            cost,
            self.config.global_requests_per_minute,
            self.config.global_burst,
            now,
        );
        state
            .sources
            .entry(source)
            .or_insert_with(|| SourceState {
                bucket: Bucket::new(self.config.source_burst, now),
                connections: 0,
            })
            .bucket
            .take(
                cost,
                self.config.source_requests_per_minute,
                self.config.source_burst,
                now,
            );
        state
            .identities
            .entry(client_id)
            .or_insert_with(|| Bucket::new(self.config.identity_burst, now))
            .take(
                cost,
                self.config.identity_requests_per_minute,
                self.config.identity_burst,
                now,
            );
        let Some(mailbox_id) = mailbox_id else {
            return true;
        };
        state
            .mailboxes
            .entry(mailbox_id)
            .or_insert_with(|| Bucket::new(self.config.mailbox_burst, now))
            .take(
                cost,
                self.config.mailbox_requests_per_minute,
                self.config.mailbox_burst,
                now,
            )
    }
}

impl Request {
    fn mailbox_id(&self) -> Option<&str> {
        match self {
            Self::Deposit { mailbox_id, .. }
            | Self::Fetch { mailbox_id, .. }
            | Self::Acknowledge { mailbox_id, .. }
            | Self::GetRecipientReceipt { mailbox_id, .. }
            | Self::GetDeliveryFailure { mailbox_id, .. }
            | Self::PublishBundle { mailbox_id, .. }
            | Self::GetBundle { mailbox_id, .. } => Some(mailbox_id),
            Self::FederationAnnounce { .. }
            | Self::FederationSnapshot
            | Self::FederationChanges { .. }
            | Self::FederationImport { .. }
            | Self::FederationImportDelta { .. }
            | Self::ServerIdentity
            | Self::Health => None,
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.limiter.state.lock()
            && let Some(source) = state.sources.get_mut(&self.source)
        {
            source.connections = source.connections.saturating_sub(1);
            source.bucket.last_used = Instant::now();
        }
    }
}

fn request_cost(request: Option<&Request>, frame_bytes: usize) -> f64 {
    let operation_cost = match request {
        Some(Request::Fetch { limit, .. }) => 1.0 + (*limit).min(128) as f64 / 128.0,
        Some(Request::PublishBundle { .. }) => 3.0,
        Some(Request::FederationImport { .. }) => 4.0,
        Some(Request::FederationImportDelta { .. }) => 3.0,
        Some(Request::FederationSnapshot | Request::FederationChanges { .. }) => 2.0,
        Some(Request::Deposit { .. }) => 1.5,
        Some(Request::GetBundle { .. }) => 1.5,
        Some(Request::Acknowledge { .. })
        | Some(Request::GetRecipientReceipt { .. })
        | Some(Request::GetDeliveryFailure { .. }) => 1.0,
        Some(Request::FederationAnnounce { .. }) => 2.0,
        Some(Request::Health | Request::ServerIdentity) | None => 0.5,
    };
    operation_cost + (frame_bytes as f64 / (16 * 1024) as f64)
}

fn evict_idle(state: &mut State, now: Instant) {
    state.sources.retain(|_, source| {
        source.connections != 0
            || now.saturating_duration_since(source.bucket.last_used) < BUCKET_IDLE_TIMEOUT
    });
    state
        .identities
        .retain(|_, bucket| now.saturating_duration_since(bucket.last_used) < BUCKET_IDLE_TIMEOUT);
    state
        .mailboxes
        .retain(|_, bucket| now.saturating_duration_since(bucket.last_used) < BUCKET_IDLE_TIMEOUT);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn limited_config() -> RateLimitConfig {
        RateLimitConfig {
            global_requests_per_minute: 1000,
            global_burst: 1000,
            source_requests_per_minute: 1000,
            source_burst: 1000,
            identity_requests_per_minute: 1,
            identity_burst: 2,
            mailbox_requests_per_minute: 1000,
            mailbox_burst: 1000,
            max_connections_per_source: 2,
        }
    }

    #[test]
    fn identity_buckets_limit_requests_and_allow_legitimate_clients_to_continue() {
        let limiter = RateLimiter::new(limited_config());
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client = [7u8; 32];
        assert!(limiter.allow_request(source, &client, Some(&Request::Health), 8));
        assert!(limiter.allow_request(source, &client, Some(&Request::Health), 8));
        assert!(limiter.allow_request(source, &client, Some(&Request::Health), 8));
        assert!(!limiter.allow_request(source, &client, Some(&Request::Health), 8));
        assert!(limiter.allow_request(source, &[8u8; 32], Some(&Request::Health), 8));
    }

    #[test]
    fn rejected_identity_requests_do_not_consume_the_global_budget() {
        let mut config = limited_config();
        config.global_burst = 2;
        config.global_requests_per_minute = 1;
        config.identity_burst = 1;
        let limiter = RateLimiter::new(config);
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client = [7u8; 32];
        assert!(limiter.allow_request(source, &client, Some(&Request::Health), 0));
        assert!(limiter.allow_request(source, &client, Some(&Request::Health), 0));
        assert!(!limiter.allow_request(source, &client, Some(&Request::Health), 0));
        assert!(!limiter.allow_request(source, &client, Some(&Request::Health), 0));
        assert!(limiter.allow_request(source, &[8u8; 32], Some(&Request::Health), 0));
    }

    #[test]
    fn source_connection_limits_are_bounded_and_released() {
        let limiter = Arc::new(RateLimiter::new(limited_config()));
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let first = limiter
            .try_acquire_source(source)
            .expect("first connection");
        let second = limiter
            .try_acquire_source(source)
            .expect("second connection");
        assert!(limiter.try_acquire_source(source).is_none());
        drop(first);
        assert!(limiter.try_acquire_source(source).is_some());
        drop(second);
    }

    #[test]
    fn configuration_rejects_unbounded_values() {
        let mut config = RateLimitConfig::default();
        assert!(config.validate().is_ok());
        config.max_connections_per_source = MAX_CONNECTIONS as u32 + 1;
        assert!(config.validate().is_err());
        config.max_connections_per_source = 1;
        config.global_burst = u32::MAX;
        assert!(config.validate().is_err());
    }

    #[test]
    fn limiter_does_not_treat_socket_ports_as_distinct_sources() {
        let mut config = limited_config();
        config.max_connections_per_source = MAX_CONNECTIONS as u32;
        config.source_burst = 2;
        let limiter = Arc::new(RateLimiter::new(config));
        let source = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let _first = limiter.try_acquire_source(source).expect("first source");
        assert!(limiter.try_acquire_source(source).is_some());
        assert!(limiter.try_acquire_source(source).is_none());
    }
}
