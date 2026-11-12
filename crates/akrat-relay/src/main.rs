use akrat_trust::{RelayIdentityProof, relay_identity_fingerprint, relay_identity_payload};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use tokio::process::{Child, Command};

#[derive(Parser)]
#[command(
    name = "akrat-relay",
    version,
    about = "Relais Iroh officiel avec identité AKRAT vérifiable"
)]
struct Cli {
    #[arg(long, default_value = "iroh-relay.toml")]
    config_path: PathBuf,
    #[arg(long)]
    advertise_url: String,
    #[arg(long, default_value = "akrat-relay-identity.key")]
    identity_key: PathBuf,
    #[arg(long, default_value = "0.0.0.0:8090")]
    identity_bind: SocketAddr,
    #[arg(long)]
    relay_binary: Option<PathBuf>,
}

#[derive(Clone)]
struct IdentityState {
    signing_key: Arc<SigningKey>,
    relay_url: String,
    fingerprint: String,
    challenge_slots: Arc<tokio::sync::Semaphore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeRequest {
    relay_url: String,
    challenge_hex: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let relay_url = canonical_relay_url(&cli.advertise_url)?;
    let signing_key = Arc::new(load_or_create_identity_key(&cli.identity_key)?);
    let fingerprint = relay_identity_fingerprint(&signing_key.verifying_key().to_bytes());
    let state = IdentityState {
        signing_key,
        relay_url,
        fingerprint: fingerprint.clone(),
        challenge_slots: Arc::new(tokio::sync::Semaphore::new(16)),
    };
    println!("Identité du relais AKRAT · empreinte Ed25519 {fingerprint}");
    println!("Vérification de défi disponible sur {}", cli.identity_bind);

    let router = identity_router(state);
    let listener = tokio::net::TcpListener::bind(cli.identity_bind).await?;
    let identity_server = axum::serve(listener, router).into_future();

    let relay_binary = match cli.relay_binary {
        Some(path) => path,
        None => std::env::current_exe()?
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(if cfg!(windows) {
                "iroh-relay.exe"
            } else {
                "iroh-relay"
            }),
    };
    let mut relay = Command::new(relay_binary)
        .arg("--config-path")
        .arg(cli.config_path)
        .stdin(Stdio::null())
        .spawn()?;
    supervise(identity_server, &mut relay).await
}

fn identity_router(state: IdentityState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/.well-known/akrat/v1/challenge", post(challenge))
        .layer(DefaultBodyLimit::max(4096))
        .with_state(state)
}

async fn supervise(
    identity_server: impl std::future::Future<Output = Result<(), std::io::Error>>,
    relay: &mut Child,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::pin!(identity_server);
    tokio::select! {
        result = &mut identity_server => {
            relay.start_kill()?;
            let _ = relay.wait().await;
            result?;
            Ok(())
        }
        result = relay.wait() => {
            result?;
            Ok(())
        }
        result = tokio::signal::ctrl_c() => {
            result?;
            relay.start_kill()?;
            let _ = relay.wait().await;
            Ok(())
        }
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn challenge(
    State(state): State<IdentityState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<RelayIdentityProof>, StatusCode> {
    let _permit = state
        .challenge_slots
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let challenge = hex::decode(&request.challenge_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if challenge.len() != 32 || request.relay_url != state.relay_url {
        return Err(StatusCode::BAD_REQUEST);
    }
    let public_key = state.signing_key.verifying_key().to_bytes();
    let software_version = env!("CARGO_PKG_VERSION").to_string();
    let signature = state.signing_key.sign(&relay_identity_payload(
        &state.relay_url,
        &challenge,
        &software_version,
    ));
    Ok(Json(RelayIdentityProof {
        relay_url: state.relay_url.clone(),
        challenge_hex: request.challenge_hex,
        public_key_hex: hex::encode(public_key),
        fingerprint: state.fingerprint.clone(),
        software_version,
        signature_hex: hex::encode(signature.to_bytes()),
    }))
}

fn canonical_relay_url(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut url = reqwest::Url::parse(value)?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err("the advertised relay URL must use HTTPS and include a host".into());
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn load_or_create_identity_key(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "relay identity key must contain exactly 32 bytes")?;
        return Ok(SigningKey::from_bytes(&bytes));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let saved = std::fs::read(path)?;
            let saved: [u8; 32] = saved
                .try_into()
                .map_err(|_| "relay identity key must contain exactly 32 bytes")?;
            return Ok(SigningKey::from_bytes(&saved));
        }
        Err(error) => return Err(error.into()),
    };
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(SigningKey::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use akrat_trust::verify_relay_identity_proof;

    #[tokio::test]
    async fn challenge_proof_is_bound_to_url_and_fresh_challenge() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[17; 32]));
        let public_key = signing_key.verifying_key().to_bytes();
        let fingerprint = relay_identity_fingerprint(&public_key);
        let relay_url = "https://relay.example.org/".to_string();
        let challenge_hex = hex::encode([29; 32]);
        let response = challenge(
            State(IdentityState {
                signing_key,
                relay_url: relay_url.clone(),
                fingerprint: fingerprint.clone(),
                challenge_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            }),
            Json(ChallengeRequest {
                relay_url: relay_url.clone(),
                challenge_hex: challenge_hex.clone(),
            }),
        )
        .await
        .expect("create signed proof");
        let pin = verify_relay_identity_proof(&response.0, &relay_url, &[29; 32], &fingerprint)
            .expect("verify proof with an independently pinned fingerprint");
        assert_eq!(pin.fingerprint, fingerprint);
        assert!(
            challenge(
                State(IdentityState {
                    signing_key: Arc::new(SigningKey::from_bytes(&[17; 32])),
                    relay_url: "https://relay.example.org/".into(),
                    fingerprint: relay_identity_fingerprint(&public_key),
                    challenge_slots: Arc::new(tokio::sync::Semaphore::new(16)),
                }),
                Json(ChallengeRequest {
                    relay_url: "https://other.example.org/".into(),
                    challenge_hex,
                }),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn remote_identity_client_verifies_the_live_http_challenge_route() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[23; 32]));
        let public_key = signing_key.verifying_key().to_bytes();
        let relay_url = "https://relay.example.org/".to_string();
        let state = IdentityState {
            signing_key,
            relay_url: relay_url.clone(),
            fingerprint: relay_identity_fingerprint(&public_key),
            challenge_slots: Arc::new(tokio::sync::Semaphore::new(16)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local identity endpoint");
        let address = listener.local_addr().expect("identity address");
        let server = tokio::spawn(axum::serve(listener, identity_router(state)).into_future());
        let pin = akrat_trust::verify_remote_relay_identity_at(
            &relay_url,
            &format!("http://{address}"),
            &relay_identity_fingerprint(&public_key),
        )
        .await
        .expect("verify identity over the live challenge HTTP route");
        assert_eq!(pin.public_key_hex, hex::encode(public_key));
        server.abort();
    }

    #[test]
    fn relay_url_requires_https_and_normalizes_its_origin() {
        assert_eq!(
            canonical_relay_url("https://relay.example.org/path?q=1").expect("canonical URL"),
            "https://relay.example.org/"
        );
        assert!(canonical_relay_url("http://relay.example.org").is_err());
    }

    #[test]
    fn relay_identity_key_survives_a_restart() {
        let directory = tempfile::tempdir().expect("temporary key directory");
        let path = directory.path().join("identity.key");
        let first = load_or_create_identity_key(&path).expect("create key");
        let second = load_or_create_identity_key(&path).expect("reload key");
        assert_eq!(first.to_bytes(), second.to_bytes());
    }
}
