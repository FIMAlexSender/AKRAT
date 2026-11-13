use akrat_trust::{
    RelayDistributionClaim, RelayIdentityProof, RelayIdentityProofV2, relay_identity_fingerprint,
    relay_identity_payload, relay_identity_v2_payload,
};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
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
    distribution: Option<RelayDistributionClaim>,
    release_attestation_path: PathBuf,
    release_signature_path: PathBuf,
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
    let executable_directory = std::env::current_exe()?
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let release_stem = format!("AKRAT-v{}-release-attestation", env!("CARGO_PKG_VERSION"));
    let state = IdentityState {
        signing_key,
        relay_url,
        fingerprint: fingerprint.clone(),
        distribution: release_distribution_claim(),
        release_attestation_path: executable_directory.join(format!("{release_stem}.json")),
        release_signature_path: executable_directory.join(format!("{release_stem}.sig")),
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
        .route("/.well-known/akrat/v2/challenge", post(challenge_v2))
        .route(
            "/.well-known/akrat/v2/release-attestation.json",
            get(release_attestation),
        )
        .route(
            "/.well-known/akrat/v2/release-attestation.sig",
            get(release_signature),
        )
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

async fn release_attestation(State(state): State<IdentityState>) -> Result<Vec<u8>, StatusCode> {
    read_release_sidecar(&state.release_attestation_path, 1_048_576).await
}

async fn release_signature(State(state): State<IdentityState>) -> Result<Vec<u8>, StatusCode> {
    read_release_sidecar(&state.release_signature_path, 256).await
}

async fn read_release_sidecar(path: &Path, maximum: u64) -> Result<Vec<u8>, StatusCode> {
    let metadata = std::fs::metadata(path).map_err(|_| StatusCode::NOT_FOUND)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(StatusCode::NOT_FOUND);
    }
    let contents = std::fs::read(path).map_err(|_| StatusCode::NOT_FOUND)?;
    if contents.len() as u64 > maximum {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(contents)
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

async fn challenge_v2(
    State(state): State<IdentityState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<RelayIdentityProofV2>, StatusCode> {
    let _permit = state
        .challenge_slots
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let challenge = hex::decode(&request.challenge_hex).map_err(|_| StatusCode::BAD_REQUEST)?;
    if challenge.len() != 32 || request.relay_url != state.relay_url {
        return Err(StatusCode::BAD_REQUEST);
    }
    let distribution = state
        .distribution
        .clone()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let public_key = state.signing_key.verifying_key().to_bytes();
    let software_version = env!("CARGO_PKG_VERSION").to_string();
    let payload = relay_identity_v2_payload(
        &state.relay_url,
        &challenge,
        &software_version,
        &distribution,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let signature = state.signing_key.sign(&payload);
    Ok(Json(RelayIdentityProofV2 {
        relay_url: state.relay_url.clone(),
        challenge_hex: request.challenge_hex,
        public_key_hex: hex::encode(public_key),
        fingerprint: state.fingerprint.clone(),
        software_version,
        distribution,
        signature_hex: hex::encode(signature.to_bytes()),
    }))
}

fn release_distribution_claim() -> Option<RelayDistributionClaim> {
    let artifact_name = option_env!("AKRAT_RELAY_ARTIFACT_NAME")?;
    let source_commit = option_env!("AKRAT_BUILD_COMMIT")?.to_ascii_lowercase();
    if source_commit.len() != 40
        || !source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let executable = std::env::current_exe().ok()?;
    let bytes = std::fs::read(executable).ok()?;
    Some(RelayDistributionClaim {
        artifact_name: artifact_name.to_string(),
        artifact_sha256: hex::encode(Sha256::digest(bytes)),
        source_commit,
        protocol_version: 1,
    })
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
                distribution: Some(RelayDistributionClaim {
                    artifact_name: "akrat-relay-test".into(),
                    artifact_sha256: "1a".repeat(32),
                    source_commit: "a".repeat(40),
                    protocol_version: 1,
                }),
                release_attestation_path: PathBuf::new(),
                release_signature_path: PathBuf::new(),
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
                    distribution: None,
                    release_attestation_path: PathBuf::new(),
                    release_signature_path: PathBuf::new(),
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
    async fn challenge_v2_binds_distribution_claim_to_the_relay_identity() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[19; 32]));
        let public_key = signing_key.verifying_key().to_bytes();
        let fingerprint = relay_identity_fingerprint(&public_key);
        let relay_url = "https://relay.example.org/".to_string();
        let response = challenge_v2(
            State(IdentityState {
                signing_key,
                relay_url: relay_url.clone(),
                fingerprint: fingerprint.clone(),
                distribution: Some(RelayDistributionClaim {
                    artifact_name: "AKRAT-v0.1.12-relay-linux-x64".into(),
                    artifact_sha256: "1a".repeat(32),
                    source_commit: "a".repeat(40),
                    protocol_version: 1,
                }),
                release_attestation_path: PathBuf::new(),
                release_signature_path: PathBuf::new(),
                challenge_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            }),
            Json(ChallengeRequest {
                relay_url: relay_url.clone(),
                challenge_hex: hex::encode([31; 32]),
            }),
        )
        .await
        .expect("create signed release claim");
        let (pin, claim) = akrat_trust::verify_relay_identity_proof_v2(
            &response.0,
            &relay_url,
            &[31; 32],
            &fingerprint,
        )
        .expect("verify signed release claim");
        assert_eq!(pin.fingerprint, fingerprint);
        assert_eq!(claim.artifact_name, "AKRAT-v0.1.12-relay-linux-x64");
        assert_eq!(claim.source_commit, "a".repeat(40));
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
            distribution: Some(RelayDistributionClaim {
                artifact_name: "akrat-relay-test".into(),
                artifact_sha256: "1a".repeat(32),
                source_commit: "a".repeat(40),
                protocol_version: 1,
            }),
            release_attestation_path: PathBuf::new(),
            release_signature_path: PathBuf::new(),
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

    #[tokio::test]
    async fn distribution_trust_verifies_signature_and_artifact_from_local_sidecars() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let release_tag = "v0.1.12";
        let attestation = akrat_trust::ReleaseAttestation {
            schema: akrat_trust::RELEASE_ATTESTATION_SCHEMA.into(),
            repository: akrat_trust::RELEASE_REPOSITORY.into(),
            tag: release_tag.into(),
            version: "0.1.12".into(),
            source_commit: "a".repeat(40),
            workflow: akrat_trust::RELEASE_WORKFLOW.into(),
            workflow_ref: format!(
                "{}/{}/.github/workflows/build.yml@refs/tags/{release_tag}",
                "FIMAlexSender", "AKRAT"
            ),
            run_id: 123_456_789,
            issued_unix_seconds: 1_794_513_600,
            protocol_version: 1,
            assets: vec![
                akrat_trust::DistributionAsset {
                    name: "AKRAT-v0.1.12-relay-linux-x64".into(),
                    sha256: "1a".repeat(32),
                },
                akrat_trust::DistributionAsset {
                    name: "AKRAT-v0.1.12-relay-windows-x64.exe".into(),
                    sha256: "2b".repeat(32),
                },
            ],
        };
        let manifest_path = directory.path().join("attestation.json");
        let signature_path = directory.path().join("attestation.sig");
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&attestation).expect("encode fixture attestation"),
        )
        .expect("write fixture attestation");
        std::fs::write(
            &signature_path,
            "f907aa16a4d501de7c81a5bd3ca7e20559843452839b3fc20fe5d43350df246fc68116d75c76893da10e004f1fb267babba66209d8cb0f6459b4b4d3f644f606",
        )
        .expect("write fixture signature");

        let signing_key = Arc::new(SigningKey::from_bytes(&[23; 32]));
        let public_key = signing_key.verifying_key().to_bytes();
        let state = IdentityState {
            signing_key,
            relay_url: "https://relay.example.org/".into(),
            fingerprint: relay_identity_fingerprint(&public_key),
            distribution: Some(RelayDistributionClaim {
                artifact_name: "AKRAT-v0.1.12-relay-linux-x64".into(),
                artifact_sha256: "1a".repeat(32),
                source_commit: "a".repeat(40),
                protocol_version: 1,
            }),
            release_attestation_path: manifest_path,
            release_signature_path: signature_path,
            challenge_slots: Arc::new(tokio::sync::Semaphore::new(16)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local relay");
        let address = listener.local_addr().expect("relay address");
        let server = tokio::spawn(axum::serve(listener, identity_router(state)).into_future());
        let fingerprint = relay_identity_fingerprint(&public_key);
        let pin = akrat_trust::verify_remote_relay_identity_with_trust_at(
            "https://relay.example.org/",
            &format!("http://{address}"),
            &fingerprint,
            akrat_trust::RelayTrustLevel::DistributionVerified,
        )
        .await
        .expect("verify L2 identity and signed release sidecars");
        assert_eq!(pin.fingerprint, fingerprint);
        server.abort();
    }

    #[tokio::test]
    async fn release_sidecar_reader_rejects_missing_and_oversized_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("attestation.json");
        std::fs::write(&path, b"signed manifest").expect("write release sidecar");
        assert_eq!(
            read_release_sidecar(&path, 15)
                .await
                .expect("sidecar within size limit"),
            b"signed manifest"
        );
        assert_eq!(
            read_release_sidecar(&path, 8).await,
            Err(StatusCode::NOT_FOUND)
        );
        assert_eq!(
            read_release_sidecar(&directory.path().join("missing.json"), 1024).await,
            Err(StatusCode::NOT_FOUND)
        );
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
