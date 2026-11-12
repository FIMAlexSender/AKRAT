use akrat_core::{Identity, network};
use akrat_mailbox::ServerSigner;
use akrat_mailbox::registry::{LocalRegistry, NodeAnnouncement};
use akrat_mailbox::server::{self, FederationPeer, Request, Response, ServerConfig};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::net::TcpStream;

struct RunningServer {
    child: Child,
}

impl RunningServer {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[tokio::test]
async fn federation_propagates_between_three_processes_after_bootstrap_is_offline() {
    let directory = tempfile::tempdir().expect("test directory");
    let mut a = create_config(directory.path(), "A");
    let mut b = create_config(directory.path(), "B");
    let mut c = create_config(directory.path(), "C");
    a.federation_peers = vec![peer(&b)];
    b.federation_peers = vec![peer(&a), peer(&c)];
    c.federation_peers = vec![peer(&b)];
    let config_a = directory.path().join("a.json");
    let config_b = directory.path().join("b.json");
    let config_c = directory.path().join("c.json");
    a.save(&config_a).expect("save A");
    b.save(&config_b).expect("save B");
    c.save(&config_c).expect("save C");

    let signer_a = signer(&a);
    let signer_b = signer(&b);
    let signer_c = signer(&c);
    let fingerprint_a = signer_a.fingerprint();
    let fingerprint_b = signer_b.fingerprint();
    let fingerprint_c = signer_c.fingerprint();
    let mut process_a = start_server(&config_a);
    let _process_b = start_server(&config_b);
    let _process_c = start_server(&config_c);
    wait_ready(&a).await;
    wait_ready(&b).await;
    wait_ready(&c).await;

    announce_self(&a, &signer_a, "A", 2).await;
    announce_self(&b, &signer_b, "B", 2).await;
    announce_self(&c, &signer_c, "C", 2).await;

    wait_for_node(&b, &fingerprint_a).await;
    announce_self(&a, &signer_a, "A renommé", 3).await;
    wait_for_node_name(&b, &fingerprint_a, "A renommé").await;
    process_a.stop();

    assert!(node_exists(&b, &fingerprint_a));
    wait_for_node(&c, &fingerprint_a).await;
    wait_for_node_name(&c, &fingerprint_a, "A renommé").await;
    assert!(node_exists(&c, &fingerprint_b));
    assert!(node_exists(&b, &fingerprint_c));
    assert!(node_is_discovered(&c, &fingerprint_a));

    health(&b).await;
    health(&c).await;
    let _restarted_process_a = start_server(&config_a);
    wait_ready(&a).await;
    wait_for_node(&a, &fingerprint_c).await;
    health(&a).await;
}

fn create_config(directory: &Path, name: &str) -> ServerConfig {
    let config_path = directory.join(format!("{name}.json"));
    ServerConfig::initialize(
        &config_path,
        format!("federation-{name}"),
        reserve_address(),
        directory.join(format!("{name}-data")),
        1024 * 1024,
        8,
        128 * 1024,
        3600,
    )
    .expect("initialize server config")
}

fn reserve_address() -> SocketAddr {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("reserved address")
}

fn peer(config: &ServerConfig) -> FederationPeer {
    FederationPeer {
        endpoint: config.bind.to_string(),
        noise_public_key_hex: hex::encode(config.noise_identity.public_key()),
        signing_public_key_hex: hex::encode(signer(config).public_key()),
    }
}

fn signer(config: &ServerConfig) -> ServerSigner {
    ServerSigner::from_bytes(&hex::decode(&config.signing_key_hex).expect("signing secret"))
        .expect("server signer")
}

fn start_server(config_path: &Path) -> RunningServer {
    let child = Command::new(env!("CARGO_BIN_EXE_akrat-mailbox"))
        .arg("--config")
        .arg(config_path)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start server process");
    RunningServer { child }
}

async fn wait_ready(config: &ServerConfig) {
    for _ in 0..300 {
        if health_try(config).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server {} did not become ready", config.name);
}

async fn health_try(config: &ServerConfig) -> bool {
    let Ok(mut channel) = connect(config).await else {
        return false;
    };
    matches!(
        server::request(&mut channel, &Request::Health).await,
        Ok(Response::Health { .. })
    )
}

async fn health(config: &ServerConfig) {
    let mut channel = connect(config).await.expect("server remains available");
    assert!(matches!(
        server::request(&mut channel, &Request::Health).await,
        Ok(Response::Health { .. })
    ));
}

async fn connect(
    config: &ServerConfig,
) -> Result<akrat_core::network::SecureChannel<TcpStream>, Box<dyn std::error::Error>> {
    let identity = Identity::generate("federation-test-client".into())?;
    let stream = TcpStream::connect(config.bind).await?;
    let pending = network::initiate(stream, &identity).await?;
    let mut channel = pending.verify_peer(config.noise_identity.public_key())?;
    server::start(&mut channel).await?;
    Ok(channel)
}

async fn announce_self(config: &ServerConfig, signer: &ServerSigner, name: &str, sequence: u64) {
    let identity =
        Identity::generate(format!("announcement-{name}")).expect("announcement identity");
    let now = akrat_mailbox::registry::unix_now().expect("system time");
    let announcement = NodeAnnouncement::create_profile(
        signer,
        config.noise_identity.public_key(),
        config.bind.to_string(),
        format!("operator-{name}"),
        name.into(),
        format!("Profil public {name}"),
        String::new(),
        1,
        1,
        vec!["mailbox".into(), "federation".into()],
        1024 * 1024,
        sequence,
        now,
        now + 3600,
    )
    .expect("signed announcement");
    let mut channel = {
        let stream = TcpStream::connect(config.bind).await.expect("connect");
        let pending = network::initiate(stream, &identity).await.expect("Noise");
        let mut channel = pending
            .verify_peer(config.noise_identity.public_key())
            .expect("server key");
        server::start(&mut channel).await.expect("protocol start");
        channel
    };
    assert!(matches!(
        server::request(&mut channel, &Request::FederationAnnounce { announcement }).await,
        Ok(Response::FederationAnnouncementAccepted)
    ));
}

async fn wait_for_node(config: &ServerConfig, fingerprint: &str) {
    for _ in 0..300 {
        if node_exists(config, fingerprint) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} did not discover node {fingerprint}", config.name);
}

async fn wait_for_node_name(config: &ServerConfig, fingerprint: &str, name: &str) {
    for _ in 0..300 {
        if node_has_name(config, fingerprint, name) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} did not learn node name {name}", config.name);
}

fn node_has_name(config: &ServerConfig, fingerprint: &str, name: &str) -> bool {
    LocalRegistry::open(config.data_dir.join("federation.sqlite3"))
        .and_then(|registry| registry.known_nodes())
        .is_ok_and(|nodes| {
            nodes
                .iter()
                .any(|(node, _)| node.node_fingerprint == fingerprint && node.name == name)
        })
}

fn node_exists(config: &ServerConfig, fingerprint: &str) -> bool {
    LocalRegistry::open(config.data_dir.join("federation.sqlite3"))
        .and_then(|registry| registry.known_nodes())
        .is_ok_and(|nodes| {
            nodes
                .iter()
                .any(|(node, _)| node.node_fingerprint == fingerprint)
        })
}

fn node_is_discovered(config: &ServerConfig, fingerprint: &str) -> bool {
    LocalRegistry::open(config.data_dir.join("federation.sqlite3"))
        .and_then(|registry| registry.known_nodes())
        .is_ok_and(|nodes| {
            nodes.iter().any(|(node, status)| {
                node.node_fingerprint == fingerprint
                    && *status == akrat_mailbox::registry::TrustStatus::Discovered
            })
        })
}
