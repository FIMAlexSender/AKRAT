use akrat_core::{
    AsyncProtocolState, Contact, DeliveryState, Identity, StoredMessage, VaultData, load_vault,
    save_vault,
};
use akrat_mailbox::server::{self, Request, Response, ServerConfig};
use akrat_mailbox::{
    ServerSigner, Store,
    registry::{LocalRegistry, NodeAnnouncement, TrustStatus},
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::Digest;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

const PASSPHRASE: &str = "independent-process-test-phrase";
const MESSAGE_ID: &str = "a11ce00000000001";
const MESSAGE_TEXT: &str = "Alice sent this while Bob was offline.";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn offline_pqxdh_delivery_survives_independent_client_and_server_processes() {
    if let Ok(role) = std::env::var("AKRAT_MAILBOX_E2E_ROLE") {
        run_client_role(&role)
            .await
            .expect("client process workflow");
        return;
    }

    let directory = tempfile::tempdir().expect("test directory");
    let config_path = directory.path().join("server.json");
    let bob_vault = directory.path().join("bob.akrat");
    let alice_vault = directory.path().join("alice.akrat");
    let port = StdTcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("reserved address")
        .port();
    let config = ServerConfig::initialize(
        &config_path,
        "independent-process-test".into(),
        format!("127.0.0.1:{port}").parse().expect("server address"),
        directory.path().join("server-data"),
        16 * 1024 * 1024,
        16,
        1024 * 1024,
        24 * 60 * 60,
    )
    .expect("initialize server");
    let signer = config.receipt_signer().expect("server receipt signer");
    let root_signer = config.root_signer().expect("server federation root");
    std::fs::create_dir_all(&config.data_dir).expect("create server data directory");
    let mut store = Store::open(
        config.data_dir.join("mailbox.sqlite3"),
        config.max_total_bytes,
        config.max_mailboxes,
    )
    .expect("server store");
    let (mailbox_id, write_capability, read_capability, bundle_capability) = store
        .create_mailbox(1024 * 1024, 24 * 60 * 60)
        .expect("Bob mailbox");
    let address = config.bind;
    let server_public_key = hex::encode(config.noise_identity.public_key());
    let signing_public_key = hex::encode(signer.public_key());
    let receipt_mailbox_id = mailbox_id.clone();
    let receipt_write_capability = write_capability.clone();
    let server_executable = env!("CARGO_BIN_EXE_akrat-mailbox");
    let server_process = Command::new(server_executable)
        .arg("--config")
        .arg(&config_path)
        .arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start separate mailbox server process");
    let _server_guard = ChildGuard(server_process);

    let alice = Identity::generate("Alice".into()).expect("Alice identity");
    let mut healthy = false;
    for _ in 0..100 {
        if let Ok(mut channel) =
            server::connect(address, &alice, config.noise_identity.public_key()).await
            && server::start(&mut channel).await.is_ok()
            && matches!(
                server::request(&mut channel, &Request::Health).await,
                Ok(Response::Health { .. })
            )
        {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(healthy, "standalone server process became ready");

    let common = [
        ("AKRAT_MAILBOX_E2E_SERVER", address.to_string()),
        ("AKRAT_MAILBOX_E2E_NOISE_KEY", server_public_key),
        ("AKRAT_MAILBOX_E2E_MAILBOX_ID", mailbox_id),
        ("AKRAT_MAILBOX_E2E_WRITE_CAP", write_capability),
        ("AKRAT_MAILBOX_E2E_BUNDLE_CAP", bundle_capability),
        ("AKRAT_MAILBOX_E2E_READ_CAP", read_capability),
        (
            "AKRAT_MAILBOX_E2E_BOB_VAULT",
            bob_vault.display().to_string(),
        ),
        (
            "AKRAT_MAILBOX_E2E_ALICE_VAULT",
            alice_vault.display().to_string(),
        ),
        ("AKRAT_MAILBOX_E2E_SIGNING_KEY", signing_public_key),
        (
            "AKRAT_MAILBOX_E2E_DATA_DIR",
            directory.path().display().to_string(),
        ),
    ];

    run_child("bob-publish", &common);
    let mut bob_data = load_vault(&bob_vault, PASSPHRASE).expect("Bob offline vault");
    let bob = bob_data.identities[0].detached_copy();
    let bob_contact = Contact {
        fingerprint: bob.fingerprint(),
        name: "Bob".into(),
        public_key: bob.public_key().to_vec(),
        transport_id: bob.transport_id(),
        legacy_address: String::new(),
        manually_verified: true,
        mailbox_route: None,
        mailbox_replicas: Vec::new(),
    };
    let alice_contact = Contact {
        fingerprint: alice.fingerprint(),
        name: "Alice".into(),
        public_key: alice.public_key().to_vec(),
        transport_id: alice.transport_id(),
        legacy_address: String::new(),
        manually_verified: true,
        mailbox_route: None,
        mailbox_replicas: Vec::new(),
    };
    bob_data.contacts.push(alice_contact);
    save_vault(&bob_vault, &mut bob_data, PASSPHRASE).expect("persist verified sender");
    let mut alice_data = VaultData {
        identities: vec![alice.detached_copy()],
        contacts: vec![bob_contact],
        ..VaultData::default()
    };
    save_vault(&alice_vault, &mut alice_data, PASSPHRASE).expect("persist Alice vault");
    drop(bob_data);

    run_child("alice-send", &common);
    let alice_data = load_vault(&alice_vault, PASSPHRASE).expect("Alice sent vault");
    assert_eq!(alice_data.messages.len(), 1);
    assert_eq!(
        alice_data.messages[0].delivery,
        DeliveryState::MailboxStored
    );
    assert!(alice_data.messages[0].outgoing);

    run_child("bob-receive", &common);
    let bob_data = load_vault(&bob_vault, PASSPHRASE).expect("Bob received vault");
    assert_eq!(bob_data.messages.len(), 1);
    assert_eq!(bob_data.messages[0].text, MESSAGE_TEXT);
    assert!(!bob_data.messages[0].outgoing);
    assert_eq!(bob_data.messages[0].delivery, DeliveryState::Received);
    assert!(!bob_data.async_protocol_states[0].state.is_empty());

    let alice = alice_data.identities[0].detached_copy();
    let mut channel = server::connect(address, &alice, config.noise_identity.public_key())
        .await
        .expect("connect to mailbox after Bob acknowledgement");
    server::start(&mut channel).await.expect("protocol marker");
    assert!(matches!(
        server::request(&mut channel, &Request::Health,).await,
        Ok(Response::Health { messages: 0, .. })
    ));
    let recipient_receipt = match server::request(
        &mut channel,
        &Request::GetRecipientReceipt {
            mailbox_id: receipt_mailbox_id,
            write_capability: receipt_write_capability,
            message_id: MESSAGE_ID.into(),
        },
    )
    .await
    .expect("recipient delivery receipt")
    {
        Response::RecipientReceipt {
            receipt: Some(receipt),
        } => receipt,
        other => panic!("unexpected recipient receipt response: {other:?}"),
    };
    assert!(
        recipient_receipt
            .verify()
            .expect("recipient signature verifies")
    );
    assert_eq!(recipient_receipt.sender_public_key, alice.public_key());
    assert_eq!(
        recipient_receipt.recipient_public_key,
        bob_data.identities[0].public_key()
    );
    let discovered_signer = ServerSigner::generate().expect("discovered node signer");
    let discovered_identity = Identity::generate("discovered node".into()).expect("node identity");
    let issued_at = unix_now();
    let announcement = NodeAnnouncement::create(
        &discovered_signer,
        discovered_identity.public_key(),
        "127.0.0.1:47475".into(),
        "test node".into(),
        1,
        1,
        vec!["mailbox".into()],
        1024 * 1024,
        1,
        issued_at,
        issued_at + 3600,
    )
    .expect("signed node announcement");
    assert!(matches!(
        server::request(
            &mut channel,
            &Request::FederationAnnounce {
                announcement: announcement.clone()
            }
        )
        .await,
        Ok(Response::FederationAnnouncementAccepted)
    ));
    let snapshot = match server::request(&mut channel, &Request::FederationSnapshot)
        .await
        .expect("network snapshot")
    {
        Response::FederationSnapshot { snapshot } => snapshot,
        other => panic!("unexpected federation response: {other:?}"),
    };
    snapshot
        .verify(&root_signer.public_key(), unix_now())
        .expect("verify server-signed snapshot");
    assert_eq!(snapshot.announcements, vec![announcement.clone()]);
    let mut local_registry = LocalRegistry::open(directory.path().join("client-registry.sqlite3"))
        .expect("local registry");
    local_registry
        .add_trusted_source(&root_signer.public_key())
        .expect("explicitly trust bootstrap");
    local_registry
        .import_snapshot(&snapshot, unix_now())
        .expect("import verified snapshot");
    assert_eq!(
        local_registry
            .trust_status(&announcement.node_fingerprint)
            .expect("node trust"),
        TrustStatus::Discovered
    );
}

fn run_child(role: &str, values: &[(&str, String)]) {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .arg("--exact")
        .arg("offline_pqxdh_delivery_survives_independent_client_and_server_processes")
        .arg("--nocapture")
        .env("AKRAT_MAILBOX_E2E_ROLE", role)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in values {
        command.env(key, value);
    }
    let Output {
        status,
        stdout,
        stderr,
    } = command.output().expect("start independent client process");
    assert!(
        status.success(),
        "{role} client failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
}

async fn run_client_role(role: &str) -> Result<(), Box<dyn std::error::Error>> {
    let address: SocketAddr = env_value("AKRAT_MAILBOX_E2E_SERVER")?.parse()?;
    let server_public_key = hex::decode(env_value("AKRAT_MAILBOX_E2E_NOISE_KEY")?)?;
    let mailbox_id = env_value("AKRAT_MAILBOX_E2E_MAILBOX_ID")?;
    let write_capability = env_value("AKRAT_MAILBOX_E2E_WRITE_CAP")?;
    let read_capability = env_value("AKRAT_MAILBOX_E2E_READ_CAP")?;
    let bundle_capability = env_value("AKRAT_MAILBOX_E2E_BUNDLE_CAP")?;
    let bob_vault = PathBuf::from(env_value("AKRAT_MAILBOX_E2E_BOB_VAULT")?);
    let alice_vault = PathBuf::from(env_value("AKRAT_MAILBOX_E2E_ALICE_VAULT")?);
    match role {
        "bob-publish" => {
            let bob = Identity::generate("Bob".into())?;
            let (bundle, state) = akrat_core::async_crypto::publish_bundle(&bob, &[]).await?;
            let mut data = VaultData {
                revision: 0,
                identities: vec![bob.detached_copy()],
                async_protocol_states: vec![AsyncProtocolState {
                    identity_id: bob.id.clone(),
                    state,
                }],
                ..VaultData::default()
            };
            save_vault(&bob_vault, &mut data, PASSPHRASE)?;
            let mut channel = server::connect(address, &bob, &server_public_key).await?;
            server::start(&mut channel).await?;
            let response = server::request(
                &mut channel,
                &Request::PublishBundle {
                    mailbox_id,
                    write_capability,
                    bundle,
                },
            )
            .await?;
            if !matches!(response, Response::BundlePublished) {
                return Err("mailbox rejected Bob's pre-key bundle".into());
            }
        }
        "alice-send" => {
            let mut data = load_vault(&alice_vault, PASSPHRASE)?;
            let alice = data.identities[0].detached_copy();
            let bob = data
                .contacts
                .iter()
                .find(|contact| contact.manually_verified)
                .ok_or("verified Bob contact missing")?;
            let mut channel = server::connect(address, &alice, &server_public_key).await?;
            server::start(&mut channel).await?;
            let response = server::request(
                &mut channel,
                &Request::GetBundle {
                    mailbox_id: mailbox_id.clone(),
                    bundle_capability: bundle_capability.clone(),
                },
            )
            .await?;
            let bundle = match response {
                Response::Bundle {
                    bundle: Some(bundle),
                } => bundle,
                _ => return Err("Bob's public pre-key bundle is missing".into()),
            };
            akrat_core::async_crypto::verify_bundle(&bundle, &bob.public_key)?;
            let current_state = data
                .async_protocol_states
                .iter()
                .find(|state| state.identity_id == alice.id)
                .map(|state| state.state.as_slice())
                .unwrap_or_default();
            let (encrypted, new_state) = akrat_core::async_crypto::encrypt(
                &alice,
                current_state,
                &bob.public_key,
                &bundle,
                MESSAGE_TEXT.as_bytes(),
            )
            .await?;
            let conversation = format!("{}:{}", alice.id, bob.fingerprint);
            data.messages.push(StoredMessage {
                conversation,
                id: MESSAGE_ID.into(),
                outgoing: true,
                text: MESSAGE_TEXT.into(),
                delivery: DeliveryState::Pending,
                timestamp: unix_now(),
                delivery_events: Vec::new(),
                received_ciphertext_sha256: None,
            });
            if let Some(state) = data
                .async_protocol_states
                .iter_mut()
                .find(|state| state.identity_id == alice.id)
            {
                state.state = new_state;
            } else {
                data.async_protocol_states.push(AsyncProtocolState {
                    identity_id: alice.id.clone(),
                    state: new_state,
                });
            }
            save_vault(&alice_vault, &mut data, PASSPHRASE)?;
            let ciphertext = serde_json::to_vec(&encrypted)?;
            let response = server::request(
                &mut channel,
                &Request::Deposit {
                    mailbox_id,
                    write_capability,
                    message_id: MESSAGE_ID.into(),
                    ciphertext: STANDARD.encode(ciphertext),
                },
            )
            .await?;
            let receipt = match response {
                Response::Deposit { receipt } => receipt,
                _ => return Err("mailbox refused the ciphertext deposit".into()),
            };
            let signer_public: [u8; 32] = hex::decode(env_value("AKRAT_MAILBOX_E2E_SIGNING_KEY")?)?
                .try_into()
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid signing public key",
                    )
                })?;
            if !akrat_mailbox::verify_receipt(&receipt, &signer_public)? {
                return Err("mailbox receipt signature did not verify".into());
            }
            let mut data = load_vault(&alice_vault, PASSPHRASE)?;
            let message = data
                .messages
                .iter_mut()
                .find(|message| message.id == MESSAGE_ID)
                .ok_or("local message disappeared")?;
            message.delivery = DeliveryState::MailboxStored;
            save_vault(&alice_vault, &mut data, PASSPHRASE)?;
        }
        "bob-receive" => {
            let mut data = load_vault(&bob_vault, PASSPHRASE)?;
            let bob = data.identities[0].detached_copy();
            let sender = data
                .contacts
                .iter()
                .find(|contact| contact.manually_verified)
                .cloned()
                .ok_or("verified Alice contact missing")?;
            let state_index = data
                .async_protocol_states
                .iter()
                .position(|state| state.identity_id == bob.id)
                .ok_or("Bob protocol state missing")?;
            let mut channel = server::connect(address, &bob, &server_public_key).await?;
            server::start(&mut channel).await?;
            let response = server::request(
                &mut channel,
                &Request::Fetch {
                    mailbox_id: mailbox_id.clone(),
                    read_capability: read_capability.clone(),
                    limit: 8,
                },
            )
            .await?;
            let envelopes = match response {
                Response::Fetch { envelopes } => envelopes,
                _ => return Err("mailbox refused message retrieval".into()),
            };
            if envelopes.len() != 1 || envelopes[0].message_id != MESSAGE_ID {
                return Err("expected one offline message".into());
            }
            let bytes = STANDARD.decode(&envelopes[0].ciphertext)?;
            let encrypted: akrat_core::async_crypto::AsyncCiphertext =
                serde_json::from_slice(&bytes)?;
            let (plaintext, updated_state) = akrat_core::async_crypto::decrypt(
                &bob,
                &data.async_protocol_states[state_index].state,
                &sender.public_key,
                &encrypted,
            )
            .await?;
            let text = String::from_utf8(plaintext)?;
            data.async_protocol_states[state_index].state = updated_state;
            data.messages.push(StoredMessage {
                conversation: format!("{}:{}", bob.id, sender.fingerprint),
                id: MESSAGE_ID.into(),
                outgoing: false,
                text,
                delivery: DeliveryState::Received,
                timestamp: unix_now(),
                delivery_events: Vec::new(),
                received_ciphertext_sha256: None,
            });
            save_vault(&bob_vault, &mut data, PASSPHRASE)?;
            let receipt = akrat_core::async_crypto::RecipientReceipt::create(
                &bob,
                &sender.public_key,
                mailbox_id.clone(),
                MESSAGE_ID.into(),
                hex::encode(sha2::Sha256::digest(&bytes)),
                unix_now(),
            )?;
            if !receipt.verify()? {
                return Err("locally generated recipient signature failed verification".into());
            }
            let response = server::request(
                &mut channel,
                &Request::Acknowledge {
                    mailbox_id,
                    read_capability,
                    receipt,
                },
            )
            .await?;
            if !matches!(response, Response::Acknowledged) {
                return Err(format!(
                    "mailbox did not acknowledge the stored message: {response:?}"
                )
                .into());
            }
        }
        _ => return Err(format!("unknown process role {role}").into()),
    }
    Ok(())
}

fn env_value(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::env::var(name)?)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
