use akrat_core::{
    Contact, Conversation, IdentityTrust, MessageDelivery, MessageDirection, PrivateIdentity,
    StoredMessage,
};
use akrat_crypto::create_identity;
use akrat_network::{
    SessionEvent, SessionHandle, accept, bind, connect, initiate_session, respond_session,
    start_message_session,
};
use akrat_protocol::Invitation;
use akrat_storage::{
    VaultData, append_message, load_vault_data_with_key, save_vault_data, save_vault_data_with_key,
};
use std::sync::Arc;
use tokio::sync::mpsc;

const ALICE_PASSPHRASE: &str = "alice independent vault passphrase";
const BOB_PASSPHRASE: &str = "bob independent vault passphrase";

fn temp_vault(label: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "akrat-{label}-{}-{stamp}.vault",
        std::process::id()
    ))
}

fn contact(identity: &PrivateIdentity, label: &str) -> Contact {
    Contact {
        id: identity.public.id.clone(),
        display_name: label.to_string(),
        public_key: identity.public.public_key.clone(),
        fingerprint: identity.public.fingerprint.clone(),
        addresses: Vec::new(),
        trust: IdentityTrust::ManuallyVerified,
        blocked: false,
        created_at_unix: 1,
        last_seen_at_unix: None,
    }
}

fn conversation(local: &PrivateIdentity, remote: &PrivateIdentity) -> Conversation {
    Conversation {
        id: format!("{}-{}", local.public.id, remote.public.id),
        local_identity_id: local.public.id.clone(),
        remote_identity_id: remote.public.id.clone(),
        created_at_unix: 1,
        messages: Vec::new(),
    }
}

async fn establish_actors(
    alice: Arc<PrivateIdentity>,
    bob: Arc<PrivateIdentity>,
    listener: tokio::net::TcpListener,
    connect_address: std::net::SocketAddr,
) -> (
    (SessionHandle, mpsc::Receiver<SessionEvent>),
    (SessionHandle, mpsc::Receiver<SessionEvent>),
) {
    let alice_key = alice.public.public_key.clone();
    let bob_key = bob.public.public_key.clone();
    let bob_id = bob.public.id.clone();
    let alice_id = alice.public.id.clone();
    let responder = tokio::spawn(async move {
        let (stream, _) = accept(&listener).await.expect("accept Alice");
        let (stream, pending) = respond_session(stream, &bob, Some(&alice_key))
            .await
            .expect("Bob handshake");
        let session = pending
            .verify_peer_identity(&alice_id, &alice_key)
            .expect("verify Alice pin");
        (stream, session)
    });
    let stream = connect(connect_address)
        .await
        .expect("connect using invitation address");
    let (stream, pending) = initiate_session(stream, &alice, Some(&bob_key))
        .await
        .expect("Alice handshake");
    let alice_session = pending
        .verify_peer_identity(&bob_id, &bob_key)
        .expect("verify Bob pin");
    let (bob_stream, bob_session) = responder.await.expect("Bob handshake task");
    (
        start_message_session(stream.into_std().expect("Alice std stream"), alice_session),
        start_message_session(bob_stream.into_std().expect("Bob std stream"), bob_session),
    )
}

async fn receive_text(events: &mut mpsc::Receiver<SessionEvent>) -> (String, String) {
    match tokio::time::timeout(std::time::Duration::from_secs(5), events.recv())
        .await
        .expect("session event timeout")
        .expect("session event channel")
    {
        SessionEvent::Received { message_id, text } => (message_id, text),
        other => panic!("expected incoming text, received {other:?}"),
    }
}

async fn receive_ack(events: &mut mpsc::Receiver<SessionEvent>, expected_id: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await.expect("session event channel") {
                SessionEvent::Acknowledged { message_id } if message_id == expected_id => return,
                SessionEvent::Transmitted { .. } => {}
                other => panic!("expected delivery acknowledgement, received {other:?}"),
            }
        }
    })
    .await
    .expect("acknowledgement timeout");
}

fn persist_incoming(
    data: &mut VaultData,
    key: &akrat_storage::VaultKey,
    path: &std::path::Path,
    conversation_id: &str,
    sender_id: &str,
    message_id: &str,
    text: &str,
) -> bool {
    let added = append_message(
        data,
        conversation_id,
        StoredMessage {
            id: message_id.to_string(),
            sender_identity_id: sender_id.to_string(),
            sent_at_unix: 2,
            direction: MessageDirection::Incoming,
            delivery: MessageDelivery::Received,
            text: text.to_string(),
        },
    )
    .expect("persist incoming message");
    if added {
        save_vault_data_with_key(path, data, key).expect("save encrypted incoming message");
    }
    added
}

#[tokio::test]
async fn independent_vaults_exchange_messages_persist_and_deduplicate_after_reconnect() {
    let alice = Arc::new(create_identity("Alice".to_string()).expect("Alice identity"));
    let bob = Arc::new(create_identity("Bob".to_string()).expect("Bob identity"));
    let alice_listener = bind("127.0.0.1:0".parse().expect("Alice loopback address"))
        .await
        .expect("bind Alice listener");
    let bob_listener = bind("127.0.0.1:0".parse().expect("Bob loopback address"))
        .await
        .expect("bind Bob listener");
    let alice_address = alice_listener.local_addr().expect("Alice address");
    let bob_address = bob_listener.local_addr().expect("Bob address");
    let alice_invitation = Invitation::new(
        vec![alice_address],
        alice
            .public
            .public_key
            .as_slice()
            .try_into()
            .expect("Alice key"),
    )
    .expect("Alice invitation");
    let bob_invitation = Invitation::new(
        vec![bob_address],
        bob.public
            .public_key
            .as_slice()
            .try_into()
            .expect("Bob key"),
    )
    .expect("Bob invitation");
    let imported_alice = Invitation::from_uri(&alice_invitation.to_uri().expect("export Alice"))
        .expect("import Alice invitation");
    let imported_bob = Invitation::from_uri(&bob_invitation.to_uri().expect("export Bob"))
        .expect("import Bob invitation");
    assert_eq!(imported_alice.identity_id, alice.public.id);
    assert_eq!(imported_bob.identity_id, bob.public.id);

    let alice_conversation = conversation(&alice, &bob);
    let bob_conversation = conversation(&bob, &alice);
    let mut alice_contact = contact(&bob, "Bob");
    alice_contact.addresses = imported_bob
        .addresses
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut bob_contact = contact(&alice, "Alice");
    bob_contact.addresses = imported_alice
        .addresses
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut alice_vault = VaultData {
        identities: vec![alice.clone()],
        contacts: vec![alice_contact],
        conversations: vec![alice_conversation.clone()],
        preferred_identity_id: Some(alice.public.id.clone()),
    };
    let mut bob_vault = VaultData {
        identities: vec![bob.clone()],
        contacts: vec![bob_contact],
        conversations: vec![bob_conversation.clone()],
        preferred_identity_id: Some(bob.public.id.clone()),
    };
    let alice_path = temp_vault("alice");
    let bob_path = temp_vault("bob");
    save_vault_data(&alice_path, &alice_vault, ALICE_PASSPHRASE).expect("save Alice vault");
    save_vault_data(&bob_path, &bob_vault, BOB_PASSPHRASE).expect("save Bob vault");
    let (loaded_alice, alice_key) =
        load_vault_data_with_key(&alice_path, ALICE_PASSPHRASE).expect("unlock Alice vault");
    let (loaded_bob, bob_key) =
        load_vault_data_with_key(&bob_path, BOB_PASSPHRASE).expect("unlock Bob vault");
    alice_vault = loaded_alice;
    bob_vault = loaded_bob;

    let (mut alice_session, mut bob_session) = establish_actors(
        alice.clone(),
        bob.clone(),
        bob_listener,
        imported_bob.addresses[0],
    )
    .await;
    let first_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    alice_session
        .0
        .send_text(first_id.to_string(), "Hello Bob".to_string())
        .expect("send Alice message");
    let (received_id, received_text) = receive_text(&mut bob_session.1).await;
    assert_eq!(received_id, first_id);
    assert_eq!(received_text, "Hello Bob");
    persist_incoming(
        &mut bob_vault,
        &bob_key,
        &bob_path,
        &bob_conversation.id,
        &alice.public.id,
        first_id,
        &received_text,
    );
    bob_session
        .0
        .confirm_received(first_id.to_string())
        .expect("confirm saved Alice message");
    receive_ack(&mut alice_session.1, first_id).await;

    let reply_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    bob_session
        .0
        .send_text(reply_id.to_string(), "Hello Alice".to_string())
        .expect("send Bob reply");
    let (received_id, received_text) = receive_text(&mut alice_session.1).await;
    assert_eq!(received_id, reply_id);
    assert_eq!(received_text, "Hello Alice");
    persist_incoming(
        &mut alice_vault,
        &alice_key,
        &alice_path,
        &alice_conversation.id,
        &bob.public.id,
        reply_id,
        &received_text,
    );
    alice_session
        .0
        .confirm_received(reply_id.to_string())
        .expect("confirm saved Bob reply");
    receive_ack(&mut bob_session.1, reply_id).await;

    drop(alice_session);
    drop(bob_session);
    let reconnect_listener = bind("127.0.0.1:0".parse().expect("reconnect loopback address"))
        .await
        .expect("bind Bob listener for reconnect");
    let reconnect_invitation = Invitation::new(
        vec![reconnect_listener.local_addr().expect("reconnect address")],
        bob.public
            .public_key
            .as_slice()
            .try_into()
            .expect("Bob key"),
    )
    .expect("reconnect invitation");
    let reconnect_invitation = Invitation::from_uri(
        &reconnect_invitation
            .to_uri()
            .expect("export reconnect invitation"),
    )
    .expect("import reconnect invitation");
    let (mut alice_session, mut bob_session) = establish_actors(
        alice.clone(),
        bob.clone(),
        reconnect_listener,
        reconnect_invitation.addresses[0],
    )
    .await;
    alice_session
        .0
        .send_text(first_id.to_string(), "Hello Bob".to_string())
        .expect("retry same message ID after reconnect");
    let (received_id, received_text) = receive_text(&mut bob_session.1).await;
    assert_eq!(received_id, first_id);
    assert!(!persist_incoming(
        &mut bob_vault,
        &bob_key,
        &bob_path,
        &bob_conversation.id,
        &alice.public.id,
        first_id,
        &received_text,
    ));
    bob_session
        .0
        .confirm_received(first_id.to_string())
        .expect("ack duplicate after dedupe");
    receive_ack(&mut alice_session.1, first_id).await;

    let (restarted_alice, _) =
        load_vault_data_with_key(&alice_path, ALICE_PASSPHRASE).expect("restart Alice vault");
    let (restarted_bob, _) =
        load_vault_data_with_key(&bob_path, BOB_PASSPHRASE).expect("restart Bob vault");
    assert_eq!(restarted_alice.conversations[0].messages.len(), 1);
    assert_eq!(restarted_bob.conversations[0].messages.len(), 1);
    assert_eq!(restarted_alice.identities[0].public.id, alice.public.id);
    assert_eq!(restarted_bob.identities[0].public.id, bob.public.id);

    drop(alice_session);
    drop(bob_session);
    std::fs::remove_file(alice_path).expect("remove Alice vault");
    std::fs::remove_file(bob_path).expect("remove Bob vault");
}
