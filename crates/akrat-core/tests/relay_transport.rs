use akrat_core::RelaySettings;
use akrat_trust::{RelayDisposition, RelayOperationalRecord};
use iroh::{Endpoint, EndpointAddr, RelayMode, Watcher, endpoint::presets::N0, tls::CaTlsConfig};

const ALPN: &[u8] = b"akrat-relay-test/0.1";
static LOCAL_RELAY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn encrypted_peer_stream_works_through_a_forced_local_iroh_relay() {
    let _guard = LOCAL_RELAY_TEST_LOCK.lock().await;
    let (relay_map, _, _relay_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start local Iroh relay");
    let relay_mode = RelayMode::Custom(relay_map);
    let server = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(relay_mode.clone())
        .clear_ip_transports()
        .bind()
        .await
        .expect("bind relay-only peer");
    server.online().await;
    let address = server.addr();
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("accept incoming peer");
        let connection = incoming.await.expect("authenticate relay transport");
        let mut receive = connection.accept_uni().await.expect("accept stream");
        receive
            .read_to_end(1024)
            .await
            .expect("read protected payload")
    });
    let client = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(relay_mode)
        .clear_ip_transports()
        .bind()
        .await
        .expect("bind relay-only peer");
    client.online().await;
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        client.connect(address, ALPN),
    )
    .await
    .expect("relay connection deadline")
    .expect("connect through relay");
    let mut send = connection.open_uni().await.expect("open stream");
    send.write_all(b"encrypted relay payload")
        .await
        .expect("send payload");
    send.finish().expect("finish payload");
    assert_eq!(
        server_task.await.expect("server task"),
        b"encrypted relay payload"
    );
    client.close().await;
}

#[tokio::test]
async fn endpoint_switches_to_an_allowed_relay_after_home_relay_fails() {
    let _guard = LOCAL_RELAY_TEST_LOCK.lock().await;
    let (relay_map, first_url, first_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start first local Iroh relay");
    let (second_map, second_url, second_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start second local Iroh relay");
    relay_map.extend(&second_map);

    let settings = RelaySettings {
        use_default_relays: false,
        custom_relays: vec![first_url.to_string(), second_url.to_string()],
        operational_records: vec![
            RelayOperationalRecord {
                relay_url: first_url.to_string(),
                disposition: RelayDisposition::Favorite,
                ..RelayOperationalRecord::default()
            },
            RelayOperationalRecord {
                relay_url: second_url.to_string(),
                disposition: RelayDisposition::Allowed,
                ..RelayOperationalRecord::default()
            },
        ],
        ..RelaySettings::default()
    };

    let endpoint = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(settings.relay_mode().expect("valid relay settings"))
        .path_selector(settings.path_selector())
        .clear_ip_transports()
        .bind()
        .await
        .expect("bind endpoint with two allowed relays");
    tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.online())
        .await
        .expect("endpoint connects to an allowed relay");

    let primary = endpoint
        .addr()
        .relay_urls()
        .next()
        .cloned()
        .expect("endpoint has a home relay");
    let fallback = if primary == first_url {
        drop(first_server);
        second_url
    } else {
        assert_eq!(primary, second_url);
        drop(second_server);
        first_url
    };

    let mut statuses = endpoint.home_relay_status();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let current = statuses.get();
            if current
                .iter()
                .any(|status| status.url() == &fallback && status.is_connected())
            {
                break;
            }
            statuses
                .updated()
                .await
                .expect("home relay status remains available");
        }
    })
    .await
    .expect("endpoint fails over to the other allowed relay");

    assert_eq!(
        endpoint.addr().relay_urls().next(),
        Some(&fallback),
        "the new home relay must be the still-running allowed relay"
    );

    let address = endpoint.addr();
    let receiving_endpoint = endpoint.clone();
    let receive_task = tokio::spawn(async move {
        let incoming = receiving_endpoint
            .accept()
            .await
            .expect("accept peer after relay failover");
        let connection = incoming
            .await
            .expect("authenticate peer after relay failover");
        let mut receive = connection
            .accept_uni()
            .await
            .expect("accept message stream");
        receive
            .read_to_end(1024)
            .await
            .expect("read message after relay failover")
    });
    let client = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(RelayMode::custom([fallback]))
        .path_selector(settings.path_selector())
        .clear_ip_transports()
        .bind()
        .await
        .expect("bind peer to the fallback relay");
    tokio::time::timeout(std::time::Duration::from_secs(30), client.online())
        .await
        .expect("peer connects to the fallback relay");
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        client.connect(address, ALPN),
    )
    .await
    .expect("connect deadline after relay failover")
    .expect("connect through the fallback relay");
    let mut send = connection.open_uni().await.expect("open fallback stream");
    send.write_all(b"message delivered after relay failover")
        .await
        .expect("send message through fallback");
    send.finish().expect("finish fallback message");
    assert_eq!(
        receive_task.await.expect("receiver task"),
        b"message delivered after relay failover"
    );
    client.close().await;
    endpoint.close().await;
}

#[tokio::test]
async fn favorite_relay_is_preferred_for_an_open_p2p_path() {
    let _guard = LOCAL_RELAY_TEST_LOCK.lock().await;
    let (relay_map, first_url, _first_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start first local Iroh relay");
    let (second_map, second_url, _second_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start second local Iroh relay");
    relay_map.extend(&second_map);

    let settings = RelaySettings {
        use_default_relays: false,
        custom_relays: vec![first_url.to_string(), second_url.to_string()],
        operational_records: vec![
            RelayOperationalRecord {
                relay_url: first_url.to_string(),
                disposition: RelayDisposition::Allowed,
                ..RelayOperationalRecord::default()
            },
            RelayOperationalRecord {
                relay_url: second_url.to_string(),
                disposition: RelayDisposition::Favorite,
                ..RelayOperationalRecord::default()
            },
        ],
        ..RelaySettings::default()
    };
    let relay_mode = RelayMode::Custom(relay_map);
    let server = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(relay_mode.clone())
        .path_selector(settings.path_selector())
        .clear_ip_transports()
        .bind()
        .await
        .expect("bind favorite-aware server");
    tokio::time::timeout(std::time::Duration::from_secs(30), server.online())
        .await
        .expect("server connects to an allowed relay");

    let client = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(relay_mode)
        .path_selector(settings.path_selector())
        .clear_ip_transports()
        .bind()
        .await
        .expect("bind favorite-aware client");
    tokio::time::timeout(std::time::Duration::from_secs(30), client.online())
        .await
        .expect("client connects to an allowed relay");

    let address = EndpointAddr::new(server.id())
        .with_relay_url(first_url.clone())
        .with_relay_url(second_url.clone());
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("accept favorite path peer");
        let connection = incoming.await.expect("accept favorite path connection");
        let mut receive = connection
            .accept_uni()
            .await
            .expect("accept favorite stream");
        receive
            .read_to_end(1024)
            .await
            .expect("read favorite stream")
    });
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.connect(address, ALPN),
    )
    .await
    .expect("favorite relay connection deadline")
    .expect("connect through an allowed relay");

    let selection = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if connection.paths().iter().any(|path| {
                path.is_selected()
                    && matches!(path.remote_addr(), iroh::TransportAddr::Relay(url) if url == &second_url)
            }) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        selection.is_ok(),
        "the selected P2P path uses the favorite relay; observed paths: {:?}",
        connection.paths()
    );

    let mut send = connection.open_uni().await.expect("open favorite stream");
    send.write_all(b"favorite relay path selected")
        .await
        .expect("send through favorite relay");
    send.finish().expect("finish favorite stream");
    assert_eq!(
        server_task.await.expect("favorite server task"),
        b"favorite relay path selected"
    );
    client.close().await;
}
