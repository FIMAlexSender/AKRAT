use iroh::{Endpoint, RelayMode, Watcher, endpoint::presets::N0, tls::CaTlsConfig};

const ALPN: &[u8] = b"akrat-relay-test/0.1";

#[tokio::test]
async fn encrypted_peer_stream_works_through_a_forced_local_iroh_relay() {
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
    let (relay_map, first_url, first_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start first local Iroh relay");
    let (second_map, second_url, second_server) = iroh::test_utils::run_relay_server()
        .await
        .expect("start second local Iroh relay");
    relay_map.extend(&second_map);

    let endpoint = Endpoint::builder(N0)
        .alpns(vec![ALPN.to_vec()])
        .ca_tls_config(CaTlsConfig::insecure_skip_verify())
        .relay_mode(RelayMode::Custom(relay_map))
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
