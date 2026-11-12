use iroh::{Endpoint, RelayMode, endpoint::presets::N0, tls::CaTlsConfig};

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
