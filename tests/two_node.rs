//! Two-node integration test: connect two PacketConn instances over a local
//! TCP loopback socket and verify that traffic flows in both directions.
//!
//! This exercises the full Ironwood stack between two in-process Rust nodes:
//! key exchange → SigReq/SigRes → ANNOUNCE → BLOOM_FILTER → PathLookup →
//! SessionInit/Ack → encrypted traffic.
//!
//! To test against a live yggdrasil-go node, set `YGG_TEST_PEER`:
//!
//! ```text
//! YGG_TEST_PEER=tcp://ygg.mkg20001.io:80 cargo test live_peer -- --nocapture
//! ```

use std::time::Duration;

use ed25519_dalek::SigningKey;
use ironwood_rs::{transport, PacketConn};
use rand::rngs::OsRng;
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_node() -> PacketConn {
    let key = SigningKey::generate(&mut OsRng);
    PacketConn::new(key)
}

/// Connect two nodes over a loopback TCP socket.
async fn connected_pair() -> (PacketConn, PacketConn) {
    let server = make_node();
    let client = make_node();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server side: accept + handshake
    let server_clone = server.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        transport::handle_stream(&server_clone, stream, 0).await.unwrap_or(());
    });

    // Client side: dial + handshake
    let client_clone = client.clone();
    tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        transport::handle_stream(&client_clone, stream, 0).await.unwrap_or(());
    });

    // Let the Ironwood handshake (SigReq/SigRes + ANNOUNCE + BLOOM) complete
    tokio::time::sleep(Duration::from_millis(400)).await;

    (server, client)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two nodes connect and exchange encrypted traffic in both directions.
#[tokio::test]
async fn test_two_nodes_exchange_traffic() {
    let (server, client) = connected_pair().await;

    let server_pub = server.public_key();
    let client_pub = client.public_key();

    // Server reads one packet
    let server_clone = server.clone();
    let server_rx = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), server_clone.read_from())
            .await
            .expect("server receive timed out")
            .expect("server read_from error")
    });

    // Wait for path discovery to complete, then send
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.write_to(b"hello from client", &server_pub).await
        .expect("write_to failed");

    let pkt = server_rx.await.expect("server reader panicked");
    assert_eq!(&pkt.payload, b"hello from client", "payload mismatch");
    assert_eq!(pkt.from, client_pub, "source key mismatch");

    // Reverse: server → client
    let client_clone = client.clone();
    let client_rx = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), client_clone.read_from())
            .await
            .expect("client receive timed out")
            .expect("client read_from error")
    });

    server.write_to(b"hello from server", &client_pub).await
        .expect("write_to server→client failed");

    let pkt2 = client_rx.await.expect("client reader panicked");
    assert_eq!(&pkt2.payload, b"hello from server");
    assert_eq!(pkt2.from, server_pub);
}

/// Public key is stable 32-byte ed25519 verifying key.
#[tokio::test]
async fn test_public_key_is_32_bytes() {
    let node = make_node();
    let key = node.public_key();
    assert_eq!(key.len(), 32);
    assert_eq!(node.public_key(), key);
}

/// MTU is within IPv6-compatible bounds.
#[tokio::test]
async fn test_mtu_reasonable() {
    let node = make_node();
    let mtu = node.mtu();
    assert!(mtu >= 1280, "MTU below IPv6 minimum: {mtu}");
    assert!(mtu <= 65535, "MTU unreasonably large: {mtu}");
}

/// Multiple nodes can be created and all have distinct public keys.
#[tokio::test]
async fn test_distinct_public_keys() {
    let a = make_node();
    let b = make_node();
    let c = make_node();
    assert_ne!(a.public_key(), b.public_key());
    assert_ne!(b.public_key(), c.public_key());
    assert_ne!(a.public_key(), c.public_key());
}

/// Connect to a live yggdrasil-go node if `YGG_TEST_PEER` is set.
///
/// Uses yggdrasil-go's TCP peer protocol — requires the full yggdrasil
/// version metadata handshake (not the simple ironwood key exchange).
/// Run:
/// ```text
/// YGG_TEST_PEER=tcp://ygg.mkg20001.io:80 cargo test live_peer -- --nocapture
/// ```
#[tokio::test]
async fn live_peer() {
    let peer_uri = match std::env::var("YGG_TEST_PEER") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Skipped: set YGG_TEST_PEER=tcp://host:port to enable");
            return;
        }
    };

    let node = make_node();
    eprintln!("Our key: {}", hex::encode(node.public_key()));

    let addr = peer_uri.strip_prefix("tcp://").unwrap_or(&peer_uri);
    let stream = TcpStream::connect(addr).await
        .expect("TCP connect to live peer");

    let node_clone = node.clone();
    tokio::spawn(async move {
        // NOTE: yggdrasil-go expects the yggdrasil version metadata handshake
        // before the Ironwood key exchange.  For a full live test, use
        // yggdrasil-rs which implements the complete handshake in core/link.rs.
        transport::handle_stream(&node_clone, stream, 0).await.unwrap_or(());
    });

    tokio::time::sleep(Duration::from_secs(4)).await;

    let stats = node.get_peer_stats();
    eprintln!("Peer count after connect: {}", stats.len());
    for p in &stats {
        eprintln!("  peer: {} rx={} tx={} latency={:?}",
            hex::encode(&p.key[..8]), p.rx_bytes, p.tx_bytes, p.latency);
    }
}
