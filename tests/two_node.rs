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

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use ironwood_rs::{transport, PacketConn};
use rand::rngs::OsRng;
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn make_node_with_key(key: &SigningKey) -> PacketConn {
    PacketConn::new(key.clone())
}

fn make_node() -> PacketConn {
    PacketConn::new(make_signing_key())
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

    // Wait for the Ironwood handshake AND the first maintenance tick
    // (SigReq/SigRes + ANNOUNCE + BLOOM_FILTER + bloom_do_maintenance).
    // The maintenance tick fires every 1s, so we must wait >1s for
    // bloom_fix_on_tree to set on_tree=true and path discovery to work.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    (server, client)
}

/// Warm up path discovery: retry write_to until a packet is received.
///
/// PathLookup is only forwarded once bloom_do_maintenance has set on_tree=true,
/// which requires at least one maintenance tick (1s interval). This helper
/// retries every 500ms so subsequent ticks can complete the session handshake.
async fn warmup(
    sender: &PacketConn,
    receiver: &PacketConn,
    dst: &[u8; 32],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let _ = sender.write_to(b"warmup", dst).await;
        let recv_clone = receiver.clone();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let probe = Duration::from_millis(800).min(remaining);
        if tokio::time::timeout(probe, recv_clone.read_from()).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two nodes connect and exchange encrypted traffic in both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_two_nodes_exchange_traffic() {
    let (server, client) = connected_pair().await;

    let server_pub = server.public_key();
    let client_pub = client.public_key();

    // Warm up path discovery in both directions before the real assertions.
    assert!(
        warmup(&client, &server, &server_pub, Duration::from_secs(10)).await,
        "client→server path never established"
    );
    assert!(
        warmup(&server, &client, &client_pub, Duration::from_secs(10)).await,
        "server→client path never established"
    );

    // client → server
    let server_clone = server.clone();
    let server_rx = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), server_clone.read_from())
            .await
            .expect("server receive timed out")
            .expect("server read_from error")
    });
    client.write_to(b"hello from client", &server_pub).await
        .expect("write_to failed");
    let pkt = server_rx.await.expect("server reader panicked");
    assert_eq!(&pkt.payload, b"hello from client", "payload mismatch");
    assert_eq!(pkt.from, client_pub, "source key mismatch");

    // server → client
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
/// Uses the yggdrasil-go wire-compatible version-metadata handshake
/// (`handle_yggdrasil_stream`). Run:
/// ```text
/// YGG_TEST_PEER=tcp://ygg.mkg20001.io:80 cargo test live_peer -- --nocapture --ignored
/// YGG_TEST_PEER=tls://ygg.mkg20001.io:443 cargo test live_peer -- --nocapture --ignored
/// ```
#[tokio::test]
#[ignore = "requires YGG_TEST_PEER env var and network access"]
async fn live_peer() {
    let peer_uri = match std::env::var("YGG_TEST_PEER") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Skipped: set YGG_TEST_PEER=tcp://host:port to enable");
            return;
        }
    };

    let signing_key = make_signing_key();
    let node = make_node_with_key(&signing_key);
    eprintln!("Our key: {}", hex::encode(node.public_key()));

    let node_clone = node.clone();
    let sk_clone = signing_key.clone();

    // Dial and handshake — TCP or TLS depending on URI scheme
    if peer_uri.starts_with("tls://") {
        let tls = transport::dial_tls(&peer_uri).await
            .expect("TLS connect to live peer");
        tokio::spawn(async move {
            transport::handle_yggdrasil_stream(&node_clone, tls, &sk_clone, b"", 0)
                .await.unwrap_or(());
        });
    } else {
        // Strip scheme and query string: "tcp://host:port?key=..." → "host:port"
        let without_scheme = peer_uri.strip_prefix("tcp://").unwrap_or(&peer_uri);
        let addr = without_scheme.split('?').next().unwrap_or(without_scheme);
        let tcp = TcpStream::connect(addr).await
            .expect("TCP connect to live peer");
        tokio::spawn(async move {
            transport::handle_yggdrasil_stream(&node_clone, tcp, &sk_clone, b"", 0)
                .await.unwrap_or(());
        });
    };

    // Wait for spanning tree to stabilise
    tokio::time::sleep(Duration::from_secs(5)).await;

    let stats = node.get_peer_stats();
    assert!(!stats.is_empty(),
        "No peers after 5s — handshake may have failed. Check that {peer_uri} is reachable.");
    eprintln!("Connected to {peer_uri}. Peers: {}", stats.len());
    for p in &stats {
        eprintln!("  peer: {} rx={} tx={} latency={:?}",
            hex::encode(&p.key[..8]), p.rx_bytes, p.tx_bytes, p.latency);
    }
}
