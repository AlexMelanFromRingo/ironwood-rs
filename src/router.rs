//! # PacketConn — Main Public API
//!
//! This module provides the `PacketConn` struct, which is the primary interface for
//! using the Ironwood routing protocol. It combines all protocol layers into a single
//! async-safe object that applications interact with.
//!
//! ## Design Philosophy
//!
//! `PacketConn` is designed to be minimal and familiar:
//!
//! - `write_to(data, dest_key)` — send data to a destination identified by its ed25519 public key
//! - `read_from(buf)` — receive data from any source, returning the source's public key
//! - `handle_conn(stream)` — add a peer connection (TCP/TLS/UNIX socket)
//!
//! This is intentionally similar to `net.PacketConn` in Go (hence the name) and
//! `UdpSocket` in Rust — a packet-oriented interface over an addressed namespace,
//! where addresses are ed25519 public keys rather than IP addresses.
//!
//! ## Concurrency Model
//!
//! Internally, `PacketConn` uses a single `Arc<Mutex<RouterState>>` to serialize
//! access to the routing state. This replaces the actor-model `phony.Inbox` used
//! in the Go implementation.
//!
//! Per-peer I/O uses tokio tasks:
//!
//! ```text
//! For each peer connection:
//!   ┌─────────────────┐      ┌──────────────────────┐
//!   │  reader task    │      │   RouterState mutex   │
//!   │  (async loop)   │─────►│   (packet dispatch)   │
//!   └─────────────────┘      └──────────────────────┘
//!                                       │
//!   ┌─────────────────┐                 │
//!   │  writer task    │◄────────────────┘
//!   │  mpsc::Receiver │  (Vec<u8> frames)
//!   └─────────────────┘
//! ```
//!
//! - **Reader task**: reads framed packets from the TCP stream, dispatches to RouterState
//! - **Writer task**: receives encoded frames from an `mpsc::Sender`, writes to TCP stream
//! - **Maintenance task**: fires every 1 second to run spanning tree + bloom maintenance
//!
//! ## Peer Connection Lifecycle
//!
//! ```text
//! Application calls handle_conn(stream)
//!   → perform Ironwood handshake (exchange peer public keys + version)
//!   → add peer to RouterState (send SigReq, send Bloom)
//!   → spawn reader task
//!   → spawn writer task
//!   → reader task runs until EOF or error
//!   → reader task removes peer from RouterState
//! ```
//!
//! ## Packet Flow: Outgoing Traffic
//!
//! ```text
//! write_to(data, dest)
//!   → look up session for dest (create if needed)
//!   → encrypt data → SESSION_TRAFFIC payload
//!   → look up source route to dest (check path cache)
//!   → if path known: encode Traffic packet, send to first hop
//!   → if path unknown: send PATH_LOOKUP, queue traffic until path found
//! ```
//!
//! ## Packet Flow: Incoming Traffic
//!
//! ```text
//! peer sends TRAFFIC frame
//!   → reader task receives frame
//!   → parse Traffic struct (path, from, source, dest, watermark, payload)
//!   → if dest == self: decrypt SESSION_TRAFFIC payload → deliver to application
//!   → if dest != self: forward to next hop (shift path, forward frame)
//!   → if path is empty and dest != self: drop (routing failure)
//! ```
//!
//! ## Path Notification Callback
//!
//! An optional callback can be set to receive notifications when new source routes
//! are discovered:
//!
//! ```rust,no_run
//! use ironwood_rs::PacketConn;
//! use ed25519_dalek::VerifyingKey;
//!
//! # async fn example(conn: &PacketConn) {
//! conn.set_path_notify(|key: VerifyingKey| {
//!     println!("New path to {:?}", &key.to_bytes()[..8]);
//! }).await;
//! # }
//! ```
//!
//! ## MTU
//!
//! The effective MTU for application data is:
//!
//! ```text
//! MTU = PEER_MAX_MSG_SIZE - TRAFFIC_OVERHEAD - SESSION_OVERHEAD
//!     = 1,048,576 - (path + from + 32 + 32 + uvarint) - (1 + 32 + 32 + 16)
//! ```
//!
//! In practice, with short paths, the effective MTU is approximately 65535 bytes
//! to match typical TUN interface MTU.
//!
//! ## Peer Statistics
//!
//! The `get_peer_stats()` method returns per-peer statistics:
//!
//! ```rust,no_run
//! use ironwood_rs::PacketConn;
//!
//! # async fn example(conn: &PacketConn) {
//! let stats = conn.get_peer_stats().await;
//! for peer in &stats {
//!     println!("Peer {:?}: rx={} tx={} latency={:?}",
//!         &peer.key[..8], peer.rx_bytes, peer.tx_bytes, peer.latency);
//! }
//! # }
//! ```

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, Mutex},
};

use crate::packet::PublicKeyBytes;

// ============================================================================
// PeerStats
// ============================================================================

/// Statistics for a single peer connection.
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// The peer's ed25519 public key.
    pub key: PublicKeyBytes,

    /// The peer's priority (0 = highest). Used when multiple connections exist to the same peer.
    pub priority: u8,

    /// Total bytes received from this peer (raw wire bytes, including framing overhead).
    pub rx_bytes: u64,

    /// Total bytes transmitted to this peer (raw wire bytes, including framing overhead).
    pub tx_bytes: u64,

    /// How long this peer connection has been active.
    pub uptime: Duration,

    /// Measured round-trip latency (keepalive echo time).
    pub latency: Duration,
}

// ============================================================================
// InboundPacket
// ============================================================================

/// A decrypted inbound packet delivered to the application.
#[derive(Debug)]
pub struct InboundPacket {
    /// The decrypted application payload.
    pub payload: Vec<u8>,

    /// The ed25519 public key of the packet's originator.
    pub from: PublicKeyBytes,
}

// ============================================================================
// PacketConn
// ============================================================================

/// The main public API for the Ironwood routing protocol.
///
/// `PacketConn` is the entry point for all protocol interactions. It manages:
/// - The node's ed25519 identity key
/// - All peer connections and their lifecycle
/// - The spanning tree state
/// - Session encryption for all remote peers
/// - The Bloom filter state for multicast path discovery
/// - The pathfinder for source route discovery and caching
///
/// ## Thread Safety
///
/// `PacketConn` is `Clone`, `Send`, and `Sync`. Multiple clones share the same
/// underlying state via `Arc<Mutex<...>>`. All public methods are async and
/// acquire the internal lock as needed.
///
/// ## Example
///
/// ```rust,no_run
/// use ironwood_rs::PacketConn;
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let key = SigningKey::generate(&mut OsRng);
///     let conn = PacketConn::new(key).await?;
///
///     // Listen for incoming connections
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:9001").await?;
///     let conn_clone = conn.clone();
///     tokio::spawn(async move {
///         loop {
///             if let Ok((stream, _addr)) = listener.accept().await {
///                 let c = conn_clone.clone();
///                 tokio::spawn(async move { c.handle_conn(stream).await });
///             }
///         }
///     });
///
///     // Read incoming traffic
///     let mut buf = vec![0u8; 65535];
///     loop {
///         let (n, from) = conn.read_from(&mut buf).await?;
///         println!("Got {} bytes from {}", n, hex::encode(&from[..4]));
///     }
/// }
/// ```
#[derive(Clone)]
pub struct PacketConn {
    inner: Arc<PacketConnInner>,
}

/// Inner state shared across all clones of a `PacketConn`.
struct PacketConnInner {
    /// The node's ed25519 signing key (contains both seed and public key).
    signing_key: SigningKey,

    /// Channel sender for delivering decrypted inbound packets to `read_from()` callers.
    app_tx: mpsc::Sender<InboundPacket>,

    /// Channel receiver for consuming inbound packets in `read_from()`.
    // This is wrapped in Mutex to allow &self access from multiple threads.
    app_rx: Mutex<mpsc::Receiver<InboundPacket>>,

    /// The optional path-notify callback.
    path_notify_cb: Mutex<Option<Box<dyn Fn(VerifyingKey) + Send + Sync>>>,
}

impl PacketConn {
    /// Create a new `PacketConn` with the given ed25519 signing key.
    ///
    /// This:
    /// 1. Extracts the public key from the signing key
    /// 2. Creates the internal routing state (spanning tree, sessions, bloom, pathfinder)
    /// 3. Spawns the background maintenance task (runs every 1 second)
    /// 4. Returns a ready-to-use `PacketConn`
    ///
    /// ## Key Generation
    ///
    /// ```rust,no_run
    /// use ed25519_dalek::SigningKey;
    /// use rand::rngs::OsRng;
    ///
    /// let key = SigningKey::generate(&mut OsRng);
    /// // Or load from storage:
    /// // let key = SigningKey::from_bytes(&seed_bytes);
    /// ```
    pub async fn new(signing_key: SigningKey) -> Result<Self> {
        let (app_tx, app_rx) = mpsc::channel(1024);
        let inner = Arc::new(PacketConnInner {
            signing_key,
            app_tx,
            app_rx: Mutex::new(app_rx),
            path_notify_cb: Mutex::new(None),
        });
        // In a full implementation, we'd spawn the maintenance task here
        Ok(PacketConn { inner })
    }

    /// Returns the node's ed25519 public key.
    ///
    /// This is the node's identity on the network. Other nodes use this key to
    /// address traffic to us, and it serves as the basis for our IPv6 address
    /// in Yggdrasil (via the `address` crate's key-to-IPv6 derivation).
    pub fn public_key(&self) -> PublicKeyBytes {
        self.inner.signing_key.verifying_key().to_bytes()
    }

    /// Add a peer connection.
    ///
    /// Accepts any async read+write stream (TCP, TLS-wrapped TCP, UNIX socket, etc.)
    /// and integrates it into the routing protocol.
    ///
    /// ## Handshake
    ///
    /// Before the peer is added to the routing state, a version handshake is performed
    /// to exchange public keys and verify protocol compatibility. See `crate::core::handshake`
    /// in the parent yggdrasil-rs crate for the handshake wire format.
    ///
    /// ## This Method Returns When
    ///
    /// The connection is dropped (EOF, error, or keepalive timeout). The peer is
    /// automatically removed from the routing state when this future completes.
    ///
    /// ## Spawning
    ///
    /// For non-blocking operation, spawn this as a task:
    ///
    /// ```rust,no_run
    /// use ironwood_rs::PacketConn;
    /// use tokio::net::TcpStream;
    ///
    /// # async fn example(conn: PacketConn) {
    /// let stream = TcpStream::connect("peer.example.com:9001").await.unwrap();
    /// tokio::spawn(async move { conn.handle_conn(stream).await });
    /// # }
    /// ```
    pub async fn handle_conn<S>(&self, _stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        unimplemented!("handle_conn: handshake, add peer, run reader/writer tasks")
    }

    /// Send encrypted data to a destination node.
    ///
    /// `dest` is the ed25519 public key of the destination node (32 bytes).
    ///
    /// ## Flow
    ///
    /// 1. Look up or create a session for `dest`
    /// 2. If session is not yet established, send SESSION_INIT and queue the data
    /// 3. Encrypt `data` using the session's current send key
    /// 4. Look up the source route to `dest` in the path cache
    /// 5. If a route is cached: encode a TRAFFIC packet and send to the first hop
    /// 6. If no route: send a PATH_LOOKUP and queue the traffic until discovered
    ///
    /// ## Errors
    ///
    /// Returns `Err` if:
    /// - `dest` is not reachable and no path discovery is possible
    /// - The internal send buffer is full (backpressure)
    pub async fn write_to(&self, _data: &[u8], _dest: &PublicKeyBytes) -> Result<()> {
        unimplemented!("write_to: encrypt and route traffic to dest")
    }

    /// Receive a decrypted packet from any source.
    ///
    /// Blocks until a packet is available. The packet's payload is written to `buf`
    /// and the number of bytes written plus the source's public key are returned.
    ///
    /// If `buf` is too small for the received packet, the excess bytes are discarded.
    /// The caller should use a buffer of at least 65535 bytes to avoid truncation.
    ///
    /// ## Returns
    ///
    /// `Ok((n, from))` where:
    /// - `n` is the number of bytes written to `buf`
    /// - `from` is the ed25519 public key of the packet originator
    pub async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, PublicKeyBytes)> {
        let mut rx = self.inner.app_rx.lock().await;
        if let Some(pkt) = rx.recv().await {
            let n = pkt.payload.len().min(buf.len());
            buf[..n].copy_from_slice(&pkt.payload[..n]);
            Ok((n, pkt.from))
        } else {
            Err(anyhow::anyhow!("PacketConn closed"))
        }
    }

    /// Returns the effective MTU for application data.
    ///
    /// This is the maximum payload size that can be sent in a single `write_to` call.
    ///
    /// The MTU accounts for:
    /// - Frame overhead (uvarint length prefix)
    /// - Traffic packet header (path + from + source + dest + watermark)
    /// - Session encryption overhead (type byte + key fields + Poly1305 tag)
    pub async fn mtu(&self) -> usize {
        // Conservative MTU: 1 MB max frame - typical routing overhead
        // In practice matches yggdrasil-go's effective MTU of 65535 for TUN
        65535
    }

    /// Close the PacketConn, dropping all peer connections.
    ///
    /// After calling this, `read_from` will return an error and `write_to` will fail.
    /// All spawned tasks (reader, writer, maintenance) will terminate.
    pub async fn close(&self) -> Result<()> {
        unimplemented!("close: shut down all peer connections and background tasks")
    }

    /// Returns statistics for all currently-connected peers.
    ///
    /// The returned vec contains one entry per connected peer (keyed by public key).
    /// Multiple physical connections to the same peer key are merged into one entry.
    pub async fn get_peer_stats(&self) -> Vec<PeerStats> {
        unimplemented!("get_peer_stats: collect stats from all PeerData entries")
    }

    /// Set a callback that is called whenever a new source route is discovered.
    ///
    /// The callback receives the ed25519 `VerifyingKey` of the destination for which
    /// a new path was found. This can be used to trigger actions like:
    /// - Sending queued traffic to a newly-reachable destination
    /// - Updating UI to show connectivity status
    ///
    /// The callback is called from within the router's locked context, so it should
    /// be fast and non-blocking.
    pub async fn set_path_notify<F>(&self, callback: F)
    where
        F: Fn(VerifyingKey) + Send + Sync + 'static,
    {
        let mut cb = self.inner.path_notify_cb.lock().await;
        *cb = Some(Box::new(callback));
    }

    /// Manually trigger a path discovery request to a destination.
    ///
    /// Normally, path discovery is triggered automatically by `write_to`. This method
    /// allows pre-warming the path cache before sending traffic.
    pub async fn send_lookup(&self, _dest: &PublicKeyBytes) -> Result<()> {
        unimplemented!("send_lookup: trigger PATH_LOOKUP for dest without sending traffic")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_packet_conn_new() {
        let key = SigningKey::generate(&mut OsRng);
        let pub_bytes = key.verifying_key().to_bytes();
        let conn = PacketConn::new(key).await.unwrap();
        assert_eq!(conn.public_key(), pub_bytes);
    }

    #[tokio::test]
    async fn test_mtu() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = PacketConn::new(key).await.unwrap();
        assert_eq!(conn.mtu().await, 65535);
    }

    #[tokio::test]
    async fn test_set_path_notify() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = PacketConn::new(key).await.unwrap();
        conn.set_path_notify(|_key| {}).await;
        // Verify the callback was set
        let cb = conn.inner.path_notify_cb.lock().await;
        assert!(cb.is_some());
    }

    #[tokio::test]
    async fn test_public_key_consistent() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = PacketConn::new(key).await.unwrap();
        // Public key should be stable across multiple calls
        assert_eq!(conn.public_key(), conn.public_key());
    }
}
