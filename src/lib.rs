//! # ironwood-rs
//!
//! A Rust implementation of the [Ironwood](https://github.com/Arceliar/ironwood) routing protocol,
//! which powers the [Yggdrasil](https://yggdrasil-network.github.io/) mesh network.
//!
//! This crate provides a fully wire-compatible implementation of the Ironwood protocol,
//! verified against `yggdrasil-go v0.5.13` (with successful end-to-end traffic exchange).
//!
//! ## Protocol Overview
//!
//! Ironwood is a self-organizing mesh routing protocol that combines:
//!
//! - **Spanning Tree Routing** — A cryptographically authenticated spanning tree
//!   provides greedy routing with logarithmic stretch. Each node selects a parent
//!   based on minimum-latency root distance.
//! - **Source Routing** — Traffic uses pre-discovered paths encoded directly in
//!   packets (zero-terminated uvarint sequences), bypassing table lookups at each hop.
//! - **Bloom Filter Multicast** — A 1024-byte (8192-bit) Bloom filter propagates
//!   through the spanning tree, allowing efficient multicast for path discovery.
//! - **Session Encryption** — NaCl box (X25519 + XSalsa20-Poly1305) with
//!   double-ratchet key rotation. Sessions use ed25519 keys for authentication
//!   and derive X25519 keys for encryption.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                   Application Layer                  │
//! │              (TUN adapter / user code)               │
//! └──────────────────────┬──────────────────────────────┘
//!                        │  PacketConn::read_from / write_to
//! ┌──────────────────────▼──────────────────────────────┐
//! │              Session Encryption Layer                │
//! │   ed25519 auth + X25519/XSalsa20-Poly1305 sessions  │
//! │         Double-ratchet forward secrecy               │
//! └──────────────────────┬──────────────────────────────┘
//!                        │  plaintext packets
//! ┌──────────────────────▼──────────────────────────────┐
//! │                  Routing Layer                       │
//! │  ┌─────────────────┐  ┌──────────────────────────┐  │
//! │  │  Spanning Tree  │  │   Source Routing (PF)    │  │
//! │  │  (RouterState)  │  │  PathLookup/Notify/Broken│  │
//! │  └────────┬────────┘  └──────────┬───────────────┘  │
//! │           │                      │                   │
//! │  ┌────────▼──────────────────────▼───────────────┐  │
//! │  │         Bloom Filter Multicast                │  │
//! │  │    1024-byte filter, murmur3 x64 128-bit      │  │
//! │  └───────────────────────────────────────────────┘  │
//! └──────────────────────┬──────────────────────────────┘
//!                        │  wire frames
//! ┌──────────────────────▼──────────────────────────────┐
//! │              Wire Encoding Layer                     │
//! │   uvarint length-prefix frames, 10 packet types     │
//! └──────────────────────┬──────────────────────────────┘
//!                        │  TCP / TLS / UNIX sockets
//! ┌──────────────────────▼──────────────────────────────┐
//! │                  Peer Connections                    │
//! │  (tokio async tasks: reader + mpsc writer per peer)  │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Wire Format
//!
//! Each peer connection uses a simple framing protocol:
//!
//! ```text
//! ┌─────────────────┬──────────────────────────┐
//! │  length (uvarint)│      body (N bytes)       │
//! └─────────────────┴──────────────────────────┘
//! ```
//!
//! The first byte of the body is the packet type:
//!
//! | Value | Name           | Direction    | Description                              |
//! |-------|----------------|--------------|------------------------------------------|
//! | 0     | DUMMY          | Any          | Padding / keepalive placeholder          |
//! | 1     | KEEP_ALIVE     | Any          | TCP keepalive at protocol level          |
//! | 2     | SIG_REQ        | Any          | Spanning tree signature request          |
//! | 3     | SIG_RES        | Any          | Spanning tree signature response         |
//! | 4     | ANNOUNCE       | Any          | Spanning tree topology announcement      |
//! | 5     | BLOOM_FILTER   | Any          | Bloom filter update                      |
//! | 6     | PATH_LOOKUP    | Flood/tree   | Source route path discovery request      |
//! | 7     | PATH_NOTIFY    | Unicast      | Source route path response               |
//! | 8     | PATH_BROKEN    | Unicast      | Source route path failure notification   |
//! | 9     | TRAFFIC        | Unicast      | Encrypted session traffic                |
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ironwood_rs::PacketConn;
//! use ed25519_dalek::SigningKey;
//! use rand::rngs::OsRng;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Generate or load an ed25519 identity key
//!     let signing_key = SigningKey::generate(&mut OsRng);
//!
//!     // Create a PacketConn — the main API
//!     let conn = PacketConn::new(signing_key).await?;
//!
//!     // Connect to peers
//!     let stream = tokio::net::TcpStream::connect("peer.example.com:9001").await?;
//!     conn.handle_conn(stream).await?;
//!
//!     // Send encrypted traffic to a destination public key
//!     let dest = [0u8; 32]; // target's ed25519 public key
//!     conn.write_to(&[1, 2, 3, 4], &dest).await?;
//!
//!     // Receive decrypted traffic
//!     let mut buf = vec![0u8; 65535];
//!     let (n, from) = conn.read_from(&mut buf).await?;
//!     println!("Received {} bytes from {:?}", n, &from[..8]);
//!
//!     Ok(())
//! }
//! ```

pub mod address;
pub mod core;
pub mod transport;

// Re-export the main public API
pub use core::{BloomFilter, BoxReader, BoxWriter, InboundPacket, PacketConn, PeerStats, PublicKeyBytes};
