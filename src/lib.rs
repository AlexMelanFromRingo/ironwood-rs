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
//! ## Packet Formats
//!
//! ### ANNOUNCE (type 4)
//!
//! ```text
//! ┌──────────┬──────────┬──────────┬───────────────┬──────────────┐
//! │ root_key │ root_seq │  parent  │  peer entries │  signature   │
//! │ (32 B)   │ (uvarint)│ (32 B)   │  (repeated)   │  (64 B)      │
//! └──────────┴──────────┴──────────┴───────────────┴──────────────┘
//! ```
//!
//! Each peer entry: `[pubkey (32B)] [port (uvarint)] [latency (uvarint)]`
//!
//! ### BLOOM_FILTER (type 5)
//!
//! ```text
//! ┌─────────┬──────────┬──────────────────────────┐
//! │ flags0  │ flags1   │  compressed bitset data   │
//! │ (16 B)  │ (16 B)   │  (variable)               │
//! └─────────┴──────────┴──────────────────────────┘
//! ```
//!
//! Compression: flags0[bit i] = 1 means word i of the filter is all-zero (skip).
//! flags1[bit i] = 1 means word i is all-ones (skip). The full filter is 1024 bytes
//! (8192 bits = 128 u64 words). 8 hashes per element.
//! Hash function: murmur3 x64 128-bit, called twice (on `data` and `data+[0x01]`).
//! Location formula: `h[i%2] + i * h[2 + (((i + (i%2)) % 4) / 2)]`
//!
//! ### PATH_LOOKUP (type 6)
//!
//! ```text
//! ┌─────────────────┬─────────────────┬──────────┬──────────┐
//! │  dest_key (32B) │ source_key (32B)│ dest_x   │ source_x │
//! │                 │                 │ (uvarint) │ (uvarint)│
//! └─────────────────┴─────────────────┴──────────┴──────────┘
//! ```
//!
//! dest_x and source_x are XOR-hashed tree coordinates for greedy routing.
//!
//! ### TRAFFIC (type 9)
//!
//! ```text
//! ┌──────────────────────────┬──────────┬──────────┬───────────┬───────────┬─────────┐
//! │  path (zero-term uvarints)│ from(path)│source(32B)│ dest(32B) │watermark  │ payload │
//! └──────────────────────────┴──────────┴──────────┴───────────┴───────────┴─────────┘
//! ```
//!
//! Path is a sequence of uvarint peer port numbers, terminated by a zero.
//!
//! ### Session Init/Ack (inside TRAFFIC payload)
//!
//! ```text
//! ┌──────┬─────────────────┬───────────┬─────────────┬───────────────┬──────────┬─────────┐
//! │ type │ box_pub (32 B)  │ encrypted │  ed_sig     │ current (32B) │ next(32B)│ key_seq │
//! │ (1B) │                 │ body      │  (64 B)     │               │          │ (8B LE) │
//! └──────┴─────────────────┴───────────┴─────────────┴───────────────┴──────────┴─────────┘
//! ```
//!
//! Total: 193 bytes. The encrypted body contains: `[current_pub (32B)] [next_pub (32B)] [seq (8B)] [key_seq (8B)]`
//!
//! ## Session Encryption Protocol
//!
//! Sessions use a double-ratchet with three key slots per direction:
//!
//! ```text
//! Each node maintains:
//!   recv_pub/priv  — previous send key, now used for receiving
//!   send_pub/priv  — current send key
//!   next_pub/priv  — next send key (pre-generated)
//!
//! On receiving Init/Ack (_handleUpdate in Go):
//!   recv ← send          (old send becomes recv)
//!   send ← next          (pre-generated next becomes current)
//!   next ← new_random()  (generate fresh next key)
//!   local_key_seq += 1
//!   remote_key_seq = init.key_seq
//! ```
//!
//! Key selection for decryption (4 cases from Go source):
//! ```text
//! fromCurrent && toRecv  → DH(remote.current, local.recv_priv)
//! fromNext    && toSend  → DH(remote.next,    local.send_priv)   [key rotation]
//! fromNext    && toRecv  → DH(remote.next,    local.recv_priv)   [simultaneous init]
//! else                   → sendInit() and drop packet
//! ```
//!
//! ## Spanning Tree Algorithm
//!
//! The spanning tree self-organizes using these rules:
//!
//! 1. The node with the numerically lowest public key becomes root
//! 2. Each non-root node selects a parent that minimizes `cost(root_distance × latency)`
//! 3. Announcements are propagated to all peers with ed25519 signatures
//! 4. Signature chains allow any node to verify the full path to root
//! 5. Tree info expires after 2 minutes without refresh
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

#![allow(dead_code)]

pub mod packet;
pub mod spanning_tree;
pub mod bloom;
pub mod pathfinder;
pub mod session;
pub mod router;

// Re-export the main public API
pub use router::PacketConn;
