//! # Wire Packet Types and Encoding
//!
//! This module defines the complete Ironwood wire protocol: the 10 packet types,
//! the uvarint frame encoding, and all packet structs with encode/decode routines.
//!
//! ## Frame Format
//!
//! Every packet sent over a TCP/TLS/UNIX peer connection is wrapped in a length-prefixed frame:
//!
//! ```text
//! ┌────────────────────┬──────────────────────────────────────────┐
//! │  length (uvarint)  │           body (length bytes)            │
//! │  (1–10 bytes)      │  byte[0]: packet type, rest: payload     │
//! └────────────────────┴──────────────────────────────────────────┘
//! ```
//!
//! The `length` field encodes the total number of bytes in the body (including the type byte).
//! Uvarint encoding uses 7 bits per byte, with the high bit set if more bytes follow:
//!
//! ```text
//! value < 128       → 1 byte
//! value < 16384     → 2 bytes
//! value < 2097152   → 3 bytes
//! ...up to 10 bytes for u64::MAX
//! ```
//!
//! The maximum allowed frame body is 1 MB (1,048,576 bytes). Frames exceeding this
//! cause the connection to be dropped.
//!
//! ## Packet Type Constants
//!
//! | Byte | Constant               | Description                              |
//! |------|------------------------|------------------------------------------|
//! | 0    | `WIRE_DUMMY`           | Padding / placeholder, always ignored    |
//! | 1    | `WIRE_KEEP_ALIVE`      | Protocol-level keepalive (no payload)    |
//! | 2    | `WIRE_PROTO_SIG_REQ`   | Signature request for spanning tree join |
//! | 3    | `WIRE_PROTO_SIG_RES`   | Signature response (parent signs child)  |
//! | 4    | `WIRE_PROTO_ANNOUNCE`  | Full spanning tree announcement          |
//! | 5    | `WIRE_PROTO_BLOOM_FILTER` | Bloom filter multicast state update   |
//! | 6    | `WIRE_PROTO_PATH_LOOKUP`  | Path discovery flood request          |
//! | 7    | `WIRE_PROTO_PATH_NOTIFY`  | Unicast path discovery response       |
//! | 8    | `WIRE_PROTO_PATH_BROKEN`  | Notification that a path has failed   |
//! | 9    | `WIRE_TRAFFIC`            | Encrypted session traffic             |
//!
//! ## Path Encoding
//!
//! Many packet types contain a sequence of peer port numbers that represent a source
//! route through the tree. Paths are encoded as a sequence of uvarint values terminated
//! by a zero:
//!
//! ```text
//! port₁ (uvarint) | port₂ (uvarint) | ... | portₙ (uvarint) | 0x00
//! ```
//!
//! At each hop, the router reads the first port from the path, removes it, and forwards
//! the packet to the peer with that port number.
//!
//! ## Announce Packet (type 4)
//!
//! The ANNOUNCE packet carries a node's position in the spanning tree. It contains:
//!
//! - The announcing node's public key (32 bytes)
//! - Its parent's public key (32 bytes)
//! - A SigRes (signature response from the parent, proving the parent accepted this node)
//! - The node's own ed25519 signature over the SigRes material
//!
//! Signature material for both signatures covers: `node_key || parent_key || seq || nonce || port`
//!
//! When a node receives an ANNOUNCE, it:
//! 1. Verifies both signatures (node and parent)
//! 2. Records the node's tree position
//! 3. Forwards it to all other peers (except the one it came from)
//!
//! ## SigReq / SigRes Handshake
//!
//! To join the spanning tree under a parent, a child node:
//! 1. Sends a SigReq to the potential parent: `{seq, nonce}`
//! 2. The parent signs `node_key || parent_key || seq || nonce || port` and returns a SigRes
//! 3. The child uses the SigRes to build an Announce and broadcasts it
//!
//! The `seq` field is the parent's current sequence number (from its own RouterInfo).
//! The `nonce` is random per-request. The `port` is the peer port number on the parent's side.
//!
//! ## Traffic Packet (type 9)
//!
//! The TRAFFIC packet carries encrypted session data between two nodes:
//!
//! ```text
//! ┌──────────────────────────┬────────────────────┬──────────┬───────────┬──────────┬──────────────────┐
//! │ path (zero-term uvarints)│ from (zero-term)   │ src (32B)│ dest (32B)│ watermark│    payload       │
//! └──────────────────────────┴────────────────────┴──────────┴───────────┴──────────┴──────────────────┘
//! ```
//!
//! - `path`: the remaining hops to the destination (consumed/shifted at each router)
//! - `from`: the reverse path back to the source (accumulated at each hop for PATH_NOTIFY replies)
//! - `src`: the ed25519 public key of the originating node
//! - `dest`: the ed25519 public key of the destination node
//! - `watermark`: a monotonically increasing sequence number to reject replays
//! - `payload`: the encrypted session content (see [`crate::session`])

/// Dummy packet — always ignored. Used for padding or testing.
pub const WIRE_DUMMY: u8 = 0;

/// Protocol-level keepalive. No payload. Sent every second to detect dead connections.
pub const WIRE_KEEP_ALIVE: u8 = 1;

/// Spanning tree signature request. Sent by a child to its candidate parent.
/// Body: `seq (uvarint) || nonce (uvarint)`
pub const WIRE_PROTO_SIG_REQ: u8 = 2;

/// Spanning tree signature response. Sent by parent to child after signing a SigReq.
/// Body: `seq (uvarint) || nonce (uvarint) || port (uvarint) || parent_sig (64 bytes)`
pub const WIRE_PROTO_SIG_RES: u8 = 3;

/// Spanning tree announcement. Flooded to all peers.
/// Body: `node_key (32B) || parent_key (32B) || seq (uvarint) || nonce (uvarint) || port (uvarint) || parent_sig (64B) || node_sig (64B)`
pub const WIRE_PROTO_ANNOUNCE: u8 = 4;

/// Bloom filter state update for multicast path discovery.
/// Body: `flags0 (16B) || flags1 (16B) || compressed_words (variable)`
pub const WIRE_PROTO_BLOOM_FILTER: u8 = 5;

/// Path discovery request. Flooded through the tree using bloom filter routing.
/// Body: `source_key (32B) || dest_key (32B) || from_path (zero-term uvarints)`
pub const WIRE_PROTO_PATH_LOOKUP: u8 = 6;

/// Path discovery response. Sent unicast back to the requester.
/// Body: `path (zero-term) || watermark (uvarint) || source (32B) || dest (32B) || seq (uvarint) || path_info (zero-term) || sig (64B)`
pub const WIRE_PROTO_PATH_NOTIFY: u8 = 7;

/// Path failure notification. Sent when a previously-known path stops working.
/// Body: `path (zero-term) || watermark (uvarint) || source (32B) || dest (32B)`
pub const WIRE_PROTO_PATH_BROKEN: u8 = 8;

/// Encrypted session traffic. The main data-plane packet type.
/// Body: `path (zero-term) || from (zero-term) || source (32B) || dest (32B) || watermark (uvarint) || payload`
pub const WIRE_TRAFFIC: u8 = 9;

/// Maximum allowed body size for any single frame (1 MB).
pub const PEER_MAX_MSG_SIZE: usize = 1_048_576;

/// A peer port number identifying a specific connection in the spanning tree.
pub type PeerPort = u64;

/// An ed25519 public key identifying a node in the network.
pub type PublicKeyBytes = [u8; 32];

/// An ed25519 signature (64 bytes).
pub type SignatureBytes = [u8; 64];

// ============================================================================
// uvarint encoding
// ============================================================================

/// Encode a u64 as a uvarint, appending to `buf`.
///
/// Uvarint encoding uses 7 bits per byte. The high bit of each byte indicates
/// whether more bytes follow. Values < 128 are encoded as a single byte.
///
/// This is identical to Go's `binary.PutUvarint`.
pub fn put_uvarint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        if v < 0x80 {
            buf.push(v as u8);
            return;
        }
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
}

/// Decode a uvarint from the start of `data`.
///
/// Returns `Some((value, bytes_consumed))` or `None` if the input is truncated or
/// exceeds 10 bytes (which would overflow u64).
pub fn get_uvarint(data: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if i == 10 {
            return None; // overflow
        }
        if b < 0x80 {
            return Some((x | (b as u64) << s, i + 1));
        }
        x |= ((b & 0x7f) as u64) << s;
        s += 7;
    }
    None // truncated
}

/// Decode and consume a uvarint from the front of `data`, advancing the slice.
pub fn chop_uvarint(data: &mut &[u8]) -> Option<u64> {
    let (v, n) = get_uvarint(data)?;
    *data = &data[n..];
    Some(v)
}

/// Consume `len` bytes from the front of `data`, returning the slice.
pub fn chop_slice<'a>(data: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if data.len() < len {
        return None;
    }
    let s = &data[..len];
    *data = &data[len..];
    Some(s)
}

/// Returns the number of bytes required to encode `v` as a uvarint.
pub fn size_uvarint(mut v: u64) -> usize {
    let mut n = 1;
    while v >= 0x80 {
        v >>= 7;
        n += 1;
    }
    n
}

// ============================================================================
// Path encoding
// ============================================================================

/// Encode a path (sequence of port numbers) as zero-terminated uvarints.
pub fn put_path(buf: &mut Vec<u8>, path: &[PeerPort]) {
    for &p in path {
        put_uvarint(buf, p);
    }
    put_uvarint(buf, 0); // zero terminator
}

/// Returns the encoded byte size of a path.
pub fn size_path(path: &[PeerPort]) -> usize {
    let mut n = 0;
    for &p in path {
        n += size_uvarint(p);
    }
    n + size_uvarint(0) // terminator
}

/// Decode and consume a zero-terminated path from `data`.
pub fn chop_path(data: &mut &[u8]) -> Option<Vec<PeerPort>> {
    let mut path = Vec::new();
    loop {
        let v = chop_uvarint(data)?;
        if v == 0 {
            break;
        }
        path.push(v);
    }
    Some(path)
}

// ============================================================================
// Frame encoding
// ============================================================================

/// Encode a wire frame: `uvarint(1 + body.len()) || type_byte || body`.
pub fn encode_frame(type_byte: u8, body: &[u8]) -> Vec<u8> {
    let frame_len = 1 + body.len();
    let mut out = Vec::with_capacity(size_uvarint(frame_len as u64) + frame_len);
    put_uvarint(&mut out, frame_len as u64);
    out.push(type_byte);
    out.extend_from_slice(body);
    out
}

// ============================================================================
// SigReq
// ============================================================================

/// A signature request sent by a child node to a candidate parent.
///
/// The `seq` field must match the parent's current announcement sequence number.
/// The `nonce` is random and prevents replay attacks.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct SigReq {
    /// The sequence number from the parent's current RouterInfo.
    pub seq: u64,
    /// A random nonce chosen by the requesting child.
    pub nonce: u64,
}

impl SigReq {
    /// Returns the bytes that both the child and parent will sign.
    ///
    /// Format: `node_key (32B) || parent_key (32B) || seq (uvarint) || nonce (uvarint)`
    pub fn bytes_for_sig(&self, node: &PublicKeyBytes, parent: &PublicKeyBytes) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + 16);
        out.extend_from_slice(node);
        out.extend_from_slice(parent);
        put_uvarint(&mut out, self.seq);
        put_uvarint(&mut out, self.nonce);
        out
    }

    /// Returns the byte size of the encoded SigReq (without key material).
    pub fn size(&self) -> usize {
        size_uvarint(self.seq) + size_uvarint(self.nonce)
    }

    /// Encode the SigReq, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_uvarint(out, self.seq);
        put_uvarint(out, self.nonce);
    }

    /// Decode a complete SigReq from `data` (must consume all bytes).
    pub fn decode(data: &[u8]) -> Option<SigReq> {
        let mut d = data;
        let req = Self::chop(&mut d)?;
        if !d.is_empty() {
            return None;
        }
        Some(req)
    }

    /// Decode a SigReq from the front of `d`, advancing the slice.
    pub fn chop(d: &mut &[u8]) -> Option<SigReq> {
        let seq = chop_uvarint(d)?;
        let nonce = chop_uvarint(d)?;
        Some(SigReq { seq, nonce })
    }
}

// ============================================================================
// SigRes
// ============================================================================

/// A signature response sent by a parent to a child after agreeing to be its parent.
///
/// The `psig` is the parent's ed25519 signature over the bytes:
/// `node_key || parent_key || seq || nonce || port`
#[derive(Clone, Debug)]
pub struct SigRes {
    /// The original request this response answers.
    pub req: SigReq,
    /// The port number the child has on the parent (identifies the peer connection).
    pub port: PeerPort,
    /// The parent's ed25519 signature.
    pub psig: SignatureBytes,
}

impl SigRes {
    /// Returns the bytes that the parent signed.
    ///
    /// Format: `node_key (32B) || parent_key (32B) || seq (uvarint) || nonce (uvarint) || port (uvarint)`
    pub fn bytes_for_sig(&self, node: &PublicKeyBytes, parent: &PublicKeyBytes) -> Vec<u8> {
        let mut out = self.req.bytes_for_sig(node, parent);
        put_uvarint(&mut out, self.port);
        out
    }

    /// Returns the byte size of the encoded SigRes (without key material).
    pub fn size(&self) -> usize {
        self.req.size() + size_uvarint(self.port) + 64
    }

    /// Encode the SigRes, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.req.encode(out);
        put_uvarint(out, self.port);
        out.extend_from_slice(&self.psig);
    }

    /// Decode a SigRes from the front of `d`, advancing the slice.
    pub fn chop(d: &mut &[u8]) -> Option<SigRes> {
        let req = SigReq::chop(d)?;
        let port = chop_uvarint(d)?;
        let psig: SignatureBytes = chop_slice(d, 64)?.try_into().ok()?;
        Some(SigRes { req, port, psig })
    }

    /// Decode a complete SigRes from `data`.
    pub fn decode(data: &[u8]) -> Option<SigRes> {
        let mut d = data;
        let res = Self::chop(&mut d)?;
        if !d.is_empty() {
            return None;
        }
        Some(res)
    }
}

// ============================================================================
// Announce
// ============================================================================

/// A spanning tree announcement, flooded to all peers.
///
/// An Announce carries:
/// - The key and tree position of the announcing node
/// - The SigRes from its parent (proving the parent relationship)
/// - The node's own signature over the same material
///
/// Both `sig` and `res.psig` sign the same bytes, allowing any receiver to verify
/// the parent-child relationship without trusting either party alone.
#[derive(Clone, Debug)]
pub struct Announce {
    /// The public key of the announcing node.
    pub key: PublicKeyBytes,
    /// The public key of the announcing node's parent in the spanning tree.
    pub parent: PublicKeyBytes,
    /// The signature response received from the parent.
    pub res: SigRes,
    /// The announcing node's own signature over the same material as `res.psig`.
    pub sig: SignatureBytes,
}

impl Announce {
    /// Returns the encoded byte size of this announcement.
    pub fn size(&self) -> usize {
        32 + 32 + self.res.size() + 64
    }

    /// Encode the Announce, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.parent);
        self.res.encode(out);
        out.extend_from_slice(&self.sig);
    }

    /// Decode a complete Announce from `data`.
    pub fn decode(data: &[u8]) -> Option<Announce> {
        let mut d = data;
        let key: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let parent: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let res = SigRes::chop(&mut d)?;
        let sig: SignatureBytes = chop_slice(&mut d, 64)?.try_into().ok()?;
        if !d.is_empty() {
            return None;
        }
        Some(Announce { key, parent, res, sig })
    }
}

// ============================================================================
// Traffic
// ============================================================================

/// A source-routed traffic packet carrying an encrypted session payload.
///
/// The `path` field contains the remaining hops to the destination. Each router:
/// 1. Reads the first element of `path`
/// 2. Removes it (shifts path forward)
/// 3. Forwards the modified packet on the peer with that port number
///
/// The `from` field accumulates reverse-path hops as the packet travels, allowing
/// intermediate nodes to build a PATH_NOTIFY response.
///
/// The `payload` is a session-layer encrypted packet (see [`crate::session`]).
#[derive(Debug, Default)]
pub struct Traffic {
    /// Remaining forward path (zero-terminated uvarint port sequence).
    pub path: Vec<PeerPort>,
    /// Accumulated reverse path from source.
    pub from: Vec<PeerPort>,
    /// ed25519 public key of the traffic originator.
    pub source: PublicKeyBytes,
    /// ed25519 public key of the traffic destination.
    pub dest: PublicKeyBytes,
    /// Monotonically increasing sequence number for replay prevention.
    pub watermark: u64,
    /// Encrypted session payload (see [`crate::session`]).
    pub payload: Vec<u8>,
}

impl Traffic {
    /// Returns the encoded byte size of this packet.
    pub fn size(&self) -> usize {
        size_path(&self.path)
            + size_path(&self.from)
            + 32
            + 32
            + size_uvarint(self.watermark)
            + self.payload.len()
    }

    /// Encode this Traffic packet to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size());
        put_path(&mut out, &self.path);
        put_path(&mut out, &self.from);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        put_uvarint(&mut out, self.watermark);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode a complete Traffic packet from `data`.
    pub fn decode(data: &[u8]) -> Option<Traffic> {
        let mut d = data;
        let path = chop_path(&mut d)?;
        let from = chop_path(&mut d)?;
        let source: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let watermark = chop_uvarint(&mut d)?;
        let payload = d.to_vec();
        Some(Traffic { path, from, source, dest, watermark, payload })
    }
}

// ============================================================================
// PathLookup
// ============================================================================

/// A path discovery request, flooded through the spanning tree using bloom filter routing.
///
/// Sent by a node that wants to discover a source route to `dest`. The request
/// is flooded to all peers whose bloom filter indicates they may be on the path
/// to the destination.
///
/// The `from` path accumulates as the lookup is forwarded, so that when the
/// destination (or a node with a cached path to it) receives the lookup, it can
/// send a PATH_NOTIFY back along `from`.
#[derive(Clone, Debug)]
pub struct PathLookup {
    /// The ed25519 public key of the requesting node.
    pub source: PublicKeyBytes,
    /// The ed25519 public key of the desired destination.
    pub dest: PublicKeyBytes,
    /// Accumulated return path from the source to the current forwarding node.
    pub from: Vec<PeerPort>,
}

impl PathLookup {
    /// Returns the encoded byte size.
    pub fn size(&self) -> usize {
        32 + 32 + size_path(&self.from)
    }

    /// Encode the PathLookup, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        put_path(out, &self.from);
    }

    /// Decode a complete PathLookup from `data`.
    pub fn decode(data: &[u8]) -> Option<PathLookup> {
        let mut d = data;
        let source: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let from = chop_path(&mut d)?;
        if !d.is_empty() {
            return None;
        }
        Some(PathLookup { source, dest, from })
    }
}

// ============================================================================
// PathNotifyInfo
// ============================================================================

/// The inner signed payload of a PATH_NOTIFY packet.
///
/// The `path` is the source route from `dest` back to `source`, signed by the
/// destination node to prove it is authentic. The `seq` is a monotonically
/// increasing sequence number from the destination.
#[derive(Clone, Debug)]
pub struct PathNotifyInfo {
    /// Sequence number from the destination (monotonically increasing).
    pub seq: u64,
    /// The source route path from destination back to source.
    pub path: Vec<PeerPort>,
    /// ed25519 signature by the destination over `seq || path`.
    pub sig: SignatureBytes,
}

impl PathNotifyInfo {
    /// Returns the bytes that the destination signs.
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_uvarint(&mut out, self.seq);
        put_path(&mut out, &self.path);
        out
    }

    /// Returns the encoded byte size.
    pub fn size(&self) -> usize {
        size_uvarint(self.seq) + size_path(&self.path) + 64
    }

    /// Encode the PathNotifyInfo, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_uvarint(out, self.seq);
        put_path(out, &self.path);
        out.extend_from_slice(&self.sig);
    }

    /// Decode a PathNotifyInfo from the front of `d`, advancing the slice.
    pub fn chop(d: &mut &[u8]) -> Option<PathNotifyInfo> {
        let seq = chop_uvarint(d)?;
        let path = chop_path(d)?;
        let sig: SignatureBytes = chop_slice(d, 64)?.try_into().ok()?;
        Some(PathNotifyInfo { seq, path, sig })
    }

    /// Decode a complete PathNotifyInfo from `data`.
    pub fn decode(data: &[u8]) -> Option<PathNotifyInfo> {
        let mut d = data;
        let info = Self::chop(&mut d)?;
        if !d.is_empty() {
            return None;
        }
        Some(info)
    }
}

// ============================================================================
// PathNotify
// ============================================================================

/// A path discovery response sent unicast back to the requesting source.
///
/// Contains the source route from the responding node back to the requester,
/// signed by the responder. Also contains the forward path so the requester
/// knows how to reach the responder.
#[derive(Clone, Debug)]
pub struct PathNotify {
    /// The forward path from source to destination.
    pub path: Vec<PeerPort>,
    /// Watermark to prevent old PATH_NOTIFY packets from overwriting newer ones.
    pub watermark: u64,
    /// The ed25519 public key of the node that sent the original PATH_LOOKUP.
    pub source: PublicKeyBytes,
    /// The ed25519 public key of the node responding with this PATH_NOTIFY.
    pub dest: PublicKeyBytes,
    /// The signed path information from the destination.
    pub info: PathNotifyInfo,
}

impl PathNotify {
    /// Returns the encoded byte size.
    pub fn size(&self) -> usize {
        size_path(&self.path) + size_uvarint(self.watermark) + 32 + 32 + self.info.size()
    }

    /// Encode the PathNotify, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_path(out, &self.path);
        put_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
        self.info.encode(out);
    }

    /// Decode a complete PathNotify from `data`.
    pub fn decode(data: &[u8]) -> Option<PathNotify> {
        let mut d = data;
        let path = chop_path(&mut d)?;
        let watermark = chop_uvarint(&mut d)?;
        let source: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let info = PathNotifyInfo::chop(&mut d)?;
        if !d.is_empty() {
            return None;
        }
        Some(PathNotify { path, watermark, source, dest, info })
    }
}

// ============================================================================
// PathBroken
// ============================================================================

/// A notification that a previously-known path has stopped working.
///
/// Sent by a node that detects forwarding failure (e.g., the next-hop peer
/// disconnected). The `watermark` identifies which path version is broken,
/// allowing the source to re-trigger path discovery.
#[derive(Clone, Debug)]
pub struct PathBroken {
    /// The reverse path back to the source that should be notified.
    pub path: Vec<PeerPort>,
    /// Watermark matching the broken path's PATH_NOTIFY.
    pub watermark: u64,
    /// The node that originally requested the path.
    pub source: PublicKeyBytes,
    /// The destination node of the broken path.
    pub dest: PublicKeyBytes,
}

impl PathBroken {
    /// Returns the encoded byte size.
    pub fn size(&self) -> usize {
        size_path(&self.path) + size_uvarint(self.watermark) + 32 + 32
    }

    /// Encode the PathBroken, appending to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        put_path(out, &self.path);
        put_uvarint(out, self.watermark);
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.dest);
    }

    /// Decode a complete PathBroken from `data`.
    pub fn decode(data: &[u8]) -> Option<PathBroken> {
        let mut d = data;
        let path = chop_path(&mut d)?;
        let watermark = chop_uvarint(&mut d)?;
        let source: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        let dest: PublicKeyBytes = chop_slice(&mut d, 32)?.try_into().ok()?;
        if !d.is_empty() {
            return None;
        }
        Some(PathBroken { path, watermark, source, dest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uvarint_roundtrip() {
        let values = [0u64, 1, 127, 128, 255, 16383, 16384, u64::MAX];
        for &v in &values {
            let mut buf = Vec::new();
            put_uvarint(&mut buf, v);
            let (decoded, _n) = get_uvarint(&buf).unwrap();
            assert_eq!(decoded, v, "uvarint roundtrip failed for {}", v);
        }
    }

    #[test]
    fn test_path_roundtrip() {
        let path = vec![1u64, 2, 300, 65535, 0xDEADBEEF];
        let mut buf = Vec::new();
        put_path(&mut buf, &path);
        let decoded = chop_path(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, path);
    }

    #[test]
    fn test_frame_encoding() {
        let frame = encode_frame(WIRE_TRAFFIC, b"hello");
        // frame[0] should be uvarint(6) = 0x06
        assert_eq!(frame[0], 6);
        assert_eq!(frame[1], WIRE_TRAFFIC);
        assert_eq!(&frame[2..], b"hello");
    }

    #[test]
    fn test_traffic_roundtrip() {
        let tr = Traffic {
            path: vec![1, 2, 3],
            from: vec![4, 5],
            source: [1u8; 32],
            dest: [2u8; 32],
            watermark: 42,
            payload: b"test payload".to_vec(),
        };
        let encoded = tr.encode();
        let decoded = Traffic::decode(&encoded).unwrap();
        assert_eq!(decoded.path, tr.path);
        assert_eq!(decoded.from, tr.from);
        assert_eq!(decoded.source, tr.source);
        assert_eq!(decoded.dest, tr.dest);
        assert_eq!(decoded.watermark, tr.watermark);
        assert_eq!(decoded.payload, tr.payload);
    }
}
