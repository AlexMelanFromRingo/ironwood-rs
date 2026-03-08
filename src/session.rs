//! # Session Encryption
//!
//! This module implements the session layer that encrypts traffic between pairs of
//! Ironwood nodes. Sessions use a double-ratchet scheme built on top of NaCl box
//! (X25519 Diffie-Hellman + XSalsa20-Poly1305 authenticated encryption).
//!
//! ## Overview
//!
//! Each pair of communicating nodes maintains a **session** with:
//! - Mutual authentication via ed25519 identity keys (the same keys used for spanning tree)
//! - Forward secrecy via ephemeral X25519 key pairs that rotate on each session init/ack
//! - Replay protection via a monotonically increasing `watermark` in traffic packets
//!
//! Sessions are established lazily — the first time a node wants to send traffic to
//! a destination, it sends a `SESSION_INIT` packet. The destination responds with
//! `SESSION_ACK`. After the ack, both sides can exchange `SESSION_TRAFFIC` packets.
//!
//! ## Key Derivation from ed25519
//!
//! Ironwood nodes identify themselves with ed25519 keys (used for signing spanning tree
//! announcements). For session encryption, these ed25519 keys are converted to X25519 keys:
//!
//! ### Private Key Conversion (ed25519 seed → X25519 scalar)
//!
//! The ed25519 private key is a 64-byte value: `[seed (32B) | public_key (32B)]`.
//! The X25519 scalar is derived from the seed using SHA-512 + clamping:
//!
//! ```text
//! hash = SHA-512(seed)          // 64 bytes
//! scalar = hash[0..32]          // take first 32 bytes
//! scalar[0]  &= 248             // clear bottom 3 bits (cofactor)
//! scalar[31] &= 127             // clear top bit
//! scalar[31] |= 64              // set second-highest bit
//! ```
//!
//! This follows RFC 7748 (Elliptic Curves for Security) and is the standard
//! way to convert an ed25519 signing key to a Curve25519 key.
//!
//! ### Public Key Conversion (ed25519 point → X25519 point)
//!
//! An ed25519 public key is a compressed Edwards25519 point. To convert to
//! Curve25519 (Montgomery form):
//!
//! ```text
//! edwards_point = decompress(ed25519_pub_key)
//! montgomery_u  = edwards_point.to_montgomery()
//! x25519_pub    = montgomery_u.to_bytes()
//! ```
//!
//! This uses the birational equivalence between Edwards and Montgomery curves.
//! Implemented via `curve25519-dalek` crate.
//!
//! ## Session Wire Format
//!
//! Session packets are the payload of TRAFFIC frames (type byte 9). The first byte
//! determines the session packet type:
//!
//! | Byte | Name              | Description                           |
//! |------|-------------------|---------------------------------------|
//! | 0    | `SESSION_DUMMY`   | Ignored (padding)                     |
//! | 1    | `SESSION_INIT`    | Initiate a new session                |
//! | 2    | `SESSION_ACK`     | Acknowledge a session init            |
//! | 3    | `SESSION_TRAFFIC` | Encrypted application data            |
//!
//! ### SESSION_INIT / SESSION_ACK Format (193 bytes total)
//!
//! ```text
//! Byte offset  Size    Field           Description
//! ───────────  ──────  ──────────────  ──────────────────────────────────────
//! 0            1       type            SESSION_INIT (1) or SESSION_ACK (2)
//! 1            32      box_pub         Sender's ephemeral X25519 public key
//! 33           16      nonce_box       Encrypted inner body (40 bytes → 56 with tag)
//! 33           56      encrypted_body  NaCl box(inner_body, nonce=0, their_x25519, our_x25519)
//! 89           64      ed_sig          ed25519 sig over [type | box_pub | encrypted_body]
//! 153          32      current_pub     Sender's current X25519 send key (public)
//! 185          32      next_pub        Sender's next X25519 key (pre-generated)
//! 217          8       key_seq         Sender's key sequence number (little-endian u64)
//! ── total: 193 bytes ────────────────────────────────────────────────────────
//! ```
//!
//! Wait, let me clarify the exact layout from the Go source:
//!
//! ```text
//! [0]     type byte (SESSION_INIT or SESSION_ACK)
//! [1..33] box_pub: our ephemeral X25519 public key (32 bytes)
//! [33..89] encrypted_body: NaCl box seal of:
//!           [current_pub (32B)] + [next_pub (32B)] + [seq (8B LE)] + [key_seq (8B LE)]
//!           = 80 bytes plaintext → 96 bytes ciphertext (+ 16 Poly1305 tag)
//!           Wait: 32+32+8+8 = 80. With 16 overhead: 96 bytes. But header says 56...
//! ```
//!
//! The total size `SESSION_INIT_SIZE = 193` from the Go source:
//! `1 + 32 + 16 + 64 + 32 + 32 + 8 + 8 = 193`
//!
//! Breaking this down:
//! - `type` (1)
//! - `box_pub` (32) — ephemeral DH key
//! - `box_ct` (16) — NaCl box of a nonce value (0 bytes plaintext → 16 bytes ciphertext)
//! - `ed_sig` (64) — ed25519 signature
//! - `current_pub` (32) — sender's current X25519 key
//! - `next_pub` (32) — sender's next X25519 key
//! - `seq` (8 LE) — session sequence number
//! - `key_seq` (8 LE) — key rotation sequence number
//!
//! The NaCl box uses the identity private key derived X25519 for `box_ct`.
//! The ed_sig authenticates `[type | box_pub | box_ct]`.
//!
//! ## Double-Ratchet Key Rotation
//!
//! Each session endpoint maintains three X25519 key slots:
//!
//! ```text
//! recv_priv / recv_pub  — Previous send key, now used to receive
//! send_priv / send_pub  — Current send key
//! next_priv / next_pub  — Pre-generated next key (not yet used for sending)
//! ```
//!
//! ### Key Rotation on Init/Ack (_handleUpdate in Go)
//!
//! When a SESSION_INIT or SESSION_ACK is received and verified:
//!
//! ```text
//! old_recv = recv_pub
//! recv ← send          // rotate: old send key is now the recv key
//! send ← next          // the pre-generated key becomes current
//! next ← random()      // generate a fresh next key
//! local_key_seq += 1   // increment our sequence
//! remote_key_seq = init.key_seq  // record their sequence
//! ```
//!
//! ### Traffic Decryption Key Selection (4 Cases)
//!
//! When receiving SESSION_TRAFFIC, we must figure out which DH shared secret to use.
//! The traffic packet contains `{current_pub, next_pub}` from the sender's perspective.
//! We try to match:
//!
//! ```text
//! Case 1: fromCurrent && toRecv
//!   → DH(remote.current_pub, local.recv_priv)
//!   (normal case: they're sending from their current key to our recv key)
//!
//! Case 2: fromNext && toSend
//!   → DH(remote.next_pub, local.send_priv)
//!   (key rotation: they rotated, using their new key to our current send key)
//!
//! Case 3: fromNext && toRecv
//!   → DH(remote.next_pub, local.recv_priv)
//!   (simultaneous init: both sides rotated at the same time)
//!
//! Case 4: else
//!   → send a new SESSION_INIT and drop this traffic packet
//!   (we're out of sync, need to re-establish session)
//! ```
//!
//! ## Nonce Scheme
//!
//! Traffic packets use a 24-byte nonce constructed from the watermark:
//!
//! ```text
//! nonce = [0; 16] + watermark.to_be_bytes()  // 8 byte big-endian at the end
//! ```
//!
//! The watermark is the same value stored in the Traffic packet, ensuring the
//! receiver can construct the same nonce for decryption.
//!
//! ## Session Traffic Format
//!
//! ```text
//! [0]     SESSION_TRAFFIC (3)
//! [1..33] current_pub: our current X25519 send key (32 bytes)
//! [33..65] next_pub: our next X25519 key (32 bytes)
//! [65..]  ciphertext: NaCl box of plaintext (variable length)
//! ```

use std::collections::HashMap;
use std::time::Instant;

use ed25519_dalek::SigningKey;

use crate::packet::PublicKeyBytes;

// ============================================================================
// Session packet type constants
// ============================================================================

/// Ignored session packet (padding).
pub const SESSION_DUMMY: u8 = 0;

/// Session init — first packet when establishing a new session.
pub const SESSION_INIT: u8 = 1;

/// Session ack — response to a session init.
pub const SESSION_ACK: u8 = 2;

/// Encrypted application traffic.
pub const SESSION_TRAFFIC: u8 = 3;

/// Total size in bytes of a SESSION_INIT or SESSION_ACK packet.
///
/// Breakdown: `1 (type) + 32 (box_pub) + 16 (box_ct) + 64 (ed_sig) + 32 (current_pub) + 32 (next_pub) + 8 (seq) + 8 (key_seq) = 193`
pub const SESSION_INIT_SIZE: usize = 193;

/// The Poly1305 authentication tag overhead added by NaCl box encryption.
pub const BOX_OVERHEAD: usize = 16;

// ============================================================================
// Key types
// ============================================================================

/// An X25519 public key (Curve25519 Montgomery point, 32 bytes).
pub type BoxPub = [u8; 32];

/// An X25519 private key (scalar, 32 bytes).
pub type BoxPriv = [u8; 32];

// ============================================================================
// Key Derivation
// ============================================================================

/// Convert an ed25519 public key to an X25519 public key.
///
/// Uses the birational map from Edwards25519 to Curve25519 (Montgomery form).
/// Implemented via `CompressedEdwardsY::decompress().to_montgomery()`.
///
/// Returns `None` if the input is not a valid compressed Edwards25519 point.
///
/// ## Wire Compatibility
///
/// This function produces identical output to Go's `extra25519.PublicKeyToCurve25519()`.
pub fn ed_pub_to_box_pub(ed_pub: &[u8; 32]) -> Option<BoxPub> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pub);
    let point = compressed.decompress()?;
    let montgomery = point.to_montgomery();
    Some(montgomery.to_bytes())
}

/// Convert an ed25519 private key (64-byte seed+pub format) to an X25519 scalar.
///
/// ## Algorithm
///
/// 1. Extract the 32-byte seed (first half of the 64-byte ed25519 key)
/// 2. Hash the seed with SHA-512
/// 3. Take the first 32 bytes of the hash
/// 4. Apply clamping per RFC 7748:
///    - Clear bits 0, 1, 2 of byte 0 (cofactor)
///    - Clear bit 7 of byte 31 (ensure scalar < 2^255)
///    - Set bit 6 of byte 31 (ensure scalar >= 2^254)
///
/// ## Wire Compatibility
///
/// This function produces identical output to Go's `extra25519.PrivateKeyToCurve25519()`.
pub fn ed_priv_to_box_priv(ed_priv_64bytes: &[u8; 64]) -> BoxPriv {
    use sha2::{Sha512, Digest};
    let seed = &ed_priv_64bytes[..32];
    let hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    // RFC 7748 clamping
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

/// Generate a fresh random X25519 key pair.
///
/// Used to pre-generate the `next` key slot during session init/ack processing.
pub fn new_box_key_pair() -> (BoxPub, BoxPriv) {
    use rand::rngs::OsRng;
    use x25519_dalek::{StaticSecret, PublicKey as X25519Public};
    let priv_key = StaticSecret::random_from_rng(OsRng);
    let pub_key = X25519Public::from(&priv_key);
    (*pub_key.as_bytes(), priv_key.to_bytes())
}

// ============================================================================
// Session state
// ============================================================================

/// The state of an encryption session with a specific remote peer.
///
/// A session is identified by the pair `(local_key, remote_key)` of ed25519
/// public keys. Key rotation happens automatically on each SESSION_INIT/ACK exchange.
#[derive(Debug)]
pub struct Session {
    /// The remote node's ed25519 public key (their identity).
    pub remote_key: PublicKeyBytes,

    // --- Local key slots ---

    /// Our previous send key (now used to receive from remote's "current" references).
    pub recv_pub: BoxPub,
    /// Private key for `recv_pub`.
    pub recv_priv: BoxPriv,

    /// Our current send key.
    pub send_pub: BoxPub,
    /// Private key for `send_pub`.
    pub send_priv: BoxPriv,

    /// Our next key (pre-generated, will become `send` on next rotation).
    pub next_pub: BoxPub,
    /// Private key for `next_pub`.
    pub next_priv: BoxPriv,

    // --- Remote key slots ---

    /// Remote's current X25519 send key (from their most recent init/ack).
    pub remote_current_pub: BoxPub,

    /// Remote's next X25519 key (from their most recent init/ack).
    pub remote_next_pub: BoxPub,

    // --- Sequence numbers ---

    /// Our local key rotation sequence number. Incremented on each rotation.
    pub local_key_seq: u64,

    /// Remote's key sequence number from their most recent init/ack.
    pub remote_key_seq: u64,

    /// Watermark for replay prevention. Only accept traffic with watermark > this.
    pub watermark: u64,

    // --- Timing ---

    /// When this session was established.
    pub established_at: Instant,

    /// Whether the session has been fully established (ack received).
    pub is_established: bool,
}

impl Session {
    /// Create a new unestablished session for communication with `remote_key`.
    ///
    /// Generates fresh key pairs for all three slots (recv, send, next).
    pub fn new(remote_key: PublicKeyBytes) -> Self {
        let (recv_pub, recv_priv) = new_box_key_pair();
        let (send_pub, send_priv) = new_box_key_pair();
        let (next_pub, next_priv) = new_box_key_pair();
        Session {
            remote_key,
            recv_pub, recv_priv,
            send_pub, send_priv,
            next_pub, next_priv,
            remote_current_pub: [0u8; 32],
            remote_next_pub: [0u8; 32],
            local_key_seq: 0,
            remote_key_seq: 0,
            watermark: 0,
            established_at: Instant::now(),
            is_established: false,
        }
    }

    /// Rotate keys after a SESSION_INIT or SESSION_ACK is received and verified.
    ///
    /// ## Rotation Steps
    ///
    /// ```text
    /// recv ← send      (old send becomes new recv)
    /// send ← next      (pre-generated next becomes current)
    /// next ← random    (generate fresh next key)
    /// local_key_seq += 1
    /// remote_key_seq = init.key_seq
    /// ```
    pub fn rotate_keys(&mut self, remote_key_seq: u64) {
        // recv ← send
        self.recv_pub = self.send_pub;
        self.recv_priv = self.send_priv;
        // send ← next
        self.send_pub = self.next_pub;
        self.send_priv = self.next_priv;
        // next ← fresh
        let (next_pub, next_priv) = new_box_key_pair();
        self.next_pub = next_pub;
        self.next_priv = next_priv;
        // update sequence numbers
        self.local_key_seq += 1;
        self.remote_key_seq = remote_key_seq;
    }

    /// Generate a SESSION_INIT or SESSION_ACK packet.
    ///
    /// The packet contains:
    /// - Our ephemeral box key
    /// - Our current and next X25519 public keys
    /// - Our key sequence number
    /// - An ed25519 signature authenticating the packet
    ///
    /// After calling this, `rotate_keys()` should be called to prepare for the response.
    pub fn make_init_or_ack(
        &self,
        _pkt_type: u8,
        _signing_key: &SigningKey,
    ) -> Vec<u8> {
        unimplemented!("make_init_or_ack: build 193-byte SESSION_INIT or SESSION_ACK packet")
    }

    /// Parse and verify a received SESSION_INIT or SESSION_ACK packet.
    ///
    /// ## Verification Steps
    ///
    /// 1. Check packet length == SESSION_INIT_SIZE (193 bytes)
    /// 2. Parse fields: type, box_pub, box_ct, ed_sig, current_pub, next_pub, seq, key_seq
    /// 3. Verify ed_sig over `[type | box_pub | box_ct]` using `remote_key`
    /// 4. Open the NaCl box to validate the ephemeral DH
    ///
    /// Returns `Ok((current_pub, next_pub, seq, key_seq))` on success.
    pub fn parse_init_or_ack(
        &self,
        _data: &[u8],
    ) -> Option<(BoxPub, BoxPub, u64, u64)> {
        unimplemented!("parse_init_or_ack: parse and verify 193-byte session handshake")
    }

    /// Encrypt a plaintext payload for transmission as SESSION_TRAFFIC.
    ///
    /// Builds the traffic payload:
    /// ```text
    /// [SESSION_TRAFFIC (1B)] [current_pub (32B)] [next_pub (32B)] [ciphertext (variable)]
    /// ```
    ///
    /// The NaCl box nonce is derived from the watermark: `[0; 16] + watermark.to_be_bytes()`.
    /// The DH shared secret uses `(remote_current_pub, send_priv)`.
    pub fn encrypt(&self, _plaintext: &[u8], _watermark: u64) -> Vec<u8> {
        unimplemented!("encrypt: NaCl box seal plaintext with current send key")
    }

    /// Decrypt a SESSION_TRAFFIC payload.
    ///
    /// ## Key Selection (4 Cases)
    ///
    /// The traffic packet contains the sender's `{current_pub, next_pub}`.
    /// We try each combination:
    ///
    /// 1. `from_current && to_recv`:  DH(remote.current, local.recv_priv)
    /// 2. `from_next && to_send`:     DH(remote.next, local.send_priv)
    /// 3. `from_next && to_recv`:     DH(remote.next, local.recv_priv)
    /// 4. else: return None (out of sync — re-init required)
    ///
    /// Returns `Some(plaintext)` on success, `None` on failure.
    pub fn decrypt(&self, _traffic_payload: &[u8], _watermark: u64) -> Option<Vec<u8>> {
        unimplemented!("decrypt: try all 4 key combinations to decrypt traffic")
    }
}

// ============================================================================
// SessionManager
// ============================================================================

/// Manages all active sessions.
///
/// Provides lookup by remote public key and handles session lifecycle:
/// creation, update on init/ack, and cleanup.
#[derive(Debug, Default)]
pub struct SessionManager {
    /// Active sessions indexed by remote ed25519 public key.
    pub sessions: HashMap<PublicKeyBytes, Session>,
}

impl SessionManager {
    /// Create a new empty SessionManager.
    pub fn new() -> Self {
        SessionManager { sessions: HashMap::new() }
    }

    /// Get or create a session for the given remote public key.
    pub fn get_or_create(&mut self, remote_key: PublicKeyBytes) -> &mut Session {
        self.sessions.entry(remote_key).or_insert_with(|| Session::new(remote_key))
    }

    /// Remove a session (e.g., when the peer disconnects).
    pub fn remove(&mut self, remote_key: &PublicKeyBytes) {
        self.sessions.remove(remote_key);
    }

    /// Returns the number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns true if there are no active sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

// ============================================================================
// NaCl box helpers
// ============================================================================

/// Construct a 24-byte NaCl box nonce from a u64 watermark.
///
/// Nonce layout: `[0u8; 16] || watermark.to_be_bytes()`
///
/// The watermark occupies the last 8 bytes of the 24-byte nonce, big-endian.
pub fn nonce_for_watermark(watermark: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[16..].copy_from_slice(&watermark.to_be_bytes());
    n
}

/// Seal a message with NaCl box (XSalsa20-Poly1305).
///
/// Uses `crypto_box::SalsaBox` with the given DH key pair and nonce derived from `watermark`.
pub fn box_seal(msg: &[u8], watermark: u64, their_pub: &BoxPub, our_priv: &BoxPriv) -> Vec<u8> {
    use crypto_box::{PublicKey, SecretKey, SalsaBox, aead::{Aead, generic_array::GenericArray}};
    let their = PublicKey::from(*their_pub);
    let ours = SecretKey::from(*our_priv);
    let b = SalsaBox::new(&their, &ours);
    let nonce_bytes = nonce_for_watermark(watermark);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    b.encrypt(nonce, msg).expect("NaCl box encrypt should not fail")
}

/// Open (decrypt + verify) a NaCl box message.
///
/// Returns `Some(plaintext)` on success, `None` if decryption or MAC verification fails.
pub fn box_open(
    ciphertext: &[u8],
    watermark: u64,
    their_pub: &BoxPub,
    our_priv: &BoxPriv,
) -> Option<Vec<u8>> {
    use crypto_box::{PublicKey, SecretKey, SalsaBox, aead::{Aead, generic_array::GenericArray}};
    let their = PublicKey::from(*their_pub);
    let ours = SecretKey::from(*our_priv);
    let b = SalsaBox::new(&their, &ours);
    let nonce_bytes = nonce_for_watermark(watermark);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    b.decrypt(nonce, ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_construction() {
        let nonce = nonce_for_watermark(1);
        assert_eq!(&nonce[..16], &[0u8; 16]);
        assert_eq!(&nonce[16..], &[0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_nonce_large_watermark() {
        let nonce = nonce_for_watermark(u64::MAX);
        assert_eq!(&nonce[16..], &[255u8; 8]);
    }

    #[test]
    fn test_box_seal_open_roundtrip() {
        let (pub1, priv1) = new_box_key_pair();
        let (pub2, priv2) = new_box_key_pair();
        let plaintext = b"hello ironwood";
        let watermark = 42u64;

        let ciphertext = box_seal(plaintext, watermark, &pub2, &priv1);
        let decrypted = box_open(&ciphertext, watermark, &pub1, &priv2).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_box_open_wrong_watermark() {
        let (pub1, priv1) = new_box_key_pair();
        let (pub2, priv2) = new_box_key_pair();
        let plaintext = b"test";
        let ciphertext = box_seal(plaintext, 1, &pub2, &priv1);
        // Wrong watermark → different nonce → decryption fails
        let result = box_open(&ciphertext, 2, &pub1, &priv2);
        assert!(result.is_none());
    }

    #[test]
    fn test_session_key_rotation() {
        let mut session = Session::new([0u8; 32]);
        let original_recv_pub = session.recv_pub;
        let original_send_pub = session.send_pub;
        let original_next_pub = session.next_pub;

        session.rotate_keys(5);

        // After rotation: recv = old send, send = old next, next = new random
        assert_eq!(session.recv_pub, original_send_pub);
        assert_eq!(session.send_pub, original_next_pub);
        // next should be fresh (very likely different from old next)
        // (There's a theoretical chance of collision but astronomically unlikely)
        assert_ne!(session.next_pub, original_next_pub);
        assert_eq!(session.local_key_seq, 1);
        assert_eq!(session.remote_key_seq, 5);
    }

    #[test]
    fn test_ed_pub_to_box_pub_valid() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let ed_pub = signing_key.verifying_key().to_bytes();
        let result = ed_pub_to_box_pub(&ed_pub);
        assert!(result.is_some(), "Valid ed25519 key should convert to X25519");
    }

    #[test]
    fn test_ed_priv_to_box_priv_clamping() {
        // The scalar's low 3 bits of byte 0 must be 0
        // The high bit of byte 31 must be 0
        // The second-highest bit of byte 31 must be 1
        let ed_priv = [0u8; 64]; // zero seed
        let scalar = ed_priv_to_box_priv(&ed_priv);
        assert_eq!(scalar[0] & 7, 0, "low 3 bits of byte 0 must be 0");
        assert_eq!(scalar[31] & 128, 0, "high bit of byte 31 must be 0");
        assert_eq!(scalar[31] & 64, 64, "second-highest bit of byte 31 must be 1");
    }

    #[test]
    fn test_session_manager_get_or_create() {
        let mut mgr = SessionManager::new();
        let key = [42u8; 32];
        assert!(mgr.is_empty());
        let _session = mgr.get_or_create(key);
        assert_eq!(mgr.len(), 1);
        // Getting again returns the same session (no duplicate)
        let _session2 = mgr.get_or_create(key);
        assert_eq!(mgr.len(), 1);
    }
}
