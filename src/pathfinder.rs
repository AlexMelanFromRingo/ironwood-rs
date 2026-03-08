//! # Source Routing Path Discovery (Pathfinder)
//!
//! This module implements the pathfinder protocol that discovers source routes
//! between nodes in the Ironwood mesh. A "source route" is a sequence of peer port
//! numbers that describes the exact path a packet should take through the network,
//! encoded directly in the packet header.
//!
//! ## Why Source Routing?
//!
//! Spanning tree routing (see [`crate::spanning_tree`]) provides baseline connectivity
//! but may use suboptimal paths (routing everything through the tree root). Source
//! routing discovers direct paths between node pairs, potentially much shorter.
//!
//! Once a source route is established:
//! - Traffic bypasses intermediate routing table lookups
//! - Each hop just reads the first port number and forwards
//! - No global state is needed — the path is in the packet itself
//!
//! ## Protocol Overview
//!
//! ```text
//! Source                           Destination
//!   │                                   │
//!   │── PATH_LOOKUP ──────────────────► │   (flooded via bloom filter)
//!   │                                   │
//!   │◄─ PATH_NOTIFY ────────────────── │   (unicast back along return path)
//!   │                                   │
//!   │═══════════ TRAFFIC ════════════► │   (using the discovered source route)
//!   │                                   │
//!   │◄══════════ TRAFFIC ════════════  │   (using the reverse path from PATH_NOTIFY)
//! ```
//!
//! ## PATH_LOOKUP Flooding
//!
//! When a source node wants to reach a destination and has no cached path:
//!
//! 1. Generate a PATH_LOOKUP packet with `source = self_key`, `dest = target_key`
//! 2. Forward it to peers whose Bloom filter indicates they may know the destination
//! 3. Each intermediate node appends its port number to `from` before forwarding
//! 4. This builds a return path in the `from` field as the lookup propagates
//!
//! Forwarding decision at each hop:
//! - Check each peer's `recv` bloom filter for the destination key
//! - Forward to peers whose filter contains the key (they claim to be able to reach it)
//! - Avoid forwarding to the peer the lookup arrived from
//! - Avoid forwarding if we already recently sent a lookup for this destination
//!
//! ## PATH_NOTIFY Response
//!
//! When the lookup reaches a node that:
//! - Is the destination itself, or
//! - Has a cached path to the destination
//!
//! That node generates a PATH_NOTIFY:
//!
//! 1. Take the `from` path from the PATH_LOOKUP (this is the path back to source)
//! 2. Sign `{seq, reverse_path}` with the destination's private key
//! 3. Send PATH_NOTIFY back along the `from` path
//!
//! The PATH_NOTIFY contains:
//! - `path`: the forward path (from source to destination)
//! - `source`: who asked for the path
//! - `dest`: who responded
//! - `info.path`: the reverse path (from destination back to source), signed
//! - `watermark`: sequence number to reject stale notifications
//!
//! ## PATH_BROKEN Notification
//!
//! When a node tries to forward traffic along a known path and the next-hop peer
//! has disconnected:
//!
//! 1. The forwarding node sends a PATH_BROKEN back to the source along the `from` path
//! 2. The PATH_BROKEN contains the watermark of the failed path
//! 3. The source removes the stale path from its cache and re-initiates discovery
//!
//! ## Path Caching and Throttling
//!
//! Discovered paths are cached per-destination:
//!
//! | Timer            | Duration | Effect                                       |
//! |------------------|----------|----------------------------------------------|
//! | `PATH_TIMEOUT`   | 60 sec   | Cached paths expire without traffic          |
//! | `PATH_THROTTLE`  | 1 sec    | Minimum time between PATH_LOOKUP retries     |
//!
//! ## XOR Tree Coordinates for Forwarding
//!
//! PATH_LOOKUP packets use XOR-hashed tree coordinates for greedy forwarding.
//! Each node computes a "tree coordinate" from its ancestry chain, and forwards
//! the lookup to whichever neighbor is "closer" to the destination in tree space.
//!
//! This is similar to Kademlia routing but applied to the spanning tree topology
//! rather than a DHT keyspace. It ensures lookups converge toward the destination
//! without creating routing loops.
//!
//! ## PathNotifyInfo Signature
//!
//! The destination signs `seq || path` (zero-terminated uvarint path), where `seq`
//! is a monotonically increasing sequence number maintained by the signer.
//! This prevents replay attacks and ensures the source can verify the path authenticity.
//!
//! Verification at source: `ed25519_verify(dest_key, info.sig, info.bytes_for_sig())`

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::packet::{PublicKeyBytes, PeerPort, PathLookup, PathNotify, PathBroken, PathNotifyInfo};

// ============================================================================
// Constants
// ============================================================================

/// How long a cached path remains valid without being used (60 seconds).
pub const PATH_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimum interval between PATH_LOOKUP retransmissions for the same destination (1 second).
pub const PATH_THROTTLE: Duration = Duration::from_secs(1);

// ============================================================================
// PathInfo
// ============================================================================

/// A cached source route to a specific destination.
///
/// Stored after a PATH_NOTIFY is received, allowing subsequent traffic to the
/// same destination to reuse the discovered path without re-flooding.
#[derive(Debug)]
pub struct PathInfo {
    /// The cached forward path (sequence of peer port numbers to the destination).
    pub path: Vec<PeerPort>,
    /// The path sequence number from the destination's PATH_NOTIFY.
    pub seq: u64,
    /// When the last PATH_LOOKUP was sent for this destination (for throttling).
    pub req_time: Instant,
    /// When this path entry was last updated (for expiry).
    pub updated: Instant,
    /// Whether this path is known to be broken (pending re-discovery).
    pub broken: bool,
    /// Traffic that was queued waiting for path discovery to complete.
    pub pending_traffic: Option<Vec<u8>>,
}

impl PathInfo {
    /// Create a new PathInfo from a received PATH_NOTIFY.
    pub fn new(path: Vec<PeerPort>, seq: u64) -> Self {
        let now = Instant::now();
        PathInfo {
            path,
            seq,
            req_time: now,
            updated: now,
            broken: false,
            pending_traffic: None,
        }
    }

    /// Returns true if this path has expired (not used within PATH_TIMEOUT).
    pub fn is_expired(&self) -> bool {
        self.updated.elapsed() > PATH_TIMEOUT
    }

    /// Returns true if we should send a new PATH_LOOKUP (throttle check).
    pub fn should_send_lookup(&self) -> bool {
        self.req_time.elapsed() > PATH_THROTTLE
    }
}

// ============================================================================
// PathRumor
// ============================================================================

/// A "rumor" — a pending PATH_LOOKUP request waiting for a response.
///
/// When a node sends a PATH_LOOKUP, it stores a PathRumor to track:
/// - Whether there's traffic waiting to be sent once the path is discovered
/// - When the lookup was sent (for throttling / expiry)
#[derive(Debug)]
pub struct PathRumor {
    /// Traffic payload waiting to be sent once the path is discovered.
    pub pending_traffic: Option<Vec<u8>>,
    /// When the PATH_LOOKUP was last sent.
    pub send_time: Instant,
    /// When this rumor was first created.
    pub created: Instant,
}

impl PathRumor {
    /// Create a new PathRumor with no pending traffic.
    pub fn new() -> Self {
        let now = Instant::now();
        PathRumor {
            pending_traffic: None,
            send_time: now,
            created: now,
        }
    }
}

impl Default for PathRumor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PathfinderState
// ============================================================================

/// State for the source routing pathfinder.
///
/// Tracks:
/// - All cached discovered paths
/// - Pending path rumors (active lookups)
/// - Our own signed path info (used when responding to others' lookups)
#[derive(Debug)]
pub struct PathfinderState {
    /// Our own node's path notify info — signed `{seq, path=[]}` to announce ourselves.
    pub self_info: PathNotifyInfo,

    /// Cached paths to remote destinations.
    pub paths: HashMap<PublicKeyBytes, PathInfo>,

    /// Active path discovery requests (lookup sent, response pending).
    pub rumors: HashMap<PublicKeyBytes, PathRumor>,
}

impl PathfinderState {
    /// Create a new PathfinderState.
    pub fn new(self_info: PathNotifyInfo) -> Self {
        PathfinderState {
            self_info,
            paths: HashMap::new(),
            rumors: HashMap::new(),
        }
    }

    /// Handle an incoming PATH_LOOKUP.
    ///
    /// ## Steps
    ///
    /// 1. Check if we are the destination — if so, send a PATH_NOTIFY back
    /// 2. Check if we have a cached path to the destination — if so, forward a PATH_NOTIFY
    /// 3. Otherwise, forward the lookup to peers whose bloom filter contains the destination
    ///    (after prepending our port to the `from` path)
    ///
    /// Rate-limiting: don't forward a lookup we've recently forwarded for the same dest.
    pub fn handle_lookup(
        &mut self,
        _lookup: &PathLookup,
        _self_key: &PublicKeyBytes,
        _arrived_from_port: PeerPort,
    ) {
        unimplemented!("handle_lookup: forward or respond to path discovery request")
    }

    /// Handle an incoming PATH_NOTIFY.
    ///
    /// ## Steps
    ///
    /// 1. Verify the destination's signature on `info.bytes_for_sig()`
    /// 2. Check watermark to avoid replays (must be >= stored watermark)
    /// 3. If we are the intended recipient (`notify.source == self_key`):
    ///    - Store the path in `self.paths[notify.dest]`
    ///    - Send any pending traffic that was waiting for this path
    /// 4. Otherwise: forward along `notify.path` toward the source
    pub fn handle_notify(
        &mut self,
        _notify: &PathNotify,
        _self_key: &PublicKeyBytes,
    ) {
        unimplemented!("handle_notify: store or forward path notification")
    }

    /// Handle an incoming PATH_BROKEN.
    ///
    /// ## Steps
    ///
    /// 1. If we are the intended recipient (`broken.source == self_key`):
    ///    - Invalidate the path in `self.paths[broken.dest]` if watermarks match
    ///    - Trigger a new PATH_LOOKUP for re-discovery
    /// 2. Otherwise: forward along `broken.path` toward the source
    pub fn handle_broken(
        &mut self,
        _broken: &PathBroken,
        _self_key: &PublicKeyBytes,
    ) {
        unimplemented!("handle_broken: invalidate stale path, trigger re-discovery")
    }

    /// Initiate path discovery to a destination.
    ///
    /// Creates a PATH_LOOKUP packet and floods it through the spanning tree using
    /// bloom filter routing. Stores a PathRumor to track the pending request.
    ///
    /// If a lookup was recently sent for this destination (within PATH_THROTTLE),
    /// this is a no-op.
    pub fn send_lookup(
        &mut self,
        _dest: &PublicKeyBytes,
        _self_key: &PublicKeyBytes,
        _pending_traffic: Option<Vec<u8>>,
    ) {
        unimplemented!("send_lookup: flood PATH_LOOKUP for destination")
    }

    /// Expire old paths and rumors.
    ///
    /// - Paths older than PATH_TIMEOUT are removed
    /// - Rumors older than PATH_TIMEOUT are removed
    ///
    /// Called during the maintenance cycle.
    pub fn expire(&mut self) {
        let now = Instant::now();

        self.paths.retain(|_, info| info.updated.elapsed() <= PATH_TIMEOUT);
        self.rumors.retain(|_, rumor| rumor.created.elapsed() <= PATH_TIMEOUT);

        let _ = now; // suppress unused warning
    }

    /// Look up a cached path to a destination.
    ///
    /// Returns `Some(&PathInfo)` if a valid, non-broken path exists in cache.
    /// Returns `None` if no path is cached or the path is broken/expired.
    pub fn get_path(&self, dest: &PublicKeyBytes) -> Option<&PathInfo> {
        self.paths.get(dest).filter(|info| !info.broken && !info.is_expired())
    }
}

// ============================================================================
// Wire coordinate helpers
// ============================================================================

/// Compute XOR tree coordinates for greedy PATH_LOOKUP forwarding.
///
/// Each node's coordinate is a hash of its ancestry chain. Two nodes in the
/// same subtree share more common prefix ancestors and thus have smaller XOR distance.
///
/// The coordinate is used when choosing which peer to forward a PATH_LOOKUP to:
/// forward to the peer whose coordinate is XOR-closest to the destination's coordinate.
///
/// This is analogous to Kademlia routing but uses tree structure instead of a DHT.
pub fn compute_tree_coordinate(_ancestry: &[[u8; 32]]) -> u64 {
    unimplemented!(
        "compute_tree_coordinate: XOR-hash ancestry chain to produce routing coordinate"
    )
}

/// Compute the XOR distance between two tree coordinates.
///
/// Used to compare candidate peers when forwarding PATH_LOOKUP:
/// prefer the peer with smaller XOR distance to the destination coordinate.
pub fn xor_distance(a: u64, b: u64) -> u64 {
    a ^ b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PathNotifyInfo, put_uvarint, put_path};

    #[test]
    fn test_path_info_expiry() {
        let info = PathInfo::new(vec![1, 2, 3], 42);
        assert!(!info.is_expired()); // just created
    }

    #[test]
    fn test_path_rumor_default() {
        let rumor = PathRumor::new();
        assert!(rumor.pending_traffic.is_none());
        assert!(!rumor.created.elapsed() > std::time::Duration::from_secs(1));
    }

    #[test]
    fn test_pathfinder_expire_empty() {
        let info = PathNotifyInfo {
            seq: 0,
            path: vec![],
            sig: [0u8; 64],
        };
        let mut pf = PathfinderState::new(info);
        pf.expire(); // should not panic on empty state
        assert!(pf.paths.is_empty());
        assert!(pf.rumors.is_empty());
    }

    #[test]
    fn test_xor_distance() {
        assert_eq!(xor_distance(5, 3), 6);
        assert_eq!(xor_distance(0, 0), 0);
        assert_eq!(xor_distance(u64::MAX, 0), u64::MAX);
    }

    #[test]
    fn test_path_notify_info_bytes_for_sig() {
        let info = PathNotifyInfo {
            seq: 42,
            path: vec![1, 2, 3],
            sig: [0u8; 64],
        };
        let bytes = info.bytes_for_sig();
        // Should encode seq=42 followed by path [1, 2, 3, 0] as uvarints
        assert!(!bytes.is_empty());
        // seq=42 encodes as single byte 0x2A
        assert_eq!(bytes[0], 42);
    }
}
