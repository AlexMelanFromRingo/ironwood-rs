//! # Bloom Filter for Multicast Path Discovery
//!
//! This module implements the Bloom filter used by Ironwood for efficient multicast
//! path discovery. The filter is wire-compatible with the
//! [bits-and-blooms/bloom/v3](https://github.com/bits-and-blooms/bloom) Go library.
//!
//! ## What Is It For?
//!
//! When a node wants to discover a source route to a destination, it floods a
//! `PATH_LOOKUP` packet through the network. To avoid flooding every link, Ironwood
//! uses a per-peer Bloom filter to decide which peers might be "on the way" to the
//! destination.
//!
//! Each node maintains a Bloom filter for each peer that contains hashes of all the
//! destination keys that peer can reach. When forwarding a PATH_LOOKUP, the node
//! checks whether the destination key is in each peer's filter before forwarding.
//!
//! ## Filter Parameters
//!
//! | Parameter     | Value             | Notes                                          |
//! |---------------|-------------------|------------------------------------------------|
//! | `BLOOM_M`     | 8192 bits (1 KB)  | Total filter size                              |
//! | `BLOOM_K`     | 8                 | Number of hash functions per element           |
//! | `BLOOM_U`     | 128               | Number of u64 words (8192 / 64)                |
//! | `BLOOM_F`     | 16                | Number of flag bytes for compression (128 / 8) |
//!
//! ## Hash Function
//!
//! The Bloom filter uses a two-call trick to simulate `BLOOM_K` independent hash
//! functions from just two calls to murmur3 x64 128-bit:
//!
//! ```text
//! // Two calls, treating 128-bit result as two u64 values
//! [h0, h1] = murmur3_x64_128(data,    seed=0)  → split into (low64, high64)
//! [h2, h3] = murmur3_x64_128(data+1b, seed=0)  → split into (low64, high64)
//! //                            ^^^^ append byte 0x01 to data
//! ```
//!
//! For each hash function `i` (0 ≤ i < 8), the bit position is:
//!
//! ```text
//! idx3 = 2 + (((i + (i % 2)) % 4) / 2)
//! bit_pos = (h[i % 2] + i × h[idx3]) % 8192
//! ```
//!
//! This formula matches the Go `bits-and-blooms/bloom/v3` `location()` function exactly.
//!
//! ## Wire Encoding (Compressed)
//!
//! The 1024-byte filter is compressed before transmission using a run-length-like scheme
//! with two flag arrays:
//!
//! ```text
//! ┌─────────────────┬─────────────────┬──────────────────────────────┐
//! │  flags0 (16 B)  │  flags1 (16 B)  │  non-trivial words (variable) │
//! └─────────────────┴─────────────────┴──────────────────────────────┘
//! ```
//!
//! For each of the 128 u64 words in the filter (indexed 0..127):
//!
//! - If `flags0[word_idx / 8]` bit `7 - (word_idx % 8)` is set: word is **all zeros** (skip)
//! - If `flags1[word_idx / 8]` bit `7 - (word_idx % 8)` is set: word is **all ones** (skip)
//! - Otherwise: the word value is included in the compressed data (big-endian u64)
//!
//! The compressed data contains only the "interesting" (non-trivial) words.
//!
//! ### Compression Example
//!
//! A filter with 10 elements set (out of 8192 possible bit positions) will likely have
//! only 1-3 non-zero words. The compressed wire format might be:
//! - `flags0`: 14 bytes with all bits set (126 words are zero) + 2 bytes with 2 bits clear
//! - `flags1`: 16 zero bytes (no all-ones words)
//! - data: 2 non-zero u64 words = 16 bytes
//! - Total: 48 bytes instead of 1024 bytes
//!
//! ## Spanning Tree Integration
//!
//! Bloom filters are distributed through the spanning tree:
//!
//! 1. Each node builds its own filter containing hashes of all keys it can reach
//!    (itself + all peers + their peers, weighted by tree position)
//! 2. Nodes exchange filter updates with their peers
//! 3. When forwarding a PATH_LOOKUP, a node checks all peers' received filters
//!    and only forwards to peers whose filter contains the destination key
//!
//! This ensures PATH_LOOKUP packets propagate toward nodes that know the destination,
//! without flooding the entire network.
//!
//! ## Maintenance
//!
//! Bloom filter maintenance (`bloom_do_maintenance`) runs every second:
//!
//! 1. Rebuild the local filter from current peer state and tree ancestry
//! 2. Send updated filters to peers whose received filter differs from our computed one
//! 3. Mark which peers are "on tree" (connected to us in the spanning tree direction)

use std::io;

// ============================================================================
// Constants
// ============================================================================

/// Number of flag bytes (BLOOM_U / 8 = 128 / 8 = 16).
pub const BLOOM_F: usize = 16;

/// Number of u64 words in the filter (BLOOM_M / 64 = 8192 / 64 = 128).
pub const BLOOM_U: usize = 128;

/// Total number of bits in the filter (1024 bytes = 8192 bits).
pub const BLOOM_M: u32 = 8192;

/// Number of hash functions per element.
pub const BLOOM_K: usize = 8;

// ============================================================================
// BloomFilter
// ============================================================================

/// A 1024-byte (8192-bit) Bloom filter with 8 murmur3-based hash functions.
///
/// Wire-compatible with the Go `bits-and-blooms/bloom/v3` library.
///
/// ## Usage
///
/// ```rust
/// use ironwood_rs::bloom::BloomFilter;
///
/// let mut filter = BloomFilter::new();
/// filter.add(b"some_destination_key");
/// assert!(filter.test(b"some_destination_key"));
/// assert!(!filter.test(b"other_key")); // probably false, unless hash collision
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct BloomFilter {
    /// The filter state as 128 u64 words (= 1024 bytes = 8192 bits).
    pub bits: [u64; BLOOM_U],
}

impl BloomFilter {
    /// Create an empty Bloom filter (all bits zero).
    pub fn new() -> Self {
        BloomFilter { bits: [0u64; BLOOM_U] }
    }

    /// Compute the four base hash values for an element.
    ///
    /// Calls murmur3 x64 128-bit twice:
    /// - First call: `murmur3_x64_128(data)` → `(h0, h1)`
    /// - Second call: `murmur3_x64_128(data + [0x01])` → `(h2, h3)`
    ///
    /// The returned array is `[h0, h1, h2, h3]` where each is a u64.
    ///
    /// This matches the Go `sum256()` function in `bits-and-blooms/bloom/v3`.
    pub fn base_hashes(data: &[u8]) -> [u64; 4] {
        // First hash: murmur3_x64_128(data, seed=0)
        let h12 = murmur3::murmur3_x64_128(&mut io::Cursor::new(data), 0).unwrap_or(0);
        let h0 = h12 as u64;
        let h1 = (h12 >> 64) as u64;

        // Second hash: murmur3_x64_128(data + 0x01, seed=0)
        let mut data_plus_one = data.to_vec();
        data_plus_one.push(0x01);
        let h34 = murmur3::murmur3_x64_128(&mut io::Cursor::new(&data_plus_one), 0).unwrap_or(0);
        let h2 = h34 as u64;
        let h3 = (h34 >> 64) as u64;

        [h0, h1, h2, h3]
    }

    /// Compute the bit position for hash function `i`.
    ///
    /// Formula (matches Go `bits-and-blooms/bloom/v3` `location()`):
    /// ```text
    /// idx3 = 2 + (((i + (i % 2)) % 4) / 2)
    /// bit_pos = (h[i % 2] + i × h[idx3]) % BLOOM_M
    /// ```
    ///
    /// The formula uses wrapping arithmetic to distribute bits uniformly.
    pub fn location(h: &[u64; 4], i: u64) -> usize {
        let idx3 = (2 + (((i + (i % 2)) % 4) / 2)) as usize;
        let v = h[(i % 2) as usize].wrapping_add(i.wrapping_mul(h[idx3]));
        (v % (BLOOM_M as u64)) as usize
    }

    /// Add an element to the filter by setting its `BLOOM_K` bit positions.
    pub fn add(&mut self, data: &[u8]) {
        let h = Self::base_hashes(data);
        for i in 0..BLOOM_K as u64 {
            let loc = Self::location(&h, i);
            self.bits[loc / 64] |= 1u64 << (loc % 64);
        }
    }

    /// Test whether an element is (probably) in the filter.
    ///
    /// Returns `true` if all `BLOOM_K` bit positions are set.
    /// A `false` return is definitive (element was never added).
    /// A `true` return may be a false positive.
    pub fn test(&self, data: &[u8]) -> bool {
        let h = Self::base_hashes(data);
        for i in 0..BLOOM_K as u64 {
            let loc = Self::location(&h, i);
            if self.bits[loc / 64] & (1u64 << (loc % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// Merge `other` into `self` by ORing all bits together.
    ///
    /// The result is the union of both filters. This is used when a node
    /// combines the filters from all its peers to build its own outgoing filter.
    pub fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_U {
            self.bits[i] |= other.bits[i];
        }
    }

    /// Returns the compressed wire size of this filter in bytes.
    ///
    /// Size = `BLOOM_F (flags0) + BLOOM_F (flags1) + 8 * non_trivial_words`
    /// where non-trivial means neither all-zero nor all-ones.
    pub fn wire_size(&self) -> usize {
        let mut kept = 0usize;
        for &u in &self.bits {
            if u != 0 && u != !0u64 {
                kept += 1;
            }
        }
        BLOOM_F + BLOOM_F + kept * 8
    }

    /// Encode the filter to its compressed wire format.
    ///
    /// Format: `flags0 (16B) || flags1 (16B) || non-trivial words (BE u64 each)`
    ///
    /// - `flags0[i/8]` bit `7-(i%8)` = 1 → word `i` is all-zero (omit from data)
    /// - `flags1[i/8]` bit `7-(i%8)` = 1 → word `i` is all-ones (omit from data)
    /// - Otherwise: word `i` is included in output in big-endian order
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut flags0 = [0u8; BLOOM_F];
        let mut flags1 = [0u8; BLOOM_F];
        let mut kept: Vec<u64> = Vec::new();

        for (idx, &u) in self.bits.iter().enumerate() {
            if u == 0 {
                flags0[idx / 8] |= 0x80u8 >> (idx % 8);
            } else if u == !0u64 {
                flags1[idx / 8] |= 0x80u8 >> (idx % 8);
            } else {
                kept.push(u);
            }
        }

        out.extend_from_slice(&flags0);
        out.extend_from_slice(&flags1);
        for u in kept {
            out.extend_from_slice(&u.to_be_bytes());
        }
    }

    /// Decode a filter from its compressed wire format.
    ///
    /// Returns `None` if the data is malformed (truncated, conflicting flags, trailing bytes).
    pub fn decode(data: &[u8]) -> Option<BloomFilter> {
        if data.len() < BLOOM_F + BLOOM_F {
            return None;
        }
        let flags0 = &data[..BLOOM_F];
        let flags1 = &data[BLOOM_F..BLOOM_F * 2];
        let mut rest = &data[BLOOM_F * 2..];
        let mut bloom = BloomFilter::new();

        for idx in 0..BLOOM_U {
            let bit_mask = 0x80u8 >> (idx % 8);
            let f0 = flags0[idx / 8] & bit_mask != 0;
            let f1 = flags1[idx / 8] & bit_mask != 0;

            if f0 && f1 {
                // Both flags set: invalid (a word cannot be both all-zero and all-ones)
                return None;
            }
            if f0 {
                bloom.bits[idx] = 0;
            } else if f1 {
                bloom.bits[idx] = !0u64;
            } else {
                // Non-trivial word: read 8 bytes big-endian
                if rest.len() < 8 {
                    return None;
                }
                bloom.bits[idx] = u64::from_be_bytes(rest[..8].try_into().ok()?);
                rest = &rest[8..];
            }
        }

        if !rest.is_empty() {
            // Trailing bytes: invalid
            return None;
        }

        Some(bloom)
    }

    /// Returns the number of bits set in the filter (population count).
    pub fn popcount(&self) -> u32 {
        self.bits.iter().map(|&w| w.count_ones()).sum()
    }

    /// Returns true if the filter is completely empty (all bits zero).
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BloomInfo (per-peer state)
// ============================================================================

/// Per-peer Bloom filter state.
///
/// Each peer has two filters:
/// - `send`: the filter we send to this peer (built from our view of the network)
/// - `recv`: the filter we received from this peer (used to decide whether to forward lookups)
#[derive(Debug)]
pub struct BloomInfo {
    /// The filter we computed for and sent to this peer.
    pub send: BloomFilter,
    /// The filter most recently received from this peer.
    pub recv: BloomFilter,
    /// Sequence number for our send filter (used to detect stale updates).
    pub seq: u16,
    /// Whether this peer is currently "on the spanning tree" (parent or child direction).
    pub on_tree: bool,
    /// Whether the filter is "dirty" (has zero bits where we'd expect ones for the zero filter).
    pub z_dirty: bool,
}

impl BloomInfo {
    /// Create a new, empty BloomInfo for a peer.
    pub fn new() -> Self {
        BloomInfo {
            send: BloomFilter::new(),
            recv: BloomFilter::new(),
            seq: 0,
            on_tree: false,
            z_dirty: false,
        }
    }
}

impl Default for BloomInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_add_test() {
        let mut f = BloomFilter::new();
        f.add(b"hello");
        assert!(f.test(b"hello"));
        // A different key probably isn't in the filter
        // (With 8 hashes and 8192 bits, false positive rate is very low for 1 element)
    }

    #[test]
    fn test_bloom_empty() {
        let f = BloomFilter::new();
        assert!(f.is_empty());
        assert!(!f.test(b"anything"));
    }

    #[test]
    fn test_bloom_merge() {
        let mut f1 = BloomFilter::new();
        let mut f2 = BloomFilter::new();
        f1.add(b"key_a");
        f2.add(b"key_b");

        let mut merged = f1.clone();
        merged.merge(&f2);
        assert!(merged.test(b"key_a"));
        assert!(merged.test(b"key_b"));
    }

    #[test]
    fn test_bloom_encode_decode() {
        let mut f = BloomFilter::new();
        f.add(b"destination_key");
        f.add(b"another_key");

        let mut encoded = Vec::new();
        f.encode(&mut encoded);

        let decoded = BloomFilter::decode(&encoded).unwrap();
        assert_eq!(f, decoded);
    }

    #[test]
    fn test_bloom_encode_empty() {
        let f = BloomFilter::new();
        let mut encoded = Vec::new();
        f.encode(&mut encoded);

        // Empty filter: all 128 words are zero, so flags0 is all 0xFF bytes
        // and no data words are included → total size = 32 bytes
        assert_eq!(encoded.len(), 32);

        let decoded = BloomFilter::decode(&encoded).unwrap();
        assert_eq!(f, decoded);
    }

    #[test]
    fn test_bloom_encode_full() {
        // All-ones filter: flags1 should be all 0xFF, no data words
        let f = BloomFilter { bits: [!0u64; BLOOM_U] };
        let mut encoded = Vec::new();
        f.encode(&mut encoded);
        assert_eq!(encoded.len(), 32); // 16 + 16 + 0 data words

        let decoded = BloomFilter::decode(&encoded).unwrap();
        assert_eq!(f, decoded);
    }

    #[test]
    fn test_bloom_location_formula() {
        // Verify the location formula produces values in [0, BLOOM_M)
        let h = [0xDEADBEEFu64, 0xCAFEBABE, 0x12345678, 0x87654321];
        for i in 0..BLOOM_K as u64 {
            let loc = BloomFilter::location(&h, i);
            assert!(loc < BLOOM_M as usize, "location {} out of range for i={}", loc, i);
        }
    }
}
