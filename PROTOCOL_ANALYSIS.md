# Ironwood / Yggdrasil — Protocol Analysis

Analysis of architectural limitations and improvement directions.
Written after porting both ironwood and yggdrasil-go to Rust (v0.5.13).

---

## Problem 1: Spanning Tree Root — Single Point of Instability

**Current behaviour**: One global root, deterministically elected as the node with
the numerically smallest ed25519 public key. All routing uses this tree.

**Consequences**:
- When the root goes offline, the entire network re-elects. All cached source-routing
  paths that traversed the old root become stale and must be rediscovered.
- The root is effectively a soft target: an adversary can force re-elections by
  making the current root unreachable, or by joining with a smaller key.
- Two nodes that are physically adjacent but on opposite sides of the tree may route
  through the root on the other side of the planet.

**Proposed fix — K parallel spanning trees**:
Each node participates in K independent trees (e.g. K = 3) with different root
selection metrics:
- Tree 0: smallest raw key (current behaviour)
- Tree 1: smallest `XOR(key, H("tree1"))` — Kademlia-style metric
- Tree 2: smallest `XOR(key, H("tree2"))`

Traffic uses the tree where the path cost to the destination is lowest.
Root failure in one tree has no impact on the other two. This approach is
explored in Ironwood v2 and is similar to Babel's multi-topology routing.

Further hardening: rotate tree parameters on a slow timer (e.g. every hour),
so there is no permanent "best key to have" for an adversary.

---

## Problem 2: Greedy Routing Is Not Optimal

**Current behaviour**: The first packet to a new destination travels the spanning
tree (greedy, not shortest path). After `PATH_NOTIFY` returns, subsequent packets
use the discovered source route. But the tree route may be many hops longer than
the physical shortest path.

**Consequences**:
- First-packet latency is bounded by the tree depth, not the graph diameter.
- In a network where nodes are well-connected but have a deep tree, this can be
  2–5× worse than optimal.

**Proposed fix A — Landmark routing**:
A small set of well-connected nodes publish themselves as landmarks (low tree
distance to root, many peers). Every node stores a path to its nearest landmark.
Routing: `source → src_landmark → dst_landmark → destination`.
This gives bounded stretch with a known constant factor.

**Proposed fix B — Hyperbolic geometric routing**:
Each node derives a coordinate in Poincaré disk space from latency measurements
to neighbours (no global information needed). Greedy forwarding in hyperbolic
space has proven near-optimality for tree-like graphs and very high success rates
(>99%) on real Internet topologies. This would eliminate the spanning tree
entirely as a routing mechanism (though it could still be used for bloom multicast).

Reference: Kleinberg 2007, "Geographic Routing Using Hyperbolic Space";
subsequent work on hyperbolic network embedding.

---

## Problem 3: Bloom Filter Scalability

**Current behaviour**: Each node sends its 1024-byte bloom filter to all peers
every ~3600 seconds (or immediately on peer join/leave). Bandwidth cost is
`O(peers × filter_size)` per node, `O(N²)` globally.

**Consequences**:
- At thousands of nodes this is manageable. At millions it becomes a meaningful
  fraction of link bandwidth just for topology maintenance.
- The filter has no deletion support: when a peer leaves, its keys remain set
  until the filter is fully rebuilt and re-sent.

**Proposed fix A — Dirty-flag sends**:
Track a content hash of the local filter. Send only when the hash changes.
In stable networks this reduces bloom traffic to near zero between topology events.
(Implemented in `feature/improvements`.)

**Proposed fix B — Hierarchical filters**:
Group nodes into regions (clusters with high internal connectivity). Within a
region: full bloom exchange. Between regions: one aggregated filter per region.
Path lookup first finds the right region, then the node within it.
Maintenance traffic drops from O(N²) to O(N√N).

**Proposed fix C — Cuckoo filter**:
Replace Bloom with a Cuckoo filter. Key advantage: supports deletion of individual
entries. When a peer disconnects, its keys are removed immediately without
rebuilding the entire filter. Better space efficiency (~1 bit/entry vs ~1.44 for
Bloom at same false-positive rate).
Wire format would change, so this requires a new protocol version.

---

## Problem 4: No Path Quality Feedback

**Current behaviour**: Routing cost = `tree_distance × latency_ms`. Latency is
measured via SigReq/SigRes RTT (spanning tree control plane). Packet loss on the
data plane is not measured or factored into routing decisions.

**Consequences**:
- A link with 10ms RTT but 30% packet loss looks better than a 20ms zero-loss link.
- Path failures are detected only when `PATH_BROKEN` is received — passive,
  not predictive.
- No way to distinguish a congested link from a stable one.

**Proposed fix — Loss-aware routing cost**:
Track per-peer packet loss by monitoring whether keepalives arrive on schedule
(keepalives are sent every 1s, timeout is 3s). Estimate loss rate via EWMA.
Modify cost: `effective_latency = latency_ms × (1 + loss_rate × K)` where K is
a tunable penalty factor (e.g. K = 9 means 100% loss → 10× cost).
Also track RTT jitter as a secondary signal for link quality.
(Implemented in `feature/improvements`.)

---

## Problem 5: No Anonymity

**Current behaviour**: Source and destination ed25519 keys are visible in every
TRAFFIC packet header. Intermediate peers see who is talking to whom.

**Consequences**:
- Yggdrasil is explicitly not an anonymity network, but in practice users sometimes
  expect privacy. The current design provides none at the network layer.
- An attacker positioned on the path sees full communication graphs.

**Proposed fix — Optional onion routing layer**:
An optional protocol extension (negotiated at session setup) where the sender
wraps the packet in 2–3 onion layers. Each layer is encrypted to the next hop's
key. Middle nodes see only previous and next hop, not source or destination.

This is not Tor (no hidden services, no guard nodes) but provides reasonable
unlinkability without a separate infrastructure. The overhead is 3 extra public
keys per packet (~96 bytes) plus 3 extra encryption operations.

---

## Summary Table

| Problem | Severity | Fix Complexity | Effect | Notes |
|---|---|---|---|---|
| Single spanning tree root | High | High | High | Ironwood v2 partially addresses |
| Non-optimal greedy routing | Medium | High | High | Hyperbolic routing is research-grade |
| Bloom filter O(N²) maintenance | Medium | Low–High | Medium–High | Dirty flag is low-hanging fruit |
| No loss-aware routing | Medium | Low | High | Easy win, no wire format change |
| No anonymity | Low | High | High | Different threat model than Yggdrasil's goals |

### What is already implemented in `feature/improvements`

- **Dirty-flag bloom filter**: send immediately on content change, suppress
  redundant periodic sends
- **Packet loss estimation**: EWMA loss rate per peer, based on keepalive
  reception intervals
- **Loss-aware routing cost**: `effective_latency = latency × (1 + loss × 9)`
- **Jitter tracking**: EWMA of |RTT delta|, exposed in PeerStats

---

## If Building a New Protocol

The combination of ideas that would yield the largest improvement with moderate
implementation complexity:

1. **K = 3 parallel spanning trees** (root stability + path diversity)
2. **Hyperbolic coordinate routing** (near-optimal paths, no tree dependency)
3. **Cuckoo filter with dirty-flag multicast** (efficient topology maintenance)
4. **Loss-aware cost with jitter** (self-healing path quality)

Items 1 + 3 + 4 are wire-compatible extensions of Ironwood.
Item 2 replaces the spanning tree entirely and would be a new protocol.

The wire format is clean enough that a v2 protocol could reuse the frame envelope
(uvarint length prefix + type byte) and session encryption layer while replacing
the routing control plane.
