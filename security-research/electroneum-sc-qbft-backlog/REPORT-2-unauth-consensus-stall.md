# Unauthenticated peer stalls the QBFT consensus loop — block production degrades from 2ms to 9.4s

## Summary

Any peer that completes a p2p handshake can stall a validator's consensus event
loop. `eth/handler.go` derives a peer address from its enode public key and hands
consensus frames to `Backend.HandleMsg` without ever checking that peer against
the validator set, and `core.handleEncodedMsg` runs `qbfttypes.Decode` **before**
`c.verifySignatures`. A 10 MiB frame — the transport cap — decodes into 1,048,517
transactions, costing 1.5–3.0s of single-threaded CPU and a deterministic 400 MiB
of allocation before anything checks who sent it. `HandleMsg` holds `sb.coreMu` and posts
synchronously to a single `handleEvents` goroutine, so that work is serialised
against all real consensus traffic. One unauthenticated peer takes block
production from 2ms to 7.6–9.4s, against a configured `BlockPeriod` of 5s.

## Setup

- electroneum-sc at commit `17c6ffe` (HEAD of `master` at time of testing)
- Go 1.19+ and `git`
- ~2 GB free RAM
- **No key of any kind.** The attacker is not a validator and holds no validator
  material. It only needs to be a connected peer.
- Attached: `electroneum-qbft-backlog-poc.zip`

Runs against a local in-memory test chain. No Electroneum host is contacted.

## Steps to reproduce

1. Unpack and run the escalation steps:

   ```bash
   unzip electroneum-qbft-backlog-poc.zip
   cd electroneum-qbft-backlog-poc
   ./reproduce.sh --unauth
   ```

2. Confirm there is no authorisation gate on the path. `eth/handler.go:862`:

   ```go
   func (h *handler) handleConsensusMsg(p *p2p.Peer, msg p2p.Msg) (bool, error) {
       if handler, ok := h.engine.(consensus.Handler); ok {
           pubKey := p.Node().Pubkey()
           addr := crypto.PubkeyToAddress(*pubKey)
           handled, err := handler.HandleMsg(addr, msg)
   ```

   `addr` comes from the peer's own enode key. Inside `Backend.HandleMsg` it is
   used only to key the `recentMessages` LRU — it is never compared to the
   validator set. The frame is posted to the consensus mux regardless.

3. Confirm the decode precedes authentication. `consensus/istanbul/core/handler.go`:

   ```go
   m, err := qbfttypes.Decode(code, data)   // full RLP decode of attacker bytes
   if err != nil { ... }
   if err = c.verifySignatures(m); err != nil {   // signature checked only now
   ```

   The 4 MiB `MaxFuturePreprepareBytes` ceiling lives in `addToBacklog`, which is
   downstream of both.

4. **Step A of the run** measures what one frame costs before any check:

   ```
   frame  4.00 MiB ->  419371 txs decoded in  943ms,   161.16 MiB allocated
   frame 10.00 MiB -> 1048517 txs decoded in 2.977s,   400.08 MiB allocated
   ```

   10 MiB is `protocolMaxMsgSize` in `eth/handler.go:54`, so 10 MiB frames are
   accepted off the wire. Decode time is CPU-bound and varies with the host —
   across three runs on a 4-core container the 10 MiB frame took 1.529s to 2.977s. The
   400 MiB allocation figure is deterministic.

5. **Step B** measures consensus ingress stall. A real 4-validator `Backend` on a
   real chain; a non-validator peer streams 10 MiB frames while a legitimate
   validator's frame is timed. `HandleMsg` returns only once the single consumer
   accepts the event, so its latency is the ingress stall.

   ```
   === UNAUTHENTICATED PEER STALLS CONSENSUS INGRESS ===
     attacker      : 0x8cd42fe102 (NOT a validator; never checked)
     frame size    : 10 MiB (eth/handler.go protocolMaxMsgSize)
     BlockPeriod   : 5s     RequestTimeout: 10s
     legit frame, loop idle: 2.416ms

     frames   wire sent    legit frame    vs idle
     2        20 MiB       4.037s         x2295
     4        40 MiB       5.192s         x2952
     8        80 MiB       4.452s         x2531
   ```

   The stall plateaus rather than growing linearly, because Go's mutex starvation
   mode eventually hands `coreMu` to the waiting caller. The plateau is the
   point: every legitimate consensus frame is delayed for as long as the attack
   runs. Absolute latency is hardware dependent — across runs the plateau sat
   between 3.7s and 7.1s — so the test asserts on the ratio to an idle loop,
   which held between x2295 and x3416.

6. **Step C** measures the metric that matters — actual block production. A
   single-validator chain (the `TestSealCommitted` pattern) drives a full QBFT
   round through the same `handleEvents` goroutine:

   ```
   === BLOCK PRODUCTION UNDER UNAUTHENTICATED FLOOD ===
     BlockPeriod configured : 5s
     seal, no attacker      : 2ms
     seal, one unauth peer  : 9.431s
     degradation            : x5766.1
   ```

   Observed 7.63s, 7.739s and 9.431s across three runs; all well above the 5s `BlockPeriod`.

7. **Step D** confirms ROUND-CHANGE carries the same payload. It embeds
   `PreparedBlock *types.Block`, and `RoundChange.DecodeRLP` materialises the
   whole block before comparing `PreparedBlock.Hash()` to `PreparedDigest`:

   ```
   === ROUND-CHANGE CARRIES THE SAME PAYLOAD ===
     frame        : 10.00 MiB ROUND-CHANGE with a PreparedBlock
     decode result: failed to decode ROUND-CHANGE message
     time         : 1.605s
     allocated    : 400.11 MiB before the digest check rejected it
   ```

   The frame does not even have to be well-formed — the cost is paid on the
   rejection path.

## Impact

One unauthenticated peer takes a validator's block production from 2ms to
7.6–9.4s, against a configured `BlockPeriod` of 5s, and delays every legitimate
consensus frame by seconds — 3.7s to 7.1s across runs, x2295 to x3416 versus an
idle loop — for as long as it keeps sending. The cost per frame is 1.5–3.0s of
single-threaded CPU and 400 MiB of allocation, paid before the node knows who
sent it, and it is serialised behind `sb.coreMu` and a single `handleEvents`
goroutine — so one peer's frames block consensus traffic from every other peer.
The attacker holds no key and is in no validator set; it only has to be
connected. Both block-bearing message codes work, and ROUND-CHANGE does not need
to be well-formed.

Measured on a live node: decode cost, ingress latency, and seal time, each with
an idle baseline. Wall-clock figures are CPU-bound and move with the host, so
ranges are given from repeated runs on a 4-core container; the allocation figure
and the ratio to an idle loop are the stable ones. I did not run a multi-node
devnet, so I have not shown a chain
halt or a round-change cascade — the numbers above are single-node block
production and ingress latency.

## Root cause

`eth/handler.go:862` `handleConsensusMsg` passes every consensus frame to
`Backend.HandleMsg` with an address derived from the peer's enode key and no
validator-set check, and `consensus/istanbul/core/handler.go` calls
`qbfttypes.Decode` before `c.verifySignatures`. So an unbounded RLP decode of
attacker-controlled bytes runs, at up to `protocolMaxMsgSize` (10 MiB), on the
single consensus goroutine, for a message that is then discarded.

Fix: reject consensus frames from peers that are not in the current validator set
before reading the payload, and bound the decode itself — the per-message ceiling
belongs in front of `qbfttypes.Decode`, not in `addToBacklog` behind it. Moving
the existing `MaxFuturePreprepareBytes` check to the ingress would cap a frame at
4 MiB instead of 10 MiB, roughly halving the per-frame decode cost; the validator-set check removes the
unauthenticated path entirely.
