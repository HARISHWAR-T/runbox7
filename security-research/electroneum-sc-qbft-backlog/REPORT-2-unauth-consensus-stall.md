# Unauthenticated peers stall the QBFT consensus loop past the round timeout — 8 keyless peers delay consensus frames 15.7s against a 10s RequestTimeout

## Summary

Any peer that completes the standard eth handshake can stall a validator's
consensus event loop, with no validator key, no stake, and no allowlist entry.
`eth/handler.go` derives a peer address from its enode public key and hands
consensus frames to `Backend.HandleMsg` without ever checking that peer against
the validator set, and `core.handleEncodedMsg` runs `qbfttypes.Decode` **before**
`c.verifySignatures`. A 10 MiB frame — the transport cap — decodes into 1,048,517
transactions before anything checks who sent it. `HandleMsg` holds `sb.coreMu`
for its whole body and posts synchronously to a single `handleEvents` goroutine,
so that work serialises against all real consensus traffic. Eight unauthenticated
peers delay a legitimate validator's consensus frame by 15.7–16.7s, against a
configured `BlockPeriod` of 5s and a `RequestTimeoutSeconds` of 10s.

## Relationship to 8219bb7 and PR #82

Both existing fixes are correct. Neither addresses this.

**8219bb7** ("deliver consensus messages synchronously to apply backpressure")
replaced a detached `go Post` at this ingress because it let a peer accumulate
unbounded blocked goroutines that each pinned a payload in heap until the node
OOMed. That was right, and the synchronous Post is the correct shape. It moved
the cost from memory to latency: the ingress now applies backpressure, which is
precisely the head-of-line blocking exploited here. The pre-fix and post-fix code
share the actual defect — neither authenticates the peer or bounds the payload
before decoding it. Reverting 8219bb7 would not fix this; it would restore the
memory bug alongside it.

**PR #82** added `MaxFuturePreprepareBytes` (4 MiB per block-bearing message).
That ceiling lives inside `addToBacklog`, which is downstream of the decode, so
it bounds what is *retained* and not what is *parsed*. A 10 MiB frame is decoded
in full and only then measured against it.

The fix for 8219bb7's bug, the fix for #82's bug, and the fix for this one are
three different changes to three different lines.

## Setup

- electroneum-sc at commit `17c6ffe` (HEAD of `master` at time of testing)
- Go 1.19+ and `git`
- ~2 GB free RAM
- **No key of any kind.** The attacker is not a validator and holds no validator
  material. It only needs to be a connected peer.
- Attached: `electroneum-qbft-backlog-poc.zip`

Runs against a local in-memory test chain. No Electroneum host was contacted at
any point, including to test reachability.

## Steps to reproduce

1. Unpack and run the escalation steps:

   ```bash
   unzip electroneum-qbft-backlog-poc.zip
   cd electroneum-qbft-backlog-poc
   ./reproduce.sh --unauth
   ```

2. Confirm the consensus subprotocol is offered to any peer. `eth/handler.go:775`,
   the `Run` handler for `istanbul/100`:

   ```go
   Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
       select {
       case <-p.EthPeerRegistered:
           ...
           ethPeer.AddConsensusProtoRW(rw)
           return h.handleConsensusLoop(p, rw)
   ```

   The only gate is `EthPeerRegistered` — the peer completed the ordinary eth
   handshake and was added to the peerset. There is no allowlist, no
   validator-set check, and no static-peer requirement. Every frame that loop
   reads goes to `HandleMsg`.

3. Confirm there is no authorisation check on the frame. `eth/handler.go:862`:

   ```go
   func (h *handler) handleConsensusMsg(p *p2p.Peer, msg p2p.Msg) (bool, error) {
       if handler, ok := h.engine.(consensus.Handler); ok {
           pubKey := p.Node().Pubkey()
           addr := crypto.PubkeyToAddress(*pubKey)
           handled, err := handler.HandleMsg(addr, msg)
   ```

   `addr` comes from the peer's own enode key. Inside `Backend.HandleMsg` it is
   used only to key the `recentMessages` LRU — it is never compared to the
   validator set.

4. Confirm the decode precedes authentication.
   `consensus/istanbul/core/handler.go`:

   ```go
   m, err := qbfttypes.Decode(code, data)   // full RLP decode of attacker bytes
   if err != nil { ... }
   if err = c.verifySignatures(m); err != nil {   // signature checked only now
   ```

5. **Step A** measures what one frame costs before any check:

   ```
   frame  4.00 MiB ->  419371 txs decoded in  943ms,   161.16 MiB allocated
   frame 10.00 MiB -> 1048517 txs decoded in 2.977s,   400.08 MiB allocated
   ```

   10 MiB is `protocolMaxMsgSize` (`eth/handler.go:54`), so 10 MiB frames are
   accepted off the wire. Decode time is CPU-bound and moves with the host —
   across three runs on a 4-core container the 10 MiB frame took 1.529s to
   2.977s. The 400 MiB allocation figure is deterministic.

6. **Step B** measures consensus ingress stall from a single peer. `HandleMsg`
   returns only once the single consumer accepts the event, so its latency for a
   legitimate validator's frame is the ingress stall.

   ```
   legit frame, loop idle: 2.198ms

   frames   wire sent    legit frame    vs idle
   2        20 MiB       4.037s         x2295
   4        40 MiB       5.192s         x2952
   8        80 MiB       4.452s         x2531
   ```

   3.7–7.1s across three runs, against a 5s `BlockPeriod`. The stall plateaus
   rather than growing with frame count, because Go's mutex switches to FIFO
   handoff after ~1ms of contention — one peer means the victim waits behind
   roughly one frame. The ratio to an idle loop (x2295–x3416) is quoted only
   because it is the stable figure across hosts; the absolute latency against
   the protocol's own thresholds is the claim.

7. **Step C** measures block production on a single-validator chain (the
   `TestSealCommitted` pattern), which drives a full QBFT round through the same
   `handleEvents` goroutine:

   ```
   BlockPeriod configured : 5s
   seal, no attacker      : 2ms
   seal, one unauth peer  : 9.431s
   ```

   7.63s, 7.739s and 9.431s across three runs — every one above the 5s
   `BlockPeriod`, from a single attacking peer.

8. **Step E — the round timeout.** Peers are the lever the plateau in step B
   leaves open: each additional peer is another position in the `coreMu` queue,
   and peers cost nothing.

   ```
   node under attack : 0x2b4846B993 (4-validator set, IsProposer=true)
   honest sender     : 0x76DA6451b1 (real validator)
   BlockPeriod       : 5s   (target block interval)
   RequestTimeout    : 10s  (QBFT round timeout)
   legit frame, idle : 2.062ms

   peers    legit frame    vs BlockPeriod vs RequestTimeout
   1        5.209s         EXCEEDED       -
   2        4.849s         -              -
   4        8.803s         EXCEEDED       -
   8        14.844s        EXCEEDED       EXCEEDED
   ```

   Five runs at 8 peers: **16.702s / 15.7s / 15.996s / 15.47s / 14.844s** — the
   round timeout is crossed every time. The 1–4 peer rows are noisy (a 2-peer run came in at
   4.914s, just under `BlockPeriod`); the 8-peer result is the stable one and is
   what the claim rests on.

9. **Step D** confirms ROUND-CHANGE carries the same payload, so round-change
   traffic feeds the same stall. `RoundChange.DecodeRLP` materialises
   `PreparedBlock` in full and only then compares its hash to `PreparedDigest`:

   ```
   frame        : 10.00 MiB ROUND-CHANGE with a PreparedBlock
   decode result: failed to decode ROUND-CHANGE message
   time         : 1.605s
   allocated    : 400.11 MiB before the digest check rejected it
   ```

   The frame does not have to be well-formed — the cost is paid on the rejection
   path.

## Impact

Eight peers holding no key and no validator-set membership delay a validator's
legitimate consensus frames by 14.8–16.7s across five runs, past the 10s
`RequestTimeoutSeconds` that bounds a QBFT round, and one such peer alone takes block production from 2ms
to 7.6–9.4s against a 5s `BlockPeriod`. Each frame costs 1.5–3.0s of
single-threaded CPU and 400 MiB of allocation, paid before the node knows who
sent it.

The node under attack is a validator; whether it is also the round's proposer
varies per run, because the harness generates fresh keys each time. The run
prints `IsProposer` rather than assuming it, and the round timeout was crossed
with it both `true` and `false`. The attack does not depend on the target's role —
it stalls that node's consensus ingress, and every validator has to PREPARE and
COMMIT for a round to close.

Adding cores does not help: the work is serialised behind one `sb.coreMu` and one
`handleEvents` goroutine, so a 16-core validator has exactly the same single-lane
ingress as a 4-core one. Validator-set size does not help either — the stall is a
per-node property of that one goroutine and mutex, so it is unchanged by how many
validators exist, and an attacker connects to every validator in parallel at no
extra cost. Both block-bearing message codes work, and ROUND-CHANGE does not even
need to be well-formed.

What is measured: decode cost, ingress latency, and seal time on a live node,
each against an idle baseline, with wall-clock figures given as ranges from
repeated runs because they are CPU-bound. What is **not** measured: I did not
observe a round actually failing to complete. Step C's chain is single-validator
and Step E's node is not exchanging messages with peer validators, so an isolated
node fires its round-change timer regardless of any attack — observing a
ROUND-CHANGE in this harness would prove nothing. That a frame arriving after the
round timer has expired is too late for its round follows from `core.go:303`
(`sendEvent(timeoutEvent{})` → `handleTimeoutMsg` → `startNewRound` →
`broadcastRoundChange`), but it is read from the code, not demonstrated. A
multi-node devnet where rounds otherwise complete is what would close that gap,
and I have not run one.

## Root cause

`eth/handler.go:775` offers the `istanbul/100` subprotocol to any peer that
completes the eth handshake, `eth/handler.go:862` passes every frame it reads to
`Backend.HandleMsg` with an address derived from the peer's own enode key and no
validator-set check, and `consensus/istanbul/core/handler.go` calls
`qbfttypes.Decode` before `c.verifySignatures`. So an unbounded RLP decode of
attacker-controlled bytes runs, at up to `protocolMaxMsgSize` (10 MiB), on the
single consensus goroutine, for a message that is then discarded.

Fix: reject consensus frames from peers outside the current validator set before
reading the payload, and bound the decode itself — the per-message ceiling
belongs in front of `qbfttypes.Decode`, not behind it in `addToBacklog`. Moving
the existing `MaxFuturePreprepareBytes` check to the ingress would cap a frame at
4 MiB instead of 10 MiB, roughly halving the per-frame decode cost; the
validator-set check removes the unauthenticated path entirely.
