# Unmetered priority-transactor registry re-read: a 21,000-gas failed transfer forces every node to do arbitrary uncharged work

## Summary

Any transaction whose `To` field equals the priority-transactor registry address
makes every node re-read the registry, and none of that work is charged to
anything. The trigger needs no calldata, no privileges, and does not even need to
succeed — a plain 21,000-gas transfer that runs out of gas still fires it. The
re-read re-parses the contract ABI from JSON on every call and then runs an EVM
static call with a 2^63-1 gas budget, followed by a secp256k1 on-curve check per
registered transactor. A full 30,000,000-gas block of these costs 16ms of
execution normally and 5.1s with 1024 transactors registered — same gas, same
block limit. The proposer pays it twice.

## Setup

- electroneum-sc at commit `17c6ffe` (HEAD of `master` at time of testing)
- Go 1.19+ and `git`
- No keys, no privileges. Any account that can pay 21,000 gas.
- The registry address is chain config: mainnet
  `0x92cdf1fc0e54d3150f100265ae2717b0689660ee` (`params/config.go:75`),
  stagenet `0x1ef0959497375a7539e487749584aeb4947b7a90` (`params/config.go:143`).

The PoC runs entirely against a local in-memory chain. No Electroneum host was
contacted, and the live registry was not queried.

## Steps to reproduce

1. Install the PoC into a clean clone and run it:

   ```bash
   git clone https://github.com/electroneum/electroneum-sc.git && cd electroneum-sc
   git checkout 17c6ffe
   cp <this>/poc/zz_registry_amp_test.go core/
   cp <this>/poc/zz_api_panic_test.go   consensus/istanbul/backend/

   go test ./core/ -run TestRegistryRefresh_UnmeteredAmplification -v
   go test ./core/ -run TestRegistryRefresh_FullBlockImpact -v          # ~50s
   ```

2. The harness deploys a contract at the configured registry address whose
   `getTransactors()` returns N entries, and deploys **byte-for-byte identical
   code at a second, non-registry address** (`decoyAddr`). Both blocks then send
   the same 21,000-gas transfers to their respective contracts, so both execute
   the same EVM code for the same gas. The only difference left between the two
   measurements is the registry refresh.

3. `TestRegistryRefresh_UnmeteredAmplification` — 400 transfers per block:

   ```
   registry               to-decoy     to-registry  factor    gas (both)
   not deployed           3.705ms      4.665ms      x1.3      8400000
   0 transactors          4.64ms       27.259ms     x5.9      8400000
   16 transactors         4.46ms       60.956ms     x13.7     8400000
   64 transactors         4.379ms      145.696ms    x33.3     8400000
     ^ triggering txs that FAILED (out of gas): 400/400 - the refresh runs anyway
   256 transactors        5.023ms      446.768ms    x88.9     8400000
   1024 transactors       7.316ms      1.481129s    x202.5    8400000
   ```

   `usedGas` is identical (8,400,000) on every row. The test asserts this, so if
   the work were ever metered the test would fail.

   Note the `0 transactors` row: an **empty** registry still costs x5.9, because
   `abi.JSON(strings.NewReader(...))` re-parses the whole contract ABI on every
   single invocation (`core/prioritytransactors.go:47`). That part is independent
   of how many transactors exist.

   Note also the `not deployed` row: with no code at the address the function
   returns early (`core/prioritytransactors.go:42-45`), so the attack needs the
   registry to actually be deployed.

4. `TestRegistryRefresh_FullBlockImpact` — a full 30M-gas block, 1428 transfers,
   which is what an attacker actually sends:

   ```
   registry           to-decoy     attack block   factor    vs 5s period
   16 transactors     12ms         216ms          x17.7     -
   64 transactors     14ms         487ms          x34.6     -
   256 transactors    15ms         1.546s         x103.9    >1s
   1024 transactors   16ms         5.145s         x317.3    EXCEEDS BlockPeriod
   ```

   Reference points are QBFT's own parameters: `BlockPeriod` 5s and
   `RequestTimeoutSeconds` 10s (`consensus/istanbul/config.go:133-140`).

5. Secondary, unrelated to the above — `istanbul_getBaseBlockReward(0)` panics:

   ```bash
   go test ./consensus/istanbul/backend/ -run TestGetBaseBlockReward_GenesisUnderflow -v
   ```

   ```
   === istanbul_getBaseBlockReward(0) PANICS ===
     panic: Failed to get next base block reward: unknown ancestor
     header.Number=0 -> Uint64()-1 underflows to 18446744073709551615
   ```

   `api.go:285` only rejects block numbers *above* the head, so 0 is accepted.
   `engine.go:283` then computes `header.Number.Uint64()-1`, which underflows on
   the genesis header, and `engine.go:284-286` panics on the resulting error
   instead of returning it.

## Impact

One account, paying one block's worth of base fee, makes every node on the
network spend 5.1 seconds executing a single block instead of 16ms, at 1024
registered transactors — past the 5s target block interval. At 256 transactors
it is 1.5s per block, roughly a third of the block period. The transactions are
plain transfers that all fail out of gas; the attacker buys the work at
21,000 gas each and the node performs it regardless of the receipt status. The
block producer pays it twice, because `miner/worker.go:953` refreshes again on
top of the refresh already done inside `core.ApplyTransaction`.

Measured on a local chain with an identical-code control at a non-registry
address, so the figure isolates the refresh rather than the contract call.

Honest limits on this. It is **not** a consensus divergence — every node does the
same work and reaches the same state, so no chain split. The multiplier is linear
in the number of registered transactors, which the attacker does not control; I
did not query the live registry, so I cannot say where mainnet sits on that
table today. What is fixed regardless of registry size is the x5.9 floor from the
per-call ABI re-parse. And the attacker does pay ordinary gas for each block —
unless they hold, or replay onto, a gas-price-waived priority key, in which case
`buyGas` charges them nothing (`core/state_transition.go:196-216`, gasPrice is 0).

## Root cause

`core/state_processor.go:160-164` refreshes the priority-transactor map on a
condition that only looks at the destination address:

```go
if msg.To() != nil && *msg.To() == config.GetPriorityTransactorsContractAddress(blockNumber) {
    statedb.SetPriorityTransactors(GetPriorityTransactors(evm))
}
```

There is no check that the transaction succeeded, carried any calldata, or wrote
to the registry at all. The work it triggers is unbounded and uncharged:
`core/prioritytransactors.go:47` re-parses the ABI JSON per call,
`core/prioritytransactors.go:63` runs `evm.StaticCall(..., params.MaxGasLimit)`
with `MaxGasLimit = 0x7fffffffffffffff` (`params/protocol_params.go:24`) so it can
never run out of gas, and `core/prioritytransactors.go:90-131` then does a
`FromHex`, an all-zero scan and a secp256k1 `IsValid()` per entry. None of it
touches `st.gp`, `*usedGas`, or the transaction's own gas.

Fix: gate the refresh on the transaction having actually changed the registry
rather than merely being addressed to it — a successful receipt plus non-empty
calldata at minimum, or better, a dirty-check on the registry account's storage
root before and after the transaction. Cache the parsed ABI in a package-level
`sync.Once` instead of re-parsing per call. Bound the static call with a fixed,
sane gas cap rather than `MaxGasLimit`, and bound the number of transactor
entries decoded.

For the RPC panic: reject block 0 in `GetBaseBlockReward`, or return the error
instead of panicking.
