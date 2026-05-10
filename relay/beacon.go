package relay

import (
	"context"
	"fmt"

	"github.com/datachainlab/ethereum-light-client-types/relayer/beacon"
	lcrelay "github.com/datachainlab/ethereum-light-client-types/relayer/relay"
	lctypes "github.com/datachainlab/ethereum-light-client-types/relayer/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func (pr *Prover) secondsPerSlot() uint64 {
	return lcrelay.SecondsPerSlot(pr.config.Network)
}

func (pr *Prover) slotsPerEpoch() uint64 {
	return lcrelay.SlotsPerEpoch(pr.config.Network)
}

func (pr *Prover) epochsPerSyncCommitteePeriod() uint64 {
	return lcrelay.EpochsPerSyncCommitteePeriod(pr.config.Network)
}

// returns the first slot of the period
func (pr *Prover) getPeriodBoundarySlot(period uint64) uint64 {
	return period * pr.epochsPerSyncCommitteePeriod() * pr.slotsPerEpoch()
}

func (pr *Prover) computeSyncCommitteePeriod(epoch uint64) uint64 {
	return epoch / pr.epochsPerSyncCommitteePeriod()
}

func (pr *Prover) computeEpoch(slot uint64) uint64 {
	return slot / pr.slotsPerEpoch()
}

func (pr *Prover) getSlotAtTimestamp(ctx context.Context, timestamp uint64) (uint64, error) {
	genesis, err := pr.beaconClient.GetGenesis(ctx)
	if err != nil {
		return 0, err
	}
	if timestamp < genesis.GenesisTimeSeconds {
		return 0, fmt.Errorf("computeSlotAtTimestamp: timestamp is smaller than genesisTime: timestamp=%v genesisTime=%v", timestamp, genesis.GenesisTimeSeconds)
	} else if (timestamp-genesis.GenesisTimeSeconds)%pr.secondsPerSlot() != 0 {
		return 0, fmt.Errorf("computeSlotAtTimestamp: timestamp is not multiple of secondsPerSlot: timestamp=%v secondsPerSlot=%v genesisTime=%v", timestamp, pr.secondsPerSlot(), genesis.GenesisTimeSeconds)
	}
	slotsSinceGenesis := (timestamp - genesis.GenesisTimeSeconds) / pr.secondsPerSlot()
	return lcrelay.GENESIS_SLOT + slotsSinceGenesis, nil
}

// returns a period corresponding to a given execution block number
func (pr *Prover) getPeriodWithBlockNumber(ctx context.Context, blockNumber uint64) (uint64, error) {
	timestamp, err := pr.chain.Timestamp(ctx, pr.newHeight(int64(blockNumber)))
	if err != nil {
		return 0, err
	}
	slot, err := pr.getSlotAtTimestamp(ctx, uint64(timestamp.Unix()))
	if err != nil {
		return 0, err
	}
	return pr.computeSyncCommitteePeriod(pr.computeEpoch(slot)), nil
}

func (pr *Prover) buildExecutionUpdate(executionHeader *beacon.ExecutionPayloadHeader) (*lctypes.ExecutionUpdate, error) {
	stateRootBranch, err := lcrelay.GenerateExecutionPayloadHeaderProof(executionHeader, lcrelay.EXECUTION_STATE_ROOT_LEAF_INDEX)
	if err != nil {
		return nil, err
	}
	blockNumberBranch, err := lcrelay.GenerateExecutionPayloadHeaderProof(executionHeader, lcrelay.EXECUTION_BLOCK_NUMBER_LEAF_INDEX)
	if err != nil {
		return nil, err
	}
	blockHashBranch, err := lcrelay.GenerateExecutionPayloadHeaderProof(executionHeader, lcrelay.EXECUTION_BLOCK_HASH_LEAF_INDEX)
	if err != nil {
		return nil, err
	}
	return &lctypes.ExecutionUpdate{
		StateRoot:         executionHeader.StateRoot,
		StateRootBranch:   stateRootBranch,
		BlockNumber:       executionHeader.BlockNumber,
		BlockNumberBranch: blockNumberBranch,
		BlockHash:         executionHeader.BlockHash,
		BlockHashBranch:   blockHashBranch,
	}, nil
}

// buildExecutionUpdateFromBlockHash fetches the block header from execution layer
// using debug_getRawHeader and builds ExecutionUpdate for Gloas fork
func (pr *Prover) buildExecutionUpdateFromBlockHash(ctx context.Context, blockHash []byte) (*lctypes.ExecutionUpdate, uint64, error) {
	hash := common.BytesToHash(blockHash)

	// Fetch RLP-encoded header via debug_getRawHeader
	rlpHeader, err := pr.getRawHeader(ctx, hash)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get raw header: %w", err)
	}

	// Decode RLP to extract state_root and block_number
	header := new(types.Header)
	if err := rlp.DecodeBytes(rlpHeader, header); err != nil {
		return nil, 0, fmt.Errorf("failed to decode RLP header: %w", err)
	}

	// For Gloas, we use RLP verification instead of SSZ merkle proofs
	// The verifier will check: keccak256(rlp) == execution_block_hash
	return &lctypes.ExecutionUpdate{
		StateRoot:   header.Root.Bytes(),
		BlockNumber: header.Number.Uint64(),
		Rlp:         rlpHeader,
	}, header.Time, nil
}

// getRawHeader fetches RLP-encoded block header via debug_getRawHeader
func (pr *Prover) getRawHeader(ctx context.Context, blockHash common.Hash) ([]byte, error) {
	var result hexutil.Bytes
	err := pr.executionClient.Raw().CallContext(
		ctx, &result, "debug_getRawHeader", blockHash,
	)
	if err != nil {
		return nil, err
	}
	return result, nil
}
