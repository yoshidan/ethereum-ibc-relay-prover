package beacon

import (
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prysmaticlabs/prysm/v5/api/client/builder"
	"github.com/prysmaticlabs/prysm/v5/api/server/structs"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	enginev1 "github.com/prysmaticlabs/prysm/v5/proto/engine/v1"
	types "github.com/prysmaticlabs/prysm/v5/validator/keymanager/remote-web3signer/v1"
)

// Primitives

type Uint64 = builder.Uint64String

// Response types

type GenesisResponse = structs.GetGenesisResponse

type BlockRootResponse struct {
	Data struct {
		Root hexutil.Bytes `json:"root"`
	} `json:"data"`
	ExecutionOptimistic bool `json:"execution_optimistic"`
}

type LightClientHeader struct {
	Beacon             BeaconBlockHeader
	Execution          *ExecutionPayloadHeader // Required for pre-Gloas
	ExecutionBlockHash []byte                  // Required for Gloas+
	ExecutionBranch    []hexutil.Bytes
}

// IsGloas returns true if this header is from Gloas fork or later
func (h *LightClientHeader) IsGloas() bool {
	return h.Execution == nil
}

// GetExecutionRoot returns the execution root (HashTreeRoot for pre-Gloas, BlockHash for Gloas)
func (h *LightClientHeader) GetExecutionRoot() []byte {
	if h.IsGloas() {
		return h.ExecutionBlockHash
	}
	root, err := h.Execution.HashTreeRoot()
	if err != nil {
		panic(err)
	}
	return root[:]
}

func (h *LightClientHeader) UnmarshalJSON(bz []byte) error {
	var hj struct {
		Beacon             types.BeaconBlockHeader              `json:"beacon"`
		Execution          *builder.ExecutionPayloadHeaderDeneb `json:"execution,omitempty"`
		ExecutionBlockHash hexutil.Bytes                        `json:"execution_block_hash,omitempty"`
		ExecutionBranch    []hexutil.Bytes                      `json:"execution_branch"`
	}
	if err := json.Unmarshal(bz, &hj); err != nil {
		return err
	}
	slot, err := strconv.Atoi(hj.Beacon.Slot)
	if err != nil {
		return err
	}
	proposerIndex, err := strconv.Atoi(hj.Beacon.ProposerIndex)
	if err != nil {
		return err
	}
	h.Beacon = BeaconBlockHeader{
		Slot:          primitives.Slot(slot),
		ProposerIndex: primitives.ValidatorIndex(proposerIndex),
		ParentRoot:    hj.Beacon.ParentRoot,
		StateRoot:     hj.Beacon.StateRoot,
		BodyRoot:      hj.Beacon.BodyRoot,
	}
	h.ExecutionBranch = hj.ExecutionBranch
	if hj.ExecutionBlockHash != nil {
		// Gloas format
		h.ExecutionBlockHash = hj.ExecutionBlockHash
	} else if hj.Execution != nil {
		// Pre-Gloas format
		h.Execution = &enginev1.ExecutionPayloadHeaderDeneb{
			ParentHash:       hj.Execution.ParentHash,
			FeeRecipient:     hj.Execution.FeeRecipient,
			StateRoot:        hj.Execution.StateRoot,
			ReceiptsRoot:     hj.Execution.ReceiptsRoot,
			LogsBloom:        hj.Execution.LogsBloom,
			PrevRandao:       hj.Execution.PrevRandao,
			BlockNumber:      uint64(hj.Execution.BlockNumber),
			GasLimit:         uint64(hj.Execution.GasLimit),
			GasUsed:          uint64(hj.Execution.GasUsed),
			Timestamp:        uint64(hj.Execution.Timestamp),
			ExtraData:        hj.Execution.ExtraData,
			BaseFeePerGas:    hj.Execution.BaseFeePerGas.SSZBytes(),
			BlockHash:        hj.Execution.BlockHash,
			TransactionsRoot: hj.Execution.TransactionsRoot,
			WithdrawalsRoot:  hj.Execution.WithdrawalsRoot,
			BlobGasUsed:      uint64(hj.Execution.BlobGasUsed),
			ExcessBlobGas:    uint64(hj.Execution.ExcessBlobGas),
		}
	}
	return nil
}

type LightClientBootstrapResponse struct {
	Data    LightClientBootstrap `json:"data"`
	Version string               `json:"version"`
}

type LightClientBootstrap struct {
	Header                     LightClientHeader `json:"header"`
	CurrentSyncCommittee       SyncCommittee     `json:"current_sync_committee"`
	CurrentSyncCommitteeBranch []hexutil.Bytes   `json:"current_sync_committee_branch"`
}

type LightClientUpdateResponse struct {
	Version string                `json:"version"`
	Data    LightClientUpdateData `json:"data"`
}

type LightClientUpdatesResponse = []LightClientUpdateResponse

type LightClientUpdateData struct {
	AttestedHeader          LightClientHeader `json:"attested_header"`
	NextSyncCommittee       SyncCommittee     `json:"next_sync_committee"`
	NextSyncCommitteeBranch []hexutil.Bytes   `json:"next_sync_committee_branch"`
	FinalizedHeader         LightClientHeader `json:"finalized_header"`
	FinalityBranch          []hexutil.Bytes   `json:"finality_branch"`
	SyncAggregate           SyncAggregate     `json:"sync_aggregate"`
	SignatureSlot           Uint64            `json:"signature_slot"`
}

type LightClientFinalityUpdateResponse struct {
	Data    LightClientFinalityUpdate `json:"data"`
	Version string                    `json:"version"`
}

type LightClientFinalityUpdate struct {
	AttestedHeader  LightClientHeader `json:"attested_header"`
	FinalizedHeader LightClientHeader `json:"finalized_header"`
	FinalityBranch  []hexutil.Bytes   `json:"finality_branch"`
	SyncAggregate   SyncAggregate     `json:"sync_aggregate"`
	SignatureSlot   Uint64            `json:"signature_slot"`
}

type StateFinalityCheckpointResponse = structs.GetFinalityCheckpointsResponse

type SyncAggregate struct {
	SyncCommitteeBits      hexutil.Bytes `json:"sync_committee_bits"`
	SyncCommitteeSignature hexutil.Bytes `json:"sync_committee_signature"`
}

type SyncCommittee struct {
	PubKeys         []hexutil.Bytes `json:"pubkeys"`
	AggregatePubKey hexutil.Bytes   `json:"aggregate_pubkey"`
}
