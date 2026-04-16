package beacon

import (
	"encoding/json"
	"strconv"

	"github.com/OffchainLabs/prysm/v7/api/client/builder"
	"github.com/OffchainLabs/prysm/v7/api/server/structs"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// beaconBlockHeaderJSON is used for JSON unmarshaling of beacon block headers
type beaconBlockHeaderJSON struct {
	Slot          string        `json:"slot"`
	ProposerIndex string        `json:"proposer_index"`
	ParentRoot    hexutil.Bytes `json:"parent_root"`
	StateRoot     hexutil.Bytes `json:"state_root"`
	BodyRoot      hexutil.Bytes `json:"body_root"`
}

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
	Beacon          BeaconBlockHeader
	Execution       ExecutionPayloadHeader
	ExecutionBranch []hexutil.Bytes
}

func (h *LightClientHeader) UnmarshalJSON(bz []byte) error {
	type LightClientHeaderJSON struct {
		Beacon          beaconBlockHeaderJSON            `json:"beacon"`
		Execution       structs.ExecutionPayloadHeaderDeneb `json:"execution"`
		ExecutionBranch []hexutil.Bytes                  `json:"execution_branch"`
	}

	var hj LightClientHeaderJSON
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

	// Convert structs.ExecutionPayloadHeaderDeneb to ExecutionPayloadHeader
	execution, err := hj.Execution.ToConsensus()
	if err != nil {
		return err
	}

	*h = LightClientHeader{
		Beacon: BeaconBlockHeader{
			Slot:          primitives.Slot(slot),
			ProposerIndex: primitives.ValidatorIndex(proposerIndex),
			ParentRoot:    hj.Beacon.ParentRoot,
			StateRoot:     hj.Beacon.StateRoot,
			BodyRoot:      hj.Beacon.BodyRoot,
		},
		Execution:       *execution,
		ExecutionBranch: hj.ExecutionBranch,
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

// BeaconBlockResponse is the response from GET /eth/v2/beacon/blocks/{block_id}
type BeaconBlockResponse struct {
	Version             string          `json:"version"`
	ExecutionOptimistic bool            `json:"execution_optimistic"`
	Finalized           bool            `json:"finalized"`
	Data                BeaconBlockData `json:"data"`
}

type BeaconBlockData struct {
	Message   BeaconBlockMessage `json:"message"`
	Signature hexutil.Bytes      `json:"signature"`
}

type BeaconBlockMessage struct {
	Slot          Uint64              `json:"slot"`
	ProposerIndex Uint64              `json:"proposer_index"`
	ParentRoot    hexutil.Bytes       `json:"parent_root"`
	StateRoot     hexutil.Bytes       `json:"state_root"`
	Body          BeaconBlockBodyJSON `json:"body"`
}

type BeaconBlockBodyJSON struct {
	RandaoReveal      hexutil.Bytes        `json:"randao_reveal"`
	Eth1Data          Eth1DataJSON         `json:"eth1_data"`
	Graffiti          hexutil.Bytes        `json:"graffiti"`
	SyncAggregate     SyncAggregate        `json:"sync_aggregate"`
	ExecutionPayload  ExecutionPayloadJSON `json:"execution_payload"`
}

type Eth1DataJSON struct {
	DepositRoot  hexutil.Bytes `json:"deposit_root"`
	DepositCount Uint64        `json:"deposit_count"`
	BlockHash    hexutil.Bytes `json:"block_hash"`
}

type ExecutionPayloadJSON struct {
	ParentHash       hexutil.Bytes `json:"parent_hash"`
	FeeRecipient     hexutil.Bytes `json:"fee_recipient"`
	StateRoot        hexutil.Bytes `json:"state_root"`
	ReceiptsRoot     hexutil.Bytes `json:"receipts_root"`
	LogsBloom        hexutil.Bytes `json:"logs_bloom"`
	PrevRandao       hexutil.Bytes `json:"prev_randao"`
	BlockNumber      Uint64        `json:"block_number"`
	GasLimit         Uint64        `json:"gas_limit"`
	GasUsed          Uint64        `json:"gas_used"`
	Timestamp        Uint64        `json:"timestamp"`
	ExtraData        hexutil.Bytes `json:"extra_data"`
	BaseFeePerGas    Uint64        `json:"base_fee_per_gas"`
	BlockHash        hexutil.Bytes `json:"block_hash"`
	TransactionsRoot hexutil.Bytes `json:"transactions_root"`
	WithdrawalsRoot  hexutil.Bytes `json:"withdrawals_root"`
	BlobGasUsed      Uint64        `json:"blob_gas_used"`
	ExcessBlobGas    Uint64        `json:"excess_blob_gas"`
}

// SyncCommitteesResponse is the response from GET /eth/v1/beacon/states/{state_id}/sync_committees
type SyncCommitteesResponse struct {
	ExecutionOptimistic bool                   `json:"execution_optimistic"`
	Finalized           bool                   `json:"finalized"`
	Data                SyncCommitteesDataJSON `json:"data"`
}

type SyncCommitteesDataJSON struct {
	Validators          []string   `json:"validators"`
	ValidatorAggregates [][]string `json:"validator_aggregates"`
}

// BeaconHeaderResponse is the response from GET /eth/v1/beacon/headers/{block_id}
type BeaconHeaderResponse struct {
	ExecutionOptimistic bool                 `json:"execution_optimistic"`
	Finalized           bool                 `json:"finalized"`
	Data                BeaconHeaderDataJSON `json:"data"`
}

type BeaconHeaderDataJSON struct {
	Root      hexutil.Bytes             `json:"root"`
	Canonical bool                      `json:"canonical"`
	Header    SignedBeaconBlockHeaderJSON `json:"header"`
}

type SignedBeaconBlockHeaderJSON struct {
	Message   beaconBlockHeaderJSON `json:"message"`
	Signature hexutil.Bytes         `json:"signature"`
}

// ToBeaconBlockHeader converts the response to BeaconBlockHeader
func (r *BeaconHeaderResponse) ToBeaconBlockHeader() (*BeaconBlockHeader, error) {
	slot, err := strconv.Atoi(r.Data.Header.Message.Slot)
	if err != nil {
		return nil, err
	}
	proposerIndex, err := strconv.Atoi(r.Data.Header.Message.ProposerIndex)
	if err != nil {
		return nil, err
	}
	return &BeaconBlockHeader{
		Slot:          primitives.Slot(slot),
		ProposerIndex: primitives.ValidatorIndex(proposerIndex),
		ParentRoot:    r.Data.Header.Message.ParentRoot,
		StateRoot:     r.Data.Header.Message.StateRoot,
		BodyRoot:      r.Data.Header.Message.BodyRoot,
	}, nil
}
