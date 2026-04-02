package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/datachainlab/ethereum-ibc-relay-prover/beacon"
	lctypes "github.com/datachainlab/ethereum-ibc-relay-prover/light-clients/ethereum/types"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz"
	enginev1 "github.com/OffchainLabs/prysm/v7/proto/engine/v1"
	ethpb "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
	fastssz "github.com/prysmaticlabs/fastssz"
)

func generateMerkleProof(leaves [][]byte, leafIndex uint64) ([][]byte, error) {
	leafLen := len(leaves)
	if leafLen == 0 {
		return nil, fmt.Errorf("leaves length must be greater than 0")
	}
	// leaves length must be power of 2
	var nearestPowerOf2 int = 1
	for nearestPowerOf2 < leafLen {
		nearestPowerOf2 *= 2
	}
	var zero [32]byte
	for i := leafLen; i < nearestPowerOf2; i++ {
		leaves = append(leaves, zero[:])
	}
	node, err := fastssz.TreeFromChunks(leaves)
	if err != nil {
		return nil, err
	}
	// NOTE: seems that fastssz sets root as index=1, so the index is off by one from the ethereum consensus-spes
	// https://github.com/ethereum/consensus-specs/blob/c46c3945fd7fbd1226ece1f8d684c4b724b7bdab/ssz/merkle-proofs.md#generalized-merkle-tree-index
	proof, err := node.Prove(nearestPowerOf2 + int(leafIndex))
	if err != nil {
		return nil, err
	}
	return proof.Hashes, nil
}

func generateExecutionPayloadHeaderProof(header *beacon.ExecutionPayloadHeader, leafIndex uint64) ([][]byte, error) {
	return generateMerkleProof([][]byte{
		header.ParentHash,
		sszBytes(header.FeeRecipient),
		header.StateRoot,
		header.ReceiptsRoot,
		sszBytes(header.LogsBloom),
		header.PrevRandao,
		sszUint64(header.BlockNumber),
		sszUint64(header.GasLimit),
		sszUint64(header.GasUsed),
		sszUint64(header.Timestamp),
		extraDataRootBytes(header.ExtraData),
		header.BaseFeePerGas,
		header.BlockHash,
		header.TransactionsRoot,
		header.WithdrawalsRoot,
		sszUint64(header.BlobGasUsed),
		sszUint64(header.ExcessBlobGas),
	}, leafIndex)
}

func sszBytes(bz []byte) []byte {
	hh := fastssz.NewHasher()
	hh.PutBytes(bz)
	root, err := hh.HashRoot()
	if err != nil {
		panic(err)
	}
	return root[:]
}

func sszUint64(v uint64) []byte {
	hh := fastssz.NewHasher()
	hh.PutUint64(v)
	root, err := hh.HashRoot()
	if err != nil {
		panic(err)
	}
	return root[:]
}

func extraDataRootBytes(tx []byte) []byte {
	bz, err := extraDataRoot(tx)
	if err != nil {
		panic(err)
	}
	return bz[:]
}

func extraDataRoot(bz []byte) ([32]byte, error) {
	chunkedRoots, err := ssz.PackByChunk([][]byte{bz})
	if err != nil {
		return [32]byte{}, err
	}
	const MAX_EXTRA_DATA_BYTES = 32

	maxLength := (MAX_EXTRA_DATA_BYTES + 31) / 32
	bytesRoot, err := ssz.BitwiseMerkleize(chunkedRoots, uint64(len(chunkedRoots)), uint64(maxLength))
	if err != nil {
		return [32]byte{}, err
	}
	bytesRootBuf := new(bytes.Buffer)
	if err := binary.Write(bytesRootBuf, binary.LittleEndian, uint64(len(bz))); err != nil {
		return [32]byte{}, err
	}
	bytesRootBufRoot := make([]byte, 32)
	copy(bytesRootBufRoot, bytesRootBuf.Bytes())
	return ssz.MixInLength(bytesRoot, bytesRootBufRoot), nil
}

// ParsedBeaconState holds parsed beacon state data with methods for generating proofs
type ParsedBeaconState struct {
	SyncCommittee     *lctypes.SyncCommittee
	NextSyncCommittee *lctypes.SyncCommittee
	forkSpec          *lctypes.ForkSpec
	stateSSZ          []byte
}

// GenerateFinalityBranch generates the Merkle proof for the finalized_checkpoint field
func (p *ParsedBeaconState) GenerateFinalityBranch() ([][]byte, error) {
	// Convert gindex to leaf index for proof generation
	leafIndex := gindexToLeafIndex(p.forkSpec.FinalizedRootGindex)
	return generateMerkleProofFromSSZ(p.stateSSZ, leafIndex, p.forkSpec.FinalizedRootGindex)
}

// GenerateNextSyncCommitteeBranch generates the Merkle proof for the next_sync_committee field
func (p *ParsedBeaconState) GenerateNextSyncCommitteeBranch() ([][]byte, error) {
	leafIndex := gindexToLeafIndex(p.forkSpec.NextSyncCommitteeGindex)
	return generateMerkleProofFromSSZ(p.stateSSZ, leafIndex, p.forkSpec.NextSyncCommitteeGindex)
}

// ParsedBeaconBlock holds parsed beacon block data with methods for generating proofs
type ParsedBeaconBlock struct {
	Slot             uint64
	ProposerIndex    uint64
	ParentRoot       []byte
	StateRoot        []byte
	BodyRoot         []byte
	ExecutionPayload *beacon.ExecutionPayloadHeader
	ExecutionRoot    []byte
	SyncAggregate    *lctypes.SyncAggregate
	forkSpec         *lctypes.ForkSpec
	bodySSZ          []byte
}

// GenerateExecutionPayloadBranch generates the Merkle proof for the execution_payload field in the block body
func (p *ParsedBeaconBlock) GenerateExecutionPayloadBranch() ([][]byte, error) {
	leafIndex := gindexToLeafIndex(p.forkSpec.ExecutionPayloadGindex)
	return generateMerkleProofFromSSZ(p.bodySSZ, leafIndex, p.forkSpec.ExecutionPayloadGindex)
}

// ParseBeaconStateSSZ parses SSZ-encoded beacon state data
// Note: This uses prysm types which are hardcoded for mainnet preset.
// Parsing will fail for minimal preset data.
func ParseBeaconStateSSZ(data []byte, version string, forkSpec *lctypes.ForkSpec) (*ParsedBeaconState, error) {
	var currentSC, nextSC *lctypes.SyncCommittee

	switch version {
	case "fulu":
		state := &ethpb.BeaconStateFulu{}
		if err := state.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BeaconStateFulu: %w", err)
		}
		currentSC = syncCommitteeToProto(state.CurrentSyncCommittee)
		nextSC = syncCommitteeToProto(state.NextSyncCommittee)
	case "electra":
		state := &ethpb.BeaconStateElectra{}
		if err := state.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BeaconStateElectra: %w", err)
		}
		currentSC = syncCommitteeToProto(state.CurrentSyncCommittee)
		nextSC = syncCommitteeToProto(state.NextSyncCommittee)
	case "deneb":
		state := &ethpb.BeaconStateDeneb{}
		if err := state.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BeaconStateDeneb: %w", err)
		}
		currentSC = syncCommitteeToProto(state.CurrentSyncCommittee)
		nextSC = syncCommitteeToProto(state.NextSyncCommittee)
	default:
		return nil, fmt.Errorf("unsupported version: %s", version)
	}

	return &ParsedBeaconState{
		SyncCommittee:     currentSC,
		NextSyncCommittee: nextSC,
		forkSpec:          forkSpec,
		stateSSZ:          data,
	}, nil
}

// ParseBeaconBlockSSZ parses SSZ-encoded signed beacon block data
// Note: This uses prysm types which are hardcoded for mainnet preset.
// Parsing will fail for minimal preset data.
func ParseBeaconBlockSSZ(data []byte, version string, forkSpec *lctypes.ForkSpec) (*ParsedBeaconBlock, error) {
	var (
		slot             uint64
		proposerIndex    uint64
		parentRoot       []byte
		stateRoot        []byte
		bodySSZ          []byte
		executionPayload *beacon.ExecutionPayloadHeader
		syncAggregate    *lctypes.SyncAggregate
	)

	switch version {
	case "fulu":
		block := &ethpb.SignedBeaconBlockFulu{}
		if err := block.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SignedBeaconBlockFulu: %w", err)
		}
		msg := block.Block
		slot = uint64(msg.Slot)
		proposerIndex = uint64(msg.ProposerIndex)
		parentRoot = msg.ParentRoot
		stateRoot = msg.StateRoot
		bodySSZ, _ = msg.Body.MarshalSSZ()
		var err error
		executionPayload, err = executionPayloadToHeader(msg.Body.ExecutionPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to convert execution payload to header: %w", err)
		}
		syncAggregate = syncAggregateToProto(msg.Body.SyncAggregate)
	case "electra":
		block := &ethpb.SignedBeaconBlockElectra{}
		if err := block.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SignedBeaconBlockElectra: %w", err)
		}
		msg := block.Block
		slot = uint64(msg.Slot)
		proposerIndex = uint64(msg.ProposerIndex)
		parentRoot = msg.ParentRoot
		stateRoot = msg.StateRoot
		bodySSZ, _ = msg.Body.MarshalSSZ()
		var err error
		executionPayload, err = executionPayloadToHeader(msg.Body.ExecutionPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to convert execution payload to header: %w", err)
		}
		syncAggregate = syncAggregateToProto(msg.Body.SyncAggregate)
	case "deneb":
		block := &ethpb.SignedBeaconBlockDeneb{}
		if err := block.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SignedBeaconBlockDeneb: %w", err)
		}
		msg := block.Block
		slot = uint64(msg.Slot)
		proposerIndex = uint64(msg.ProposerIndex)
		parentRoot = msg.ParentRoot
		stateRoot = msg.StateRoot
		bodySSZ, _ = msg.Body.MarshalSSZ()
		var err error
		executionPayload, err = executionPayloadToHeader(msg.Body.ExecutionPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to convert execution payload to header: %w", err)
		}
		syncAggregate = syncAggregateToProto(msg.Body.SyncAggregate)
	default:
		return nil, fmt.Errorf("unsupported version: %s", version)
	}

	// Compute body root
	hh := fastssz.NewHasher()
	hh.PutBytes(bodySSZ)
	bodyRoot, err := hh.HashRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute body root: %w", err)
	}

	// Compute execution root
	executionRoot, err := executionPayload.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute execution root: %w", err)
	}

	return &ParsedBeaconBlock{
		Slot:             slot,
		ProposerIndex:    proposerIndex,
		ParentRoot:       parentRoot,
		StateRoot:        stateRoot,
		BodyRoot:         bodyRoot[:],
		ExecutionPayload: executionPayload,
		ExecutionRoot:    executionRoot[:],
		SyncAggregate:    syncAggregate,
		forkSpec:         forkSpec,
		bodySSZ:          bodySSZ,
	}, nil
}

// syncCommitteeToProto converts prysm SyncCommittee to lctypes.SyncCommittee
func syncCommitteeToProto(sc *ethpb.SyncCommittee) *lctypes.SyncCommittee {
	if sc == nil {
		return nil
	}
	pubkeys := make([][]byte, len(sc.Pubkeys))
	for i, pk := range sc.Pubkeys {
		pubkeys[i] = pk
	}
	return &lctypes.SyncCommittee{
		Pubkeys:         pubkeys,
		AggregatePubkey: sc.AggregatePubkey,
	}
}

// syncAggregateToProto converts prysm SyncAggregate to lctypes.SyncAggregate
func syncAggregateToProto(sa *ethpb.SyncAggregate) *lctypes.SyncAggregate {
	if sa == nil {
		return nil
	}
	return &lctypes.SyncAggregate{
		SyncCommitteeBits:      sa.SyncCommitteeBits,
		SyncCommitteeSignature: sa.SyncCommitteeSignature,
	}
}

// gindexToLeafIndex converts a generalized index to a leaf index for Merkle proof generation
// The leaf index is the position in the bottom layer of the Merkle tree
func gindexToLeafIndex(gindex uint32) uint64 {
	// Calculate depth from gindex (gindex = 2^depth + leaf_index)
	depth := gindexToDepth(gindex)
	// leaf_index = gindex - 2^depth
	return uint64(gindex - (1 << depth))
}

// gindexToDepth calculates the depth of a generalized index in the Merkle tree
func gindexToDepth(gindex uint32) int {
	if gindex == 0 {
		return 0
	}
	depth := 0
	temp := gindex
	for temp > 1 {
		temp >>= 1
		depth++
	}
	return depth
}

// toBytes32Slice converts a slice of byte slices to a slice of [32]byte arrays
func toBytes32Slice(input [][]byte) [][32]byte {
	result := make([][32]byte, len(input))
	for i, b := range input {
		copy(result[i][:], b)
	}
	return result
}

// generateMerkleProofFromGindex generates a Merkle proof for a specific gindex
func generateMerkleProofFromGindex(leaves [][]byte, gindex uint32) ([][]byte, error) {
	leafIndex := gindexToLeafIndex(gindex)
	return generateMerkleProof(leaves, leafIndex)
}

// packUint64s packs a slice of uint64 values into 32-byte chunks (4 uint64s per chunk)
func packUint64s(values []uint64) [][32]byte {
	if len(values) == 0 {
		return nil
	}

	// 4 uint64s fit in one 32-byte chunk
	numChunks := (len(values) + 3) / 4
	chunks := make([][32]byte, numChunks)

	for i, v := range values {
		chunkIndex := i / 4
		offset := (i % 4) * 8
		binary.LittleEndian.PutUint64(chunks[chunkIndex][offset:], v)
	}

	return chunks
}

// generateMerkleProofFromSSZ generates a Merkle proof for a specific field in SSZ data
// This is a placeholder implementation - actual implementation requires proper SSZ tree construction
func generateMerkleProofFromSSZ(sszData []byte, leafIndex uint64, gindex uint32) ([][]byte, error) {
	// TODO: Implement proper Merkle proof generation from SSZ data
	// This requires constructing the full Merkle tree from the SSZ object
	// and then extracting the proof for the specified leaf
	return nil, fmt.Errorf("generateMerkleProofFromSSZ not yet implemented for gindex %d", gindex)
}

// executionPayloadToHeader converts ExecutionPayloadDeneb to ExecutionPayloadHeaderDeneb
func executionPayloadToHeader(payload *enginev1.ExecutionPayloadDeneb) (*beacon.ExecutionPayloadHeader, error) {
	if payload == nil {
		return nil, fmt.Errorf("execution payload is nil")
	}

	// Compute transactions root
	transactionsRoot, err := computeTransactionsRoot(payload.Transactions)
	if err != nil {
		return nil, fmt.Errorf("failed to compute transactions root: %w", err)
	}

	// Compute withdrawals root
	withdrawalsRoot, err := computeWithdrawalsRoot(payload.Withdrawals)
	if err != nil {
		return nil, fmt.Errorf("failed to compute withdrawals root: %w", err)
	}

	return &beacon.ExecutionPayloadHeader{
		ParentHash:       payload.ParentHash,
		FeeRecipient:     payload.FeeRecipient,
		StateRoot:        payload.StateRoot,
		ReceiptsRoot:     payload.ReceiptsRoot,
		LogsBloom:        payload.LogsBloom,
		PrevRandao:       payload.PrevRandao,
		BlockNumber:      payload.BlockNumber,
		GasLimit:         payload.GasLimit,
		GasUsed:          payload.GasUsed,
		Timestamp:        payload.Timestamp,
		ExtraData:        payload.ExtraData,
		BaseFeePerGas:    payload.BaseFeePerGas,
		BlockHash:        payload.BlockHash,
		TransactionsRoot: transactionsRoot[:],
		WithdrawalsRoot:  withdrawalsRoot[:],
		BlobGasUsed:      payload.BlobGasUsed,
		ExcessBlobGas:    payload.ExcessBlobGas,
	}, nil
}

// computeTransactionsRoot computes the SSZ root of transactions list
func computeTransactionsRoot(transactions [][]byte) ([32]byte, error) {
	// Hash each transaction
	txRoots := make([][32]byte, len(transactions))
	for i, tx := range transactions {
		txRoot, err := transactionRoot(tx)
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to compute transaction root %d: %w", i, err)
		}
		txRoots[i] = txRoot
	}

	// Create Merkle tree from transaction roots
	const MAX_TRANSACTIONS_PER_PAYLOAD = 1048576
	root, err := ssz.BitwiseMerkleize(txRoots, uint64(len(txRoots)), MAX_TRANSACTIONS_PER_PAYLOAD)
	if err != nil {
		return [32]byte{}, err
	}

	// Mix in length
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(transactions)))
	return ssz.MixInLength(root, lengthBuf), nil
}

// transactionRoot computes the SSZ root of a single transaction
func transactionRoot(tx []byte) ([32]byte, error) {
	chunkedRoots, err := ssz.PackByChunk([][]byte{tx})
	if err != nil {
		return [32]byte{}, err
	}
	const MAX_BYTES_PER_TRANSACTION = 1073741824 // 1 GB
	maxLength := (MAX_BYTES_PER_TRANSACTION + 31) / 32

	bytesRoot, err := ssz.BitwiseMerkleize(chunkedRoots, uint64(len(chunkedRoots)), uint64(maxLength))
	if err != nil {
		return [32]byte{}, err
	}

	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(tx)))
	return ssz.MixInLength(bytesRoot, lengthBuf), nil
}

// computeWithdrawalsRoot computes the SSZ root of withdrawals list
func computeWithdrawalsRoot(withdrawals []*enginev1.Withdrawal) ([32]byte, error) {
	// Hash each withdrawal
	wRoots := make([][32]byte, len(withdrawals))
	for i, w := range withdrawals {
		hh := fastssz.NewHasher()
		hh.PutUint64(w.Index)
		hh.PutUint64(uint64(w.ValidatorIndex))
		hh.PutBytes(w.Address)
		hh.PutUint64(w.Amount)
		root, err := hh.HashRoot()
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to compute withdrawal root %d: %w", i, err)
		}
		wRoots[i] = root
	}

	// Create Merkle tree from withdrawal roots
	const MAX_WITHDRAWALS_PER_PAYLOAD = 16
	root, err := ssz.BitwiseMerkleize(wRoots, uint64(len(wRoots)), MAX_WITHDRAWALS_PER_PAYLOAD)
	if err != nil {
		return [32]byte{}, err
	}

	// Mix in length
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(withdrawals)))
	return ssz.MixInLength(root, lengthBuf), nil
}
