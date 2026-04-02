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
	// Parsed prysm state types for proof generation
	stateFulu    *ethpb.BeaconStateFulu
	stateElectra *ethpb.BeaconStateElectra
	stateDeneb   *ethpb.BeaconStateDeneb
	version      string
}

// GenerateFinalityBranch generates the Merkle proof for the finalized_checkpoint field
func (p *ParsedBeaconState) GenerateFinalityBranch() ([][]byte, error) {
	gindex := p.forkSpec.FinalizedRootGindex
	return p.generateStateProofFromSSZ(gindex)
}

// GenerateNextSyncCommitteeBranch generates the Merkle proof for the next_sync_committee field
func (p *ParsedBeaconState) GenerateNextSyncCommitteeBranch() ([][]byte, error) {
	gindex := p.forkSpec.NextSyncCommitteeGindex
	return p.generateStateProofFromSSZ(gindex)
}

// generateStateProofFromSSZ generates a Merkle proof by building the tree from field hashes
func (p *ParsedBeaconState) generateStateProofFromSSZ(gindex uint32) ([][]byte, error) {
	// Calculate required tree depth based on gindex
	depth := gindexToDepth(gindex)
	numLeaves := 1 << depth // 2^depth leaves required

	// Get field hashes based on version
	var fieldHashes [][]byte
	var err error

	switch p.version {
	case "fulu":
		if p.stateFulu == nil {
			return nil, fmt.Errorf("fulu state not parsed")
		}
		fieldHashes, err = getBeaconStateFuluFieldHashesWithSize(p.stateFulu, numLeaves)
	case "electra":
		if p.stateElectra == nil {
			return nil, fmt.Errorf("electra state not parsed")
		}
		fieldHashes, err = getBeaconStateElectraFieldHashesWithSize(p.stateElectra, numLeaves)
	case "deneb":
		if p.stateDeneb == nil {
			return nil, fmt.Errorf("deneb state not parsed")
		}
		fieldHashes, err = getBeaconStateDenebFieldHashesWithSize(p.stateDeneb, numLeaves)
	default:
		return nil, fmt.Errorf("unsupported version: %s", p.version)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get field hashes: %w", err)
	}

	// Generate proof using gindex
	leafIndex := gindexToLeafIndex(gindex)
	return generateMerkleProof(fieldHashes, leafIndex)
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
	// Parsed prysm body types for proof generation
	// Note: Fulu uses the same body type as Electra
	bodyElectra *ethpb.BeaconBlockBodyElectra
	bodyDeneb   *ethpb.BeaconBlockBodyDeneb
	version     string
}

// GenerateExecutionPayloadBranch generates the Merkle proof for the execution_payload field in the block body
func (p *ParsedBeaconBlock) GenerateExecutionPayloadBranch() ([][]byte, error) {
	gindex := p.forkSpec.ExecutionPayloadGindex

	// Get field hashes based on version
	var fieldHashes [][]byte
	var err error

	switch p.version {
	case "fulu", "electra":
		if p.bodyElectra == nil {
			return nil, fmt.Errorf("%s body not parsed", p.version)
		}
		fieldHashes, err = getBeaconBlockBodyElectraFieldHashes(p.bodyElectra)
	case "deneb":
		if p.bodyDeneb == nil {
			return nil, fmt.Errorf("deneb body not parsed")
		}
		fieldHashes, err = getBeaconBlockBodyDenebFieldHashes(p.bodyDeneb)
	default:
		return nil, fmt.Errorf("unsupported version: %s", p.version)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get field hashes: %w", err)
	}

	// Generate proof using gindex
	leafIndex := gindexToLeafIndex(gindex)
	return generateMerkleProof(fieldHashes, leafIndex)
}

// ParseBeaconStateSSZ parses SSZ-encoded beacon state data
// Note: This uses prysm types which are hardcoded for mainnet preset.
// Parsing will fail for minimal preset data.
func ParseBeaconStateSSZ(data []byte, version string, forkSpec *lctypes.ForkSpec) (*ParsedBeaconState, error) {
	result := &ParsedBeaconState{
		forkSpec: forkSpec,
		stateSSZ: data,
		version:  version,
	}

	switch version {
	case "fulu":
		state := &ethpb.BeaconStateFulu{}
		if err := state.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BeaconStateFulu: %w", err)
		}
		result.SyncCommittee = syncCommitteeToProto(state.CurrentSyncCommittee)
		result.NextSyncCommittee = syncCommitteeToProto(state.NextSyncCommittee)
		result.stateFulu = state
	case "electra":
		state := &ethpb.BeaconStateElectra{}
		if err := state.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BeaconStateElectra: %w", err)
		}
		result.SyncCommittee = syncCommitteeToProto(state.CurrentSyncCommittee)
		result.NextSyncCommittee = syncCommitteeToProto(state.NextSyncCommittee)
		result.stateElectra = state
	case "deneb":
		state := &ethpb.BeaconStateDeneb{}
		if err := state.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal BeaconStateDeneb: %w", err)
		}
		result.SyncCommittee = syncCommitteeToProto(state.CurrentSyncCommittee)
		result.NextSyncCommittee = syncCommitteeToProto(state.NextSyncCommittee)
		result.stateDeneb = state
	default:
		return nil, fmt.Errorf("unsupported version: %s", version)
	}

	return result, nil
}

// ParseBeaconBlockSSZ parses SSZ-encoded signed beacon block data
// Note: This uses prysm types which are hardcoded for mainnet preset.
// Parsing will fail for minimal preset data.
func ParseBeaconBlockSSZ(data []byte, version string, forkSpec *lctypes.ForkSpec) (*ParsedBeaconBlock, error) {
	result := &ParsedBeaconBlock{
		forkSpec: forkSpec,
		version:  version,
	}

	switch version {
	case "fulu":
		block := &ethpb.SignedBeaconBlockFulu{}
		if err := block.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SignedBeaconBlockFulu: %w", err)
		}
		msg := block.Block
		result.Slot = uint64(msg.Slot)
		result.ProposerIndex = uint64(msg.ProposerIndex)
		result.ParentRoot = msg.ParentRoot
		result.StateRoot = msg.StateRoot
		result.bodySSZ, _ = msg.Body.MarshalSSZ()
		// Fulu uses the same block body type as Electra
		result.bodyElectra = msg.Body
		var err error
		result.ExecutionPayload, err = executionPayloadToHeader(msg.Body.ExecutionPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to convert execution payload to header: %w", err)
		}
		result.SyncAggregate = syncAggregateToProto(msg.Body.SyncAggregate)
	case "electra":
		block := &ethpb.SignedBeaconBlockElectra{}
		if err := block.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SignedBeaconBlockElectra: %w", err)
		}
		msg := block.Block
		result.Slot = uint64(msg.Slot)
		result.ProposerIndex = uint64(msg.ProposerIndex)
		result.ParentRoot = msg.ParentRoot
		result.StateRoot = msg.StateRoot
		result.bodySSZ, _ = msg.Body.MarshalSSZ()
		result.bodyElectra = msg.Body
		var err error
		result.ExecutionPayload, err = executionPayloadToHeader(msg.Body.ExecutionPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to convert execution payload to header: %w", err)
		}
		result.SyncAggregate = syncAggregateToProto(msg.Body.SyncAggregate)
	case "deneb":
		block := &ethpb.SignedBeaconBlockDeneb{}
		if err := block.UnmarshalSSZ(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal SignedBeaconBlockDeneb: %w", err)
		}
		msg := block.Block
		result.Slot = uint64(msg.Slot)
		result.ProposerIndex = uint64(msg.ProposerIndex)
		result.ParentRoot = msg.ParentRoot
		result.StateRoot = msg.StateRoot
		result.bodySSZ, _ = msg.Body.MarshalSSZ()
		result.bodyDeneb = msg.Body
		var err error
		result.ExecutionPayload, err = executionPayloadToHeader(msg.Body.ExecutionPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to convert execution payload to header: %w", err)
		}
		result.SyncAggregate = syncAggregateToProto(msg.Body.SyncAggregate)
	default:
		return nil, fmt.Errorf("unsupported version: %s", version)
	}

	// Compute body root
	hh := fastssz.NewHasher()
	hh.PutBytes(result.bodySSZ)
	bodyRoot, err := hh.HashRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute body root: %w", err)
	}
	result.BodyRoot = bodyRoot[:]

	// Compute execution root
	executionRoot, err := result.ExecutionPayload.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute execution root: %w", err)
	}
	result.ExecutionRoot = executionRoot[:]

	return result, nil
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

// getBeaconStateFuluFieldHashesWithSize computes field hashes with a specific tree size
func getBeaconStateFuluFieldHashesWithSize(state *ethpb.BeaconStateFulu, numLeaves int) ([][]byte, error) {
	hh := fastssz.NewHasher()

	// Use HashTreeRootWith to compute the hash, but we need individual field hashes
	// For now, we'll compute the entire state hash and extract field hashes manually
	if err := state.HashTreeRootWith(hh); err != nil {
		return nil, fmt.Errorf("failed to hash state: %w", err)
	}

	// Since fastssz doesn't expose the tree structure, we need to compute field hashes individually
	// The number of leaves is determined by the required gindex depth
	fieldHashes := make([][]byte, numLeaves)

	// Field 0: genesis_time (uint64)
	fieldHashes[0] = sszUint64(state.GenesisTime)

	// Field 1: genesis_validators_root (Bytes32)
	fieldHashes[1] = padTo32(state.GenesisValidatorsRoot)

	// Field 2: slot (uint64)
	fieldHashes[2] = sszUint64(uint64(state.Slot))

	// Field 3: fork
	if state.Fork != nil {
		root, err := state.Fork.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[3] = root[:]
	} else {
		fieldHashes[3] = make([]byte, 32)
	}

	// Field 4: latest_block_header
	if state.LatestBlockHeader != nil {
		root, err := state.LatestBlockHeader.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[4] = root[:]
	} else {
		fieldHashes[4] = make([]byte, 32)
	}

	// Field 5: block_roots (Vector[Root, 8192])
	root5, err := vectorRootHash(state.BlockRoots, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[5] = root5[:]

	// Field 6: state_roots (Vector[Root, 8192])
	root6, err := vectorRootHash(state.StateRoots, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[6] = root6[:]

	// Field 7: historical_roots (List - frozen, typically empty)
	root7, err := listRootHash(state.HistoricalRoots, 16777216)
	if err != nil {
		return nil, err
	}
	fieldHashes[7] = root7[:]

	// Field 8: eth1_data
	if state.Eth1Data != nil {
		root, err := state.Eth1Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[8] = root[:]
	} else {
		fieldHashes[8] = make([]byte, 32)
	}

	// Field 9: eth1_data_votes (List)
	root9, err := eth1DataVotesRoot(state.Eth1DataVotes, 2048)
	if err != nil {
		return nil, err
	}
	fieldHashes[9] = root9[:]

	// Field 10: eth1_deposit_index
	fieldHashes[10] = sszUint64(state.Eth1DepositIndex)

	// Field 11: validators (List)
	root11, err := validatorsRoot(state.Validators)
	if err != nil {
		return nil, err
	}
	fieldHashes[11] = root11[:]

	// Field 12: balances (List)
	root12, err := balancesRoot(state.Balances)
	if err != nil {
		return nil, err
	}
	fieldHashes[12] = root12[:]

	// Field 13: randao_mixes (Vector[Bytes32, 65536])
	root13, err := vectorRootHash(state.RandaoMixes, 65536)
	if err != nil {
		return nil, err
	}
	fieldHashes[13] = root13[:]

	// Field 14: slashings (Vector[Gwei, 8192])
	root14, err := uint64VectorRoot(state.Slashings, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[14] = root14[:]

	// Field 15: previous_epoch_participation (List[uint8, ...])
	root15, err := participationRoot(state.PreviousEpochParticipation)
	if err != nil {
		return nil, err
	}
	fieldHashes[15] = root15[:]

	// Field 16: current_epoch_participation
	root16, err := participationRoot(state.CurrentEpochParticipation)
	if err != nil {
		return nil, err
	}
	fieldHashes[16] = root16[:]

	// Field 17: justification_bits (Bitvector[4])
	fieldHashes[17] = padTo32(state.JustificationBits)

	// Field 18: previous_justified_checkpoint
	if state.PreviousJustifiedCheckpoint != nil {
		root, err := state.PreviousJustifiedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[18] = root[:]
	} else {
		fieldHashes[18] = make([]byte, 32)
	}

	// Field 19: current_justified_checkpoint
	if state.CurrentJustifiedCheckpoint != nil {
		root, err := state.CurrentJustifiedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[19] = root[:]
	} else {
		fieldHashes[19] = make([]byte, 32)
	}

	// Field 20: finalized_checkpoint
	if state.FinalizedCheckpoint != nil {
		root, err := state.FinalizedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[20] = root[:]
	} else {
		fieldHashes[20] = make([]byte, 32)
	}

	// Field 21: inactivity_scores (List)
	root21, err := uint64ListRoot(state.InactivityScores)
	if err != nil {
		return nil, err
	}
	fieldHashes[21] = root21[:]

	// Field 22: current_sync_committee
	if state.CurrentSyncCommittee != nil {
		root, err := state.CurrentSyncCommittee.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[22] = root[:]
	} else {
		fieldHashes[22] = make([]byte, 32)
	}

	// Field 23: next_sync_committee
	if state.NextSyncCommittee != nil {
		root, err := state.NextSyncCommittee.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[23] = root[:]
	} else {
		fieldHashes[23] = make([]byte, 32)
	}

	// Field 24: latest_execution_payload_header
	if state.LatestExecutionPayloadHeader != nil {
		root, err := state.LatestExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[24] = root[:]
	} else {
		fieldHashes[24] = make([]byte, 32)
	}

	// Field 25: next_withdrawal_index
	fieldHashes[25] = sszUint64(state.NextWithdrawalIndex)

	// Field 26: next_withdrawal_validator_index
	fieldHashes[26] = sszUint64(uint64(state.NextWithdrawalValidatorIndex))

	// Field 27: historical_summaries (List)
	root27, err := historicalSummariesRoot(state.HistoricalSummaries)
	if err != nil {
		return nil, err
	}
	fieldHashes[27] = root27[:]

	// Electra fields
	// Field 28: deposit_requests_start_index
	fieldHashes[28] = sszUint64(state.DepositRequestsStartIndex)

	// Field 29: deposit_balance_to_consume
	fieldHashes[29] = sszUint64(uint64(state.DepositBalanceToConsume))

	// Field 30: exit_balance_to_consume
	fieldHashes[30] = sszUint64(uint64(state.ExitBalanceToConsume))

	// Field 31: earliest_exit_epoch
	fieldHashes[31] = sszUint64(uint64(state.EarliestExitEpoch))

	// Field 32: consolidation_balance_to_consume
	fieldHashes[32] = sszUint64(uint64(state.ConsolidationBalanceToConsume))

	// Field 33: earliest_consolidation_epoch
	fieldHashes[33] = sszUint64(uint64(state.EarliestConsolidationEpoch))

	// Field 34: pending_deposits (List)
	root34, err := pendingDepositsRoot(state.PendingDeposits)
	if err != nil {
		return nil, err
	}
	fieldHashes[34] = root34[:]

	// Field 35: pending_partial_withdrawals (List)
	root35, err := pendingPartialWithdrawalsRoot(state.PendingPartialWithdrawals)
	if err != nil {
		return nil, err
	}
	fieldHashes[35] = root35[:]

	// Field 36: pending_consolidations (List)
	root36, err := pendingConsolidationsRoot(state.PendingConsolidations)
	if err != nil {
		return nil, err
	}
	fieldHashes[36] = root36[:]

	// Field 37: proposer_lookahead (Vector[uint64, 64])
	root37, err := uint64VectorRoot(state.ProposerLookahead, 64)
	if err != nil {
		return nil, err
	}
	fieldHashes[37] = root37[:]

	// Fill remaining fields with zeros
	for i := 38; i < numLeaves; i++ {
		fieldHashes[i] = make([]byte, 32)
	}

	return fieldHashes, nil
}

// getBeaconStateElectraFieldHashesWithSize computes field hashes for BeaconStateElectra with a specific tree size
func getBeaconStateElectraFieldHashesWithSize(state *ethpb.BeaconStateElectra, numLeaves int) ([][]byte, error) {
	// Electra is similar to Fulu but without proposer_lookahead
	// For simplicity, we use HashTreeRoot on the whole state
	// This is a placeholder - proper implementation would extract field hashes
	hh := fastssz.NewHasher()
	if err := state.HashTreeRootWith(hh); err != nil {
		return nil, fmt.Errorf("failed to hash state: %w", err)
	}

	// Similar structure to Fulu, just without the last field
	// The number of leaves is determined by the required gindex depth
	fieldHashes := make([][]byte, numLeaves)

	// Copy most of the logic from Fulu
	// Field 0-36 are the same as Fulu
	// Field 37+ are zeros

	fieldHashes[0] = sszUint64(state.GenesisTime)
	fieldHashes[1] = padTo32(state.GenesisValidatorsRoot)
	fieldHashes[2] = sszUint64(uint64(state.Slot))

	if state.Fork != nil {
		root, err := state.Fork.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[3] = root[:]
	} else {
		fieldHashes[3] = make([]byte, 32)
	}

	if state.LatestBlockHeader != nil {
		root, err := state.LatestBlockHeader.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[4] = root[:]
	} else {
		fieldHashes[4] = make([]byte, 32)
	}

	root5, err := vectorRootHash(state.BlockRoots, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[5] = root5[:]

	root6, err := vectorRootHash(state.StateRoots, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[6] = root6[:]

	root7, err := listRootHash(state.HistoricalRoots, 16777216)
	if err != nil {
		return nil, err
	}
	fieldHashes[7] = root7[:]

	if state.Eth1Data != nil {
		root, err := state.Eth1Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[8] = root[:]
	} else {
		fieldHashes[8] = make([]byte, 32)
	}

	root9, err := eth1DataVotesRoot(state.Eth1DataVotes, 2048)
	if err != nil {
		return nil, err
	}
	fieldHashes[9] = root9[:]

	fieldHashes[10] = sszUint64(state.Eth1DepositIndex)

	root11, err := validatorsRoot(state.Validators)
	if err != nil {
		return nil, err
	}
	fieldHashes[11] = root11[:]

	root12, err := balancesRoot(state.Balances)
	if err != nil {
		return nil, err
	}
	fieldHashes[12] = root12[:]

	root13, err := vectorRootHash(state.RandaoMixes, 65536)
	if err != nil {
		return nil, err
	}
	fieldHashes[13] = root13[:]

	root14, err := uint64VectorRoot(state.Slashings, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[14] = root14[:]

	root15, err := participationRoot(state.PreviousEpochParticipation)
	if err != nil {
		return nil, err
	}
	fieldHashes[15] = root15[:]

	root16, err := participationRoot(state.CurrentEpochParticipation)
	if err != nil {
		return nil, err
	}
	fieldHashes[16] = root16[:]

	fieldHashes[17] = padTo32(state.JustificationBits)

	if state.PreviousJustifiedCheckpoint != nil {
		root, err := state.PreviousJustifiedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[18] = root[:]
	} else {
		fieldHashes[18] = make([]byte, 32)
	}

	if state.CurrentJustifiedCheckpoint != nil {
		root, err := state.CurrentJustifiedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[19] = root[:]
	} else {
		fieldHashes[19] = make([]byte, 32)
	}

	if state.FinalizedCheckpoint != nil {
		root, err := state.FinalizedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[20] = root[:]
	} else {
		fieldHashes[20] = make([]byte, 32)
	}

	root21, err := uint64ListRoot(state.InactivityScores)
	if err != nil {
		return nil, err
	}
	fieldHashes[21] = root21[:]

	if state.CurrentSyncCommittee != nil {
		root, err := state.CurrentSyncCommittee.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[22] = root[:]
	} else {
		fieldHashes[22] = make([]byte, 32)
	}

	if state.NextSyncCommittee != nil {
		root, err := state.NextSyncCommittee.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[23] = root[:]
	} else {
		fieldHashes[23] = make([]byte, 32)
	}

	if state.LatestExecutionPayloadHeader != nil {
		root, err := state.LatestExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[24] = root[:]
	} else {
		fieldHashes[24] = make([]byte, 32)
	}

	fieldHashes[25] = sszUint64(state.NextWithdrawalIndex)
	fieldHashes[26] = sszUint64(uint64(state.NextWithdrawalValidatorIndex))

	root27, err := historicalSummariesRoot(state.HistoricalSummaries)
	if err != nil {
		return nil, err
	}
	fieldHashes[27] = root27[:]

	fieldHashes[28] = sszUint64(state.DepositRequestsStartIndex)
	fieldHashes[29] = sszUint64(uint64(state.DepositBalanceToConsume))
	fieldHashes[30] = sszUint64(uint64(state.ExitBalanceToConsume))
	fieldHashes[31] = sszUint64(uint64(state.EarliestExitEpoch))
	fieldHashes[32] = sszUint64(uint64(state.ConsolidationBalanceToConsume))
	fieldHashes[33] = sszUint64(uint64(state.EarliestConsolidationEpoch))

	root34, err := pendingDepositsRoot(state.PendingDeposits)
	if err != nil {
		return nil, err
	}
	fieldHashes[34] = root34[:]

	root35, err := pendingPartialWithdrawalsRoot(state.PendingPartialWithdrawals)
	if err != nil {
		return nil, err
	}
	fieldHashes[35] = root35[:]

	root36, err := pendingConsolidationsRoot(state.PendingConsolidations)
	if err != nil {
		return nil, err
	}
	fieldHashes[36] = root36[:]

	// Fill remaining fields with zeros
	for i := 37; i < numLeaves; i++ {
		fieldHashes[i] = make([]byte, 32)
	}

	return fieldHashes, nil
}

// getBeaconStateDenebFieldHashesWithSize computes field hashes for BeaconStateDeneb with a specific tree size
func getBeaconStateDenebFieldHashesWithSize(state *ethpb.BeaconStateDeneb, numLeaves int) ([][]byte, error) {
	// Deneb has fewer fields than Electra
	// The number of leaves is determined by the required gindex depth
	fieldHashes := make([][]byte, numLeaves)

	fieldHashes[0] = sszUint64(state.GenesisTime)
	fieldHashes[1] = padTo32(state.GenesisValidatorsRoot)
	fieldHashes[2] = sszUint64(uint64(state.Slot))

	if state.Fork != nil {
		root, err := state.Fork.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[3] = root[:]
	} else {
		fieldHashes[3] = make([]byte, 32)
	}

	if state.LatestBlockHeader != nil {
		root, err := state.LatestBlockHeader.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[4] = root[:]
	} else {
		fieldHashes[4] = make([]byte, 32)
	}

	root5, err := vectorRootHash(state.BlockRoots, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[5] = root5[:]

	root6, err := vectorRootHash(state.StateRoots, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[6] = root6[:]

	root7, err := listRootHash(state.HistoricalRoots, 16777216)
	if err != nil {
		return nil, err
	}
	fieldHashes[7] = root7[:]

	if state.Eth1Data != nil {
		root, err := state.Eth1Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[8] = root[:]
	} else {
		fieldHashes[8] = make([]byte, 32)
	}

	root9, err := eth1DataVotesRoot(state.Eth1DataVotes, 2048)
	if err != nil {
		return nil, err
	}
	fieldHashes[9] = root9[:]

	fieldHashes[10] = sszUint64(state.Eth1DepositIndex)

	root11, err := validatorsRoot(state.Validators)
	if err != nil {
		return nil, err
	}
	fieldHashes[11] = root11[:]

	root12, err := balancesRoot(state.Balances)
	if err != nil {
		return nil, err
	}
	fieldHashes[12] = root12[:]

	root13, err := vectorRootHash(state.RandaoMixes, 65536)
	if err != nil {
		return nil, err
	}
	fieldHashes[13] = root13[:]

	root14, err := uint64VectorRoot(state.Slashings, 8192)
	if err != nil {
		return nil, err
	}
	fieldHashes[14] = root14[:]

	root15, err := participationRoot(state.PreviousEpochParticipation)
	if err != nil {
		return nil, err
	}
	fieldHashes[15] = root15[:]

	root16, err := participationRoot(state.CurrentEpochParticipation)
	if err != nil {
		return nil, err
	}
	fieldHashes[16] = root16[:]

	fieldHashes[17] = padTo32(state.JustificationBits)

	if state.PreviousJustifiedCheckpoint != nil {
		root, err := state.PreviousJustifiedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[18] = root[:]
	} else {
		fieldHashes[18] = make([]byte, 32)
	}

	if state.CurrentJustifiedCheckpoint != nil {
		root, err := state.CurrentJustifiedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[19] = root[:]
	} else {
		fieldHashes[19] = make([]byte, 32)
	}

	if state.FinalizedCheckpoint != nil {
		root, err := state.FinalizedCheckpoint.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[20] = root[:]
	} else {
		fieldHashes[20] = make([]byte, 32)
	}

	root21, err := uint64ListRoot(state.InactivityScores)
	if err != nil {
		return nil, err
	}
	fieldHashes[21] = root21[:]

	if state.CurrentSyncCommittee != nil {
		root, err := state.CurrentSyncCommittee.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[22] = root[:]
	} else {
		fieldHashes[22] = make([]byte, 32)
	}

	if state.NextSyncCommittee != nil {
		root, err := state.NextSyncCommittee.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[23] = root[:]
	} else {
		fieldHashes[23] = make([]byte, 32)
	}

	if state.LatestExecutionPayloadHeader != nil {
		root, err := state.LatestExecutionPayloadHeader.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[24] = root[:]
	} else {
		fieldHashes[24] = make([]byte, 32)
	}

	fieldHashes[25] = sszUint64(state.NextWithdrawalIndex)
	fieldHashes[26] = sszUint64(uint64(state.NextWithdrawalValidatorIndex))

	root27, err := historicalSummariesRoot(state.HistoricalSummaries)
	if err != nil {
		return nil, err
	}
	fieldHashes[27] = root27[:]

	// Fill remaining with zeros
	for i := 28; i < numLeaves; i++ {
		fieldHashes[i] = make([]byte, 32)
	}

	return fieldHashes, nil
}

// getBeaconBlockBodyElectraFieldHashes computes field hashes for BeaconBlockBodyElectra
// Note: This is also used for Fulu since they share the same block body structure
func getBeaconBlockBodyElectraFieldHashes(body *ethpb.BeaconBlockBodyElectra) ([][]byte, error) {
	fieldHashes := make([][]byte, 16)

	fieldHashes[0] = sszBytes(body.RandaoReveal)

	if body.Eth1Data != nil {
		root, err := body.Eth1Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[1] = root[:]
	} else {
		fieldHashes[1] = make([]byte, 32)
	}

	fieldHashes[2] = padTo32(body.Graffiti)

	root3, err := proposerSlashingsRoot(body.ProposerSlashings)
	if err != nil {
		return nil, err
	}
	fieldHashes[3] = root3[:]

	root4, err := attesterSlashingsRoot(body.AttesterSlashings)
	if err != nil {
		return nil, err
	}
	fieldHashes[4] = root4[:]

	root5, err := attestationsRoot(body.Attestations)
	if err != nil {
		return nil, err
	}
	fieldHashes[5] = root5[:]

	root6, err := depositsRoot(body.Deposits)
	if err != nil {
		return nil, err
	}
	fieldHashes[6] = root6[:]

	root7, err := voluntaryExitsRoot(body.VoluntaryExits)
	if err != nil {
		return nil, err
	}
	fieldHashes[7] = root7[:]

	if body.SyncAggregate != nil {
		root, err := body.SyncAggregate.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[8] = root[:]
	} else {
		fieldHashes[8] = make([]byte, 32)
	}

	if body.ExecutionPayload != nil {
		root, err := body.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[9] = root[:]
	} else {
		fieldHashes[9] = make([]byte, 32)
	}

	root10, err := blsToExecutionChangesRoot(body.BlsToExecutionChanges)
	if err != nil {
		return nil, err
	}
	fieldHashes[10] = root10[:]

	root11, err := blobKzgCommitmentsRoot(body.BlobKzgCommitments)
	if err != nil {
		return nil, err
	}
	fieldHashes[11] = root11[:]

	if body.ExecutionRequests != nil {
		root, err := body.ExecutionRequests.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[12] = root[:]
	} else {
		fieldHashes[12] = make([]byte, 32)
	}

	for i := 13; i < 16; i++ {
		fieldHashes[i] = make([]byte, 32)
	}

	return fieldHashes, nil
}

// getBeaconBlockBodyDenebFieldHashes computes field hashes for BeaconBlockBodyDeneb
func getBeaconBlockBodyDenebFieldHashes(body *ethpb.BeaconBlockBodyDeneb) ([][]byte, error) {
	fieldHashes := make([][]byte, 16)

	fieldHashes[0] = sszBytes(body.RandaoReveal)

	if body.Eth1Data != nil {
		root, err := body.Eth1Data.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[1] = root[:]
	} else {
		fieldHashes[1] = make([]byte, 32)
	}

	fieldHashes[2] = padTo32(body.Graffiti)

	root3, err := proposerSlashingsRootDeneb(body.ProposerSlashings)
	if err != nil {
		return nil, err
	}
	fieldHashes[3] = root3[:]

	root4, err := attesterSlashingsRootDeneb(body.AttesterSlashings)
	if err != nil {
		return nil, err
	}
	fieldHashes[4] = root4[:]

	root5, err := attestationsRootDeneb(body.Attestations)
	if err != nil {
		return nil, err
	}
	fieldHashes[5] = root5[:]

	root6, err := depositsRoot(body.Deposits)
	if err != nil {
		return nil, err
	}
	fieldHashes[6] = root6[:]

	root7, err := voluntaryExitsRoot(body.VoluntaryExits)
	if err != nil {
		return nil, err
	}
	fieldHashes[7] = root7[:]

	if body.SyncAggregate != nil {
		root, err := body.SyncAggregate.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[8] = root[:]
	} else {
		fieldHashes[8] = make([]byte, 32)
	}

	if body.ExecutionPayload != nil {
		root, err := body.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, err
		}
		fieldHashes[9] = root[:]
	} else {
		fieldHashes[9] = make([]byte, 32)
	}

	root10, err := blsToExecutionChangesRoot(body.BlsToExecutionChanges)
	if err != nil {
		return nil, err
	}
	fieldHashes[10] = root10[:]

	root11, err := blobKzgCommitmentsRoot(body.BlobKzgCommitments)
	if err != nil {
		return nil, err
	}
	fieldHashes[11] = root11[:]

	for i := 12; i < 16; i++ {
		fieldHashes[i] = make([]byte, 32)
	}

	return fieldHashes, nil
}

// Helper functions for computing roots of various types

func padTo32(b []byte) []byte {
	result := make([]byte, 32)
	copy(result, b)
	return result
}

func vectorRootHash(roots [][]byte, size uint64) ([32]byte, error) {
	chunks := make([][32]byte, len(roots))
	for i, r := range roots {
		copy(chunks[i][:], r)
	}
	return ssz.BitwiseMerkleize(chunks, uint64(len(chunks)), size)
}

func listRootHash(roots [][]byte, maxSize uint64) ([32]byte, error) {
	chunks := make([][32]byte, len(roots))
	for i, r := range roots {
		copy(chunks[i][:], r)
	}
	root, err := ssz.BitwiseMerkleize(chunks, uint64(len(chunks)), maxSize)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(roots)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func uint64VectorRoot(values []uint64, size uint64) ([32]byte, error) {
	chunks := packUint64s(values)
	return ssz.BitwiseMerkleize(chunks, uint64(len(chunks)), (size+3)/4)
}

func uint64ListRoot(values []uint64) ([32]byte, error) {
	chunks := packUint64s(values)
	const VALIDATOR_REGISTRY_LIMIT uint64 = 1099511627776
	maxChunks := (VALIDATOR_REGISTRY_LIMIT + 3) / 4
	root, err := ssz.BitwiseMerkleize(chunks, uint64(len(chunks)), maxChunks)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(values)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func participationRoot(participation []byte) ([32]byte, error) {
	chunkedRoots, err := ssz.PackByChunk([][]byte{participation})
	if err != nil {
		return [32]byte{}, err
	}
	const VALIDATOR_REGISTRY_LIMIT uint64 = 1099511627776
	maxLength := (VALIDATOR_REGISTRY_LIMIT + 31) / 32
	bytesRoot, err := ssz.BitwiseMerkleize(chunkedRoots, uint64(len(chunkedRoots)), maxLength)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(participation)))
	return ssz.MixInLength(bytesRoot, lengthBuf), nil
}

func validatorsRoot(validators []*ethpb.Validator) ([32]byte, error) {
	roots := make([][32]byte, len(validators))
	for i, v := range validators {
		if v == nil {
			continue
		}
		root, err := v.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const VALIDATOR_REGISTRY_LIMIT = 1099511627776
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), VALIDATOR_REGISTRY_LIMIT)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(validators)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func balancesRoot(balances []uint64) ([32]byte, error) {
	return uint64ListRoot(balances)
}

func eth1DataVotesRoot(votes []*ethpb.Eth1Data, maxSize uint64) ([32]byte, error) {
	roots := make([][32]byte, len(votes))
	for i, v := range votes {
		if v == nil {
			continue
		}
		root, err := v.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), maxSize)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(votes)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func historicalSummariesRoot(summaries []*ethpb.HistoricalSummary) ([32]byte, error) {
	roots := make([][32]byte, len(summaries))
	for i, s := range summaries {
		if s == nil {
			continue
		}
		root, err := s.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const HISTORICAL_ROOTS_LIMIT = 16777216
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), HISTORICAL_ROOTS_LIMIT)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(summaries)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func pendingDepositsRoot(deposits []*ethpb.PendingDeposit) ([32]byte, error) {
	roots := make([][32]byte, len(deposits))
	for i, d := range deposits {
		if d == nil {
			continue
		}
		root, err := d.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const PENDING_DEPOSITS_LIMIT = 134217728
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), PENDING_DEPOSITS_LIMIT)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(deposits)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func pendingPartialWithdrawalsRoot(withdrawals []*ethpb.PendingPartialWithdrawal) ([32]byte, error) {
	roots := make([][32]byte, len(withdrawals))
	for i, w := range withdrawals {
		if w == nil {
			continue
		}
		root, err := w.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const PENDING_PARTIAL_WITHDRAWALS_LIMIT = 134217728
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), PENDING_PARTIAL_WITHDRAWALS_LIMIT)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(withdrawals)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func pendingConsolidationsRoot(consolidations []*ethpb.PendingConsolidation) ([32]byte, error) {
	roots := make([][32]byte, len(consolidations))
	for i, c := range consolidations {
		if c == nil {
			continue
		}
		root, err := c.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const PENDING_CONSOLIDATIONS_LIMIT = 262144
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), PENDING_CONSOLIDATIONS_LIMIT)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(consolidations)))
	return ssz.MixInLength(root, lengthBuf), nil
}

// Block body helper functions

func proposerSlashingsRoot(slashings []*ethpb.ProposerSlashing) ([32]byte, error) {
	roots := make([][32]byte, len(slashings))
	for i, s := range slashings {
		if s == nil {
			continue
		}
		root, err := s.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_PROPOSER_SLASHINGS = 16
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_PROPOSER_SLASHINGS)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(slashings)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func proposerSlashingsRootDeneb(slashings []*ethpb.ProposerSlashing) ([32]byte, error) {
	return proposerSlashingsRoot(slashings)
}

func attesterSlashingsRoot(slashings []*ethpb.AttesterSlashingElectra) ([32]byte, error) {
	roots := make([][32]byte, len(slashings))
	for i, s := range slashings {
		if s == nil {
			continue
		}
		root, err := s.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_ATTESTER_SLASHINGS_ELECTRA = 1
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_ATTESTER_SLASHINGS_ELECTRA)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(slashings)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func attesterSlashingsRootDeneb(slashings []*ethpb.AttesterSlashing) ([32]byte, error) {
	roots := make([][32]byte, len(slashings))
	for i, s := range slashings {
		if s == nil {
			continue
		}
		root, err := s.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_ATTESTER_SLASHINGS = 2
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_ATTESTER_SLASHINGS)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(slashings)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func attestationsRoot(attestations []*ethpb.AttestationElectra) ([32]byte, error) {
	roots := make([][32]byte, len(attestations))
	for i, a := range attestations {
		if a == nil {
			continue
		}
		root, err := a.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_ATTESTATIONS_ELECTRA = 8
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_ATTESTATIONS_ELECTRA)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(attestations)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func attestationsRootDeneb(attestations []*ethpb.Attestation) ([32]byte, error) {
	roots := make([][32]byte, len(attestations))
	for i, a := range attestations {
		if a == nil {
			continue
		}
		root, err := a.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_ATTESTATIONS = 128
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_ATTESTATIONS)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(attestations)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func depositsRoot(deposits []*ethpb.Deposit) ([32]byte, error) {
	roots := make([][32]byte, len(deposits))
	for i, d := range deposits {
		if d == nil {
			continue
		}
		root, err := d.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_DEPOSITS = 16
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_DEPOSITS)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(deposits)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func voluntaryExitsRoot(exits []*ethpb.SignedVoluntaryExit) ([32]byte, error) {
	roots := make([][32]byte, len(exits))
	for i, e := range exits {
		if e == nil {
			continue
		}
		root, err := e.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_VOLUNTARY_EXITS = 16
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_VOLUNTARY_EXITS)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(exits)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func blsToExecutionChangesRoot(changes []*ethpb.SignedBLSToExecutionChange) ([32]byte, error) {
	roots := make([][32]byte, len(changes))
	for i, c := range changes {
		if c == nil {
			continue
		}
		root, err := c.HashTreeRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_BLS_TO_EXECUTION_CHANGES = 16
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_BLS_TO_EXECUTION_CHANGES)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(changes)))
	return ssz.MixInLength(root, lengthBuf), nil
}

func blobKzgCommitmentsRoot(commitments [][]byte) ([32]byte, error) {
	roots := make([][32]byte, len(commitments))
	for i, c := range commitments {
		// KZG commitment is 48 bytes, hash it
		hh := fastssz.NewHasher()
		hh.PutBytes(c)
		root, err := hh.HashRoot()
		if err != nil {
			return [32]byte{}, err
		}
		roots[i] = root
	}
	const MAX_BLOB_COMMITMENTS_PER_BLOCK = 4096
	root, err := ssz.BitwiseMerkleize(roots, uint64(len(roots)), MAX_BLOB_COMMITMENTS_PER_BLOCK)
	if err != nil {
		return [32]byte{}, err
	}
	lengthBuf := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthBuf, uint64(len(commitments)))
	return ssz.MixInLength(root, lengthBuf), nil
}
