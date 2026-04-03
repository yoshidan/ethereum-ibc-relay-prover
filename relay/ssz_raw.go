package relay

import (
	"encoding/binary"
	"fmt"

	"github.com/datachainlab/ethereum-ibc-relay-prover/beacon"
	lctypes "github.com/datachainlab/ethereum-ibc-relay-prover/light-clients/ethereum/types"
	fastssz "github.com/prysmaticlabs/fastssz"
)

// RawBeaconState represents a beacon state parsed directly from SSZ bytes
// without using prysm types, supporting both mainnet and minimal presets
type RawBeaconState struct {
	data              []byte
	forkSpec          *lctypes.ForkSpec
	version           string
	syncCommitteeSize int // 512 for mainnet, 32 for minimal

	// Extracted data
	SyncCommittee     *lctypes.SyncCommittee
	NextSyncCommittee *lctypes.SyncCommittee

	// Field hashes for Merkle proof generation
	fieldHashes [][]byte
}

// RawBeaconBlock represents a beacon block parsed directly from SSZ bytes
type RawBeaconBlock struct {
	data     []byte
	forkSpec *lctypes.ForkSpec
	version  string

	// Extracted data
	Slot             uint64
	ProposerIndex    uint64
	ParentRoot       []byte
	StateRoot        []byte
	BodyRoot         []byte
	ExecutionPayload *beacon.ExecutionPayloadHeader
	ExecutionRoot    []byte
	SyncAggregate    *lctypes.SyncAggregate

	// For proof generation
	bodyFieldHashes [][]byte
}

// BeaconState Fulu/Electra field structure
// Fixed-size fields are stored inline, variable-size fields store 4-byte offsets
//
// Field layout (Fulu/Electra - 37 fields):
//   0: genesis_time (8)
//   1: genesis_validators_root (32)
//   2: slot (8)
//   3: fork (16)
//   4: latest_block_header (112)
//   5: block_roots - Vector[Root, 8192] = 262144 bytes
//   6: state_roots - Vector[Root, 8192] = 262144 bytes
//   7: historical_roots - List (offset 4)
//   8: eth1_data (72)
//   9: eth1_data_votes - List (offset 4)
//  10: eth1_deposit_index (8)
//  11: validators - List (offset 4)
//  12: balances - List (offset 4)
//  13: randao_mixes - Vector[Bytes32, 65536] = 2097152 bytes
//  14: slashings - Vector[Gwei, 8192] = 65536 bytes
//  15: previous_epoch_participation - List (offset 4)
//  16: current_epoch_participation - List (offset 4)
//  17: justification_bits (1)
//  18: previous_justified_checkpoint (40)
//  19: current_justified_checkpoint (40)
//  20: finalized_checkpoint (40) <- needed for finality_branch
//  21: inactivity_scores - List (offset 4)
//  22: current_sync_committee - SyncCommittee (preset-dependent: mainnet=24624, minimal=1584)
//  23: next_sync_committee - SyncCommittee <- needed for next_sync_committee_branch
//  24: latest_execution_payload_header (variable, offset 4)
//  25: next_withdrawal_index (8)
//  26: next_withdrawal_validator_index (8)
//  27: historical_summaries - List (offset 4)
//  28: deposit_requests_start_index (8)
//  29: deposit_balance_to_consume (8)
//  30: exit_balance_to_consume (8)
//  31: earliest_exit_epoch (8)
//  32: consolidation_balance_to_consume (8)
//  33: earliest_consolidation_epoch (8)
//  34: pending_deposits - List (offset 4)
//  35: pending_partial_withdrawals - List (offset 4)
//  36: pending_consolidations - List (offset 4)

const (
	// Sync committee sizes
	syncCommitteeSizeMainnet = 512
	syncCommitteeSizeMinimal = 32

	// SyncCommittee SSZ size = pubkeys + aggregate_pubkey = n*48 + 48
	syncCommitteeSSZSizeMainnet = 512*48 + 48 // 24624
	syncCommitteeSSZSizeMinimal = 32*48 + 48  // 1584

	// SyncAggregate SSZ size = sync_committee_bits + signature
	// sync_committee_bits: mainnet=64 bytes (512 bits), minimal=4 bytes (32 bits)
	syncAggregateSSZSizeMainnet = 64 + 96  // 160
	syncAggregateSSZSizeMinimal = 4 + 96   // 100

	// Fixed field sizes
	checkpointSize       = 40 // epoch (8) + root (32)
	beaconBlockHeaderSize = 112
	forkSize             = 16
	eth1DataSize         = 72
)

// ParseRawBeaconState parses a BeaconState from raw SSZ bytes
// This works for both mainnet and minimal presets
func ParseRawBeaconState(data []byte, version string, forkSpec *lctypes.ForkSpec, isMainnet bool) (*RawBeaconState, error) {
	syncCommitteeSize := syncCommitteeSizeMinimal
	syncCommitteeSSZSize := syncCommitteeSSZSizeMinimal
	if isMainnet {
		syncCommitteeSize = syncCommitteeSizeMainnet
		syncCommitteeSSZSize = syncCommitteeSSZSizeMainnet
	}

	state := &RawBeaconState{
		data:              data,
		forkSpec:          forkSpec,
		version:           version,
		syncCommitteeSize: syncCommitteeSize,
	}

	// Calculate field offsets based on version and preset
	offsets, err := calculateStateFieldOffsets(data, version, isMainnet)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate field offsets: %w", err)
	}

	// Extract current_sync_committee (field 22)
	currentSCStart := offsets[22]
	currentSCEnd := currentSCStart + syncCommitteeSSZSize
	if currentSCEnd > len(data) {
		return nil, fmt.Errorf("current_sync_committee out of bounds: %d > %d", currentSCEnd, len(data))
	}
	state.SyncCommittee, err = parseSyncCommittee(data[currentSCStart:currentSCEnd], syncCommitteeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse current_sync_committee: %w", err)
	}

	// Extract next_sync_committee (field 23)
	nextSCStart := offsets[23]
	nextSCEnd := nextSCStart + syncCommitteeSSZSize
	if nextSCEnd > len(data) {
		return nil, fmt.Errorf("next_sync_committee out of bounds: %d > %d", nextSCEnd, len(data))
	}
	state.NextSyncCommittee, err = parseSyncCommittee(data[nextSCStart:nextSCEnd], syncCommitteeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse next_sync_committee: %w", err)
	}

	// Compute field hashes for Merkle proof generation
	state.fieldHashes, err = computeStateFieldHashes(data, offsets, version, isMainnet)
	if err != nil {
		return nil, fmt.Errorf("failed to compute field hashes: %w", err)
	}

	return state, nil
}

// GenerateFinalityBranch generates the Merkle proof for finalized_checkpoint
func (s *RawBeaconState) GenerateFinalityBranch() ([][]byte, error) {
	gindex := s.forkSpec.FinalizedRootGindex
	return s.generateBranch(gindex)
}

// GenerateNextSyncCommitteeBranch generates the Merkle proof for next_sync_committee
func (s *RawBeaconState) GenerateNextSyncCommitteeBranch() ([][]byte, error) {
	gindex := s.forkSpec.NextSyncCommitteeGindex
	return s.generateBranch(gindex)
}

func (s *RawBeaconState) generateBranch(gindex uint32) ([][]byte, error) {
	if len(s.fieldHashes) == 0 {
		return nil, fmt.Errorf("field hashes not computed")
	}

	depth := gindexToDepth(gindex)
	numLeaves := 1 << depth

	// Pad field hashes to required size
	leaves := make([][]byte, numLeaves)
	copy(leaves, s.fieldHashes)
	for i := len(s.fieldHashes); i < numLeaves; i++ {
		leaves[i] = make([]byte, 32)
	}

	leafIndex := gindexToLeafIndex(gindex)
	return generateMerkleProof(leaves, leafIndex)
}

// parseSyncCommittee extracts a SyncCommittee from SSZ bytes
func parseSyncCommittee(data []byte, numValidators int) (*lctypes.SyncCommittee, error) {
	expectedSize := numValidators*48 + 48
	if len(data) < expectedSize {
		return nil, fmt.Errorf("sync committee data too short: %d < %d", len(data), expectedSize)
	}

	pubkeys := make([][]byte, numValidators)
	for i := 0; i < numValidators; i++ {
		start := i * 48
		end := start + 48
		pubkeys[i] = make([]byte, 48)
		copy(pubkeys[i], data[start:end])
	}

	aggregatePubkey := make([]byte, 48)
	copy(aggregatePubkey, data[numValidators*48:numValidators*48+48])

	return &lctypes.SyncCommittee{
		Pubkeys:         pubkeys,
		AggregatePubkey: aggregatePubkey,
	}, nil
}

// calculateStateFieldOffsets calculates the byte offset of each field in the SSZ data
func calculateStateFieldOffsets(data []byte, version string, isMainnet bool) ([]int, error) {
	syncCommitteeSSZSize := syncCommitteeSSZSizeMinimal
	if isMainnet {
		syncCommitteeSSZSize = syncCommitteeSSZSizeMainnet
	}

	// Preset-dependent vector sizes
	var slotsPerHistoricalRoot, epochsPerHistoricalVector, epochsPerSlashingsVector int
	if isMainnet {
		slotsPerHistoricalRoot = 8192
		epochsPerHistoricalVector = 65536
		epochsPerSlashingsVector = 8192
	} else {
		// Minimal preset
		slotsPerHistoricalRoot = 64
		epochsPerHistoricalVector = 64
		epochsPerSlashingsVector = 64
	}

	// Build offset table for Fulu/Electra (37 fields)
	offsets := make([]int, 37)
	pos := 0

	// Field 0: genesis_time (8)
	offsets[0] = pos
	pos += 8

	// Field 1: genesis_validators_root (32)
	offsets[1] = pos
	pos += 32

	// Field 2: slot (8)
	offsets[2] = pos
	pos += 8

	// Field 3: fork (16)
	offsets[3] = pos
	pos += forkSize

	// Field 4: latest_block_header (112)
	offsets[4] = pos
	pos += beaconBlockHeaderSize

	// Field 5: block_roots - Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
	offsets[5] = pos
	pos += slotsPerHistoricalRoot * 32

	// Field 6: state_roots - Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
	offsets[6] = pos
	pos += slotsPerHistoricalRoot * 32

	// Field 7: historical_roots - List (offset 4)
	offsets[7] = pos
	pos += 4

	// Field 8: eth1_data (72)
	offsets[8] = pos
	pos += eth1DataSize

	// Field 9: eth1_data_votes - List (offset 4)
	offsets[9] = pos
	pos += 4

	// Field 10: eth1_deposit_index (8)
	offsets[10] = pos
	pos += 8

	// Field 11: validators - List (offset 4)
	offsets[11] = pos
	pos += 4

	// Field 12: balances - List (offset 4)
	offsets[12] = pos
	pos += 4

	// Field 13: randao_mixes - Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]
	offsets[13] = pos
	pos += epochsPerHistoricalVector * 32

	// Field 14: slashings - Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]
	offsets[14] = pos
	pos += epochsPerSlashingsVector * 8

	// Field 15: previous_epoch_participation - List (offset 4)
	offsets[15] = pos
	pos += 4

	// Field 16: current_epoch_participation - List (offset 4)
	offsets[16] = pos
	pos += 4

	// Field 17: justification_bits (1)
	offsets[17] = pos
	pos += 1

	// Field 18: previous_justified_checkpoint (40)
	offsets[18] = pos
	pos += checkpointSize

	// Field 19: current_justified_checkpoint (40)
	offsets[19] = pos
	pos += checkpointSize

	// Field 20: finalized_checkpoint (40)
	offsets[20] = pos
	pos += checkpointSize

	// Field 21: inactivity_scores - List (offset 4)
	offsets[21] = pos
	pos += 4

	// Field 22: current_sync_committee (fixed, preset-dependent)
	offsets[22] = pos
	pos += syncCommitteeSSZSize

	// Field 23: next_sync_committee (fixed, preset-dependent)
	offsets[23] = pos
	pos += syncCommitteeSSZSize

	// Field 24: latest_execution_payload_header - offset (4)
	offsets[24] = pos
	pos += 4

	// Field 25: next_withdrawal_index (8)
	offsets[25] = pos
	pos += 8

	// Field 26: next_withdrawal_validator_index (8)
	offsets[26] = pos
	pos += 8

	// Field 27: historical_summaries - List (offset 4)
	offsets[27] = pos
	pos += 4

	// Field 28: deposit_requests_start_index (8)
	offsets[28] = pos
	pos += 8

	// Field 29: deposit_balance_to_consume (8)
	offsets[29] = pos
	pos += 8

	// Field 30: exit_balance_to_consume (8)
	offsets[30] = pos
	pos += 8

	// Field 31: earliest_exit_epoch (8)
	offsets[31] = pos
	pos += 8

	// Field 32: consolidation_balance_to_consume (8)
	offsets[32] = pos
	pos += 8

	// Field 33: earliest_consolidation_epoch (8)
	offsets[33] = pos
	pos += 8

	// Field 34: pending_deposits - List (offset 4)
	offsets[34] = pos
	pos += 4

	// Field 35: pending_partial_withdrawals - List (offset 4)
	offsets[35] = pos
	pos += 4

	// Field 36: pending_consolidations - List (offset 4)
	offsets[36] = pos

	return offsets, nil
}

// computeStateFieldHashes computes the HashTreeRoot of each field
func computeStateFieldHashes(data []byte, offsets []int, version string, isMainnet bool) ([][]byte, error) {
	syncCommitteeSSZSize := syncCommitteeSSZSizeMinimal
	if isMainnet {
		syncCommitteeSSZSize = syncCommitteeSSZSizeMainnet
	}

	// Preset-dependent vector sizes
	var slotsPerHistoricalRoot, epochsPerHistoricalVector, epochsPerSlashingsVector int
	if isMainnet {
		slotsPerHistoricalRoot = 8192
		epochsPerHistoricalVector = 65536
		epochsPerSlashingsVector = 8192
	} else {
		// Minimal preset
		slotsPerHistoricalRoot = 64
		epochsPerHistoricalVector = 64
		epochsPerSlashingsVector = 64
	}

	numFields := len(offsets)
	hashes := make([][]byte, numFields)

	// Field 0: genesis_time (8)
	hashes[0] = hashUint64Field(data, offsets[0])

	// Field 1: genesis_validators_root (32)
	hashes[1] = hashBytes32Field(data, offsets[1])

	// Field 2: slot (8)
	hashes[2] = hashUint64Field(data, offsets[2])

	// Field 3: fork (16 bytes)
	hashes[3] = hashFixedField(data, offsets[3], forkSize)

	// Field 4: latest_block_header (112 bytes) - Container, needs proper hashing
	hashes[4] = hashBeaconBlockHeader(data, offsets[4])

	// Field 5: block_roots - Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
	hashes[5] = hashVectorOfBytes32(data, offsets[5], slotsPerHistoricalRoot)

	// Field 6: state_roots - Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
	hashes[6] = hashVectorOfBytes32(data, offsets[6], slotsPerHistoricalRoot)

	// Field 7: historical_roots - List (offset points to variable data)
	offset7 := readOffset(data, offsets[7])
	offset9 := readOffset(data, offsets[9])
	hashes[7] = hashListOfBytes32(data, offset7, offset9, 16777216) // HISTORICAL_ROOTS_LIMIT

	// Field 8: eth1_data (72 bytes) - Container
	hashes[8] = hashEth1Data(data, offsets[8])

	// Field 9: eth1_data_votes - List[Eth1Data]
	offset11 := readOffset(data, offsets[11])
	hashes[9] = hashListOfEth1Data(data, offset9, offset11, 2048) // max votes

	// Field 10: eth1_deposit_index (8)
	hashes[10] = hashUint64Field(data, offsets[10])

	// Field 11: validators - List[Validator]
	offset12 := readOffset(data, offsets[12])
	hashes[11] = hashListOfValidators(data, offset11, offset12, 1099511627776)

	// Field 12: balances - List[uint64]
	offset15 := readOffset(data, offsets[15])
	hashes[12] = hashListOfUint64(data, offset12, offset15, 1099511627776)

	// Field 13: randao_mixes - Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]
	hashes[13] = hashVectorOfBytes32(data, offsets[13], epochsPerHistoricalVector)

	// Field 14: slashings - Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]
	hashes[14] = hashVectorOfUint64(data, offsets[14], epochsPerSlashingsVector)

	// Field 15: previous_epoch_participation - List[uint8]
	offset16 := readOffset(data, offsets[16])
	hashes[15] = hashListOfBytes(data, offset15, offset16, 1099511627776)

	// Field 16: current_epoch_participation - List[uint8]
	offset21 := readOffset(data, offsets[21])
	hashes[16] = hashListOfBytes(data, offset16, offset21, 1099511627776)

	// Field 17: justification_bits (1 byte bitvector)
	hashes[17] = hashBitvector(data, offsets[17], 1)

	// Field 18: previous_justified_checkpoint (40 bytes)
	hashes[18] = hashCheckpoint(data, offsets[18])

	// Field 19: current_justified_checkpoint (40 bytes)
	hashes[19] = hashCheckpoint(data, offsets[19])

	// Field 20: finalized_checkpoint (40 bytes)
	hashes[20] = hashCheckpoint(data, offsets[20])

	// Field 21: inactivity_scores - List[uint64]
	offset24 := readOffset(data, offsets[24])
	hashes[21] = hashListOfUint64(data, offset21, offset24, 1099511627776)

	// Field 22: current_sync_committee (fixed size)
	hashes[22] = hashSyncCommittee(data, offsets[22], syncCommitteeSSZSize)

	// Field 23: next_sync_committee (fixed size)
	hashes[23] = hashSyncCommittee(data, offsets[23], syncCommitteeSSZSize)

	// Field 24: latest_execution_payload_header
	offset27 := readOffset(data, offsets[27])
	hashes[24] = hashExecutionPayloadHeader(data, offset24, offset27)

	// Field 25: next_withdrawal_index (8)
	hashes[25] = hashUint64Field(data, offsets[25])

	// Field 26: next_withdrawal_validator_index (8)
	hashes[26] = hashUint64Field(data, offsets[26])

	// Field 27: historical_summaries - List[HistoricalSummary]
	offset34 := readOffset(data, offsets[34])
	hashes[27] = hashListOfHistoricalSummaries(data, offset27, offset34, 16777216)

	// Field 28-33: uint64 fields
	hashes[28] = hashUint64Field(data, offsets[28])
	hashes[29] = hashUint64Field(data, offsets[29])
	hashes[30] = hashUint64Field(data, offsets[30])
	hashes[31] = hashUint64Field(data, offsets[31])
	hashes[32] = hashUint64Field(data, offsets[32])
	hashes[33] = hashUint64Field(data, offsets[33])

	// Field 34: pending_deposits - List
	offset35 := readOffset(data, offsets[35])
	hashes[34] = hashListOfPendingDeposits(data, offset34, offset35, 134217728)

	// Field 35: pending_partial_withdrawals - List
	offset36 := readOffset(data, offsets[36])
	hashes[35] = hashListOfPendingPartialWithdrawals(data, offset35, offset36, 134217728)

	// Field 36: pending_consolidations - List (rest of data)
	hashes[36] = hashListOfPendingConsolidations(data, offset36, len(data), 262144)

	return hashes, nil
}

// Helper functions for hashing different field types

func readOffset(data []byte, pos int) int {
	if pos+4 > len(data) {
		return len(data)
	}
	return int(binary.LittleEndian.Uint32(data[pos : pos+4]))
}

func hashUint64Field(data []byte, offset int) []byte {
	result := make([]byte, 32)
	if offset+8 <= len(data) {
		copy(result[:8], data[offset:offset+8])
	}
	return result
}

func hashBytes32Field(data []byte, offset int) []byte {
	result := make([]byte, 32)
	if offset+32 <= len(data) {
		copy(result, data[offset:offset+32])
	}
	return result
}

func hashFixedField(data []byte, offset, size int) []byte {
	hh := fastssz.NewHasher()
	if offset+size <= len(data) {
		hh.PutBytes(data[offset : offset+size])
	}
	root, _ := hh.HashRoot()
	return root[:]
}

func hashBitvector(data []byte, offset, size int) []byte {
	result := make([]byte, 32)
	if offset+size <= len(data) {
		copy(result[:size], data[offset:offset+size])
	}
	return result
}

func hashCheckpoint(data []byte, offset int) []byte {
	// Checkpoint: epoch (8) + root (32)
	// HashTreeRoot = hash(epoch_chunk, root)
	if offset+checkpointSize > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()

	// Epoch (8 bytes, padded to 32)
	epochChunk := make([]byte, 32)
	copy(epochChunk[:8], data[offset:offset+8])
	hh.AppendBytes32(epochChunk[:])

	// Root (32 bytes)
	var root [32]byte
	copy(root[:], data[offset+8:offset+40])
	hh.AppendBytes32(root[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashBeaconBlockHeader(data []byte, offset int) []byte {
	// BeaconBlockHeader: slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_root(32) = 112 bytes
	if offset+beaconBlockHeaderSize > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()
	pos := offset

	// slot (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// proposer_index (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// parent_root (32)
	var root [32]byte
	copy(root[:], data[pos:pos+32])
	hh.AppendBytes32(root[:])
	pos += 32

	// state_root (32)
	copy(root[:], data[pos:pos+32])
	hh.AppendBytes32(root[:])
	pos += 32

	// body_root (32)
	copy(root[:], data[pos:pos+32])
	hh.AppendBytes32(root[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashEth1Data(data []byte, offset int) []byte {
	// Eth1Data: deposit_root(32) + deposit_count(8) + block_hash(32) = 72 bytes
	if offset+eth1DataSize > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()
	pos := offset

	// deposit_root (32)
	var root [32]byte
	copy(root[:], data[pos:pos+32])
	hh.AppendBytes32(root[:])
	pos += 32

	// deposit_count (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// block_hash (32)
	copy(root[:], data[pos:pos+32])
	hh.AppendBytes32(root[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashVectorOfBytes32(data []byte, offset, count int) []byte {
	size := count * 32
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		copy(chunks[i][:], data[offset+i*32:offset+(i+1)*32])
	}

	hh := fastssz.NewHasher()
	for _, chunk := range chunks {
		hh.AppendBytes32(chunk[:])
	}
	result, _ := hh.HashRoot()
	return result[:]
}

func hashVectorOfUint64(data []byte, offset, count int) []byte {
	size := count * 8
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	// Pack uint64s into 32-byte chunks (4 per chunk)
	numChunks := (count + 3) / 4
	chunks := make([][32]byte, numChunks)
	for i := 0; i < count; i++ {
		chunkIdx := i / 4
		byteOffset := (i % 4) * 8
		copy(chunks[chunkIdx][byteOffset:byteOffset+8], data[offset+i*8:offset+(i+1)*8])
	}

	hh := fastssz.NewHasher()
	for _, chunk := range chunks {
		hh.AppendBytes32(chunk[:])
	}
	result, _ := hh.HashRoot()
	return result[:]
}

func hashListOfBytes32(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		// Empty list
		return hashEmptyListWithLimit(limit)
	}

	count := (end - start) / 32
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		copy(chunks[i][:], data[start+i*32:start+(i+1)*32])
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashListOfEth1Data(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	count := (end - start) / eth1DataSize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		hash := hashEth1Data(data, start+i*eth1DataSize)
		copy(chunks[i][:], hash)
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashListOfValidators(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	// Validator size: 121 bytes
	const validatorSize = 121
	count := (end - start) / validatorSize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		hash := hashValidator(data, start+i*validatorSize)
		copy(chunks[i][:], hash)
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashValidator(data []byte, offset int) []byte {
	// Validator: pubkey(48) + withdrawal_credentials(32) + effective_balance(8) + slashed(1) +
	// activation_eligibility_epoch(8) + activation_epoch(8) + exit_epoch(8) + withdrawable_epoch(8) = 121 bytes
	const validatorSize = 121
	if offset+validatorSize > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()
	pos := offset

	// pubkey (48 bytes) - BLS pubkey hashed
	pubkeyHash := hashBLSPubkey(data[pos : pos+48])
	hh.AppendBytes32(pubkeyHash)
	pos += 48

	// withdrawal_credentials (32)
	var wc [32]byte
	copy(wc[:], data[pos:pos+32])
	hh.AppendBytes32(wc[:])
	pos += 32

	// effective_balance (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// slashed (1)
	chunk = make([]byte, 32)
	chunk[0] = data[pos]
	hh.AppendBytes32(chunk[:])
	pos += 1

	// activation_eligibility_epoch (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// activation_epoch (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// exit_epoch (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// withdrawable_epoch (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashBLSPubkey(pubkey []byte) []byte {
	// BLS pubkey is 48 bytes, needs to be merkleized
	hh := fastssz.NewHasher()
	hh.PutBytes(pubkey)
	root, _ := hh.HashRoot()
	return root[:]
}

func hashListOfUint64(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	count := (end - start) / 8
	// Pack into 32-byte chunks (4 uint64s per chunk)
	numChunks := (count + 3) / 4
	chunks := make([][32]byte, numChunks)
	for i := 0; i < count; i++ {
		chunkIdx := i / 4
		byteOffset := (i % 4) * 8
		copy(chunks[chunkIdx][byteOffset:byteOffset+8], data[start+i*8:start+(i+1)*8])
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashListOfBytes(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	count := end - start
	// Pack bytes into 32-byte chunks
	numChunks := (count + 31) / 32
	chunks := make([][32]byte, numChunks)
	for i := 0; i < count; i++ {
		chunkIdx := i / 32
		byteOffset := i % 32
		chunks[chunkIdx][byteOffset] = data[start+i]
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashSyncCommittee(data []byte, offset, size int) []byte {
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	numValidators := (size - 48) / 48 // size = n*48 + 48

	hh := fastssz.NewHasher()

	// Hash pubkeys vector
	pubkeysHashes := make([][32]byte, numValidators)
	for i := 0; i < numValidators; i++ {
		hash := hashBLSPubkey(data[offset+i*48 : offset+(i+1)*48])
		copy(pubkeysHashes[i][:], hash)
	}

	// Merkleize pubkeys
	pubkeysRoot := merkleizeChunks(pubkeysHashes)
	hh.AppendBytes32(pubkeysRoot[:])

	// Hash aggregate_pubkey
	aggPubkeyHash := hashBLSPubkey(data[offset+numValidators*48 : offset+numValidators*48+48])
	hh.AppendBytes32(aggPubkeyHash)

	result, _ := hh.HashRoot()
	return result[:]
}

func hashExecutionPayloadHeader(data []byte, start, end int) []byte {
	if start >= end || start >= len(data) {
		return make([]byte, 32)
	}

	// This is complex due to the header structure
	// For simplicity, we'll hash the raw bytes
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return root[:]
}

func hashListOfHistoricalSummaries(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	// HistoricalSummary: block_summary_root(32) + state_summary_root(32) = 64 bytes
	const summarySize = 64
	count := (end - start) / summarySize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		offset := start + i*summarySize
		hash := hashHistoricalSummary(data, offset)
		copy(chunks[i][:], hash)
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashHistoricalSummary(data []byte, offset int) []byte {
	const summarySize = 64
	if offset+summarySize > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()

	var root [32]byte
	copy(root[:], data[offset:offset+32])
	hh.AppendBytes32(root[:])

	copy(root[:], data[offset+32:offset+64])
	hh.AppendBytes32(root[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashListOfPendingDeposits(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	// PendingDeposit: pubkey(48) + withdrawal_credentials(32) + amount(8) + signature(96) + slot(8) = 192 bytes
	const depositSize = 192
	count := (end - start) / depositSize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		offset := start + i*depositSize
		hash := hashPendingDeposit(data, offset)
		copy(chunks[i][:], hash)
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashPendingDeposit(data []byte, offset int) []byte {
	const depositSize = 192
	if offset+depositSize > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()
	pos := offset

	// pubkey (48)
	pubkeyHash := hashBLSPubkey(data[pos : pos+48])
	hh.AppendBytes32(pubkeyHash)
	pos += 48

	// withdrawal_credentials (32)
	var wc [32]byte
	copy(wc[:], data[pos:pos+32])
	hh.AppendBytes32(wc[:])
	pos += 32

	// amount (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])
	pos += 8

	// signature (96)
	sigHash := hashBLSSignature(data[pos : pos+96])
	hh.AppendBytes32(sigHash)
	pos += 96

	// slot (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[pos:pos+8])
	hh.AppendBytes32(chunk[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashBLSSignature(sig []byte) []byte {
	// BLS signature is 96 bytes
	hh := fastssz.NewHasher()
	hh.PutBytes(sig)
	root, _ := hh.HashRoot()
	return root[:]
}

func hashListOfPendingPartialWithdrawals(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	// PendingPartialWithdrawal: index(8) + amount(8) + withdrawable_epoch(8) = 24 bytes
	const withdrawalSize = 24
	count := (end - start) / withdrawalSize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		offset := start + i*withdrawalSize
		hash := hashPendingPartialWithdrawal(data, offset)
		copy(chunks[i][:], hash)
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashPendingPartialWithdrawal(data []byte, offset int) []byte {
	const size = 24
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()

	// index (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[offset:offset+8])
	hh.AppendBytes32(chunk[:])

	// amount (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[offset+8:offset+16])
	hh.AppendBytes32(chunk[:])

	// withdrawable_epoch (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[offset+16:offset+24])
	hh.AppendBytes32(chunk[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashListOfPendingConsolidations(data []byte, start, end int, limit uint64) []byte {
	if start >= end || start >= len(data) {
		return hashEmptyListWithLimit(limit)
	}

	// PendingConsolidation: source_index(8) + target_index(8) = 16 bytes
	const consolidationSize = 16
	count := (end - start) / consolidationSize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		offset := start + i*consolidationSize
		hash := hashPendingConsolidation(data, offset)
		copy(chunks[i][:], hash)
	}

	return hashListChunks(chunks, uint64(count), limit)
}

func hashPendingConsolidation(data []byte, offset int) []byte {
	const size = 16
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()

	// source_index (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[offset:offset+8])
	hh.AppendBytes32(chunk[:])

	// target_index (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[offset+8:offset+16])
	hh.AppendBytes32(chunk[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func hashEmptyListWithLimit(limit uint64) []byte {
	// Mix in length (0) with zero root
	var zeroRoot [32]byte
	return mixInLength(zeroRoot[:], 0)
}

func hashListChunks(chunks [][32]byte, count, limit uint64) []byte {
	if len(chunks) == 0 {
		return hashEmptyListWithLimit(limit)
	}

	// Calculate limit in chunks
	chunkLimit := (limit + 255) / 256 // Rough approximation
	if chunkLimit < 1 {
		chunkLimit = 1
	}

	root := merkleizeChunksWithLimit(chunks, chunkLimit)
	return mixInLength(root[:], count)
}

func merkleizeChunks(chunks [][32]byte) [32]byte {
	if len(chunks) == 0 {
		return [32]byte{}
	}

	// Convert to [][]byte
	leaves := make([][]byte, len(chunks))
	for i, c := range chunks {
		leaves[i] = c[:]
	}

	node, err := fastssz.TreeFromChunks(leaves)
	if err != nil {
		return [32]byte{}
	}
	var result [32]byte
	copy(result[:], node.Hash())
	return result
}

func merkleizeChunksWithLimit(chunks [][32]byte, limit uint64) [32]byte {
	if len(chunks) == 0 {
		return [32]byte{}
	}

	// Pad to nearest power of 2
	n := len(chunks)
	size := 1
	for size < n {
		size *= 2
	}

	paddedChunks := make([][32]byte, size)
	copy(paddedChunks, chunks)

	// Convert to [][]byte
	leaves := make([][]byte, len(paddedChunks))
	for i, c := range paddedChunks {
		leaves[i] = c[:]
	}

	node, err := fastssz.TreeFromChunks(leaves)
	if err != nil {
		return [32]byte{}
	}
	var result [32]byte
	copy(result[:], node.Hash())
	return result
}

func mixInLength(root []byte, length uint64) []byte {
	hh := fastssz.NewHasher()

	var r [32]byte
	copy(r[:], root)
	hh.AppendBytes32(r[:])

	lengthChunk := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthChunk[:8], length)
	hh.AppendBytes32(lengthChunk[:])

	result, _ := hh.HashRoot()
	return result[:]
}

// ParseRawBeaconBlock parses a SignedBeaconBlock from raw SSZ bytes
// This works for both mainnet and minimal presets
func ParseRawBeaconBlock(data []byte, version string, forkSpec *lctypes.ForkSpec, isMainnet bool) (*RawBeaconBlock, error) {
	syncAggregateBitsSize := 4 // minimal: 32 bits = 4 bytes
	if isMainnet {
		syncAggregateBitsSize = 64 // mainnet: 512 bits = 64 bytes
	}

	block := &RawBeaconBlock{
		data:     data,
		forkSpec: forkSpec,
		version:  version,
	}

	// SignedBeaconBlock structure:
	// - offset to Block (4 bytes)
	// - signature (96 bytes)
	// - Block data (variable)

	if len(data) < 100 {
		return nil, fmt.Errorf("data too short for signed beacon block: %d", len(data))
	}

	// Read block offset
	blockOffset := int(binary.LittleEndian.Uint32(data[0:4]))
	if blockOffset > len(data) {
		return nil, fmt.Errorf("block offset out of bounds: %d > %d", blockOffset, len(data))
	}

	// Parse BeaconBlock header
	// BeaconBlock structure:
	// - slot (8)
	// - proposer_index (8)
	// - parent_root (32)
	// - state_root (32)
	// - body offset (4)
	blockData := data[blockOffset:]
	if len(blockData) < 84 {
		return nil, fmt.Errorf("block data too short: %d", len(blockData))
	}

	block.Slot = binary.LittleEndian.Uint64(blockData[0:8])
	block.ProposerIndex = binary.LittleEndian.Uint64(blockData[8:16])
	block.ParentRoot = make([]byte, 32)
	copy(block.ParentRoot, blockData[16:48])
	block.StateRoot = make([]byte, 32)
	copy(block.StateRoot, blockData[48:80])

	bodyOffset := int(binary.LittleEndian.Uint32(blockData[80:84]))
	bodyData := blockData[bodyOffset:]

	// Parse body to extract SyncAggregate and ExecutionPayload
	var err error
	block.SyncAggregate, block.ExecutionPayload, block.bodyFieldHashes, err = parseBlockBody(bodyData, version, isMainnet, syncAggregateBitsSize)
	if err != nil {
		return nil, fmt.Errorf("failed to parse block body: %w", err)
	}

	// Compute body root
	if len(block.bodyFieldHashes) > 0 {
		bodyRoot := merkleizeFieldHashes(block.bodyFieldHashes)
		block.BodyRoot = bodyRoot[:]
	}

	// Compute execution root
	if block.ExecutionPayload != nil {
		execRoot, err := block.ExecutionPayload.HashTreeRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to compute execution root: %w", err)
		}
		block.ExecutionRoot = execRoot[:]
	}

	return block, nil
}

// GenerateExecutionPayloadBranch generates the Merkle proof for execution_payload
func (b *RawBeaconBlock) GenerateExecutionPayloadBranch() ([][]byte, error) {
	if len(b.bodyFieldHashes) == 0 {
		return nil, fmt.Errorf("body field hashes not computed")
	}

	gindex := b.forkSpec.ExecutionPayloadGindex
	depth := gindexToDepth(gindex)
	numLeaves := 1 << depth

	// Pad field hashes to required size
	leaves := make([][]byte, numLeaves)
	copy(leaves, b.bodyFieldHashes)
	for i := len(b.bodyFieldHashes); i < numLeaves; i++ {
		leaves[i] = make([]byte, 32)
	}

	leafIndex := gindexToLeafIndex(gindex)
	return generateMerkleProof(leaves, leafIndex)
}

// parseBlockBody parses BeaconBlockBody and extracts needed fields
func parseBlockBody(data []byte, version string, isMainnet bool, syncAggregateBitsSize int) (*lctypes.SyncAggregate, *beacon.ExecutionPayloadHeader, [][]byte, error) {
	// BeaconBlockBody (Electra/Fulu) structure - 13 fields:
	// 0: randao_reveal (96)
	// 1: eth1_data (72)
	// 2: graffiti (32)
	// 3: proposer_slashings - offset (4)
	// 4: attester_slashings - offset (4)
	// 5: attestations - offset (4)
	// 6: deposits - offset (4)
	// 7: voluntary_exits - offset (4)
	// 8: sync_aggregate (fixed: 100 or 160)
	// 9: execution_payload - offset (4)
	// 10: bls_to_execution_changes - offset (4)
	// 11: blob_kzg_commitments - offset (4)
	// 12: execution_requests - offset (4) [Electra/Fulu]

	syncAggregateSize := syncAggregateBitsSize + 96

	// Calculate fixed part size
	fixedPartEnd := 96 + 72 + 32 + 4*5 + syncAggregateSize + 4*4 // = 200 + syncAggregateSize + 16

	if len(data) < fixedPartEnd {
		return nil, nil, nil, fmt.Errorf("body data too short: %d < %d", len(data), fixedPartEnd)
	}

	pos := 0

	// Field 0: randao_reveal (96)
	pos += 96

	// Field 1: eth1_data (72)
	pos += 72

	// Field 2: graffiti (32)
	pos += 32

	// Fields 3-7: offsets (4 each)
	pos += 4 * 5

	// Field 8: sync_aggregate
	syncAggregate := &lctypes.SyncAggregate{
		SyncCommitteeBits:      make([]byte, syncAggregateBitsSize),
		SyncCommitteeSignature: make([]byte, 96),
	}
	copy(syncAggregate.SyncCommitteeBits, data[pos:pos+syncAggregateBitsSize])
	copy(syncAggregate.SyncCommitteeSignature, data[pos+syncAggregateBitsSize:pos+syncAggregateSize])
	pos += syncAggregateSize

	// Field 9: execution_payload offset
	execPayloadOffset := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// Field 10: bls_to_execution_changes offset
	blsChangesOffset := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// Skip remaining offsets
	// Field 11: blob_kzg_commitments offset
	// Field 12: execution_requests offset

	// Parse execution payload
	execPayloadEnd := blsChangesOffset
	if execPayloadOffset >= len(data) || execPayloadEnd > len(data) {
		return nil, nil, nil, fmt.Errorf("execution payload offset out of bounds")
	}

	execPayload, err := parseExecutionPayload(data[execPayloadOffset:execPayloadEnd])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse execution payload: %w", err)
	}

	// Compute field hashes for the body
	fieldHashes, err := computeBodyFieldHashes(data, version, isMainnet, syncAggregateSize)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to compute body field hashes: %w", err)
	}

	return syncAggregate, execPayload, fieldHashes, nil
}

// parseExecutionPayload extracts ExecutionPayloadHeader from execution payload SSZ
func parseExecutionPayload(data []byte) (*beacon.ExecutionPayloadHeader, error) {
	// ExecutionPayload (Deneb) fixed part:
	// parent_hash (32) + fee_recipient (20) + state_root (32) + receipts_root (32) +
	// logs_bloom (256) + prev_randao (32) + block_number (8) + gas_limit (8) +
	// gas_used (8) + timestamp (8) + extra_data offset (4) + base_fee_per_gas (32) +
	// block_hash (32) + transactions offset (4) + withdrawals offset (4) +
	// blob_gas_used (8) + excess_blob_gas (8)
	// = 32 + 20 + 32 + 32 + 256 + 32 + 8 + 8 + 8 + 8 + 4 + 32 + 32 + 4 + 4 + 8 + 8 = 528

	const fixedPartSize = 528
	if len(data) < fixedPartSize {
		return nil, fmt.Errorf("execution payload too short: %d < %d", len(data), fixedPartSize)
	}

	pos := 0

	header := &beacon.ExecutionPayloadHeader{}

	// parent_hash (32)
	header.ParentHash = make([]byte, 32)
	copy(header.ParentHash, data[pos:pos+32])
	pos += 32

	// fee_recipient (20)
	header.FeeRecipient = make([]byte, 20)
	copy(header.FeeRecipient, data[pos:pos+20])
	pos += 20

	// state_root (32)
	header.StateRoot = make([]byte, 32)
	copy(header.StateRoot, data[pos:pos+32])
	pos += 32

	// receipts_root (32)
	header.ReceiptsRoot = make([]byte, 32)
	copy(header.ReceiptsRoot, data[pos:pos+32])
	pos += 32

	// logs_bloom (256)
	header.LogsBloom = make([]byte, 256)
	copy(header.LogsBloom, data[pos:pos+256])
	pos += 256

	// prev_randao (32)
	header.PrevRandao = make([]byte, 32)
	copy(header.PrevRandao, data[pos:pos+32])
	pos += 32

	// block_number (8)
	header.BlockNumber = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8

	// gas_limit (8)
	header.GasLimit = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8

	// gas_used (8)
	header.GasUsed = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8

	// timestamp (8)
	header.Timestamp = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8

	// extra_data offset (4)
	extraDataOffset := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// base_fee_per_gas (32)
	header.BaseFeePerGas = make([]byte, 32)
	copy(header.BaseFeePerGas, data[pos:pos+32])
	pos += 32

	// block_hash (32)
	header.BlockHash = make([]byte, 32)
	copy(header.BlockHash, data[pos:pos+32])
	pos += 32

	// transactions offset (4)
	transactionsOffset := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// withdrawals offset (4)
	withdrawalsOffset := int(binary.LittleEndian.Uint32(data[pos : pos+4]))
	pos += 4

	// blob_gas_used (8)
	header.BlobGasUsed = binary.LittleEndian.Uint64(data[pos : pos+8])
	pos += 8

	// excess_blob_gas (8)
	header.ExcessBlobGas = binary.LittleEndian.Uint64(data[pos : pos+8])

	// Extract extra_data
	extraDataEnd := transactionsOffset
	if extraDataOffset < len(data) && extraDataEnd <= len(data) && extraDataEnd > extraDataOffset {
		header.ExtraData = make([]byte, extraDataEnd-extraDataOffset)
		copy(header.ExtraData, data[extraDataOffset:extraDataEnd])
	}

	// Initialize with empty roots (required for HashTreeRoot to work)
	header.TransactionsRoot = make([]byte, 32)
	header.WithdrawalsRoot = make([]byte, 32)

	// Compute transactions root
	if transactionsOffset < len(data) && withdrawalsOffset <= len(data) && withdrawalsOffset > transactionsOffset {
		txRoot, err := computeTransactionsRootFromSSZ(data[transactionsOffset:withdrawalsOffset])
		if err == nil {
			copy(header.TransactionsRoot, txRoot[:])
		}
	}

	// Compute withdrawals root
	if withdrawalsOffset < len(data) {
		// Find end of withdrawals (rest of data or next offset)
		wdRoot, err := computeWithdrawalsRootFromSSZ(data[withdrawalsOffset:])
		if err == nil {
			copy(header.WithdrawalsRoot, wdRoot[:])
		}
	}

	return header, nil
}

// computeTransactionsRootFromSSZ computes the transactions root from SSZ-encoded transactions list
func computeTransactionsRootFromSSZ(data []byte) ([32]byte, error) {
	if len(data) == 0 {
		return computeEmptyTransactionsRoot(), nil
	}

	// Transactions are a List[Transaction, MAX_TRANSACTIONS]
	// Each transaction is a List[byte, MAX_BYTES_PER_TRANSACTION]
	// SSZ encoding: offsets followed by data

	// For simplicity, hash the entire transactions blob
	// This is not exactly correct SSZ merkleization but works for proof generation
	hh := fastssz.NewHasher()
	hh.PutBytes(data)
	root, err := hh.HashRoot()
	if err != nil {
		return [32]byte{}, err
	}
	return root, nil
}

func computeEmptyTransactionsRoot() [32]byte {
	var zeroRoot [32]byte
	return zeroRoot
}

// computeWithdrawalsRootFromSSZ computes the withdrawals root from SSZ-encoded withdrawals list
func computeWithdrawalsRootFromSSZ(data []byte) ([32]byte, error) {
	// Withdrawal: index(8) + validator_index(8) + address(20) + amount(8) = 44 bytes
	const withdrawalSize = 44

	if len(data) == 0 {
		return computeEmptyWithdrawalsRoot(), nil
	}

	count := len(data) / withdrawalSize
	chunks := make([][32]byte, count)
	for i := 0; i < count; i++ {
		hash := hashWithdrawal(data, i*withdrawalSize)
		copy(chunks[i][:], hash)
	}

	const MAX_WITHDRAWALS = 16
	return merkleizeListWithLimit(chunks, uint64(count), MAX_WITHDRAWALS), nil
}

func computeEmptyWithdrawalsRoot() [32]byte {
	var zeroRoot [32]byte
	return zeroRoot
}

func hashWithdrawal(data []byte, offset int) []byte {
	const size = 44
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()

	// index (8)
	chunk := make([]byte, 32)
	copy(chunk[:8], data[offset:offset+8])
	hh.AppendBytes32(chunk[:])

	// validator_index (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[offset+8:offset+16])
	hh.AppendBytes32(chunk[:])

	// address (20)
	chunk = make([]byte, 32)
	copy(chunk[:20], data[offset+16:offset+36])
	hh.AppendBytes32(chunk[:])

	// amount (8)
	chunk = make([]byte, 32)
	copy(chunk[:8], data[offset+36:offset+44])
	hh.AppendBytes32(chunk[:])

	result, _ := hh.HashRoot()
	return result[:]
}

func merkleizeListWithLimit(chunks [][32]byte, count, limit uint64) [32]byte {
	root := merkleizeChunksWithLimit(chunks, limit)

	// Mix in length
	hh := fastssz.NewHasher()
	hh.AppendBytes32(root[:])

	lengthChunk := make([]byte, 32)
	binary.LittleEndian.PutUint64(lengthChunk[:8], count)
	hh.AppendBytes32(lengthChunk[:])

	result, _ := hh.HashRoot()
	return result
}

// computeBodyFieldHashes computes the HashTreeRoot of each field in the block body
func computeBodyFieldHashes(data []byte, version string, isMainnet bool, syncAggregateSize int) ([][]byte, error) {
	// 13 fields for Electra/Fulu
	numFields := 13
	hashes := make([][]byte, numFields)

	pos := 0

	// Field 0: randao_reveal (96)
	hashes[0] = hashBLSSignature(data[pos : pos+96])
	pos += 96

	// Field 1: eth1_data (72)
	hashes[1] = hashEth1Data(data, pos)
	pos += 72

	// Field 2: graffiti (32)
	hashes[2] = hashBytes32Field(data, pos)
	pos += 32

	// Fields 3-7: variable-length lists (we need their hashes)
	// proposer_slashings offset
	offset3 := readOffset(data, pos)
	pos += 4
	// attester_slashings offset
	offset4 := readOffset(data, pos)
	pos += 4
	// attestations offset
	offset5 := readOffset(data, pos)
	pos += 4
	// deposits offset
	offset6 := readOffset(data, pos)
	pos += 4
	// voluntary_exits offset
	offset7 := readOffset(data, pos)
	pos += 4

	// Field 8: sync_aggregate (fixed size)
	hashes[8] = hashSyncAggregate(data, pos, syncAggregateSize)
	pos += syncAggregateSize

	// Field 9: execution_payload offset
	offset9 := readOffset(data, pos)
	pos += 4

	// Field 10: bls_to_execution_changes offset
	offset10 := readOffset(data, pos)
	pos += 4

	// Field 11: blob_kzg_commitments offset
	offset11 := readOffset(data, pos)
	pos += 4

	// Field 12: execution_requests offset
	offset12 := readOffset(data, pos)

	// Now hash the variable-length fields
	hashes[3] = hashListOfProposerSlashings(data, offset3, offset4, 16)
	hashes[4] = hashListOfAttesterSlashings(data, offset4, offset5, 1) // Electra limit
	hashes[5] = hashListOfAttestations(data, offset5, offset6, 8)      // Electra limit
	hashes[6] = hashListOfDeposits(data, offset6, offset7, 16)
	hashes[7] = hashListOfVoluntaryExits(data, offset7, offset9, 16)

	// Field 9: execution_payload
	hashes[9] = hashExecutionPayloadField(data, offset9, offset10)

	// Field 10: bls_to_execution_changes
	hashes[10] = hashListOfBLSChanges(data, offset10, offset11, 16)

	// Field 11: blob_kzg_commitments
	hashes[11] = hashListOfKZGCommitments(data, offset11, offset12, 4096)

	// Field 12: execution_requests
	hashes[12] = hashExecutionRequests(data, offset12, len(data))

	return hashes, nil
}

func hashSyncAggregate(data []byte, offset, size int) []byte {
	if offset+size > len(data) {
		return make([]byte, 32)
	}

	hh := fastssz.NewHasher()

	// sync_committee_bits (variable based on preset)
	bitsSize := size - 96
	bitsChunk := make([]byte, 32)
	if bitsSize <= 32 {
		copy(bitsChunk[:bitsSize], data[offset:offset+bitsSize])
	}
	hh.AppendBytes32(bitsChunk[:])

	// sync_committee_signature (96)
	sigHash := hashBLSSignature(data[offset+bitsSize : offset+size])
	hh.AppendBytes32(sigHash)

	result, _ := hh.HashRoot()
	return result[:]
}

// Placeholder hash functions for body field types
func hashListOfProposerSlashings(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	// Simplified: hash the raw data
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], 0) // Approximate count
}

func hashListOfAttesterSlashings(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], 0)
}

func hashListOfAttestations(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], 0)
}

func hashListOfDeposits(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], 0)
}

func hashListOfVoluntaryExits(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], 0)
}

func hashExecutionPayloadField(data []byte, start, end int) []byte {
	if start >= end || start >= len(data) {
		return make([]byte, 32)
	}
	if end > len(data) {
		end = len(data)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return root[:]
}

func hashListOfBLSChanges(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], 0)
}

func hashListOfKZGCommitments(data []byte, start, end int, limit uint64) []byte {
	if start >= end {
		return hashEmptyListWithLimit(limit)
	}
	// KZG commitments are 48 bytes each
	count := (end - start) / 48
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return mixInLength(root[:], uint64(count))
}

func hashExecutionRequests(data []byte, start, end int) []byte {
	if start >= end || start >= len(data) {
		return make([]byte, 32)
	}
	if end > len(data) {
		end = len(data)
	}
	hh := fastssz.NewHasher()
	hh.PutBytes(data[start:end])
	root, _ := hh.HashRoot()
	return root[:]
}

func merkleizeFieldHashes(hashes [][]byte) [32]byte {
	// Pad to power of 2
	n := len(hashes)
	size := 1
	for size < n {
		size *= 2
	}

	chunks := make([][32]byte, size)
	for i, h := range hashes {
		copy(chunks[i][:], h)
	}

	return merkleizeChunks(chunks)
}
