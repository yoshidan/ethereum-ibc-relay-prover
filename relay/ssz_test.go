package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
)

func newTestProverForSSZ(t *testing.T) *Prover {
	// Use the same helper as prover_test.go
	return newTestProver(t)
}

func TestGindexToDepth(t *testing.T) {
	tests := []struct {
		name     string
		gindex   uint32
		expected int
	}{
		{"gindex 0", 0, 0},
		{"gindex 1 (root)", 1, 0},
		{"gindex 2", 2, 1},
		{"gindex 3", 3, 1},
		{"gindex 4", 4, 2},
		{"gindex 7", 7, 2},
		{"gindex 8", 8, 3},
		{"gindex 25 (execution payload)", 25, 4},
		{"gindex 55 (next sync committee deneb)", 55, 5},
		{"gindex 87 (next sync committee electra)", 87, 6},
		{"gindex 105 (finalized root deneb)", 105, 6},
		{"gindex 169 (finalized root electra)", 169, 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gindexToDepth(tt.gindex)
			if result != tt.expected {
				t.Errorf("gindexToDepth(%d) = %d, expected %d", tt.gindex, result, tt.expected)
			}
		})
	}
}

func TestGindexToLeafIndex(t *testing.T) {
	tests := []struct {
		name     string
		gindex   uint32
		expected uint64
	}{
		{"gindex 1 (root)", 1, 0},
		{"gindex 2 (left child)", 2, 0},
		{"gindex 3 (right child)", 3, 1},
		{"gindex 4", 4, 0},
		{"gindex 5", 5, 1},
		{"gindex 6", 6, 2},
		{"gindex 7", 7, 3},
		{"gindex 25 (execution payload)", 25, 9},
		{"gindex 55 (next sync committee deneb)", 55, 23},
		{"gindex 87 (next sync committee electra)", 87, 23},
		{"gindex 105 (finalized root deneb)", 105, 41},
		{"gindex 169 (finalized root electra)", 169, 41},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gindexToLeafIndex(tt.gindex)
			if result != tt.expected {
				t.Errorf("gindexToLeafIndex(%d) = %d, expected %d", tt.gindex, result, tt.expected)
			}
		})
	}
}

func TestToBytes32Slice(t *testing.T) {
	input := [][]byte{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	result := toBytes32Slice(input)

	if len(result) != len(input) {
		t.Errorf("toBytes32Slice returned %d elements, expected %d", len(result), len(input))
	}

	for i := range input {
		for j := 0; j < 32; j++ {
			if result[i][j] != input[i][j] {
				t.Errorf("toBytes32Slice[%d][%d] = %d, expected %d", i, j, result[i][j], input[i][j])
			}
		}
	}
}

func TestToBytes32SliceWithShortInput(t *testing.T) {
	// Test with input shorter than 32 bytes
	input := [][]byte{
		{1, 2, 3, 4, 5},
	}

	result := toBytes32Slice(input)

	if len(result) != 1 {
		t.Errorf("toBytes32Slice returned %d elements, expected 1", len(result))
	}

	// First 5 bytes should match
	for i := 0; i < 5; i++ {
		if result[0][i] != input[0][i] {
			t.Errorf("toBytes32Slice[0][%d] = %d, expected %d", i, result[0][i], input[0][i])
		}
	}

	// Remaining bytes should be zero
	for i := 5; i < 32; i++ {
		if result[0][i] != 0 {
			t.Errorf("toBytes32Slice[0][%d] = %d, expected 0", i, result[0][i])
		}
	}
}

func TestGenerateMerkleProof(t *testing.T) {
	// Create 4 leaves (power of 2)
	leaves := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 32),
	}
	leaves[0][0] = 1
	leaves[1][0] = 2
	leaves[2][0] = 3
	leaves[3][0] = 4

	// Generate proof for leaf index 0
	proof, err := generateMerkleProof(leaves, 0)
	if err != nil {
		t.Fatalf("generateMerkleProof failed: %v", err)
	}

	// For 4 leaves, depth is 2, so proof should have 2 elements
	if len(proof) != 2 {
		t.Errorf("proof length = %d, expected 2", len(proof))
	}

	// Generate proof for leaf index 2
	proof2, err := generateMerkleProof(leaves, 2)
	if err != nil {
		t.Fatalf("generateMerkleProof failed: %v", err)
	}

	if len(proof2) != 2 {
		t.Errorf("proof2 length = %d, expected 2", len(proof2))
	}
}

func TestGenerateMerkleProofFromGindex(t *testing.T) {
	// Create 16 leaves for depth 4
	leaves := make([][]byte, 16)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
		leaves[i][0] = byte(i)
	}

	// Test with gindex 25 (depth 4, leaf index 9)
	proof, err := generateMerkleProofFromGindex(leaves, 25)
	if err != nil {
		t.Fatalf("generateMerkleProofFromGindex failed: %v", err)
	}

	// Depth is 4, so proof should have 4 elements
	if len(proof) != 4 {
		t.Errorf("proof length = %d, expected 4", len(proof))
	}
}

func TestSyncCommitteeToProto(t *testing.T) {
	// Test nil input
	result := syncCommitteeToProto(nil)
	if result != nil {
		t.Error("syncCommitteeToProto(nil) should return nil")
	}
}

// TestParsedBeaconStateGenerateBranches tests the proof generation methods
func TestParsedBeaconStateGenerateBranches(t *testing.T) {
	// This test requires a beacon node to be running
	// Use the same test helper as prover_test.go
	pr := newTestProverForSSZ(t)
	ctx := context.Background()

	// Get finalized block info
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", slot)
	}

	// Get state SSZ
	stateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, "finalized")
	if err != nil {
		t.Fatalf("Failed to get state SSZ: %v", err)
	}

	// Parse state
	parsedState, err := ParseBeaconStateSSZ(stateSSZ, block.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse state SSZ: %v", err)
	}

	// Test finality branch generation
	finalityBranch, err := parsedState.GenerateFinalityBranch()
	if err != nil {
		t.Fatalf("GenerateFinalityBranch failed: %v", err)
	}

	expectedDepth := gindexToDepth(forkSpec.FinalizedRootGindex)
	if len(finalityBranch) != expectedDepth {
		t.Errorf("Finality branch has %d elements, expected %d (depth for gindex %d)",
			len(finalityBranch), expectedDepth, forkSpec.FinalizedRootGindex)
	}

	t.Logf("Finality branch generated with %d elements for gindex %d", len(finalityBranch), forkSpec.FinalizedRootGindex)

	// Test next sync committee branch generation
	nextSCBranch, err := parsedState.GenerateNextSyncCommitteeBranch()
	if err != nil {
		t.Fatalf("GenerateNextSyncCommitteeBranch failed: %v", err)
	}

	expectedSCDepth := gindexToDepth(forkSpec.NextSyncCommitteeGindex)
	if len(nextSCBranch) != expectedSCDepth {
		t.Errorf("Next sync committee branch has %d elements, expected %d (depth for gindex %d)",
			len(nextSCBranch), expectedSCDepth, forkSpec.NextSyncCommitteeGindex)
	}

	t.Logf("Next sync committee branch generated with %d elements for gindex %d", len(nextSCBranch), forkSpec.NextSyncCommitteeGindex)
}

// TestParsedBeaconBlockGenerateExecutionBranch tests the execution branch generation
func TestParsedBeaconBlockGenerateExecutionBranch(t *testing.T) {
	// This test requires a beacon node to be running
	pr := newTestProverForSSZ(t)
	ctx := context.Background()

	// Get finalized block info
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", slot)
	}

	// Get block SSZ
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, "finalized")
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	// Parse block
	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, block.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	// Test execution branch generation
	executionBranch, err := parsedBlock.GenerateExecutionPayloadBranch()
	if err != nil {
		t.Fatalf("GenerateExecutionPayloadBranch failed: %v", err)
	}

	expectedDepth := gindexToDepth(forkSpec.ExecutionPayloadGindex)
	if len(executionBranch) != expectedDepth {
		t.Errorf("Execution branch has %d elements, expected %d (depth for gindex %d)",
			len(executionBranch), expectedDepth, forkSpec.ExecutionPayloadGindex)
	}

	t.Logf("Execution branch generated with %d elements for gindex %d", len(executionBranch), forkSpec.ExecutionPayloadGindex)
}

func TestGenerateMerkleProofEmpty(t *testing.T) {
	_, err := generateMerkleProof([][]byte{}, 0)
	if err == nil {
		t.Error("generateMerkleProof with empty leaves should return error")
	}
}

func TestGenerateMerkleProofNonPowerOfTwo(t *testing.T) {
	// Create 3 leaves (not a power of 2)
	leaves := [][]byte{
		make([]byte, 32),
		make([]byte, 32),
		make([]byte, 32),
	}
	leaves[0][0] = 1
	leaves[1][0] = 2
	leaves[2][0] = 3

	// Should work - function pads to nearest power of 2
	proof, err := generateMerkleProof(leaves, 0)
	if err != nil {
		t.Fatalf("generateMerkleProof failed: %v", err)
	}

	// 3 leaves padded to 4, depth is 2
	if len(proof) != 2 {
		t.Errorf("proof length = %d, expected 2", len(proof))
	}
}

func TestPackUint64s(t *testing.T) {
	// Test packing 4 uint64s (exactly 1 chunk)
	values := []uint64{1, 2, 3, 4}
	chunks := packUint64s(values)
	if len(chunks) != 1 {
		t.Errorf("packUint64s returned %d chunks, expected 1", len(chunks))
	}

	// Verify the bytes are correct (little-endian)
	expected := [32]byte{
		1, 0, 0, 0, 0, 0, 0, 0, // 1
		2, 0, 0, 0, 0, 0, 0, 0, // 2
		3, 0, 0, 0, 0, 0, 0, 0, // 3
		4, 0, 0, 0, 0, 0, 0, 0, // 4
	}
	if chunks[0] != expected {
		t.Errorf("packUint64s chunk mismatch: got %v, expected %v", chunks[0], expected)
	}

	// Test packing 5 uint64s (2 chunks, second partially filled)
	values2 := []uint64{1, 2, 3, 4, 5}
	chunks2 := packUint64s(values2)
	if len(chunks2) != 2 {
		t.Errorf("packUint64s returned %d chunks, expected 2", len(chunks2))
	}

	// Test empty slice
	emptyChunks := packUint64s([]uint64{})
	if len(emptyChunks) != 0 {
		t.Errorf("packUint64s returned %d chunks for empty input, expected 0", len(emptyChunks))
	}
}

func TestForkSpecGindexValues(t *testing.T) {
	// Verify gindex values match the plan
	tests := []struct {
		name   string
		fork   string
		checks map[string]uint32
	}{
		{
			name: "Deneb gindex values",
			fork: "deneb",
			checks: map[string]uint32{
				"FinalizedRoot":        105,
				"CurrentSyncCommittee": 54,
				"NextSyncCommittee":    55,
				"ExecutionPayload":     25,
			},
		},
		{
			name: "Electra gindex values",
			fork: "electra",
			checks: map[string]uint32{
				"FinalizedRoot":        169,
				"CurrentSyncCommittee": 86,
				"NextSyncCommittee":    87,
				"ExecutionPayload":     25,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify depth calculations for each gindex
			for name, gindex := range tt.checks {
				depth := gindexToDepth(gindex)
				leafIndex := gindexToLeafIndex(gindex)
				t.Logf("%s: gindex=%d, depth=%d, leafIndex=%d", name, gindex, depth, leafIndex)

				// Verify gindex = 2^depth + leafIndex
				reconstructed := uint32(1<<depth) + uint32(leafIndex)
				if reconstructed != gindex {
					t.Errorf("%s: reconstructed gindex %d != original %d", name, reconstructed, gindex)
				}
			}
		})
	}
}

// isValidMerkleBranch verifies a merkle branch proof (same logic as ethereum-light-client-rs)
// leaf: the hash of the value being proven
// branch: the merkle proof (sibling hashes from leaf to root)
// gindex: generalized index of the leaf
// root: the expected root hash
func isValidMerkleBranch(leaf []byte, branch [][]byte, gindex uint32, root []byte) error {
	if gindex == 0 {
		return fmt.Errorf("invalid gindex: 0")
	}
	depth := gindexToDepth(gindex)
	subtreeIndex := gindex % (1 << depth)

	if len(branch) != depth {
		return fmt.Errorf("invalid branch length: got %d, expected %d", len(branch), depth)
	}

	value := make([]byte, 32)
	copy(value, leaf)

	for i := 0; i < depth; i++ {
		var combined []byte
		if (subtreeIndex>>i)%2 == 1 {
			// subtree_index / 2^i % 2 == 1: hash(branch[i] || value)
			combined = append(branch[i], value...)
		} else {
			// subtree_index / 2^i % 2 == 0: hash(value || branch[i])
			combined = append(value, branch[i]...)
		}
		h := sha256.Sum256(combined)
		value = h[:]
	}

	if !bytes.Equal(value, root) {
		return fmt.Errorf("merkle branch verification failed: computed root %x != expected root %x", value, root)
	}
	return nil
}

// TestVerifyExecutionBranchLikeELC tests execution branch verification using the same logic as ELC
func TestVerifyExecutionBranchLikeELC(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", slot)
	}

	// Get block SSZ
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, "finalized")
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	// Parse block
	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, block.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	// Generate execution branch
	executionBranch, err := parsedBlock.GenerateExecutionPayloadBranch()
	if err != nil {
		t.Fatalf("GenerateExecutionPayloadBranch failed: %v", err)
	}

	t.Logf("Execution branch length: %d", len(executionBranch))
	t.Logf("Execution root: %x", parsedBlock.ExecutionRoot)
	t.Logf("Body root: %x", parsedBlock.BodyRoot)
	t.Logf("Gindex: %d", forkSpec.ExecutionPayloadGindex)

	// Verify using ELC logic
	// leaf = hash_tree_root(execution_payload)
	// root = body_root (execution_payload is in the block body)
	err = isValidMerkleBranch(
		parsedBlock.ExecutionRoot,        // leaf
		executionBranch,                  // branch
		forkSpec.ExecutionPayloadGindex,  // gindex: 25
		parsedBlock.BodyRoot,             // root: body_root
	)
	if err != nil {
		t.Fatalf("Execution branch verification failed (ELC-style): %v", err)
	}

	t.Log("Execution branch verification passed!")
}

// TestVerifyFinalityBranchLikeELC tests finality branch verification using the same logic as ELC
func TestVerifyFinalityBranchLikeELC(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get head block (recent, should be in memory)
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "head")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	version := block.Version
	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", slot)
	}

	// Get block SSZ and parse
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", slot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	// Get state SSZ
	stateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", slot))
	if err != nil {
		t.Fatalf("Failed to get state SSZ: %v", err)
	}

	parsedState, err := ParseBeaconStateSSZ(stateSSZ, version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse state SSZ: %v", err)
	}

	// Get finalized checkpoint root from parsed state
	// Note: We trust the state root from block header (parsedBlock.StateRoot) instead of computing it
	// because state root computation is not needed for actual relay/prover processing
	var finalizedCheckpointRoot []byte
	switch version {
	case "fulu":
		finalizedCheckpointRoot = parsedState.stateFulu.FinalizedCheckpoint.Root
	case "electra":
		finalizedCheckpointRoot = parsedState.stateElectra.FinalizedCheckpoint.Root
	case "deneb":
		finalizedCheckpointRoot = parsedState.stateDeneb.FinalizedCheckpoint.Root
	}

	// Generate finality branch
	finalityBranch, err := parsedState.GenerateFinalityBranch()
	if err != nil {
		t.Fatalf("GenerateFinalityBranch failed: %v", err)
	}

	t.Logf("Finality branch length: %d", len(finalityBranch))
	t.Logf("Finalized checkpoint root: %x", finalizedCheckpointRoot)
	t.Logf("State root: %x", parsedBlock.StateRoot)
	t.Logf("Gindex: %d", forkSpec.FinalizedRootGindex)

	// Output prover-generated data for Rust test verification
	t.Logf("=== Prover Generated Data (for Rust test) ===")
	t.Logf("leaf (finalized_checkpoint.root): 0x%x", finalizedCheckpointRoot)
	t.Logf("root (attested_state_root): 0x%x", parsedBlock.StateRoot)
	t.Logf("finality_branch:")
	for i, hash := range finalityBranch {
		t.Logf("  [%d]: 0x%x", i, hash)
	}

	// Verify using ELC logic
	err = isValidMerkleBranch(
		finalizedCheckpointRoot,          // leaf: finalized_checkpoint.root
		finalityBranch,                   // branch
		forkSpec.FinalizedRootGindex,     // gindex: 169 (electra) or 105 (deneb)
		parsedBlock.StateRoot,            // root: state root
	)
	if err != nil {
		t.Fatalf("Finality branch verification failed (ELC-style): %v", err)
	}

	t.Log("Finality branch verification passed!")
}

// TestVerifyNextSyncCommitteeBranchLikeELC tests next sync committee branch verification
func TestVerifyNextSyncCommitteeBranchLikeELC(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get head block
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "head")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	version := block.Version
	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", slot)
	}

	// Get block SSZ and parse
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", slot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	// Get state SSZ
	stateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", slot))
	if err != nil {
		t.Fatalf("Failed to get state SSZ: %v", err)
	}

	parsedState, err := ParseBeaconStateSSZ(stateSSZ, version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse state SSZ: %v", err)
	}

	// Get next sync committee root from parsed state
	// Note: We trust the state root from block header (parsedBlock.StateRoot) instead of computing it
	// because state root computation is not needed for actual relay/prover processing
	var nextSyncCommitteeRoot [32]byte
	switch version {
	case "fulu":
		if parsedState.stateFulu.NextSyncCommittee != nil {
			nextSyncCommitteeRoot, err = parsedState.stateFulu.NextSyncCommittee.HashTreeRoot()
		}
	case "electra":
		if parsedState.stateElectra.NextSyncCommittee != nil {
			nextSyncCommitteeRoot, err = parsedState.stateElectra.NextSyncCommittee.HashTreeRoot()
		}
	case "deneb":
		if parsedState.stateDeneb.NextSyncCommittee != nil {
			nextSyncCommitteeRoot, err = parsedState.stateDeneb.NextSyncCommittee.HashTreeRoot()
		}
	}
	if err != nil {
		t.Fatalf("Failed to compute next sync committee root: %v", err)
	}

	// Generate next sync committee branch
	nextSCBranch, err := parsedState.GenerateNextSyncCommitteeBranch()
	if err != nil {
		t.Fatalf("GenerateNextSyncCommitteeBranch failed: %v", err)
	}

	t.Logf("Next sync committee branch length: %d", len(nextSCBranch))
	t.Logf("Next sync committee root: %x", nextSyncCommitteeRoot)
	t.Logf("State root: %x", parsedBlock.StateRoot)
	t.Logf("Gindex: %d", forkSpec.NextSyncCommitteeGindex)

	// Verify using ELC logic
	err = isValidMerkleBranch(
		nextSyncCommitteeRoot[:],         // leaf: hash_tree_root(next_sync_committee)
		nextSCBranch,                     // branch
		forkSpec.NextSyncCommitteeGindex, // gindex: 87 (electra) or 55 (deneb)
		parsedBlock.StateRoot,            // root: state root
	)
	if err != nil {
		t.Fatalf("Next sync committee branch verification failed (ELC-style): %v", err)
	}

	t.Log("Next sync committee branch verification passed!")
}

// TestVerifyConsensusUpdateFinalityBranch tests that consensus update's finality branch
// is valid against the attested header's state root
func TestVerifyConsensusUpdateFinalityBranch(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block info
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	// Get head block to check if chain has enough blocks
	headBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "head")
	if err != nil {
		t.Fatalf("Failed to get head block: %v", err)
	}

	finalizedSlot := uint64(block.Data.Message.Slot)
	headSlot := uint64(headBlock.Data.Message.Slot)

	if headSlot < finalizedSlot+17 {
		t.Skipf("Chain head (%d) is too close to finalized slot (%d), need more blocks", headSlot, finalizedSlot)
	}

	// Get finalized block root
	finalizedBlockRoot, err := pr.beaconClient.GetBlockRootByID(ctx, "finalized", true)
	if err != nil {
		t.Fatalf("Failed to get finalized block root: %v", err)
	}

	// Find signature and attested slots
	signatureSlot, attestedSlot, err := pr.findSignatureAndAttestedSlot(ctx, finalizedBlockRoot.Data.Root, finalizedSlot)
	if err != nil {
		t.Fatalf("findSignatureAndAttestedSlot failed: %v", err)
	}

	t.Logf("signature_slot=%d, attested_slot=%d, version=%s", signatureSlot, attestedSlot, block.Version)

	// Build consensus update
	update, _, err := pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, "finalized", block.Version, true)
	if err != nil {
		t.Fatalf("buildConsensusUpdateWithSlots failed: %v", err)
	}

	// Get fork spec
	forkSpec := pr.getForkSpecForSlot(signatureSlot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", signatureSlot)
	}

	t.Logf("=== Consensus Update Data ===")
	t.Logf("attested_header.state_root: 0x%x", update.AttestedHeader.StateRoot)
	t.Logf("finalized_header slot: %d", update.FinalizedHeader.Slot)
	t.Logf("finality_branch length: %d", len(update.FinalizedHeaderBranch))
	t.Logf("gindex: %d", forkSpec.FinalizedRootGindex)

	// Get attested state to get the finalized checkpoint root (this is the actual leaf)
	attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		t.Fatalf("Failed to get attested state SSZ: %v", err)
	}

	parsedAttestedState, err := ParseBeaconStateSSZ(attestedStateSSZ, block.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse attested state SSZ: %v", err)
	}

	// Get finalized checkpoint root from the attested state
	var finalizedCheckpointRoot []byte
	switch block.Version {
	case "fulu":
		finalizedCheckpointRoot = parsedAttestedState.stateFulu.FinalizedCheckpoint.Root
	case "electra":
		finalizedCheckpointRoot = parsedAttestedState.stateElectra.FinalizedCheckpoint.Root
	case "deneb":
		finalizedCheckpointRoot = parsedAttestedState.stateDeneb.FinalizedCheckpoint.Root
	}

	t.Logf("finalized_checkpoint.root (leaf): 0x%x", finalizedCheckpointRoot)

	// Output branch for Rust test
	t.Logf("=== Data for Rust Test ===")
	t.Logf("leaf: 0x%x", finalizedCheckpointRoot)
	t.Logf("root: 0x%x", update.AttestedHeader.StateRoot)
	for i, hash := range update.FinalizedHeaderBranch {
		t.Logf("branch[%d]: 0x%x", i, hash)
	}

	// Verify finality branch
	err = isValidMerkleBranch(
		finalizedCheckpointRoot,
		update.FinalizedHeaderBranch,
		forkSpec.FinalizedRootGindex,
		update.AttestedHeader.StateRoot,
	)
	if err != nil {
		t.Fatalf("Finality branch verification failed: %v", err)
	}

	t.Log("Consensus update finality branch verification passed!")
}

// TestCompareMultiplePeriods compares finality data across multiple periods
func TestCompareMultiplePeriods(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get current finalized info
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	finalizedSlot := uint64(block.Data.Message.Slot)
	finalizedEpoch := pr.computeEpoch(finalizedSlot)
	finalizedPeriod := pr.computeSyncCommitteePeriod(finalizedEpoch)

	t.Logf("Current: finalized_slot=%d, epoch=%d, period=%d", finalizedSlot, finalizedEpoch, finalizedPeriod)

	if finalizedPeriod < 1 {
		t.Skipf("Need at least period 1 (current=%d)", finalizedPeriod)
	}

	type result struct {
		period              uint64
		attestedSlot        uint64
		finalizedSlot       uint64
		finalizedRootMatch  bool
		stateRootMatch      bool
		branchMatch         bool
		lcVerifyPass        bool
		bsVerifyPass        bool
		lcFinalizedRoot     string
		bsFinalizedRoot     string
		lcStateRoot         string
		bsStateRoot         string
		branchMismatches    []int
	}

	var results []result

	// Test each past period
	for period := uint64(0); period < finalizedPeriod; period++ {
		lcUpdate, err := pr.beaconClient.GetLightClientUpdate(ctx, period)
		if err != nil {
			t.Logf("Period %d: Failed to get LC update: %v", period, err)
			continue
		}

		attestedSlot := uint64(lcUpdate.Data.AttestedHeader.Beacon.Slot)
		finSlot := uint64(lcUpdate.Data.FinalizedHeader.Beacon.Slot)

		res := result{
			period:        period,
			attestedSlot:  attestedSlot,
			finalizedSlot: finSlot,
		}

		// Compute LC finalized_root
		lcFinalizedRoot := computeBeaconBlockHeaderRoot(
			uint64(lcUpdate.Data.FinalizedHeader.Beacon.Slot),
			uint64(lcUpdate.Data.FinalizedHeader.Beacon.ProposerIndex),
			lcUpdate.Data.FinalizedHeader.Beacon.ParentRoot,
			lcUpdate.Data.FinalizedHeader.Beacon.StateRoot,
			lcUpdate.Data.FinalizedHeader.Beacon.BodyRoot,
		)
		res.lcFinalizedRoot = fmt.Sprintf("0x%x", lcFinalizedRoot[:8])

		// Get BeaconState data
		forkSpec := pr.getForkSpecForSlot(attestedSlot)
		attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
		if err != nil {
			t.Logf("Period %d: Failed to get state SSZ: %v", period, err)
			continue
		}

		parsedState, err := ParseBeaconStateSSZ(attestedStateSSZ, lcUpdate.Version, forkSpec)
		if err != nil {
			t.Logf("Period %d: Failed to parse state: %v", period, err)
			continue
		}

		// Get finalized checkpoint root
		var bsFinalizedRoot []byte
		switch lcUpdate.Version {
		case "fulu":
			bsFinalizedRoot = parsedState.stateFulu.FinalizedCheckpoint.Root
		case "electra":
			bsFinalizedRoot = parsedState.stateElectra.FinalizedCheckpoint.Root
		case "deneb":
			bsFinalizedRoot = parsedState.stateDeneb.FinalizedCheckpoint.Root
		}
		res.bsFinalizedRoot = fmt.Sprintf("0x%x", bsFinalizedRoot[:8])

		// Generate branch from BeaconState
		bsBranch, err := parsedState.GenerateFinalityBranch()
		if err != nil {
			t.Logf("Period %d: Failed to generate branch: %v", period, err)
			continue
		}

		// Get attested block for state_root
		attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
		if err != nil {
			t.Logf("Period %d: Failed to get block SSZ: %v", period, err)
			continue
		}
		parsedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, lcUpdate.Version, forkSpec)
		if err != nil {
			t.Logf("Period %d: Failed to parse block: %v", period, err)
			continue
		}

		// Compare
		res.finalizedRootMatch = bytes.Equal(lcFinalizedRoot, bsFinalizedRoot)

		lcStateRoot := []byte(lcUpdate.Data.AttestedHeader.Beacon.StateRoot)
		bsStateRoot := parsedBlock.StateRoot
		res.lcStateRoot = fmt.Sprintf("0x%x", lcStateRoot[:8])
		res.bsStateRoot = fmt.Sprintf("0x%x", bsStateRoot[:8])
		res.stateRootMatch = bytes.Equal(lcStateRoot, bsStateRoot)

		// Compare branches
		res.branchMatch = true
		lcBranch := make([][]byte, len(lcUpdate.Data.FinalityBranch))
		for i, b := range lcUpdate.Data.FinalityBranch {
			lcBranch[i] = b
			if !bytes.Equal([]byte(b), bsBranch[i]) {
				res.branchMatch = false
				res.branchMismatches = append(res.branchMismatches, i)
			}
		}

		// Verify
		err = isValidMerkleBranch(lcFinalizedRoot, lcBranch, forkSpec.FinalizedRootGindex, lcStateRoot)
		res.lcVerifyPass = err == nil

		err = isValidMerkleBranch(bsFinalizedRoot, bsBranch, forkSpec.FinalizedRootGindex, bsStateRoot)
		res.bsVerifyPass = err == nil

		results = append(results, res)
	}

	// Print table
	t.Logf("\n=== COMPARISON TABLE ===")
	t.Logf("| Period | Attested | Finalized | Root | State | Branch | LC✓ | BS✓ |")
	t.Logf("|--------|----------|-----------|------|-------|--------|-----|-----|")

	allMatch := true
	for _, r := range results {
		rootIcon := "✅"
		if !r.finalizedRootMatch {
			rootIcon = "❌"
			allMatch = false
		}
		stateIcon := "✅"
		if !r.stateRootMatch {
			stateIcon = "❌"
			allMatch = false
		}
		branchIcon := "✅"
		if !r.branchMatch {
			branchIcon = fmt.Sprintf("❌%v", r.branchMismatches)
			allMatch = false
		}
		lcIcon := "✅"
		if !r.lcVerifyPass {
			lcIcon = "❌"
			allMatch = false
		}
		bsIcon := "✅"
		if !r.bsVerifyPass {
			bsIcon = "❌"
			allMatch = false
		}

		t.Logf("| %6d | %8d | %9d | %s | %s | %s | %s | %s |",
			r.period, r.attestedSlot, r.finalizedSlot,
			rootIcon, stateIcon, branchIcon, lcIcon, bsIcon)
	}

	if allMatch {
		t.Logf("\nAll periods match! ✅")
	} else {
		t.Logf("\nSome periods have mismatches! ❌")
	}
}

// TestCompareLightClientAPIvsBeaconState compares finality data from Light Client API vs BeaconState generation
func TestCompareLightClientAPIvsBeaconState(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update (current finalized state)
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	t.Logf("=== Light Client API Data ===")
	t.Logf("version: %s", lcFinalityUpdate.Version)
	t.Logf("attested_header.slot: %d", lcFinalityUpdate.Data.AttestedHeader.Beacon.Slot)
	t.Logf("attested_header.state_root: 0x%x", lcFinalityUpdate.Data.AttestedHeader.Beacon.StateRoot)
	t.Logf("finalized_header.slot: %d", lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	t.Logf("signature_slot: %d", lcFinalityUpdate.Data.SignatureSlot)

	// Compute finalized_root from Light Client API's finalized_header
	lcFinalizedRoot := computeBeaconBlockHeaderRoot(
		uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot),
		uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.ProposerIndex),
		lcFinalityUpdate.Data.FinalizedHeader.Beacon.ParentRoot,
		lcFinalityUpdate.Data.FinalizedHeader.Beacon.StateRoot,
		lcFinalityUpdate.Data.FinalizedHeader.Beacon.BodyRoot,
	)
	t.Logf("finalized_root (hash_tree_root of finalized_header): 0x%x", lcFinalizedRoot)

	// Log finality branch from Light Client API
	// Note: hexutil.Bytes with %x prints hex of string, use []byte conversion
	t.Logf("finality_branch (from LC API):")
	for i, b := range lcFinalityUpdate.Data.FinalityBranch {
		t.Logf("  branch[%d]: 0x%x", i, []byte(b))
	}

	// Now get the same data from BeaconState
	attestedSlot := uint64(lcFinalityUpdate.Data.AttestedHeader.Beacon.Slot)
	signatureSlot := uint64(lcFinalityUpdate.Data.SignatureSlot)

	t.Logf("\n=== BeaconState Generated Data ===")

	// Get fork spec
	forkSpec := pr.getForkSpecForSlot(signatureSlot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", signatureSlot)
	}

	// Get attested state SSZ
	attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		t.Logf("Failed to get attested state SSZ: %v", err)
		t.Logf("Skipping BeaconState comparison due to SSZ fetch error")
		goto verifyLCAPIOnly
	}

	{
		parsedAttestedState, err := ParseBeaconStateSSZ(attestedStateSSZ, lcFinalityUpdate.Version, forkSpec)
		if err != nil {
			t.Logf("Failed to parse attested state SSZ: %v", err)
			t.Logf("This is expected if chain uses minimal preset but Go code uses mainnet types")
			t.Logf("Skipping BeaconState comparison due to SSZ parse error")
			goto verifyLCAPIOnly
		}

		// Get finalized checkpoint root from the attested state
		var bsFinalizedCheckpointRoot []byte
		switch lcFinalityUpdate.Version {
		case "fulu":
			bsFinalizedCheckpointRoot = parsedAttestedState.stateFulu.FinalizedCheckpoint.Root
		case "electra":
			bsFinalizedCheckpointRoot = parsedAttestedState.stateElectra.FinalizedCheckpoint.Root
		case "deneb":
			bsFinalizedCheckpointRoot = parsedAttestedState.stateDeneb.FinalizedCheckpoint.Root
		}
		t.Logf("finalized_checkpoint.root (from BeaconState): 0x%x", bsFinalizedCheckpointRoot)

		// Generate finality branch from BeaconState
		bsFinalityBranch, err := parsedAttestedState.GenerateFinalityBranch()
		if err != nil {
			t.Fatalf("Failed to generate finality branch: %v", err)
		}

		t.Logf("finality_branch (from BeaconState):")
		for i, b := range bsFinalityBranch {
			t.Logf("  branch[%d]: 0x%x", i, b)
		}

		// Get attested block to get state_root
		attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
		if err != nil {
			t.Fatalf("Failed to get attested block SSZ: %v", err)
		}

		parsedAttestedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, lcFinalityUpdate.Version, forkSpec)
		if err != nil {
			t.Fatalf("Failed to parse attested block SSZ: %v", err)
		}
		t.Logf("attested_header.state_root (from BeaconBlock): 0x%x", parsedAttestedBlock.StateRoot)

		// === COMPARISON ===
		t.Logf("\n=== COMPARISON ===")

		// Compare finalized_root
		lcFinalizedRootMatch := bytes.Equal(lcFinalizedRoot, bsFinalizedCheckpointRoot)
		t.Logf("finalized_root match: %v", lcFinalizedRootMatch)
		if !lcFinalizedRootMatch {
			t.Logf("  LC API finalized_root:     0x%x", lcFinalizedRoot)
			t.Logf("  BeaconState checkpoint:    0x%x", bsFinalizedCheckpointRoot)
		}

		// Compare state_root
		lcStateRoot := []byte(lcFinalityUpdate.Data.AttestedHeader.Beacon.StateRoot)
		bsStateRoot := parsedAttestedBlock.StateRoot
		stateRootMatch := bytes.Equal(lcStateRoot, bsStateRoot)
		t.Logf("attested_header.state_root match: %v", stateRootMatch)
		if !stateRootMatch {
			t.Logf("  LC API state_root:      0x%x", lcStateRoot)
			t.Logf("  BeaconBlock state_root: 0x%x", bsStateRoot)
		}

		// Compare finality branch
		branchMatch := true
		if len(lcFinalityUpdate.Data.FinalityBranch) != len(bsFinalityBranch) {
			branchMatch = false
			t.Logf("finality_branch length mismatch: LC=%d, BS=%d",
				len(lcFinalityUpdate.Data.FinalityBranch), len(bsFinalityBranch))
		} else {
			for i := range bsFinalityBranch {
				if !bytes.Equal([]byte(lcFinalityUpdate.Data.FinalityBranch[i]), bsFinalityBranch[i]) {
					branchMatch = false
					t.Logf("finality_branch[%d] mismatch:", i)
					t.Logf("  LC API:      0x%x", []byte(lcFinalityUpdate.Data.FinalityBranch[i]))
					t.Logf("  BeaconState: 0x%x", bsFinalityBranch[i])
				}
			}
		}
		t.Logf("finality_branch match: %v", branchMatch)

		// Verify both branches
		t.Logf("\n=== VERIFICATION ===")

		// Verify LC API branch
		lcBranch := make([][]byte, len(lcFinalityUpdate.Data.FinalityBranch))
		for i, b := range lcFinalityUpdate.Data.FinalityBranch {
			lcBranch[i] = b
		}
		err = isValidMerkleBranch(lcFinalizedRoot, lcBranch, forkSpec.FinalizedRootGindex, lcStateRoot)
		if err != nil {
			t.Logf("LC API branch verification FAILED: %v", err)
		} else {
			t.Logf("LC API branch verification PASSED")
		}

		// Verify BeaconState branch
		err = isValidMerkleBranch(bsFinalizedCheckpointRoot, bsFinalityBranch, forkSpec.FinalizedRootGindex, bsStateRoot)
		if err != nil {
			t.Logf("BeaconState branch verification FAILED: %v", err)
		} else {
			t.Logf("BeaconState branch verification PASSED")
		}
		return
	}

verifyLCAPIOnly:
	// Only verify LC API branch when BeaconState parsing fails
	t.Logf("\n=== VERIFICATION (LC API only) ===")
	lcBranch := make([][]byte, len(lcFinalityUpdate.Data.FinalityBranch))
	for i, b := range lcFinalityUpdate.Data.FinalityBranch {
		lcBranch[i] = b
	}
	lcStateRoot := []byte(lcFinalityUpdate.Data.AttestedHeader.Beacon.StateRoot)
	err = isValidMerkleBranch(lcFinalizedRoot, lcBranch, forkSpec.FinalizedRootGindex, lcStateRoot)
	if err != nil {
		t.Logf("LC API branch verification FAILED: %v", err)
	} else {
		t.Logf("LC API branch verification PASSED")
	}
}

// TestLightClientAPIForPeriodUpdate tests using the Light Client API for period updates
func TestLightClientAPIForPeriodUpdate(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block info
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	finalizedSlot := uint64(block.Data.Message.Slot)
	finalizedEpoch := pr.computeEpoch(finalizedSlot)
	finalizedPeriod := pr.computeSyncCommitteePeriod(finalizedEpoch)

	t.Logf("finalized_slot=%d, finalized_epoch=%d, finalized_period=%d, version=%s",
		finalizedSlot, finalizedEpoch, finalizedPeriod, block.Version)

	if finalizedPeriod < 1 {
		t.Skipf("Need at least period 1 to be finalized (current finalized_period=%d)", finalizedPeriod)
	}

	// Test Light Client API for each past period
	for period := uint64(0); period < finalizedPeriod; period++ {
		t.Run(fmt.Sprintf("period_%d", period), func(t *testing.T) {
			// Try to get light client update for this period
			lcUpdate, err := pr.beaconClient.GetLightClientUpdate(ctx, period)
			if err != nil {
				t.Fatalf("GetLightClientUpdate failed for period %d: %v", period, err)
			}

			t.Logf("Light Client Update for period %d:", period)
			t.Logf("  version=%s", lcUpdate.Version)
			t.Logf("  attested_header slot=%d", lcUpdate.Data.AttestedHeader.Beacon.Slot)
			t.Logf("  finalized_header slot=%d", lcUpdate.Data.FinalizedHeader.Beacon.Slot)
			t.Logf("  finality_branch length=%d", len(lcUpdate.Data.FinalityBranch))
			t.Logf("  signature_slot=%d", lcUpdate.Data.SignatureSlot)

			// Get fork spec for this slot
			forkSpec := pr.getForkSpecForSlot(uint64(lcUpdate.Data.AttestedHeader.Beacon.Slot))
			if forkSpec == nil {
				t.Fatalf("getForkSpecForSlot returned nil")
			}

			// The leaf for finality branch verification is hash_tree_root(finalized_beacon_header)
			// which should match finalized_checkpoint.root in the attested state
			// We can compute this from the finalized_header beacon block header
			finalizedBeaconHeader := lcUpdate.Data.FinalizedHeader.Beacon

			// Compute hash_tree_root of finalized beacon header
			// Using ssz library to compute the root
			leaf := computeBeaconBlockHeaderRoot(
				uint64(finalizedBeaconHeader.Slot),
				uint64(finalizedBeaconHeader.ProposerIndex),
				finalizedBeaconHeader.ParentRoot,
				finalizedBeaconHeader.StateRoot,
				finalizedBeaconHeader.BodyRoot,
			)

			t.Logf("  finalized_header hash_tree_root (leaf): 0x%x", leaf)
			t.Logf("  attested_header.state_root (expected root): 0x%x", lcUpdate.Data.AttestedHeader.Beacon.StateRoot)

			// Convert branch to [][]byte
			branch := make([][]byte, len(lcUpdate.Data.FinalityBranch))
			for i, b := range lcUpdate.Data.FinalityBranch {
				branch[i] = b
			}

			// Output branch for debugging
			for i, b := range branch {
				t.Logf("  branch[%d]: 0x%x", i, b)
			}

			// Verify finality branch
			err = isValidMerkleBranch(
				leaf,
				branch,
				forkSpec.FinalizedRootGindex,
				lcUpdate.Data.AttestedHeader.Beacon.StateRoot,
			)
			if err != nil {
				t.Fatalf("Light Client API finality branch verification failed for period %d: %v", period, err)
			}

			t.Logf("  Finality branch verification PASSED for period %d", period)
		})
	}
}

// computeBeaconBlockHeaderRoot computes the hash_tree_root of a BeaconBlockHeader
func computeBeaconBlockHeaderRoot(slot, proposerIndex uint64, parentRoot, stateRoot, bodyRoot []byte) []byte {
	// BeaconBlockHeader has 5 fields, all fixed size:
	// slot: uint64
	// proposer_index: uint64
	// parent_root: Bytes32
	// state_root: Bytes32
	// body_root: Bytes32

	// Pad each field to 32 bytes and compute merkle root
	// For uint64, pad to 32 bytes (little endian)
	slotBytes := make([]byte, 32)
	proposerIndexBytes := make([]byte, 32)

	// Little endian encoding
	for i := 0; i < 8; i++ {
		slotBytes[i] = byte(slot >> (8 * i))
		proposerIndexBytes[i] = byte(proposerIndex >> (8 * i))
	}

	// Create leaves for merkle tree (5 leaves, pad to 8 for power of 2)
	leaves := make([][]byte, 8)
	leaves[0] = slotBytes
	leaves[1] = proposerIndexBytes
	leaves[2] = parentRoot
	leaves[3] = stateRoot
	leaves[4] = bodyRoot
	// Padding with zero hashes
	zeroHash := make([]byte, 32)
	leaves[5] = zeroHash
	leaves[6] = zeroHash
	leaves[7] = zeroHash

	// Compute merkle root
	return computeMerkleRoot(leaves)
}

// computeMerkleRoot computes merkle root from leaves (must be power of 2)
func computeMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}

	newLeaves := make([][]byte, len(leaves)/2)
	for i := 0; i < len(leaves)/2; i++ {
		combined := append(leaves[2*i], leaves[2*i+1]...)
		h := sha256.Sum256(combined)
		newLeaves[i] = h[:]
	}
	return computeMerkleRoot(newLeaves)
}

// TestBuildConsensusUpdateForPeriod tests that buildConsensusUpdateForPeriod generates
// valid finality branches for past periods (intermediate header generation)
func TestBuildConsensusUpdateForPeriod(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block info
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	finalizedSlot := uint64(block.Data.Message.Slot)
	finalizedEpoch := pr.computeEpoch(finalizedSlot)
	finalizedPeriod := pr.computeSyncCommitteePeriod(finalizedEpoch)

	t.Logf("finalized_slot=%d, finalized_epoch=%d, finalized_period=%d, version=%s",
		finalizedSlot, finalizedEpoch, finalizedPeriod, block.Version)

	// For minimal preset: SLOTS_PER_EPOCH=8, EPOCHS_PER_SYNC_COMMITTEE_PERIOD=8
	// So period 0 = slots 0-63, period 1 = slots 64-127, etc.
	slotsPerPeriod := pr.slotsPerEpoch() * pr.epochsPerSyncCommitteePeriod()
	t.Logf("slots_per_period=%d", slotsPerPeriod)

	if finalizedPeriod < 1 {
		t.Skipf("Need at least period 1 to be finalized (current finalized_period=%d)", finalizedPeriod)
	}

	// Test building consensus update for each past period
	for period := uint64(0); period < finalizedPeriod; period++ {
		t.Run(fmt.Sprintf("period_%d", period), func(t *testing.T) {
			t.Logf("Testing buildConsensusUpdateForPeriod for period %d", period)

			// Build consensus update for this period
			update, execPayload, err := pr.buildConsensusUpdateForPeriod(ctx, period)
			if err != nil {
				t.Fatalf("buildConsensusUpdateForPeriod failed for period %d: %v", period, err)
			}

			t.Logf("  attested_slot=%d, finalized_slot=%d", update.AttestedHeader.Slot, update.FinalizedHeader.Slot)
			t.Logf("  attested_header.state_root: 0x%x", update.AttestedHeader.StateRoot)
			t.Logf("  execution_block_number=%d", execPayload.BlockNumber)
			t.Logf("  finality_branch length=%d", len(update.FinalizedHeaderBranch))

			// Get fork spec for this slot
			forkSpec := pr.getForkSpecForSlot(update.AttestedHeader.Slot)
			if forkSpec == nil {
				t.Fatalf("getForkSpecForSlot returned nil for slot %d", update.AttestedHeader.Slot)
			}

			t.Logf("  gindex=%d", forkSpec.FinalizedRootGindex)

			// Get the attested state to get the actual leaf value (finalized_checkpoint.root)
			attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", update.AttestedHeader.Slot))
			if err != nil {
				t.Fatalf("Failed to get attested state SSZ: %v", err)
			}

			// Determine version for parsing
			attestedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", update.AttestedHeader.Slot))
			if err != nil {
				t.Fatalf("Failed to get attested block: %v", err)
			}

			parsedAttestedState, err := ParseBeaconStateSSZ(attestedStateSSZ, attestedBlock.Version, forkSpec)
			if err != nil {
				t.Fatalf("Failed to parse attested state SSZ: %v", err)
			}

			// Get finalized checkpoint root from the attested state
			var finalizedCheckpointRoot []byte
			switch attestedBlock.Version {
			case "fulu":
				finalizedCheckpointRoot = parsedAttestedState.stateFulu.FinalizedCheckpoint.Root
			case "electra":
				finalizedCheckpointRoot = parsedAttestedState.stateElectra.FinalizedCheckpoint.Root
			case "deneb":
				finalizedCheckpointRoot = parsedAttestedState.stateDeneb.FinalizedCheckpoint.Root
			}

			t.Logf("  finalized_checkpoint.root (leaf): 0x%x", finalizedCheckpointRoot)

			// Verify finality branch
			err = isValidMerkleBranch(
				finalizedCheckpointRoot,
				update.FinalizedHeaderBranch,
				forkSpec.FinalizedRootGindex,
				update.AttestedHeader.StateRoot,
			)
			if err != nil {
				// Output debug info for failed verification
				t.Logf("=== FAILED: Data for Rust Test ===")
				t.Logf("leaf: 0x%x", finalizedCheckpointRoot)
				t.Logf("root: 0x%x", update.AttestedHeader.StateRoot)
				for i, hash := range update.FinalizedHeaderBranch {
					t.Logf("branch[%d]: 0x%x", i, hash)
				}
				t.Fatalf("Finality branch verification failed for period %d: %v", period, err)
			}

			t.Logf("  Finality branch verification PASSED for period %d", period)
		})
	}
}
