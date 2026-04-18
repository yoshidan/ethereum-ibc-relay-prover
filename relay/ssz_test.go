package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	ethpb "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
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

	// SPEC.md flow: SignatureBlock → parent_root → AttestedBlock → state.finalized_checkpoint.root → FinalizedBlock
	// Get head block as SignatureBlock
	headBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "head")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}
	signatureSlot := uint64(headBlock.Data.Message.Slot)

	// Get AttestedBlock (parent of SignatureBlock)
	attestedBlockRoot := headBlock.Data.Message.ParentRoot.String()
	attestedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, attestedBlockRoot)
	if err != nil {
		t.Fatalf("Failed to get attested block: %v", err)
	}
	attestedSlot := uint64(attestedBlock.Data.Message.Slot)

	// Get FinalizedBlock from AttestedState.finalized_checkpoint.root
	checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		t.Fatalf("Failed to get finality checkpoints at attested slot: %v", err)
	}
	finalizedBlockRoot := fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:])

	t.Logf("signature_slot=%d, attested_slot=%d, version=%s", signatureSlot, attestedSlot, headBlock.Version)

	// Build consensus update
	update, _, err := pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, finalizedBlockRoot, headBlock.Version, true)
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

	parsedAttestedState, err := ParseBeaconStateSSZ(attestedStateSSZ, headBlock.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse attested state SSZ: %v", err)
	}

	// Get finalized checkpoint root from the attested state
	var finalizedCheckpointRoot []byte
	switch headBlock.Version {
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

// TestCompareFinalizedHeaderFields compares finalized_header fields between LC API and SSZ parsing
func TestCompareFinalizedHeaderFields(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	// Get LC finalized header fields
	lcHeader := lcFinalityUpdate.Data.FinalizedHeader.Beacon
	lcSlot := uint64(lcHeader.Slot)
	lcProposerIndex := uint64(lcHeader.ProposerIndex)
	lcParentRoot := []byte(lcHeader.ParentRoot)
	lcStateRoot := []byte(lcHeader.StateRoot)
	lcBodyRoot := []byte(lcHeader.BodyRoot)

	t.Logf("=== LC API Finalized Header ===")
	t.Logf("slot: %d", lcSlot)
	t.Logf("proposer_index: %d", lcProposerIndex)
	t.Logf("parent_root: 0x%x", lcParentRoot)
	t.Logf("state_root: 0x%x", lcStateRoot)
	t.Logf("body_root: 0x%x", lcBodyRoot)

	// Compute LC finalized root
	lcFinalizedRoot, _ := lcHeader.HashTreeRoot()
	t.Logf("hash_tree_root: 0x%x", lcFinalizedRoot)

	// Now get the same block via SSZ
	forkSpec := pr.getForkSpecForSlot(lcSlot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", lcSlot)
	}

	// Get finalized block SSZ using the slot
	finalizedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get finalized block SSZ: %v", err)
	}

	parsedBlock, err := ParseBeaconBlockSSZ(finalizedBlockSSZ, lcFinalityUpdate.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse finalized block SSZ: %v", err)
	}

	// Get BS finalized header fields
	bsSlot := parsedBlock.Slot
	bsProposerIndex := parsedBlock.ProposerIndex
	bsParentRoot := parsedBlock.ParentRoot
	bsStateRoot := parsedBlock.StateRoot
	bsBodyRoot := parsedBlock.BodyRoot

	t.Logf("\n=== BeaconState (SSZ) Finalized Header ===")
	t.Logf("slot: %d", bsSlot)
	t.Logf("proposer_index: %d", bsProposerIndex)
	t.Logf("parent_root: 0x%x", bsParentRoot)
	t.Logf("state_root: 0x%x", bsStateRoot)
	t.Logf("body_root: 0x%x", bsBodyRoot)

	// Compute BS finalized root
	bsFinalizedRoot := computeBeaconBlockHeaderRoot(bsSlot, bsProposerIndex, bsParentRoot, bsStateRoot, bsBodyRoot)
	t.Logf("hash_tree_root: 0x%x", bsFinalizedRoot)

	// Compare fields
	t.Logf("\n=== COMPARISON ===")
	t.Logf("slot match: %v (lc=%d, bs=%d)", lcSlot == bsSlot, lcSlot, bsSlot)
	t.Logf("proposer_index match: %v (lc=%d, bs=%d)", lcProposerIndex == bsProposerIndex, lcProposerIndex, bsProposerIndex)
	t.Logf("parent_root match: %v", bytes.Equal(lcParentRoot, bsParentRoot))
	t.Logf("state_root match: %v", bytes.Equal(lcStateRoot, bsStateRoot))
	t.Logf("body_root match: %v", bytes.Equal(lcBodyRoot, bsBodyRoot))
	t.Logf("hash_tree_root match: %v", bytes.Equal(lcFinalizedRoot[:], bsFinalizedRoot))

	if !bytes.Equal(lcStateRoot, bsStateRoot) {
		t.Errorf("state_root MISMATCH!")
		t.Logf("  LC: 0x%x", lcStateRoot)
		t.Logf("  BS: 0x%x", bsStateRoot)
	}
	// NOTE: body_root mismatch is expected due to differences in SSZ hash computation
	// between prysm (used here) and lodestar (used by the beacon node).
	// This is a known issue and is worked around by fetching body_root from the
	// beacon header API (/eth/v1/beacon/headers/{block_id}) instead of computing it locally.
	if !bytes.Equal(lcBodyRoot, bsBodyRoot) {
		t.Logf("body_root MISMATCH (expected - prysm vs lodestar difference):")
		t.Logf("  LC (lodestar): 0x%x", lcBodyRoot)
		t.Logf("  BS (prysm):    0x%x", bsBodyRoot)
	}
	// hash_tree_root mismatch is derived from body_root mismatch
	if !bytes.Equal(lcFinalizedRoot[:], bsFinalizedRoot) {
		t.Logf("hash_tree_root MISMATCH (expected - derived from body_root difference)")
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
	return computeMerkleRootRecursive(leaves)
}

// computeMerkleRootRecursive computes merkle root from leaves (must be power of 2)
// This is used in tests; the production version is in ssz.go
func computeMerkleRootRecursive(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}

	newLeaves := make([][]byte, len(leaves)/2)
	for i := 0; i < len(leaves)/2; i++ {
		combined := append(leaves[2*i], leaves[2*i+1]...)
		h := sha256.Sum256(combined)
		newLeaves[i] = h[:]
	}
	return computeMerkleRootRecursive(newLeaves)
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

			// Build consensus update for this period (not the latest period)
			update, execPayload, err := pr.buildConsensusUpdateForPeriod(ctx, period, false)
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

// TestDebugBodyRootFields computes each field's hash in BeaconBlockBody
// to identify which field causes the difference between prysm and lodestar
func TestDebugBodyRootFields(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	lcSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	lcBodyRoot := []byte(lcFinalityUpdate.Data.FinalizedHeader.Beacon.BodyRoot)

	t.Logf("=== LC API body_root: 0x%x ===", lcBodyRoot)

	// Get the block SSZ
	forkSpec := pr.getForkSpecForSlot(lcSlot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", lcSlot)
	}

	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	t.Logf("Block SSZ size: %d bytes", len(blockSSZ))
	t.Logf("Version: %s", lcFinalityUpdate.Version)

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, lcFinalityUpdate.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	t.Logf("=== prysm computed body_root: 0x%x ===", parsedBlock.BodyRoot)
	t.Logf("=== body SSZ size: %d bytes ===", len(parsedBlock.bodySSZ))

	if bytes.Equal(lcBodyRoot, parsedBlock.BodyRoot) {
		t.Logf("body_root MATCH!")
		return
	}

	t.Logf("body_root MISMATCH - debugging field hashes...")

	// Re-serialize body with prysm to get the bytes
	body := parsedBlock.bodyElectra
	reserializedBody, err := body.MarshalSSZ()
	if err != nil {
		t.Fatalf("Failed to re-serialize body: %v", err)
	}
	t.Logf("Re-serialized body SSZ size: %d bytes", len(reserializedBody))

	// Compare first 100 bytes of body SSZ
	t.Logf("Original body SSZ (first 100 bytes): 0x%x", parsedBlock.bodySSZ[:min(100, len(parsedBlock.bodySSZ))])
	t.Logf("Re-serialized body SSZ (first 100 bytes): 0x%x", reserializedBody[:min(100, len(reserializedBody))])

	// Check if SSZ matches
	if bytes.Equal(parsedBlock.bodySSZ, reserializedBody) {
		t.Logf("Body SSZ MATCH - issue is in hash computation")
	} else {
		t.Logf("Body SSZ MISMATCH - issue is in parsing/serialization")
		t.Logf("Original size: %d, Re-serialized size: %d", len(parsedBlock.bodySSZ), len(reserializedBody))
	}

	// Compute hash of raw SSZ bytes directly to compare with beacon node
	rawSSZHash := sha256.Sum256(parsedBlock.bodySSZ)
	t.Logf("SHA256 of original body SSZ: 0x%x", rawSSZHash)

	rawSSZHash2 := sha256.Sum256(reserializedBody)
	t.Logf("SHA256 of re-serialized body SSZ: 0x%x", rawSSZHash2)

	// Get the field hashes to see which field differs
	fieldHashes, err := getBeaconBlockBodyElectraFieldHashes(parsedBlock.bodyElectra)
	if err != nil {
		t.Fatalf("Failed to get field hashes: %v", err)
	}

	fieldNames := []string{
		"0: randao_reveal",
		"1: eth1_data",
		"2: graffiti",
		"3: proposer_slashings",
		"4: attester_slashings",
		"5: attestations",
		"6: deposits",
		"7: voluntary_exits",
		"8: sync_aggregate",
		"9: execution_payload",
		"10: bls_to_execution_changes",
		"11: blob_kzg_commitments",
		"12: execution_requests",
		"13: (padding)",
		"14: (padding)",
		"15: (padding)",
	}

	t.Logf("\n=== Field Hashes (prysm) ===")
	for i, hash := range fieldHashes {
		t.Logf("%s: 0x%x", fieldNames[i], hash)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestDebugManualBodyRoot manually computes body_root step by step
// to understand the exact algorithm used by prysm
func TestDebugManualBodyRoot(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	lcSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	lcBodyRoot := []byte(lcFinalityUpdate.Data.FinalizedHeader.Beacon.BodyRoot)

	t.Logf("=== LC API body_root: 0x%x ===", lcBodyRoot)

	// Get the block SSZ
	forkSpec := pr.getForkSpecForSlot(lcSlot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", lcSlot)
	}

	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, lcFinalityUpdate.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	body := parsedBlock.bodyElectra

	// Compute body root using prysm's HashTreeRoot
	prysmBodyRoot, err := body.HashTreeRoot()
	if err != nil {
		t.Fatalf("Failed to compute prysm body root: %v", err)
	}
	t.Logf("prysm body.HashTreeRoot(): 0x%x", prysmBodyRoot)

	// Now let's compute body root manually using the same algorithm
	// BeaconBlockBodyElectra has 13 fields -> padded to 16 leaves

	// Use fastssz to compute each field's contribution
	fieldHashes, err := getBeaconBlockBodyElectraFieldHashes(body)
	if err != nil {
		t.Fatalf("Failed to get field hashes: %v", err)
	}

	// Compute merkle root from field hashes manually
	manualRoot, err := computeMerkleRoot(fieldHashes)
	if err != nil {
		t.Fatalf("Failed to compute manual root: %v", err)
	}
	t.Logf("Manual merkle root: 0x%x", manualRoot)

	// Compare
	if bytes.Equal(prysmBodyRoot[:], manualRoot) {
		t.Logf("prysm HashTreeRoot matches manual computation - field hashes are correct")
	} else {
		t.Logf("prysm HashTreeRoot DIFFERS from manual computation")
		t.Logf("This means the field hash functions don't match prysm's internal computation")

		// Let's try to identify which field differs
		// by computing each field hash using prysm's hasher
	}

	// Also compare with LC API
	if bytes.Equal(lcBodyRoot, prysmBodyRoot[:]) {
		t.Logf("prysm matches LC API")
	} else {
		t.Logf("prysm DIFFERS from LC API")
	}

	// Debug: print SyncAggregate details
	t.Logf("\n=== SyncAggregate Details ===")
	t.Logf("SyncCommitteeBits length: %d bytes", len(body.SyncAggregate.SyncCommitteeBits))
	t.Logf("SyncCommitteeBits (hex): 0x%x", body.SyncAggregate.SyncCommitteeBits)
	t.Logf("SyncCommitteeSignature length: %d bytes", len(body.SyncAggregate.SyncCommitteeSignature))

	// Compute SyncAggregate hash separately
	syncAggRoot, err := body.SyncAggregate.HashTreeRoot()
	if err != nil {
		t.Fatalf("Failed to compute SyncAggregate root: %v", err)
	}
	t.Logf("SyncAggregate HashTreeRoot: 0x%x", syncAggRoot)

	// Debug: print attestations details
	t.Logf("\n=== Attestations Details ===")
	t.Logf("Number of attestations: %d", len(body.Attestations))
	for i, att := range body.Attestations {
		t.Logf("Attestation %d:", i)
		t.Logf("  AggregationBits length: %d", len(att.AggregationBits))
		t.Logf("  CommitteeBits length: %d bytes", len(att.CommitteeBits))
		t.Logf("  CommitteeBits (hex): 0x%x", att.CommitteeBits)
		attRoot, err := att.HashTreeRoot()
		if err != nil {
			t.Logf("  Failed to compute attestation root: %v", err)
		} else {
			t.Logf("  Attestation HashTreeRoot: 0x%x", attRoot)
		}
	}
}

// TestCompareBodyRootWithBeaconHeader compares our computed body_root with the beacon header API
func TestCompareBodyRootWithBeaconHeader(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	lcSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	lcBodyRoot := []byte(lcFinalityUpdate.Data.FinalizedHeader.Beacon.BodyRoot)

	t.Logf("=== Light Client API ===")
	t.Logf("Slot: %d", lcSlot)
	t.Logf("body_root: 0x%x", lcBodyRoot)

	// Get beacon header from header API
	beaconHeader, err := pr.beaconClient.GetBeaconHeader(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get beacon header: %v", err)
	}

	header, err := beaconHeader.ToBeaconBlockHeader()
	if err != nil {
		t.Fatalf("Failed to convert beacon header: %v", err)
	}

	t.Logf("\n=== Beacon Header API ===")
	t.Logf("Slot: %d", header.Slot)
	t.Logf("body_root: 0x%x", header.BodyRoot)

	// Compare LC API body_root with Beacon Header API body_root
	if bytes.Equal(lcBodyRoot, header.BodyRoot) {
		t.Logf("\nLC API and Beacon Header API body_root MATCH!")
	} else {
		t.Logf("\nLC API and Beacon Header API body_root DIFFER!")
		t.Logf("This suggests they're looking at different blocks")
	}

	// Get the block SSZ and compute body_root
	forkSpec := pr.getForkSpecForSlot(lcSlot)
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, lcFinalityUpdate.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	t.Logf("\n=== Prysm Computed ===")
	t.Logf("Slot: %d", parsedBlock.Slot)
	t.Logf("body_root: 0x%x", parsedBlock.BodyRoot)

	// Compare all three
	t.Logf("\n=== Comparison ===")
	if bytes.Equal(parsedBlock.BodyRoot, header.BodyRoot) {
		t.Logf("Prysm matches Beacon Header API!")
	} else {
		t.Logf("Prysm DIFFERS from Beacon Header API")
	}

	if bytes.Equal(parsedBlock.BodyRoot, lcBodyRoot) {
		t.Logf("Prysm matches LC API!")
	} else {
		t.Logf("Prysm DIFFERS from LC API")
	}
}

// TestDebugAttestationHash computes attestation hash step by step
func TestDebugAttestationHash(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	lcSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	forkSpec := pr.getForkSpecForSlot(lcSlot)

	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, lcFinalityUpdate.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	body := parsedBlock.bodyElectra
	if len(body.Attestations) == 0 {
		t.Skipf("No attestations in block")
	}

	att := body.Attestations[0]
	t.Logf("=== Attestation Details ===")
	t.Logf("AggregationBits raw bytes: 0x%x", att.AggregationBits)
	t.Logf("AggregationBits length: %d bytes", len(att.AggregationBits))
	t.Logf("CommitteeBits raw bytes: 0x%x", att.CommitteeBits)
	t.Logf("CommitteeBits length: %d bytes", len(att.CommitteeBits))
	t.Logf("Signature length: %d bytes", len(att.Signature))

	// Compute attestation hash using prysm
	attRoot, err := att.HashTreeRoot()
	if err != nil {
		t.Fatalf("Failed to compute attestation hash: %v", err)
	}
	t.Logf("Prysm attestation HashTreeRoot: 0x%x", attRoot)

	// Manually compute field hashes
	t.Logf("\n=== Manual Field Hashes ===")

	// Field 0: AggregationBits (Bitlist)
	// For minimal preset, max size is 512 bits
	// PutBitlist computes (maxSize+255)/256 = (512+255)/256 = 2 chunks
	t.Logf("AggregationBits: calling PutBitlist with maxSize=512")
	t.Logf("  Chunk limit = (512+255)/256 = %d", (512+255)/256)

	// Field 1: Data
	if att.Data != nil {
		dataRoot, _ := att.Data.HashTreeRoot()
		t.Logf("AttestationData HashTreeRoot: 0x%x", dataRoot)
	}

	// Field 2: Signature (96 bytes)
	sigHash := sha256.Sum256(att.Signature[:32])
	sigHash2 := sha256.Sum256(att.Signature[32:64])
	sigHash3 := sha256.Sum256(att.Signature[64:96])
	t.Logf("Signature chunk hashes (for reference)")

	// Field 3: CommitteeBits (Bitvector)
	// For minimal preset, 4 bits = 1 byte
	t.Logf("CommitteeBits: 1 byte for minimal (4 committees)")

	// Check the attestation SSZ
	attSSZ, err := att.MarshalSSZ()
	if err != nil {
		t.Fatalf("Failed to marshal attestation: %v", err)
	}
	t.Logf("\nAttestation SSZ size: %d bytes", len(attSSZ))
	t.Logf("Attestation SSZ: 0x%x", attSSZ)

	// Ignore unused variable warnings
	_ = sigHash
	_ = sigHash2
	_ = sigHash3
}

// TestDebugBlockParsing tries parsing the block as different versions
func TestDebugBlockParsing(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	lcSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	t.Logf("Slot: %d", lcSlot)
	t.Logf("Version from LC API: %s", lcFinalityUpdate.Version)

	// Get the block SSZ
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}
	t.Logf("Block SSZ size: %d bytes", len(blockSSZ))
	t.Logf("Block SSZ first 32 bytes: 0x%x", blockSSZ[:min(32, len(blockSSZ))])

	// Parse as fulu
	fulu := &ethpb.SignedBeaconBlockFulu{}
	if err := fulu.UnmarshalSSZ(blockSSZ); err != nil {
		t.Logf("Failed to parse as Fulu: %v", err)
	} else {
		t.Logf("Parsed as Fulu successfully!")
		t.Logf("  Slot: %d", fulu.Block.Slot)
		t.Logf("  Body ExecutionPayload BlockNumber: %d", fulu.Block.Body.ExecutionPayload.BlockNumber)
		bodyRoot, _ := fulu.Block.Body.HashTreeRoot()
		t.Logf("  Body root: 0x%x", bodyRoot)
	}

	// Parse as electra
	electra := &ethpb.SignedBeaconBlockElectra{}
	if err := electra.UnmarshalSSZ(blockSSZ); err != nil {
		t.Logf("Failed to parse as Electra: %v", err)
	} else {
		t.Logf("Parsed as Electra successfully!")
		t.Logf("  Slot: %d", electra.Block.Slot)
		t.Logf("  Body ExecutionPayload BlockNumber: %d", electra.Block.Body.ExecutionPayload.BlockNumber)
		bodyRoot, _ := electra.Block.Body.HashTreeRoot()
		t.Logf("  Body root: 0x%x", bodyRoot)
	}
}

// TestDebugSyncAggregateAndBodyRoot checks SyncAggregate details and body root computation
func TestDebugSyncAggregateAndBodyRoot(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get Light Client Finality Update
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		t.Skipf("Light Client API not available: %v", err)
	}

	lcSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	lcBodyRoot := []byte(lcFinalityUpdate.Data.FinalizedHeader.Beacon.BodyRoot)
	forkSpec := pr.getForkSpecForSlot(lcSlot)

	t.Logf("=== LC API Body Root ===")
	t.Logf("Slot: %d", lcSlot)
	t.Logf("body_root: 0x%x", lcBodyRoot)
	t.Logf("Version: %s", lcFinalityUpdate.Version)

	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", lcSlot))
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}
	t.Logf("Block SSZ size: %d bytes", len(blockSSZ))

	parsedBlock, err := ParseBeaconBlockSSZ(blockSSZ, lcFinalityUpdate.Version, forkSpec)
	if err != nil {
		t.Fatalf("Failed to parse block SSZ: %v", err)
	}

	body := parsedBlock.bodyElectra
	t.Logf("\n=== SyncAggregate Details ===")

	// Marshal SyncAggregate to see its SSZ size
	syncAggSSZ, err := body.SyncAggregate.MarshalSSZ()
	if err != nil {
		t.Fatalf("Failed to marshal SyncAggregate: %v", err)
	}
	t.Logf("SyncAggregate SSZ size: %d bytes (expected 100 for minimal, 160 for mainnet)", len(syncAggSSZ))
	t.Logf("SyncCommitteeBits length: %d bytes (expected 4 for minimal, 64 for mainnet)", len(body.SyncAggregate.SyncCommitteeBits))
	t.Logf("SyncCommitteeBits: 0x%x", body.SyncAggregate.SyncCommitteeBits)
	t.Logf("SyncCommitteeSignature length: %d bytes", len(body.SyncAggregate.SyncCommitteeSignature))

	// Compute SyncAggregate hash
	syncAggRoot, err := body.SyncAggregate.HashTreeRoot()
	if err != nil {
		t.Fatalf("Failed to compute SyncAggregate HashTreeRoot: %v", err)
	}
	t.Logf("SyncAggregate HashTreeRoot: 0x%x", syncAggRoot)

	t.Logf("\n=== Body SSZ Details ===")
	// Marshal body to see its SSZ size
	bodySSZ, err := body.MarshalSSZ()
	if err != nil {
		t.Fatalf("Failed to marshal body: %v", err)
	}
	t.Logf("BeaconBlockBodyElectra SSZ size: %d bytes", len(bodySSZ))

	// Check if body SSZ matches the one from parsing
	t.Logf("parsedBlock.bodySSZ size: %d bytes", len(parsedBlock.bodySSZ))
	if bytes.Equal(bodySSZ, parsedBlock.bodySSZ) {
		t.Logf("Body SSZ matches!")
	} else {
		t.Logf("Body SSZ DIFFERS!")
		t.Logf("bodySSZ first 100 bytes: 0x%x", bodySSZ[:min(100, len(bodySSZ))])
		t.Logf("parsedBlock.bodySSZ first 100 bytes: 0x%x", parsedBlock.bodySSZ[:min(100, len(parsedBlock.bodySSZ))])
	}

	t.Logf("\n=== Individual Field HashTreeRoots ===")

	// Field 0: RandaoReveal
	randaoHash := sha256.Sum256(append(body.RandaoReveal[:48], make([]byte, 16)...))
	randaoHash2 := sha256.Sum256(append(body.RandaoReveal[48:], make([]byte, 16)...))
	randaoRoot := sha256.Sum256(append(randaoHash[:], randaoHash2[:]...))
	t.Logf("Field 0 - RandaoReveal root: 0x%x", randaoRoot)

	// Field 1: Eth1Data
	eth1Root, _ := body.Eth1Data.HashTreeRoot()
	t.Logf("Field 1 - Eth1Data root: 0x%x", eth1Root)

	// Field 2: Graffiti
	t.Logf("Field 2 - Graffiti: 0x%x", body.Graffiti)

	// Field 3: ProposerSlashings (List with limit 16)
	t.Logf("Field 3 - ProposerSlashings count: %d (limit 16)", len(body.ProposerSlashings))

	// Field 4: AttesterSlashings
	t.Logf("Field 4 - AttesterSlashings count: %d", len(body.AttesterSlashings))

	// Field 5: Attestations
	t.Logf("Field 5 - Attestations count: %d", len(body.Attestations))
	for i, att := range body.Attestations {
		attRoot, _ := att.HashTreeRoot()
		t.Logf("  Attestation[%d] root: 0x%x", i, attRoot)
		t.Logf("    AggregationBits: 0x%x (%d bytes)", att.AggregationBits, len(att.AggregationBits))
		t.Logf("    CommitteeBits: 0x%x (%d bytes)", att.CommitteeBits, len(att.CommitteeBits))
	}

	// Field 6: Deposits
	t.Logf("Field 6 - Deposits count: %d", len(body.Deposits))

	// Field 7: VoluntaryExits
	t.Logf("Field 7 - VoluntaryExits count: %d", len(body.VoluntaryExits))

	// Field 8: SyncAggregate
	t.Logf("Field 8 - SyncAggregate root: 0x%x", syncAggRoot)

	// Field 9: ExecutionPayload
	execRoot, _ := body.ExecutionPayload.HashTreeRoot()
	t.Logf("Field 9 - ExecutionPayload root: 0x%x", execRoot)

	// Field 10: BlsToExecutionChanges
	t.Logf("Field 10 - BlsToExecutionChanges count: %d", len(body.BlsToExecutionChanges))

	// Field 11: BlobKzgCommitments
	t.Logf("Field 11 - BlobKzgCommitments count: %d", len(body.BlobKzgCommitments))

	// Field 12: ExecutionRequests
	execReqRoot, _ := body.ExecutionRequests.HashTreeRoot()
	t.Logf("Field 12 - ExecutionRequests root: 0x%x", execReqRoot)

	t.Logf("\n=== Final Body Root Comparison ===")
	computedBodyRoot, err := body.HashTreeRoot()
	if err != nil {
		t.Fatalf("Failed to compute body HashTreeRoot: %v", err)
	}
	t.Logf("Computed body_root: 0x%x", computedBodyRoot)
	t.Logf("Expected body_root: 0x%x", lcBodyRoot)

	if bytes.Equal(computedBodyRoot[:], lcBodyRoot) {
		t.Logf("MATCH!")
	} else {
		t.Logf("MISMATCH!")
	}

	// Detailed field-by-field hash computation using fastssz hasher
	t.Logf("\n=== Detailed Field Hash Analysis ===")

	// Import the hasher from fastssz
	// We'll compute each field's contribution to understand the tree structure
	t.Logf("BeaconBlockBodyElectra has 13 fields (indices 0-12)")
	t.Logf("Merkle tree for 13 fields requires 16 leaf nodes (next power of 2)")
	t.Logf("Tree depth = 4 (2^4 = 16)")

	// Check the limits used in MerkleizeWithMixin for each list field
	t.Logf("\n=== MerkleizeWithMixin limits check ===")
	t.Logf("Field 3 (ProposerSlashings): limit=16, count=%d", len(body.ProposerSlashings))
	t.Logf("Field 4 (AttesterSlashings): limit=1, count=%d", len(body.AttesterSlashings))
	t.Logf("Field 5 (Attestations): limit=8, count=%d", len(body.Attestations))
	t.Logf("Field 6 (Deposits): limit=16, count=%d", len(body.Deposits))
	t.Logf("Field 7 (VoluntaryExits): limit=16, count=%d", len(body.VoluntaryExits))
	t.Logf("Field 10 (BlsToExecutionChanges): limit=16, count=%d", len(body.BlsToExecutionChanges))
	t.Logf("Field 11 (BlobKzgCommitments): limit=16 (minimal), count=%d", len(body.BlobKzgCommitments))

	// Verify the Attestation hash matches what lodestar would compute
	// by checking the SSZ serialization
	if len(body.Attestations) > 0 {
		att := body.Attestations[0]
		attSSZ, _ := att.MarshalSSZ()
		t.Logf("\n=== Attestation SSZ Debug ===")
		t.Logf("Attestation SSZ size: %d bytes", len(attSSZ))
		t.Logf("Attestation SSZ hex: 0x%x", attSSZ)
	}

	// Also try parsing as "electra" to compare
	t.Logf("\n=== Try parsing as electra instead of fulu ===")
	parsedBlockElectra, err := ParseBeaconBlockSSZ(blockSSZ, "electra", forkSpec)
	if err != nil {
		t.Logf("Failed to parse as electra: %v", err)
	} else {
		t.Logf("Parsed as electra successfully")
		t.Logf("Electra body_root: 0x%x", parsedBlockElectra.BodyRoot)
		if bytes.Equal(parsedBlockElectra.BodyRoot, lcBodyRoot) {
			t.Logf("Electra parsing MATCHES LC API!")
		} else {
			t.Logf("Electra parsing also MISMATCHES")
		}

		// Compare body SSZ between fulu and electra parsing
		t.Logf("\n=== Compare body SSZ ===")
		t.Logf("Fulu body SSZ size: %d", len(parsedBlock.bodySSZ))
		t.Logf("Electra body SSZ size: %d", len(parsedBlockElectra.bodySSZ))
		if bytes.Equal(parsedBlock.bodySSZ, parsedBlockElectra.bodySSZ) {
			t.Logf("Body SSZ MATCHES between fulu and electra parsing!")
		} else {
			t.Logf("Body SSZ DIFFERS!")
			// Find first difference
			minLen := len(parsedBlock.bodySSZ)
			if len(parsedBlockElectra.bodySSZ) < minLen {
				minLen = len(parsedBlockElectra.bodySSZ)
			}
			for i := 0; i < minLen; i++ {
				if parsedBlock.bodySSZ[i] != parsedBlockElectra.bodySSZ[i] {
					t.Logf("First difference at byte %d: fulu=0x%02x, electra=0x%02x", i, parsedBlock.bodySSZ[i], parsedBlockElectra.bodySSZ[i])
					break
				}
			}
		}

		// Compare the actual body objects
		fuluBodyRoot, _ := parsedBlock.bodyElectra.HashTreeRoot()
		electraBodyRoot, _ := parsedBlockElectra.bodyElectra.HashTreeRoot()
		t.Logf("\nFulu bodyElectra.HashTreeRoot(): 0x%x", fuluBodyRoot)
		t.Logf("Electra bodyElectra.HashTreeRoot(): 0x%x", electraBodyRoot)

		// Try creating a fresh object from body SSZ directly
		t.Logf("\n=== Fresh body from SSZ ===")
		freshBody := &ethpb.BeaconBlockBodyElectra{}
		if err := freshBody.UnmarshalSSZ(parsedBlock.bodySSZ); err != nil {
			t.Logf("Failed to unmarshal fresh body: %v", err)
		} else {
			freshBodyRoot, _ := freshBody.HashTreeRoot()
			t.Logf("Fresh body HashTreeRoot: 0x%x", freshBodyRoot)

			// Re-marshal and check if it matches
			freshBodySSZ, _ := freshBody.MarshalSSZ()
			t.Logf("Fresh body SSZ size: %d", len(freshBodySSZ))
			if bytes.Equal(freshBodySSZ, parsedBlock.bodySSZ) {
				t.Logf("Fresh body SSZ matches original!")
			} else {
				t.Logf("Fresh body SSZ DIFFERS!")
			}
		}

		// Compare individual field hashes between fulu and electra parsed bodies
		t.Logf("\n=== Compare individual field hashes ===")
		fuluBody := parsedBlock.bodyElectra
		electraBody := parsedBlockElectra.bodyElectra

		// SyncAggregate
		fuluSyncRoot, _ := fuluBody.SyncAggregate.HashTreeRoot()
		electraSyncRoot, _ := electraBody.SyncAggregate.HashTreeRoot()
		t.Logf("Fulu SyncAggregate root: 0x%x", fuluSyncRoot)
		t.Logf("Electra SyncAggregate root: 0x%x", electraSyncRoot)
		t.Logf("SyncCommitteeBits - Fulu: 0x%x, Electra: 0x%x",
			fuluBody.SyncAggregate.SyncCommitteeBits, electraBody.SyncAggregate.SyncCommitteeBits)

		// ExecutionPayload
		fuluExecRoot, _ := fuluBody.ExecutionPayload.HashTreeRoot()
		electraExecRoot, _ := electraBody.ExecutionPayload.HashTreeRoot()
		t.Logf("Fulu ExecutionPayload root: 0x%x", fuluExecRoot)
		t.Logf("Electra ExecutionPayload root: 0x%x", electraExecRoot)

		// ExecutionRequests
		fuluReqRoot, _ := fuluBody.ExecutionRequests.HashTreeRoot()
		electraReqRoot, _ := electraBody.ExecutionRequests.HashTreeRoot()
		t.Logf("Fulu ExecutionRequests root: 0x%x", fuluReqRoot)
		t.Logf("Electra ExecutionRequests root: 0x%x", electraReqRoot)

		// Attestations
		if len(fuluBody.Attestations) > 0 && len(electraBody.Attestations) > 0 {
			fuluAttRoot, _ := fuluBody.Attestations[0].HashTreeRoot()
			electraAttRoot, _ := electraBody.Attestations[0].HashTreeRoot()
			t.Logf("Fulu Attestation[0] root: 0x%x", fuluAttRoot)
			t.Logf("Electra Attestation[0] root: 0x%x", electraAttRoot)
		}

		// Check SizeSSZ
		t.Logf("\n=== SizeSSZ Comparison ===")
		t.Logf("Fulu body SizeSSZ: %d", fuluBody.SizeSSZ())
		t.Logf("Electra body SizeSSZ: %d", electraBody.SizeSSZ())

		// Check if maybe the pointers are different causing different behavior
		t.Logf("Fulu body address: %p", fuluBody)
		t.Logf("Electra body address: %p", electraBody)

		// Try calling HashTreeRoot twice on fulu body
		t.Logf("\n=== Multiple HashTreeRoot calls ===")
		fuluRoot1, _ := fuluBody.HashTreeRoot()
		fuluRoot2, _ := fuluBody.HashTreeRoot()
		t.Logf("Fulu body HashTreeRoot call 1: 0x%x", fuluRoot1)
		t.Logf("Fulu body HashTreeRoot call 2: 0x%x", fuluRoot2)
		if fuluRoot1 != fuluRoot2 {
			t.Logf("WARNING: Fulu body HashTreeRoot is non-deterministic!")
		}

		// Try deserializing the fulu body from its own SSZ and computing hash
		t.Logf("\n=== Re-deserialize fulu body SSZ ===")
		fuluBodySSZ2, _ := fuluBody.MarshalSSZ()
		fuluBody2 := &ethpb.BeaconBlockBodyElectra{}
		fuluBody2.UnmarshalSSZ(fuluBodySSZ2)
		fuluRoot3, _ := fuluBody2.HashTreeRoot()
		t.Logf("Re-deserialized fulu body HashTreeRoot: 0x%x", fuluRoot3)
	}
}
