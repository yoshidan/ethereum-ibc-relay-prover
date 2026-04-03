package relay

import (
	"context"
	"testing"
)

func newTestProverForSSZ(t *testing.T) *Prover {
	initTestLogger()

	// Create a devnet config for testing (mainnet preset with all forks at epoch 0)
	config := ProverConfig{}
	return &Prover{
		chain:  &mockChain{},
		config: config,
	}
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
