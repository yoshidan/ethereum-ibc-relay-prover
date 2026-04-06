package beacon

import (
	"context"
	"encoding/hex"
	"os"
	"sync"
	"testing"

	"github.com/hyperledger-labs/yui-relayer/log"
)

var initLoggerOnce sync.Once

func initTestLogger() {
	initLoggerOnce.Do(func() {
		_ = log.InitLogger("error", "json", "stderr", false)
	})
}

func TestGindexToBitstring(t *testing.T) {
	tests := []struct {
		gindex   uint64
		expected string
	}{
		{1, "1"},
		{2, "10"},
		{3, "11"},
		{105, "1101001"},
		{169, "10101001"},
		{55, "110111"},
		{87, "1010111"},
		{25, "11001"},
	}

	for _, tt := range tests {
		got := gindexToBitstring(tt.gindex)
		if got != tt.expected {
			t.Errorf("gindexToBitstring(%d) = %s, want %s", tt.gindex, got, tt.expected)
		}
	}
}

func TestComputeDescriptor(t *testing.T) {
	tests := []struct {
		name        string
		gindices    []uint64
		expectedHex string
	}{
		{
			name:        "FINALIZED_ROOT_GINDEX_ELECTRA",
			gindices:    []uint64{169},
			expectedHex: "247e",
		},
		{
			name:        "FINALIZED_ROOT_GINDEX_DENEB",
			gindices:    []uint64{105},
			expectedHex: "48f8",
		},
		{
			name:        "NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA",
			gindices:    []uint64{87},
			expectedHex: "2578",
		},
		{
			name:        "NEXT_SYNC_COMMITTEE_GINDEX_DENEB",
			gindices:    []uint64{55},
			expectedHex: "4ae0",
		},
		{
			name:        "BLOCK_BODY_EXECUTION_PAYLOAD_GINDEX",
			gindices:    []uint64{25},
			expectedHex: "4780",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := ComputeDescriptor(tt.gindices)
			gotHex := hex.EncodeToString(descriptor)
			if gotHex != tt.expectedHex {
				t.Errorf("ComputeDescriptor(%v) = 0x%s, want 0x%s", tt.gindices, gotHex, tt.expectedHex)
			}
		})
	}
}

func TestDescriptorToBitlist(t *testing.T) {
	descriptor := []byte{0x24, 0x7e} // 00100100 01111110
	bitlist := descriptorToBitlist(descriptor)

	expected := []bool{
		false, false, true, false, false, true, false, false, // 00100100
		false, true, true, true, true, true, true, false, // 01111110
	}

	if len(bitlist) != len(expected) {
		t.Errorf("bitlist length = %d, want %d", len(bitlist), len(expected))
	}

	for i, b := range expected {
		if bitlist[i] != b {
			t.Errorf("bitlist[%d] = %v, want %v", i, bitlist[i], b)
		}
	}
}

func TestComputeProofBitstrings(t *testing.T) {
	// Test for gindex 169 = 10101001
	branch, path := computeProofBitstrings("10101001")

	// Path should contain: 10101001, 1010100, 101010, 10101, 1010, 101, 10, 1
	expectedPath := map[string]struct{}{
		"10101001": {},
		"1010100":  {},
		"101010":   {},
		"10101":    {},
		"1010":     {},
		"101":      {},
		"10":       {},
		"1":        {},
	}

	// Branch should contain siblings: 10101000, 1010101, 101011, 10100, 1011, 100, 11
	expectedBranch := map[string]struct{}{
		"10101000": {},
		"1010101":  {},
		"101011":   {},
		"10100":    {},
		"1011":     {},
		"100":      {},
		"11":       {},
	}

	for p := range expectedPath {
		if _, ok := path[p]; !ok {
			t.Errorf("Expected path to contain %s", p)
		}
	}

	for b := range expectedBranch {
		if _, ok := branch[b]; !ok {
			t.Errorf("Expected branch to contain %s", b)
		}
	}

	if len(path) != len(expectedPath) {
		t.Errorf("Path length = %d, want %d", len(path), len(expectedPath))
	}

	if len(branch) != len(expectedBranch) {
		t.Errorf("Branch length = %d, want %d", len(branch), len(expectedBranch))
	}
}

func TestExtractSingleProofBranch(t *testing.T) {
	// Create mock leaves for gindex 169
	// The proof bitstrings in sorted order are:
	// '100', '10100', '10101000', '10101001', '1010101', '101011', '1011', '11'
	// Position: 0     1         2           3           4          5        6      7
	leaves := [][]byte{
		[]byte("leaf_100"),      // pos 0 - sibling of gindex 5 (101)
		[]byte("leaf_10100"),    // pos 1 - sibling of gindex 21 (10101)
		[]byte("leaf_10101000"), // pos 2 - sibling of gindex 169 (10101001)
		[]byte("leaf_10101001"), // pos 3 - target (gindex 169)
		[]byte("leaf_1010101"),  // pos 4 - sibling of gindex 84 (1010100)
		[]byte("leaf_101011"),   // pos 5 - sibling of gindex 42 (101010)
		[]byte("leaf_1011"),     // pos 6 - sibling of gindex 10 (1010)
		[]byte("leaf_11"),       // pos 7 - sibling of gindex 2 (10)
	}

	branch, err := ExtractSingleProofBranch(leaves, 169)
	if err != nil {
		t.Fatalf("ExtractSingleProofBranch failed: %v", err)
	}

	// Expected branch order from leaf to root:
	// sibling of 169 (depth 7) = 168 = 10101000 -> pos 2
	// sibling of 84 (depth 6) = 85 = 1010101 -> pos 4
	// sibling of 42 (depth 5) = 43 = 101011 -> pos 5
	// sibling of 21 (depth 4) = 20 = 10100 -> pos 1
	// sibling of 10 (depth 3) = 11 = 1011 -> pos 6
	// sibling of 5 (depth 2) = 4 = 100 -> pos 0
	// sibling of 2 (depth 1) = 3 = 11 -> pos 7
	expectedBranch := [][]byte{
		[]byte("leaf_10101000"), // sibling of 169
		[]byte("leaf_1010101"),  // sibling of 84
		[]byte("leaf_101011"),   // sibling of 42
		[]byte("leaf_10100"),    // sibling of 21
		[]byte("leaf_1011"),     // sibling of 10
		[]byte("leaf_100"),      // sibling of 5
		[]byte("leaf_11"),       // sibling of 2
	}

	if len(branch) != len(expectedBranch) {
		t.Fatalf("Branch length = %d, expected %d", len(branch), len(expectedBranch))
	}

	for i := range expectedBranch {
		if string(branch[i]) != string(expectedBranch[i]) {
			t.Errorf("Branch[%d] = %s, expected %s", i, string(branch[i]), string(expectedBranch[i]))
		}
	}
}

// TestLodestarProofAPIIntegration tests the Lodestar proof API
// This test requires a running Lodestar node
func TestLodestarProofAPIIntegration(t *testing.T) {
	endpoint := os.Getenv("BEACON_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:59014"
	}

	initTestLogger()
	client := NewClient(endpoint)
	ctx := context.Background()

	// Test state proof for finalized root (gindex 169 for Electra/Fulu)
	t.Run("StateProof_FinalizedRoot", func(t *testing.T) {
		res, err := client.GetStateProof(ctx, "finalized", []uint64{FinalizedRootGindexElectra})
		if err != nil {
			t.Fatalf("GetStateProof failed: %v", err)
		}

		t.Logf("Version: %s", res.Version)
		t.Logf("Leaves count: %d", len(res.Data.Leaves))
		t.Logf("Descriptor: 0x%s", hex.EncodeToString(res.Data.Descriptor))

		// For gindex 169, we expect 8 leaves (7 siblings + 1 target)
		if len(res.Data.Leaves) != 8 {
			t.Errorf("Expected 8 leaves, got %d", len(res.Data.Leaves))
		}

		for i, leaf := range res.Data.Leaves {
			t.Logf("Leaf[%d]: 0x%s", i, hex.EncodeToString(leaf))
		}
	})

	// Test state proof for next sync committee (gindex 87 for Electra/Fulu)
	t.Run("StateProof_NextSyncCommittee", func(t *testing.T) {
		res, err := client.GetStateProof(ctx, "finalized", []uint64{NextSyncCommitteeGindexElectra})
		if err != nil {
			t.Fatalf("GetStateProof failed: %v", err)
		}

		t.Logf("Version: %s", res.Version)
		t.Logf("Leaves count: %d", len(res.Data.Leaves))

		// For gindex 87, we expect 7 leaves (6 siblings + 1 target)
		if len(res.Data.Leaves) != 7 {
			t.Errorf("Expected 7 leaves, got %d", len(res.Data.Leaves))
		}
	})

	// Test block proof for execution payload (gindex 25)
	t.Run("BlockProof_ExecutionPayload", func(t *testing.T) {
		res, err := client.GetBlockProof(ctx, "finalized", []uint64{BlockBodyExecutionPayloadGindex})
		if err != nil {
			t.Fatalf("GetBlockProof failed: %v", err)
		}

		t.Logf("Version: %s", res.Version)
		t.Logf("Leaves count: %d", len(res.Data.Leaves))

		// For gindex 25, we expect 5 leaves (4 siblings + 1 target)
		if len(res.Data.Leaves) != 5 {
			t.Errorf("Expected 5 leaves, got %d", len(res.Data.Leaves))
		}
	})
}
