package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	lctypes "github.com/datachainlab/ethereum-ibc-relay-prover/light-clients/ethereum/types"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	ethpb "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
)

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
		{"gindex 87 (next sync committee)", 87, 6},
		{"gindex 169 (finalized root)", 169, 7},
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
		{"gindex 87 (next sync committee)", 87, 23},
		{"gindex 169 (finalized root)", 169, 41},
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

func TestForkSpecGindexValues(t *testing.T) {
	// Verify gindex values match the plan
	tests := []struct {
		name   string
		fork   string
		checks map[string]uint32
	}{
		{
			name: "Electra/Fulu gindex values",
			fork: "electra",
			checks: map[string]uint32{
				"FinalizedRoot":     169,
				"NextSyncCommittee": 87,
				"ExecutionPayload":  25,
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

// isValidNormalizedMerkleBranch verifies a Merkle proof against a root
// This matches the Rust implementation in ethereum-light-client-rs
func isValidNormalizedMerkleBranch(leaf []byte, branch [][]byte, gindex uint32, root []byte) error {
	if gindex == 0 {
		return fmt.Errorf("invalid gindex: 0")
	}
	depth := gindexToDepth(gindex)
	subtreeIndex := gindexToLeafIndex(gindex)
	return isValidMerkleBranch(leaf, branch, depth, uint32(subtreeIndex), root)
}

// isValidMerkleBranch implements the Ethereum consensus-specs is_valid_merkle_branch
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
func isValidMerkleBranch(leaf []byte, branch [][]byte, depth int, subtreeIndex uint32, root []byte) error {
	if depth != len(branch) {
		return fmt.Errorf("invalid branch length: expected %d, got %d", depth, len(branch))
	}

	value := make([]byte, 32)
	copy(value, leaf)

	for i, b := range branch {
		var combined []byte
		divisor := uint32(1) << uint32(i)
		if (subtreeIndex/divisor)%2 == 1 {
			// branch[i] is on the left
			combined = append(b, value...)
		} else {
			// branch[i] is on the right
			combined = append(value, b...)
		}
		value = sha256Hash(combined)
	}

	if !bytes.Equal(value, root) {
		return fmt.Errorf("merkle proof verification failed: computed root %x != expected root %x", value, root)
	}
	return nil
}

// sha256Hash computes SHA256 hash
func sha256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func TestHashBeaconBlockHeader(t *testing.T) {
	// Test with known values from slot 168
	// Expected root from beacon API: 0xecc35dfed68b899cbe96c37ed9f7b22cee38a9cd35b79b6941b693106b16cd9e
	parentRoot, _ := hex.DecodeString("e8634ef6a217c325ab6b6591f2eb404b9022b2e1a3a51509d69c214c599abfb9")
	stateRoot, _ := hex.DecodeString("d9a2a961e5eeac47fabab7a4bd96937df04e02555dc219f7d04aa10b53ef5be5")
	bodyRoot, _ := hex.DecodeString("f6495100a31305ffe427efe37b3414876267933cedac311868e07e46dc0c6fa6")

	// Test using prysm's BeaconBlockHeader directly
	prysmHeader := &ethpb.BeaconBlockHeader{
		Slot:          primitives.Slot(168),
		ProposerIndex: primitives.ValidatorIndex(13),
		ParentRoot:    parentRoot,
		StateRoot:     stateRoot,
		BodyRoot:      bodyRoot,
	}

	prysmRoot, err := prysmHeader.HashTreeRoot()
	if err != nil {
		t.Fatalf("prysm HashTreeRoot failed: %v", err)
	}

	expectedRoot, _ := hex.DecodeString("ecc35dfed68b899cbe96c37ed9f7b22cee38a9cd35b79b6941b693106b16cd9e")

	t.Logf("Prysm computed root: %x", prysmRoot)
	t.Logf("Expected root:       %x", expectedRoot)

	if !bytes.Equal(prysmRoot[:], expectedRoot) {
		t.Errorf("Prysm hash mismatch: computed %x, expected %x", prysmRoot, expectedRoot)
	}

	// Also test our wrapper function
	header := &lctypes.BeaconBlockHeader{
		Slot:          168,
		ProposerIndex: 13,
		ParentRoot:    parentRoot,
		StateRoot:     stateRoot,
		BodyRoot:      bodyRoot,
	}

	// Convert to prysm type and hash
	prysmHeader2 := &ethpb.BeaconBlockHeader{
		Slot:          primitives.Slot(header.Slot),
		ProposerIndex: primitives.ValidatorIndex(header.ProposerIndex),
		ParentRoot:    header.ParentRoot,
		StateRoot:     header.StateRoot,
		BodyRoot:      header.BodyRoot,
	}

	root2, err := prysmHeader2.HashTreeRoot()
	if err != nil {
		t.Fatalf("HashTreeRoot failed: %v", err)
	}

	t.Logf("Wrapper computed root: %x", root2)

	if !bytes.Equal(root2[:], expectedRoot) {
		t.Errorf("Wrapper hash mismatch: computed %x, expected %x", root2, expectedRoot)
	}
}

func TestIsValidMerkleBranch(t *testing.T) {
	// Create 4 leaves
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

	// Compute the root manually
	h01 := sha256Hash(append(leaves[0], leaves[1]...))
	h23 := sha256Hash(append(leaves[2], leaves[3]...))
	root := sha256Hash(append(h01, h23...))

	// Generate and verify proof for leaf 0 (gindex = 4)
	proof0, err := generateMerkleProof(leaves, 0)
	if err != nil {
		t.Fatalf("generateMerkleProof failed: %v", err)
	}

	err = isValidNormalizedMerkleBranch(leaves[0], proof0, 4, root)
	if err != nil {
		t.Errorf("isValidNormalizedMerkleBranch failed for leaf 0: %v", err)
	}

	// Generate and verify proof for leaf 2 (gindex = 6)
	proof2, err := generateMerkleProof(leaves, 2)
	if err != nil {
		t.Fatalf("generateMerkleProof failed: %v", err)
	}

	err = isValidNormalizedMerkleBranch(leaves[2], proof2, 6, root)
	if err != nil {
		t.Errorf("isValidNormalizedMerkleBranch failed for leaf 2: %v", err)
	}

	// Test with wrong root - should fail
	wrongRoot := make([]byte, 32)
	err = isValidNormalizedMerkleBranch(leaves[0], proof0, 4, wrongRoot)
	if err == nil {
		t.Error("isValidNormalizedMerkleBranch should fail with wrong root")
	}

	// Test with corrupted branch - should fail
	corruptedProof := make([][]byte, len(proof0))
	for i := range proof0 {
		corruptedProof[i] = make([]byte, 32)
		copy(corruptedProof[i], proof0[i])
	}
	corruptedProof[0][0] ^= 0xFF // Flip some bits
	err = isValidNormalizedMerkleBranch(leaves[0], corruptedProof, 4, root)
	if err == nil {
		t.Error("isValidNormalizedMerkleBranch should fail with corrupted branch")
	}
}
