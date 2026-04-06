package beacon

import (
	"fmt"
	"math/bits"
	"sort"
)

// Gindex constants for different forks
const (
	// Deneb gindices
	FinalizedRootGindexDeneb        = 105
	NextSyncCommitteeGindexDeneb    = 55

	// Electra/Fulu gindices (post-Electra)
	FinalizedRootGindexElectra      = 169
	NextSyncCommitteeGindexElectra  = 87

	// Lodestar proof API gindices
	// The Lodestar /eth/v0/beacon/proof/block API uses a virtual tree structure where:
	// - body_root = hash(other_fields || execution_payload)
	// - So execution_payload is at gindex 3 (right child) in the body tree
	// - But gindex 25 is used for the full block tree (block_root → body_root → execution_payload)
	LodestarExecutionPayloadInBlockGindex = 25
	// For verification against body_root, use gindex 3 (depth 1, right child)
	ExecutionPayloadInBodyGindex = 3
)

// computeProofBitstrings computes the branch (siblings) and path (ancestors) for a leaf gindex
func computeProofBitstrings(leafBitstring string) (branch, path map[string]struct{}) {
	branch = make(map[string]struct{})
	path = make(map[string]struct{})

	current := leafBitstring
	path[current] = struct{}{}

	for len(current) > 1 {
		// Get sibling (flip last bit)
		siblingBit := '0'
		if current[len(current)-1] == '0' {
			siblingBit = '1'
		}
		sibling := current[:len(current)-1] + string(siblingBit)
		branch[sibling] = struct{}{}

		// Move to parent
		current = current[:len(current)-1]
		path[current] = struct{}{}
	}

	return branch, path
}

// gindexToBitstring converts a gindex to its binary string representation
func gindexToBitstring(gindex uint64) string {
	if gindex == 0 {
		return "0"
	}
	// Count leading zeros to determine the length
	length := 64 - bits.LeadingZeros64(gindex)
	result := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		if gindex&1 == 1 {
			result[i] = '1'
		} else {
			result[i] = '0'
		}
		gindex >>= 1
	}
	return string(result)
}

// ComputeDescriptor computes a descriptor for the given gindices
// This implements the algorithm from @chainsafe/persistent-merkle-tree
func ComputeDescriptor(gindices []uint64) []byte {
	proofBitstrings := make(map[string]struct{})
	pathBitstrings := make(map[string]struct{})

	for _, leafIndex := range gindices {
		leafBitstring := gindexToBitstring(leafIndex)
		proofBitstrings[leafBitstring] = struct{}{}

		branch, path := computeProofBitstrings(leafBitstring)

		// Remove the leaf from path set (it's in proof, not path)
		delete(path, leafBitstring)

		for pathIndex := range path {
			pathBitstrings[pathIndex] = struct{}{}
		}
		for branchIndex := range branch {
			proofBitstrings[branchIndex] = struct{}{}
		}
	}

	// Remove path indices from proof set
	for pathIndex := range pathBitstrings {
		delete(proofBitstrings, pathIndex)
	}

	// Sort bitstrings lexicographically (in-order traversal)
	allBitstrings := make([]string, 0, len(proofBitstrings))
	for bitstring := range proofBitstrings {
		allBitstrings = append(allBitstrings, bitstring)
	}
	sort.Strings(allBitstrings)

	// Convert gindex bitstrings into descriptor bitstring
	var descriptorBits string
	for _, gindexBitstring := range allBitstrings {
		// Find rightmost '1' and count trailing zeros before it
		for i := 0; i < len(gindexBitstring); i++ {
			idx := len(gindexBitstring) - 1 - i
			if gindexBitstring[idx] == '1' {
				// Output i zeros followed by 1
				for j := 0; j < i; j++ {
					descriptorBits += "0"
				}
				descriptorBits += "1"
				break
			}
		}
	}

	// Append zero bits to byte-align
	if len(descriptorBits)%8 != 0 {
		padding := 8 - (len(descriptorBits) % 8)
		for i := 0; i < padding; i++ {
			descriptorBits += "0"
		}
	}

	// Convert to bytes
	descriptor := make([]byte, len(descriptorBits)/8)
	for i := 0; i < len(descriptor); i++ {
		var b byte
		for j := 0; j < 8; j++ {
			if descriptorBits[i*8+j] == '1' {
				b |= 1 << (7 - j)
			}
		}
		descriptor[i] = b
	}

	return descriptor
}

// ExtractSingleProofBranch extracts a proof branch for a single gindex from CompactMultiProof leaves
// The leaves are returned in in-order traversal (lexicographic order of gindex bitstrings)
// Returns the branch in order from leaf-level sibling to root-level sibling
func ExtractSingleProofBranch(leaves [][]byte, gindex uint64) ([][]byte, error) {
	depth := bits.Len64(gindex) - 1 // depth from root (excluding root)

	if depth == 0 {
		return [][]byte{}, nil
	}

	expectedLeaves := depth + 1 // depth siblings + 1 target leaf
	if len(leaves) != expectedLeaves {
		return nil, fmt.Errorf("wrong number of leaves for gindex %d: got %d, expected %d", gindex, len(leaves), expectedLeaves)
	}

	// For a single gindex, the leaves are ordered by lexicographic order of gindex bitstrings
	// We need to compute the position of each sibling in this ordering

	// First, compute the sorted proof bitstrings
	leafBitstring := gindexToBitstring(gindex)
	proofBitstrings := make(map[string]struct{})
	pathBitstrings := make(map[string]struct{})

	proofBitstrings[leafBitstring] = struct{}{}
	branchSet, pathSet := computeProofBitstrings(leafBitstring)
	delete(pathSet, leafBitstring)

	for p := range pathSet {
		pathBitstrings[p] = struct{}{}
	}
	for b := range branchSet {
		proofBitstrings[b] = struct{}{}
	}
	for p := range pathBitstrings {
		delete(proofBitstrings, p)
	}

	// Sort the proof bitstrings
	sortedBitstrings := make([]string, 0, len(proofBitstrings))
	for b := range proofBitstrings {
		sortedBitstrings = append(sortedBitstrings, b)
	}
	sort.Strings(sortedBitstrings)

	// Create a map from bitstring to leaf position
	positionMap := make(map[string]int)
	for i, b := range sortedBitstrings {
		positionMap[b] = i
	}

	// Extract the branch by walking from leaf to root
	branch := make([][]byte, depth)
	currentGindex := gindex

	for i := 0; i < depth; i++ {
		// Get sibling gindex (flip last bit)
		siblingGindex := currentGindex ^ 1
		siblingBitstring := gindexToBitstring(siblingGindex)

		// Find the position of this sibling in the sorted leaves
		pos, ok := positionMap[siblingBitstring]
		if !ok {
			return nil, fmt.Errorf("sibling gindex %d (bitstring %s) not found in proof", siblingGindex, siblingBitstring)
		}

		branch[i] = leaves[pos]

		// Move to parent
		currentGindex = currentGindex / 2
	}

	return branch, nil
}

// GetFinalizedRootGindex returns the finalized root gindex for the given version
func GetFinalizedRootGindex(version string) uint64 {
	switch version {
	case "deneb":
		return FinalizedRootGindexDeneb
	default: // electra, fulu, and future forks use the Electra gindex
		return FinalizedRootGindexElectra
	}
}

// GetNextSyncCommitteeGindex returns the next sync committee gindex for the given version
func GetNextSyncCommitteeGindex(version string) uint64 {
	switch version {
	case "deneb":
		return NextSyncCommitteeGindexDeneb
	default:
		return NextSyncCommitteeGindexElectra
	}
}

// ExtractExecutionBranchForBodyRoot extracts the execution branch for verification against body_root
// The Lodestar block proof API returns a proof from execution_payload to block_root (gindex 25, depth 4)
// But for Light Client verification, we need a proof against body_root (gindex 3, depth 1)
// This function extracts just the first level of the branch (the sibling of execution_payload within body)
func ExtractExecutionBranchForBodyRoot(leaves [][]byte, fullGindex uint64) ([][]byte, error) {
	// First extract the full branch for gindex 25
	fullBranch, err := ExtractSingleProofBranch(leaves, fullGindex)
	if err != nil {
		return nil, fmt.Errorf("failed to extract full branch: %w", err)
	}

	// For body_root verification (gindex 3), we only need the first element
	// This is the sibling of execution_payload in the virtual body tree
	if len(fullBranch) < 1 {
		return nil, fmt.Errorf("full branch is empty")
	}

	// Return just the first branch element (depth 1 for gindex 3)
	return [][]byte{fullBranch[0]}, nil
}

// ExtractTargetLeaf extracts the target leaf (the node at the given gindex) from CompactMultiProof leaves
func ExtractTargetLeaf(leaves [][]byte, gindex uint64) ([]byte, error) {
	depth := bits.Len64(gindex) - 1

	if depth == 0 {
		return nil, fmt.Errorf("cannot extract target leaf for gindex 1 (root)")
	}

	// Compute the sorted proof bitstrings to find the position of the target
	leafBitstring := gindexToBitstring(gindex)
	proofBitstrings := make(map[string]struct{})
	pathBitstrings := make(map[string]struct{})

	proofBitstrings[leafBitstring] = struct{}{}
	branchSet, pathSet := computeProofBitstrings(leafBitstring)
	delete(pathSet, leafBitstring)

	for p := range pathSet {
		pathBitstrings[p] = struct{}{}
	}
	for b := range branchSet {
		proofBitstrings[b] = struct{}{}
	}
	for p := range pathBitstrings {
		delete(proofBitstrings, p)
	}

	// Sort the proof bitstrings
	sortedBitstrings := make([]string, 0, len(proofBitstrings))
	for b := range proofBitstrings {
		sortedBitstrings = append(sortedBitstrings, b)
	}
	sort.Strings(sortedBitstrings)

	// Find the position of the target leaf
	for i, b := range sortedBitstrings {
		if b == leafBitstring {
			if i >= len(leaves) {
				return nil, fmt.Errorf("target leaf position %d out of bounds (leaves len %d)", i, len(leaves))
			}
			return leaves[i], nil
		}
	}

	return nil, fmt.Errorf("target leaf bitstring %s not found in proof", leafBitstring)
}
