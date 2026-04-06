package relay

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/datachainlab/ethereum-ibc-relay-prover/beacon"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz"
	enginev1 "github.com/OffchainLabs/prysm/v7/proto/engine/v1"
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
