package relay

import (
	"context"

	lcrelay "github.com/datachainlab/ethereum-light-client-types/prover/relay"
	lctypes "github.com/datachainlab/ethereum-light-client-types/prover/types"
)

func (pr *Prover) buildAccountUpdate(ctx context.Context, blockNumber uint64) (*lctypes.AccountUpdate, error) {
	return lcrelay.BuildAccountUpdate(ctx, proofClient{pr.executionClient}, pr.ibcAddress, blockNumber)
}

func (pr *Prover) buildStateProof(ctx context.Context, path []byte, height int64) ([]byte, error) {
	return lcrelay.BuildStateProof(ctx, proofClient{pr.executionClient}, pr.ibcAddress, path, height)
}
