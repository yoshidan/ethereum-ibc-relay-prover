package relay

import (
	"context"

	"github.com/datachainlab/ethereum-light-client-types/prover/beacon"
	lcrelay "github.com/datachainlab/ethereum-light-client-types/prover/relay"
	lctypes "github.com/datachainlab/ethereum-light-client-types/prover/types"
)

func (pr *Prover) secondsPerSlot() uint64 {
	return lcrelay.SecondsPerSlot(pr.config.Network)
}

func (pr *Prover) slotsPerEpoch() uint64 {
	return lcrelay.SlotsPerEpoch(pr.config.Network)
}

func (pr *Prover) epochsPerSyncCommitteePeriod() uint64 {
	return lcrelay.EpochsPerSyncCommitteePeriod(pr.config.Network)
}

func (pr *Prover) getPeriodBoundarySlot(period uint64) uint64 {
	return lcrelay.GetPeriodBoundarySlot(pr.config.Network, period)
}

func (pr *Prover) computeSyncCommitteePeriod(epoch uint64) uint64 {
	return lcrelay.ComputeSyncCommitteePeriod(pr.config.Network, epoch)
}

func (pr *Prover) computeEpoch(slot uint64) uint64 {
	return lcrelay.ComputeEpoch(pr.config.Network, slot)
}

func (pr *Prover) getSlotAtTimestamp(ctx context.Context, timestamp uint64) (uint64, error) {
	return lcrelay.GetSlotAtTimestamp(ctx, pr.beaconClient, pr.config.Network, timestamp)
}

func (pr *Prover) getPeriodWithBlockNumber(ctx context.Context, blockNumber uint64) (uint64, error) {
	return lcrelay.GetPeriodWithBlockNumber(ctx, pr.beaconClient, pr.executionClient, pr.config.Network, blockNumber)
}

func (pr *Prover) buildExecutionUpdateFromFinalizedHeader(ctx context.Context, finalizedHeader *beacon.LightClientHeader) (*lctypes.ExecutionUpdate, uint64, error) {
	return lcrelay.BuildExecutionUpdateFromFinalizedHeader(ctx, pr.executionClient.Raw(), finalizedHeader, false)
}
