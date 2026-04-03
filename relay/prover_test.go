package relay

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	transfertypes "github.com/cosmos/ibc-go/v8/modules/apps/transfer/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	conntypes "github.com/cosmos/ibc-go/v8/modules/core/03-connection/types"
	chantypes "github.com/cosmos/ibc-go/v8/modules/core/04-channel/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/ethereum-ibc-relay-prover/beacon"
	lctypes "github.com/datachainlab/ethereum-ibc-relay-prover/light-clients/ethereum/types"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
)

var initLoggerOnce sync.Once

func initTestLogger() {
	initLoggerOnce.Do(func() {
		// Initialize logger with minimal settings for testing
		_ = log.InitLogger("error", "json", "stderr", false)
	})
}

// mockChain implements core.Chain interface for testing
type mockChain struct{}

func (m *mockChain) ChainID() string                     { return "test-chain" }
func (m *mockChain) GetAddress() (sdk.AccAddress, error) { return nil, nil }
func (m *mockChain) Codec() codec.ProtoCodecMarshaler    { return nil }
func (m *mockChain) Path() *core.PathEnd                 { return nil }
func (m *mockChain) Init(string, time.Duration, codec.ProtoCodecMarshaler, bool) error {
	return nil
}
func (m *mockChain) SetRelayInfo(*core.PathEnd, *core.ProvableChain, *core.PathEnd) error {
	return nil
}
func (m *mockChain) SetupForRelay(context.Context) error                       { return nil }
func (m *mockChain) SendMsgs(context.Context, []sdk.Msg) ([]core.MsgID, error) { return nil, nil }
func (m *mockChain) GetMsgResult(context.Context, core.MsgID) (core.MsgResult, error) {
	return nil, nil
}
func (m *mockChain) RegisterMsgEventListener(core.MsgEventListener)           {}
func (m *mockChain) LatestHeight(context.Context) (ibcexported.Height, error) { return nil, nil }
func (m *mockChain) Timestamp(context.Context, ibcexported.Height) (time.Time, error) {
	return time.Time{}, nil
}
func (m *mockChain) AverageBlockTime() time.Duration { return time.Second }

// ICS02Querier
func (m *mockChain) QueryClientState(core.QueryContext) (*clienttypes.QueryClientStateResponse, error) {
	return nil, nil
}
func (m *mockChain) QueryClientConsensusState(core.QueryContext, ibcexported.Height) (*clienttypes.QueryConsensusStateResponse, error) {
	return nil, nil
}

// ICS03Querier
func (m *mockChain) QueryConnection(core.QueryContext, string) (*conntypes.QueryConnectionResponse, error) {
	return nil, nil
}

// ICS04Querier
func (m *mockChain) QueryChannel(core.QueryContext) (*chantypes.QueryChannelResponse, error) {
	return nil, nil
}
func (m *mockChain) QueryUnreceivedPackets(core.QueryContext, []uint64) ([]uint64, error) {
	return nil, nil
}
func (m *mockChain) QueryUnfinalizedRelayPackets(core.QueryContext, core.LightClientICS04Querier) (core.PacketInfoList, error) {
	return nil, nil
}
func (m *mockChain) QueryUnreceivedAcknowledgements(core.QueryContext, []uint64) ([]uint64, error) {
	return nil, nil
}
func (m *mockChain) QueryUnfinalizedRelayAcknowledgements(core.QueryContext, core.LightClientICS04Querier) (core.PacketInfoList, error) {
	return nil, nil
}
func (m *mockChain) QueryChannelUpgrade(core.QueryContext) (*chantypes.QueryUpgradeResponse, error) {
	return nil, nil
}
func (m *mockChain) QueryChannelUpgradeError(core.QueryContext) (*chantypes.QueryUpgradeErrorResponse, error) {
	return nil, nil
}
func (m *mockChain) QueryCanTransitionToFlushComplete(core.QueryContext) (bool, error) {
	return false, nil
}

// ICS20Querier
func (m *mockChain) QueryBalance(core.QueryContext, sdk.AccAddress) (sdk.Coins, error) {
	return nil, nil
}
func (m *mockChain) QueryDenomTraces(core.QueryContext, uint64, uint64) (*transfertypes.QueryDenomTracesResponse, error) {
	return nil, nil
}

var _ core.Chain = (*mockChain)(nil)

func getBeaconEndpoint() string {
	endpoint := os.Getenv("BEACON_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:59014"
	}
	return endpoint
}

func newTestProver(t *testing.T) *Prover {
	initTestLogger()

	endpoint := getBeaconEndpoint()
	beaconClient := beacon.NewClient(endpoint)

	// Create a devnet config for testing (mainnet preset with all forks at epoch 0)
	config := ProverConfig{
		Network:        "kurtosis_minimal",
		BeaconEndpoint: endpoint,
	}

	return &Prover{
		chain:        &mockChain{},
		config:       config,
		beaconClient: beaconClient,
	}
}

func TestGetForkSpecForSlot(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get a finalized block to get a valid slot
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	t.Logf("Testing with slot: %d, version: %s", slot, block.Version)

	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		t.Fatalf("getForkSpecForSlot returned nil for slot %d", slot)
	}

	t.Logf("ForkSpec for slot %d: FinalizedRootGindex=%d, NextSyncCommitteeGindex=%d, ExecutionPayloadGindex=%d",
		slot, forkSpec.FinalizedRootGindex, forkSpec.NextSyncCommitteeGindex, forkSpec.ExecutionPayloadGindex)

	// Verify gindex values are reasonable
	if forkSpec.FinalizedRootGindex == 0 {
		t.Error("FinalizedRootGindex should not be 0")
	}
	if forkSpec.ExecutionPayloadGindex == 0 {
		t.Error("ExecutionPayloadGindex should not be 0")
	}
}

func TestFindValidBlockSlot(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get a finalized block to get a valid slot
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	targetSlot := uint64(block.Data.Message.Slot)
	t.Logf("Testing findValidBlockSlot with target slot: %d", targetSlot)

	foundSlot, err := pr.findValidBlockSlot(ctx, targetSlot)
	if err != nil {
		t.Fatalf("findValidBlockSlot failed: %v", err)
	}

	t.Logf("Found valid block at slot: %d", foundSlot)

	if foundSlot > targetSlot {
		t.Errorf("Found slot %d is greater than target slot %d", foundSlot, targetSlot)
	}
}

func TestFindSignatureAndAttestedSlot(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block
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

	// Need at least 2 slots after finalized for attested and signature blocks
	// Attested slot is typically finalized + 1 epoch (8 slots for minimal)
	// Signature slot is attested + 1
	if headSlot < finalizedSlot+17 {
		t.Skipf("Chain head (%d) is too close to finalized slot (%d), need more blocks for signature", headSlot, finalizedSlot)
	}

	// Get finalized block root
	finalizedBlockRoot, err := pr.beaconClient.GetBlockRootByID(ctx, "finalized", true)
	if err != nil {
		t.Fatalf("Failed to get finalized block root: %v", err)
	}

	t.Logf("Testing findSignatureAndAttestedSlot: finalized_slot=%d, finalized_root=%s",
		finalizedSlot, finalizedBlockRoot.Data.Root.String())

	signatureSlot, attestedSlot, err := pr.findSignatureAndAttestedSlot(ctx, finalizedBlockRoot.Data.Root, finalizedSlot)
	if err != nil {
		t.Fatalf("findSignatureAndAttestedSlot failed: %v", err)
	}

	t.Logf("Found: signature_slot=%d, attested_slot=%d, finalized_slot=%d",
		signatureSlot, attestedSlot, finalizedSlot)

	// Verify slot ordering: signature > attested > finalized
	if signatureSlot <= attestedSlot {
		t.Errorf("Signature slot %d should be greater than attested slot %d", signatureSlot, attestedSlot)
	}
	if attestedSlot < finalizedSlot {
		t.Errorf("Attested slot %d should be >= finalized slot %d", attestedSlot, finalizedSlot)
	}

	// Verify the signature block's parent is the attested block
	signatureBlock, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", signatureSlot))
	if err != nil {
		t.Fatalf("Failed to get signature block: %v", err)
	}

	attestedBlockRoot, err := pr.beaconClient.GetBlockRootByID(ctx, fmt.Sprintf("%d", attestedSlot), true)
	if err != nil {
		t.Fatalf("Failed to get attested block root: %v", err)
	}

	if signatureBlock.Data.Message.ParentRoot.String() != attestedBlockRoot.Data.Root.String() {
		t.Errorf("Signature block's parent_root %s doesn't match attested block root %s",
			signatureBlock.Data.Message.ParentRoot.String(), attestedBlockRoot.Data.Root.String())
	}

	// Verify attested block's state has finalized_checkpoint.root == finalized block root
	checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		t.Fatalf("Failed to get finality checkpoints at attested slot: %v", err)
	}

	if fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:]) != finalizedBlockRoot.Data.Root.String() {
		t.Errorf("Attested state's finalized_checkpoint.root %s doesn't match finalized block root %s",
			fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:]), finalizedBlockRoot.Data.Root.String())
	}
}

func TestGetSyncCommitteesFromState(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	version := block.Version

	t.Logf("Testing getSyncCommitteesFromState: slot=%d, version=%s", slot, version)

	currentSC, nextSC, err := pr.getSyncCommitteesFromState(ctx, slot, version)
	if err != nil {
		t.Fatalf("getSyncCommitteesFromState failed: %v", err)
	}

	if currentSC == nil {
		t.Error("Current sync committee should not be nil")
	} else {
		t.Logf("Current sync committee pubkeys count: %d", len(currentSC.Pubkeys))
		if len(currentSC.Pubkeys) == 0 {
			t.Error("Current sync committee should have pubkeys")
		}
		if len(currentSC.AggregatePubkey) == 0 {
			t.Error("Current sync committee should have aggregate pubkey")
		}
	}

	if nextSC == nil {
		t.Error("Next sync committee should not be nil")
	} else {
		t.Logf("Next sync committee pubkeys count: %d", len(nextSC.Pubkeys))
	}
}

func TestBuildConsensusUpdateFromBeaconAPI(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// First check if beacon API is available
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

	// Need enough blocks after finalized for attested and signature blocks
	if headSlot < finalizedSlot+17 {
		t.Skipf("Chain head (%d) is too close to finalized slot (%d), need more blocks", headSlot, finalizedSlot)
	}

	t.Logf("Testing buildConsensusUpdateFromBeaconAPI: version=%s", block.Version)
	t.Log("Testing buildConsensusUpdateFromBeaconAPI without next sync committee")
	update, execHeader, err := pr.buildConsensusUpdateFromBeaconAPI(ctx, false)
	if err != nil {
		t.Fatalf("buildConsensusUpdateFromBeaconAPI failed: %v", err)
	}

	validateConsensusUpdate(t, update, false)
	validateExecutionHeader(t, execHeader)

	t.Log("Testing buildConsensusUpdateFromBeaconAPI with next sync committee")
	updateWithSC, execHeader2, err := pr.buildConsensusUpdateFromBeaconAPI(ctx, true)
	if err != nil {
		t.Fatalf("buildConsensusUpdateFromBeaconAPI with next sync committee failed: %v", err)
	}

	validateConsensusUpdate(t, updateWithSC, true)
	validateExecutionHeader(t, execHeader2)
}

func TestBuildConsensusUpdateWithSlots(t *testing.T) {
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

	// Need enough blocks after finalized for attested and signature blocks
	if headSlot < finalizedSlot+17 {
		t.Skipf("Chain head (%d) is too close to finalized slot (%d), need more blocks", headSlot, finalizedSlot)
	}

	t.Logf("Testing buildConsensusUpdateWithSlots: version=%s", block.Version)

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

	t.Logf("Testing buildConsensusUpdateWithSlots: signature_slot=%d, attested_slot=%d, finalized_block=finalized, version=%s",
		signatureSlot, attestedSlot, block.Version)

	update, execHeader, err := pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, "finalized", block.Version, false)
	if err != nil {
		t.Fatalf("buildConsensusUpdateWithSlots failed: %v", err)
	}

	validateConsensusUpdate(t, update, false)
	validateExecutionHeader(t, execHeader)
}

func validateConsensusUpdate(t *testing.T, update *lctypes.ConsensusUpdate, expectNextSyncCommittee bool) {
	t.Helper()

	if update == nil {
		t.Fatal("ConsensusUpdate should not be nil")
	}

	// Validate AttestedHeader
	if update.AttestedHeader == nil {
		t.Error("AttestedHeader should not be nil")
	} else {
		t.Logf("AttestedHeader: slot=%d, proposer_index=%d", update.AttestedHeader.Slot, update.AttestedHeader.ProposerIndex)
		if len(update.AttestedHeader.StateRoot) != 32 {
			t.Errorf("AttestedHeader.StateRoot length should be 32, got %d", len(update.AttestedHeader.StateRoot))
		}
		if len(update.AttestedHeader.BodyRoot) != 32 {
			t.Errorf("AttestedHeader.BodyRoot length should be 32, got %d", len(update.AttestedHeader.BodyRoot))
		}
	}

	// Validate FinalizedHeader
	if update.FinalizedHeader == nil {
		t.Error("FinalizedHeader should not be nil")
	} else {
		t.Logf("FinalizedHeader: slot=%d, proposer_index=%d", update.FinalizedHeader.Slot, update.FinalizedHeader.ProposerIndex)
		if len(update.FinalizedHeader.StateRoot) != 32 {
			t.Errorf("FinalizedHeader.StateRoot length should be 32, got %d", len(update.FinalizedHeader.StateRoot))
		}
	}

	// Validate slot ordering
	if update.AttestedHeader != nil && update.FinalizedHeader != nil {
		if update.FinalizedHeader.Slot > update.AttestedHeader.Slot {
			t.Errorf("FinalizedHeader.Slot (%d) should be <= AttestedHeader.Slot (%d)",
				update.FinalizedHeader.Slot, update.AttestedHeader.Slot)
		}
	}

	// Validate FinalizedHeaderBranch
	if len(update.FinalizedHeaderBranch) == 0 {
		t.Error("FinalizedHeaderBranch should not be empty")
	} else {
		t.Logf("FinalizedHeaderBranch length: %d", len(update.FinalizedHeaderBranch))
		for i, hash := range update.FinalizedHeaderBranch {
			if len(hash) != 32 {
				t.Errorf("FinalizedHeaderBranch[%d] length should be 32, got %d", i, len(hash))
			}
		}
	}

	// Validate FinalizedExecutionRoot
	if len(update.FinalizedExecutionRoot) != 32 {
		t.Errorf("FinalizedExecutionRoot length should be 32, got %d", len(update.FinalizedExecutionRoot))
	}

	// Validate FinalizedExecutionBranch
	if len(update.FinalizedExecutionBranch) == 0 {
		t.Error("FinalizedExecutionBranch should not be empty")
	} else {
		t.Logf("FinalizedExecutionBranch length: %d", len(update.FinalizedExecutionBranch))
	}

	// Validate SyncAggregate
	if update.SyncAggregate == nil {
		t.Error("SyncAggregate should not be nil")
	} else {
		if len(update.SyncAggregate.SyncCommitteeBits) == 0 {
			t.Error("SyncAggregate.SyncCommitteeBits should not be empty")
		}
		if len(update.SyncAggregate.SyncCommitteeSignature) == 0 {
			t.Error("SyncAggregate.SyncCommitteeSignature should not be empty")
		}
	}

	// Validate SignatureSlot
	if update.SignatureSlot == 0 {
		t.Error("SignatureSlot should not be 0")
	}
	t.Logf("SignatureSlot: %d", update.SignatureSlot)

	// Validate NextSyncCommittee if expected
	if expectNextSyncCommittee {
		if update.NextSyncCommittee == nil {
			t.Error("NextSyncCommittee should not be nil when expected")
		} else {
			t.Logf("NextSyncCommittee pubkeys count: %d", len(update.NextSyncCommittee.Pubkeys))
		}
		if len(update.NextSyncCommitteeBranch) == 0 {
			t.Error("NextSyncCommitteeBranch should not be empty when NextSyncCommittee is expected")
		}
	}
}

func validateExecutionHeader(t *testing.T, header *beacon.ExecutionPayloadHeader) {
	t.Helper()

	if header == nil {
		t.Fatal("ExecutionPayloadHeader should not be nil")
	}

	t.Logf("ExecutionPayloadHeader: block_number=%d, timestamp=%d", header.BlockNumber, header.Timestamp)

	if len(header.ParentHash) != 32 {
		t.Errorf("ParentHash length should be 32, got %d", len(header.ParentHash))
	}
	if len(header.StateRoot) != 32 {
		t.Errorf("StateRoot length should be 32, got %d", len(header.StateRoot))
	}
	if len(header.BlockHash) != 32 {
		t.Errorf("BlockHash length should be 32, got %d", len(header.BlockHash))
	}
	if header.BlockNumber == 0 {
		t.Error("BlockNumber should not be 0")
	}
	if header.Timestamp == 0 {
		t.Error("Timestamp should not be 0")
	}
}

func TestGetSyncCommitteesInPeriod(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block to determine current period
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	t.Logf("Testing getSyncCommitteesInPeriod: version=%s", block.Version)

	slot := uint64(block.Data.Message.Slot)
	epoch := pr.computeEpoch(slot)
	period := pr.computeSyncCommitteePeriod(epoch)

	t.Logf("Testing getSyncCommitteesInPeriod: slot=%d, epoch=%d, period=%d", slot, epoch, period)

	currentSC, nextSC, err := pr.getSyncCommitteesInPeriod(ctx, period)
	if err != nil {
		t.Fatalf("getSyncCommitteesInPeriod failed: %v", err)
	}

	if currentSC == nil {
		t.Error("Current sync committee should not be nil")
	} else {
		t.Logf("Current sync committee pubkeys count: %d", len(currentSC.Pubkeys))
	}

	if nextSC == nil {
		t.Error("Next sync committee should not be nil")
	} else {
		t.Logf("Next sync committee pubkeys count: %d", len(nextSC.Pubkeys))
	}
}

func TestGetBootstrapInPeriod(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block to determine current period
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	t.Logf("Testing getBootstrapInPeriod: version=%s", block.Version)

	slot := uint64(block.Data.Message.Slot)
	epoch := pr.computeEpoch(slot)
	period := pr.computeSyncCommitteePeriod(epoch)

	t.Logf("Testing getBootstrapInPeriod: slot=%d, epoch=%d, period=%d", slot, epoch, period)

	syncCommittee, err := pr.getBootstrapInPeriod(ctx, period)
	if err != nil {
		t.Fatalf("getBootstrapInPeriod failed: %v", err)
	}

	if syncCommittee == nil {
		t.Fatal("Sync committee should not be nil")
	}

	t.Logf("Sync committee pubkeys count: %d", len(syncCommittee.Pubkeys))

	if len(syncCommittee.Pubkeys) == 0 {
		t.Error("Sync committee should have pubkeys")
	}
	if len(syncCommittee.AggregatePubkey) == 0 {
		t.Error("Sync committee should have aggregate pubkey")
	}
}

// TestSSZParsing tests if SSZ can be parsed correctly
func TestSSZParsing(t *testing.T) {
	pr := newTestProver(t)
	ctx := context.Background()

	// Get finalized block
	block, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		t.Skipf("Beacon API not available: %v", err)
	}

	slot := uint64(block.Data.Message.Slot)
	t.Logf("Block version: %s, slot: %d", block.Version, slot)

	// Get fork spec
	forkSpec := pr.getForkSpecForSlot(slot)
	t.Logf("ForkSpec: FinalizedRootGindex=%d", forkSpec.FinalizedRootGindex)

	// Get SSZ data
	blockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, "finalized")
	if err != nil {
		t.Fatalf("Failed to get block SSZ: %v", err)
	}
	t.Logf("Block SSZ size: %d bytes", len(blockSSZ))

	// Parse block SSZ
	parsed, err := ParseBeaconBlockSSZ(blockSSZ, block.Version, forkSpec)
	if err != nil {
		t.Fatalf("ParseBeaconBlockSSZ failed: %v", err)
	}
	t.Logf("Successfully parsed block: slot=%d, proposer_index=%d", parsed.Slot, parsed.ProposerIndex)

	// Validate parsed block data
	if parsed.Slot != slot {
		t.Errorf("Parsed slot %d doesn't match expected slot %d", parsed.Slot, slot)
	}
	if len(parsed.ParentRoot) != 32 {
		t.Errorf("ParentRoot length should be 32, got %d", len(parsed.ParentRoot))
	}
	if len(parsed.StateRoot) != 32 {
		t.Errorf("StateRoot length should be 32, got %d", len(parsed.StateRoot))
	}
	if len(parsed.BodyRoot) != 32 {
		t.Errorf("BodyRoot length should be 32, got %d", len(parsed.BodyRoot))
	}
	if len(parsed.ExecutionRoot) != 32 {
		t.Errorf("ExecutionRoot length should be 32, got %d", len(parsed.ExecutionRoot))
	}
	if parsed.ExecutionPayload == nil {
		t.Error("ExecutionPayload should not be nil")
	}
	if parsed.SyncAggregate == nil {
		t.Error("SyncAggregate should not be nil")
	}
}
