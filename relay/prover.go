package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/codec"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/ethereum-ibc-relay-chain/pkg/client"
	"github.com/datachainlab/ethereum-ibc-relay-prover/beacon"
	lctypes "github.com/datachainlab/ethereum-ibc-relay-prover/light-clients/ethereum/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	fastssz "github.com/prysmaticlabs/fastssz"
)

var IBCCommitmentsSlot = common.HexToHash("1ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900")

type Prover struct {
	chain           core.Chain
	config          ProverConfig
	ibcAddress      common.Address
	executionClient *client.ETHClient
	beaconClient    beacon.Client
	codec           codec.ProtoCodecMarshaler
}

func NewProver(chain core.Chain, config ProverConfig, ibcAddress common.Address, executionClient *client.ETHClient) *Prover {
	beaconClient := beacon.NewClient(config.BeaconEndpoint)
	return &Prover{
		chain:           chain,
		config:          config,
		ibcAddress:      ibcAddress,
		executionClient: executionClient,
		beaconClient:    beaconClient,
	}
}

func (pr *Prover) GetLogger() *log.RelayLogger {
	return log.GetLogger().WithChain(pr.chain.ChainID()).WithModule(ModuleName)
}

//--------- Prover implementation ---------//

var _ core.Prover = (*Prover)(nil)

// Init initializes the chain
func (pr *Prover) Init(homePath string, timeout time.Duration, codec codec.ProtoCodecMarshaler, debug bool) error {
	pr.codec = codec
	return nil
}

// SetRelayInfo sets source's path and counterparty's info to the chain
func (pr *Prover) SetRelayInfo(path *core.PathEnd, counterparty *core.ProvableChain, counterpartyPath *core.PathEnd) error {
	return nil
}

// SetupForRelay performs chain-specific setup before starting the relay
func (pr *Prover) SetupForRelay(ctx context.Context) error {
	return nil
}

//--------- LightClient implementation ---------//

type InitialState struct {
	Genesis              beacon.Genesis
	Slot                 uint64
	BlockNumber          uint64
	AccountStorageRoot   [32]byte
	Timestamp            time.Time
	CurrentSyncCommittee lctypes.SyncCommittee
	NextSyncCommittee    lctypes.SyncCommittee
}

// CreateInitialLightClientState returns a pair of ClientState and ConsensusState based on the state of the self chain at `height`.
// These states will be submitted to the counterparty chain as MsgCreateClient.
// If `height` is nil, the latest finalized height is selected automatically.
func (pr *Prover) CreateInitialLightClientState(ctx context.Context, height ibcexported.Height) (ibcexported.ClientState, ibcexported.ConsensusState, error) {
	if height == nil {
		height = pr.newHeight(0)
	}
	initialState, err := pr.buildInitialState(ctx, height.GetRevisionHeight())
	if err != nil {
		return nil, nil, err
	}
	pr.GetLogger().DebugContext(ctx, "InitialState", "initial_state", initialState)
	committeeSize := len(initialState.CurrentSyncCommittee.Pubkeys)
	if pr.config.IsMainnetPreset() {
		if committeeSize != MAINNET_PRESET_SYNC_COMMITTEE_SIZE {
			return nil, nil, fmt.Errorf("the size of current sync committee is not %v: actual=%v", MAINNET_PRESET_SYNC_COMMITTEE_SIZE, committeeSize)
		}
	} else {
		if committeeSize != MINIMAL_PRESET_SYNC_COMMITTEE_SIZE {
			return nil, nil, fmt.Errorf("the size of current sync committee is not %v: actual=%v", MINIMAL_PRESET_SYNC_COMMITTEE_SIZE, committeeSize)
		}
	}
	clientState := pr.buildClientState(
		initialState.Genesis.GenesisValidatorsRoot[:],
		initialState.Genesis.GenesisTimeSeconds,
		initialState.BlockNumber,
	)
	consensusState := &lctypes.ConsensusState{
		Slot:                 initialState.Slot,
		StorageRoot:          initialState.AccountStorageRoot[:],
		Timestamp:            initialState.Timestamp,
		CurrentSyncCommittee: initialState.CurrentSyncCommittee.AggregatePubkey,
		NextSyncCommittee:    initialState.NextSyncCommittee.AggregatePubkey,
	}
	return clientState, consensusState, nil
}

// SetupHeadersForUpdate returns the finalized header and any intermediate headers needed to apply it to the client on the counterparty chain
// The order of the returned header slice should be as: [<intermediate headers>..., <update header>]
// if the header slice's length == 0 and err == nil, the relayer should skip the update-client
func (pr *Prover) SetupHeadersForUpdate(ctx context.Context, counterparty core.FinalityAwareChain, latestFinalizedHeader core.Header) (<-chan *core.HeaderOrError, error) {
	lfh, ok := latestFinalizedHeader.(*lctypes.Header)
	if !ok {
		return nil, fmt.Errorf("unexpected header type: %T", latestFinalizedHeader)
	}
	if err := lfh.ValidateBasic(); err != nil {
		return nil, err
	}

	latestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return nil, err
	}

	pr.GetLogger().DebugContext(ctx, "query the latest height of the counterparty chain", "latest_height", latestHeight)

	// retrieve the client state from the counterparty chain
	counterpartyClientRes, err := counterparty.QueryClientState(core.NewQueryContext(ctx, latestHeight))
	if err != nil {
		return nil, err
	}
	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(counterpartyClientRes.ClientState, &cs); err != nil {
		return nil, fmt.Errorf("failed to unpack Any into client state: %v", err)
	}

	if cs.GetLatestHeight().GetRevisionHeight() == lfh.ExecutionUpdate.BlockNumber {
		return core.MakeHeaderStream(), nil
	} else if cs.GetLatestHeight().GetRevisionHeight() > lfh.ExecutionUpdate.BlockNumber {
		return nil, fmt.Errorf("the latest finalized header is older than the latest height of client state: finalized_block_number=%v client_latest_height=%v", lfh.ExecutionUpdate.BlockNumber, cs.GetLatestHeight().GetRevisionHeight())
	}

	statePeriod, err := pr.getPeriodWithBlockNumber(ctx, cs.GetLatestHeight().GetRevisionHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get period with block number: block_number=%v %v", cs.GetLatestHeight().GetRevisionHeight(), err)
	}
	latestPeriod := pr.computeSyncCommitteePeriod(pr.computeEpoch(lfh.ConsensusUpdate.SignatureSlot))

	pr.GetLogger().DebugContext(ctx, "try to setup headers for updating the light-client", "lc_latest_height", cs.GetLatestHeight(), "lc_latest_height_period", statePeriod, "latest_period", latestPeriod)

	if statePeriod == latestPeriod {
		latestHeight := cs.GetLatestHeight().(clienttypes.Height)
		// Get current sync committee for the period
		currentSyncCommittee, err := pr.getBootstrapInPeriod(ctx, statePeriod)
		if err != nil {
			return nil, fmt.Errorf("failed to get bootstrap in period: state_period=%v %v", statePeriod, err)
		}
		lfh.TrustedSyncCommittee = &lctypes.TrustedSyncCommittee{
			TrustedHeight: &latestHeight,
			SyncCommittee: currentSyncCommittee,
			IsNext:        false,
		}
		return core.MakeHeaderStream(lfh), nil
	} else if statePeriod > latestPeriod {
		return nil, fmt.Errorf("the light-client server's response is old: client_state_period=%v latest_finalized_period=%v", statePeriod, latestPeriod)
	}

	//--------- In case statePeriod < latestPeriod ---------//

	var (
		headers                     []core.Header
		trustedNextSyncCommittee    *lctypes.SyncCommittee
		trustedCurrentSyncCommittee *lctypes.SyncCommittee
		trustedHeight               = cs.GetLatestHeight().(clienttypes.Height)
	)
	pr.GetLogger().DebugContext(ctx, "setup headers for updating the light-client", "state_period", statePeriod, "latest_period", latestPeriod, "client_state_latest_height", cs.GetLatestHeight().GetRevisionHeight())
	// Get next sync committee for the state period
	_, trustedNextSyncCommittee, err = pr.getSyncCommitteesInPeriod(ctx, statePeriod)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync committees in period: state_period=%v %v", statePeriod, err)
	}
	for p := statePeriod + 1; p <= latestPeriod; p++ {
		header, err := pr.buildNextSyncCommitteeUpdate(ctx, p, trustedHeight, trustedNextSyncCommittee)
		if err != nil {
			return nil, fmt.Errorf("failed to build next sync committee update for next: period=%v trusted_height=%v %v", p, trustedHeight, err)
		}
		pr.GetLogger().DebugContext(ctx, "setup intermediate header for updating the light-client", "period", p, "trusted_height", header.TrustedSyncCommittee.TrustedHeight, "trusted_sync_committee", fmt.Sprintf("0x%x", header.TrustedSyncCommittee.SyncCommittee.AggregatePubkey), "is_next", header.TrustedSyncCommittee.IsNext, "untrusted_execution_block_number", header.ExecutionUpdate.BlockNumber, "next_sync_committee", fmt.Sprintf("0x%x", header.ConsensusUpdate.NextSyncCommittee.AggregatePubkey))
		trustedHeight = clienttypes.NewHeight(0, header.ExecutionUpdate.BlockNumber)
		trustedCurrentSyncCommittee = trustedNextSyncCommittee
		trustedNextSyncCommittee = header.ConsensusUpdate.NextSyncCommittee
		headers = append(headers, header)
	}
	if trustedCurrentSyncCommittee == nil { // never happen
		panic(fmt.Errorf("trusted current sync committee must not be nil: period=%v", statePeriod))
	}
	if trustedHeight.GT(lfh.GetHeight()) {
		return nil, fmt.Errorf("the latest finalized header is older than the trusted height: finalized_block_number=%v trusted_block_number=%v", lfh.GetHeight().GetRevisionHeight(), trustedHeight.GetRevisionHeight())
	} else if trustedHeight.EQ(lfh.GetHeight()) {
		pr.GetLogger().DebugContext(ctx, "the latest finalized header is the same as the trusted height", "finalized_block_number", lfh.GetHeight().GetRevisionHeight(), "trusted_block_number", trustedHeight.GetRevisionHeight())
		return core.MakeHeaderStream(headers...), nil
	}
	lfh.TrustedSyncCommittee = &lctypes.TrustedSyncCommittee{
		TrustedHeight: &trustedHeight,
		SyncCommittee: trustedCurrentSyncCommittee,
		IsNext:        false,
	}
	headers = append(headers, lfh)
	return core.MakeHeaderStream(headers...), nil
}

// if `blockNumber` is 0, the latest block number is used
func (pr *Prover) buildInitialState(ctx context.Context, blockNumber uint64) (*InitialState, error) {
	// 1. Get finalized block to determine block number
	finalizedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %v", err)
	}
	finalizedSlot := uint64(finalizedBlock.Data.Message.Slot)
	finalizedBlockNumber := uint64(finalizedBlock.Data.Message.Body.ExecutionPayload.BlockNumber)

	if blockNumber == 0 {
		blockNumber = finalizedBlockNumber
	} else if finalizedBlockNumber < blockNumber {
		return nil, fmt.Errorf("the height is not finalized yet: blockNumber=%v finalized_block_number=%v", blockNumber, finalizedBlockNumber)
	}

	timestamp, err := pr.chain.Timestamp(ctx, pr.newHeight(int64(blockNumber)))
	if err != nil {
		return nil, fmt.Errorf("failed to get timestamp: %v", err)
	}
	if truncatedTm := timestamp.Truncate(time.Second); truncatedTm != timestamp {
		return nil, fmt.Errorf("ethereum timestamp must be truncated to seconds: timestamp=%v truncated_timestamp=%v", timestamp, truncatedTm)
	}

	slot, err := pr.getSlotAtTimestamp(ctx, uint64(timestamp.Unix()))
	if err != nil {
		return nil, fmt.Errorf("failed to compute slot at timestamp: %v", err)
	}

	period := pr.computeSyncCommitteePeriod(pr.computeEpoch(slot))

	pr.GetLogger().InfoContext(ctx, "build initial state", "slot", slot, "block_number", blockNumber, "period", period)

	// 2. Get sync committees from state
	currentSyncCommittee, nextSyncCommittee, err := pr.getSyncCommitteesFromState(ctx, finalizedSlot, finalizedBlock.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync committees from state: %v", err)
	}

	accountUpdate, err := pr.buildAccountUpdate(ctx, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to build account update: %v", err)
	}
	var accountStorageRoot [32]byte
	copy(accountStorageRoot[:], accountUpdate.AccountStorageRoot)

	genesis, err := pr.beaconClient.GetGenesis(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get genesis: %v", err)
	}

	return &InitialState{
		Genesis:              *genesis,
		Slot:                 slot,
		BlockNumber:          blockNumber,
		AccountStorageRoot:   accountStorageRoot,
		Timestamp:            timestamp,
		CurrentSyncCommittee: *currentSyncCommittee,
		NextSyncCommittee:    *nextSyncCommittee,
	}, nil
}

// GetLatestFinalizedHeader returns the latest finalized header on this chain
// The returned header is expected to be the latest one of headers that can be verified by the light client
func (pr *Prover) GetLatestFinalizedHeader(ctx context.Context) (headers core.Header, err error) {
	lcUpdate, executionHeader, err := pr.buildConsensusUpdateFromBeaconAPI(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build consensus update: %w", err)
	}

	executionUpdate, err := pr.buildExecutionUpdate(executionHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to build execution update: %v", err)
	}

	accountUpdate, err := pr.buildAccountUpdate(ctx, executionHeader.BlockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to build account update: %v", err)
	}
	pr.GetLogger().InfoContext(ctx, "build latest finalized header", "block_number", executionHeader.BlockNumber, "timestamp", executionHeader.Timestamp, "state_root", hex.EncodeToString(executionHeader.StateRoot))
	return &lctypes.Header{
		ConsensusUpdate: lcUpdate,
		ExecutionUpdate: executionUpdate,
		AccountUpdate:   accountUpdate,
		Timestamp:       executionHeader.Timestamp,
	}, nil
}

func (pr *Prover) CheckRefreshRequired(ctx context.Context, counterparty core.ChainInfoICS02Querier) (bool, error) {
	cpQueryHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get the latest height of the counterparty chain: %v", err)
	}
	cpQueryCtx := core.NewQueryContext(ctx, cpQueryHeight)

	resCs, err := counterparty.QueryClientState(cpQueryCtx)
	if err != nil {
		return false, fmt.Errorf("failed to query the client state on the counterparty chain: %v", err)
	}

	var cs ibcexported.ClientState
	if err := pr.codec.UnpackAny(resCs.ClientState, &cs); err != nil {
		return false, fmt.Errorf("failed to unpack Any into tendermint client state: %v", err)
	}

	resCons, err := counterparty.QueryClientConsensusState(cpQueryCtx, cs.GetLatestHeight())
	if err != nil {
		return false, fmt.Errorf("failed to query the consensus state on the counterparty chain: %v", err)
	}

	var cons ibcexported.ConsensusState
	if err := pr.codec.UnpackAny(resCons.ConsensusState, &cons); err != nil {
		return false, fmt.Errorf("failed to unpack Any into tendermint consensus state: %v", err)
	}
	lcLastTimestamp := time.Unix(0, int64(cons.GetTimestamp()))

	selfQueryHeight, err := pr.chain.LatestHeight(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get the latest height of the self chain: %v", err)
	}

	selfTimestamp, err := pr.chain.Timestamp(ctx, selfQueryHeight)
	if err != nil {
		return false, fmt.Errorf("failed to get timestamp of the self chain: %v", err)
	}

	elapsedTime := selfTimestamp.Sub(lcLastTimestamp)

	durationMulByFraction := func(d time.Duration, f *Fraction) time.Duration {
		nsec := d.Nanoseconds() * int64(f.Numerator) / int64(f.Denominator)
		return time.Duration(nsec) * time.Nanosecond
	}
	needsRefresh := elapsedTime > durationMulByFraction(pr.config.GetTrustingPeriod(), pr.config.RefreshThresholdRate)

	return needsRefresh, nil
}

func (pr *Prover) buildClientState(
	genesisValidatorsRoot []byte,
	genesisTime uint64,
	latestExecutionBlockNumber uint64,
) *lctypes.ClientState {
	return &lctypes.ClientState{
		GenesisValidatorsRoot:        genesisValidatorsRoot,
		MinSyncCommitteeParticipants: 1,
		GenesisTime:                  genesisTime,

		ForkParameters:               pr.config.getForkParameters(),
		SecondsPerSlot:               pr.secondsPerSlot(),
		SlotsPerEpoch:                pr.slotsPerEpoch(),
		EpochsPerSyncCommitteePeriod: pr.epochsPerSyncCommitteePeriod(),

		IbcAddress:         pr.ibcAddress.Bytes(),
		IbcCommitmentsSlot: IBCCommitmentsSlot[:],
		TrustLevel: &lctypes.Fraction{
			Numerator:   2,
			Denominator: 3,
		},
		TrustingPeriod: pr.config.GetTrustingPeriod(),
		MaxClockDrift:  pr.config.GetMaxClockDrift(),

		LatestExecutionBlockNumber: latestExecutionBlockNumber,

		FrozenHeight: nil,
	}
}

func (pr *Prover) getBootstrapInPeriod(ctx context.Context, period uint64) (*lctypes.SyncCommittee, error) {
	currentSyncCommittee, _, err := pr.getSyncCommitteesInPeriod(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrap in period: %w", err)
	}
	return currentSyncCommittee, nil
}

func (pr *Prover) buildNextSyncCommitteeUpdate(ctx context.Context, period uint64, trustedHeight clienttypes.Height, trustedNextSyncCommittee *lctypes.SyncCommittee) (*lctypes.Header, error) {
	// Build consensus update with next_sync_committee using standard Beacon API
	lcUpdate, executionHeader, err := pr.buildConsensusUpdateForPeriod(ctx, period)
	if err != nil {
		return nil, fmt.Errorf("failed to build consensus update for period %d: %w", period, err)
	}

	executionUpdate, err := pr.buildExecutionUpdate(executionHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to build execution update: %v", err)
	}

	accountUpdate, err := pr.buildAccountUpdate(ctx, executionHeader.BlockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to build account update: %v", err)
	}

	return &lctypes.Header{
		TrustedSyncCommittee: &lctypes.TrustedSyncCommittee{
			TrustedHeight: &trustedHeight,
			SyncCommittee: trustedNextSyncCommittee,
			IsNext:        true,
		},
		ConsensusUpdate: lcUpdate,
		ExecutionUpdate: executionUpdate,
		AccountUpdate:   accountUpdate,
		Timestamp:       executionHeader.Timestamp,
	}, nil
}

//--------- StateProver implementation ---------//

var _ core.StateProver = (*Prover)(nil)

// ProveState returns the proof of an IBC state specified by `path` and `value`
func (pr *Prover) ProveState(ctx core.QueryContext, path string, value []byte) ([]byte, clienttypes.Height, error) {
	proofHeight := int64(ctx.Height().GetRevisionHeight())
	height := pr.newHeight(proofHeight)
	proof, err := pr.buildStateProof(ctx.Context(), []byte(path), proofHeight)
	return proof, height, err
}

// ProveHostConsensusState returns an existence proof of the consensus state at `height`
// This proof would be ignored in ibc-go, but it is required to `getSelfConsensusState` of ibc-solidity.
func (pr *Prover) ProveHostConsensusState(ctx core.QueryContext, height ibcexported.Height, consensusState ibcexported.ConsensusState) (proof []byte, err error) {
	return clienttypes.MarshalConsensusState(pr.codec, consensusState)
}

func (pr *Prover) newHeight(blockNumber int64) clienttypes.Height {
	return clienttypes.NewHeight(0, uint64(blockNumber))
}

// getForkSpecForSlot returns the ForkSpec applicable for the given slot
func (pr *Prover) getForkSpecForSlot(slot uint64) *lctypes.ForkSpec {
	epoch := pr.computeEpoch(slot)
	forkParams := pr.config.getForkParameters()

	// Find the applicable fork (latest fork with epoch <= current epoch)
	var spec *lctypes.ForkSpec
	for _, fork := range forkParams.Forks {
		if fork.Epoch <= epoch {
			spec = fork.Spec
		}
	}
	return spec
}

// findSignatureAndAttestedSlot finds the earliest signature slot and attested slot for a given finalized block.
// According to the Ethereum Light Client spec:
// - attested_block: The first block after finalized_block whose state has finalized_checkpoint.root == hash(finalized_block)
// - signature_block: The child of attested_block (contains sync_aggregate signing attested_block)
// Returns (signatureSlot, attestedSlot, error)
func (pr *Prover) findSignatureAndAttestedSlot(ctx context.Context, finalizedBlockRoot []byte, finalizedSlot uint64) (signatureSlot uint64, attestedSlot uint64, err error) {
	// Search for the earliest attested block after finalized_slot
	// The attested block's state must have finalized_checkpoint.root == finalizedBlockRoot
	slotsPerEpoch := pr.slotsPerEpoch()
	maxSearchSlots := slotsPerEpoch * 2 // Search up to 2 epochs

	// Log search parameters for debugging
	pr.GetLogger().DebugContext(ctx, "searching for signature and attested slots",
		"finalized_slot", finalizedSlot,
		"finalized_block_root", fmt.Sprintf("0x%x", finalizedBlockRoot),
		"slots_per_epoch", slotsPerEpoch,
		"max_search_slots", maxSearchSlots)

	var attestedBlockRootHex string

	for offset := uint64(1); offset <= maxSearchSlots; offset++ {
		candidateSlot := finalizedSlot + offset

		// Check if a block exists at this slot
		_, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", candidateSlot))
		if err != nil {
			// No block at this slot (skipped), continue
			continue
		}

		// Check if this block's state has finalized_checkpoint matching our finalized block
		checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", candidateSlot))
		if err != nil {
			pr.GetLogger().DebugContext(ctx, "failed to get finality checkpoints", "slot", candidateSlot, "err", err)
			continue
		}

		// Compare finalized checkpoint root with our finalized block root
		checkpointRoot := checkpoints.Finalized.Root[:]
		if bytesEqual(checkpointRoot, finalizedBlockRoot) {
			// Found the attested block
			attestedSlot = candidateSlot

			// Get the block root for the attested block
			blockRootRes, err := pr.beaconClient.GetBlockRootByID(ctx, fmt.Sprintf("%d", candidateSlot), true)
			if err != nil {
				return 0, 0, fmt.Errorf("failed to get block root for attested slot %d: %w", candidateSlot, err)
			}
			attestedBlockRootHex = blockRootRes.Data.Root.String()

			pr.GetLogger().DebugContext(ctx, "found attested block",
				"attested_slot", attestedSlot,
				"attested_block_root", attestedBlockRootHex,
				"finalized_checkpoint_root", fmt.Sprintf("0x%x", checkpointRoot))
			break
		}
	}

	if attestedSlot == 0 {
		return 0, 0, fmt.Errorf("attested block not found within %d slots after finalized slot %d", maxSearchSlots, finalizedSlot)
	}

	// Now find the signature block (the child of attested block)
	// The signature block's parent_root must equal the attested block's root
	// Wait for the chain to advance if necessary
	requiredSlot := attestedSlot + slotsPerEpoch
	maxWaitAttempts := 30 // Max ~3 minutes with 6 second intervals

	for attempt := 0; attempt < maxWaitAttempts; attempt++ {
		// Check current head slot
		headBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "head")
		if err != nil {
			return 0, 0, fmt.Errorf("failed to get head block: %w", err)
		}
		headSlot := uint64(headBlock.Data.Message.Slot)

		pr.GetLogger().DebugContext(ctx, "checking chain progress",
			"head_slot", headSlot,
			"attested_slot", attestedSlot,
			"required_slot", requiredSlot,
			"attempt", attempt)

		// Search for signature block in available slots
		for offset := uint64(1); offset <= slotsPerEpoch; offset++ {
			candidateSlot := attestedSlot + offset

			// Don't search beyond head slot
			if candidateSlot > headSlot {
				break
			}

			block, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", candidateSlot))
			if err != nil {
				// No block at this slot, continue
				continue
			}

			// Check if this block's parent is the attested block
			parentRootHex := block.Data.Message.ParentRoot.String()
			if parentRootHex == attestedBlockRootHex {
				signatureSlot = candidateSlot
				pr.GetLogger().DebugContext(ctx, "found signature block",
					"signature_slot", signatureSlot,
					"attested_slot", attestedSlot,
					"parent_root", parentRootHex)
				return signatureSlot, attestedSlot, nil
			}
		}

		// If head slot is beyond our search range and we still haven't found the signature block,
		// it means the attested block is not on the canonical chain (shouldn't happen normally)
		if headSlot >= requiredSlot {
			return 0, 0, fmt.Errorf("signature block not found within %d slots after attested slot %d (head: %d, expected parent: %s)", slotsPerEpoch, attestedSlot, headSlot, attestedBlockRootHex)
		}

		// Wait for more blocks to be produced
		pr.GetLogger().DebugContext(ctx, "waiting for chain to advance",
			"head_slot", headSlot,
			"required_slot", requiredSlot)
		time.Sleep(time.Duration(pr.secondsPerSlot()) * time.Second)
	}

	return 0, 0, fmt.Errorf("timeout waiting for signature block after attested slot %d", attestedSlot)
}

// bytesEqual compares two byte slices for equality
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// buildConsensusUpdateFromBeaconAPI builds ConsensusUpdate using standard Beacon API
func (pr *Prover) buildConsensusUpdateFromBeaconAPI(ctx context.Context, includeNextSyncCommittee bool) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	// 1. Get finalized block
	finalizedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block: %w", err)
	}
	finalizedSlot := uint64(finalizedBlock.Data.Message.Slot)
	pr.GetLogger().DebugContext(ctx, "got finalized block", "slot", finalizedSlot, "version", finalizedBlock.Version)

	// 2. Get finalized block root
	finalizedBlockRoot, err := pr.beaconClient.GetBlockRootByID(ctx, "finalized", true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block root: %w", err)
	}
	pr.GetLogger().DebugContext(ctx, "finalized block root", "root", finalizedBlockRoot.Data.Root.String())

	// 3. Find signature and attested slots
	// These are blocks AFTER finalized that can prove the finalized block is finalized
	signatureSlot, attestedSlot, err := pr.findSignatureAndAttestedSlot(ctx, finalizedBlockRoot.Data.Root, finalizedSlot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find signature and attested slots: %w", err)
	}

	// 4. Build consensus update
	return pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, "finalized", finalizedBlock.Version, includeNextSyncCommittee)
}

// getSyncCommitteesFromState retrieves current and next sync committees from beacon state
func (pr *Prover) getSyncCommitteesFromState(ctx context.Context, slot uint64, version string) (*lctypes.SyncCommittee, *lctypes.SyncCommittee, error) {
	forkSpec := pr.getForkSpecForSlot(slot)
	if forkSpec == nil {
		return nil, nil, fmt.Errorf("no fork spec found for slot %d", slot)
	}

	stateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", slot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get beacon state SSZ: %w", err)
	}

	parsedState, err := ParseBeaconStateSSZ(stateSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse beacon state SSZ: %w", err)
	}

	return parsedState.SyncCommittee, parsedState.NextSyncCommittee, nil
}

// buildConsensusUpdateForPeriod builds a ConsensusUpdate for a specific period with next_sync_committee
func (pr *Prover) buildConsensusUpdateForPeriod(ctx context.Context, period uint64) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	// Get finalized block to determine current state
	finalizedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block: %w", err)
	}
	currentFinalizedSlot := uint64(finalizedBlock.Data.Message.Slot)
	currentFinalizedPeriod := pr.computeSyncCommitteePeriod(pr.computeEpoch(currentFinalizedSlot))

	pr.GetLogger().DebugContext(ctx, "building consensus update for period",
		"target_period", period,
		"current_finalized_slot", currentFinalizedSlot,
		"current_finalized_period", currentFinalizedPeriod)

	// For period updates, we need to find a state where:
	// 1. The attested block is from the target period (so we can prove next_sync_committee)
	// 2. The finalized block should be as recent as possible (ideally from target period or later)
	//
	// Strategy: Search backwards from the end of period+1 to find a state where
	// finalized_checkpoint points to a block in the target period

	periodStartSlot := pr.getPeriodBoundarySlot(period)
	periodEndSlot := pr.getPeriodBoundarySlot(period+1) - 1

	// Search from the end of the next period backwards
	searchEndSlot := pr.getPeriodBoundarySlot(period + 2)
	if searchEndSlot > currentFinalizedSlot+pr.slotsPerEpoch() {
		searchEndSlot = currentFinalizedSlot + pr.slotsPerEpoch()
	}

	var bestFinalizedRoot []byte
	var bestFinalizedSlot uint64
	var bestVersion string

	// Search for a state that has finalized a block within the target period
	for searchSlot := searchEndSlot; searchSlot > periodEndSlot; searchSlot-- {
		block, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", searchSlot))
		if err != nil {
			continue
		}

		checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", searchSlot))
		if err != nil {
			continue
		}

		// Check if the finalized checkpoint is in the target period or later
		finalizedEpoch := checkpoints.Finalized.Epoch
		finalizedPeriod := pr.computeSyncCommitteePeriod(finalizedEpoch)

		if finalizedPeriod >= period {
			// Get the actual finalized slot
			finalizedBlockId := fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:])
			finalizedBlockData, err := pr.beaconClient.GetBeaconBlock(ctx, finalizedBlockId)
			if err != nil {
				continue
			}
			finalizedSlotCandidate := uint64(finalizedBlockData.Data.Message.Slot)

			// Check if this is better than what we have
			if bestFinalizedSlot == 0 || finalizedSlotCandidate > bestFinalizedSlot {
				bestFinalizedRoot = checkpoints.Finalized.Root[:]
				bestFinalizedSlot = finalizedSlotCandidate
				bestVersion = block.Version

				pr.GetLogger().DebugContext(ctx, "found candidate finalized block",
					"search_slot", searchSlot,
					"finalized_slot", finalizedSlotCandidate,
					"finalized_epoch", finalizedEpoch,
					"finalized_period", finalizedPeriod)

				// If finalized slot is in the target period, we found a good one
				if finalizedSlotCandidate >= periodStartSlot && finalizedSlotCandidate <= periodEndSlot {
					break
				}
			}
		}
	}

	if bestFinalizedRoot == nil {
		return nil, nil, fmt.Errorf("could not find suitable finalized block for period %d", period)
	}

	pr.GetLogger().DebugContext(ctx, "using finalized block for period",
		"period", period,
		"finalized_slot", bestFinalizedSlot,
		"finalized_epoch", pr.computeEpoch(bestFinalizedSlot))

	// Find signature and attested slots using the selected finalized block
	signatureSlot, attestedSlot, err := pr.findSignatureAndAttestedSlot(ctx, bestFinalizedRoot, bestFinalizedSlot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find signature and attested slots: %w", err)
	}

	// Build consensus update using the explicit slots
	finalizedBlockId := fmt.Sprintf("0x%x", bestFinalizedRoot)
	return pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, finalizedBlockId, bestVersion, true)
}

// buildConsensusUpdateCore is the common implementation for building ConsensusUpdate
// signatureSlot is the slot of the block containing sync_aggregate
// The attested block is the PARENT of the signature block (sync_aggregate signs the parent)
func (pr *Prover) buildConsensusUpdateCore(ctx context.Context, signatureSlot uint64, finalizedBlockId string, version string, includeNextSyncCommittee bool) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	forkSpec := pr.getForkSpecForSlot(signatureSlot)
	if forkSpec == nil {
		return nil, nil, fmt.Errorf("no fork spec found for slot %d", signatureSlot)
	}

	// Get signature block SSZ (contains sync_aggregate that signs its parent)
	signatureBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", signatureSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature block SSZ: %w", err)
	}

	parsedSignatureBlock, err := ParseBeaconBlockSSZ(signatureBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signature block SSZ: %w", err)
	}

	// Get the attested block (parent of signature block)
	// The sync_aggregate in signature block signs this parent block
	attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("0x%x", parsedSignatureBlock.ParentRoot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block SSZ (parent of signature block): %w", err)
	}

	parsedAttestedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested block SSZ: %w", err)
	}

	// Get attested state SSZ for finality_branch and next_sync_committee_branch generation
	// The state at the attested block contains the finalized_checkpoint
	attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", parsedAttestedBlock.Slot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested state SSZ: %w", err)
	}

	parsedState, err := ParseBeaconStateSSZ(attestedStateSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested state SSZ: %w", err)
	}

	finalityBranch, err := parsedState.GenerateFinalityBranch()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate finality branch: %w", err)
	}

	// Get finalized block SSZ for execution_branch generation
	finalizedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block SSZ: %w", err)
	}

	parsedFinalizedBlock, err := ParseBeaconBlockSSZ(finalizedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse finalized block SSZ: %w", err)
	}

	executionBranch, err := parsedFinalizedBlock.GenerateExecutionPayloadBranch()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate execution branch: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "building consensus update",
		"signature_slot", signatureSlot,
		"attested_slot", parsedAttestedBlock.Slot,
		"finalized_slot", parsedFinalizedBlock.Slot)

	// Build ConsensusUpdate
	// - AttestedHeader: the block that sync_aggregate signs (parent of signature block)
	// - SyncAggregate: from signature block, signs the attested header
	// - SignatureSlot: slot of the signature block
	update := &lctypes.ConsensusUpdate{
		AttestedHeader: &lctypes.BeaconBlockHeader{
			Slot:          parsedAttestedBlock.Slot,
			ProposerIndex: parsedAttestedBlock.ProposerIndex,
			ParentRoot:    parsedAttestedBlock.ParentRoot,
			StateRoot:     parsedAttestedBlock.StateRoot,
			BodyRoot:      parsedAttestedBlock.BodyRoot,
		},
		FinalizedHeader: &lctypes.BeaconBlockHeader{
			Slot:          parsedFinalizedBlock.Slot,
			ProposerIndex: parsedFinalizedBlock.ProposerIndex,
			ParentRoot:    parsedFinalizedBlock.ParentRoot,
			StateRoot:     parsedFinalizedBlock.StateRoot,
			BodyRoot:      parsedFinalizedBlock.BodyRoot,
		},
		FinalizedHeaderBranch:    finalityBranch,
		FinalizedExecutionRoot:   parsedFinalizedBlock.ExecutionRoot,
		FinalizedExecutionBranch: executionBranch,
		SyncAggregate:            parsedSignatureBlock.SyncAggregate,
		SignatureSlot:            signatureSlot,
	}

	// Optionally add next sync committee
	if includeNextSyncCommittee {
		update.NextSyncCommittee = parsedState.NextSyncCommittee
		nextSyncCommitteeBranch, err := parsedState.GenerateNextSyncCommitteeBranch()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate next sync committee branch: %w", err)
		}
		update.NextSyncCommitteeBranch = nextSyncCommitteeBranch
	}

	return update, parsedFinalizedBlock.ExecutionPayload, nil
}

// buildConsensusUpdateWithSlots builds ConsensusUpdate with explicitly provided signature and attested slots
func (pr *Prover) buildConsensusUpdateWithSlots(ctx context.Context, signatureSlot, attestedSlot uint64, finalizedBlockId string, version string, includeNextSyncCommittee bool) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	forkSpec := pr.getForkSpecForSlot(signatureSlot)
	if forkSpec == nil {
		return nil, nil, fmt.Errorf("no fork spec found for slot %d", signatureSlot)
	}

	// Get signature block SSZ (contains sync_aggregate that signs the attested block)
	signatureBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", signatureSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature block SSZ: %w", err)
	}

	parsedSignatureBlock, err := ParseBeaconBlockSSZ(signatureBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signature block SSZ: %w", err)
	}

	// Get attested block SSZ directly using the provided slot
	attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block SSZ: %w", err)
	}

	parsedAttestedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested block SSZ: %w", err)
	}

	// Get attested state SSZ for finality_branch and next_sync_committee_branch generation
	attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested state SSZ: %w", err)
	}

	parsedState, err := ParseBeaconStateSSZ(attestedStateSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested state SSZ: %w", err)
	}

	finalityBranch, err := parsedState.GenerateFinalityBranch()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate finality branch: %w", err)
	}

	// Get finalized block SSZ for execution_branch generation
	finalizedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block SSZ: %w", err)
	}

	parsedFinalizedBlock, err := ParseBeaconBlockSSZ(finalizedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse finalized block SSZ: %w", err)
	}

	executionBranch, err := parsedFinalizedBlock.GenerateExecutionPayloadBranch()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate execution branch: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "building consensus update with slots",
		"signature_slot", signatureSlot,
		"attested_slot", attestedSlot,
		"finalized_slot", parsedFinalizedBlock.Slot)

	// Build ConsensusUpdate
	update := &lctypes.ConsensusUpdate{
		AttestedHeader: &lctypes.BeaconBlockHeader{
			Slot:          parsedAttestedBlock.Slot,
			ProposerIndex: parsedAttestedBlock.ProposerIndex,
			ParentRoot:    parsedAttestedBlock.ParentRoot,
			StateRoot:     parsedAttestedBlock.StateRoot,
			BodyRoot:      parsedAttestedBlock.BodyRoot,
		},
		FinalizedHeader: &lctypes.BeaconBlockHeader{
			Slot:          parsedFinalizedBlock.Slot,
			ProposerIndex: parsedFinalizedBlock.ProposerIndex,
			ParentRoot:    parsedFinalizedBlock.ParentRoot,
			StateRoot:     parsedFinalizedBlock.StateRoot,
			BodyRoot:      parsedFinalizedBlock.BodyRoot,
		},
		FinalizedHeaderBranch:    finalityBranch,
		FinalizedExecutionRoot:   parsedFinalizedBlock.ExecutionRoot,
		FinalizedExecutionBranch: executionBranch,
		SyncAggregate:            parsedSignatureBlock.SyncAggregate,
		SignatureSlot:            signatureSlot,
	}

	// Optionally add next sync committee
	if includeNextSyncCommittee {
		update.NextSyncCommittee = parsedState.NextSyncCommittee
		nextSyncCommitteeBranch, err := parsedState.GenerateNextSyncCommitteeBranch()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate next sync committee branch: %w", err)
		}
		update.NextSyncCommitteeBranch = nextSyncCommitteeBranch
	}

	// Debug: Compare with Light Client API
	pr.compareWithLightClientAPI(ctx, update, attestedSlot)

	return update, parsedFinalizedBlock.ExecutionPayload, nil
}

// compareWithLightClientAPI compares BeaconState-generated values with Light Client API values
// Uses the SAME finalized slot from LC API to ensure fair comparison
func (pr *Prover) compareWithLightClientAPI(ctx context.Context, update *lctypes.ConsensusUpdate, attestedSlot uint64) {
	logger := pr.GetLogger()

	// Get finality_update from LC API
	lcFinalityUpdate, err := pr.beaconClient.GetLightClientFinalityUpdate(ctx)
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to get Light Client API finality update", "err", err)
		return
	}

	lcAttestedSlot := uint64(lcFinalityUpdate.Data.AttestedHeader.Beacon.Slot)
	lcFinalizedSlot := uint64(lcFinalityUpdate.Data.FinalizedHeader.Beacon.Slot)
	lcSignatureSlot := uint64(lcFinalityUpdate.Data.SignatureSlot)

	logger.InfoContext(ctx, "[DEBUG] ===== CONSENSUS UPDATE COMPARISON =====")
	logger.InfoContext(ctx, "[DEBUG] LC API finality_update",
		"lc_attested_slot", lcAttestedSlot,
		"lc_finalized_slot", lcFinalizedSlot,
		"lc_signature_slot", lcSignatureSlot)

	// Now build BeaconState-based update using the SAME finalized slot from LC API
	// Get finalized block root from LC API
	lcFinalizedRoot := computeBeaconBlockHeaderRootFromLC(&lcFinalityUpdate.Data.FinalizedHeader.Beacon)

	logger.InfoContext(ctx, "[DEBUG] Using LC finalized_root to build BS update",
		"finalized_root", fmt.Sprintf("0x%x", lcFinalizedRoot[:16]))

	// Find signature and attested slots for this finalized block
	bsSignatureSlot, bsAttestedSlot, err := pr.findSignatureAndAttestedSlot(ctx, lcFinalizedRoot, lcFinalizedSlot)
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to find signature/attested slots", "err", err)
		return
	}

	logger.InfoContext(ctx, "[DEBUG] BS computed slots",
		"bs_attested_slot", bsAttestedSlot,
		"bs_signature_slot", bsSignatureSlot)

	// Get fork spec and build BS finality branch
	forkSpec := pr.getForkSpecForSlot(bsAttestedSlot)
	if forkSpec == nil {
		logger.WarnContext(ctx, "[DEBUG] No fork spec for slot", "slot", bsAttestedSlot)
		return
	}

	// Get attested state and generate finality branch
	attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", bsAttestedSlot))
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to get attested state SSZ", "err", err)
		return
	}

	// Get block for version
	attestedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", bsAttestedSlot))
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to get attested block", "err", err)
		return
	}

	parsedState, err := ParseBeaconStateSSZ(attestedStateSSZ, attestedBlock.Version, forkSpec)
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to parse state SSZ", "err", err)
		return
	}

	bsBranch, err := parsedState.GenerateFinalityBranch()
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to generate finality branch", "err", err)
		return
	}

	// Get BS attested state root
	attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, fmt.Sprintf("%d", bsAttestedSlot))
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to get attested block SSZ", "err", err)
		return
	}

	parsedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, attestedBlock.Version, forkSpec)
	if err != nil {
		logger.WarnContext(ctx, "[DEBUG] Failed to parse block SSZ", "err", err)
		return
	}

	// Now compare
	logger.InfoContext(ctx, "[DEBUG] Comparison (same finalized_slot):")
	logger.InfoContext(ctx, "[DEBUG] Attested slots",
		"lc", lcAttestedSlot,
		"bs", bsAttestedSlot,
		"match", lcAttestedSlot == bsAttestedSlot)

	lcStateRoot := []byte(lcFinalityUpdate.Data.AttestedHeader.Beacon.StateRoot)
	bsStateRoot := parsedBlock.StateRoot
	logger.InfoContext(ctx, "[DEBUG] Attested StateRoot",
		"lc", fmt.Sprintf("0x%x", lcStateRoot),
		"bs", fmt.Sprintf("0x%x", bsStateRoot),
		"match", bytesEqual(lcStateRoot, bsStateRoot))

	// Compare finality branch
	logger.InfoContext(ctx, "[DEBUG] Finality Branch comparison:")
	lcBranch := lcFinalityUpdate.Data.FinalityBranch
	logger.InfoContext(ctx, "[DEBUG] Branch lengths", "lc_len", len(lcBranch), "bs_len", len(bsBranch))

	allMatch := true
	minLen := len(lcBranch)
	if len(bsBranch) < minLen {
		minLen = len(bsBranch)
	}
	for i := 0; i < minLen; i++ {
		lcVal := []byte(lcBranch[i])
		bsVal := bsBranch[i]
		match := bytesEqual(lcVal, bsVal)
		if !match {
			allMatch = false
		}
		logger.InfoContext(ctx, fmt.Sprintf("[DEBUG] Branch[%d]", i),
			"lc", fmt.Sprintf("0x%x", lcVal),
			"bs", fmt.Sprintf("0x%x", bsVal),
			"match", match)
	}
	logger.InfoContext(ctx, "[DEBUG] All branch elements match", "result", allMatch)
	logger.InfoContext(ctx, "[DEBUG] ===== END COMPARISON =====")
}

// computeBeaconBlockHeaderRootFromLC computes the hash tree root of a beacon block header from Light Client API
func computeBeaconBlockHeaderRootFromLC(header *beacon.BeaconBlockHeader) []byte {
	root, err := header.HashTreeRoot()
	if err != nil {
		return nil
	}
	return root[:]
}

// computeBeaconBlockHeaderRootFromUpdate computes the hash tree root of a beacon block header from ConsensusUpdate
func computeBeaconBlockHeaderRootFromUpdate(header *lctypes.BeaconBlockHeader) []byte {
	hh := fastssz.NewHasher()
	hh.PutUint64(header.Slot)
	hh.PutUint64(header.ProposerIndex)
	hh.PutBytes(header.ParentRoot)
	hh.PutBytes(header.StateRoot)
	hh.PutBytes(header.BodyRoot)
	hh.MerkleizeWithMixin(0, 5, 8)
	root, _ := hh.HashRoot()
	return root[:]
}

// findValidBlockSlot finds a valid block slot at or before the target slot
func (pr *Prover) findValidBlockSlot(ctx context.Context, targetSlot uint64) (uint64, error) {
	// Try the target slot first
	_, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", targetSlot))
	if err == nil {
		return targetSlot, nil
	}

	// Search backward for a valid block
	for offset := uint64(1); offset <= 32; offset++ {
		if targetSlot < offset {
			break
		}
		candidateSlot := targetSlot - offset
		_, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", candidateSlot))
		if err == nil {
			return candidateSlot, nil
		}
	}

	return 0, fmt.Errorf("no valid block found near slot %d", targetSlot)
}

// getSyncCommitteesInPeriod retrieves current and next sync committees for a specific period
func (pr *Prover) getSyncCommitteesInPeriod(ctx context.Context, period uint64) (*lctypes.SyncCommittee, *lctypes.SyncCommittee, error) {
	slotsPerEpoch := pr.slotsPerEpoch()
	startSlot := pr.getPeriodBoundarySlot(period)
	lastSlotInPeriod := pr.getPeriodBoundarySlot(period+1) - 1
	pr.GetLogger().DebugContext(ctx, "get sync committees in period", "period", period, "start_slot", startSlot, "last_slot_in_period", lastSlotInPeriod)

	var errs []error
	for i := startSlot + slotsPerEpoch; i <= lastSlotInPeriod; i += slotsPerEpoch {
		// Try to get block at this slot to determine version
		block, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", i))
		if err != nil {
			pr.GetLogger().DebugContext(ctx, "failed to get block", "slot", i, "err", err)
			errs = append(errs, err)
			continue
		}

		// Get sync committees from state
		currentSyncCommittee, nextSyncCommittee, err := pr.getSyncCommitteesFromState(ctx, i, block.Version)
		if err != nil {
			pr.GetLogger().WarnContext(ctx, "failed to get sync committees from state", "slot", i, "err", err)
			errs = append(errs, err)
			continue
		}
		return currentSyncCommittee, nextSyncCommittee, nil
	}
	return nil, nil, fmt.Errorf("failed to get sync committees in period: period=%v err=%v", period, errors.Join(errs...))
}
