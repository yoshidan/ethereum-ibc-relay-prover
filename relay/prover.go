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
		headers                  []core.Header
		trustedNextSyncCommittee *lctypes.SyncCommittee
		trustedHeight            = cs.GetLatestHeight().(clienttypes.Height)
	)
	pr.GetLogger().DebugContext(ctx, "setup headers for updating the light-client", "state_period", statePeriod, "latest_period", latestPeriod, "client_state_latest_height", cs.GetLatestHeight().GetRevisionHeight())
	// Get next sync committee for the state period
	_, trustedNextSyncCommittee, err = pr.getSyncCommitteesInPeriod(ctx, statePeriod)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync committees in period: state_period=%v %v", statePeriod, err)
	}
	// Build intermediate headers for periods statePeriod+1 to latestPeriod-1
	// The final lfh in latestPeriod will be verified using trustedNextSyncCommittee with IsNext=true
	for p := statePeriod + 1; p < latestPeriod; p++ {
		header, err := pr.buildNextSyncCommitteeUpdate(ctx, p, trustedHeight, trustedNextSyncCommittee)
		if err != nil {
			return nil, fmt.Errorf("failed to build next sync committee update for next: period=%v trusted_height=%v %v", p, trustedHeight, err)
		}
		pr.GetLogger().DebugContext(ctx, "setup intermediate header for updating the light-client", "period", p, "trusted_height", header.TrustedSyncCommittee.TrustedHeight, "trusted_sync_committee", fmt.Sprintf("0x%x", header.TrustedSyncCommittee.SyncCommittee.AggregatePubkey), "is_next", header.TrustedSyncCommittee.IsNext, "untrusted_execution_block_number", header.ExecutionUpdate.BlockNumber, "next_sync_committee", fmt.Sprintf("0x%x", header.ConsensusUpdate.NextSyncCommittee.AggregatePubkey))
		trustedHeight = clienttypes.NewHeight(0, header.ExecutionUpdate.BlockNumber)
		trustedNextSyncCommittee = header.ConsensusUpdate.NextSyncCommittee
		headers = append(headers, header)
	}
	if trustedHeight.GT(lfh.GetHeight()) {
		return nil, fmt.Errorf("the latest finalized header is older than the trusted height: finalized_block_number=%v trusted_block_number=%v", lfh.GetHeight().GetRevisionHeight(), trustedHeight.GetRevisionHeight())
	} else if trustedHeight.EQ(lfh.GetHeight()) {
		pr.GetLogger().DebugContext(ctx, "the latest finalized header is the same as the trusted height", "finalized_block_number", lfh.GetHeight().GetRevisionHeight(), "trusted_block_number", trustedHeight.GetRevisionHeight())
		return core.MakeHeaderStream(headers...), nil
	}
	// lfh is in latestPeriod, verify using trustedNextSyncCommittee (committee for latestPeriod) with IsNext=true
	lfh.TrustedSyncCommittee = &lctypes.TrustedSyncCommittee{
		TrustedHeight: &trustedHeight,
		SyncCommittee: trustedNextSyncCommittee,
		IsNext:        true,
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
	// Always include next_sync_committee so this header can be used for period updates
	lcUpdate, executionHeader, err := pr.buildConsensusUpdateFromBeaconAPI(ctx, true)
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

// buildConsensusUpdateFromBeaconAPI builds ConsensusUpdate using standard Beacon API
// Following SPEC.md design:
//
//	SignatureBlock (head) → parent_root → AttestedBlock
//	AttestedState → finalized_checkpoint.root → FinalizedBlock
//	AttestedState → next_sync_committee
func (pr *Prover) buildConsensusUpdateFromBeaconAPI(ctx context.Context, includeNextSyncCommittee bool) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	const maxRetries = 10

	// 1. Get head block as starting point
	headBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "head")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get head block: %w", err)
	}

	// 2. Search for a block with sufficient sync committee participation
	signatureSlot := uint64(headBlock.Data.Message.Slot)
	var signatureBlock *beacon.BeaconBlockResponse

	for i := 0; i < maxRetries; i++ {
		block, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", signatureSlot))
		if err != nil {
			signatureSlot--
			continue
		}

		// Check sync committee participation rate (require >= 2/3)
		// Use integer arithmetic to avoid floating point rounding issues
		setBits, totalBits := pr.countSyncCommitteeBits(block.Data.Message.Body.SyncAggregate.SyncCommitteeBits)
		pr.GetLogger().DebugContext(ctx, "checking sync committee participation",
			"slot", signatureSlot,
			"set_bits", setBits,
			"total_bits", totalBits)

		// setBits/totalBits >= 2/3  =>  setBits * 3 >= totalBits * 2
		if setBits*3 >= totalBits*2 {
			signatureBlock = block
			break
		}

		signatureSlot--
	}

	if signatureBlock == nil {
		return nil, nil, fmt.Errorf("could not find block with sufficient sync committee participation within %d retries", maxRetries)
	}

	// 3. Get AttestedBlock (parent of SignatureBlock)
	attestedBlockRoot := signatureBlock.Data.Message.ParentRoot.String()
	attestedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, attestedBlockRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block: %w", err)
	}
	attestedSlot := uint64(attestedBlock.Data.Message.Slot)

	// 4. Get FinalizedBlock from AttestedState.finalized_checkpoint.root
	checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finality checkpoints at attested slot %d: %w", attestedSlot, err)
	}
	finalizedBlockRoot := fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:])

	pr.GetLogger().DebugContext(ctx, "building consensus update from beacon API",
		"signature_slot", signatureSlot,
		"attested_slot", attestedSlot,
		"finalized_checkpoint_root", finalizedBlockRoot,
		"finalized_checkpoint_epoch", checkpoints.Finalized.Epoch)

	// 5. Build consensus update
	return pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, finalizedBlockRoot, signatureBlock.Version, includeNextSyncCommittee)
}

// countSyncCommitteeBits counts the set bits and total bits in sync_committee_bits
func (pr *Prover) countSyncCommitteeBits(bits []byte) (setBits int, totalBits int) {
	totalBits = len(bits) * 8
	for _, b := range bits {
		setBits += popCount(b)
	}
	return
}

// popCount counts the number of set bits in a byte
func popCount(b byte) int {
	count := 0
	for b != 0 {
		count += int(b & 1)
		b >>= 1
	}
	return count
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
// This function is only called for past periods (not the latest period), so all slots are already finalized.
// Following SPEC.md design:
//
//	SignatureBlock (signatureSlot) → parent_root → AttestedBlock
//	AttestedState → finalized_checkpoint.root → FinalizedBlock
//	AttestedState → next_sync_committee (period+1's committee)
func (pr *Prover) buildConsensusUpdateForPeriod(ctx context.Context, period uint64) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	periodStartSlot := pr.getPeriodBoundarySlot(period)
	periodEndSlot := pr.getPeriodBoundarySlot(period+1) - 1

	pr.GetLogger().DebugContext(ctx, "building consensus update for period",
		"target_period", period,
		"period_start_slot", periodStartSlot,
		"period_end_slot", periodEndSlot)

	// Search backwards within latter half of target period
	// By starting from period midpoint, we guarantee attestedSlot (parent of signatureSlot) is within the period
	minSignatureSlot := periodStartSlot + (periodEndSlot-periodStartSlot)/2
	for signatureSlot := periodEndSlot; signatureSlot > minSignatureSlot; signatureSlot-- {
		// Get signature block
		signatureBlock, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", signatureSlot))
		if err != nil {
			continue
		}

		// Get attested block (parent of signature block)
		attestedBlockRoot := signatureBlock.Data.Message.ParentRoot.String()
		attestedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, attestedBlockRoot)
		if err != nil {
			continue
		}
		attestedSlot := uint64(attestedBlock.Data.Message.Slot)

		// Get finalized checkpoint from attested state
		checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", attestedSlot))
		if err != nil {
			continue
		}

		finalizedBlockRoot := fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:])

		pr.GetLogger().DebugContext(ctx, "found valid signature/attested slots",
			"signature_slot", signatureSlot,
			"attested_slot", attestedSlot,
			"finalized_checkpoint_root", finalizedBlockRoot,
			"finalized_checkpoint_epoch", checkpoints.Finalized.Epoch)

		// Build consensus update
		return pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, finalizedBlockRoot, signatureBlock.Version, true)
	}

	return nil, nil, fmt.Errorf("could not find valid signature slot in period %d (searched %d to %d)", period, periodEndSlot, minSignatureSlot)
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
	attestedBlockId := fmt.Sprintf("0x%x", parsedSignatureBlock.ParentRoot)
	attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, attestedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block SSZ (parent of signature block): %w", err)
	}

	parsedAttestedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested block SSZ: %w", err)
	}

	// Get attested block header from beacon API to get the correct body_root
	// (prysm's HashTreeRoot may compute differently than the beacon node)
	attestedHeader, err := pr.beaconClient.GetBeaconHeader(ctx, attestedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block header: %w", err)
	}
	attestedHeaderProto, err := attestedHeader.ToBeaconBlockHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert attested header: %w", err)
	}
	// Use the body_root from beacon API
	parsedAttestedBlock.SetBodyRoot(attestedHeaderProto.BodyRoot)

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

	// Get finalized block header from beacon API to get the correct body_root
	finalizedHeader, err := pr.beaconClient.GetBeaconHeader(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block header: %w", err)
	}
	finalizedHeaderProto, err := finalizedHeader.ToBeaconBlockHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert finalized header: %w", err)
	}
	// Use the body_root from beacon API
	parsedFinalizedBlock.SetBodyRoot(finalizedHeaderProto.BodyRoot)

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
	attestedBlockIdSlots := fmt.Sprintf("%d", attestedSlot)
	attestedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, attestedBlockIdSlots)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block SSZ: %w", err)
	}

	parsedAttestedBlock, err := ParseBeaconBlockSSZ(attestedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested block SSZ: %w", err)
	}

	// Get attested block header from beacon API to get the correct body_root
	attestedHeaderSlots, err := pr.beaconClient.GetBeaconHeader(ctx, attestedBlockIdSlots)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block header: %w", err)
	}
	attestedHeaderProtoSlots, err := attestedHeaderSlots.ToBeaconBlockHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert attested header: %w", err)
	}
	// Use the body_root from beacon API
	parsedAttestedBlock.SetBodyRoot(attestedHeaderProtoSlots.BodyRoot)

	// Get attested state SSZ for finality_branch and next_sync_committee_branch generation
	attestedStateSSZ, err := pr.beaconClient.GetBeaconStateSSZ(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested state SSZ: %w", err)
	}

	parsedState, err := ParseBeaconStateSSZ(attestedStateSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse attested state SSZ: %w", err)
	}

	// Debug: log state info including finalized checkpoint
	fcEpoch, fcRoot := parsedState.GetFinalizedCheckpoint()
	pr.GetLogger().DebugContext(ctx, "[DEBUG] attested state parsed",
		"attested_slot", attestedSlot,
		"state_ssz_size", len(attestedStateSSZ),
		"finalized_checkpoint_epoch", fcEpoch,
		"finalized_checkpoint_root", fmt.Sprintf("0x%x", fcRoot))

	finalityBranch, err := parsedState.GenerateFinalityBranch()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate finality branch: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "[DEBUG] finality branch generated",
		"branch_len", len(finalityBranch),
		"epoch_hash", fmt.Sprintf("0x%x", finalityBranch[0]))

	// Get finalized block SSZ for execution_branch generation
	finalizedBlockSSZ, err := pr.beaconClient.GetBeaconBlockSSZ(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block SSZ: %w", err)
	}

	parsedFinalizedBlock, err := ParseBeaconBlockSSZ(finalizedBlockSSZ, version, forkSpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse finalized block SSZ: %w", err)
	}

	// Get finalized block header from beacon API to get the correct body_root
	finalizedHeaderSlots, err := pr.beaconClient.GetBeaconHeader(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block header: %w", err)
	}
	finalizedHeaderProtoSlots, err := finalizedHeaderSlots.ToBeaconBlockHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert finalized header: %w", err)
	}
	// Use the body_root from beacon API
	parsedFinalizedBlock.SetBodyRoot(finalizedHeaderProtoSlots.BodyRoot)

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

	// Debug logging for consensus update
	pr.GetLogger().InfoContext(ctx, "[DEBUG] consensus update built",
		"attested_header.slot", update.AttestedHeader.Slot,
		"attested_header.state_root", fmt.Sprintf("0x%x", update.AttestedHeader.StateRoot),
		"attested_header.body_root", fmt.Sprintf("0x%x", update.AttestedHeader.BodyRoot),
		"finalized_header.slot", update.FinalizedHeader.Slot,
		"finalized_header.state_root", fmt.Sprintf("0x%x", update.FinalizedHeader.StateRoot),
		"finalized_header.body_root", fmt.Sprintf("0x%x", update.FinalizedHeader.BodyRoot),
		"finalized_execution_root", fmt.Sprintf("0x%x", update.FinalizedExecutionRoot),
		"finality_branch_len", len(update.FinalizedHeaderBranch),
		"execution_branch_len", len(update.FinalizedExecutionBranch),
		"signature_slot", update.SignatureSlot)

	return update, parsedFinalizedBlock.ExecutionPayload, nil
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
			pr.GetLogger().InfoContext(ctx, "failed to get sync committees from state", "slot", i, "err", err)
			errs = append(errs, err)
			continue
		}
		return currentSyncCommittee, nextSyncCommittee, nil
	}
	return nil, nil, fmt.Errorf("failed to get sync committees in period: period=%v err=%v", period, errors.Join(errs...))
}
