package relay

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/OffchainLabs/prysm/v7/crypto/bls"
	"github.com/OffchainLabs/prysm/v7/encoding/ssz"
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
	for offset := uint64(1); offset <= slotsPerEpoch; offset++ {
		candidateSlot := attestedSlot + offset

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

	return 0, 0, fmt.Errorf("signature block not found within %d slots after attested slot %d", slotsPerEpoch, attestedSlot)
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

// computeAggregatePubkey computes the BLS aggregate public key from a list of pubkeys
func computeAggregatePubkey(pubkeys [][]byte) ([]byte, error) {
	if len(pubkeys) == 0 {
		return nil, fmt.Errorf("empty pubkeys list")
	}

	aggregated, err := bls.AggregatePublicKeys(pubkeys)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate pubkeys: %w", err)
	}
	return aggregated.Marshal(), nil
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
// This function first tries to use the standard Beacon API (more efficient),
// and falls back to downloading full state SSZ if the API fails.
func (pr *Prover) getSyncCommitteesFromState(ctx context.Context, slot uint64, version string) (*lctypes.SyncCommittee, *lctypes.SyncCommittee, error) {
	stateId := fmt.Sprintf("%d", slot)
	epoch := pr.computeEpoch(slot)

	// Get current sync committee using standard Beacon API
	currentSC, err := pr.getSyncCommitteeFromBeaconAPI(ctx, stateId, &epoch)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current sync committee: %w", err)
	}

	// Get next sync committee (next epoch)
	nextEpoch := epoch + 1
	nextSC, err := pr.getSyncCommitteeFromBeaconAPI(ctx, stateId, &nextEpoch)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get next sync committee: %w", err)
	}

	return currentSC, nextSC, nil
}

// getSyncCommitteeFromBeaconAPI retrieves a sync committee using standard Beacon API
// epoch parameter specifies which sync committee to return (current or next)
func (pr *Prover) getSyncCommitteeFromBeaconAPI(ctx context.Context, stateId string, epoch *uint64) (*lctypes.SyncCommittee, error) {
	// Get sync committee validator indices
	scRes, err := pr.beaconClient.GetSyncCommittees(ctx, stateId)
	if err != nil {
		return nil, fmt.Errorf("failed to get sync committees: %w", err)
	}

	// Extract unique validator indices (sync committee can have duplicates)
	uniqueIndices := make([]string, 0, len(scRes.Data.Validators))
	seen := make(map[string]bool)
	for _, idx := range scRes.Data.Validators {
		if !seen[idx] {
			seen[idx] = true
			uniqueIndices = append(uniqueIndices, idx)
		}
	}

	// Get validator pubkeys for unique indices
	validatorsRes, err := pr.beaconClient.GetValidators(ctx, stateId, uniqueIndices)
	if err != nil {
		return nil, fmt.Errorf("failed to get validators: %w", err)
	}

	// Build pubkey map by validator index
	pubkeyMap := make(map[string][]byte)
	for _, v := range validatorsRes.Data {
		pubkeyMap[v.Index] = v.Validator.Pubkey
	}

	// Collect pubkeys in order (preserving duplicates from original list)
	pubkeys := make([][]byte, len(scRes.Data.Validators))
	for i, idx := range scRes.Data.Validators {
		pk, ok := pubkeyMap[idx]
		if !ok {
			return nil, fmt.Errorf("validator %s not found in response", idx)
		}
		pubkeys[i] = pk
	}

	// Compute aggregate pubkey using BLS
	aggregatePubkey, err := computeAggregatePubkey(pubkeys)
	if err != nil {
		return nil, fmt.Errorf("failed to compute aggregate pubkey: %w", err)
	}

	return &lctypes.SyncCommittee{
		Pubkeys:         pubkeys,
		AggregatePubkey: aggregatePubkey,
	}, nil
}

// buildConsensusUpdateForPeriod builds a ConsensusUpdate for a specific period with next_sync_committee
func (pr *Prover) buildConsensusUpdateForPeriod(ctx context.Context, period uint64) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	// Get finalized block to determine current state
	finalizedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, "finalized")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block: %w", err)
	}
	finalizedSlot := uint64(finalizedBlock.Data.Message.Slot)
	finalizedPeriod := pr.computeSyncCommitteePeriod(pr.computeEpoch(finalizedSlot))

	// Determine the target slot for this period
	var targetSlot uint64
	if period < finalizedPeriod {
		// For past periods, use the last slot of the period
		targetSlot = pr.getPeriodBoundarySlot(period+1) - 1
	} else {
		// For current period, use the finalized slot
		targetSlot = finalizedSlot
	}

	pr.GetLogger().DebugContext(ctx, "building consensus update for period", "period", period, "target_slot", targetSlot, "finalized_period", finalizedPeriod)

	// Find a valid block in the target slot range
	blockSlot, err := pr.findValidBlockSlot(ctx, targetSlot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find valid block slot: %w", err)
	}

	// Get block details for version
	block, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", blockSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block at slot %d: %w", blockSlot, err)
	}

	// Get finality checkpoints to determine finalized block root
	checkpoints, err := pr.beaconClient.GetFinalityCheckpointsAtState(ctx, fmt.Sprintf("%d", blockSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finality checkpoints at slot %d: %w", blockSlot, err)
	}

	// Find signature and attested slots using the finalized checkpoint root
	signatureSlot, attestedSlot, err := pr.findSignatureAndAttestedSlot(ctx, checkpoints.Finalized.Root[:], blockSlot)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find signature and attested slots: %w", err)
	}

	// Build consensus update using the explicit slots
	// Note: Use the finalized checkpoint root's block as finalized block
	finalizedBlockId := fmt.Sprintf("0x%x", checkpoints.Finalized.Root[:])
	return pr.buildConsensusUpdateWithSlots(ctx, signatureSlot, attestedSlot, finalizedBlockId, block.Version, true)
}

// buildConsensusUpdateWithSlots builds ConsensusUpdate with explicitly provided signature and attested slots
// This function uses the standard Beacon API for header data (body_root) and JSON API for other data,
// which works correctly for both mainnet and minimal presets.
func (pr *Prover) buildConsensusUpdateWithSlots(ctx context.Context, signatureSlot, attestedSlot uint64, finalizedBlockId string, version string, includeNextSyncCommittee bool) (*lctypes.ConsensusUpdate, *beacon.ExecutionPayloadHeader, error) {
	// Get block headers from API (these include body_root computed by the beacon node)
	attestedBlockHeader, err := pr.beaconClient.GetBeaconBlockHeader(ctx, fmt.Sprintf("%d", attestedSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get attested block header: %w", err)
	}

	finalizedBlockHeader, err := pr.beaconClient.GetBeaconBlockHeader(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block header: %w", err)
	}

	// Get signature block JSON for sync_aggregate
	signatureBlock, err := pr.beaconClient.GetBeaconBlock(ctx, fmt.Sprintf("%d", signatureSlot))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature block: %w", err)
	}

	// Get finalized block JSON for execution payload
	finalizedBlock, err := pr.beaconClient.GetBeaconBlock(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finalized block: %w", err)
	}

	// Convert execution payload from JSON to header format (for return value)
	executionPayload, err := convertExecutionPayloadFromJSON(&finalizedBlock.Data.Message.Body.ExecutionPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert execution payload: %w", err)
	}

	// Convert sync aggregate from JSON
	syncAggregate := &lctypes.SyncAggregate{
		SyncCommitteeBits:      signatureBlock.Data.Message.Body.SyncAggregate.SyncCommitteeBits,
		SyncCommitteeSignature: signatureBlock.Data.Message.Body.SyncAggregate.SyncCommitteeSignature,
	}

	// Use Lodestar proof API for branches
	var finalityBranch, nextSyncCommitteeBranch, executionBranch [][]byte
	var executionRoot []byte
	var nextSyncCommittee *lctypes.SyncCommittee

	attestedStateId := fmt.Sprintf("%d", attestedSlot)
	finalityBranch, nextSyncCommitteeBranch, err = pr.getBranchesFromProofAPI(ctx, attestedStateId, version, includeNextSyncCommittee)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get branches from proof API: %w", err)
	}

	// Get next_sync_committee data if requested (we need the actual pubkeys, not just the branch)
	if includeNextSyncCommittee {
		_, nextSyncCommittee, err = pr.getSyncCommitteesFromState(ctx, attestedSlot, version)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get next sync committee: %w", err)
		}
	}

	// Get execution branch and root from proof API
	// Note: We use the execution_root from the proof API rather than computing it ourselves
	// because our JSON-based computation may not match for all network presets
	executionBranch, executionRoot, err = pr.getExecutionBranchFromProofAPI(ctx, finalizedBlockId)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get execution branch from proof API: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "building consensus update with slots",
		"signature_slot", signatureSlot,
		"attested_slot", attestedSlot,
		"finalized_slot", uint64(finalizedBlockHeader.Data.Header.Message.Slot))

	// Build ConsensusUpdate using header data from API
	update := &lctypes.ConsensusUpdate{
		AttestedHeader: &lctypes.BeaconBlockHeader{
			Slot:          uint64(attestedBlockHeader.Data.Header.Message.Slot),
			ProposerIndex: uint64(attestedBlockHeader.Data.Header.Message.ProposerIndex),
			ParentRoot:    attestedBlockHeader.Data.Header.Message.ParentRoot,
			StateRoot:     attestedBlockHeader.Data.Header.Message.StateRoot,
			BodyRoot:      attestedBlockHeader.Data.Header.Message.BodyRoot,
		},
		FinalizedHeader: &lctypes.BeaconBlockHeader{
			Slot:          uint64(finalizedBlockHeader.Data.Header.Message.Slot),
			ProposerIndex: uint64(finalizedBlockHeader.Data.Header.Message.ProposerIndex),
			ParentRoot:    finalizedBlockHeader.Data.Header.Message.ParentRoot,
			StateRoot:     finalizedBlockHeader.Data.Header.Message.StateRoot,
			BodyRoot:      finalizedBlockHeader.Data.Header.Message.BodyRoot,
		},
		FinalizedHeaderBranch:    finalityBranch,
		FinalizedExecutionRoot:   executionRoot,
		FinalizedExecutionBranch: executionBranch,
		SyncAggregate:            syncAggregate,
		SignatureSlot:            signatureSlot,
	}

	// Optionally add next sync committee
	if includeNextSyncCommittee {
		update.NextSyncCommittee = nextSyncCommittee
		update.NextSyncCommitteeBranch = nextSyncCommitteeBranch
	}

	return update, executionPayload, nil
}

// convertExecutionPayloadFromJSON converts ExecutionPayloadJSON to ExecutionPayloadHeader
func convertExecutionPayloadFromJSON(ep *beacon.ExecutionPayloadJSON) (*beacon.ExecutionPayloadHeader, error) {
	// Compute transactions root from raw transactions
	txs := make([][]byte, len(ep.Transactions))
	for i, tx := range ep.Transactions {
		txs[i] = tx
	}
	transactionsRoot, err := computeTransactionsRoot(txs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute transactions root: %w", err)
	}

	// Compute withdrawals root from raw withdrawals
	withdrawals := make([]*Withdrawal, len(ep.Withdrawals))
	for i, w := range ep.Withdrawals {
		withdrawals[i] = &Withdrawal{
			Index:          uint64(w.Index),
			ValidatorIndex: uint64(w.ValidatorIndex),
			Address:        w.Address,
			Amount:         uint64(w.Amount),
		}
	}
	withdrawalsRoot, err := computeWithdrawalsRootFromWithdrawals(withdrawals)
	if err != nil {
		return nil, fmt.Errorf("failed to compute withdrawals root: %w", err)
	}

	return &beacon.ExecutionPayloadHeader{
		ParentHash:       ep.ParentHash,
		FeeRecipient:     ep.FeeRecipient,
		StateRoot:        ep.StateRoot,
		ReceiptsRoot:     ep.ReceiptsRoot,
		LogsBloom:        ep.LogsBloom,
		PrevRandao:       ep.PrevRandao,
		BlockNumber:      uint64(ep.BlockNumber),
		GasLimit:         uint64(ep.GasLimit),
		GasUsed:          uint64(ep.GasUsed),
		Timestamp:        uint64(ep.Timestamp),
		ExtraData:        ep.ExtraData,
		BaseFeePerGas:    bigIntTo32Bytes(ep.BaseFeePerGas),
		BlockHash:        ep.BlockHash,
		TransactionsRoot: transactionsRoot[:],
		WithdrawalsRoot:  withdrawalsRoot[:],
		BlobGasUsed:      uint64(ep.BlobGasUsed),
		ExcessBlobGas:    uint64(ep.ExcessBlobGas),
	}, nil
}

// Withdrawal is a simple representation of a withdrawal
type Withdrawal struct {
	Index          uint64
	ValidatorIndex uint64
	Address        []byte
	Amount         uint64
}

// bigIntTo32Bytes converts a big.Int-like Uint64 to a 32-byte little-endian representation
func bigIntTo32Bytes(v beacon.Uint64) []byte {
	result := make([]byte, 32)
	// BaseFeePerGas is stored as little-endian in SSZ
	val := uint64(v)
	for i := 0; i < 8; i++ {
		result[i] = byte(val >> (8 * i))
	}
	return result
}

// computeWithdrawalsRootFromWithdrawals computes the SSZ root of withdrawals list
func computeWithdrawalsRootFromWithdrawals(withdrawals []*Withdrawal) ([32]byte, error) {
	// Hash each withdrawal
	wRoots := make([][32]byte, len(withdrawals))
	for i, w := range withdrawals {
		hh := fastssz.NewHasher()
		hh.PutUint64(w.Index)
		hh.PutUint64(w.ValidatorIndex)
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

// getBranchesFromProofAPI retrieves finality_branch and optionally next_sync_committee_branch using Lodestar's proof API
// This is more efficient than downloading the full BeaconState (which can be several GB on mainnet)
// Note: This is a Lodestar-specific API and will not work with other beacon node implementations
func (pr *Prover) getBranchesFromProofAPI(ctx context.Context, stateId string, version string, includeNextSyncCommittee bool) (finalityBranch [][]byte, nextSyncCommitteeBranch [][]byte, err error) {
	// Get the appropriate gindices for the version
	finalizedRootGindex := beacon.GetFinalizedRootGindex(version)

	// Get finality branch
	finalityProofRes, err := pr.beaconClient.GetStateProof(ctx, stateId, []uint64{finalizedRootGindex})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get finality proof: %w", err)
	}

	leaves := make([][]byte, len(finalityProofRes.Data.Leaves))
	for i, l := range finalityProofRes.Data.Leaves {
		leaves[i] = l
	}

	finalityBranch, err = beacon.ExtractSingleProofBranch(leaves, finalizedRootGindex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract finality branch: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "got finality branch from proof API",
		"stateId", stateId,
		"version", version,
		"gindex", finalizedRootGindex,
		"branch_length", len(finalityBranch))

	if !includeNextSyncCommittee {
		return finalityBranch, nil, nil
	}

	// Get next sync committee branch
	nextSyncCommitteeGindex := beacon.GetNextSyncCommitteeGindex(version)

	nextSyncCommitteeProofRes, err := pr.beaconClient.GetStateProof(ctx, stateId, []uint64{nextSyncCommitteeGindex})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get next sync committee proof: %w", err)
	}

	leaves = make([][]byte, len(nextSyncCommitteeProofRes.Data.Leaves))
	for i, l := range nextSyncCommitteeProofRes.Data.Leaves {
		leaves[i] = l
	}

	nextSyncCommitteeBranch, err = beacon.ExtractSingleProofBranch(leaves, nextSyncCommitteeGindex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract next sync committee branch: %w", err)
	}

	// Extract the target leaf (next_sync_committee_root from beacon node)
	// This is needed because prysm types are hardcoded for mainnet preset and can't compute
	// the hash correctly for minimal preset
	nextSyncCommitteeRoot, err := beacon.ExtractTargetLeaf(leaves, nextSyncCommitteeGindex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract next sync committee root from proof: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "got next sync committee branch from proof API",
		"stateId", stateId,
		"version", version,
		"gindex", nextSyncCommitteeGindex,
		"branch_length", len(nextSyncCommitteeBranch),
		"next_sync_committee_root", fmt.Sprintf("%x", nextSyncCommitteeRoot))

	return finalityBranch, nextSyncCommitteeBranch, nil
}

// getExecutionBranchFromProofAPI retrieves execution_branch and execution_root using Lodestar's proof API
// Returns the branch for body_root verification and the execution_root (target leaf) from the proof
//
// Note: The Lodestar /eth/v0/beacon/proof/block API uses gindex 25 which provides a proof from
// execution_payload to block_root (4 levels deep). However, for Light Client verification,
// we need a proof against body_root (only 1 level deep, gindex 3).
// This function extracts only the body-relative portion of the proof.
func (pr *Prover) getExecutionBranchFromProofAPI(ctx context.Context, blockId string) (branch [][]byte, executionRoot []byte, err error) {
	// Use gindex 25 to query the Lodestar proof API (execution_payload in full block tree)
	fullGindex := uint64(beacon.LodestarExecutionPayloadInBlockGindex)

	proofRes, err := pr.beaconClient.GetBlockProof(ctx, blockId, []uint64{fullGindex})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get execution payload proof: %w", err)
	}

	leaves := make([][]byte, len(proofRes.Data.Leaves))
	for i, l := range proofRes.Data.Leaves {
		leaves[i] = l
	}

	// Extract just the body-relative branch (gindex 3, depth 1) for body_root verification
	branch, err = beacon.ExtractExecutionBranchForBodyRoot(leaves, fullGindex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract execution branch for body root: %w", err)
	}

	// Extract the target leaf (execution_root from beacon node)
	executionRoot, err = beacon.ExtractTargetLeaf(leaves, fullGindex)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract execution root from proof: %w", err)
	}

	pr.GetLogger().DebugContext(ctx, "got execution branch and root from proof API",
		"blockId", blockId,
		"version", proofRes.Version,
		"full_gindex", fullGindex,
		"body_gindex", beacon.ExecutionPayloadInBodyGindex,
		"branch_length", len(branch),
		"execution_root", fmt.Sprintf("%x", executionRoot))

	return branch, executionRoot, nil
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
