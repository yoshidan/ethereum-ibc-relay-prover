package beacon

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/hyperledger-labs/yui-relayer/log"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var SupportedVersions = []string{"deneb", "electra", "fulu"}

var httpClient = &http.Client{
	Transport: otelhttp.NewTransport(http.DefaultTransport),
}

type Client struct {
	endpoint string
}

func NewClient(endpoint string) Client {
	return Client{endpoint: endpoint}
}

func IsSupportedVersion(v string) bool {
	return slices.Contains(SupportedVersions, v)
}

func (cl Client) GetGenesis(ctx context.Context) (*Genesis, error) {
	var res GenesisResponse
	if err := cl.get(ctx, "/eth/v1/beacon/genesis", &res); err != nil {
		return nil, err
	}
	return ToGenesis(res)
}

func (cl Client) GetBlockRoot(ctx context.Context, slot uint64, allowOptimistic bool) (*BlockRootResponse, error) {
	return cl.GetBlockRootByID(ctx, fmt.Sprintf("%d", slot), allowOptimistic)
}

// GetBlockRootByID gets block root by block ID (slot number, "finalized", "head", or block root)
func (cl Client) GetBlockRootByID(ctx context.Context, blockId string, allowOptimistic bool) (*BlockRootResponse, error) {
	var res BlockRootResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v1/beacon/blocks/%s/root", blockId), &res); err != nil {
		return nil, err
	}
	if !allowOptimistic && res.ExecutionOptimistic {
		return nil, fmt.Errorf("optimistic execution not allowed")
	}
	return &res, nil
}

func (cl Client) GetFinalityCheckpoints(ctx context.Context) (*StateFinalityCheckpoints, error) {
	var res StateFinalityCheckpointResponse
	if err := cl.get(ctx, "/eth/v1/beacon/states/head/finality_checkpoints", &res); err != nil {
		return nil, err
	}
	return ToStateFinalityCheckpoints(res)
}

func (cl Client) GetBootstrap(ctx context.Context, finalizedRoot []byte) (*LightClientBootstrapResponse, error) {
	if len(finalizedRoot) != 32 {
		return nil, fmt.Errorf("finalizedRoot length must be 32: actual=%v", finalizedRoot)
	}
	var res LightClientBootstrapResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v1/beacon/light_client/bootstrap/0x%v", hex.EncodeToString(finalizedRoot[:])), &res); err != nil {
		return nil, err
	}
	if !IsSupportedVersion(res.Version) {
		return nil, fmt.Errorf("unsupported version: %v", res.Version)
	}
	return &res, nil
}

func (cl Client) GetLightClientUpdates(ctx context.Context, period uint64, count uint64) (LightClientUpdatesResponse, error) {
	var res LightClientUpdatesResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v1/beacon/light_client/updates?start_period=%v&count=%v", period, count), &res); err != nil {
		return nil, err
	}
	if len(res) != int(count) {
		return nil, fmt.Errorf("unexpected response length: expected=%v actual=%v", count, len(res))
	}
	for i := range res {
		if !IsSupportedVersion(res[i].Version) {
			return nil, fmt.Errorf("unsupported version: %v", res[i].Version)
		}
	}
	return res, nil
}

func (cl Client) GetLightClientUpdate(ctx context.Context, period uint64) (*LightClientUpdateResponse, error) {
	res, err := cl.GetLightClientUpdates(ctx, period, 1)
	if err != nil {
		return nil, err
	}
	return &res[0], nil
}

func (cl Client) GetLightClientFinalityUpdate(ctx context.Context) (*LightClientFinalityUpdateResponse, error) {
	var res LightClientFinalityUpdateResponse
	if err := cl.get(ctx, "/eth/v1/beacon/light_client/finality_update", &res); err != nil {
		return nil, err
	}
	if !IsSupportedVersion(res.Version) {
		return nil, fmt.Errorf("unsupported version: %v", res.Version)
	}
	return &res, nil
}

// GetBeaconBlock retrieves a beacon block by block_id (slot number, "head", "finalized", etc.)
func (cl Client) GetBeaconBlock(ctx context.Context, blockId string) (*BeaconBlockResponse, error) {
	var res BeaconBlockResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v2/beacon/blocks/%s", blockId), &res); err != nil {
		return nil, err
	}
	if !IsSupportedVersion(res.Version) {
		return nil, fmt.Errorf("unsupported version: %v", res.Version)
	}
	return &res, nil
}

// GetBeaconBlockHeader retrieves a beacon block header by block_id
// The header includes the body_root computed by the beacon node
func (cl Client) GetBeaconBlockHeader(ctx context.Context, blockId string) (*BeaconBlockHeaderResponse, error) {
	var res BeaconBlockHeaderResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v1/beacon/headers/%s", blockId), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetFinalityCheckpointsAtState retrieves finality checkpoints for a specific state
func (cl Client) GetFinalityCheckpointsAtState(ctx context.Context, stateId string) (*StateFinalityCheckpoints, error) {
	var res StateFinalityCheckpointResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v1/beacon/states/%s/finality_checkpoints", stateId), &res); err != nil {
		return nil, err
	}
	return ToStateFinalityCheckpoints(res)
}

// GetSyncCommittees retrieves the sync committees for a state
func (cl Client) GetSyncCommittees(ctx context.Context, stateId string) (*SyncCommitteesResponse, error) {
	var res SyncCommitteesResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v1/beacon/states/%s/sync_committees", stateId), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetValidators retrieves validators by their indices using POST method
// POST is used to avoid URL length limits with many validator indices
func (cl Client) GetValidators(ctx context.Context, stateId string, indices []string) (*ValidatorsResponse, error) {
	var res ValidatorsResponse
	body := map[string][]string{"ids": indices}
	if err := cl.post(ctx, fmt.Sprintf("/eth/v1/beacon/states/%s/validators", stateId), body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetStateProof retrieves a Merkle proof for specific gindices from Lodestar's proof API
// This is a Lodestar-specific API (not standard Beacon API)
func (cl Client) GetStateProof(ctx context.Context, stateId string, gindices []uint64) (*CompactMultiProofResponse, error) {
	descriptor := ComputeDescriptor(gindices)
	descriptorHex := "0x" + hex.EncodeToString(descriptor)

	var res CompactMultiProofResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v0/beacon/proof/state/%s?format=%s", stateId, descriptorHex), &res); err != nil {
		return nil, err
	}
	if !IsSupportedVersion(res.Version) {
		return nil, fmt.Errorf("unsupported version: %v", res.Version)
	}
	return &res, nil
}

// GetBlockProof retrieves a Merkle proof for specific gindices from Lodestar's proof API
// This is a Lodestar-specific API (not standard Beacon API)
func (cl Client) GetBlockProof(ctx context.Context, blockId string, gindices []uint64) (*CompactMultiProofResponse, error) {
	descriptor := ComputeDescriptor(gindices)
	descriptorHex := "0x" + hex.EncodeToString(descriptor)

	var res CompactMultiProofResponse
	if err := cl.get(ctx, fmt.Sprintf("/eth/v0/beacon/proof/block/%s?format=%s", blockId, descriptorHex), &res); err != nil {
		return nil, err
	}
	if !IsSupportedVersion(res.Version) {
		return nil, fmt.Errorf("unsupported version: %v", res.Version)
	}
	return &res, nil
}

func (cl Client) get(ctx context.Context, path string, res any) error {
	log.GetLogger().DebugContext(ctx, "Beacon API request", "endpoint", cl.endpoint+path)
	req, err := http.NewRequestWithContext(ctx, "GET", cl.endpoint+path, nil)
	if err != nil {
		return err
	}

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	bz, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		log.GetLogger().DebugContext(ctx, "Non 2xx response to Beacon API request", "endpoint", cl.endpoint+path, "status code", r.StatusCode, "response body", string(bz))
		return fmt.Errorf("request returned status code %d", r.StatusCode)
	}
	return json.Unmarshal(bz, &res)
}

func (cl Client) post(ctx context.Context, path string, body any, res any) error {
	log.GetLogger().DebugContext(ctx, "Beacon API POST request", "endpoint", cl.endpoint+path)
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cl.endpoint+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	r, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	bz, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		log.GetLogger().DebugContext(ctx, "Non 2xx response to Beacon API POST request", "endpoint", cl.endpoint+path, "status code", r.StatusCode, "response body", string(bz))
		return fmt.Errorf("request returned status code %d", r.StatusCode)
	}
	return json.Unmarshal(bz, &res)
}

