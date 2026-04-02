package beacon

import (
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

// GetBeaconBlockSSZ retrieves a beacon block in SSZ format
func (cl Client) GetBeaconBlockSSZ(ctx context.Context, blockId string) ([]byte, error) {
	return cl.getSSZ(ctx, fmt.Sprintf("/eth/v2/beacon/blocks/%s", blockId))
}

// GetBeaconStateSSZ retrieves a beacon state in SSZ format
func (cl Client) GetBeaconStateSSZ(ctx context.Context, stateId string) ([]byte, error) {
	return cl.getSSZ(ctx, fmt.Sprintf("/eth/v2/debug/beacon/states/%s", stateId))
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

func (cl Client) getSSZ(ctx context.Context, path string) ([]byte, error) {
	log.GetLogger().DebugContext(ctx, "Beacon API SSZ request", "endpoint", cl.endpoint+path)
	req, err := http.NewRequestWithContext(ctx, "GET", cl.endpoint+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")

	r, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	bz, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		log.GetLogger().DebugContext(ctx, "Non 2xx response to Beacon API SSZ request", "endpoint", cl.endpoint+path, "status code", r.StatusCode)
		return nil, fmt.Errorf("request returned status code %d", r.StatusCode)
	}
	return bz, nil
}
