// Package apiClient implements the HTTP client for vpn-core backend calls.
package apiClient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is the vpn-core API client.
type Client struct {
	baseURL    string
	httpClient *http.Client
	tokenFunc  func() string // returns the current access token
}

// New creates a new Client.
func New(baseURL string, tokenFunc func() string) *Client {
	return &Client{
		baseURL:   baseURL,
		tokenFunc: tokenFunc,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// ----- Data types -----

// Server is a VPN server entry.
type Server struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Host        string `json:"host"`
	Endpoint    string `json:"endpoint"`
	Port        int    `json:"port"`
	WGPort      int    `json:"wg_port"`
	PublicKey   string `json:"public_key"`
	Location    string `json:"location"`
	CountryCode string `json:"country_code"`
	MaxPeers    int    `json:"max_peers"`
	CurrentPeers int   `json:"current_peers"`
	IsActive    bool   `json:"is_active"`
	ProxyPort   int    `json:"proxy_port"`
}

// Connection is a VPN peer/connection entry.
type Connection struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	ServerID     string `json:"server_id"`
	PublicKey    string `json:"public_key"`
	AssignedIP   string `json:"assigned_ip"`
	IsActive     bool   `json:"is_active"`
	DeviceName   string `json:"device_name"`
	BytesSent    int64  `json:"bytes_sent"`
	BytesReceived int64 `json:"bytes_received"`
}

// Keypair is a generated WireGuard keypair.
type Keypair struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// MeshNode is the mesh node status from the backend.
type MeshNode struct {
	Active    bool   `json:"active"`
	MeshIP    string `json:"mesh_ip"`
	MeshID    string `json:"mesh_id"`
	PublicIP  string `json:"public_ip"`
	Peers     []Peer `json:"peers"`
}

// Peer is a mesh peer entry.
type Peer struct {
	MeshIP      string `json:"mesh_ip"`
	DisplayName string `json:"display_name"`
	PublicIP    string `json:"public_ip,omitempty"`
	ProxyPort   int    `json:"proxy_port,omitempty"`
	IsExitNode  bool   `json:"is_exit_node,omitempty"`
}

// ExitNode is a peer that is an exit node.
type ExitNode struct {
	UserID      string `json:"user_id"`
	MeshIP      string `json:"mesh_ip"`
	DisplayName string `json:"display_name"`
	ProxyHost   string `json:"proxy_host"`
	ProxyPort   int    `json:"proxy_port"`
}

// ----- API calls -----

// ListServers returns all active VPN servers.
func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	var result struct {
		Servers []Server `json:"servers"`
	}
	if err := c.get(ctx, "/api/v1/control/servers", &result); err != nil {
		return nil, err
	}
	return result.Servers, nil
}

// GenerateKeypair requests a new ephemeral keypair from the backend.
func (c *Client) GenerateKeypair(ctx context.Context) (*Keypair, error) {
	var kp Keypair
	if err := c.post(ctx, "/api/v1/control/keypair", nil, &kp); err != nil {
		return nil, err
	}
	return &kp, nil
}

// CreateConnection registers a new VPN peer for the given server.
func (c *Client) CreateConnection(ctx context.Context, serverID, publicKey, deviceName string) (*Connection, error) {
	body := map[string]string{
		"server_id":   serverID,
		"public_key":  publicKey,
		"device_name": deviceName,
	}
	var conn Connection
	if err := c.post(ctx, "/api/v1/control/connections", body, &conn); err != nil {
		return nil, err
	}
	return &conn, nil
}

// ListConnections returns the user's active VPN connections.
func (c *Client) ListConnections(ctx context.Context) ([]Connection, error) {
	var result struct {
		Connections []Connection `json:"connections"`
	}
	if err := c.get(ctx, "/api/v1/control/connections", &result); err != nil {
		return nil, err
	}
	return result.Connections, nil
}

// DeleteConnection removes a VPN peer.
func (c *Client) DeleteConnection(ctx context.Context, connID string) error {
	return c.delete(ctx, "/api/v1/control/connections/"+connID)
}

// AutoMesh provisions or returns the user's session mesh.
func (c *Client) AutoMesh(ctx context.Context) (*MeshNode, error) {
	var node MeshNode
	if err := c.post(ctx, "/api/v1/control/mesh/auto", nil, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

// DeleteAutoMesh removes the user's session mesh (called on logout).
func (c *Client) DeleteAutoMesh(ctx context.Context) error {
	return c.delete(ctx, "/api/v1/control/mesh/auto")
}

// NodeStatus returns the user's current mesh node status.
func (c *Client) NodeStatus(ctx context.Context) (*MeshNode, error) {
	var node MeshNode
	if err := c.get(ctx, "/api/v1/control/mesh/node", &node); err != nil {
		return nil, err
	}
	return &node, nil
}

// ActivateNode activates the mesh node.
func (c *Client) ActivateNode(ctx context.Context) (*MeshNode, error) {
	var node MeshNode
	if err := c.post(ctx, "/api/v1/control/mesh/node", nil, &node); err != nil {
		return nil, err
	}
	return &node, nil
}

// DeactivateNode deactivates the mesh node.
func (c *Client) DeactivateNode(ctx context.Context) error {
	return c.delete(ctx, "/api/v1/control/mesh/node")
}

// RegisterExitNode registers this desktop as an exit node with its proxy details.
func (c *Client) RegisterExitNode(ctx context.Context, proxyPort int) error {
	body := map[string]any{
		"proxy_port":  proxyPort,
		"is_exit_node": true,
	}
	return c.post(ctx, "/api/v1/control/mesh/node/register", body, nil)
}

// ListExitNodes returns peers that offer exit-node capability.
func (c *Client) ListExitNodes(ctx context.Context) ([]ExitNode, error) {
	var result struct {
		ExitNodes []ExitNode `json:"exit_nodes"`
	}
	if err := c.get(ctx, "/api/v1/control/mesh/exit-nodes", &result); err != nil {
		return nil, err
	}
	return result.ExitNodes, nil
}

// SetExitNode sets the user's preferred exit node.
func (c *Client) SetExitNode(ctx context.Context, proxyHost string, proxyPort int) error {
	body := map[string]any{
		"proxy_host": proxyHost,
		"proxy_port": proxyPort,
	}
	return c.put(ctx, "/api/v1/control/mesh/exit-node", body)
}

// ClearExitNode removes the user's exit node preference.
func (c *Client) ClearExitNode(ctx context.Context) error {
	return c.delete(ctx, "/api/v1/control/mesh/exit-node")
}

// RefreshToken exchanges a refresh_token for new tokens.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, expiresIn int, err error) {
	body := map[string]string{"refresh_token": refreshToken}
	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err = c.postNoAuth(ctx, "/api/v1/auth/refresh", body, &result); err != nil {
		return
	}
	return result.AccessToken, result.RefreshToken, result.ExpiresIn, nil
}

// ----- HTTP helpers -----

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out, true)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out, true)
}

func (c *Client) postNoAuth(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out, false)
}

func (c *Client) put(ctx context.Context, path string, body any) error {
	return c.do(ctx, http.MethodPut, path, body, nil, true)
}

func (c *Client) delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil, true)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, auth bool) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		if token := c.tokenFunc(); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("api error %d: %s", resp.StatusCode, string(b))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
