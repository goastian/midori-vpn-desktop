// Package apiClient implements the HTTP client for vpn-core backend calls.
package apiClient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/httpx"
)

// APIError is a non-success response returned by vpn-core. Code is the
// backend's stable machine-readable identifier; callers must not match the
// human-readable Message to decide retry behavior.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("api request failed (status=%d code=[%s])", e.StatusCode, e.Code)
	}
	return fmt.Sprintf("api request failed (status=%d)", e.StatusCode)
}

func sanitizeAPIErrorCode(code string) string {
	if len(code) > 64 {
		return ""
	}
	for _, char := range code {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return ""
		}
	}
	return code
}

func ErrorCode(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return ""
}

func ErrorStatus(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

func ErrorMessage(err error) string {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Message
	}
	return err.Error()
}

// Client is the vpn-core API client.
type Client struct {
	baseURL     string
	origin      string
	clientID    string
	httpClient  *http.Client
	tokenFunc   func() string // returns the current access token
	refreshFunc func(context.Context) error
}

// CloseIdleConnections releases resources owned by the dedicated transport.
func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

// New creates a new Client.
func New(baseURL string, clientID string, tokenFunc func() string, refreshFunc func(context.Context) error) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	origin, err := originFromBaseURL(baseURL)
	if err != nil && baseURL != "" {
		slog.Warn("api client: API_URL cannot be used as CSRF origin", "api_url", baseURL, "err", err)
	}
	return &Client{
		baseURL:     baseURL,
		origin:      origin,
		clientID:    clientID,
		tokenFunc:   tokenFunc,
		refreshFunc: refreshFunc,
		httpClient:  httpx.NewClient(30 * time.Second),
	}
}

func originFromBaseURL(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("missing scheme or host")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// ----- Data types -----

// Server is a VPN server entry.
type Server struct {
	ID                string                `json:"id"`
	Name              string                `json:"name"`
	Host              string                `json:"host"`
	ProbeURL          string                `json:"probe_url"`
	Endpoint          string                `json:"endpoint"`
	Port              int                   `json:"port"`
	WGPort            int                   `json:"wg_port"`
	PublicKey         string                `json:"public_key"`
	Location          string                `json:"location"`
	CountryCode       string                `json:"country_code"`
	MaxPeers          int                   `json:"max_peers"`
	CurrentPeers      int                   `json:"current_peers"`
	IsActive          bool                  `json:"is_active"`
	SupportsWireGuard bool                  `json:"supports_wireguard"`
	SupportsProxy     bool                  `json:"supports_proxy"`
	SupportsMeshExit  bool                  `json:"supports_mesh_exit"`
	Transports        []TransportCapability `json:"transports"`
}

// ServerCandidate is the fail-closed placement projection returned by
// Control. It contains only public data needed to measure and select an edge.
type ServerCandidate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Location    string `json:"location"`
	CountryCode string `json:"country_code"`
	Protocol    string `json:"protocol"`
	ProbeURL    string `json:"probe_url"`
	Endpoint    string `json:"endpoint"`
	Port        int    `json:"port"`
	Priority    int    `json:"priority"`
}

type ConnectionReason string

const (
	ConnectionReasonUser              ConnectionReason = "user"
	ConnectionReasonAutomaticFailover ConnectionReason = "automatic_failover"
)

type TransportCapability struct {
	Protocol     string                 `json:"protocol"`
	Host         string                 `json:"host"`
	Port         int                    `json:"port"`
	Enabled      bool                   `json:"enabled"`
	Priority     int                    `json:"priority"`
	HealthStatus string                 `json:"health_status"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Connection is a VPN peer/connection entry.
type Connection struct {
	ID            string `json:"id"`
	DeviceID      string `json:"device_id"`
	UserID        string `json:"user_id"`
	ServerID      string `json:"server_id"`
	PublicKey     string `json:"public_key"`
	AssignedIP    string `json:"assigned_ip"`
	IsActive      bool   `json:"is_active"`
	DeviceName    string `json:"device_name"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// ConnectionConfig is the WireGuard configuration returned by connect.
type ConnectionConfig struct {
	PeerID          string `json:"peer_id"`
	DeviceID        string `json:"device_id"`
	PeerIP          string `json:"peer_ip"`
	ServerPublicKey string `json:"server_public_key"`
	ServerEndpoint  string `json:"server_endpoint"`
	PresharedKey    string `json:"preshared_key,omitempty"`
	PQKEMCiphertext string `json:"pq_kem_ciphertext,omitempty"`
	DNS             string `json:"dns"`
	AllowedIPs      string `json:"allowed_ips"`
}

// DeviceRegistration is the stable installation identity sent to Core. The
// adapter reference is an HMAC produced locally; a raw hardware address must
// never be placed in this contract.
type DeviceRegistration struct {
	ClientInstanceID string `json:"client_instance_id"`
	ReportedName     string `json:"reported_name"`
	DeviceType       string `json:"device_type"`
	AdapterReference string `json:"adapter_reference,omitempty"`
}

type TunnelCredentials struct {
	TunnelToken string `json:"tunnel_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// DeviceCertificate is the public portion of a certificate issued for one
// local device. Private keys are generated and retained by the desktop agent.
type DeviceCertificate struct {
	ID               string     `json:"id"`
	DeviceID         string     `json:"device_id"`
	ServerID         string     `json:"server_id"`
	DeviceName       string     `json:"device_name"`
	SerialNumber     string     `json:"serial_number"`
	CertificatePEM   string     `json:"certificate_pem"`
	PublicKeySHA256  string     `json:"public_key_sha256"`
	NotBefore        time.Time  `json:"not_before"`
	NotAfter         time.Time  `json:"not_after"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason *string    `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

type DeviceCertificateEnrollment struct {
	Certificate      DeviceCertificate `json:"certificate"`
	CACertificatePEM string            `json:"ca_certificate_pem"`
}

// MeshNode is the mesh node status from the backend.
type MeshNode struct {
	Active   bool   `json:"active"`
	MeshIP   string `json:"mesh_ip"`
	MeshID   string `json:"mesh_id"`
	PublicIP string `json:"public_ip"`
	Peers    []Peer `json:"peers"`
}

// Peer is a mesh peer entry.
type Peer struct {
	MeshIP      string `json:"mesh_ip"`
	DisplayName string `json:"display_name"`
	PublicIP    string `json:"public_ip,omitempty"`
	ProxyPort   int    `json:"proxy_port,omitempty"`
	ProxyScheme string `json:"proxy_scheme,omitempty"`
	SupportsTCP bool   `json:"supports_tcp,omitempty"`
	SupportsUDP bool   `json:"supports_udp,omitempty"`
	IsExitNode  bool   `json:"is_exit_node,omitempty"`
}

// ExitNode is a peer that is an exit node.
type ExitNode struct {
	UserID      string `json:"user_id"`
	MeshIP      string `json:"mesh_ip"`
	ProxyScheme string `json:"proxy_scheme"`
	ProxyPort   int    `json:"proxy_port"`
	SupportsTCP bool   `json:"supports_tcp"`
	SupportsUDP bool   `json:"supports_udp"`
	IsActive    bool   `json:"is_active"`
}

// ----- API calls -----

// ListServers returns all active VPN servers.
func (c *Client) ListServers(ctx context.Context) ([]Server, error) {
	var result []Server
	if err := c.get(ctx, "/api/v1/control/servers", &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ListServerCandidates returns only centrally eligible placements for one
// transport protocol. The backend response is deliberately not cached here.
func (c *Client) ListServerCandidates(ctx context.Context, protocol string) ([]ServerCandidate, error) {
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		return nil, errors.New("server candidate protocol is required")
	}
	var result []ServerCandidate
	if err := c.get(ctx, "/api/v1/control/servers/candidates?protocol="+url.QueryEscape(protocol), &result); err != nil {
		return nil, err
	}
	return result, nil
}

// CreateConnection registers a new VPN peer for the given server with optional Post-Quantum ML-KEM-768 public key.
func (c *Client) CreateConnection(ctx context.Context, serverID, publicKey string, device DeviceRegistration, reason ConnectionReason, pqKEMPublicKey ...string) (*ConnectionConfig, error) {
	if reason != ConnectionReasonUser && reason != ConnectionReasonAutomaticFailover {
		return nil, errors.New("valid connection reason is required")
	}
	body := struct {
		ServerID         string             `json:"server_id"`
		PublicKey        string             `json:"public_key"`
		Device           DeviceRegistration `json:"device"`
		ConnectionReason ConnectionReason   `json:"connection_reason"`
		PQKEMPublicKey   string             `json:"pq_kem_public_key,omitempty"`
	}{
		ServerID:         serverID,
		PublicKey:        publicKey,
		Device:           device,
		ConnectionReason: reason,
	}
	if len(pqKEMPublicKey) > 0 && pqKEMPublicKey[0] != "" {
		body.PQKEMPublicKey = pqKEMPublicKey[0]
	}
	var connCfg ConnectionConfig
	if err := c.post(ctx, "/api/v1/control/connections", body, &connCfg); err != nil {
		return nil, err
	}
	return &connCfg, nil
}

func (c *Client) TunnelCredentials(ctx context.Context, peerID string) (*TunnelCredentials, error) {
	var credentials TunnelCredentials
	if err := c.post(ctx, "/api/v1/control/tunnel-credentials", map[string]string{"peer_id": peerID}, &credentials); err != nil {
		return nil, err
	}
	return &credentials, nil
}

// EnrollDeviceCertificate submits only a CSR. The corresponding private key
// must never be included in this or any other backend request.
func (c *Client) EnrollDeviceCertificate(ctx context.Context, serverID string, device DeviceRegistration, csrPEM string) (*DeviceCertificateEnrollment, error) {
	body := struct {
		ServerID string             `json:"server_id"`
		Device   DeviceRegistration `json:"device"`
		CSRPEM   string             `json:"csr_pem"`
	}{
		ServerID: serverID,
		Device:   device,
		CSRPEM:   csrPEM,
	}
	var enrollment DeviceCertificateEnrollment
	if err := c.post(ctx, "/api/v1/control/certificates", body, &enrollment); err != nil {
		return nil, err
	}
	return &enrollment, nil
}

func (c *Client) RevokeDeviceCertificate(ctx context.Context, certificateID string) error {
	return c.delete(ctx, "/api/v1/control/certificates/"+url.PathEscape(certificateID))
}

func (c *Client) ListDeviceCertificates(ctx context.Context) ([]DeviceCertificate, error) {
	var result []DeviceCertificate
	if err := c.get(ctx, "/api/v1/control/certificates", &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ListConnections returns the user's active VPN connections.
func (c *Client) ListConnections(ctx context.Context) ([]Connection, error) {
	var result []Connection
	if err := c.get(ctx, "/api/v1/control/connections", &result); err != nil {
		return nil, err
	}
	return result, nil
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
func (c *Client) RegisterExitNode(ctx context.Context, meshID string, proxyScheme string, proxyPort int, supportsTCP, supportsUDP bool) error {
	body := map[string]any{
		"mesh_id":      meshID,
		"proxy_scheme": proxyScheme,
		"proxy_port":   proxyPort,
		"supports_tcp": supportsTCP,
		"supports_udp": supportsUDP,
	}
	return c.post(ctx, "/api/v1/control/mesh/exit-node/register", body, nil)
}

// ListExitNodes returns peers that offer exit-node capability.
func (c *Client) ListExitNodes(ctx context.Context) ([]ExitNode, error) {
	var result []ExitNode
	if err := c.get(ctx, "/api/v1/control/mesh/exit-nodes", &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SetExitNode sets the user's preferred exit node.
func (c *Client) SetExitNode(ctx context.Context, meshIP, proxyScheme string, proxyPort int) error {
	body := map[string]any{
		"mesh_ip":      meshIP,
		"proxy_scheme": proxyScheme,
		"proxy_port":   proxyPort,
	}
	return c.put(ctx, "/api/v1/control/mesh/exit-node", body)
}

// ClearExitNode removes the user's exit node preference.
func (c *Client) ClearExitNode(ctx context.Context) error {
	return c.delete(ctx, "/api/v1/control/mesh/exit-node")
}

// RefreshToken exchanges a refresh_token for new tokens.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (accessToken, newRefreshToken string, expiresIn int, err error) {
	clientID := c.clientID
	if clientID == "" {
		return "", "", 0, fmt.Errorf("api client: AUTHENTIK_CLIENT_ID is not configured")
	}
	body := map[string]string{
		"refresh_token": refreshToken,
		"client_id":     clientID,
	}
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
	return c.doOnce(ctx, method, path, body, out, auth, true)
}

func (c *Client) doOnce(ctx context.Context, method, path string, body, out any, auth bool, allowRefresh bool) error {
	if c.baseURL == "" {
		return fmt.Errorf("api client: API_URL is not configured (check /etc/midorivpn/config.env)")
	}

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
	// vpn-core's auth endpoints use the Origin header for CSRF checks. Keep it
	// aligned with API_URL so desktop deployments need one backend origin.
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
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

	if resp.StatusCode == http.StatusUnauthorized && auth && allowRefresh && c.refreshFunc != nil {
		if err := c.refreshFunc(ctx); err == nil {
			return c.doOnce(ctx, method, path, body, out, auth, false)
		}
	}

	if resp.StatusCode >= 400 {
		b, readErr := httpx.ReadBody(resp.Body, httpx.MaxResponseBytes)
		if readErr != nil {
			code := "response_read_failed"
			responseBytes := 0
			if errors.Is(readErr, httpx.ErrResponseTooLarge) {
				code = "response_too_large"
				responseBytes = httpx.MaxResponseBytes + 1
			}
			return httpx.NewRemoteError("core_api", code, resp.StatusCode, responseBytes, readErr)
		}
		message := strings.TrimSpace(string(b))
		var envelope struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(b, &envelope) == nil && envelope.Error != "" {
			message = envelope.Error
		}
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return &APIError{StatusCode: resp.StatusCode, Code: sanitizeAPIErrorCode(envelope.Code), Message: message}
	}

	if out != nil {
		// The backend wraps all responses in {"ok":bool,"data":...}.
		// Decode into the envelope and unwrap data into out.
		var envelope struct {
			OK   bool            `json:"ok"`
			Data json.RawMessage `json:"data"`
		}
		raw, err := httpx.ReadBody(resp.Body, httpx.MaxResponseBytes)
		if err != nil {
			code := "response_read_failed"
			responseBytes := 0
			if errors.Is(err, httpx.ErrResponseTooLarge) {
				code = "response_too_large"
				responseBytes = httpx.MaxResponseBytes + 1
			}
			return httpx.NewRemoteError("core_api", code, resp.StatusCode, responseBytes, err)
		}
		if err := json.Unmarshal(raw, &envelope); err == nil && envelope.Data != nil {
			// Wrapped response — decode data into out.
			if err := json.Unmarshal(envelope.Data, out); err != nil {
				return fmt.Errorf("decode response data: %w", err)
			}
		} else {
			// Unwrapped or non-JSON response — decode directly.
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}
		}
	}
	return nil
}
