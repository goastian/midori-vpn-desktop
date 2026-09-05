package rpc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/goastian/midorivpn-agent/internal/settings"
)

const (
	disconnectReasonUserRequest  = "user_request"
	disconnectReasonServerSwitch = "server_switch"
)

type vpnDisconnectRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason"`
}

type vpnConnectRequest struct {
	ServerID      string                 `json:"server_id"`
	Protocol      string                 `json:"protocol"`
	SelectionMode settings.SelectionMode `json:"selection_mode"`
}

type vpnConnectResult struct {
	AssignedIP     string `json:"assigned_ip"`
	Server         string `json:"server"`
	ActiveProtocol string `json:"active_protocol"`
	FallbackReason string `json:"fallback_reason,omitempty"`
	ConnectionMS   int64  `json:"connection_ms"`
	PostQuantum    bool   `json:"post_quantum"`
	PQAlgorithm    string `json:"pq_algorithm"`
}

type vpnConnectFailure struct {
	Status  int
	Code    string
	Message string
}

func connectFailure(status int, code, message string) *vpnConnectFailure {
	return &vpnConnectFailure{Status: status, Code: code, Message: message}
}

func newVPNConnectionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate connection identity: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func decodeVPNConnectRequest(r *http.Request) (vpnConnectRequest, error) {
	var req vpnConnectRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, fmt.Errorf("decode connect request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return req, fmt.Errorf("decode connect request: trailing JSON data")
	}
	if req.Protocol == "" {
		req.Protocol = "smart_auto"
	}
	switch req.Protocol {
	case "wireguard", "smart_auto", "wss", "masque", "openvpn", "ikev2":
	default:
		return req, fmt.Errorf("invalid protocol")
	}
	if req.SelectionMode == "" {
		if req.ServerID == "" {
			req.SelectionMode = settings.SelectionModeAutomatic
		} else {
			req.SelectionMode = settings.SelectionModeManual
		}
	}
	if !req.SelectionMode.Valid() {
		return req, fmt.Errorf("invalid selection_mode")
	}
	if req.SelectionMode == settings.SelectionModeManual {
		if !isValidUUID(req.ServerID) {
			return req, fmt.Errorf("valid server_id required in manual mode")
		}
	} else if req.ServerID != "" {
		return req, fmt.Errorf("server_id must be empty in automatic mode")
	}
	return req, nil
}

func decodeVPNDisconnectRequest(r *http.Request) (vpnDisconnectRequest, error) {
	var req vpnDisconnectRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, fmt.Errorf("decode disconnect request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return req, fmt.Errorf("decode disconnect request: trailing JSON data")
	}
	if req.ConnectionID == "" {
		return req, fmt.Errorf("connection_id required")
	}
	if req.Reason != disconnectReasonUserRequest && req.Reason != disconnectReasonServerSwitch {
		return req, fmt.Errorf("invalid disconnect reason")
	}
	return req, nil
}
