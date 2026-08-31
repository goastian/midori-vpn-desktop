package rpc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	disconnectReasonUserRequest  = "user_request"
	disconnectReasonServerSwitch = "server_switch"
)

type vpnDisconnectRequest struct {
	ConnectionID string `json:"connection_id"`
	Reason       string `json:"reason"`
}

func newVPNConnectionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate connection identity: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
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
