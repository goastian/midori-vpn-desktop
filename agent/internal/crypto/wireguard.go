package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// WireGuardKeypair contains an ephemeral client keypair. The private key is
// generated and consumed locally and must never be sent to vpn-core.
type WireGuardKeypair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateWireGuardKeypair creates a Curve25519 keypair in WireGuard's
// standard base64 representation.
func GenerateWireGuardKeypair() (*WireGuardKeypair, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("generate wireguard private key: %w", err)
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive wireguard public key: %w", err)
	}

	return &WireGuardKeypair{
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}
