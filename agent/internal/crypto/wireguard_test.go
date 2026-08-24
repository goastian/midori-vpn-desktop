package crypto_test

import (
	"encoding/base64"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/crypto"
	"golang.org/x/crypto/curve25519"
)

func TestGenerateWireGuardKeypair(t *testing.T) {
	first, err := crypto.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair() error = %v", err)
	}
	second, err := crypto.GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("GenerateWireGuardKeypair() second error = %v", err)
	}
	if first.PrivateKey == second.PrivateKey {
		t.Fatal("generated private keys must be unique")
	}

	privateKey, err := base64.StdEncoding.DecodeString(first.PrivateKey)
	if err != nil || len(privateKey) != curve25519.ScalarSize {
		t.Fatalf("private key is not a 32-byte base64 scalar: len=%d err=%v", len(privateKey), err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(publicKey); got != first.PublicKey {
		t.Fatalf("public key mismatch: got %q want %q", got, first.PublicKey)
	}
}
