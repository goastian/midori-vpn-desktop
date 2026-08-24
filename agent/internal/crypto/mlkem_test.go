package crypto_test

import (
	"encoding/base64"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/crypto"
)

func TestMLKEM768_Roundtrip(t *testing.T) {
	clientKeypair, err := crypto.GenerateMLKEM768Keypair()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Keypair failed: %v", err)
	}

	serverSharedKeyB64, ciphertextB64, err := crypto.EncapsulateSharedKey(clientKeypair.EncapsulationKeyB64)
	if err != nil {
		t.Fatalf("EncapsulateSharedKey failed: %v", err)
	}

	serverSharedKeyBytes, err := base64.StdEncoding.DecodeString(serverSharedKeyB64)
	if err != nil {
		t.Fatalf("Decode serverSharedKeyB64 failed: %v", err)
	}
	if len(serverSharedKeyBytes) != 32 {
		t.Fatalf("Expected 32-byte shared key, got %d bytes", len(serverSharedKeyBytes))
	}

	clientSharedKeyB64, err := crypto.DecapsulateSharedKey(clientKeypair.DecapsulationKey, ciphertextB64)
	if err != nil {
		t.Fatalf("DecapsulateSharedKey failed: %v", err)
	}

	if serverSharedKeyB64 != clientSharedKeyB64 {
		t.Fatalf("Shared keys mismatch:\nserver: %s\nclient: %s", serverSharedKeyB64, clientSharedKeyB64)
	}
}
