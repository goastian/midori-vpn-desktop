package rpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/devicepki"
)

const certificateRenewalWindow = 24 * time.Hour

func (s *Server) ensureDeviceCredential(ctx context.Context, serverID string) (*devicepki.Credential, error) {
	if s.devicePKI == nil {
		return nil, errors.New("secret service is required for certificate-based VPN transports")
	}
	now := time.Now()
	credential, err := s.devicePKI.Load(serverID)
	if err == nil {
		if validationErr := credential.Validate(serverID, now); validationErr == nil && now.Add(certificateRenewalWindow).Before(credential.NotAfter) {
			return &credential, nil
		}
	} else if !errors.Is(err, devicepki.ErrNotFound) {
		return nil, fmt.Errorf("load device credential: %w", err)
	}

	deviceName := localDeviceName()
	request, err := devicepki.NewRequest(deviceName)
	if err != nil {
		return nil, err
	}
	enrollment, err := s.apiClient.EnrollDeviceCertificate(ctx, serverID, deviceName, request.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("enroll device certificate: %w", err)
	}
	credential = devicepki.Credential{
		CertificateID:    enrollment.Certificate.ID,
		ServerID:         enrollment.Certificate.ServerID,
		DeviceName:       enrollment.Certificate.DeviceName,
		Identity:         "urn:midorivpn:device:" + enrollment.Certificate.ID,
		CertificatePEM:   enrollment.Certificate.CertificatePEM,
		CACertificatePEM: enrollment.CACertificatePEM,
		PrivateKeyPEM:    request.PrivateKeyPEM,
		NotAfter:         enrollment.Certificate.NotAfter,
	}
	if err := credential.Validate(serverID, now); err != nil {
		_ = s.apiClient.RevokeDeviceCertificate(context.Background(), enrollment.Certificate.ID)
		return nil, fmt.Errorf("validate enrolled device credential: %w", err)
	}
	if err := s.devicePKI.Save(credential); err != nil {
		revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.apiClient.RevokeDeviceCertificate(revokeCtx, enrollment.Certificate.ID)
		return nil, fmt.Errorf("persist device credential: %w", err)
	}
	return &credential, nil
}

// localDeviceName is stable on one installation without disclosing the raw
// machine-id or hostname to the service.
func localDeviceName() string {
	identifier, err := os.ReadFile("/etc/machine-id")
	if err != nil || strings.TrimSpace(string(identifier)) == "" {
		hostname, hostErr := os.Hostname()
		if hostErr != nil {
			return "linux-desktop"
		}
		identifier = []byte(hostname)
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(string(identifier))))
	return "linux-" + hex.EncodeToString(digest[:6])
}
