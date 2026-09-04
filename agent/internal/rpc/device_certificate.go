package rpc

import (
	"context"
	"errors"
	"fmt"
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

	identity, err := s.deviceIdentity.Current()
	if err != nil {
		return nil, fmt.Errorf("load device identity: %w", err)
	}
	request, err := devicepki.NewRequest(identity.ReportedName)
	if err != nil {
		return nil, err
	}
	enrollment, err := s.apiClient.EnrollDeviceCertificate(ctx, serverID, deviceRegistration(identity), request.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("enroll device certificate: %w", err)
	}
	credential = devicepki.Credential{
		CertificateID:    enrollment.Certificate.ID,
		DeviceID:         enrollment.Certificate.DeviceID,
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
