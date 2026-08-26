// Package devicepki owns device-generated certificate keys and credentials.
// Private keys never leave this package except as short-lived, mode-0600 files
// required by native VPN clients.
package devicepki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrNotFound = errors.New("device certificate not found")

type Credential struct {
	CertificateID    string    `json:"certificate_id"`
	ServerID         string    `json:"server_id"`
	DeviceName       string    `json:"device_name"`
	Identity         string    `json:"identity"`
	CertificatePEM   string    `json:"certificate_pem"`
	CACertificatePEM string    `json:"ca_certificate_pem"`
	PrivateKeyPEM    string    `json:"private_key_pem"`
	NotAfter         time.Time `json:"not_after"`
}

type Request struct {
	PrivateKeyPEM string
	CSRPEM        string
}

// NewRequest creates a protocol-compatible P-256 key and CSR locally.
func NewRequest(deviceName string) (*Request, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal device key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.TrimSpace(deviceName)},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create device CSR: %w", err)
	}
	return &Request{
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		CSRPEM:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	}, nil
}

// Validate verifies the complete credential chain, key match, client-auth
// usage, identity and expected server before it is persisted or executed.
func (c *Credential) Validate(expectedServerID string, now time.Time) error {
	if c.ServerID == "" || c.ServerID != expectedServerID {
		return errors.New("device certificate server does not match request")
	}
	cert, err := parseSingleCertificate(c.CertificatePEM)
	if err != nil {
		return fmt.Errorf("parse device certificate: %w", err)
	}
	ca, err := parseSingleCertificate(c.CACertificatePEM)
	if err != nil {
		return fmt.Errorf("parse device CA certificate: %w", err)
	}
	key, err := parseECPrivateKey(c.PrivateKeyPEM)
	if err != nil {
		return err
	}
	certPublic, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPublic.Equal(&key.PublicKey) {
		return errors.New("device certificate does not match local private key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("verify device certificate: %w", err)
	}
	if c.CertificateID == "" || cert.Subject.CommonName != "device:"+c.CertificateID {
		return errors.New("device certificate identity does not match certificate id")
	}
	expectedIdentity := "urn:midorivpn:device:" + c.CertificateID
	if len(cert.URIs) != 1 || cert.URIs[0].String() != expectedIdentity {
		return errors.New("device certificate URI identity is invalid")
	}
	if c.Identity != expectedIdentity {
		return errors.New("stored device identity is invalid")
	}
	if !c.NotAfter.Equal(cert.NotAfter) {
		return errors.New("stored certificate expiry is invalid")
	}
	return nil
}

func parseSingleCertificate(value string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseECPrivateKey(value string) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PKCS#8 private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse device private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || ecKey.Curve != elliptic.P256() {
		return nil, errors.New("device private key must use ECDSA P-256")
	}
	return ecKey, nil
}

type RuntimeFiles struct {
	Directory       string
	CertificatePath string
	CAPath          string
	PrivateKeyPath  string
}

// Materialize writes a validated credential only into the per-user runtime
// directory. Close must be called as soon as the native client exits.
func (c *Credential) Materialize() (*RuntimeFiles, error) {
	base := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR"))
	if base == "" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, "midorivpn-pki-")
	if err != nil {
		return nil, fmt.Errorf("create credential runtime directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("secure credential runtime directory: %w", err)
	}
	files := &RuntimeFiles{
		Directory:       dir,
		CertificatePath: filepath.Join(dir, "device.crt"),
		CAPath:          filepath.Join(dir, "ca.crt"),
		PrivateKeyPath:  filepath.Join(dir, "device.key"),
	}
	for path, value := range map[string]string{
		files.CertificatePath: c.CertificatePEM,
		files.CAPath:          c.CACertificatePEM,
		files.PrivateKeyPath:  c.PrivateKeyPEM,
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			_ = files.Close()
			return nil, fmt.Errorf("write runtime credential: %w", err)
		}
	}
	return files, nil
}

func (f *RuntimeFiles) Close() error {
	if f == nil || f.Directory == "" {
		return nil
	}
	dir := f.Directory
	f.Directory = ""
	return os.RemoveAll(dir)
}

func encodeCredential(c Credential) ([]byte, error) { return json.Marshal(c) }
func decodeCredential(data []byte) (Credential, error) {
	var c Credential
	err := json.Unmarshal(data, &c)
	return c, err
}
