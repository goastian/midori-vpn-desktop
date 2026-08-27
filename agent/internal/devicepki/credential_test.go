package devicepki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewRequestKeepsP256PrivateKeyLocal(t *testing.T) {
	request, err := NewRequest("linux-test")
	if err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("invalid CSR: %v", err)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		t.Fatalf("CSR key = %T, want ECDSA P-256", csr.PublicKey)
	}
	privateKey, err := parseECPrivateKey(request.PrivateKeyPEM)
	if err != nil || !publicKey.Equal(&privateKey.PublicKey) {
		t.Fatalf("CSR and private key do not match: %v", err)
	}
}

func TestCredentialValidationAndRuntimePermissions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	id := "fd2649e9-bc30-47e4-9ea8-9f06d320e5e1"
	request, err := NewRequest("linux-test")
	if err != nil {
		t.Fatal(err)
	}
	credential := issueTestCredential(t, request, id, now)
	if err := credential.Validate("server-one", now); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if err := credential.Validate("other-server", now); err == nil {
		t.Fatal("Validate() accepted a credential for another server")
	}

	runtimeRoot := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeRoot)
	files, err := credential.Materialize()
	if err != nil {
		t.Fatal(err)
	}
	dir := files.Directory
	for _, path := range []string{files.CertificatePath, files.CAPath, files.PrivateKeyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat runtime file %s: %v", filepath.Base(path), err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("runtime file %s mode = %v", filepath.Base(path), info.Mode().Perm())
		}
	}
	if err := files.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("runtime credential directory remains after Close: %v", err)
	}
}

func TestCredentialValidationAcceptsOnlyX509PrecisionDifference(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	request, err := NewRequest("linux-test")
	if err != nil {
		t.Fatal(err)
	}
	credential := issueTestCredential(t, request, "fd2649e9-bc30-47e4-9ea8-9f06d320e5e1", now)
	credential.NotAfter = credential.NotAfter.Add(731 * time.Millisecond)
	if err := credential.Validate("server-one", now); err != nil {
		t.Fatalf("Validate() rejected subsecond JSON/X.509 precision difference: %v", err)
	}
	credential.NotAfter = credential.NotAfter.Add(time.Second)
	if err := credential.Validate("server-one", now); err == nil {
		t.Fatal("Validate() accepted a material certificate expiry mismatch")
	}
}

func issueTestCredential(t *testing.T, request *Request, id string, now time.Time) Credential {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	csrBlock, _ := pem.Decode([]byte(request.CSRPEM))
	csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
	identity, _ := url.Parse("urn:midorivpn:device:" + id)
	notAfter := now.Add(90 * 24 * time.Hour)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "device:" + id},
		NotBefore: now.Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{identity},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, ca, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return Credential{
		CertificateID: id, ServerID: "server-one", DeviceName: "linux-test",
		Identity:         "urn:midorivpn:device:" + id,
		CertificatePEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		CACertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		PrivateKeyPEM:    request.PrivateKeyPEM, NotAfter: notAfter,
	}
}
