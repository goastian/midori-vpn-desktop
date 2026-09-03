package rpc

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/devicepki"
	"github.com/goastian/midorivpn-agent/internal/state"
)

var canonicalUUID = regexp.MustCompile(`^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[1-8][[:xdigit:]]{3}-[89abAB][[:xdigit:]]{3}-[[:xdigit:]]{12}$`)

type deviceCertificateView struct {
	apiClient.DeviceCertificate
	IsThisDevice bool `json:"is_this_device"`
}

func (s *Server) handleListDeviceCertificates(w http.ResponseWriter, r *http.Request) {
	if !s.authMgr.LoggedIn() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	certificates, err := s.apiClient.ListDeviceCertificates(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "list device certificates: "+err.Error())
		return
	}
	result := make([]deviceCertificateView, 0, len(certificates))
	for _, certificate := range certificates {
		result = append(result, deviceCertificateView{
			DeviceCertificate: certificate,
			IsThisDevice:      s.isLocalDeviceCertificate(certificate),
		})
	}
	writeJSON(w, result)
}

func (s *Server) handleRevokeDeviceCertificate(w http.ResponseWriter, r *http.Request) {
	if !s.authMgr.LoggedIn() {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	certificateID := r.PathValue("id")
	if !canonicalUUID.MatchString(certificateID) {
		writeError(w, http.StatusBadRequest, "invalid certificate id")
		return
	}
	certificates, err := s.apiClient.ListDeviceCertificates(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "list device certificates: "+err.Error())
		return
	}
	var selected *apiClient.DeviceCertificate
	for index := range certificates {
		if certificates[index].ID == certificateID && certificates[index].RevokedAt == nil {
			selected = &certificates[index]
			break
		}
	}
	if selected == nil {
		writeError(w, http.StatusNotFound, "active device certificate not found")
		return
	}
	isLocal := s.isLocalDeviceCertificate(*selected)
	if isLocal {
		if vpn, ok := s.agent.Snapshot()["vpn"].(state.VPNStatus); ok && vpn.Connected && vpn.ServerID == selected.ServerID {
			writeStructuredError(w, http.StatusConflict, "ERR_CERTIFICATE_IN_USE", "Desconecta la VPN antes de revocar el certificado de este dispositivo.")
			return
		}
	}
	if err := s.apiClient.RevokeDeviceCertificate(r.Context(), selected.ID); err != nil {
		writeError(w, http.StatusBadGateway, "revoke device certificate: "+err.Error())
		return
	}
	localCredentialRemoved := false
	if isLocal && s.devicePKI != nil {
		credential, loadErr := s.devicePKI.Load(selected.ServerID)
		if loadErr == nil && credential.CertificateID == selected.ID {
			if deleteErr := s.devicePKI.Delete(selected.ServerID); deleteErr != nil {
				slog.Error("revoked local device certificate could not be removed", "server_id", selected.ServerID, "err", deleteErr)
				writeStructuredError(w, http.StatusInternalServerError, "ERR_LOCAL_CREDENTIAL_DELETE_FAILED", "El certificado fue revocado, pero no se pudo retirar del almacén local.")
				return
			}
			localCredentialRemoved = true
		} else if loadErr != nil && !errors.Is(loadErr, devicepki.ErrNotFound) {
			slog.Warn("local device certificate lookup failed after revocation", "server_id", selected.ServerID, "err", loadErr)
		}
	}
	writeJSON(w, map[string]any{"ok": true, "local_credential_removed": localCredentialRemoved})
}

func (s *Server) isLocalDeviceCertificate(certificate apiClient.DeviceCertificate) bool {
	if s.devicePKI == nil {
		return false
	}
	credential, err := s.devicePKI.Load(certificate.ServerID)
	if err != nil {
		if !errors.Is(err, devicepki.ErrNotFound) {
			slog.Warn("local device certificate lookup failed", "server_id", certificate.ServerID, "err", err)
		}
		return false
	}
	return credential.CertificateID == certificate.ID
}
