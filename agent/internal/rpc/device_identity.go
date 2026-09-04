package rpc

import (
	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/deviceidentity"
)

// deviceRegistration is the single boundary between the private local
// identity store and every Core enrollment path. Keeping it centralized
// prevents WireGuard and certificate transports from drifting apart.
func deviceRegistration(identity deviceidentity.Identity) apiClient.DeviceRegistration {
	return apiClient.DeviceRegistration{
		ClientInstanceID: identity.ClientInstanceID,
		ReportedName:     identity.ReportedName,
		DeviceType:       identity.DeviceType,
		AdapterReference: identity.AdapterReference,
	}
}
