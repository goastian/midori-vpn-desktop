package rpc

import (
	"testing"

	"github.com/goastian/midorivpn-agent/internal/deviceidentity"
)

func TestDeviceRegistrationPreservesStableIdentityContract(t *testing.T) {
	identity := deviceidentity.Identity{
		ClientInstanceID: "88a4e639-54f9-4b57-9460-671c95136adf",
		ReportedName:     "Tecno-09",
		Alias:            "Personal laptop",
		DeviceType:       deviceidentity.DeviceTypeDesktop,
		AdapterReference: "net-v1:1234567890123456789012345678901234567890123",
		AdapterKind:      deviceidentity.AdapterKindEthernet,
	}

	registration := deviceRegistration(identity)
	if registration.ClientInstanceID != identity.ClientInstanceID ||
		registration.ReportedName != identity.ReportedName ||
		registration.DeviceType != identity.DeviceType ||
		registration.AdapterReference != identity.AdapterReference {
		t.Fatalf("deviceRegistration() = %#v, want persistent identity fields", registration)
	}
}
