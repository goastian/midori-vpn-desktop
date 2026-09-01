package state

import "testing"

func TestVPNConnectionProgressIsOwnedByOpaqueIdentity(t *testing.T) {
	agent := NewAgent()
	if got := agent.Snapshot()["vpn"].(VPNStatus).Phase; got != VPNPhaseDisconnected {
		t.Fatalf("initial phase = %q, want disconnected", got)
	}

	agent.BeginVPNConnection("first", "server-one", "ikev2")
	if !agent.UpdateVPNConnection("first", VPNPhaseNegotiating, "", "") {
		t.Fatal("current attempt did not advance")
	}
	agent.BeginVPNConnection("second", "server-two", "smart_auto")
	if agent.FailVPNConnection("first") {
		t.Fatal("superseded attempt changed current state")
	}

	vpn := agent.Snapshot()["vpn"].(VPNStatus)
	if vpn.ConnectionID != "second" || vpn.RequestedProtocol != "smart_auto" || vpn.Phase != VPNPhasePreparing {
		t.Fatalf("new attempt state = %#v", vpn)
	}
	if !agent.FailVPNConnection("second") {
		t.Fatal("current attempt failure was not published")
	}
	vpn = agent.Snapshot()["vpn"].(VPNStatus)
	if vpn.Phase != VPNPhaseError || vpn.ConnectionID != "" || vpn.RequestedProtocol != "smart_auto" {
		t.Fatalf("terminal failure state = %#v", vpn)
	}

	agent.SetVPN(VPNStatus{Connected: true, ConnectionID: "established", Phase: VPNPhaseConnected})
	if agent.FailVPNConnection("established") {
		t.Fatal("deferred failure overwrote an established tunnel")
	}
}
