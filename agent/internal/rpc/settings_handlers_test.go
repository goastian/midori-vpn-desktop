package rpc

import (
	"testing"

	"github.com/goastian/midorivpn-agent/internal/settings"
)

func TestMergeVPNSettingsValidatesManualPin(t *testing.T) {
	automatic := settings.SelectionModeAutomatic
	manual := settings.SelectionModeManual
	invalid := settings.SelectionMode("nearest")
	validID := "7dfcc1cc-df12-42ec-bc8e-3d2a616ab1d7"

	if got, err := mergeVPNSettings(settings.VPNSettings{SelectionMode: manual, ManualServerID: validID}, &vpnSettingsPatch{
		SelectionMode: &automatic,
	}); err != nil || got.SelectionMode != automatic || got.ManualServerID != "" {
		t.Fatalf("automatic settings = %#v, %v", got, err)
	}
	if _, err := mergeVPNSettings(settings.VPNSettings{SelectionMode: automatic}, &vpnSettingsPatch{
		SelectionMode: &manual,
	}); err == nil {
		t.Fatal("manual mode without a canonical server ID was accepted")
	}
	if _, err := mergeVPNSettings(settings.VPNSettings{SelectionMode: automatic}, &vpnSettingsPatch{
		SelectionMode: &invalid,
	}); err == nil {
		t.Fatal("unknown selection mode was accepted")
	}
	if got, err := mergeVPNSettings(settings.VPNSettings{SelectionMode: automatic}, &vpnSettingsPatch{
		SelectionMode: &manual, ManualServerID: &validID,
	}); err != nil || got.SelectionMode != manual || got.ManualServerID != validID {
		t.Fatalf("manual settings = %#v, %v", got, err)
	}
}
