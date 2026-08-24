//go:build !linux

package rpc

type securityIssue struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	FixCmd string `json:"fix_cmd"`
	Level  string `json:"level"`
}

func installedCapabilitiesGranted() bool          { return true }
func setInstalledCapabilities(bool) (bool, error) { return true, nil }
func revokeInstalledCapabilities() (bool, error)  { return true, nil }
func autostartEnabled() bool                      { return false }
func setAutostart(bool, int, string) error        { return nil }
func inspectSystemSecurity() []securityIssue      { return nil }
