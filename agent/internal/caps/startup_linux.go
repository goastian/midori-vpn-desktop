//go:build linux

package caps

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// ValidateProcessPrivileges runs before any caller-controlled filesystem I/O.
// An older installation may still carry broad file capabilities: fail closed,
// rather than running this agent with DAC override or other unrelated powers.
func ValidateProcessPrivileges() error {
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() {
		return fmt.Errorf("run the agent as the desktop user, never root or setuid")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	return validateCapabilityMasks(data)
}

func validateCapabilityMasks(data [2]unix.CapUserData) error {
	const network = uint32(1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_NET_RAW)
	if (data[0].Effective|data[0].Permitted|data[0].Inheritable)&^network != 0 ||
		(data[1].Effective|data[1].Permitted|data[1].Inheritable) != 0 {
		return fmt.Errorf("only network capabilities are supported; reinstall and authorize network permissions again")
	}
	return nil
}
