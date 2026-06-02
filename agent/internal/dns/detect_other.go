//go:build !linux

package dns

// Detect returns a no-op backend on non-Linux platforms; DNS handling on
// macOS/Windows is performed by their platform-specific wg manager files.
func Detect() Backend { return noopBackend{} }

type noopBackend struct{}

func (noopBackend) Kind() Kind                          { return KindNone }
func (noopBackend) Apply(string, []string) error        { return nil }
func (noopBackend) Restore() error                      { return nil }
