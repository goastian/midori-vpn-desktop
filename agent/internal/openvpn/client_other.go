//go:build !linux

package openvpn

import (
	"context"
	"errors"
	"time"

	"github.com/goastian/midorivpn-agent/internal/devicepki"
)

type Config struct {
	Endpoint   string
	ServerName string
	Credential *devicepki.Credential
	Timeout    time.Duration
}

type Client struct{}

func Start(context.Context, Config) (*Client, error) {
	return nil, errors.New("OpenVPN DCO is only available on Linux")
}
func (*Client) Close()                             {}
func (*Client) InterfaceName() string              { return "" }
func (*Client) DNS() []string                      { return nil }
func (*Client) AssignedIP() string                 { return "" }
func (*Client) ByteCounters() (int64, int64, bool) { return 0, 0, false }
