//go:build !linux

package ikev2

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
	return nil, errors.New("IKEv2 is only available on Linux")
}

func (c *Client) Close()                             {}
func (c *Client) InterfaceName() string              { return "" }
func (c *Client) AssignedIP() string                 { return "" }
func (c *Client) ByteCounters() (int64, int64, bool) { return 0, 0, false }
