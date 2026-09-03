// Package httpx centralizes bounded HTTP clients, servers, and remote response
// reads used by the MidoriVPN desktop agent.
package httpx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	MaxHeaderBytes   = 64 << 10
	MaxResponseBytes = 1 << 20

	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 90 * time.Second
)

var ErrResponseTooLarge = errors.New("remote response exceeds configured limit")

func ReadBody(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("negative response limit")
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrResponseTooLarge
	}
	return body, nil
}

func NewClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            dialer.DialContext,
			ForceAttemptHTTP2:      true,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:           64,
			MaxIdleConnsPerHost:    8,
			MaxConnsPerHost:        16,
			MaxResponseHeaderBytes: MaxHeaderBytes,
			IdleConnTimeout:        90 * time.Second,
			TLSHandshakeTimeout:    5 * time.Second,
			ResponseHeaderTimeout:  10 * time.Second,
			ExpectContinueTimeout:  time.Second,
		},
	}
}

func NewAPIServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
	}
}

// NewTunnelServer leaves read/write deadlines at zero after CONNECT hijacking
// while bounding request headers and idle HTTP keep-alive connections.
func NewTunnelServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
	}
}

// AllowStreaming clears server-level deadlines for an explicitly long-lived
// SSE or upgraded connection.
func AllowStreaming(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
}

type RemoteError struct {
	Operation     string
	Code          string
	Status        int
	ResponseBytes int
	cause         error
}

func NewRemoteError(operation, code string, status, responseBytes int, cause error) *RemoteError {
	return &RemoteError{Operation: operation, Code: code, Status: status, ResponseBytes: responseBytes, cause: cause}
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("remote operation %s failed (%s, status=%d, response_bytes=%d)", e.Operation, e.Code, e.Status, e.ResponseBytes)
}

func (e *RemoteError) Unwrap() error {
	return e.cause
}
