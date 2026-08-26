package rpc

import (
	"errors"
	"net/http"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

func TestShouldRetryAutoMesh(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "country unavailable is explicit degraded state",
			err:  &apiClient.APIError{StatusCode: http.StatusServiceUnavailable, Code: "origin_country_unavailable", Message: "unavailable"},
			want: false,
		},
		{
			name: "other client errors are permanent",
			err:  &apiClient.APIError{StatusCode: http.StatusForbidden, Message: "forbidden"},
			want: false,
		},
		{
			name: "rate limiting is transient",
			err:  &apiClient.APIError{StatusCode: http.StatusTooManyRequests, Message: "slow down"},
			want: true,
		},
		{name: "network errors are transient", err: errors.New("network unavailable"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRetryAutoMesh(tt.err); got != tt.want {
				t.Fatalf("shouldRetryAutoMesh() = %v, want %v", got, tt.want)
			}
		})
	}
}
