package failover

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSelectUsesThreeSuccessfulProbesAndLowestMedian(t *testing.T) {
	var fastCalls atomic.Int32
	fast := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.URL.Path != ProbePath {
			t.Fatalf("unexpected fast probe: %s %s", r.Method, r.URL.Path)
		}
		fastCalls.Add(1)
		time.Sleep(2 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer fast.Close()
	var slowCalls atomic.Int32
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		slowCalls.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer slow.Close()

	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // ephemeral test certificates
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	prober := NewProber(client, time.Second, 2)
	selected, err := prober.Select(context.Background(), []Candidate{
		{ID: "slow", ProbeURL: slow.URL + ProbePath, Priority: 100},
		{ID: "fast", ProbeURL: fast.URL + ProbePath, Priority: 1},
	})
	if err != nil || selected.Candidate.ID != "fast" {
		t.Fatalf("Select() = %#v, %v", selected, err)
	}
	if fastCalls.Load() != 3 || slowCalls.Load() != 3 {
		t.Fatalf("probe calls fast=%d slow=%d, want 3 each", fastCalls.Load(), slowCalls.Load())
	}
}

func TestSelectFailsClosedWhenAProbeFails(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	prober := NewProber(server.Client(), time.Second, 1)
	if _, err := prober.Select(context.Background(), []Candidate{{
		ID: "partial", ProbeURL: server.URL + ProbePath,
	}}); err != ErrNoReachableCandidate {
		t.Fatalf("Select() error = %v, want %v", err, ErrNoReachableCandidate)
	}
	if calls.Load() != 3 {
		t.Fatalf("probe calls = %d, want 3", calls.Load())
	}
}

func TestSelectBoundsGlobalProbeParallelism(t *testing.T) {
	var current atomic.Int32
	var maximum atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		active := current.Add(1)
		defer current.Add(-1)
		for {
			observed := maximum.Load()
			if active <= observed || maximum.CompareAndSwap(observed, active) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	prober := NewProber(server.Client(), time.Second, 2)
	_, err := prober.Select(context.Background(), []Candidate{
		{ID: "one", ProbeURL: server.URL + ProbePath},
		{ID: "two", ProbeURL: server.URL + ProbePath},
		{ID: "three", ProbeURL: server.URL + ProbePath},
	})
	if err != nil {
		t.Fatalf("Select(): %v", err)
	}
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum concurrent probes = %d, want 2", got)
	}
}

func TestValidProbeURLRequiresExactHTTPSContract(t *testing.T) {
	for value, want := range map[string]bool{
		"https://edge.example.test/.well-known/midorivpn/edge-health":      true,
		"http://edge.example.test/.well-known/midorivpn/edge-health":       false,
		"https://user@edge.example.test/.well-known/midorivpn/edge-health": false,
		"https://edge.example.test/health":                                 false,
		"https://edge.example.test/.well-known/midorivpn/edge-health?q=1":  false,
	} {
		if got := ValidProbeURL(value); got != want {
			t.Fatalf("ValidProbeURL(%q) = %t, want %t", value, got, want)
		}
	}
}

func TestFailureTrackerRequiresThreeConsecutiveFailures(t *testing.T) {
	var tracker FailureTracker
	if tracker.Observe(false) {
		t.Fatal("tracker switched before three failures")
	}
	if tracker.Observe(false) {
		t.Fatal("tracker switched before three failures")
	}
	if !tracker.Observe(false) {
		t.Fatal("tracker did not switch on third failure")
	}
	tracker.Observe(true)
	if tracker.Observe(false) {
		t.Fatal("success did not reset failure sequence")
	}
	if tracker.Observe(false) {
		t.Fatal("success did not reset failure sequence")
	}
}

func TestRetryDelayScheduleAndJitterBounds(t *testing.T) {
	tests := []struct {
		attempt int
		low     time.Duration
		high    time.Duration
	}{
		{0, 4 * time.Second, 6 * time.Second},
		{1, 8 * time.Second, 12 * time.Second},
		{2, 16 * time.Second, 24 * time.Second},
		{3, 32 * time.Second, 48 * time.Second},
		{4, 48 * time.Second, 72 * time.Second},
		{99, 48 * time.Second, 72 * time.Second},
	}
	for _, test := range tests {
		if got := RetryDelay(test.attempt, 0); got != test.low {
			t.Fatalf("RetryDelay(%d, 0) = %s, want %s", test.attempt, got, test.low)
		}
		if got := RetryDelay(test.attempt, 1); got != test.high {
			t.Fatalf("RetryDelay(%d, 1) = %s, want %s", test.attempt, got, test.high)
		}
	}
}
