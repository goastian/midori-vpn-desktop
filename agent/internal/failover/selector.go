// Package failover implements fail-closed edge measurement and retry policy.
// It has no tunnel side effects; the RPC lifecycle owns network transitions.
package failover

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	ProbePath            = "/.well-known/midorivpn/edge-health"
	ProbesPerCandidate   = 3
	DefaultProbeTimeout  = 1500 * time.Millisecond
	DefaultParallelism   = 4
	FailuresBeforeSwitch = 3
)

var ErrNoReachableCandidate = errors.New("no reachable VPN edge candidate")

type Candidate struct {
	ID       string
	ProbeURL string
	Priority int
}

type Measurement struct {
	Candidate Candidate
	Median    time.Duration
}

type Prober struct {
	client      *http.Client
	timeout     time.Duration
	parallelism int
}

func NewProber(client *http.Client, timeout time.Duration, parallelism int) *Prober {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	if parallelism <= 0 {
		parallelism = DefaultParallelism
	}
	return &Prober{client: client, timeout: timeout, parallelism: parallelism}
}

func ValidProbeURL(raw string) bool {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	return err == nil &&
		parsed.Scheme == "https" &&
		parsed.Host != "" &&
		parsed.User == nil &&
		parsed.RawQuery == "" &&
		parsed.Fragment == "" &&
		parsed.Opaque == "" &&
		parsed.RawPath == "" &&
		parsed.Path == ProbePath
}

func (p *Prober) Probe(ctx context.Context, candidate Candidate) (time.Duration, bool) {
	if p == nil || p.client == nil || !ValidProbeURL(candidate.ProbeURL) {
		return 0, false
	}
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodHead, candidate.ProbeURL, nil)
	if err != nil {
		return 0, false
	}
	request.Header.Set("Cache-Control", "no-cache")
	started := time.Now()
	response, err := p.client.Do(request)
	elapsed := time.Since(started)
	if err != nil {
		return 0, false
	}
	response.Body.Close()
	return elapsed, response.StatusCode == http.StatusNoContent
}

// Select executes exactly three probes per valid candidate with bounded global
// parallelism. A candidate must pass all three probes; the smallest median wins.
// Priority and original order provide deterministic ties.
func (p *Prober) Select(ctx context.Context, candidates []Candidate) (Measurement, error) {
	type job struct{ index int }
	type result struct {
		index   int
		elapsed time.Duration
		ok      bool
	}

	valid := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.ID != "" && ValidProbeURL(candidate.ProbeURL) {
			valid = append(valid, candidate)
		}
	}
	if len(valid) == 0 {
		return Measurement{}, ErrNoReachableCandidate
	}

	jobs := make(chan job)
	results := make(chan result)
	workerCount := p.parallelism
	if max := len(valid) * ProbesPerCandidate; workerCount > max {
		workerCount = max
	}
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			for next := range jobs {
				elapsed, ok := p.Probe(ctx, valid[next.index])
				select {
				case results <- result{index: next.index, elapsed: elapsed, ok: ok}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range valid {
			for probe := 0; probe < ProbesPerCandidate; probe++ {
				select {
				case jobs <- job{index: index}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	durations := make([][]time.Duration, len(valid))
	expected := len(valid) * ProbesPerCandidate
	for received := 0; received < expected; received++ {
		select {
		case next := <-results:
			if next.ok {
				durations[next.index] = append(durations[next.index], next.elapsed)
			}
		case <-ctx.Done():
			return Measurement{}, ctx.Err()
		}
	}

	measurements := make([]Measurement, 0, len(valid))
	for index, samples := range durations {
		if len(samples) != ProbesPerCandidate {
			continue
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		measurements = append(measurements, Measurement{Candidate: valid[index], Median: samples[1]})
	}
	if len(measurements) == 0 {
		return Measurement{}, ErrNoReachableCandidate
	}
	sort.SliceStable(measurements, func(i, j int) bool {
		if measurements[i].Median != measurements[j].Median {
			return measurements[i].Median < measurements[j].Median
		}
		return measurements[i].Candidate.Priority > measurements[j].Candidate.Priority
	})
	return measurements[0], nil
}

type FailureTracker struct {
	consecutive int
}

func (tracker *FailureTracker) Observe(success bool) bool {
	if success {
		tracker.consecutive = 0
		return false
	}
	tracker.consecutive++
	return tracker.consecutive >= FailuresBeforeSwitch
}

func (tracker *FailureTracker) Reset() {
	tracker.consecutive = 0
}

var retrySchedule = [...]time.Duration{
	5 * time.Second,
	10 * time.Second,
	20 * time.Second,
	40 * time.Second,
	60 * time.Second,
}

// RetryDelay applies a bounded ±20 percent jitter. sample is clamped to [0,1]
// so tests and callers can inject a cryptographically or pseudo-random value.
func RetryDelay(attempt int, sample float64) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= len(retrySchedule) {
		attempt = len(retrySchedule) - 1
	}
	if sample < 0 {
		sample = 0
	}
	if sample > 1 {
		sample = 1
	}
	factor := 0.8 + (0.4 * sample)
	return time.Duration(float64(retrySchedule[attempt]) * factor)
}
