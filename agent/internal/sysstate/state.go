// Package sysstate tracks runtime system mutations made by the agent so they
// can be atomically reverted on shutdown (SIGTERM, explicit cleanup, or Tauri
// exit). All operations are idempotent and best-effort: each step logs its
// outcome but does not block other steps.
package sysstate

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Mutation is a named system change with an associated revert function.
type Mutation struct {
	Name   string
	Revert func(ctx context.Context)
}

// Registry holds all mutations recorded during the agent's lifetime.
type Registry struct {
	mu        sync.Mutex
	mutations []Mutation
}

// Global is the process-wide singleton registry. All packages record their
// mutations here so Shutdown() can revert everything in reverse order.
var Global = &Registry{}

// Record adds a mutation to the registry. The revert function will be called
// during shutdown in LIFO (last-in, first-out) order.
func (r *Registry) Record(name string, revert func(ctx context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mutations = append(r.mutations, Mutation{Name: name, Revert: revert})
	slog.Debug("sysstate: recorded mutation", "name", name)
}

// RevertAll calls every recorded revert function in reverse registration order
// (LIFO), then clears the registry. Safe to call multiple times; a second call
// is a no-op if the registry is already empty.
func (r *Registry) RevertAll(ctx context.Context) {
	r.mu.Lock()
	muts := r.mutations
	r.mutations = nil
	r.mu.Unlock()

	if len(muts) == 0 {
		return
	}

	slog.Info("sysstate: reverting system mutations", "count", len(muts))
	for i := len(muts) - 1; i >= 0; i-- {
		m := muts[i]
		slog.Info("sysstate: reverting", "mutation", m.Name)
		func() {
			defer func() {
				if v := recover(); v != nil {
					slog.Warn("sysstate: revert panicked", "mutation", m.Name, "panic", v)
				}
			}()
			m.Revert(ctx)
		}()
	}
	slog.Info("sysstate: all mutations reverted")
}

// RevertByPrefix reverts and removes only mutations whose names match one of
// the given prefixes. This lets feature toggles clean up their own system
// changes immediately without waiting for agent shutdown.
func (r *Registry) RevertByPrefix(ctx context.Context, prefixes ...string) {
	r.mu.Lock()
	kept := r.mutations[:0]
	var matched []Mutation
	for _, m := range r.mutations {
		if hasAnyPrefix(m.Name, prefixes) {
			matched = append(matched, m)
		} else {
			kept = append(kept, m)
		}
	}
	r.mutations = kept
	r.mu.Unlock()

	if len(matched) == 0 {
		return
	}

	slog.Info("sysstate: reverting selected system mutations", "count", len(matched))
	for i := len(matched) - 1; i >= 0; i-- {
		m := matched[i]
		slog.Info("sysstate: reverting", "mutation", m.Name)
		func() {
			defer func() {
				if v := recover(); v != nil {
					slog.Warn("sysstate: revert panicked", "mutation", m.Name, "panic", v)
				}
			}()
			m.Revert(ctx)
		}()
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}
