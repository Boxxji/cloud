// SPDX-License-Identifier: Apache-2.0 OR MIT

package admission

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hanzoai/cloud/clients/principal"
	"github.com/zap-proto/zip"
)

// Middleware wraps zip routes with pre-execution tenant budget + adaptive
// concurrency admission control and emits structured HIP-1348 budget_exhausted
// JSON responses on overload or spend-ceiling exhaustion.
func Middleware(lim Limiter) zip.Handler {
	if lim == nil {
		return func(c *zip.Ctx) error { return c.Next() }
	}
	return func(c *zip.Ctx) error {
		tenant, _ := principal.Org(c)
		release, exhausted := lim.Acquire(c.Context(), tenant)
		if exhausted != nil {
			retrySec := (exhausted.RetryAfterMs + 999) / 1000
			if retrySec < 1 {
				retrySec = 1
			}
			c.Fiber().Set("Retry-After", strconv.FormatInt(retrySec, 10))
			return c.JSON(exhausted.HTTPStatus, exhausted)
		}

		start := time.Now()
		err := c.Next()
		rtt := time.Since(start)

		status := c.Fiber().Response().StatusCode()
		outcome := ClassifyHTTPOutcome(status, err)
		release(rtt, outcome)
		return err
	}
}

// ClassifyHTTPOutcome maps downstream HTTP status codes and handler errors to
// limiter feedback outcomes.
func ClassifyHTTPOutcome(status int, err error) Outcome {
	if err != nil {
		if he, ok := err.(*zip.HTTPError); ok {
			status = he.Status
		} else {
			return OutcomeOverload
		}
	}
	switch {
	case status == 429 || status == 502 || status == 503 || status == 504:
		return OutcomeOverload
	case status >= 400 && status < 500:
		return OutcomeIgnore
	case status >= 500:
		return OutcomeOverload
	default:
		return OutcomeSuccess
	}
}

// Registry aggregates named endpoint limiters so operators and Enso/Cloud
// control planes can inspect live admission state through a typed op.
type Registry struct {
	mu       sync.RWMutex
	limiters map[string]Limiter
}

// NewRegistry creates an empty limiter registry.
func NewRegistry() *Registry {
	return &Registry{limiters: make(map[string]Limiter)}
}

// Put registers or replaces a named limiter.
func (r *Registry) Put(name string, lim Limiter) {
	if name == "" || lim == nil {
		return
	}
	r.mu.Lock()
	r.limiters[name] = lim
	r.mu.Unlock()
}

// SnapshotIn is the typed request for GET /v1/gateway/admission.
type SnapshotIn struct {
	Endpoint string `query:"endpoint" json:"endpoint,omitempty"`
}

// EndpointStats pairs an endpoint name with its live limiter snapshot.
type EndpointStats struct {
	Endpoint string `json:"endpoint"`
	Stats    Stats  `json:"stats"`
}

// SnapshotOut is the typed response for GET /v1/gateway/admission.
type SnapshotOut struct {
	Endpoints []EndpointStats `json:"endpoints"`
}

// RegisterOps mounts typed inspection operations onto app per LLM.md
// Architecture Invariant #1 (Typed Operations Only).
func RegisterOps(app *zip.App, reg *Registry) error {
	if app == nil {
		return fmt.Errorf("admission.RegisterOps: nil zip.App")
	}
	if reg == nil {
		return fmt.Errorf("admission.RegisterOps: nil Registry")
	}
	app.Get[SnapshotIn, SnapshotOut]("/v1/gateway/admission",
		func(_ context.Context, in *SnapshotIn) (*SnapshotOut, error) {
			reg.mu.RLock()
			defer reg.mu.RUnlock()

			if in != nil && in.Endpoint != "" {
				lim, ok := reg.limiters[in.Endpoint]
				if !ok {
					return nil, zip.ErrNotFound("unknown admission endpoint: " + in.Endpoint)
				}
				return &SnapshotOut{
					Endpoints: []EndpointStats{{Endpoint: in.Endpoint, Stats: lim.Snapshot()}},
				}, nil
			}

			names := make([]string, 0, len(reg.limiters))
			for k := range reg.limiters {
				names = append(names, k)
			}
			sort.Strings(names)
			out := make([]EndpointStats, 0, len(names))
			for _, name := range names {
				out = append(out, EndpointStats{
					Endpoint: name,
					Stats:    reg.limiters[name].Snapshot(),
				})
			}
			return &SnapshotOut{Endpoints: out}, nil
		},
		zip.WithOperationID("gateway_admission_snapshot"),
		zip.WithSummary("Inspect adaptive concurrency admission state across endpoints"),
		zip.WithTags("gateway"),
	)
	return nil
}
