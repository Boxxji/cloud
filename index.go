// SPDX-License-Identifier: Apache-2.0 OR MIT

package cloud

import (
	"context"

	"github.com/zap-proto/zip"
)

// Capability is one row of the capability index: a product this process serves,
// the address it answers at, and what it is for (HIP-0139).
type Capability struct {
	// Name is the subsystem's name, the one CLOUD_ENABLE takes.
	Name string `json:"name"`
	// Href is the address the subsystem is mounted at.
	Href string `json:"href"`
	// Stage is how settled the capability is. Every mounted subsystem is "ga".
	Stage string `json:"stage"`
	// Description is one sentence saying what the capability is for.
	Description string `json:"description"`
}

// Capabilities is the GET /v1 body.
type Capabilities struct {
	// Capabilities lists every subsystem this deployment mounted, in mount order.
	Capabilities []Capability `json:"capabilities"`
}

// capabilities builds the index from the specs that are enabled. A subsystem that
// is linked but not enabled is not served, so it is not listed.
func capabilities(specs []MountSpec, cfg *Config) Capabilities {
	out := Capabilities{Capabilities: []Capability{}}
	for _, s := range specs {
		if !cfg.Enabled(s.Name) {
			continue
		}
		href := s.Prefix
		if href == "" {
			href = "/v1/" + s.Name
		}
		out.Capabilities = append(out.Capabilities, Capability{
			Name: s.Name, Href: href, Stage: "ga", Description: s.Description,
		})
	}
	return out
}

// mountIndex registers GET /v1: what this process serves, so a client can find the
// rest of the API from one unauthenticated read. It grants nothing; every
// subsystem it names stays gated by its own rules.
func mountIndex(app *zip.App, specs []MountSpec, cfg *Config) {
	index := capabilities(specs, cfg)
	app.Get("/v1", func(context.Context, *struct{}) (*Capabilities, error) {
		return &index, nil
	})
}
