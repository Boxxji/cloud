// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package blueprint is what a template costs to run, worked out before you deploy.
//
// Each deployable blueprint is a docker-compose stack
// (templates.hanzo.ai/blueprints/<id>/docker-compose.yml); this subsystem turns
// one into two things a deploying org and a console need:
//
//  1. its SBOM — the bill of container images/services the stack runs, and
//  2. a COMPUTE COST estimate — a per-hour rate derived from the services' summed
//     CPU/memory footprint through a documented rate card (estimate.go).
//
// That rate is what a console SHOWS as "~$X/mo to run" per template, and the basis
// a host can meter a deployment on. EstimateTemplate and EstimateService are the
// in-process entrypoints for it; Rates is the rate card they applied.
//
// It prices IMAGES: the bill of images a compose stack runs and the stack's
// footprint. A dependency SBOM keyed by image digest — the packages inside one
// image — is a different granularity and a different concern.
//
// Reference content, no store. The blueprints are embedded and validated once at
// mount (a malformed fixture fails the mount closed); there is no per-tenant state.
//
// Surface (/v1 only):
//
//	GET /v1/blueprint                 list blueprint ids + a cost summary   -> {data:[…]}
//	GET /v1/blueprint/sbom?template=<id>  one blueprint's SBOM + cost        -> Estimate
//	GET /v1/blueprint/sbom            batch: every blueprint's SBOM + cost   -> {data:[Estimate]}
//	GET /v1/blueprint/health          liveness + the active rate card       (not JWT-gated)
//
// The package imports zip and nothing of its host. Mount takes the host's router and
// a logger; the operator tunes the rate card with CLOUD_BLUEPRINT_UCPU_HR and
// CLOUD_BLUEPRINT_UGB_HR.
package blueprint
