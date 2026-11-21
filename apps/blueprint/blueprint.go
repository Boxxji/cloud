// SPDX-License-Identifier: Apache-2.0 OR MIT

package blueprint

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

//go:embed blueprints
var blueprintsFS embed.FS

// composeName is the compose file each blueprint dir carries. We accept the short
// name; the public path is templates.hanzo.ai/blueprints/<id>/docker-compose.yml.
const composeName = "compose.yml"

// Mount wires the blueprint surface and validates every embedded blueprint at boot.
// It asks its host for a logger and nothing else: the catalog is reference content
// embedded in the binary, the same for every caller.
func Mount(app *zip.App, log luxlog.Logger) error {
	if app == nil {
		return errors.New("blueprint: nil app")
	}
	rates = rateCardFromEnv() // overlay operator rate-card knobs once, at mount
	ids, err := validate()
	if err != nil {
		return err
	}
	log.Info("blueprint estimator",
		"blueprints", len(ids),
		"uUSDPerVCPUHr", rates.MicroUSDPerVCPUHour,
		"uUSDPerGBHr", rates.MicroUSDPerGBHour)
	routes(app)
	log.Info("blueprint mounted")
	return nil
}

// validate fails the mount closed if any embedded blueprint cannot be parsed and
// priced — a broken fixture must never reach a deploy sizing or a "$X/mo" card.
func validate() ([]string, error) {
	ids, err := catalogIDs()
	if err != nil {
		return nil, fmt.Errorf("blueprint: read embedded blueprints: %w", err)
	}
	if len(ids) == 0 {
		return nil, errors.New("blueprint: no embedded blueprints")
	}
	for _, id := range ids {
		if _, ok, err := estimateTemplate(id); err != nil {
			return nil, fmt.Errorf("blueprint: %q: %w", id, err)
		} else if !ok {
			return nil, fmt.Errorf("blueprint: %q: missing %s", id, composeName)
		}
	}
	return ids, nil
}

// routes registers the read surface. Health is registered before nothing greedy
// (the paths are exact), and is not JWT-gated (liveness must be probe-able).
func routes(app *zip.App) {
	o := ops{}
	g := app.Group("/v1/blueprint")
	g.Get("/health", o.health)
	// UNTYPED, and it has to be: ONE address answers with TWO shapes at 200 —
	// `?template=<id>` returns a bare Estimate, no template returns the
	// `{data:[Estimate]}` batch. A typed op declares one Out, so either shape
	// would publish the other as a lie. Convertible the day zip can declare a
	// polymorphic response (the #78 family).
	g.Raw(http.MethodGet, "/sbom", sbomRead)
	blueprint := app.Group("/v1/blueprint")
	blueprint.Get("", o.list)
}

// ops binds the typed blueprint ops. A TypedHandler takes no service parameter, so
// the ops arrive as a RECEIVER and every op is a method value — the only bound form
// cmd/zipdoc can lift prose from.
type ops struct{}

// noIn is the input of an op that takes nothing: no body, no path parameter, no
// query. GET carries no request body (zip's hasBody), so this publishes nothing.
type noIn struct{}

// ── in-process client ────────────────────────────────────────────────────────

// EstimateTemplate prices an embedded blueprint by id, returning ok=false for an
// unknown id. This is the ONE in-process entrypoint for a template's compute rate:
// est.MicroUSDPerHour is the exact per-hour figure a host meters a deployment on,
// and est.CentsPerMonth is the "~$X/mo to run" a console renders.
func EstimateTemplate(id string) (Estimate, bool) {
	est, ok, err := estimateTemplate(id)
	if !ok || err != nil {
		return Estimate{}, false
	}
	return est, true
}

// estimateTemplate is the internal form that surfaces a parse error (build uses it
// to fail closed; EstimateTemplate collapses it to ok=false for callers).
func estimateTemplate(id string) (Estimate, bool, error) {
	doc, ok := loadCompose(id)
	if !ok {
		return Estimate{}, false, nil
	}
	est, err := EstimateCompose(id, doc)
	if err != nil {
		return Estimate{}, true, err
	}
	return est, true, nil
}

// loadCompose reads an embedded blueprint's compose by id. id must be a bare slug
// (no path separators or dots) so it can never traverse out of the embed root.
func loadCompose(id string) ([]byte, bool) {
	if id == "" || strings.ContainsAny(id, "/\\.") {
		return nil, false
	}
	b, err := blueprintsFS.ReadFile(path.Join("blueprints", id, composeName))
	if err != nil {
		return nil, false
	}
	return b, true
}

// catalogIDs lists the embedded blueprint ids, sorted for deterministic output.
func catalogIDs() ([]string, error) {
	entries, err := fs.ReadDir(blueprintsFS, "blueprints")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// ── handlers ─────────────────────────────────────────────────────────────────

// sbomRead answers GET /v1/blueprint/sbom. With ?template=<id> it returns that
// blueprint's SBOM + cost (404 on an unknown id); with no template it returns the
// batch of every blueprint's estimate for a gallery grid.
func sbomRead(c *zip.Ctx) error {
	id := strings.TrimSpace(c.Query("template"))
	if id == "" {
		ids, err := catalogIDs()
		if err != nil {
			return zip.Errorf(http.StatusInternalServerError, "blueprint: %v", err)
		}
		out := make([]Estimate, 0, len(ids))
		for _, bid := range ids {
			if est, ok := EstimateTemplate(bid); ok {
				out = append(out, est)
			}
		}
		return c.JSON(http.StatusOK, map[string]any{"data": out})
	}
	est, ok := EstimateTemplate(id)
	if !ok {
		return zip.ErrNotFound("no blueprint " + id)
	}
	return c.JSON(http.StatusOK, est)
}

// blueprintRow is one entry of the blueprint index: which stack it is, how many
// services it runs, and what a month of that footprint costs at the active card.
type blueprintRow struct {
	// TemplateID is the blueprint slug — the id GET /v1/blueprint/sbom takes as
	// ?template= and the path under templates.hanzo.ai/blueprints/<id>/.
	TemplateID string `json:"templateId"`
	// Services is how many compose services the stack runs.
	Services int `json:"services"`
	// CentsPerMonth is the estimated compute cost of running the whole stack for
	// one month, in USD cents, from the rate card GET /v1/blueprint/health echoes.
	CentsPerMonth int64 `json:"estCentsPerMonth"`
}

// blueprintIndex is the GET /v1/blueprint envelope: every priced blueprint, id-sorted.
type blueprintIndex struct {
	// Data is one row per embedded blueprint, sorted by template id.
	Data []blueprintRow `json:"data"`
}

// list returns every deployable blueprint with its service count and estimated
// monthly compute cost.
//
// It is the lightweight index the console renders as a template gallery before
// drilling into one stack's bill of images — GET /v1/blueprint/sbom?template=<id>
// is the detail view. The cost is the same figure the deploy path meters the
// deploying org on and the 20% author royalty is taken from, priced from the
// active rate card (GET /v1/blueprint/health echoes that card).
func (o ops) list(ctx context.Context, _ *noIn) (*blueprintIndex, error) {
	ids, err := catalogIDs()
	if err != nil {
		return nil, zip.Errorf(http.StatusInternalServerError, "blueprint: %v", err)
	}
	out := make([]blueprintRow, 0, len(ids))
	for _, id := range ids {
		est, ok := EstimateTemplate(id)
		if !ok {
			continue
		}
		out = append(out, blueprintRow{TemplateID: id, Services: len(est.SBOM), CentsPerMonth: est.CentsPerMonth})
	}
	return &blueprintIndex{Data: out}, nil
}

// blueprintHealth is the GET /v1/blueprint/health body. Field order is the
// alphabetical key order the map it replaced marshalled in, so the bytes on the
// wire did not move when this route became a typed op.
type blueprintHealth struct {
	// Blueprints is how many blueprints this build has embedded and priced.
	Blueprints int `json:"blueprints"`
	// RateCard is the rate card actually in force after the operator env overlay
	// (CLOUD_BLUEPRINT_UCPU_HR / CLOUD_BLUEPRINT_UGB_HR), not the shipped default.
	RateCard RateCard `json:"rateCard"`
	// Service names the subsystem answering — always "blueprint".
	Service string `json:"service"`
	// Status is "ok"; the route answers 200 whenever the subsystem is mounted.
	Status string `json:"status"`
}

// health reports blueprint liveness and echoes the compute rate card in force.
//
// The rate card is the one the estimator actually applies after the operator env
// overlay, so an operator can confirm a tuned knob took effect rather than
// inferring it from a price. Not JWT-gated — a liveness probe must be reachable —
// and it always answers 200 while the subsystem is mounted.
func (o ops) health(ctx context.Context, _ *noIn) (*blueprintHealth, error) {
	ids, _ := catalogIDs()
	return &blueprintHealth{
		Blueprints: len(ids),
		RateCard:   rates,
		Service:    "blueprint",
		Status:     "ok",
	}, nil
}

// ── rate-card env overlay ────────────────────────────────────────────────────

// rateCardFromEnv overlays the two operator knobs on the shipped rate card. A
// non-positive or unset value keeps the default, so a partial or absent config
// never zeroes a rate (which would make every deployment appear free).
func rateCardFromEnv() RateCard {
	rc := DefaultRateCard()
	if v := positive("CLOUD_BLUEPRINT_UCPU_HR"); v > 0 {
		rc.MicroUSDPerVCPUHour = int64(v)
	}
	if v := positive("CLOUD_BLUEPRINT_UGB_HR"); v > 0 {
		rc.MicroUSDPerGBHour = int64(v)
	}
	return rc
}

// positive reads a positive integer from the environment and returns 0 when the
// variable is unset, malformed, or not positive.
func positive(key string) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
