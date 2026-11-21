// SPDX-License-Identifier: Apache-2.0 OR MIT

package template

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
)

// This file is the MEASUREMENT that typing the gallery did not move its wire.
// Every claim here is one the conversion could have broken silently: a status a
// typed op writes by declaration rather than by hand, a body key a struct drops
// where a map carried it, and — the one no status-code test would have caught —
// a query parameter zip's binder fills that this route has never accepted.

// galleryOps reads the OpenAPI document zip projects from the LIVE router: every
// operation the gallery serves, keyed "METHOD /path", with the operation object as
// a client reads it. Reading the router rather than the source is what makes this
// a gate and not a promise. The document round-trips through JSON so the walk sees
// exactly what is published.
func galleryOps(t *testing.T) (served map[string]map[string]any) {
	t.Helper()
	raw, err := json.Marshal(mountApp(t).OpenAPISpec())
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	var doc struct {
		Paths map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	served = map[string]map[string]any{}
	for path, item := range doc.Paths {
		if !strings.HasPrefix(path, "/v1/template") {
			continue
		}
		for method, op := range item {
			served[strings.ToUpper(method)+" "+path] = op
		}
	}
	return served
}

// TestEveryRouteIsDescribed is the closed ledger: the gallery serves five
// operations, so a sixth added goes red without anyone remembering to look, and
// every one carries its prose. zipdoc lifts a handler's doc comment into
// zipdoc_gen.go at BUILD time, so a package that loses its //go:generate directive
// keeps compiling perfectly while every operation goes back to publishing nothing.
func TestEveryRouteIsDescribed(t *testing.T) {
	served := galleryOps(t)
	if len(served) != 5 {
		keys := map[string]bool{}
		for k := range served {
			keys[k] = true
		}
		t.Fatalf("the gallery serves %d operations, not the 5 this ledger knows: %s", len(served), sorted(keys))
	}
	for key, op := range served {
		if d, _ := op["description"].(string); strings.TrimSpace(d) == "" {
			t.Errorf("%s publishes NO description — the OpenAPI prose and the MCP tool description are both empty", key)
		}
	}
}

// TestWriteStatusesAreUnmoved pins the three success statuses. zip writes 200 by
// default and 204 for a nil Out, so a create converted without zip.WithStatus(201)
// downgrades silently — a break for every client that checks the code — and a
// delete whose Out is a NAMED empty type publishes "200 with a body" for a route
// that answers 204 with none.
func TestWriteStatusesAreUnmoved(t *testing.T) {
	app := mountApp(t)
	kit := map[string]any{"slug": "status-kit", "title": "Status Kit"}

	if code, body := do(t, app, http.MethodPost, "/v1/template", "acme", kit); code != http.StatusCreated {
		t.Fatalf("publish want 201, got %d (%s)", code, body)
	}
	if code, body := do(t, app, http.MethodPut, "/v1/template/status-kit", "acme", kit); code != http.StatusOK {
		t.Fatalf("replace want 200, got %d (%s)", code, body)
	}
	code, body := do(t, app, http.MethodDelete, "/v1/template/status-kit", "acme", nil)
	if code != http.StatusNoContent {
		t.Fatalf("delete want 204, got %d (%s)", code, body)
	}
	if len(body) != 0 {
		t.Fatalf("delete answered 204 with a body: %s", body)
	}
}

// TestTheQueryStringCannotRedirectAWrite is the pin on `url:"-"`. zip's binder
// fills an In field from the QUERY as well as the body (typed.go bindURL: body,
// then query, then path), so a body field left URL-bindable silently starts
// accepting `?slug=` — and `?slug=` on a publish would create a kit under a name
// the body never asked for. The untyped handler this replaced read the body and
// nothing else, so the only wire-preserving answer is that the query is ignored.
func TestTheQueryStringCannotRedirectAWrite(t *testing.T) {
	app := mountApp(t)
	kit := map[string]any{"slug": "asked-for", "title": "Asked For"}

	if code, body := do(t, app, http.MethodPost, "/v1/template?slug=hijacked&title=Hijacked", "acme", kit); code != http.StatusCreated {
		t.Fatalf("publish want 201, got %d (%s)", code, body)
	}
	if code, _ := do(t, app, http.MethodGet, "/v1/template/asked-for", "acme", nil); code != http.StatusOK {
		t.Fatal("the query string redirected a publish: the kit the BODY named was not created")
	}
	if code, _ := do(t, app, http.MethodGet, "/v1/template/hijacked", "acme", nil); code != http.StatusNotFound {
		t.Fatal("the query string redirected a publish: a kit was created under the QUERY's slug")
	}
	code, body := do(t, app, http.MethodGet, "/v1/template/asked-for", "acme", nil)
	if code != http.StatusOK {
		t.Fatalf("get want 200, got %d", code)
	}
	var got StarterKit
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Title != "Asked For" {
		t.Fatalf("the query string overwrote a body field: title=%q, want %q", got.Title, "Asked For")
	}
}

// TestThePathOwnsTheIdentityOnReplace is the other half: on a PUT the path binds
// LAST, so a body slug can never rename a kit or redirect the write onto another
// one. That is the wire the untyped handler had — it overwrote the bound slug
// with the path param — and it is what keeps a write on the resource the URL named.
func TestThePathOwnsTheIdentityOnReplace(t *testing.T) {
	app := mountApp(t)
	for _, slug := range []string{"first", "second"} {
		if code, body := do(t, app, http.MethodPost, "/v1/template", "acme",
			map[string]any{"slug": slug, "title": strings.ToUpper(slug)}); code != http.StatusCreated {
			t.Fatalf("publish %s want 201, got %d (%s)", slug, code, body)
		}
	}
	code, body := do(t, app, http.MethodPut, "/v1/template/first", "acme",
		map[string]any{"slug": "second", "title": "Rewritten"})
	if code != http.StatusOK {
		t.Fatalf("replace want 200, got %d (%s)", code, body)
	}
	var got StarterKit
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Slug != "first" {
		t.Fatalf("the body renamed a kit: slug=%q, want %q", got.Slug, "first")
	}
	_, body = do(t, app, http.MethodGet, "/v1/template/second", "acme", nil)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Title != "SECOND" {
		t.Fatalf("a PUT on /first wrote /second: title=%q", got.Title)
	}
}

// TestCurationFieldsStayServerOwned pins the one thing the In deliberately does
// NOT carry. tier and rating are public-gallery curation; the untyped handler
// bound them and then cleared them, so a caller could always send them and never
// set them. Leaving them off the In keeps that wire AND stops every generated SDK
// offering two arguments the server discards.
func TestCurationFieldsStayServerOwned(t *testing.T) {
	app := mountApp(t)
	code, body := do(t, app, http.MethodPost, "/v1/template", "acme",
		map[string]any{"slug": "curated", "title": "Curated", "tier": 1, "rating": 4.9})
	if code != http.StatusCreated {
		t.Fatalf("publish want 201, got %d (%s)", code, body)
	}
	var got StarterKit
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Tier != nil || got.Rating != nil {
		t.Fatalf("a caller set gallery curation: tier=%v rating=%v", got.Tier, got.Rating)
	}
}

// TestBrowseIsOneKeyedList pins the browse envelope. The op returns a struct
// where a map[string]any used to be, and a struct drops any key its fields do not
// name — so this asserts the answer is still exactly {"data": [...]}.
func TestBrowseIsOneKeyedList(t *testing.T) {
	app := mountApp(t)
	code, body := do(t, app, http.MethodGet, "/v1/template", "", nil)
	if code != http.StatusOK {
		t.Fatalf("browse want 200, got %d", code)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(envelope) != 1 {
		t.Fatalf("browse answers %d keys, want exactly 1 (data)", len(envelope))
	}
	if _, ok := envelope["data"]; !ok {
		t.Fatal("browse lost its data key")
	}
}

// TestTheCallerComesFromTheHost is the structural claim every tenancy test here
// rests on. A typed op reads its tenant through the Deps the host supplied, so the
// claim is proved end to end through the REAL Mount: a validated caller is served,
// an anonymous one is refused.
func TestTheCallerComesFromTheHost(t *testing.T) {
	app := mountApp(t)
	if code, body := do(t, app, http.MethodPost, "/v1/template", "acme",
		map[string]any{"slug": "hosted", "title": "Hosted"}); code != http.StatusCreated {
		t.Fatalf("a validated caller got %d (%s) — the op saw no org", code, body)
	}
	if code, _ := do(t, app, http.MethodPost, "/v1/template", "",
		map[string]any{"slug": "anon", "title": "Anon"}); code != http.StatusUnauthorized {
		t.Fatalf("an anonymous write got %d, want 401", code)
	}
}

// TestTheCollectionRootHasNoTrailingSlash pins failure mode #9: declaring a
// group's root as its EMPTY leaf names "<prefix>/", and op.Path is the identity
// the document, the operationId, the MCP tool name and every generated SDK's URL
// all read. The router is non-strict, so nothing would break on the wire — it is
// visible only in the published artifact, which is the whole product surface.
func TestTheCollectionRootHasNoTrailingSlash(t *testing.T) {
	for key := range galleryOps(t) {
		if strings.HasSuffix(key, "/") {
			t.Errorf("%s publishes a trailing slash for a path this API has never served", key)
		}
	}
}

func sorted(m map[string]bool) string {
	return strings.Join(slices.Sorted(maps.Keys(m)), ", ")
}

// TestEveryPublishedFieldIsDescribed closes the half of the surface the op-level
// gate above cannot see. Typing a route documents its ADDRESS and its SHAPE; it
// does not document the shape's FIELDS, and those come from a different place —
// doc comments on the In/Out struct fields, which zipdoc lifts per field.
//
// It found twelve when it was written, and the split is the tell: publishKitIn
// and replaceKitIn — written AT the conversion — described every field, while
// StarterKit, the view all five routes answer with, described four of fourteen.
// So the REQUEST side of the gallery was documented and the RESPONSE side was
// not, in openapi.yaml, in every generated SDK and in every MCP inputSchema. The
// two that mattered most were `tier` and `rating`, which a caller could see are
// numbers and nowhere that they are public-catalog curation no request can set.
// Add a field to a view without saying what it is and this fails.
func TestEveryPublishedFieldIsDescribed(t *testing.T) {
	raw, err := json.Marshal(mountApp(t).OpenAPISpec())
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Description string `json:"description"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	if len(doc.Components.Schemas) == 0 {
		t.Fatal("no schemas in the document at all")
	}
	var bare []string
	for name, sch := range doc.Components.Schemas {
		for field, p := range sch.Properties {
			if strings.TrimSpace(p.Description) == "" {
				bare = append(bare, name+"."+field)
			}
		}
	}
	if len(bare) > 0 {
		sort.Strings(bare)
		t.Errorf("published propert(ies) with no description: %s\n"+
			"Every field of a published schema is read by SDK users and by a model choosing a tool. Write a "+
			"doc comment on the struct field and run: go generate ./apps/template",
			strings.Join(bare, ", "))
	}
}
