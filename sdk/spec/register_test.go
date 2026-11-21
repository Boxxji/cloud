package spec

import (
	"reflect"
	"strings"
	"testing"
)

// unregister removes a test registration so the package-level registry stays
// clean across tests. Test-only: production registrations are for life.
func unregister(path, method string) {
	regMu.Lock()
	delete(registry, opKey{method: strings.ToUpper(method), path: path})
	regMu.Unlock()
}

type widgetReq struct {
	Name      string   `json:"name"`
	StorageGB int      `json:"storageGb"`
	Tags      []string `json:"tags"`
	Nested    struct {
		URL string `json:"url"`
	} `json:"nested"`
	Skipped string `json:"-"` // explicitly excluded
}

type widgetView struct {
	ID        string `json:"id"`
	StorageGB int    `json:"storageGb,omitempty"`
}

// A registered route renders its declared bodies: requestBody and a 2XX
// response, both by $ref to components reflected from the Go structs.
func TestRegisterMergesDeclaredBodies(t *testing.T) {
	Register("/v1/widgets/:id", "POST", widgetReq{}, widgetView{})
	t.Cleanup(func() { unregister("/v1/widgets/:id", "POST") })

	doc, err := From([]Route{{Method: "POST", Path: "/v1/widgets/:id"}}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	op := doc.Paths["/v1/widgets/{id}"]["post"]
	if op == nil {
		t.Fatal("missing operation")
	}
	// The Operation carries bodies as `any` (the typed fold shares the fields);
	// what Register produced is still its closed types, and asserting the
	// concrete type here IS part of the contract under test.
	body, ok := op.RequestBody.(*RequestBody)
	if !ok || body.Content["application/json"].Schema.Ref != "#/components/schemas/widgetReq" {
		t.Fatalf("requestBody = %+v, want *RequestBody with $ref widgetReq", op.RequestBody)
	}
	responses, ok := op.Responses.(map[string]*Response)
	if !ok {
		t.Fatalf("responses = %+v, want map[string]*Response", op.Responses)
	}
	resp := responses["2XX"]
	if resp == nil || resp.Content["application/json"].Schema.Ref != "#/components/schemas/widgetView" {
		t.Fatalf("responses = %+v, want 2XX $ref widgetView", op.Responses)
	}

	req, _ := doc.Components.Schemas["widgetReq"].(*Schema)
	if req == nil || req.Type != "object" {
		t.Fatalf("widgetReq component = %+v", req)
	}
	if p := req.Properties["storageGb"]; p == nil || p.Type != "integer" {
		t.Errorf("storageGb = %+v, want integer", p)
	}
	if p := req.Properties["tags"]; p == nil || p.Type != "array" || p.Items == nil || p.Items.Type != "string" {
		t.Errorf("tags = %+v, want array of string", p)
	}
	if p := req.Properties["nested"]; p == nil || p.Type != "object" || p.Properties["url"] == nil {
		t.Errorf("nested = %+v, want inline object with url", p)
	}
	if _, leaked := req.Properties["hidden"]; leaked {
		t.Error("unexported field leaked into the schema; encoding/json never emits it")
	}
	if _, leaked := req.Properties["-"]; leaked {
		t.Error(`json:"-" field leaked into the schema`)
	}
	if _, leaked := req.Properties["Skipped"]; leaked {
		t.Error(`json:"-" field leaked into the schema under its Go name`)
	}
}

// The NEGATIVES that keep the mechanism one-way:
//   - a route with no registration renders exactly as before — no requestBody,
//     no responses, no panic, and no components block appears for it;
//   - a registration whose route is NOT in the router renders NOTHING — the
//     registry cannot add a path or a schema the router does not carry.
func TestUnregisteredRouteAndOrphanRegistrationBothStayHonest(t *testing.T) {
	Register("/v1/ghosts", "POST", widgetReq{}, widgetView{})
	t.Cleanup(func() { unregister("/v1/ghosts", "POST") })

	// The route table carries only an UNregistered route.
	doc, err := From([]Route{{Method: "GET", Path: "/v1/plain"}}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	op := doc.Paths["/v1/plain"]["get"]
	if op == nil {
		t.Fatal("unregistered route must still render")
	}
	if op.RequestBody != nil || op.Responses != nil {
		t.Errorf("unregistered route grew bodies: %+v", op)
	}
	if doc.Components != nil {
		t.Errorf("orphan registration leaked components: %+v — schemas must attach only to live routes", doc.Components)
	}
	if _, ok := doc.Paths["/v1/ghosts"]; ok {
		t.Error("orphan registration minted a path — the registry must never add routes")
	}
}

// A duplicate Register for one (method, path) is an init-time programming error
// and must refuse loudly, not let two declarations race for one operation.
func TestRegisterRefusesDuplicate(t *testing.T) {
	Register("/v1/dups", "POST", widgetReq{}, nil)
	t.Cleanup(func() { unregister("/v1/dups", "POST") })
	defer func() {
		if recover() == nil {
			t.Fatal("second Register for the same (method, path) must panic")
		}
	}()
	Register("/v1/dups", "POST", widgetReq{}, nil)
}

// Two DIFFERENT Go types claiming one component name would hand an SDK
// generator a silently merged lie; From must refuse instead.
func TestFromRefusesComponentNameCollision(t *testing.T) {
	type collide struct { // local type: same name as the sibling below
		A string `json:"a"`
	}
	first := collide{}
	second := func() any {
		type collide struct {
			B int `json:"b"`
		}
		return collide{}
	}()

	Register("/v1/collide/a", "POST", first, nil)
	Register("/v1/collide/b", "POST", second, nil)
	t.Cleanup(func() {
		unregister("/v1/collide/a", "POST")
		unregister("/v1/collide/b", "POST")
	})

	_, err := From([]Route{
		{Method: "POST", Path: "/v1/collide/a"},
		{Method: "POST", Path: "/v1/collide/b"},
	}, Info{Title: "t", Version: "v1"})
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("From = %v, want a component-name collision error naming %q", err, "collide")
	}
}

// One view type shared by several routes (the platform appView shape) must
// yield ONE component, referenced from each — not an error, not a copy.
func TestSharedViewYieldsOneComponent(t *testing.T) {
	Register("/v1/shared", "GET", nil, widgetView{})
	Register("/v1/shared/list", "GET", nil, []widgetView{})
	t.Cleanup(func() {
		unregister("/v1/shared", "GET")
		unregister("/v1/shared/list", "GET")
	})

	doc, err := From([]Route{
		{Method: "GET", Path: "/v1/shared"},
		{Method: "GET", Path: "/v1/shared/list"},
	}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	if n := len(doc.Components.Schemas); n != 1 {
		t.Fatalf("components = %d, want exactly one widgetView", n)
	}
	list := doc.Paths["/v1/shared/list"]["get"].Responses.(map[string]*Response)["2XX"].Content["application/json"].Schema
	if list.Type != "array" || list.Items == nil || list.Items.Ref != "#/components/schemas/widgetView" {
		t.Fatalf("list schema = %+v, want array of $ref widgetView", list)
	}
}

// A POLYMORPHIC body renders `oneOf` over every declared alternative, in the
// order declared, and a named struct among them is the SAME component the other
// alternatives and other routes $ref — one shape, one name, however many wires
// mention it.
func TestOneOfRendersEveryAlternative(t *testing.T) {
	Register("/v1/poly", "POST", OneOf{widgetReq{}, []widgetReq{}, widgetView{}}, widgetView{})
	t.Cleanup(func() { unregister("/v1/poly", "POST") })

	doc, err := From([]Route{{Method: "POST", Path: "/v1/poly"}}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	body, ok := doc.Paths["/v1/poly"]["post"].RequestBody.(*RequestBody)
	if !ok {
		t.Fatalf("requestBody = %+v, want *RequestBody", doc.Paths["/v1/poly"]["post"].RequestBody)
	}
	got := body.Content["application/json"].Schema
	if got.Ref != "" || got.Type != "" {
		t.Errorf("polymorphic schema = %+v, want oneOf alone — naming one shape is the under-description this exists to avoid", got)
	}
	if len(got.OneOf) != 3 {
		t.Fatalf("oneOf = %d alternatives, want 3", len(got.OneOf))
	}
	if got.OneOf[0].Ref != "#/components/schemas/widgetReq" {
		t.Errorf("oneOf[0] = %+v, want $ref widgetReq", got.OneOf[0])
	}
	if got.OneOf[1].Type != "array" || got.OneOf[1].Items == nil || got.OneOf[1].Items.Ref != "#/components/schemas/widgetReq" {
		t.Errorf("oneOf[1] = %+v, want array of $ref widgetReq", got.OneOf[1])
	}
	if got.OneOf[2].Ref != "#/components/schemas/widgetView" {
		t.Errorf("oneOf[2] = %+v, want $ref widgetView", got.OneOf[2])
	}
	// Two alternatives and the response all name widgetReq/widgetView, so the
	// document carries exactly the two components those two Go types claim.
	if n := len(doc.Components.Schemas); n != 2 {
		t.Fatalf("components = %d, want 2 (widgetReq, widgetView)", n)
	}
}

// An empty OneOf is a declaration that says nothing while looking like one, so it
// is refused at registration rather than rendering an empty `oneOf: []`.
func TestEmptyOneOfIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Register(OneOf{}) did not panic")
		}
	}()
	Register("/v1/poly/empty", "POST", OneOf{}, nil)
}

// The prose half. A described route renders its summary and description
// verbatim; the same declaration on a route the router does not carry renders
// NOTHING — Describe cannot add an operation any more than Register can. Both
// halves on one operation compose: prose from Describe, bodies from Register,
// one declaration in two statements.
func TestDescribeRendersProseOnLiveRoutesOnly(t *testing.T) {
	Describe("/v1/widgets/:id/events", "GET",
		"Widget event stream.", "Holds the connection open as Server-Sent Events.")
	Describe("/v1/ghost/events", "GET", "Never renders.", "")
	Register("/v1/widgets/:id/events", "GET", nil, widgetView{})
	t.Cleanup(func() {
		unregister("/v1/widgets/:id/events", "GET")
		unregister("/v1/ghost/events", "GET")
	})

	doc, err := From([]Route{{Method: "GET", Path: "/v1/widgets/:id/events"}}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	op := doc.Paths["/v1/widgets/{id}/events"]["get"]
	if op == nil {
		t.Fatal("missing operation")
	}
	if op.Summary != "Widget event stream." || op.Description != "Holds the connection open as Server-Sent Events." {
		t.Errorf("prose = %q / %q, want the declared summary and description verbatim", op.Summary, op.Description)
	}
	responses, ok := op.Responses.(map[string]*Response)
	if !ok || responses["2XX"] == nil {
		t.Errorf("responses = %+v — a Describe must not displace the same op's Register", op.Responses)
	}
	if _, minted := doc.Paths["/v1/ghost/events"]; minted {
		t.Error("orphan Describe minted a path — the registry must never add routes")
	}
}

// A second Describe for one (method, path) is the same init-time programming
// error a second Register is — and a Register plus a Describe is NOT one, which
// is the other half of this contract: each half guards only itself.
func TestDescribeRefusesDuplicateButComposesWithRegister(t *testing.T) {
	Register("/v1/described", "GET", nil, widgetView{})
	Describe("/v1/described", "GET", "Once.", "")
	t.Cleanup(func() { unregister("/v1/described", "GET") })
	defer func() {
		if recover() == nil {
			t.Fatal("second Describe for the same (method, path) must panic")
		}
	}()
	Describe("/v1/described", "GET", "Twice.", "")
}

// A Describe with no summary and no description is a declaration that states
// nothing while looking like one — refused at declaration time, like OneOf{}.
func TestEmptyDescribeIsRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal(`Describe(path, method, "", "  ") did not panic`)
		}
	}()
	Describe("/v1/described/empty", "GET", "", "  ")
}

// A relayed operation's request body crosses beside its responses, so a client
// generated from the document has somewhere to put the body. It renders only on
// a route that exists, and a body declared by Register wins over it.
func TestTakesCarriesARelayedBody(t *testing.T) {
	body := map[string]any{
		"required": true,
		"content": map[string]any{"application/json": map[string]any{
			"schema": map[string]any{"type": "object", "properties": map[string]any{"model": map[string]any{"type": "string"}}},
		}},
	}
	Takes("/v1/relayed", "POST", body)
	Takes("/v1/ghost/relayed", "POST", body)
	Register("/v1/typed/relayed", "POST", widgetReq{}, widgetView{})
	Takes("/v1/typed/relayed", "POST", body)
	t.Cleanup(func() {
		unregister("/v1/relayed", "POST")
		unregister("/v1/ghost/relayed", "POST")
		unregister("/v1/typed/relayed", "POST")
	})

	doc, err := From([]Route{{Method: "POST", Path: "/v1/relayed"}, {Method: "POST", Path: "/v1/typed/relayed"}}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	if got := doc.Paths["/v1/relayed"]["post"].RequestBody; !reflect.DeepEqual(got, body) {
		t.Errorf("relayed requestBody = %v, want the source document's body verbatim", got)
	}
	if _, ok := doc.Paths["/v1/typed/relayed"]["post"].RequestBody.(*RequestBody); !ok {
		t.Errorf("typed requestBody = %T — a Register must win over a relayed body", doc.Paths["/v1/typed/relayed"]["post"].RequestBody)
	}
	if _, minted := doc.Paths["/v1/ghost/relayed"]; minted {
		t.Error("an orphan Takes minted a path — the registry must never add routes")
	}
}

// A relayed operation's headers cross beside its body, so a generated client takes
// them as arguments of the call. The path's own parameters come from the route and
// are not repeated, and an orphan declaration mints no path.
func TestParamsCarriesARelayedHeader(t *testing.T) {
	params := []any{
		map[string]any{"name": "X-Max-Cost", "in": "header", "required": false,
			"description": "The most this request may cost.", "schema": map[string]any{"type": "number"}},
		map[string]any{"name": "id", "in": "path", "required": true, "schema": map[string]any{"type": "string"}},
	}
	Params("/v1/relayed/:id", "POST", params)
	Params("/v1/ghost/params", "POST", params)
	t.Cleanup(func() {
		unregister("/v1/relayed/:id", "POST")
		unregister("/v1/ghost/params", "POST")
	})

	doc, err := From([]Route{{Method: "POST", Path: "/v1/relayed/:id"}}, Info{Title: "t", Version: "v1"})
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	got := doc.Paths["/v1/relayed/{id}"]["post"].Parameters
	want := []Parameter{
		{Name: "id", In: "path", Required: true, Schema: map[string]any{"type": "string"}},
		{Name: "X-Max-Cost", In: "header", Description: "The most this request may cost.", Schema: map[string]any{"type": "number"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parameters = %+v, want the route's path parameter once and the relayed header", got)
	}
	if _, minted := doc.Paths["/v1/ghost/params"]; minted {
		t.Error("an orphan Params minted a path — the registry must never add routes")
	}
}
