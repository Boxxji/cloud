package spec

import (
	"net/http"
	"testing"
)

// TestWritesNamesOneGET: a GET declared as writing is marked on the document and
// nothing else is; a wildcard, another method or a second declaration panics.
func TestWritesNamesOneGET(t *testing.T) {
	Writes("/v1/test/writes/:id", http.MethodGet)
	t.Cleanup(func() {
		writesMu.Lock()
		defer writesMu.Unlock()
		delete(writesOps, opKey{method: http.MethodGet, path: "/v1/test/writes/{id}"})
	})
	d := &Document{Paths: map[string]PathItem{
		"/v1/test/writes/{id}": {"get": &Operation{OperationID: "w"}},
		"/v1/test/reads":       {"get": &Operation{OperationID: "r"}},
	}}
	writes(d)
	if !d.Paths["/v1/test/writes/{id}"]["get"].Writes || d.Paths["/v1/test/reads"]["get"].Writes {
		t.Fatalf("marked: %+v", d.Paths)
	}
	for name, declare := range map[string]func(){
		"a wildcard":       func() { Writes("/v1/test/*", http.MethodGet) },
		"a POST":           func() { Writes("/v1/test/post", http.MethodPost) },
		"a second declare": func() { Writes("/v1/test/writes/:id", http.MethodGet) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s did not panic", name)
				}
			}()
			declare()
		}()
	}
}
