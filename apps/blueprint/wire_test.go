// SPDX-License-Identifier: Apache-2.0 OR MIT

package blueprint

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// TestEveryOperationAndFieldIsDescribed holds the published document to a bar: the
// prose a typed op carries becomes the OpenAPI description and the MCP tool
// description a model reads to pick the tool, and every published field carries its
// doc comment. zipdoc_gen.go is what carries both into the binary, so a change
// made without regenerating shows up here as a nameless operation or field.
func TestEveryOperationAndFieldIsDescribed(t *testing.T) {
	// The document round-trips through JSON so the walk below reads exactly what a
	// client receives, not the builder's typed intermediates.
	raw, err := json.Marshal(mountApp(t).OpenAPISpec())
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode document: %v", err)
	}

	paths, _ := doc["paths"].(map[string]any)
	served := 0
	for path, item := range paths {
		if !strings.HasPrefix(path, "/v1/blueprint") {
			continue
		}
		for method, raw := range item.(map[string]any) {
			served++
			op, _ := raw.(map[string]any)
			if desc, _ := op["description"].(string); strings.TrimSpace(desc) == "" {
				t.Errorf("%s %s has no description — run: go generate ./apps/blueprint", strings.ToUpper(method), path)
			}
		}
	}
	if served == 0 {
		t.Fatal("no blueprint operations in the document at all")
	}

	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)
	var bare []string
	for name, raw := range schemas {
		props, _ := raw.(map[string]any)["properties"].(map[string]any)
		for field, praw := range props {
			if desc, _ := praw.(map[string]any)["description"].(string); strings.TrimSpace(desc) == "" {
				bare = append(bare, name+"."+field)
			}
		}
	}
	if len(bare) > 0 {
		sort.Strings(bare)
		t.Errorf("published propert(ies) with no description: %s\nWrite a doc comment on the struct field and run: go generate ./apps/blueprint", strings.Join(bare, ", "))
	}
}

// TestTypedOpsKeepTheirBytes pins the two converted reads at the BYTE level. Both
// used to marshal a map[string]any, whose keys Go emits in sorted order; a struct
// emits them in declaration order. Declaring the fields in that same sorted order
// is what kept the wire byte-identical, and this is the assertion that keeps it so
// — a field inserted in the "natural" place goes red here rather than silently
// reordering a shipped body.
func TestTypedOpsKeepTheirBytes(t *testing.T) {
	app := mountApp(t)

	code, body := get(t, app, "/v1/blueprint/health")
	if code != 200 {
		t.Fatalf("health: %d", code)
	}
	if err := sameKeyOrder(body, []string{"blueprints", "rateCard", "service", "status"}); err != nil {
		t.Errorf("health: %v", err)
	}

	code, body = get(t, app, "/v1/blueprint")
	if code != 200 {
		t.Fatalf("index: %d", code)
	}
	if err := sameKeyOrder(body, []string{"data"}); err != nil {
		t.Errorf("index: %v", err)
	}
	var index struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatalf("index decode: %v", err)
	}
	if len(index.Data) == 0 {
		t.Fatal("index is empty")
	}
	if err := sameKeyOrder(index.Data[0], []string{"templateId", "services", "estCentsPerMonth"}); err != nil {
		t.Errorf("index row: %v", err)
	}
}

// sameKeyOrder reports whether obj's top-level keys appear in exactly want's
// order. json.Decoder.Token walks the object in WIRE order, which is the fact
// under test — json.Unmarshal into a map would sort it away.
func sameKeyOrder(obj []byte, want []string) error {
	dec := json.NewDecoder(strings.NewReader(string(obj)))
	if _, err := dec.Token(); err != nil { // opening {
		return err
	}
	var got []string
	depth := 0
	for dec.More() || depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
			} else {
				depth--
			}
			continue
		case string:
			if depth == 0 {
				got = append(got, v)
				// Skip the value, whatever it is.
				var skip json.RawMessage
				if err := dec.Decode(&skip); err != nil {
					return err
				}
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return errKeyOrder(got, want)
	}
	return nil
}

type keyOrderErr struct{ got, want []string }

func (e keyOrderErr) Error() string {
	return "key order " + strings.Join(e.got, ",") + ", want " + strings.Join(e.want, ",")
}

func errKeyOrder(got, want []string) error { return keyOrderErr{got, want} }
