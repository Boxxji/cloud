// SPDX-License-Identifier: Apache-2.0 OR MIT

package apps

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/hanzoai/cloud"

// TestAppsImportNothingOfTheirHost holds every package under apps/<name> to one
// rule: it imports zip, the standard library, public modules and itself, never
// the host's framework or another of its packages. An app that imports its host
// cannot be mounted by a second one; an app that does not is the same source in
// every host that hands it a router and what it reads.
func TestAppsImportNothingOfTheirHost(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		own := module + "/apps/" + e.Name()
		err := filepath.WalkDir(e.Name(), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if (p == module || strings.HasPrefix(p, module+"/")) && p != own && !strings.HasPrefix(p, own+"/") {
					t.Errorf("%s imports %s: an app imports zip, never its host", path, p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
