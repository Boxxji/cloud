package cloud

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// sdk/ imports itself and public modules only, and links a production backend (hanzo-sql,
// hanzo-kv, hanzo-s3, the bus, a remote KMS) only under sdk/driver and the test kits.
const module = "github.com/hanzoai/cloud/"

// backends are the production clients the rest of sdk/ must not link.
var backends = []string{
	"github.com/jackc/pgx",               // hanzo-sql
	"github.com/hanzokv/",                // hanzo-kv
	"github.com/hanzos3/",                // hanzo-s3
	"github.com/nats-io/",                // the cross-pod bus
	"github.com/hanzo-ds/",               // datastore (the OLAP mirror)
	"github.com/luxfi/kms/pkg/zapclient", // remote KMS
}

// isBackend reports whether the package at dir is one of the backends or their kits.
func isBackend(dir string) bool {
	return dir == "sdk/sqltest" || dir == "sdk/sqlcheck" || strings.HasPrefix(dir, "sdk/driver")
}

func refusedImport(dir, imp string) bool {
	switch {
	case strings.HasPrefix(imp, module+"sdk/") || imp == module+"sdk":
		return false
	case strings.HasPrefix(imp, module), strings.HasPrefix(imp, "github.com/hanzo-inc/"):
		return true
	}
	if isBackend(dir) {
		return false
	}
	for _, b := range backends {
		if strings.HasPrefix(imp, b) {
			return true
		}
	}
	return false
}

func TestTheSDKImportsOnlyItselfAndPublicModules(t *testing.T) {
	fset := token.NewFileSet()
	err := filepath.WalkDir("sdk", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); path != "sdk" && (strings.HasPrefix(n, ".") || n == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if refusedImport(dir, p) {
				t.Errorf("%s imports %s: sdk/ imports only sdk/... and public modules and links no production backend; "+
					"name an interface here and register the backend from the host", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk sdk: %v", err)
	}
}
