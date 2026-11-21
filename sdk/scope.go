// Copyright © 2026 Hanzo AI. MIT License.

package cloud

import (
	"fmt"
	"strings"

	"github.com/zap-proto/zip"
)

// Router is the definition a subsystem fills: an App of its own, which the host
// composes once every address it declares lies under the subsystem's prefixes.
type Router = *zip.App

// held is nil when def composes and every address it declares lies under one
// of prefixes.
func held(def *zip.App, prefixes []string) error {
	if err := def.Verify(); err != nil {
		return err
	}
	for _, d := range def.Declaration().Routes {
		if !within(d.Pattern, prefixes) {
			return fmt.Errorf("%s %s is outside %s", d.Method, d.Pattern, strings.Join(prefixes, ", "))
		}
	}
	return nil
}

// Under runs h for requests at prefix and beneath it and passes every other one on.
func Under(prefix string, h zip.Handler) zip.Handler {
	return func(c *zip.Ctx) error {
		if PathUnder(c.Path(), prefix) {
			return h(c)
		}
		return c.Continue()
	}
}

// within reports whether path lies under one of prefixes.
func within(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if PathUnder(path, p) {
			return true
		}
	}
	return false
}

// PathUnder reports whether path is p or lies beneath it. Both sides fold through
// RoutePath, because the router matches case-insensitively.
func PathUnder(path, p string) bool {
	path, p = RoutePath(path), RoutePath(p)
	return path == p || strings.HasPrefix(path, strings.TrimSuffix(p, "/")+"/")
}
