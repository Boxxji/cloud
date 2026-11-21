// SPDX-License-Identifier: Apache-2.0 OR MIT

package template

import (
	"strings"
	"testing"
)

// catalog_test.go pins what makes a catalog row worth shipping, as opposed to
// merely well-formed (templates_test.go already covers the shape).

// TestEveryTemplateDescribesItself: the description is not decoration — a fork
// copies it onto the new project, so an empty one would propagate into every
// customer's project list.
func TestEveryTemplateDescribesItself(t *testing.T) {
	cat, err := catalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	for _, tpl := range cat {
		d := strings.TrimSpace(tpl.Description)
		switch {
		case d == "":
			t.Errorf("template %q has no description", tpl.Slug)
		case len(d) < 24:
			t.Errorf("template %q description is not a sentence: %q", tpl.Slug, d)
		case strings.Contains(d, "\n"):
			t.Errorf("template %q description is not ONE line", tpl.Slug)
		}
	}
}

// TestSourceIsARepository: a fork assigns `source` to the new project's git
// remote, so it names the repository or it names nothing usable.
func TestSourceIsARepository(t *testing.T) {
	cat, err := catalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	for _, tpl := range cat {
		for _, src := range append([]string{tpl.Source}, variantSources(tpl)...) {
			if !strings.HasPrefix(src, "https://github.com/") {
				t.Errorf("template %q source %q is not a repository URL", tpl.Slug, src)
			}
		}
	}
}

// TestSlugIsASingleCleanName: a slug is the name a person types and the name the
// forked project gets. Doubled compounds (`helpdesk-deskline`) say the same thing
// twice.
func TestSlugIsASingleCleanName(t *testing.T) {
	cat, err := catalog()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	for _, tpl := range cat {
		if !slugRE.MatchString(tpl.Slug) {
			t.Errorf("template slug %q is not a DNS label", tpl.Slug)
		}
		for w := range strings.SplitSeq(tpl.Slug, "-") {
			if strings.Count(tpl.Slug, w) > 1 {
				t.Errorf("template slug %q repeats %q", tpl.Slug, w)
			}
		}
	}
}

func variantSources(tpl StarterKit) []string {
	out := make([]string, 0, len(tpl.Variants))
	for _, v := range tpl.Variants {
		out = append(out, v.Source)
	}
	return out
}
