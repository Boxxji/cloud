package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Conflict is two apps disagreeing about one name. Typed rather than a bare
// error string so a caller (and the gate) can assert on the KIND of collision
// without matching prose.
type Conflict struct {
	Kind string // "operation", "schema", or "case"
	Name string // "GET /v1/x" or the schema name
	A, B string // the two apps that claim it, in compose order
}

func (c *Conflict) Error() string {
	switch c.Kind {
	case "operation":
		return fmt.Sprintf("%s is claimed by both %q and %q — one address, two apps: "+
			"the fleet cannot route it and the spec must not pick a winner", c.Name, c.A, c.B)
	case "case":
		return fmt.Sprintf("schemas %s differ only in case, claimed by %q and %q — every "+
			"generator that PascalCases a name reads them as ONE class, so an SDK binds "+
			"whichever it emitted last or refuses to compile at all", c.Name, c.A, c.B)
	default:
		return fmt.Sprintf("schema %q means different things in %q and %q — "+
			"one name, two shapes: every generated SDK would bind whichever it read last", c.Name, c.A, c.B)
	}
}

// Nouns is THE noun gate: one schema name, one shape, wherever two claimants meet.
//
// Schemas are named after Go types (AccessOut, Campaign, None), so two
// contributors can reach the same name honestly and mean different things — and
// every generated SDK would bind whichever the merge read last. There is one gate
// for that, here, and both composition points call it: [Compose], where the
// claimants are two apps, and [Project], where they are an app and the registry
// behind its relay. A second implementation would be a second policy.
//
// Shapes are compared as CANONICAL JSON rather than with DeepEqual: they arrive as
// decoded `any` trees whose numbers may be float64 or json.Number depending on how
// the part was read, and two trees that serialize identically describe the same
// type whatever their in-memory shape. encoding/json sorts object keys, so the
// bytes are canonical.
//
// The canonical bytes are the COMPARISON only. What reaches the document is the
// claimant's own value, because [Components] states which value each client
// contributes — Register a *Schema, the typed fold zip's decoded JSON — and a
// re-decode here would flatten every one of them to map[string]any, silently
// undoing [Fold] for a document that merely passed through [Project].
type Nouns struct {
	claim map[string]noun
	// folded indexes each claimed name by its lowercase form, because a generator
	// that PascalCases a schema reads `call` and `Call` as one class. See [caseOK].
	folded map[string]string
}

// noun is everything known about one schema name: the value to publish, the
// canonical bytes to compare the next claimant against, and who claimed it.
type noun struct {
	val   any
	raw   json.RawMessage
	owner string
}

func NewNouns() *Nouns {
	return &Nouns{claim: map[string]noun{}, folded: map[string]string{}}
}

// Add takes one claimant's schemas, or refuses the name it disagrees about.
func (n *Nouns) Add(owner string, schemas map[string]any) error {
	for _, name := range sortedKeys(schemas) {
		raw, err := json.Marshal(schemas[name])
		if err != nil {
			return fmt.Errorf("%s: schema %q: %w", owner, name, err)
		}
		if prev, seen := n.claim[name]; seen {
			if !bytes.Equal(prev.raw, raw) {
				return &Conflict{Kind: "schema", Name: name, A: prev.owner, B: owner}
			}
			continue
		}
		fold := strings.ToLower(name)
		if other, seen := n.folded[fold]; seen && other != name && !caseOK[fold] {
			return &Conflict{
				Kind: "case",
				Name: fmt.Sprintf("%q and %q", other, name),
				A:    n.claim[other].owner,
				B:    owner,
			}
		}
		n.folded[fold] = name
		n.claim[name] = noun{val: schemas[name], raw: raw, owner: owner}
	}
	return nil
}

// Into merges the accumulated schemas into doc's components, leaving doc
// untouched when there are none — an empty components block is noise in every
// artifact that carries it.
func (n *Nouns) Into(doc *Document) {
	if len(n.claim) == 0 {
		return
	}
	if doc.Components == nil {
		doc.Components = &Components{Schemas: map[string]any{}}
	}
	if doc.Components.Schemas == nil {
		doc.Components.Schemas = map[string]any{}
	}
	for name, c := range n.claim {
		doc.Components.Schemas[name] = c.val
	}
}

// caseOK is the CLOSED list of names that differ from another claimed name only
// in case, and are allowed to. Every one of them predates the check above.
//
// A pair here is not harmless — it is the same defect the gate exists for, one
// level down. `call` and `Call` were both claimed (meet's media room and tel's
// telephony call), the Kotlin client imported ai.hanzo.cloud.model.Call beside
// okhttp3.Call, and it stopped compiling on an ambiguous import. That pair is
// GONE, renamed to `venue`, which is why it is not in this list.
//
// The rest stay because renaming a schema renames it in every published client,
// and each of these is already bound by one. They come off this list one at a
// time, when the route that carries the name is changing shape anyway and the
// rename rides along. A new pair is refused outright: the cost of the name is
// paid once, at the moment somebody picks it, which is the only moment it is
// free.
var caseOK = map[string]bool{
	"accounts":         true, // account (billing) · accounts (a scoped roll-up)
	"activityview":     true, // agent activity · a source's availability
	"appview":          true, // platform's deployed app · projects' app record
	"askrequest":       true, // a question to a person · a research query
	"campaignlist":     true, // marketing · campaign, two lists of one word
	"catalogentry":     true, // a prompt in the catalogue · a configured provider
	"flowrun":          true, // flow's run record · the input that starts one
	"funnel":           true, // two funnels, from analytics and from crm
	"grantout":         true, // a granted scope · a granted award
	"health":           true, // the fleet's health · one subsystem's
	"hit":              true, // a search hit, twice, from two search surfaces
	"iam.listresponse": true, // iam's keys · iam's SCIM list envelope
	"leaderboardrow":   true, // usage leaderboard · referral leaderboard
	"leasein":          true, // lease by class · lease by image
	"listing":          true, // a marketplace listing · a bucket listing
	"listout":          true, // two list envelopes
	"productrow":       true, // two product rows
	"readout":          true, // two read results
	"runin":            true, // exec's argv · flow's action
	"seriespoint":      true, // two time-series points
	"sourcestate":      true, // the same four fields, described twice
	"summary":          true, // campaign spend · call and message counts
	"totals":           true, // two totals
	"totalview":        true, // the same six fields, described twice
	"usage":            true, // two usage records
	"usagepoint":       true, // two usage points
	"verdict":          true, // a scan verdict · a build verdict
	"verifyout":        true, // two verification results
}
