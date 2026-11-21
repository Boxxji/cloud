package iam

// view.go — an org as a payer and payee, as data: who it is, how it is
// documented for tax, how it screens, what it holds, which agents answer to it.
// The facts are the owning apps'; /v1/principal composes them (apps/principals),
// and the shape they are answered in is here, beside the org they describe.

import (
	"time"

	"github.com/hanzoai/cloud/sdk/principal"
)

// View is the caller's org as a payer and payee: who it is, how it is documented
// for tax, whether it screens clear, what it holds, which agents act for it, and
// what it still lacks.
type View struct {
	// Org is the org — the principal itself.
	Org string `json:"org"`
	// Identity is whether its founders are verified.
	Identity Identity `json:"identity"`
	// Entity is its legal entity, when it formed or imported one here.
	Entity *Entity `json:"entity,omitempty"`
	// Tax is the form it certified about itself.
	Tax *Form `json:"tax,omitempty"`
	// Sanctions is its screening against the OFAC, UN, EU and UK lists and the
	// embargoed jurisdictions, run on this read and recorded by none: a match is
	// recorded for a reviewer when a payment to or from the org is cleared.
	// Matches are answered to the org's admins.
	Sanctions Screening `json:"sanctions"`
	// Wallets are its addresses.
	Wallets []WalletBrief `json:"wallets"`
	// Agents are the agents that answer to it, spawned ones with their parent.
	Agents []AgentBrief `json:"agents"`
	// Compliance is what it lacks to pay and be paid on the platform's rails.
	Compliance Summary `json:"compliance"`
	// Sources says which owning apps answered.
	Sources []Source `json:"sources"`
}

// Identity is whether an org's legal identity is verified, and on what.
type Identity struct {
	// Status is verified (every founder of its formation passed identity
	// verification through the licensed provider, or a platform reviewer
	// confirmed them), pending, failed, or none (no formation, or one naming no
	// founder).
	Status string `json:"status"`
	// Reason says which founders, and what is outstanding.
	Reason string `json:"reason"`
}

// Entity is an org's legal entity.
type Entity struct {
	// Name is the company name.
	Name string `json:"name"`
	// Structure is c-corp, llc or dao-llc.
	Structure string `json:"structure"`
	// Jurisdiction is the U.S. state of formation.
	Jurisdiction string `json:"jurisdiction"`
	// Stage is the formation's stage; "company" is formed.
	Stage string `json:"stage"`
	// Imported is an entity that existed before and was imported.
	Imported bool `json:"imported,omitempty"`
	// EIN is on_file when the org's W-9 carries an EIN, and absent otherwise.
	EIN string `json:"ein"`
	// Founders are its beneficial owners with their verification status —
	// answered to the org's admins.
	Founders []Founder `json:"founders,omitempty"`
}

// Form is an org's tax form as its principal view answers it.
type Form struct {
	// Form is w9, w8ben or w8bene.
	Form string `json:"form"`
	// USPerson is true for a W-9.
	USPerson bool `json:"usPerson"`
	// Country is US for a W-9, or the country of citizenship or incorporation.
	Country string `json:"country"`
	// Residence is the country of the permanent residence address.
	Residence string `json:"residence"`
	// Certified is whether the signature covers the current facts.
	Certified bool `json:"certified"`
	// Valid is whether it establishes what it certifies today.
	Valid bool `json:"valid"`
	// Expires is when a W-8 stops being valid, unix seconds.
	Expires int64 `json:"expires,omitempty"`
	// TIN and ForeignTIN are masked — answered to the org's admins.
	TIN        string `json:"tin,omitempty"`
	ForeignTIN string `json:"foreignTin,omitempty"`
	// Chapter3 and Chapter4 are a W-8BEN-E's statuses — to the org's admins.
	Chapter3 string `json:"chapter3,omitempty"`
	Chapter4 string `json:"chapter4,omitempty"`
	// Treaty is a W-8's treaty claim — to the org's admins.
	Treaty *Treaty `json:"treaty,omitempty"`
}

// Summary is what an org lacks to pay and be paid.
type Summary struct {
	// Ready is true when it lacks nothing its own facts decide.
	Ready bool `json:"ready"`
	// Missing are the steps it owes, each with the rule that asks for it.
	Missing []principal.Step `json:"missing"`
}

// Source is whether one owning app answered.
type Source struct {
	// App names it: company, tax, wallet or agent.
	App string `json:"app"`
	// Status is read, or absent when this deployment does not run it.
	Status string `json:"status"`
}

// Screening is an org's sanctions verdict.
type Screening struct {
	// Status is clear, review (a possible match awaits a platform reviewer),
	// blocked (a confirmed match), unscreened (the org states nothing to screen),
	// or unavailable (the lists are not fit to screen against).
	Status string `json:"status"`
	// Reason says why, in words.
	Reason string `json:"reason"`
	// Lists is each publisher's readiness at the moment of screening.
	Lists []List `json:"lists"`
	// At is when it ran, unix seconds.
	At int64 `json:"at"`
	// Matches are what matched — answered to the org's own admins and to a
	// reviewer, never to another org.
	Matches []Match `json:"matches,omitempty"`
}

// List is one publisher's list as screening found it: loaded, how fresh, and why
// the last load failed if it did. It is luxfi/aml's screen.Fitness field for
// field, so one converts to the other.
type List struct {
	// Source is the publisher.
	Source string `json:"source"`
	// Designations is how many entries the last successful load carried.
	Designations int `json:"designations"`
	// LoadedAt is when that load happened. Zero means this list has never loaded,
	// which is not the same as a publisher who designates nobody.
	LoadedAt time.Time `json:"loaded_at"`
	// Digest is the digest of the payload that produced Designations.
	Digest string `json:"digest,omitempty"`
	// Err is why the last attempt failed, empty if it succeeded.
	Err string `json:"error,omitempty"`
	// AttemptedAt is when the last attempt happened, successful or not.
	AttemptedAt time.Time `json:"attempted_at"`
}

// Match is one designation an org screened close to, with everything of the org
// that did.
type Match struct {
	// ID addresses the match for a reviewer's decision. It is the org and the
	// designation together, so a decision is about the org whatever it is called.
	ID string `json:"id"`
	// Org is the org the match names.
	Org string `json:"org"`
	// List is the publisher — ofac, un, eu or ofsi — or jurisdiction for an
	// embargoed place.
	List string `json:"list"`
	// Ref is the entry's reference on that list, or the country code.
	Ref string `json:"ref"`
	// Entry is the designated subject's primary name, or the jurisdiction's.
	Entry string `json:"entry"`
	// Hits are the org's names, addresses and countries that matched, in the order
	// they were first seen. A decision covers the hits it was made on.
	Hits []Hit `json:"hits"`
	// Score is the highest similarity seen, 0 to 1; an address or a jurisdiction
	// is 1.
	Score float64 `json:"score"`
	// Reason is what first matched, and which identifiers agreed or conflicted.
	Reason string `json:"reason"`
	// Status is open (a reviewer decides), cleared (a namesake, decided) or
	// confirmed (the designated person, decided — or a designated address).
	Status string `json:"status"`
	// DecidedBy is the reviewer, or "exact designated address".
	DecidedBy string `json:"decidedBy,omitempty"`
	// DecidedAt is when, unix seconds.
	DecidedAt int64 `json:"decidedAt,omitempty"`
	// Note is the reviewer's reason.
	Note string `json:"note,omitempty"`
	// FoundAt is when a screening first found it, unix seconds.
	FoundAt int64 `json:"foundAt"`
}

// Hit is one thing an org is known by that screened close to a designation.
type Hit struct {
	// Subject is the name, address or country as the org stated it.
	Subject string `json:"subject"`
	// Role is where it came from: entity, founder, form, wallet, or — for a
	// country — citizenship, organization or residence.
	Role string `json:"role"`
	// Kind is name (matched fuzzily), address (matched exactly) or jurisdiction.
	Kind string `json:"kind"`
}
