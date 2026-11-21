package principal

// clearance.go — the record of whether one org may pay another, as data. The
// rules that decide it are served at /v1/principal/clearance (apps/principals);
// the shape is here, beside the org it is about, so every app that reads a
// clearance reads this one.

// Notice is what every clearance says about itself.
const Notice = "A clearance applies the rules this platform cites to the facts it holds, and returns the facts it does not " +
	"hold as questions. It is not legal or tax advice. Every return and report it names is filed by the org named as its " +
	"filer, never by Hanzo; apps/tax prepares the U.S. forms for that org to review and file."

// Rule is why a field of a clearance is what it is: a stable code and the rule
// stated, with its source.
type Rule struct {
	// Code is the rule's stable name, for a caller that branches on it.
	Code string `json:"code"`
	// Reason is the rule, stated.
	Reason string `json:"reason"`
}

// Clearance is one decision on one payment.
type Clearance struct {
	// ID is the clearance, "clr_"-prefixed.
	ID string `json:"id"`
	// Payer is the caller's org.
	Payer string `json:"payer"`
	// Payee is the org to be paid.
	Payee string `json:"payee"`
	// Amount is the gross amount, U.S. dollars.
	Amount string `json:"amount"`
	// Category is what is bought: services, attorney, rents, royalties, other or
	// merchandise.
	Category string `json:"category"`
	// Rail is how it moves.
	Rail string `json:"rail"`
	// Performed is where the service is performed, as stated.
	Performed string `json:"performed,omitempty"`
	// Platform is whether the caller operates the payee's platform, as stated.
	Platform *bool `json:"platform,omitempty"`
	Decision
	// DecidedAt is when, unix seconds.
	DecidedAt int64 `json:"decidedAt"`
	// Notice is what a clearance is and is not.
	Notice string `json:"notice"`
}

// Decision is what the rules make of one payment.
type Decision struct {
	// Allowed is true when nothing is required first and no fact blocks.
	Allowed bool `json:"allowed"`
	// Status is what the payer may treat the payee as: us, foreign or unknown —
	// read off the form the payee granted the payer, and unknown without one.
	Status string `json:"status"`
	// Required are the steps before the payment.
	Required []Step `json:"required_before_payment"`
	// Reporting are the returns this payment makes someone owe.
	Reporting []Obligation `json:"reporting_obligations"`
	// Settlement are the ways it may settle, net of what is withheld.
	Settlement []Method `json:"settlement_methods"`
	// Withholding is what must be withheld.
	Withholding Withholding `json:"withholding"`
	// Facts are what a rule turns on that the platform does not know.
	Facts []Fact `json:"facts_required"`
	// Rules names the rule behind each field above.
	Rules []Decided `json:"rules"`
}

// Step is something that must happen before the payment.
type Step struct {
	// Code is the step's stable name, for a caller that branches on it.
	Code string `json:"code"`
	// What must happen, in words.
	What string `json:"what"`
	// Who does it: payer, payee, or "Hanzo platform reviewer".
	Who string `json:"who"`
	// Where it is done, when it is done on this platform.
	Where string `json:"where,omitempty"`
	// Rule is why.
	Rule Rule `json:"rule"`
}

// Obligation is a return or report someone must file because of this payment.
type Obligation struct {
	// Code is the obligation's stable name.
	Code string `json:"code"`
	// Form is what is filed.
	Form string `json:"form"`
	// Filer is the org that files it. It is never Hanzo: Hanzo prepares what an org
	// files, and files nothing itself.
	Filer string `json:"filer"`
	// Jurisdiction is where, ISO 3166-1 alpha-2 or "EU".
	Jurisdiction string `json:"jurisdiction"`
	// Authority is who it is filed with.
	Authority string `json:"authority"`
	// Due is when.
	Due string `json:"due"`
	// When is the condition it is owed on, when it is owed on one.
	When string `json:"when,omitempty"`
	// Rule is why.
	Rule Rule `json:"rule"`
}

// Method is one way the payment may settle.
type Method struct {
	// Rail is the rail: ledger or chain.
	Rail string `json:"rail"`
	// Net is what the payee receives, U.S. dollars.
	Net string `json:"net"`
	// Withheld is what the payer keeps back and deposits itself, U.S. dollars.
	Withheld string `json:"withheld"`
	// Rule is why.
	Rule Rule `json:"rule"`
}

// Withholding is what the payer must withhold from this payment.
type Withholding struct {
	// Chapter is "3" (IRC chapter 3, a payment to a foreign person) or "backup"
	// (IRC §3406), and empty when nothing is withheld or it cannot yet be decided.
	Chapter string `json:"chapter,omitempty"`
	// Rate is the rate in percent: "30", "24", "10", "0". Empty when it cannot be
	// decided on the facts held — see facts_required.
	Rate string `json:"rate"`
	// Amount is the amount to withhold, U.S. dollars; empty when the rate is.
	Amount string `json:"amount"`
	// Reason says why, in words.
	Reason string `json:"reason"`
	// Rule is the rule that decided it.
	Rule Rule `json:"rule"`
}

// Fact is something a rule turns on that the platform does not know. A fact that
// blocks leaves the payment uncleared until it is answered; one that does not
// names a question whose answer can change what is owed.
type Fact struct {
	// Code is the fact's stable name.
	Code string `json:"code"`
	// Question is what must be answered.
	Question string `json:"question"`
	// Blocks is whether the payment waits on it.
	Blocks bool `json:"blocks"`
	// Rule is the rule that turns on it.
	Rule Rule `json:"rule"`
}

// Decided names the rule behind one field of a clearance.
type Decided struct {
	Field string `json:"field"`
	Rule  Rule   `json:"rule"`
}
