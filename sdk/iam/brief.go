package iam

// brief.go — the small shapes an org's view is made of, answered by the apps that
// own the facts and composed into a [View] beside the org they describe. They
// live with the identity provider's types because the org is IAM's noun.

// AgentBrief is one agent, named and classified.
type AgentBrief struct {
	// ID is the agent id — the ref a run names and the value a member id derives
	// from, so it must be stable across a reconcile.
	ID string `json:"id"`
	// Name is the display name a person reads in a member list.
	Name string `json:"name"`
	// Status is the registry status VERBATIM, never a boolean. The caller decides
	// what counts as live: apps/team reads empty/active/ready as a live member and
	// anything else as one that keeps its authorship and drops out of the roster,
	// and folding that judgement into a bool here would move the policy to the
	// wrong side of the wire.
	Status string `json:"status"`
	// Parent is the agent that spawned this one; empty for an agent a person
	// defined.
	Parent string `json:"parent,omitempty"`
}

// Founder is one founding stakeholder.
type Founder struct {
	// Name is the full legal name.
	Name string `json:"name"`
	// EquityBps is ownership in basis points, 0–10000.
	EquityBps int `json:"equityBps"`
	// KYC is pending, verified, reviewer_confirmed or failed, verbatim.
	KYC string `json:"kyc"`
}

// Treaty is a claim of reduced withholding under an income tax treaty (W-8BEN
// Part II, W-8BEN-E Part III).
type Treaty struct {
	// Country is the treaty country the beneficial owner is resident in.
	Country string `json:"country"`
	// Article is the treaty article and paragraph claimed, e.g. "12(2)".
	Article string `json:"article"`
	// RateBps is the claimed withholding rate in basis points: 0 is exempt,
	// 1000 is 10%.
	RateBps int `json:"rateBps"`
	// Income is the type of income the claim covers: services, rents, royalties
	// or other.
	Income string `json:"income"`
	// Conditions is the explanation the form asks for: the conditions of the
	// article the beneficial owner meets.
	Conditions string `json:"conditions,omitempty"`
	// LOB is W-8BEN-E line 14b: the treaty's limitation on benefits provision the
	// entity meets. Required on a W-8BEN-E treaty claim; a W-8BEN has no line 14b.
	LOB string `json:"lob,omitempty"`
}

// WalletBrief is one wallet, as a payer or a screen needs it.
type WalletBrief struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Chain   string `json:"chain,omitempty"`
	Address string `json:"address"`
	Custody string `json:"custody"`
	// Agent is the agent the wallet is scoped to, when it is one agent's.
	Agent string `json:"agent,omitempty"`
}
