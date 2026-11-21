package cloud

// commerce.go — the entitlement check the framework hands apps (deps.Commerce): commerce's
// answer to "does this org hold a licensed product", in the framework's own shape. The
// host fills it from the commerce app (in-process, or over the plane).

import "context"

// LicenseEntitlement is commerce's answer to "does this org/user hold an
// active entitlement for licensed product X, and what does its plan grant?".
//
// It is the inter-subsystem transport for the entitlement-flow that gates
// licensing token issuance (commerce → licensing → engine). The licensing
// subsystem copies Features verbatim into the signed token's `features`
// list so the proprietary engine's offline release gate (hasFeatures)
// enforces exactly the plan the buyer paid for.
//
// Features is the FLAT capability list produced from the canonical
// entitlement vocabulary by the data plane's toLicenseFeatures contract
// (@hanzo/plans entitlements.mjs): licensing.engine_features verbatim,
// plus derived capability tokens (e.g. "ai.premium", "training",
// "tools.<name>"), plus scoping tokens ("licensing.app:<id>",
// "licensing.product:<id>"). Numeric quotas (tokens_per_min, seats,
// max_vms, …) ride out of band and are NOT encoded here.
type LicenseEntitlement struct {
	// ProductID is the licensed product the entitlement was checked for
	// (e.g. "engine", "team", a plugin id). A product is a thing sold, never a
	// build of it: engine ships CUDA, ROCm and Metal from one SKU, so an
	// accelerator never appears here.
	ProductID string
	// Active reports whether the entitlement is currently valid (paid,
	// not lapsed/cancelled). Licensing refuses to mint when false.
	Active bool
	// Plan is the resolved plan/tier id (e.g. "developer", "pro", "max",
	// "enterprise"). Surfaced for logging/audit; not load-bearing for the
	// release gate.
	Plan string
	// Features is the flat license-feature list per the toLicenseFeatures
	// vocab contract — copied verbatim into License.Features at issue.
	Features []string
	// ExpiresUnix bounds the entitlement (unix seconds, 0 = no bound). The
	// issued token's exp is clamped to it so a token never outlives the
	// entitlement.
	ExpiresUnix int64
	// EarlyAccess reports that a live plan of the org carries early access
	// (@hanzo/plans licensing.early_access, every Max rung): the org opens each
	// product in beta without applying (apps/entitlement). It is the org's,
	// whichever product was asked about, and is read off the same subscriptions.
	EarlyAccess bool
}

// CommerceClient is the inter-subsystem interface to Commerce: entitlements. Money
// is NOT here — a subject's prepaid balance/deposit/usage is
// the orthogonal BillingClient, so commerce (catalog/subscriptions/licensing) and
// billing (the money ledger) never braid. Every method is a DIRECT in-process call
// to the embedded commerce datastore in commerce's own process, or a call by name
// over the plane to it from any other (cloud.planeCommerce).
type CommerceClient interface {
	// CheckEntitlement reports whether org `orgID` holds an active
	// entitlement for licensed product `productID`, and returns the plan's
	// flat license-features per the toLicenseFeatures vocab contract. Used
	// by the licensing subsystem to gate + scope token issuance. orgID is
	// the org the buyer acts as (X-Org-Id); when callers only have a
	// user subject they pass it through here and commerce resolves the
	// owning org.
	CheckEntitlement(ctx context.Context, orgID, productID string) (*LicenseEntitlement, error)
}
