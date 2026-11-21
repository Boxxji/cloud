// Package mint makes opaque identifiers.
//
// It is a LEAF on purpose. The function is pure, so every layer may use it —
// including the packages the root cloud package itself imports, which cannot
// import cloud back. A minter parked in the framework package would be reachable
// only from above it, and the money packages that sit below would need their own.
package mint
