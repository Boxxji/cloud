// Package env reads deployment facts out of the process environment: Or, Int and
// Cents read one variable with the blank-means-unset rule, and DataDir names the
// on-disk data root.
//
// A LEAF, for the reason sdk/mint is one: several of the packages the framework
// imports read the environment too, and they cannot import it back.
package env
