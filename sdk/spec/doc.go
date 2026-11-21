// Package spec is how an app declares what the router cannot read, and the
// document model every projection of the router is written in.
//
// The router says which operations exist: address, method, product. It cannot
// say what an operation takes, what it answers, what it does, whether it needs a
// credential or whether a GET writes. An app states those beside its routes:
//
//	[Register], [Bytes], [Binary], [OneOf], [Params], [Answers], [Takes]   bodies
//	[Describe], [DescribeRest]                                             prose
//	[Open]                                                                 the credential
//	[Writes]                                                               a GET that writes
//	[Front] with [Mounted] or [Table]                                      a route that stands for an API
//
// A declaration renders only on a route the router carries, so the registry can
// never invent an operation and the document cannot disagree with the router.
//
// [Of] is the per-app projection: the live router ([Live], [From]), the typed
// registry ([Typed], [Fold]), the relays ([Project]), then the facts the router
// cannot hold ([Stamp], [Secure], writes). It is what a plugin serves for
// `describe`. The fleet's document is COMPOSED from those projections by
// package openapi, which imports this one; nothing here knows a manifest, a
// brand or a fleet.
package spec
