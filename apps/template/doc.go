// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package templates is a gallery of starter kits you can deploy as they come.
//
// The Hanzo starter-kit gallery at /v1/template, in TWO layers that never mix:
//
//   - the PUBLIC catalog: deployable app/site scaffolds (source of truth:
//     hanzoai/gallery), vendored so the unified `cloud` binary ships it with no
//     external dependency. Reference content — embedded, immutable, and with NO
//     write route, so nothing a customer does can add to it.
//   - a customer's OWN templates: rows in the database the host opens, keyed by
//     the validated org of the caller (never a request field), PRIVATE to that
//     org. Only that org lists, reads, edits, deletes, or forks them.
//
// Two layers rather than one visibility flag is the whole safety argument: a
// private template cannot surface in the public hanzo.app catalog by
// CONSTRUCTION — it lives in a different container, reached only by a query that
// binds org — not by a filter every future reader has to remember. An anonymous
// GET never touches the store at all.
//
// A slug is single-valued across both layers: publishing over a public slug is
// 409, so a slug still names exactly one template and no org can shadow the
// gallery.
//
// ONE template is ONE entry. The shapes it ships in — format, page, theme — are
// Variants inside that entry, chosen at fork time.
//
// Surface — every route is a TYPED op (zip.Get[In, Out] and friends), so each is
// ONE registry entry the document, the MCP tool, the CLI command and the
// generated SDK method are all projected from:
//
//	GET    /v1/template          public catalog + (validated caller) that org's own -> {data:[StarterKit]}
//	GET    /v1/template/:slug    one kit: the caller org's own, else public         -> StarterKit
//	POST   /v1/template          publish a kit PRIVATE to the caller's org          -> 201 StarterKit
//	PUT    /v1/template/:slug    replace the caller org's own kit                   -> StarterKit
//	DELETE /v1/template/:slug    delete the caller org's own kit                    -> 204
//
// The value is StarterKit, not Template: the schema namespace of a composed
// document is flat and another product already publishes a `Template`, so the name
// that was not yet published yields, qualified by the value's own vocabulary
// ("Template is one starter kit", below) rather than by a place.
//
// The package imports zip and nothing of its host. Mount takes the host's router
// and a Deps naming what the gallery reads from it: a logger, who the caller is, and
// the database that holds the private kits.
package template
