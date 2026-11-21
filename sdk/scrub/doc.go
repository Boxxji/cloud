// Package scrub answers one question — what does a credential look like in text,
// and how is one removed — and it is a LEAF so that every renderer can ask.
//
// It lived in package cloud, which is ~400 packages, so the only way to reach the
// rule was to link the world. Two places wanted it and could not pay that: the
// fleet's MCP server (fleet), whose whole point is that the host stays light, and
// apps/admission, which kept its own copy of the key prefixes with a comment
// asking whoever changes one to remember the other. A rule with two copies has
// two answers; this is the one home.
//
// The shape test is what distinguishes this from key-NAME redaction (audit.Redact):
// an upstream that answers "Invalid API key: sk-…" gives no field name to key on,
// so only the value's own shape can find it.
package scrub
