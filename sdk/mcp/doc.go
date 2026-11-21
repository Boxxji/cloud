// Package mcp is the fleet's agent MCP server as its addresses and the
// protocol facts it answers with, and nothing else.
//
// It is a LEAF on purpose: the routing table (manifest) states the MCP
// server's address and the document (openapi) projects it, and neither may
// import the other — each has tests that reach into the other's package, which
// Go refuses as a cycle. A value both need lives where both can read it
// without reading each other, the way brand does for the issuer. The server
// itself (client/mcp.go) and the card that describes it (openapi/agent.go)
// read the protocol facts below, so the card cannot name a revision or a name
// the server does not answer with.
package mcp
