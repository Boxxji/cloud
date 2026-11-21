package mcp

const (
	// Path is the fleet's one agent MCP address: POST /v1/mcp, served by the host
	// that fronts the API. See manifest.MCPPath for why it is this address.
	Path = "/v1/mcp"

	// Framework is zip's built-in default — where a plugin serves its OWN MCP
	// server, and the address the host signposts to Path. See
	// manifest.FrameworkMCPPath.
	Framework = "/mcp"

	// Metadata is where the host publishes RFC 9728 metadata for the MCP server:
	// which authorization server mints the bearer a tools/call needs. The MCP
	// server's WWW-Authenticate challenge names it (client/mcp.go) and the host
	// serves it (openapi/agent.go) — one name, two readers, so the challenge
	// can never point at an address the host does not answer.
	Metadata = "/.well-known/oauth-protected-resource"

	// MetadataMCP is the same document for the MCP server alone, at the path the
	// MCP authorization spec tries first: the resource's own path appended to the
	// well-known name (RFC 9728 §3.1). Its resource is the server's URL, not the
	// API's origin, because a client checks that the resource it was told is the
	// one it called.
	MetadataMCP = Metadata + Path

	// Card is where the host publishes the MCP server's card: its name, version,
	// endpoint, transport and revisions, readable before a client connects.
	Card = "/.well-known/mcp/server-card.json"

	// Name is the server's name, as initialize answers it in serverInfo.
	Name = "cloud"

	// Protocol is the newest MCP revision the server speaks, and the one it
	// answers in when a client asks for none it knows.
	Protocol = "2026-07-28"
)

// Revisions are the MCP revisions the server answers in, oldest first. They
// are zip's (zip mcpRevisions): the two before Protocol define the same
// Streamable HTTP transport and the same tool methods, and none has JSON-RPC
// batches, so a client that asks for one is served it as written. The set is
// pinned to what a zip child answers by client.TestInitializeAnswersTheRevisionsZipAnswers.
var Revisions = []string{"2025-06-18", "2025-11-25", Protocol}

// Negotiate is the revision an initialize is answered in, by the MCP lifecycle's
// version negotiation: the one the client asked for when the server speaks it,
// else Protocol.
func Negotiate(asked string) string {
	for _, r := range Revisions {
		if r == asked {
			return r
		}
	}
	return Protocol
}
