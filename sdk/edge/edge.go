package edge

import (
	"github.com/hanzoai/cloud/sdk/env"
)

// ReadBufferSize is the header ceiling. Above fiber's 4 KiB default so a
// multi-domain SSO session (Domain=.hanzo.ai cookies on every subdomain) does
// not 431 at the public edge. Env GATEWAY_READ_BUFFER_SIZE.
func ReadBufferSize() int { return env.Int("GATEWAY_READ_BUFFER_SIZE", 32768) }

// BodyLimit is the maximum request body a public edge accepts, in bytes.
// Env GATEWAY_BODY_LIMIT.
func BodyLimit() int { return env.Int("GATEWAY_BODY_LIMIT", 16<<20) }
