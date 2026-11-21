package role

import (
	"fmt"
	"os"
	"strings"
)

// EnvVar is the environment variable that selects the role. Unset ⇒ Writer.
const EnvVar = "CLOUD_ROLE"

// Role is the HA role of this process.
type Role string

const (
	// Writer owns the RWO data dir and is the ONLY process permitted to open the
	// ZapDB KMS store, the SQLite audit chain, and per-tenant SQLite for write.
	// It streams its WAL/backup to S3/vfs for readers to hydrate from.
	Writer Role = "writer"

	// Reader holds no RWO PVC and never takes an exclusive store lock. It opens
	// read-only replicas hydrated from the writer's replication stream and serves
	// GET/read traffic, enabling rolling upgrades + read horizontal scale.
	Reader Role = "reader"
)

// IsWriter reports whether this role owns the RWO stores.
func (r Role) IsWriter() bool { return r == Writer }

// IsReader reports whether this role is a read-only replica.
func (r Role) IsReader() bool { return r == Reader }

// String implements fmt.Stringer.
func (r Role) String() string { return string(r) }

// FromEnv resolves the role from CLOUD_ROLE.
//
//   - unset / empty      → Writer, nil   (byte-identical to today's single pod)
//   - "writer" / "reader" (any case, trimmed) → that role, nil
//   - anything else      → Writer, error (fail-secure: the caller MUST refuse to
//     boot on a malformed role rather than silently guess — guessing "reader"
//     could drop a real writer, guessing "writer" could double-open a store)
//
// The returned error is non-nil ONLY for an explicitly-set invalid value; the
// caller decides to fail closed. The Role is always usable (Writer on error) so
// a caller that chooses to log-and-continue still lands on the safe default.
func FromEnv() (Role, error) {
	return Parse(os.Getenv(EnvVar))
}

// Parse is FromEnv over a value the caller already has, so a decision that must
// be testable against an injected environment reads the role through the SAME
// rules rather than re-implementing them. One definition of what "reader" means.
func Parse(raw string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(Writer):
		return Writer, nil
	case string(Reader):
		return Reader, nil
	default:
		return Writer, fmt.Errorf("role: invalid %s=%q (want %q or %q)", EnvVar, raw, Writer, Reader)
	}
}
