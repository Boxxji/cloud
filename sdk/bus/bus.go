package bus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	neturl "net/url"
	"strconv"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/cloud/sdk/env"
	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/hanzoai/namespace"
)

// The bus knob, in one place. See the package doc.
const (
	urlEnv      = "CLOUD_PUBSUB_URL"
	portEnv     = "CLOUD_PUBSUB_PORT"
	defaultPort = 4222
)

// URL is THE bus address for every app in this process. Callers dial it; nobody
// reads an environment variable of their own to find the bus.
//
// It never fails and it is never empty: a malformed port is Mount's error to
// report (it aborts boot), so by the time an app dials, the port either parsed or
// the process is gone — and a caller reached before Mount gets the default rather
// than an empty string it would have to branch on.
func URL() string {
	if u := env.Or(urlEnv, ""); u != "" {
		return u
	}
	port, err := Port()
	if err != nil || port <= 0 {
		// -1 is the server's "any free port" and is not an address: a client
		// dialing an ephemeral bus is told where it landed through
		// CLOUD_PUBSUB_URL, and one that was told nothing dials the default.
		port = defaultPort
	}
	return "nats://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// Display is URL with the client's password hidden: what a log line, an error or a
// health answer may say. URL itself can carry the credential (nats://user:password@host),
// which is how a client of the shared cluster is given one without a second knob.
func Display() string {
	u, err := neturl.Parse(URL())
	if err != nil {
		return "(CLOUD_PUBSUB_URL is not a URL)"
	}
	return u.Redacted()
}

// Remote reports whether the plane is somewhere other than this process's own
// embedded server: CLOUD_PUBSUB_URL names it. A deployment of several pods sets it to
// the one shared cluster, so every pod sees the same streams and consumers, and then
// no pod runs a server of its own.
func Remote() bool { return env.Or(urlEnv, "") != "" }

// Replicas is how many copies of a stream the plane keeps (CLOUD_PUBSUB_REPLICAS, 1 to
// 5, default 1). The shared cluster states 3; a single embedded node can keep only one,
// and a stream declared with more would be refused.
func Replicas() int {
	n, err := strconv.Atoi(env.Or("CLOUD_PUBSUB_REPLICAS", "1"))
	if err != nil || n < 1 {
		return 1
	}
	return min(n, 5)
}

// clientPort resolves the port the embedded server binds and the default URL dials —
// ONE parse, so the server and its clients cannot land on different ports.
//
// 0 means ANY FREE PORT, and it is spelled -1 to the library, which reads 0 as
// "use my default" and lands back on 4222. It exists because describing an app
// (mk/plugin.mk) MOUNTS it, mounting this one binds a real bus, and a projection of the route table is no
// reason to contend for a fixed port with whatever else is on the host. Without
// it two describes on one machine cannot run at once — and the second fails as a
// bare make Error 2 that names no app, because the parallel run swallows which
// target died.
func Port() (int, error) {
	v := env.Or(portEnv, "")
	if v == "" {
		return defaultPort, nil
	}
	p, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("bad %s %q: %w", portEnv, v, err)
	}
	if p == 0 {
		return -1, nil
	}
	return p, nil
}

// TenantPrefix marks every tenant-created stream and KV bucket, keeping the
// tenant plane disjoint by construction from the platform's own streams (EVENT
// et al.), which never carry it.
//
// It is EXPORTED for the one question a platform subsystem must be able to ask
// before it removes a stream it did not create: is this a tenant's? Asking the
// prefix's OWNER is what keeps that check from becoming a second "t-" literal
// somewhere else, which is how the two would drift apart.
const TenantPrefix = "t-"

// Org resolves the VALIDATED org — the tenant-isolation key — from the context
// cloud.Bridge parked it on. It is never an In field: an In field is
// caller-supplied, so a tenant key read from one would be a cross-tenant read
// the caller asserted for itself. Fails closed off the HTTP path with the same
// 403 every data plane answers.
//
// The org id must also be usable as a NATS subject token and name fragment; one
// that is not (outside [A-Za-z0-9_-], or over 64 bytes) is refused rather than
// mangled — a mangling could collide two orgs onto one namespace.
func Org(ctx context.Context) (string, error) {
	org, err := principal.Acting(ctx)
	if err != nil {
		return "", err
	}
	if !token(org, true) {
		return "", zip.ErrForbidden("org id is not addressable on the bus")
	}
	return org, nil
}

// Qualify is the plane-wide name of one org's stream or bucket, and reports
// whether the caller's name can have one.
//
// The two answers are one call because they are one rule: the physical name is
// "t-<org>-<name>", so it decodes to exactly one (org, name) pair ONLY while the
// caller's half carries no dash. Splitting them into a validator and a formatter
// is how a caller ends up formatting a name it never checked. What the refusal
// MEANS is the caller's to choose — 400 on a create, 404 on a read, so a bad
// name never tells one org that another org's bucket exists.
func Qualify(org, name string) (string, bool) {
	if !token(name, false) || org == "" {
		return "", false
	}
	return Phys(org, name), true
}

// token reports whether s is 1–64 bytes of [A-Za-z0-9_], plus '-' when dash is
// allowed. Stream and bucket names refuse the dash so the physical name
// "t-<org>-<name>" splits at its LAST dash into exactly one (org, name) pair.
func token(s string, dash bool) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		case c == '-' && dash:
		default:
			return false
		}
	}
	return true
}

// Phys is the physical (whole-plane) name of an org's stream, bucket or subject.
func Phys(org, name string) string { return TenantPrefix + addressable(org) + "-" + name }

// addressable is an org id as a plane name: the slug cloud already names that
// org's storage with, and the hash of its bytes for an id the slugger refuses.
//
// An org id may carry a dot or a star. Both fold injectively through the
// slugger, so principal admits both, and a NATS subject reads a dot as a token
// separator and a bare star as a one-token wildcard — so org "a.*.b" formatted
// verbatim is a subject that receives every org's frames.
//
// The slugger is the whole answer rather than a fallback behind a shortcut of
// our own. It is the identity on a clean label, folds everything else to
// "<fold>-<hash of the exact bytes>", and refuses to be the identity on a name
// already shaped like one of its folds — so no org addresses the plane at the
// name another org folds onto. A shortcut that returned a bare token verbatim
// skipped that refusal: "hanzo.ai" folds to "hanzo-ai-46cf0af5224ce42a", which is
// itself a bare token, so an org registered under that name subscribed to the
// first one's subjects and opened its streams and buckets. The hash is public,
// so the colliding name is computable without asking anyone.
//
// The fallback carries that same refusal, which is why it is written in the shape
// of a fold — "<16 hex>-<16 hex>". The slugger declines to be the identity on
// anything ending in a dash and sixteen hex characters, while a BARE sixteen hex
// characters is a clean label it passes through unchanged: that form is a name
// the slugger answers with for an org registered under it, so it addresses the
// same subject, stream and bucket as the org the fallback answers for. The digest
// is public, so that name is computable without asking anyone.
//
// One org has one slug, here and in the store both, because both ask the same
// function.
func addressable(org string) string {
	if slug := namespace.Sanitize(org); slug != "" {
		return slug
	}
	sum := sha256.Sum256([]byte(org))
	return hex.EncodeToString(sum[:8]) + "-" + hex.EncodeToString(sum[8:16])
}
