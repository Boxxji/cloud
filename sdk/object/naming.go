package object

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strings"

	"github.com/hanzoai/cloud/sdk/env"
)

// How a tenant's resource becomes a physical name on a shared backend.
//
// Every engine and every subsystem needs the same answer, and a second derivation
// is how two orgs fold onto one bucket. The fixed-width hash is the part that
// matters: joining org and name with a separator folds the boundary ("acme"+"my-db"
// and "acme-my"+"db" produced the SAME identifier, a cross-tenant collision). A
// 64-bit hash of the org, always 16 characters, cannot be confused with the name
// that follows it.

// OrgHash is the fixed-width tenant discriminator: 64 bits of SHA-256, hex.
func OrgHash(org string) string {
	sum := sha256.Sum256([]byte(org))
	return hex.EncodeToString(sum[:])[:16]
}

// Ident folds '-' to '_', the only non-alphanumeric a validated name may carry.
// Valid names never contain '_', so the fold round-trips and stays injective.
func Ident(name string) string { return strings.ReplaceAll(name, "-", "_") }

// PhysicalName namespaces a resource as "o"<OrgHash>_<Ident>. The leading 'o'
// keeps it alpha-initial, which every backend accepts as an identifier. With a
// name of 40 characters or fewer the result is at most 58, inside both a 63
// character bucket limit and Postgres's 63-character identifier limit. A store
// that wraps the bucket (AffixEnv) leaves less room, and Bucket shortens a longer name.
func PhysicalName(org, name string) string {
	return "o" + OrgHash(org) + "_" + Ident(name)
}

// BucketName is the physical bucket a tenant's named resource lives in.
func BucketName(org, name string) string { return BucketOf(PhysicalName(org, name)) }

// BucketPrefix is the string every one of a tenant's buckets begins with, which
// is what makes a listing filterable back to one org.
func BucketPrefix(org string) string { return BucketOf("o"+OrgHash(org)) + "-" }

// AffixEnv names how many characters the store puts around a bucket name before it
// reaches AWS: the AWS gateway's bucket.prefix and bucket.suffix, 22 of them. A
// store that adds none leaves it unset.
const AffixEnv = "S3_BUCKET_AFFIX"

// tagLen is the hex digits of the hash that keeps a shortened name distinct.
const tagLen = 10

// BucketOf renders a physical name in the alphabet buckets accept and within the length
// the store can hold: 63 characters less the store's own affix. A name that fits is
// returned as it was; one that does not keeps its leading characters, which carry the
// org's prefix, and ends in a hash of the whole name, so it is deterministic, still
// ordered under its org, and distinct from every other name. A name this function
// returned fits, and so BucketOf its friendly part returns it again: a listing's
// names can be addressed.
func BucketOf(physical string) string {
	b := strings.Trim(strings.ToLower(strings.ReplaceAll(physical, "_", "-")), "-")
	room := 63 - env.Int(AffixEnv, 0)
	if len(b) <= room {
		return b
	}
	sum := sha256.Sum256([]byte(physical))
	tag := hex.EncodeToString(sum[:])[:tagLen]
	return strings.Trim(b[:room-1-tagLen], "-") + "-" + tag
}

// friendlyRE is the FRIENDLY bucket name a tenant supplies: a DNS-safe slug of at
// most 40 characters. BucketName of a name this shape admits is always a legal
// bucket name, so the friendly<->physical map round-trips.
var friendlyRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// Friendly reports whether name is a bucket name a tenant may address. It is
// checked AS-IS, never lowercased: a name in a request must be exactly what a
// listing showed, so "Photos" is refused rather than quietly read as "photos".
func Friendly(name string) bool { return friendlyRE.MatchString(name) }

// Key normalizes an object key and refuses any traversal or unsafe byte. A key may
// contain "/" (nested paths) but must not be absolute, empty, a directory marker,
// or escape via "..". It must also hold no control byte (\x00-\x1f) or backslash:
// neither appears in a legitimate key, a null byte serializes as %00 in a presigned
// URL and can truncate a C-string consumer downstream, and '\' is a separator a
// non-Go backend may split on. path.Clean collapses "a/../b"; any residual "../"
// or leading "/" is then refused.
func Key(raw string) (string, bool) {
	k := strings.TrimSpace(raw)
	if k == "" || strings.HasPrefix(k, "/") || strings.HasSuffix(k, "/") {
		return "", false
	}
	for _, r := range k {
		if r < 0x20 || r == '\\' {
			return "", false
		}
	}
	clean := path.Clean(k)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", false
	}
	return clean, true
}

// bucketRE is what any engine accepts as a bucket: DNS-safe, 3 to 63 characters.
var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ValidBucket reports whether name is a bucket an engine can hold. It is wider than
// Friendly (which is what a tenant may type) and is the check Local makes before a
// name becomes a directory.
func ValidBucket(name string) bool {
	return bucketRE.MatchString(name) && !strings.Contains(name, "..")
}
