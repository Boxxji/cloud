package tenure

// field.go — Cipher for one VALUE of one COLUMN of one ROW, so a column that holds
// personal data or a credential is ciphertext in the database and a reader of the
// storage (a disk, a snapshot, a replica, a backup, a role with SELECT) gets none of it.
//
// WHY IT EXISTS. A SQLite store was a SQLCipher file, so every byte was ciphertext on
// disk; a store on hanzo-sql is plaintext rows. The owner's rule is that what the files
// protected is still protected after the move: those fields are sealed columns, never
// plaintext. Conceal (cipher.go) was the first of them, for a TIN, and it binds a value
// to a namespace and a subsystem only. It cannot say "this ciphertext belongs to THIS
// row's THIS column", it has no version to rotate by, its 96-bit random nonces are bounded
// at 2^32 seals per key, and it leaves each caller to write its own prefix, base64 and
// legacy branch (apps/tax, webhook, provider each did). This is the one that does, and a
// store that seals a column should use it.
//
//	c, _ := org.NewCipher(master)                       // master = cloud.Deps.MasterKey
//	f, _ := c.Fields(namespace.System(), "compliance")  // the namespace the schema is keyed on
//	r := f.Row("compliance_subject", org, id)           // table and primary key
//	enc := r.Seal("email", "a@b.example")               // store enc in the TEXT column
//	got := r.Open("email", enc)                         // read it back
//	if err := r.Err(); err != nil { ... }               // the first failure; later calls answer ""
//
// THE CONSTRUCTION. The key is Cipher's: cek.DeriveKey(master, namespace, subsystem), the
// one place a master becomes a key, the same derivation that keys the SQLCipher file. It is
// never used as a key itself. The SQLCipher page key is that value, so a column key is a
// different output of it (HKDF-Expand with its own label), and so is the blind-index key:
//
//	prk  = cek.DeriveKey(root, namespace, subsystem)
//	key  = HKDF-Expand(prk, "hanzo/org/field/v1/aead")
//	bkey = HKDF-Expand(prk, "hanzo/org/field/v1/blind")
//
// The AEAD is XChaCha20-Poly1305 with a fresh random 192-bit nonce per seal, and not the
// AES-256-GCM Conceal uses, for one reason: a column such as a visitor's touch is sealed
// twelve values at a time on every browser event under ONE namespace key, and GCM's 96-bit
// random nonce must not be drawn more than 2^32 times per key. 192 bits has no such bound
// to count against. A value is
//
//	"seal:" + base64url( version || nonce(24) || AEAD(plaintext) )
//
// with the version, namespace, subsystem, table, column and the row's primary key all in the
// associated data, each length-framed so no two bindings render the same bytes. A ciphertext
// moved to another row, tenant, column, table or namespace, or relabelled with another
// version, fails its tag. Text, not bytes: it is valid in a Postgres TEXT column whatever
// the plaintext was (TEXT refuses NUL and invalid UTF-8), and it carries a prefix a SQL
// predicate can ask of either engine.
//
// WHAT IS NOT HIDDEN. The length of a value (the overhead is 41 bytes, unpadded) and
// whether it is empty: an empty value is stored empty, so a column that defaults to the
// empty string keeps its meaning and "has an email" stays a fact the schema can carry. That
// also means emptiness is not authenticated: a writer can blank a column, though it cannot
// fill one.
//
// EQUALITY. A store that must find a row by a sealed value never seals deterministically
// (that makes the ciphertexts an equality oracle over the whole column). It keeps a second
// column holding Blind(table, column, value), a keyed HMAC, and looks up by that. The index
// reveals which rows share a value, and nothing else, to a reader without the key. No store
// sealed so far needs one: its sealed fields are read by their row's key.
//
// ROTATION. A root has a version; the newest seals and every held root opens. WithRoot adds
// one. Nothing supplies a second root from configuration yet, because cek has none: a new
// master reopens no file. Version 1 is NewCipher's master. A sweep that re-seals old
// versions, and the re-index a Blind column needs after one, are written when a second root
// exists to test them on. Seal, Open and Conceal stay on version 1 and their formats, which
// carry no version and are on disk.

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/hanzoai/cek"
	"github.com/hanzoai/namespace"
	"golang.org/x/crypto/chacha20poly1305"
)

// The refusals. Each wraps with the table and column, never the value or the bytes.
var (
	// ErrFieldPlain is a non-empty value that is not a sealed one. On hanzo-sql that is a
	// defect (a row written around the store); on SQLite it is a row that predates sealing,
	// which Upgrade seals before any read.
	ErrFieldPlain = errors.New("org: the field is not sealed")
	// ErrFieldMalformed is a sealed value that does not parse: truncated, or not the one
	// canonical encoding of its bytes.
	ErrFieldMalformed = errors.New("org: the sealed field is malformed")
	// ErrFieldVersion is a sealed value under a root this process does not hold.
	ErrFieldVersion = errors.New("org: the sealed field is under a root version this process does not hold")
	// ErrFieldAuth is a value that parses and does not authenticate: tampered, moved to
	// another row, column, table or namespace, or sealed under another root. The causes are
	// one answer on purpose; telling them apart tells an attacker which part of the binding
	// to fix.
	ErrFieldAuth = errors.New("org: the sealed field does not authenticate")
	// ErrFieldRow is a row that names too little to bind to: no table, no column, or no key.
	ErrFieldRow = errors.New("org: a field needs a table, a column and a row key")
)

const (
	// fieldPrefix leads every sealed value. It is what Open and Upgrade tell a sealed value
	// from a plaintext one by, and it is ASCII so a SQL predicate can ask it of either
	// engine.
	fieldPrefix = "seal:"

	labelAEAD  = "hanzo/org/field/v1/aead"
	labelBlind = "hanzo/org/field/v1/blind"
	labelAAD   = "hanzo/org/field/v1/aad"

	fieldNonce = chacha20poly1305.NonceSizeX
	// fieldMin is a version, a nonce and a tag: a sealed empty message, the shortest there is.
	fieldMin = 1 + fieldNonce + chacha20poly1305.Overhead
)

// WithRoot returns a Cipher that also holds master as root version. The highest version
// seals fields; every held version opens them. Version 1 is NewCipher's master, so version
// is 2 or more and not one already held.
func (c *Cipher) WithRoot(version uint8, master []byte) (*Cipher, error) {
	if version < 2 {
		return nil, fmt.Errorf("org: root version %d: version 1 is NewCipher's master", version)
	}
	if len(master) != keyLen {
		return nil, fmt.Errorf("org: root key must be %d bytes, got %d", keyLen, len(master))
	}
	if _, held := c.later[version]; held {
		return nil, fmt.Errorf("org: root version %d is held already", version)
	}
	next := &Cipher{master: c.master, later: maps.Clone(c.later)}
	if next.later == nil {
		next.later = map[uint8][]byte{}
	}
	next.later[version] = append([]byte(nil), master...)
	return next, nil
}

// Fields seals and opens the columns of one namespace's one subsystem. It holds derived
// keys only, is safe for concurrent use, and is made once when the store opens.
type Fields struct {
	ns, subsystem string
	aead          map[uint8]cipher.AEAD
	newest        uint8
	blind         []byte // the newest root's blind-index key
}

// Fields derives the keys for ns and subsystem from every root c holds. It fails closed: the
// zero namespace and an empty subsystem refuse, so a store never comes up able to write a
// plaintext column because a key was missing. Pass the namespace and subsystem the store's
// database is opened under: a column's key and its schema then cannot name two things.
func (c *Cipher) Fields(ns namespace.Namespace, subsystem string) (*Fields, error) {
	roots := map[uint8][]byte{1: c.master}
	maps.Copy(roots, c.later)
	f := &Fields{ns: ns.String(), subsystem: subsystem, aead: map[uint8]cipher.AEAD{}}
	for version, root := range roots {
		prk, err := cek.DeriveKey(root, ns, subsystem)
		if err != nil {
			return nil, fmt.Errorf("org: fields: %w", err)
		}
		key, err := expand(prk, labelAEAD)
		if err != nil {
			return nil, err
		}
		a, err := chacha20poly1305.NewX(key)
		zero(key)
		if err != nil {
			return nil, fmt.Errorf("org: fields: aead: %w", err)
		}
		f.aead[version] = a
		if version > f.newest {
			bkey, err := expand(prk, labelBlind)
			if err != nil {
				return nil, err
			}
			zero(f.blind)
			f.newest, f.blind = version, bkey
		}
		zero(prk)
	}
	return f, nil
}

// Row is a row of a table, held to its Fields, for a store that seals or opens several
// columns of it and wants to check one error. The first failure stops the rest: every
// later call answers the empty string, and Err says what failed.
//
// key is the row's primary key, one element per key column in key order. The tenant column
// belongs in it even when the primary key is only an id, so a row cannot be carried to
// another tenant with its ciphertexts.
type Row struct {
	f     *Fields
	table string
	key   []string
	err   error
}

// Row names a row by its table and primary key.
func (f *Fields) Row(table string, key ...string) *Row {
	r := &Row{f: f, table: table, key: append([]string(nil), key...)}
	if table == "" || len(key) == 0 {
		r.err = ErrFieldRow
	}
	return r
}

// Err is the first failure of the row's Seal and Open calls, or nil.
func (r *Row) Err() error { return r.err }

// Seal returns the text to store in column. The empty string seals to the empty string. Two
// seals of one value differ.
func (r *Row) Seal(column, plain string) string {
	if r.err != nil {
		return ""
	}
	if column == "" {
		r.err = ErrFieldRow
		return ""
	}
	if plain == "" {
		return ""
	}
	f := r.f
	buf := make([]byte, 1+fieldNonce, fieldMin+len(plain))
	buf[0] = f.newest
	if _, err := io.ReadFull(rand.Reader, buf[1:]); err != nil {
		r.err = fmt.Errorf("org: field nonce: %w", err)
		return ""
	}
	buf = f.aead[f.newest].Seal(buf, buf[1:1+fieldNonce], []byte(plain), f.aad(f.newest, r.table, column, r.key))
	return fieldPrefix + base64.RawURLEncoding.EncodeToString(buf)
}

// Open returns the plaintext of a value read from column. The empty string opens to the
// empty string. A value that is not sealed is ErrFieldPlain, never passed through: a
// plaintext written around the store must not read as if the store wrote it.
func (r *Row) Open(column, stored string) string {
	if r.err != nil {
		return ""
	}
	if column == "" {
		r.err = ErrFieldRow
		return ""
	}
	if stored == "" {
		return ""
	}
	at := r.table + "." + column
	body, ok := strings.CutPrefix(stored, fieldPrefix)
	if !ok {
		r.err = fmt.Errorf("%w: %s", ErrFieldPlain, at)
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	// Decoding forgives what the encoder would not write (a line break, a spare bit in the
	// last character), so two texts would open as one ciphertext. Only the encoder's own
	// output is a sealed value.
	if err != nil || len(raw) < fieldMin || base64.RawURLEncoding.EncodeToString(raw) != body {
		r.err = fmt.Errorf("%w: %s", ErrFieldMalformed, at)
		return ""
	}
	version := raw[0]
	a, ok := r.f.aead[version]
	if !ok {
		r.err = fmt.Errorf("%w: %s version %d", ErrFieldVersion, at, version)
		return ""
	}
	plain, err := a.Open(nil, raw[1:1+fieldNonce], raw[1+fieldNonce:], r.f.aad(version, r.table, column, r.key))
	if err != nil {
		r.err = fmt.Errorf("%w: %s", ErrFieldAuth, at)
		return ""
	}
	return string(plain)
}

// Blind is the lookup key of a sealed value: HMAC-SHA256, under the namespace's blind key,
// of the table, the column and the value, in hex. It is stable for one namespace and
// differs across namespaces, subsystems, tables, columns and values, so it equates rows of
// one column of one store and correlates nothing else. The empty value has no index (the
// empty string), as it has no ciphertext.
//
// It is keyed by the newest root. After a root is added, an index column is rebuilt from
// the sealed values (Open, then Blind): it is derived data.
func (f *Fields) Blind(table, column, value string) string {
	if value == "" {
		return ""
	}
	m := hmac.New(sha256.New, f.blind)
	m.Write(frame(frame(nil, table), column))
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}

// aad is what a ciphertext is authenticated against. Every variable part is framed by its
// length, so the bytes of ("ab","c") and ("a","bc") differ; the version leads, so a value
// cannot be relabelled with another root's version and still authenticate.
func (f *Fields) aad(version uint8, table, column string, key []string) []byte {
	b := make([]byte, 0, 96)
	b = append(b, labelAAD...)
	b = append(b, version)
	b = frame(b, f.ns)
	b = frame(b, f.subsystem)
	b = frame(b, table)
	b = frame(b, column)
	b = binary.BigEndian.AppendUint32(b, uint32(len(key)))
	for _, k := range key {
		b = frame(b, k)
	}
	return b
}

func frame(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// expand is one purpose's 32-byte key out of the namespace's key.
func expand(prk []byte, label string) ([]byte, error) {
	k, err := hkdf.Expand(sha256.New, prk, label, keyLen)
	if err != nil {
		return nil, fmt.Errorf("org: derive field key: %w", err)
	}
	return k, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
