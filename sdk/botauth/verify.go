package botauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// skew is how far ahead of the verifier's clock a signature's created may be.
const skew = time.Minute

// Verify checks r's Web Bot Auth signature against a key directory document, as
// a site does: the Signature-Input member tagged web-bot-auth covers @authority
// and, when the request names one, signature-agent; it is inside its validity
// window at now; its keyid is a key the directory publishes; and the signature
// over the rebuilt base verifies under that key. Every refusal wraps
// [ErrRefused].
func Verify(r *http.Request, doc []byte, now time.Time) error {
	keys, err := Published(doc)
	if err != nil {
		return err
	}
	inputs, err := parseDict(strings.Join(r.Header.Values("Signature-Input"), ", "))
	if err != nil {
		return fmt.Errorf("%w: Signature-Input: %v", ErrRefused, err)
	}
	sigs, err := parseDict(strings.Join(r.Header.Values("Signature"), ", "))
	if err != nil {
		return fmt.Errorf("%w: Signature: %v", ErrRefused, err)
	}
	var in *member
	for i := range inputs {
		if tag, _ := inputs[i].params.str("tag"); tag == Tag && inputs[i].list != nil {
			in = &inputs[i]
			break
		}
	}
	if in == nil {
		return fmt.Errorf("%w: no signature is tagged %s", ErrRefused, Tag)
	}
	var sig []byte
	for _, m := range sigs {
		if m.name == in.name {
			sig = m.bytes
		}
	}
	if sig == nil {
		return fmt.Errorf("%w: no Signature named %s", ErrRefused, in.name)
	}

	agent := strings.Join(r.Header.Values("Signature-Agent"), ", ")
	if !slices.Contains(in.list, "@authority") {
		return fmt.Errorf("%w: the signature does not cover @authority", ErrRefused)
	}
	if agent != "" && !slices.Contains(in.list, "signature-agent") {
		return fmt.Errorf("%w: the signature does not cover signature-agent", ErrRefused)
	}
	if alg, ok := in.params.str("alg"); ok && alg != "ed25519" {
		return fmt.Errorf("%w: alg %q", ErrRefused, alg)
	}
	created, ok := in.params.integer("created")
	if !ok || time.Unix(created, 0).After(now.Add(skew)) {
		return fmt.Errorf("%w: created is missing or in the future", ErrRefused)
	}
	expires, ok := in.params.integer("expires")
	if !ok || !now.Before(time.Unix(expires, 0)) {
		return fmt.Errorf("%w: the signature has expired", ErrRefused)
	}
	keyid, _ := in.params.str("keyid")
	pub, ok := keys[keyid]
	if !ok {
		return fmt.Errorf("%w: keyid %q is not in the directory", ErrRefused, keyid)
	}

	var base strings.Builder
	for _, c := range in.list {
		var v string
		switch c {
		case "@authority":
			v = authority(r)
		case "signature-agent":
			v = agent
		default:
			h := r.Header.Values(c)
			if strings.HasPrefix(c, "@") || len(h) == 0 {
				return fmt.Errorf("%w: cannot cover %q", ErrRefused, c)
			}
			v = strings.Join(h, ", ")
		}
		base.WriteString(strconv.Quote(c) + ": " + v + "\n")
	}
	base.WriteString(`"@signature-params": ` + in.raw)
	if !ed25519.Verify(pub, []byte(base.String()), sig) {
		return fmt.Errorf("%w: the signature does not verify under key %s", ErrRefused, keyid)
	}
	return nil
}

// VerifyDirectory checks a directory response the way a verifier that fetched it
// at authority does: every key the document publishes has a signature in the
// response's headers, tagged http-message-signatures-directory, over
// ("@authority";req), that verifies under that key at now.
func VerifyDirectory(h http.Header, authority string, doc []byte, now time.Time) error {
	keys, err := Published(doc)
	if err != nil {
		return err
	}
	inputs, err := parseDict(strings.Join(h.Values("Signature-Input"), ", "))
	if err != nil {
		return fmt.Errorf("%w: Signature-Input: %v", ErrRefused, err)
	}
	sigs, err := parseDict(strings.Join(h.Values("Signature"), ", "))
	if err != nil {
		return fmt.Errorf("%w: Signature: %v", ErrRefused, err)
	}
	signed := map[string]bool{}
	for _, in := range inputs {
		if tag, _ := in.params.str("tag"); tag != DirectoryTag {
			continue
		}
		keyid, _ := in.params.str("keyid")
		pub, ok := keys[keyid]
		if !ok || len(in.list) != 1 || in.list[0] != "@authority" || !in.req[0] {
			continue
		}
		created, cok := in.params.integer("created")
		expires, eok := in.params.integer("expires")
		if !cok || !eok || time.Unix(created, 0).After(now.Add(skew)) || !now.Before(time.Unix(expires, 0)) {
			continue
		}
		base := `"@authority";req: ` + normalAuthority(authority, "https") + "\n" + `"@signature-params": ` + in.raw
		for _, s := range sigs {
			if s.name == in.name && ed25519.Verify(pub, []byte(base), s.bytes) {
				signed[keyid] = true
			}
		}
	}
	for id := range keys {
		if !signed[id] {
			return fmt.Errorf("%w: the directory does not prove it holds key %s", ErrRefused, id)
		}
	}
	return nil
}

// member is one Dictionary member of Signature-Input or Signature: an inner list
// of component names (each with whether it carries req) and its parameters, or a
// byte sequence. raw is the member's value exactly as received, which is what
// @signature-params repeats.
type member struct {
	name   string
	list   []string
	req    []bool
	params params
	bytes  []byte
	raw    string
}

type params []param

type param struct {
	key string
	val any // string, int64, []byte, bool, or a token as string
}

func (p params) str(k string) (string, bool) {
	for _, x := range p {
		if x.key == k {
			s, ok := x.val.(string)
			return s, ok
		}
	}
	return "", false
}

func (p params) integer(k string) (int64, bool) {
	for _, x := range p {
		if x.key == k {
			n, ok := x.val.(int64)
			return n, ok
		}
	}
	return 0, false
}

// parseDict reads an RFC 8941 Dictionary whose members are inner lists of
// strings or byte sequences, each with parameters: the two shapes RFC 9421's
// fields take.
func parseDict(s string) ([]member, error) {
	p := &sf{s: s}
	var out []member
	p.ows()
	for !p.done() {
		name := p.key()
		if name == "" {
			return nil, fmt.Errorf("a member has no name at %d", p.i)
		}
		if !p.eat('=') {
			return nil, fmt.Errorf("member %s has no value", name)
		}
		m := member{name: name}
		start := p.i
		switch {
		case p.peek() == '(':
			p.i++
			for {
				p.sp()
				if p.eat(')') {
					break
				}
				c, err := p.str()
				if err != nil {
					return nil, err
				}
				ps, err := p.params()
				if err != nil {
					return nil, err
				}
				_, req := ps.boolean("req")
				m.list, m.req = append(m.list, c), append(m.req, req)
				if p.done() {
					return nil, fmt.Errorf("member %s: unterminated list", name)
				}
			}
		case p.peek() == ':':
			b, err := p.byteSeq()
			if err != nil {
				return nil, err
			}
			m.bytes = b
		default:
			return nil, fmt.Errorf("member %s is neither a list nor bytes", name)
		}
		ps, err := p.params()
		if err != nil {
			return nil, err
		}
		m.params, m.raw = ps, s[start:p.i]
		out = append(out, m)
		p.ows()
		if p.done() {
			break
		}
		if !p.eat(',') {
			return nil, fmt.Errorf("expected , after member %s", name)
		}
		p.ows()
	}
	return out, nil
}

func (p params) boolean(k string) (bool, bool) {
	for _, x := range p {
		if x.key == k {
			b, ok := x.val.(bool)
			return b, ok && b
		}
	}
	return false, false
}

// sf is a cursor over a structured field.
type sf struct {
	s string
	i int
}

func (p *sf) done() bool { return p.i >= len(p.s) }

func (p *sf) peek() byte {
	if p.done() {
		return 0
	}
	return p.s[p.i]
}

func (p *sf) eat(c byte) bool {
	if p.peek() == c && !p.done() {
		p.i++
		return true
	}
	return false
}

func (p *sf) sp() {
	for p.peek() == ' ' {
		p.i++
	}
}

func (p *sf) ows() {
	for p.peek() == ' ' || p.peek() == '\t' {
		p.i++
	}
}

func (p *sf) key() string {
	start := p.i
	for !p.done() {
		c := p.s[p.i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '*' {
			p.i++
			continue
		}
		break
	}
	return p.s[start:p.i]
}

func (p *sf) str() (string, error) {
	if !p.eat('"') {
		return "", fmt.Errorf("expected a string at %d", p.i)
	}
	var b strings.Builder
	for !p.done() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '\\':
			if p.done() {
				return "", fmt.Errorf("unterminated escape")
			}
			b.WriteByte(p.s[p.i])
			p.i++
		case c == '"':
			return b.String(), nil
		default:
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("unterminated string")
}

func (p *sf) byteSeq() ([]byte, error) {
	if !p.eat(':') {
		return nil, fmt.Errorf("expected a byte sequence at %d", p.i)
	}
	end := strings.IndexByte(p.s[p.i:], ':')
	if end < 0 {
		return nil, fmt.Errorf("unterminated byte sequence")
	}
	b, err := base64.StdEncoding.DecodeString(p.s[p.i : p.i+end])
	if err != nil {
		return nil, fmt.Errorf("a byte sequence is not base64")
	}
	p.i += end + 1
	return b, nil
}

func (p *sf) params() (params, error) {
	var out params
	for p.eat(';') {
		p.sp()
		k := p.key()
		if k == "" {
			return nil, fmt.Errorf("a parameter has no name at %d", p.i)
		}
		if !p.eat('=') {
			out = append(out, param{k, true})
			continue
		}
		switch c := p.peek(); {
		case c == '"':
			s, err := p.str()
			if err != nil {
				return nil, err
			}
			out = append(out, param{k, s})
		case c == ':':
			b, err := p.byteSeq()
			if err != nil {
				return nil, err
			}
			out = append(out, param{k, b})
		case c == '?':
			p.i++
			switch {
			case p.eat('1'):
				out = append(out, param{k, true})
			case p.eat('0'):
				out = append(out, param{k, false})
			default:
				return nil, fmt.Errorf("parameter %s is not a boolean", k)
			}
		case c == '-' || c >= '0' && c <= '9':
			start := p.i
			p.i++
			for !p.done() && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
				p.i++
			}
			n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parameter %s is not an integer", k)
			}
			out = append(out, param{k, n})
		default:
			start := p.i
			for !p.done() && !strings.ContainsRune(" ;,()=\"", rune(p.s[p.i])) {
				p.i++
			}
			out = append(out, param{k, p.s[start:p.i]})
		}
	}
	return out, nil
}
