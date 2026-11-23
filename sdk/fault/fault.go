// Copyright 2026 Hanzo AI Inc. All Rights Reserved.

// Package fault is the one error type of the platform: what failed, where, why,
// and the key every occurrence of it shares.
//
// A request answered with a 5xx, a run that ended in error, a scheduled job that
// failed and a crash a client reported are four ways one thing happens. Each used
// to name itself differently, so the same fault read as four unrelated lines and
// none of them was a count. A Fault states all four the same way: a Code (the word
// a reader branches on), an Op (the place: a route, a run, a job, a product), a
// Frame (the site: the top frame where one is known, else the root cause and its
// shape) and a Reason (the sentence). Its Fingerprint is a function of the first
// three and of nothing else, so two occurrences of one fault have one key in any
// process, on any day, and a reason that quotes an id does not split them.
//
// The fingerprint is the unit everything downstream counts: the event plane groups
// by it, the aggregator files one issue per fingerprint, and a fix is judged by
// whether the fingerprint stops.
package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Class is the kind of occurrence, which is also what a threshold is set per: a
// browser's lost connection and a server's 500 are not one rate.
type Class string

const (
	// Server is a request this process answered with a 5xx.
	Server Class = "server"
	// Dependency is a 502, 503 or 504: something this process depends on is away.
	Dependency Class = "dependency"
	// Run is a session that ended in error.
	Run Class = "run"
	// Cron is a scheduled job that failed.
	Cron Class = "cron"
	// Client is a crash a client reported through the event plane.
	Client Class = "client"
)

// Fault is one occurrence, stated the same way wherever it happened.
type Fault struct {
	// Class is the kind of occurrence.
	Class Class
	// Code is the machine word: the refusal's own code, else one the status names.
	Code string
	// Op is where it happened: "POST /v1/x/:id" for a request, "run:<agent>" for a
	// run, "cron:<name>" for a job. A route is its PATTERN, never the address a
	// caller typed, so two callers of one route share an Op.
	Op string
	// Frame is the site: the top frame when one is known, else the root cause's
	// type and the shape of its message.
	Frame string
	// Reason is the sentence a reader is told. It is not part of the fingerprint.
	Reason string
	// Status is the HTTP status, 0 for a fault that answered no request.
	Status int
	// Request is the id that ties the occurrence to the response its caller holds.
	Request string
}

// Event is the name a fault is stated under on the event plane.
func (c Class) Event() string {
	switch c {
	case Run:
		return "run_error"
	case Cron:
		return "cron_failed"
	case Client:
		return "client_error"
	}
	return "server_error"
}

// Route is the route pattern of a request's Op, "" for a fault that answered no
// request (a run, a job).
func (f Fault) Route() string {
	if f.Class != Server && f.Class != Dependency {
		return ""
	}
	_, route, _ := strings.Cut(f.Op, " ")
	if route == "(unrouted)" {
		return ""
	}
	return route
}

// Fingerprint is the stable key of the fault: sixteen hex digits over Code, Op and
// Frame. Reason, Status and Request are not in it.
func (f Fault) Fingerprint() string {
	h := sha256.New()
	for _, part := range []string{f.Code, f.Op, f.Frame} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// Sited is an error that knows where it was made. An error that implements it names
// its own top frame, which beats anything inferred from its text.
type Sited interface {
	error
	Site() string
}

// maxFrame bounds a Frame, so a fault whose root cause quotes a page of text still
// has a short key input.
const maxFrame = 160

// Request is the fault of one request answered with status. route is the pattern
// the router matched ("" when none did), code the refusal's own word ("" when it
// had none) and err what the handler returned.
func Request(method, route string, status int, code string, err error) Fault {
	class := Server
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		class = Dependency
	}
	if code == "" {
		code = CodeOf(status)
	}
	f := Fault{Class: class, Code: code, Op: Op(method, route), Frame: Frame(err), Status: status}
	if err != nil {
		f.Reason = err.Error()
	}
	return f
}

// Op names a request's place: its method and the route pattern. A request no route
// matched is named by method alone, so a scanner walking addresses is one fault.
func Op(method, route string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	route = strings.TrimSpace(route)
	if route == "" {
		return method + " (unrouted)"
	}
	return method + " " + route
}

// CodeOf is the word a status names when the refusal carried none. It is used for
// the fingerprint and for a reader; it is never written onto a response, whose own
// code member belongs to the handler that chose it.
func CodeOf(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusPaymentRequired:
		return "payment_required"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "unprocessable"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusInternalServerError:
		return "internal"
	case http.StatusBadGateway:
		return "bad_gateway"
	case http.StatusServiceUnavailable:
		return "unavailable"
	case http.StatusGatewayTimeout:
		return "timeout"
	}
	switch {
	case status >= 500:
		return "server_error"
	case status >= 400:
		return "client_error"
	}
	return "error"
}

// Frame is the site of err: what the error says about itself if it implements
// Sited, else the type of its root cause and the shape of the root's message.
//
// The root, not the outermost: a handler wraps the same failure in a different
// sentence at every call site ("create: %w", "billing: %w"), and the failure is
// what is underneath. The shape strips the variable parts of the message, so "user
// 41 not found" and "user 907 not found" are one frame.
func Frame(err error) string {
	if err == nil {
		return ""
	}
	if s, ok := errors.AsType[Sited](err); ok {
		if site := strings.TrimSpace(s.Site()); site != "" {
			return clip(site)
		}
	}
	root := err
	for {
		if multi, ok := root.(interface{ Unwrap() []error }); ok {
			if inner := multi.Unwrap(); len(inner) > 0 && inner[0] != nil {
				root = inner[0]
				continue
			}
			break
		}
		next := errors.Unwrap(root)
		if next == nil {
			break
		}
		root = next
	}
	return clip(fmt.Sprintf("%T:%s", root, Shape(root.Error())))
}

func clip(s string) string {
	if len(s) <= maxFrame {
		return s
	}
	return strings.ToValidUTF8(s[:maxFrame], "")
}

// Shape strips the variable parts of a message so one failure is one key:
// ISO-8601 timestamps and short digit runs collapse to 0; UUIDs, 0x hex
// literals, hex/alphanumeric IDs (such as k8s job/pod suffixes and hashes)
// collapse to x.
func Shape(msg string) string {
	var b strings.Builder
	b.Grow(len(msg))
	prevCollapsedID := false

	for i := 0; i < len(msg); {
		if n := matchTimestamp(msg, i); n > 0 {
			b.WriteByte('0')
			prevCollapsedID = false
			i += n
			continue
		}
		if matchUUID(msg, i) {
			b.WriteByte('x')
			prevCollapsedID = true
			i += 36
			continue
		}
		if isAlnum(msg[i]) {
			start := i
			for i < len(msg) && isAlnum(msg[i]) {
				i++
			}
			tok := msg[start:i]
			if isVariableID(tok, start > 0 && msg[start-1] == '-', prevCollapsedID) {
				b.WriteByte('x')
				prevCollapsedID = true
				continue
			}
			writeCollapsedDigits(&b, tok)
			prevCollapsedID = false
			continue
		}
		c := msg[i]
		b.WriteByte(c)
		if c != '-' {
			prevCollapsedID = false
		}
		i++
	}
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isLowerAlnum(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'z') }

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isVariableID reports whether an alphanumeric token is a variable identifier
// (hex/numeric hash, 0x literal, mixed random alnum id, or 5-char k8s pod suffix)
// that should collapse to 'x' rather than split fingerprints.
func isVariableID(tok string, afterHyphen, prevCollapsedID bool) bool {
	n := len(tok)
	// 0x / 0X prefixed hex literal (e.g. 0xdeadbeef, 0x1a2b).
	if n >= 3 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X') {
		allHex := true
		for j := 2; j < n; j++ {
			if !isHex(tok[j]) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}

	allDigits := true
	allHex := true
	allLower := true
	hasDigit := false
	transitions := 0
	for j := 0; j < n; j++ {
		c := tok[j]
		d := isDigit(c)
		if d {
			hasDigit = true
		} else {
			allDigits = false
		}
		if !isHex(c) {
			allHex = false
		}
		if !isLowerAlnum(c) {
			allLower = false
		}
		if j > 0 && d != isDigit(tok[j-1]) {
			transitions++
		}
	}

	if allDigits {
		return n >= 8
	}
	// Hex token (e.g. job/commit/pod hash): >=8 chars with at least one digit,
	// or >=10 pure hex chars (avoids collapsing 8-letter English words like "feedback").
	if allHex && n >= 8 && (hasDigit || n >= 10) {
		return true
	}
	// Mixed alphanumeric ID (base32/36/62): >=8 chars with interleaved letters and digits.
	if n >= 8 && hasDigit && transitions >= 2 {
		return true
	}
	// Kubernetes 5-char pod suffix following a hyphen (e.g. -xk9p2, or -abcde after -<rs-hash>-).
	if afterHyphen && n == 5 && allLower && (hasDigit || prevCollapsedID) {
		return true
	}
	return false
}

// writeCollapsedDigits writes tok with every contiguous digit run collapsed to '0'.
func writeCollapsedDigits(b *strings.Builder, tok string) {
	inDigits := false
	for j := 0; j < len(tok); j++ {
		if isDigit(tok[j]) {
			if !inDigits {
				b.WriteByte('0')
				inDigits = true
			}
		} else {
			inDigits = false
			b.WriteByte(tok[j])
		}
	}
}

// matchUUID reports whether msg[i:] begins with a canonical 36-byte UUID
// (8-4-4-4-12 hex) on alphanumeric token boundaries.
func matchUUID(msg string, i int) bool {
	if i+36 > len(msg) {
		return false
	}
	if i > 0 && isAlnum(msg[i-1]) {
		return false
	}
	if i+36 < len(msg) && isAlnum(msg[i+36]) {
		return false
	}
	for k := 0; k < 36; k++ {
		c := msg[i+k]
		if k == 8 || k == 13 || k == 18 || k == 23 {
			if c != '-' {
				return false
			}
		} else if !isHex(c) {
			return false
		}
	}
	return true
}

// matchTimestamp returns the byte length of an ISO-8601 timestamp starting at msg[i]
// (YYYY-MM-DD[T ]HH:MM:SS with optional fractional seconds and Z / ±HH:MM offset),
// or 0 if msg[i:] does not begin with one.
func matchTimestamp(msg string, i int) int {
	if i+19 > len(msg) || !isDigit(msg[i]) {
		return 0
	}
	if i > 0 && isAlnum(msg[i-1]) {
		return 0
	}
	// Check YYYY-MM-DD[T ]HH:MM:SS
	if !isDigit(msg[i+1]) || !isDigit(msg[i+2]) || !isDigit(msg[i+3]) ||
		msg[i+4] != '-' || !isDigit(msg[i+5]) || !isDigit(msg[i+6]) ||
		msg[i+7] != '-' || !isDigit(msg[i+8]) || !isDigit(msg[i+9]) ||
		(msg[i+10] != 'T' && msg[i+10] != 't' && msg[i+10] != ' ') ||
		!isDigit(msg[i+11]) || !isDigit(msg[i+12]) || msg[i+13] != ':' ||
		!isDigit(msg[i+14]) || !isDigit(msg[i+15]) || msg[i+16] != ':' ||
		!isDigit(msg[i+17]) || !isDigit(msg[i+18]) {
		return 0
	}
	j := i + 19
	// Optional fractional seconds (.123456)
	if j < len(msg) && msg[j] == '.' {
		k := j + 1
		for k < len(msg) && isDigit(msg[k]) {
			k++
		}
		if k > j+1 {
			j = k
		}
	}
	// Optional timezone (Z / z / +HH:MM / -HH:MM / +HHMM)
	if j < len(msg) {
		switch msg[j] {
		case 'Z', 'z':
			j++
		case '+', '-':
			if j+6 <= len(msg) && isDigit(msg[j+1]) && isDigit(msg[j+2]) && msg[j+3] == ':' && isDigit(msg[j+4]) && isDigit(msg[j+5]) {
				j += 6
			} else if j+5 <= len(msg) && isDigit(msg[j+1]) && isDigit(msg[j+2]) && isDigit(msg[j+3]) && isDigit(msg[j+4]) {
				j += 5
			}
		}
	}
	if j < len(msg) && isAlnum(msg[j]) {
		return 0
	}
	return j - i
}

// Ended is the fault of a run that ended in error. agent names the kind of run and
// reason is what the run said; a run never ends in error without one, so an empty
// reason is itself the fault's frame and says so.
func Ended(agent, reason string) Fault {
	reason = strings.TrimSpace(reason)
	frame := Shape(reason)
	if reason == "" {
		frame = "(no reason)"
	}
	return Fault{Class: Run, Code: "run_error", Op: "run:" + strings.TrimSpace(agent), Frame: clip(frame), Reason: reason}
}

// Failed is the fault of a scheduled job that did not complete. job names it and
// err is what it returned.
func Failed(job string, err error) Fault {
	f := Fault{Class: Cron, Code: "cron_failed", Op: "cron:" + strings.TrimSpace(job), Frame: Frame(err)}
	if err != nil {
		f.Reason = err.Error()
	}
	return f
}
