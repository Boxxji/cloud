package text

import "strings"

const esc = 0x1b

// Plain is s with its terminal escape sequences removed and every control
// character but the line break and the tab dropped. A carriage return becomes a
// line break, so a progress bar's redraws read as the lines they were rather
// than running together.
//
// It removes what ECMA-48 says a terminal consumes: a CSI sequence (ESC [ …
// through a final byte in @–~), an OSC sequence (ESC ] … through BEL or ESC \),
// and any other ESC with its intermediate bytes and the final byte after them.
// An escape cut off at the end of s is dropped whole.
func Plain(s string) string {
	if clean(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == esc:
			i = skip(s, i)
		case c == '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				continue // the \n that follows is the break
			}
			b.WriteByte('\n')
		case c == '\n' || c == '\t':
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			// a control character nothing downstream can show
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// skip answers the index of the last byte of the escape sequence starting at s[i].
func skip(s string, i int) int {
	if i+1 >= len(s) {
		return i
	}
	switch s[i+1] {
	case '[': // CSI: parameters and intermediates, then one final byte
		for j := i + 2; j < len(s); j++ {
			if s[j] >= 0x40 && s[j] <= 0x7e {
				return j
			}
		}
		return len(s) - 1
	case ']': // OSC: a string, ended by BEL or by ESC \
		for j := i + 2; j < len(s); j++ {
			if s[j] == 0x07 {
				return j
			}
			if s[j] == esc && j+1 < len(s) && s[j+1] == '\\' {
				return j + 1
			}
		}
		return len(s) - 1
	}
	j := i + 1 // any other escape: intermediates in space–/, then one final byte
	for j < len(s)-1 && s[j] >= 0x20 && s[j] <= 0x2f {
		j++
	}
	return j
}

// clean reports whether s has nothing Text would change, which is the common
// case and costs one pass with no allocation.
func clean(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}
