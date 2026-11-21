package text

import "testing"

func TestPlain(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain line\n\twith a tab", "plain line\n\twith a tab"},
		{"\x1b[1;31merror\x1b[0m: build failed", "error: build failed"},
		{"\x1b]0;window title\x07ready", "ready"},
		{"\x1b]8;;https://x\x1b\\link\x1b]8;;\x1b\\", "link"},
		{"10%\r50%\r100%\r\ndone", "10%\n50%\n100%\ndone"},
		{"bell\x07 null\x00 del\x7f", "bell null del"},
		{"\x1b(Bcharset", "charset"},
		{"\x1bMreverse", "reverse"},
		{"cut off \x1b[3", "cut off "},
		{"trailing \x1b", "trailing "},
		{"ünïcödé ✓", "ünïcödé ✓"},
	} {
		if got := Plain(c.in); got != c.want {
			t.Errorf("Plain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Text never leaves a byte a JSON reader must refuse raw.
func TestPlainLeavesNoControlCharacter(t *testing.T) {
	var all []byte
	for c := range 0x80 {
		all = append(all, byte(c), '[', byte(c))
	}
	for _, c := range []byte(Plain(string(all))) {
		if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
			t.Fatalf("control byte %#x survived", c)
		}
	}
}
