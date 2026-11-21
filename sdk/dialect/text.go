package dialect

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// ErrText is what Text answers for a value PostgreSQL would refuse.
var ErrText = errors.New("dialect: text holds a NUL byte or is not valid UTF-8")

// Text refuses, before it is stored, a value the two engines disagree about.
// SQLite keeps any bytes a TEXT column is given; PostgreSQL refuses a NUL byte and
// bytes that are not UTF-8, at the statement, with an error that names neither the
// column nor the cause. A store calls it at the boundary where text comes in, so a
// value that fits on one engine is the same error on both, and says why. The error
// never carries the value: what is refused may be a secret.
func Text(values ...string) error {
	for _, v := range values {
		if strings.IndexByte(v, 0) >= 0 || !utf8.ValidString(v) {
			return ErrText
		}
	}
	return nil
}
