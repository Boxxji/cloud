package dialect

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Document refuses a JSON document a JSON column would: bytes that are not UTF-8, a
// string that holds a NUL (which a document spells \u0000), or text that is not JSON.
// PostgreSQL's JSONB refuses all three at the statement and SQLite's TEXT keeps them,
// so a store calls it where a document comes in, and the error is the same on both
// engines. The error never carries the document.
func Document(raw []byte) error {
	if err := Text(string(raw)); err != nil {
		return err
	}
	if !json.Valid(raw) {
		return ErrText
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return ErrText
		}
		if s, ok := tok.(string); ok {
			if err := Text(s); err != nil {
				return err
			}
		}
	}
}
