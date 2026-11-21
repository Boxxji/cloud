package iam

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// envelope is the legacy verb shape.
type envelope struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
}

// Answer returns the payload of one IAM response, or an error carrying IAM's own
// message. raw is the (size-bounded) body; it is never logged by this package —
// a user row carries an address, and a key mint carries a secret exactly once.
// ErrNotFound is IAM answering that the row is not there. Wrapped into the error
// a 404 returns, so a caller that treats absence as success — a delete, a rotate
// clearing the previous row — can say so with errors.Is instead of matching on
// the words in a message.
var ErrNotFound = errors.New("iam: not found")

// ErrConflict is IAM refusing to overwrite something that already exists — a key
// name already held, an org already registered. A caller that means to REPLACE
// the thing reads this and clears the old row; one that does not, reports it.
var ErrConflict = errors.New("iam: conflict")

func Answer(status int, raw []byte) (json.RawMessage, error) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return nil, fmt.Errorf("iam denied (%d)", status)
	}
	var env envelope
	enveloped := json.Unmarshal(raw, &env) == nil && env.Status != ""

	if status < 200 || status >= 300 {
		// A 404 is wrapped rather than flattened, because "there was no such row"
		// is an ANSWER to a delete and a failure to a read, and only the caller
		// knows which it asked. Every other status keeps its own words.
		err := fmt.Errorf("iam: %s", message(env, raw, status))
		switch status {
		case http.StatusNotFound:
			return nil, fmt.Errorf("%w: %s", ErrNotFound, err)
		case http.StatusConflict:
			return nil, fmt.Errorf("%w: %s", ErrConflict, err)
		}
		return nil, err
	}
	if enveloped {
		if env.Status != "ok" {
			return nil, fmt.Errorf("iam: %s", message(env, raw, status))
		}
		return env.Data, nil
	}
	// A 2xx that is not an envelope: the body is the resource.
	return json.RawMessage(raw), nil
}

// message is IAM's own words for a refusal, whichever shape carried them, and a
// bare status only when it said nothing.
func message(env envelope, raw []byte, status int) string {
	var alt struct {
		Error string `json:"error"`
		Msg   string `json:"msg"`
	}
	_ = json.Unmarshal(raw, &alt)
	return cmp.Or(env.Msg, alt.Error, alt.Msg, fmt.Sprintf("iam status %d", status))
}
