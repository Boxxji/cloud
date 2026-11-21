// Copyright © 2026 Hanzo AI. MIT License.

package iam

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/cloud/sdk/plane"
	"github.com/hanzoai/cloud/sdk/principal"
	"github.com/zap-proto/zip"
)

// IAMSelf answers who the CALLER is as one person: their IAM user row's id,
// which their sign-in token carries as `sub`, and the row's `<owner>/<name>`,
// which is the subject every API key of theirs presents. One person signs in
// with the one and calls with the other, so a record one person holds — a
// machine, a tunnel account, a place in a pool — is keyed on the id, which both
// credentials resolve to. The subject is the caller's and never an argument,
// as for [IAMEmail].
const IAMSelf = "iam_self"

// Self is the one person behind a call, whichever credential they made it
// with.
//
// A person reaches cloud with two kinds of credential, and each presents its own
// subject (Principal.Stable): their sign-in token its `sub`, the id of their IAM
// user row, and every API key of theirs the row's `<owner>/<name>`. A record one
// person holds — a machine they linked, a tunnel account, a place in a pool —
// keyed on the subject is two records for one person. Both credentials resolve to
// the row, so the row's id is the key.
type Self struct {
	// ID is what a record one person holds is keyed on: the id of their IAM user
	// row, the `sub` their sign-in token carries, whichever credential the call
	// came with. An application acting as itself is its own `app:` subject, and a
	// row IAM minted no id for is keyed on its `<owner>/<name>`, which is then its
	// token's `sub` as well. Empty is nobody.
	ID string `json:"id"`
	// Row is the row's `<owner>/<name>`, the subject an API key of theirs
	// presented, and what a record they made with one was keyed on before records
	// were keyed on ID. It is matched to carry such a record across (Is) and is
	// never written: IAM deletes a row outright, which frees its name for whoever
	// signs up next. Empty when it could not be read.
	Row string `json:"row"`
}

// Is reports whether key names this person: their ID, or their Row, which a
// record of theirs written with an API key before is keyed on. Empty is nobody's.
func (p Self) Is(key string) bool {
	return key != "" && (key == p.ID || key == p.Row)
}

// unread is the refusal of an API key whose person IAM did not say.
const unread = "who this API key belongs to cannot be read right now; try again"

// appPrefix marks an application's subject, which no user row holds (the
// identity boundary's userID).
const appPrefix = "app:"

// SelfFrom is the caller as one person (Self): the subject the identity
// boundary attested (SubjectFrom), resolved to the IAM user row it names.
//
// A sign-in's subject is the row's id, so its ID stands even when IAM cannot be
// asked; only its Row, which carries an older record across, goes unread. An
// API key's subject is the row's `<owner>/<name>`, and the id it resolves to is
// IAM's to say: when IAM cannot say it, the call is refused (503) rather than
// keyed on the name, which is the split this exists to close. An application
// acting as itself is its own subject, a call naming nobody is nobody, and a
// credential that names no stable subject is refused (403).
//
// IAM answers for the caller on ctx (IAMSelf); each answer is kept for
// a minute, so a machine's daemon, which polls all day, asks once a minute.
func SelfFrom(ctx context.Context) (Self, error) {
	sub, ok := principal.SubjectFrom(ctx)
	if !ok {
		return Self{}, zip.ErrForbidden("this credential names no person: sign in again, or use an API key")
	}
	sub = strings.TrimSpace(sub)
	if sub == "" || strings.HasPrefix(sub, appPrefix) {
		return Self{ID: sub}, nil
	}
	if p, ok := people.get(sub); ok {
		return p, nil
	}
	keyed := strings.Contains(sub, "/")
	row, err := plane.Call[struct{}, Self](ctx, "iam", IAMSelf, &struct{}{})
	if err != nil || row == nil {
		row = &Self{}
	}
	p := Self{ID: strings.TrimSpace(row.ID), Row: strings.TrimSpace(row.Row)}
	switch {
	case keyed && (p.Row != sub || p.ID == ""):
		// No answer, or one for a row other than the one the key presented.
		return Self{}, zip.Errorf(http.StatusServiceUnavailable, "%s", unread)
	case !keyed && p.ID != sub:
		// A sign-in is keyed on its own `sub`, answered or not; a row that is not
		// it carries nothing across. Kept like an answer, so a reader asking once
		// per machine it lists asks IAM once.
		p = Self{ID: sub}
	}
	people.put(sub, p)
	return p, nil
}

// people keeps IAM's answers for personTTL, at most peopleCap of them.
var people = book{m: map[string]booked{}}

const (
	personTTL = time.Minute
	peopleCap = 4096
)

type book struct {
	mu sync.Mutex
	m  map[string]booked
}

type booked struct {
	p   Self
	exp time.Time
}

func (b *book) get(sub string) (Self, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.m[sub]
	if !ok || time.Now().After(e.exp) {
		return Self{}, false
	}
	return e.p, true
}

func (b *book) put(sub string, p Self) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.m) >= peopleCap {
		now := time.Now()
		for k, e := range b.m {
			if now.After(e.exp) {
				delete(b.m, k)
			}
		}
		if len(b.m) >= peopleCap {
			clear(b.m)
		}
	}
	b.m[sub] = booked{p: p, exp: time.Now().Add(personTTL)}
}
