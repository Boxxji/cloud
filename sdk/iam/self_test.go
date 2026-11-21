package iam_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hanzoai/cloud/sdk/iam"
	"github.com/hanzoai/cloud/sdk/kit"
	"github.com/zap-proto/zip"
)

// ONE PERSON, WHICHEVER CREDENTIAL. A sign-in presents the id of the person's IAM
// row and an API key presents the row's `<owner>/<name>`; SelfFrom answers both
// with the one id, and the row a record an API key wrote before is keyed on. An
// application is its own subject, a call naming nobody is nobody, a credential
// naming no stable subject is refused, and an API key whose person IAM cannot say
// is refused rather than keyed on its name — while a sign-in, whose subject is
// already the id, keeps it.
func TestSelfFromIsOnePersonWhicheverCredential(t *testing.T) {
	t.Setenv("ZIP_RUNTIME_DIR", kit.Sockets(t))
	nia := iam.Self{ID: "uuid-nia", Row: "hanzo/nia"}
	peer := zip.New(zip.Config{AppName: "iam", DisableStartupMessage: true})
	peer.Post("/iam/self", func(ctx context.Context, _ *struct{}) (*iam.Self, error) {
		switch zip.CallerOf(ctx).User {
		case "uuid-nia", "hanzo/nia":
			return &nia, nil
		case "hanzo/liar":
			return &nia, nil // a row other than the one the key presented
		}
		return nil, zip.ErrUnauthorized("no such subject")
	}, zip.WithOperationID(iam.IAMSelf))
	at := zip.SocketPath("iam")
	go func() { _ = peer.Listen(at) }()
	t.Cleanup(func() { _ = peer.Shutdown() })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if c, err := net.Dial("unix", at); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never accepted", at)
		}
	}
	as := func(user string) context.Context {
		return zip.WithCaller(context.Background(), zip.Caller{Org: "hanzo", User: user})
	}

	for _, user := range []string{"uuid-nia", "hanzo/nia"} {
		p, err := iam.SelfFrom(as(user))
		if err != nil || p != (iam.Self{ID: "uuid-nia", Row: "hanzo/nia"}) {
			t.Fatalf("%s is %+v (%v), want nia's id and row", user, p, err)
		}
		if !p.Is("uuid-nia") || !p.Is("hanzo/nia") || p.Is("hanzo/other") || p.Is("") {
			t.Fatalf("%s matches the wrong keys", user)
		}
	}
	if p, err := iam.SelfFrom(as("app:hanzo/bot")); err != nil || p != (iam.Self{ID: "app:hanzo/bot"}) {
		t.Fatalf("an application is %+v (%v), want its own subject", p, err)
	}
	if p, err := iam.SelfFrom(context.Background()); err != nil || p.ID != "" {
		t.Fatalf("a call naming nobody is %+v (%v)", p, err)
	}
	if p, err := iam.SelfFrom(as("uuid-unread")); err != nil || p != (iam.Self{ID: "uuid-unread"}) {
		t.Fatalf("a sign-in IAM did not answer for is %+v (%v), want its own id", p, err)
	}
	for _, user := range []string{"hanzo/ghost", "hanzo/liar"} {
		var said *zip.HTTPError
		if p, err := iam.SelfFrom(as(user)); !errors.As(err, &said) || said.Status != 503 {
			t.Fatalf("an API key IAM did not say the person of (%s) is %+v (%v), want 503", user, p, err)
		}
	}
}
