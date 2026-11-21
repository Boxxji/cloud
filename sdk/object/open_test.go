package object

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fresh(t *testing.T) {
	t.Helper()
	driverMu.Lock()
	driver = nil
	driverMu.Unlock()
	for _, k := range []string{"CLOUD_ENV", "KUBERNETES_SERVICE_HOST", ConfigEnv, LocalEnv} {
		t.Setenv(k, "")
	}
}

func TestOpenDefaultsToLocalDisk(t *testing.T) {
	fresh(t)
	l := &Local{Dir: t.TempDir()}
	s, err := Open(l)
	if err != nil || s != Store(l) {
		t.Fatalf("open = %v, %v", s, err)
	}
}

func TestProductionRefusesLocalDisk(t *testing.T) {
	for name, set := range map[string]map[string]string{
		"a named deployment":          {"CLOUD_ENV": "mainnet"},
		"a named deployment in a pod": {"CLOUD_ENV": "testnet", "KUBERNETES_SERVICE_HOST": "10.0.0.1"},
	} {
		t.Run(name, func(t *testing.T) {
			fresh(t)
			for k, v := range set {
				t.Setenv(k, v)
			}
			if _, err := Open(&Local{Dir: t.TempDir()}); !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("open = %v, want ErrNotConfigured", err)
			}
			// The same refusal reaches every call of the process-wide store.
			z := &lazy{}
			if err := z.Ensure(context.Background(), "bkt"); !errors.Is(err, ErrNotConfigured) {
				t.Fatalf("ensure = %v", err)
			}
			t.Setenv(LocalEnv, "local")
			if _, err := Open(&Local{Dir: t.TempDir()}); err != nil {
				t.Fatalf("declared local = %v", err)
			}
		})
	}
	// A pod that names no deployment is not one: a CI runner is a pod.
	for _, envName := range []string{"", "test"} {
		fresh(t)
		t.Setenv("CLOUD_ENV", envName)
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		if _, err := Open(&Local{Dir: t.TempDir()}); err != nil {
			t.Fatalf("a pod with CLOUD_ENV=%q = %v", envName, err)
		}
	}
}

func TestConfiguredStoreWithoutADriverRefuses(t *testing.T) {
	fresh(t)
	t.Setenv(ConfigEnv, "key")
	if _, err := Open(&Local{Dir: t.TempDir()}); !errors.Is(err, ErrNoDriver) {
		t.Fatalf("open = %v, want ErrNoDriver", err)
	}
}

type fake struct{ Store }

func TestARegisteredDriverIsUsedWhenConfigured(t *testing.T) {
	fresh(t)
	on := false
	Register(Driver{Name: "fake", Open: func() (Store, bool, error) { return fake{}, on, nil }})
	defer func() { driver = nil }()
	if s, err := Open(&Local{Dir: t.TempDir()}); err != nil {
		t.Fatalf("unconfigured driver falls to local on a laptop: %v", err)
	} else if _, ok := s.(*Local); !ok {
		t.Fatalf("got %T", s)
	}
	on = true
	if s, err := Open(&Local{Dir: t.TempDir()}); err != nil || s != Store(fake{}) {
		t.Fatalf("open = %v, %v", s, err)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a second driver must panic")
		}
	}()
	Register(Driver{Name: "second"})
}

func TestNaming(t *testing.T) {
	if got := BucketName("acme", "library"); got != "o"+OrgHash("acme")+"-library" {
		t.Fatalf("bucket = %s", got)
	}
	if !strings.HasPrefix(BucketName("acme", "x"), BucketPrefix("acme")) || strings.HasPrefix(BucketName("acme2", "x"), BucketPrefix("acme")) {
		t.Fatal("prefix")
	}
	if BucketName("acme", "my-db") == BucketName("acme-my", "db") {
		t.Fatal("two orgs folded onto one bucket")
	}
	for _, bad := range []string{"", "/a", "a/", "../a", "a/../../b", "a\x00b", `a\b`, "."} {
		if _, ok := Key(bad); ok {
			t.Fatalf("Key(%q) accepted", bad)
		}
	}
	if k, ok := Key("a//b/./c"); !ok || k != "a/b/c" {
		t.Fatalf("Key = %q %v", k, ok)
	}
	if Friendly("Photos") || !Friendly("photos-1") || Friendly("-a") {
		t.Fatal("friendly")
	}
	if !ValidBucket(BucketName("acme", "library")) || ValidBucket("a..b") || ValidBucket("../x") || ValidBucket("ab") {
		t.Fatal("valid bucket")
	}
}

// The process-wide store follows the environment that picks its engine: opened on a
// laptop it is local disk, and the same process told it is a production deployment
// with nothing configured refuses rather than keep serving the disk it opened.
func TestTheProcessWideStoreFollowsItsEnvironment(t *testing.T) {
	fresh(t)
	t.Setenv("CLOUD_DATA_DIR", t.TempDir())
	z := &lazy{}
	if err := z.Ensure(context.Background(), "bkt"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUD_ENV", "mainnet")
	if err := z.Ensure(context.Background(), "bkt"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("a production process kept the disk it opened as a laptop: %v", err)
	}
	t.Setenv(LocalEnv, "local")
	if err := z.Ensure(context.Background(), "bkt"); err != nil {
		t.Fatalf("declared local: %v", err)
	}
}
