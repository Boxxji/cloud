package object

import (
	"strings"
	"testing"
)

// The AWS gateway puts 22 characters around a bucket (its prefix and suffix), and AWS
// holds 63. A tenant's bucket named for a wallet org (27 characters) came to 45 with
// the org's prefix and 67 once wrapped, which AWS refused: the store answered 502 for
// every friendly name of 24 characters or more.
func TestABucketFitsTheStoreThatWrapsIt(t *testing.T) {
	t.Setenv(AffixEnv, "22")
	const org = "wallet-evm-db4d55cb76473850-a5659f7dc386ec41"
	for n := 1; n <= 40; n++ {
		name := strings.Repeat("a", n)
		b := BucketName(org, name)
		if len(b)+22 > 63 {
			t.Fatalf("a %d-character name makes a %d-character bucket, %d with the store's affix", n, len(b), len(b)+22)
		}
		if !ValidBucket(b) || !strings.HasPrefix(b, BucketPrefix(org)) {
			t.Fatalf("%q is not a bucket of this org", b)
		}
	}
}

func TestAShortNameKeepsItsBucket(t *testing.T) {
	t.Setenv(AffixEnv, "22")
	if got, want := BucketName("acme", "photos"), "o"+OrgHash("acme")+"-photos"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// 23 characters is the longest that still fits: 18 of prefix and 22 of affix leave 23.
	n := strings.Repeat("b", 23)
	if got, want := BucketName("acme", n), "o"+OrgHash("acme")+"-"+n; got != want {
		t.Fatalf("a 23-character name was shortened: %q", got)
	}
}

func TestALongNameShortensDeterministicallyAndStaysDistinct(t *testing.T) {
	t.Setenv(AffixEnv, "22")
	a, b := "wallet-evm-db4d55cb76473850", "wallet-evm-db4d55cb76473851"
	if BucketName("acme", a) != BucketName("acme", a) {
		t.Fatal("the same name made two buckets")
	}
	if BucketName("acme", a) == BucketName("acme", b) {
		t.Fatalf("%q and %q share a bucket", a, b)
	}
	if BucketName("acme", a) == BucketName("other", a) {
		t.Fatal("two orgs share a bucket")
	}
}

// A listing recovers a friendly name by taking the org's prefix off the bucket, and a
// caller addresses the bucket by that name: it must lead to the same bucket.
func TestAShortenedBucketIsAddressableByItsListedName(t *testing.T) {
	t.Setenv(AffixEnv, "22")
	for _, name := range []string{"wallet-evm-db4d55cb76473850", strings.Repeat("c", 40), "x"} {
		b := BucketName("acme", name)
		listed := strings.TrimPrefix(b, BucketPrefix("acme"))
		if !Friendly(listed) {
			t.Fatalf("%q lists as %q, which is not a name a tenant may address", name, listed)
		}
		if again := BucketName("acme", listed); again != b {
			t.Fatalf("%q lists as %q, which addresses %q, not %q", name, listed, again, b)
		}
	}
}

func TestWithoutAnAffixAnyFriendlyNameIsItsOwnBucket(t *testing.T) {
	n := strings.Repeat("d", 40)
	if got, want := BucketName("acme", n), "o"+OrgHash("acme")+"-"+n; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
