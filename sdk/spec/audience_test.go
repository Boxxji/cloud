package spec

import "testing"

// A relay publishes whatever grows behind it and names nothing a client can
// call; it stays internal whatever product it sits under.
func TestARelayEndpointIsNotPublic(t *testing.T) {
	op := &Operation{OperationID: "get_v1_tasks_wildcard1"}
	if audience("/v1/tasks/{wildcard1}", op) {
		t.Fatal("an untyped {wildcardN} address came back public")
	}
}

// A typed op on a greedy tail is not a relay: the tail is a parameter it binds,
// so it names exactly what a client calls. The KMS broker's one-secret delete is
// the case — internal, it reached no CLI command and no SDK method.
func TestATypedOpOnAGreedyTailIsPublic(t *testing.T) {
	op := &Operation{OperationID: "delete_kms_secrets_by_wildcard1", Tool: true}
	if !audience("/v1/kms/secrets/{wildcard1}", op) {
		t.Fatal("a typed op on a greedy tail stayed internal")
	}
	// The other terms still hold: an operator's typed tail stays out.
	if audience("/v1/admin/pricing/catalog/models/{wildcard1}", &Operation{Tool: true}) {
		t.Fatal("an operator's typed tail came back public")
	}
}

// A legacy spelling is served so a pinned caller keeps working and is, by its
// own declaration, not the contract.
func TestALegacySpellingIsNotPublic(t *testing.T) {
	op := &Operation{OperationID: "post_v1_chat", Tags: []string{"chat", Compat}}
	if audience("/v1/chat", op) {
		t.Fatal("a compat-tagged operation came back public")
	}
}
