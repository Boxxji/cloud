package cloud

import (
	"github.com/hanzoai/cloud/sdk/audit"
	"github.com/zap-proto/zip"
)

// Witness installs rec on app as every program serving requests carries it, and
// the host and a hand-written main (plugin/o11y) both call it, so neither can carry
// less:
//   - Trail, the one door AuditTrail cannot reach: an in-process invoke has no
//     request, and it stands down for any call one carried, since the middleware
//     sees the response the client got (note.go);
//   - AuditTrail around the rest of the chain;
//   - Contain inside it: a support session (an IAM impersonation) changes nothing
//     that outlives it and moves no money (impersonation.go), every refusal on the
//     trail with its operator named, ahead of everything that could spend.
//
// A nil rec (CLOUD_AUDIT_DISABLED) records nothing and still contains.
func Witness(app *zip.App, rec *audit.Recorder) {
	app.OnResult(Trail(rec))
	app.Use(AuditTrail(rec))
	app.Use(Contain())
}
