package cloud

// hooks.go — what the framework asks of the process that links it.
//
// The edge middleware, the metrics, the billing gates and the deployment's
// composition root are the host's, not the framework's; but the identity boundary,
// the tracing span, the op-invoke rule and the config check each end in a question
// only the host can answer. The host registers its answers once, at boot (it links
// first: every plugin main imports it), the way it registers the app table
// (SetFleet) and the peers (SetPeers). A field left nil answers "nothing", which is
// a standalone process with no host.

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/hanzoai/cloud/sdk/fault"
	"github.com/hanzoai/cloud/sdk/meter"
	"github.com/zap-proto/zip"
)

// Hooks is the host's half of the framework.
type Hooks struct {
	// App is the host's program: the whole middleware chain in its one order.
	App func(name string, cfg *Config, deps Deps, tools zip.Source) *zip.App
	// Listen serves plugins as one process.
	Listen func(plugins []Plugin, enable []string) error
	// BuildDeps constructs the process-wide handles.
	BuildDeps func(cfg *Config) Deps

	// PlatformPush asks the platform app, over the plane, to build a landed push.
	PlatformPush func(ctx context.Context, ev GitPushEvent) (int, error)
	// PlatformRelease asks the platform app to roll a proven image onto its service.
	PlatformRelease func(ctx context.Context, ev ServiceReleaseEvent) error
	// PlatformJob asks the platform app to launch a runner for a queued job.
	PlatformJob func(ctx context.Context, ev JobEvent) (string, error)
	// X402Fee asks the payment rail about one metered fee for the request c, and
	// writes what it answered onto c's response headers (x402fee.go).
	X402Fee func(c *zip.Ctx, resource string, step FeeStep) (FeeAnswer, error)

	// Declared is how many writers the deployment may run.
	Declared func(cfg *Config) int
	// PeerCount is how many pods a CLOUD_PEERS value names.
	PeerCount func(spec string) int
	// PeerHas reports whether a CLOUD_PEERS value names the pod id.
	PeerHas func(spec, id string) bool

	// ReportFault states one fault on the event plane: a 5xx this process
	// answered, a run that ended in error, a job that failed.
	ReportFault func(f fault.Fault)
	// Ceiling is the op-invoke half of the rate ceiling.
	Ceiling func() zip.Authorizer
	// Toll is the op-invoke authorizer that charges.
	Toll func(m *meter.Client, commerce CommerceClient) zip.Authorizer
	// IsDoor reports whether a path is a door: an address that reaches an operation
	// without naming it.
	IsDoor func(path string) bool
	// Nobody finishes a request whose credential resolved to no principal: the
	// per-IP charge, and the strike against the address.
	Nobody func(c *zip.Ctx, refusal error, strike bool) error
	// ObserveRequest counts one answered request.
	ObserveRequest func(product, org string, status int, d time.Duration)
	// ProductFromPath names the product a path belongs to.
	ProductFromPath func(path string) string
	// Billable reports whether a request is one standing is asked of.
	Billable func(method, path string) bool
	// PlaneServed notes that an app's plane socket was bound here.
	PlaneServed func(name string)
	// ObserveDebit counts one debit.
	ObserveDebit func(product string, u meter.Usage, res *meter.RecordResult, err error)
	// ObserveGate counts one gate verdict.
	ObserveGate func(err error)
}

var hostHooks atomic.Pointer[Hooks]

// SetHooks installs the host's answers. The host calls it once, at boot.
func SetHooks(h Hooks) { hostHooks.Store(&h) }

func hooks() Hooks {
	if h := hostHooks.Load(); h != nil {
		return *h
	}
	return Hooks{}
}

func declared(c *Config) int {
	if f := hooks().Declared; f != nil {
		return f(c)
	}
	return c.Replicas
}

func peerCount(spec string) int {
	if f := hooks().PeerCount; f != nil {
		return f(spec)
	}
	return 0
}

func peerHas(spec, id string) bool {
	if f := hooks().PeerHas; f != nil {
		return f(spec, id)
	}
	return false
}

// ReportFault states one fault on the event plane, detached and bounded, so any
// process can say a failure the same way the request handler does: a run that
// ended in error (fault.Ended), a scheduled job that failed (fault.Failed). A
// process with no host says nothing.
func ReportFault(f fault.Fault) {
	if h := hooks().ReportFault; h != nil {
		h(f)
	}
}

func allowAll(context.Context, zip.Op, any) (zip.Decision, error) {
	return zip.Decision{Effect: zip.Allow}, nil
}

func ceiling() zip.Authorizer {
	if f := hooks().Ceiling; f != nil {
		return f()
	}
	return allowAll
}

func toll(m *meter.Client, commerce CommerceClient) zip.Authorizer {
	if f := hooks().Toll; f != nil {
		return f(m, commerce)
	}
	return allowAll
}

func isDoor(path string) bool {
	if f := hooks().IsDoor; f != nil {
		return f(path)
	}
	return false
}

func nobody(c *zip.Ctx, refusal error, strike bool) error {
	if f := hooks().Nobody; f != nil {
		return f(c, refusal, strike)
	}
	return refusal
}

func observeRequest(product, org string, status int, d time.Duration) {
	if f := hooks().ObserveRequest; f != nil {
		f(product, org, status, d)
	}
}

func productFromPath(path string) string {
	if f := hooks().ProductFromPath; f != nil {
		return f(path)
	}
	return ""
}

func billable(method, path string) bool {
	if f := hooks().Billable; f != nil {
		return f(method, path)
	}
	return false
}

func planeServed(name string) {
	if f := hooks().PlaneServed; f != nil {
		f(name)
	}
}

func observeDebit(product string, u meter.Usage, res *meter.RecordResult, err error) {
	if f := hooks().ObserveDebit; f != nil {
		f(product, u, res, err)
	}
}

func observeGate(err error) {
	if f := hooks().ObserveGate; f != nil {
		f(err)
	}
}
