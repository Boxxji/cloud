package plane

// wake.go — the router's start handshake, the one op contract this package owns.
//
// [Reach] asks the fleet router to start a lazy app, and the question and its
// answer are these two types. They live here rather than with the other op
// contracts because the mechanism cannot be written without them, and a package
// that names its own handshake cannot be made to import its callers.

// HostApp is the socket name the fleet router answers on. It is not an app —
// there is no manifest row, no Mount and no prefix — it is the process that
// LOADS the apps, and the only one that can start one.
//
// It exists because a lazy app has exactly one trigger: a request reaching one
// of its prefixes. A plane call never touches the router, so an app reached only
// over its socket was never started and the socket was never bound. That is not
// a bug in laziness; it is a second entry point the loader has to serve, and
// this names it.
const HostApp = "host"

// HostStart is the fleet ROUTER's own op, not an app's. See [HostApp].
const HostStart = "host_start"

// StartIn names the app to bring up. It is the one plane input that names an APP
// rather than acting for a tenant: the router owns no tenant data, and starting a
// process is not a read of anyone's books.
type StartIn struct {
	App string `json:"app" validate:"required" zap:"@0"`
}

// Started reports what the router did.
//
// Known is the load-bearing field and it is on a 200, not on a status code. "This
// fleet does not run that app" is the ONE answer a caller may read as free, and
// carrying it as a 404 made it indistinguishable from two other 404s on the same
// wire: zip's own "unknown op" when the router predates this op, and any framework
// 404 for the path. All three rebuild into the same *HTTPError with an empty Code,
// so only the message text differed — and matching on text is not a fact.
//
// That mattered on a rolling deploy. A host pod on an older build answers "unknown
// op: host_start", which as a status is 404, which as a fact would have been "not
// deployed here" — and a payment rail reading that concludes nothing is priced and
// serves every priced tool free, fleet-wide, for the whole skew window.
//
// So an answer states the fact and EVERY error is an outage. A router that cannot
// answer this op cannot claim anything about the fleet.
type Started struct {
	Addr  string `json:"addr" zap:"@0"`
	Known bool   `json:"known" zap:"@8"`
}
