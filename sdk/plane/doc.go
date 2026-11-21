// Package plane is the mechanism of a typed op between two apps: the CLIENT half
// that dials a peer by name over its unix socket and invokes one op, and the
// plumbing both halves share (where sockets live, how a caller names the tenant
// it acts for, how long a call may wait).
//
// It holds no contract. The request and reply types of an op and the names ops
// answer to are the host repository's (its client package), imported by both
// ends; this package is what carries them. The one exception is the router's wake
// handshake (see [HostApp]), because [Reach] is that handshake and cannot be
// written without it.
//
// It is a leaf: it imports zip and the standard library, and nothing of any host.
// A caller that wants one typed peer call links this and no request tier.
//
// The SERVER half — binding a socket and registering ops — stays with the
// framework that owns the deployment, because binding a socket reports itself to
// the host's observability. Registering an op and calling one are opposite duties;
// only the second has to be reachable from everywhere.
package plane
