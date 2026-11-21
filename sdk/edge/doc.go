// Package edge holds the transport ceilings of a PUBLIC HTTP edge.
//
// It exists because TWO processes are one edge and each was configured
// separately. cmd/cloud is the host every request reaches first; the program
// behind it is built by cloud.App(). The host reads the header and body limits
// off Config itself, so GATEWAY_BODY_LIMIT and its siblings take effect at the
// edge, not only downstream. The 16 MiB body default exists so a 1M-token prompt
// (~4.3 MB of JSON) can reach the 1M-context models; a smaller cap answers an
// opaque 400 "Error when parsing request", which reads like a malformed payload
// rather than a size cap.
//
// This package is a LEAF on purpose. The host links zip, manifest and webui and
// nothing else — importing the cloud root to reach a number would re-fuse the
// monolith the host was built to replace. Anything that terminates public HTTP
// calls these; there is no second place to write the number down, because a
// second place is how this broke.
package edge
