// Package object is the object store every subsystem keeps files in: buckets,
// objects, and the signed links a browser follows to read or write one.
//
// A process runs on local disk by default. Open returns the engine under the data
// directory (Local), and its signed links are served by its own Handler, so a
// laptop needs nothing configured and a presigned URL works end to end. A
// production deployment turns an object store on by configuration, never by build
// tag: its driver (internal/driver/s3) registers here from the host and the
// plugin mains, and Open uses it when the environment configures it.
//
// Local disk is never the silent answer where data may already live elsewhere.
// A process that is not on a laptop (see Production) and has no configured driver
// refuses to open (ErrNotConfigured), and so does one whose environment names a
// store whose driver is not linked (ErrNoDriver). An explicit
// CLOUD_OBJECT_STORE=local says that a single-pod deployment keeps its files on
// its own volume.
//
// The naming rules are part of the contract: BucketName and its siblings decide
// which bucket an org's resource lives in, on every engine, and Key decides what
// a key may be.
package object
