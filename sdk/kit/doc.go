// Package kit is what a test needs from its environment:
//
//   - Tool and CI answer for a program a test runs for real (git, a shell, the Go
//     toolchain). The gate's runner has them, so there a missing one is a failure:
//     a test that stood down in CI would report nothing, and nothing reads as a
//     pass. A workstation without one skips.
//   - Sockets is a runtime directory short enough to bind a unix socket in on
//     every platform.
//   - Codec stands a test down when the build links no SQLCipher C codec.
//
// Its sibling sdk/kit/master keys a test binary's data plane, imported for its
// side effect.
package kit
