// Package inflight counts the requests this process is handling, so a shutdown
// waits for the work in flight and not for the streams clients hold open.
//
// A streamed reply stops counting when its handler returns: its bytes are
// written after that, for as long as the client keeps reading, and a drain that
// waited on them would end when the client chose. A console tab holding an event
// stream would hold a whole pod's rollout.
package inflight
