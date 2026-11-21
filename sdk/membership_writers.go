package cloud

import (
	"context"

	"github.com/hanzoai/cloud/sdk/coord"
	"github.com/hanzoai/cloud/sdk/tenure"
)

// MembershipSource resolves the writer-membership Source the durability fencer and
// the shard router both read: the deployment's live set when its pods share a KV
// (each pod's root joins at boot and leaves when it starts to drain, and one that
// dies drops out when its heartbeat lapses), else the static set, CLOUD_PEERS or
// this process alone.
//
// The live set holds this pod unless it is leaving or, in a deployment that declares
// more than one writer, the set its peers read has dropped it (Coord.Members). So a
// KV that is down at boot, or that refuses the one declared writer's heartbeat,
// leaves this pod owning what it would own alone rather than owning nothing, and a
// pod its peers no longer see owns nothing. The object store's rounds, not this
// list, keep two owners apart.
func MembershipSource(static []tenure.Member, c *coord.Coord) tenure.Source {
	if c == nil || !c.Shared() {
		return tenure.StaticSource(static...)
	}
	return func(context.Context) ([]tenure.Member, error) {
		ms := c.Members()
		out := make([]tenure.Member, len(ms))
		for i, m := range ms {
			out[i] = tenure.Member(m)
		}
		return out, nil
	}
}
