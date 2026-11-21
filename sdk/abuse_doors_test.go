package cloud

// WHAT THE SENSOR SEES OF A CALLER THAT WALKS THE CATALOGUE.
//
// Pattern.Paths is the approximate number of distinct paths one caller touched
// in the window — the spread signal, and the one that separates a client using a
// capability from one enumerating them. The gate builds its observation from
// RouteFamily of the path the TRANSPORT carried, and a request that names its
// operation in the payload carries a path that names the door. So every
// operation in the fleet reached that way is one path.
//
// The fleet serves 2,400-odd operations, and an agent has a door to all of them.
// This drives the same eight operations over the two doors and reads the count
// back off the sensor.

type walkIn struct {
	N int `json:"n"`
}

type walkOut struct {
	OK bool `json:"ok"`
}

// walkOps is more than one and fewer than the spread counter saturates at, so
// the count it produces is the number of operations and not a ceiling.
const walkOps = 8

// walkKey is the credential the walk presents. The sensor keys a caller on a
// VALIDATED credential and falls back to its address, and a request driven at a
// listener in-process has no address the framework surfaces — so an unkeyed walk
// lands in the unattributed lane and records no paths at all, whichever door it
// used. Presenting a key is what makes the two rows below comparable rather than
// both empty.
const walkKey = "sk-walk-catalogue"
