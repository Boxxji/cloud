// Package bus is how a process TALKS to the message bus. It does not run one.
//
// This surface lived in apps/pubsub beside the embedded NATS server, so the six
// apps that wanted only the bus ADDRESS had to import the app that embeds a
// broker in order to get it.
//
// So the bus is two things and they are separated. apps/pubsub RUNS one and is
// linked by plugin/pubsub alone; this package ADDRESSES one and is linked by
// everybody. Nothing here can start a server, which is the property that keeps
// the separation true as callers are added.
package bus
