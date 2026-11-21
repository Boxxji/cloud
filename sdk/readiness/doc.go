// Package readiness holds the process state its health endpoints report: the
// subsystems that mounted fail-closed (Degraded) and whether a graceful drain has
// begun (Draining), which turns /readyz to 503.
package readiness
