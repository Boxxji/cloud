// Package cloud is the framework every Hanzo Cloud app is built on (HIP-0106).
//
// An app is a package under apps/ with a Use(app cloud.Router, deps cloud.Deps)
// entry, run as its own plugin binary (plugin/<app>) through Listen. This
// package is what that binary links:
//
//   - the contract: Plugin, Router, Deps, Service, Price, typed-op Bridge;
//   - the request tier Serve installs: the identity boundary
//     (SanitizeIdentity), edge limits and CORS, rate limits, billing and spend
//     gates, the audit trail, tracing and metrics;
//   - the internal plane between apps (Ask, For, As, Who);
//   - per-org storage (OrgDB, OrgStore) and the data-plane master.
//
// Focused pieces live in their own packages under internal/ (aimodel, network,
// orgns, readiness, reserve, ...) and this package imports them, never the
// other way round.
package cloud
