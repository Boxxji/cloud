// Package brand is the white-label registry (HIP-0111): the map from a brand id
// (and from a request Host) to that brand's PUBLIC identity — its canonical OIDC
// issuer and its serving domains.
//
// It is a LEAF (imports only the standard library and publicsuffix), on purpose. Three unrelated callers need
// it and none should drag the others in: package cloud derives Config.IAMIssuer
// and validates token `iss` from it; the light webui console reads it to write
// the per-Host <title>; and cmd/cloud — the light host, which cannot import
// package cloud — reaches it through webui to brand the "/" it serves. A brand
// map that lived in package cloud would be unreachable from the host without
// linking every subsystem, so the white-label fact lives here, once.
//
// The cloud binary is one artifact serving every brand's API host (api.hanzo.ai,
// api.lux.cloud, api.zoo.cloud, api.cloud.pars.network, ...). Brand is a
// per-deployment value (CLOUD_BRAND / --brand). These facts are public (issuer
// host + brand domain), so they live in code, not in KMS.
package brand
