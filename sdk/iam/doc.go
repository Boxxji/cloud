// Package iam is how a deployment talks to Hanzo IAM: where IAM is and how this
// deployment signs in to it (the issuer for the brand, the in-cluster base URL for
// server-to-server calls, the machine identity's client-credentials token source),
// and how what IAM answers is read.
//
// IAM speaks TWO wire shapes on one base path, and every caller here has to read
// both. The legacy verbs answer the {status,msg,data} envelope; the typed nouns —
// /v1/iam/users/get among them — answer THE RESOURCE DIRECTLY, and their errors
// come back as {"status":404,"error":"…"} where `status` is a NUMBER, not the
// string "ok".
//
// Assuming the envelope breaks both halves, and the failure looks like anything
// except a parsing mistake: a bare resource parses with Status "" and is rejected
// as `iam status 200`, and an error body does not parse at all and is reported as
// `iam non-envelope response (400)`. Both wore the words of a business rule —
// "photo stored but the profile could not be updated" on one endpoint, "no Hanzo
// account for <address> in this org" on the other — which is why each survived
// until somebody drove the call by hand.
//
// So: the HTTP status decides, and the body is read only for what it carries. A
// 2xx with no envelope IS the data; a non-2xx yields IAM's own message.
//
// The answer rule lives here because two clients ask it (apps/account, apps/team) and the
// question has one answer. Stating it twice is how one of them stays wrong after
// the other is fixed — which is exactly the state this package was extracted from.
package iam
