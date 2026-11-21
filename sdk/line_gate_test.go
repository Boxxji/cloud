package cloud

// pooled is a member of a tenant org: every member spends the org's own account,
// the one a credit line covers.
var pooled = map[string]string{
	"X-User-Id":    "u_2",
	"X-User-Name":  "buyer",
	"X-Org-Id":     "acme",
	"X-User-Owner": "acme",
}
