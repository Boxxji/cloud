package locate

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

//go:embed country.mmdb.gz
var packed []byte

var db = sync.OnceValue(func() *maxminddb.Reader {
	zr, err := gzip.NewReader(bytes.NewReader(packed))
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return nil
	}
	r, err := maxminddb.FromBytes(raw)
	if err != nil {
		return nil
	}
	return r
})

// Country is the upper-case ISO 3166-1 alpha-2 code ip is registered in, or ""
// when ip is not an address, is private, or is not in the data.
func Country(ip string) string {
	addr := net.ParseIP(strings.TrimSpace(ip))
	r := db()
	if addr == nil || r == nil || addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() {
		return ""
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.Lookup(addr, &rec); err != nil {
		return ""
	}
	code := strings.ToUpper(rec.Country.ISOCode)
	if len(code) != 2 {
		return ""
	}
	return code
}
