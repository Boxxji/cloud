package locate

import "testing"

func TestCountry(t *testing.T) {
	for ip, want := range map[string]string{
		"8.8.8.8":     "US", // Google public DNS
		"1.1.1.1":     "AU", // APNIC/Cloudflare research, registered in Australia
		"81.2.69.142": "GB",
		"10.0.0.19":   "", // private
		"127.0.0.1":   "",
		"not an addr": "",
		"":            "",
	} {
		if got := Country(ip); got != want {
			t.Errorf("Country(%q) = %q, want %q", ip, got, want)
		}
	}
	if got := Country("2001:4860:4860::8888"); len(got) != 2 {
		t.Errorf("an IPv6 address resolves too; got %q", got)
	}
}
