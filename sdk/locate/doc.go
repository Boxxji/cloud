// Package locate names the country an IP address is registered in.
//
// It answers for the consent rule when no edge stated a country: api.hanzo.ai is
// not proxied by Cloudflare, so the CF-IPCountry header never arrives there, and a
// visitor with no stated country was given the strictest regime everywhere in the
// world. The country of an address is a weak signal (a VPN moves it), and it is
// used only to pick the consent defaults a visitor starts from, never for money or
// risk.
//
// It is apart from sdk/geo because the database it embeds is a 4 MB lookup the
// host's edge never asks: geo is linked by the light host, this is not.
//
// The data is DB-IP's IP to Country Lite (https://db-ip.com), CC BY 4.0, embedded
// compressed and opened once on first use. Refresh it monthly from
// https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz.
package locate
