// Package geo says where a caller is: IP is the one rule for the caller's address
// (the socket peer, or, behind our own proxies, the first forwarded hop that is
// not ours, read from the right), and Country and Region read what a Cloudflare hop
// attests.
//
// The package is not named ip because ip is what every caller names the answer.
package geo
