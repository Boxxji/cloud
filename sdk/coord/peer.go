package coord

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"time"
)

// Pods reach each other over mutual TLS under a certificate authority every pod
// derives from the deployment's master key. A request one pod forwards to another
// carries its caller's credentials, so both ends prove themselves: the caller
// refuses a listener the authority did not certify, and the listener refuses a
// caller it did not. Nothing is issued or distributed: whoever holds the master
// holds the authority, which is exactly the set of processes that can already open
// the deployment's data.

// peerName is the name every peer certificate is issued for and every caller
// verifies; the authority, not the address, is what is being checked.
const peerName = "peer.cloud.hanzo.internal"

type peerTLS struct {
	self  string
	ca    *x509.Certificate
	caKey ed25519.PrivateKey
	pool  *x509.CertPool

	mu   sync.Mutex
	leaf *tls.Certificate
}

func newPeerTLS(secret []byte, self string) (*peerTLS, error) {
	if len(secret) == 0 {
		return nil, errors.New("coord: no master key to derive the peer authority from")
	}
	key := ed25519.NewKeyFromSeed(derive(secret, "hanzo cloud peer authority v1"))
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hanzo cloud peers"},
		NotBefore:             time.Unix(1577836800, 0), // 2020-01-01
		NotAfter:              time.Unix(4102444800, 0), // 2100-01-01
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &peerTLS{self: self, ca: ca, caKey: key, pool: pool}, nil
}

// cert is this process's certificate: a fresh key the authority certified, renewed
// a day before it would expire.
func (p *peerTLS) cert() (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.leaf != nil && time.Until(p.leaf.Leaf.NotAfter) > 24*time.Hour {
		return p.leaf, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: p.self},
		DNSNames:     []string{peerName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	p.leaf = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	return p.leaf, nil
}

func (c *Coord) peers() (*peerTLS, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.peer != nil {
		return c.peer, nil
	}
	p, err := newPeerTLS(c.secret, c.self.ID)
	if err != nil {
		return nil, err
	}
	c.peer = p
	return p, nil
}

// ServerTLS is what the pod's root serves its peers with: a certificate from the
// deployment's authority, and one required of every caller.
func (c *Coord) ServerTLS() (*tls.Config, error) {
	p, err := c.peers()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      p.pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return p.cert() },
	}, nil
}

// ClientTLS is what a process dials a peer with: it presents a certificate from the
// deployment's authority, and accepts only a listener holding one.
func (c *Coord) ClientTLS() (*tls.Config, error) {
	p, err := c.peers()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		RootCAs:              p.pool,
		ServerName:           peerName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return p.cert() },
	}, nil
}
