package common

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Names of the share certificate in the gateway's tls directory.
const ShareCertFile, ShareKeyFile = "share.crt", "share.key"

// CertPicker serves the share certificate when the client asks for a name it
// covers, and the gateway's usual certificate otherwise.
//
// The share certificate is obtained by the core (ACME DNS-01 through the relay)
// and dropped here; the gateway only serves it. It is re-read when the file's
// mtime changes, so a renewal needs no restart.
type CertPicker struct {
	def      tls.Certificate
	certPath string
	keyPath  string

	mu    sync.Mutex
	share *tls.Certificate
	leaf  *x509.Certificate
	mod   time.Time
}

// NewCertPicker loads def once and watches dir/share.{crt,key}.
func NewCertPicker(def TLSConfig, dir string) (*CertPicker, error) {
	cert, err := tls.LoadX509KeyPair(def.CertFile, def.KeyFile)
	if err != nil {
		return nil, err
	}

	return &CertPicker{
		def:      cert,
		certPath: filepath.Join(dir, ShareCertFile),
		keyPath:  filepath.Join(dir, ShareKeyFile),
	}, nil
}

// GetCertificate is the share certificate when it exists and covers the server
// name of the hello, else the default one. It never fails: a share pair that
// cannot be read must not take the dashboard down with it.
func (p *CertPicker) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.refresh()

	if p.share != nil && hello.ServerName != "" && p.leaf.VerifyHostname(hello.ServerName) == nil {
		return p.share, nil
	}

	return &p.def, nil
}

// refresh follows the files by mtime. A pair that does not load (the two files
// caught mid-write) keeps the previous one, and the previous mtime, so the next
// handshake tries again.
func (p *CertPicker) refresh() {
	info, err := os.Stat(p.certPath)
	if err != nil {
		p.share, p.leaf, p.mod = nil, nil, time.Time{}

		return
	}
	if info.ModTime().Equal(p.mod) {
		return
	}

	cert, err := tls.LoadX509KeyPair(p.certPath, p.keyPath)
	if err != nil {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}

	p.share, p.leaf, p.mod = &cert, leaf, info.ModTime()
}

// Config is the TLS configuration of a listener that picks by name.
func (p *CertPicker) Config() *tls.Config {
	return &tls.Config{GetCertificate: p.GetCertificate, MinVersion: tls.VersionTLS12}
}
