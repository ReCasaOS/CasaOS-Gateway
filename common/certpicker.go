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
//
// The default pair is followed the same way, so an administrator's renewal is
// served without a restart.
type CertPicker struct {
	mu    sync.Mutex
	def   watchedPair
	share watchedPair
}

// watchedPair is a certificate pair on disk, re-read when the certificate's
// mtime changes.
type watchedPair struct {
	certPath, keyPath string
	sticky            bool // keep the last pair when the files are gone

	cert *tls.Certificate
	leaf *x509.Certificate
	mod  time.Time
}

// read follows the files by mtime. A pair that does not load (the two files
// caught mid-write) keeps the previous one, and the previous mtime, so the next
// call tries again. A missing certificate forgets the pair unless it is sticky.
func (w *watchedPair) read() error {
	info, err := os.Stat(w.certPath)
	if err != nil {
		if !w.sticky {
			w.cert, w.leaf, w.mod = nil, nil, time.Time{}
		}
		return err
	}
	if info.ModTime().Equal(w.mod) {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(w.certPath, w.keyPath)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	w.cert, w.leaf, w.mod = &cert, leaf, info.ModTime()
	return nil
}

// NewCertPicker loads def, which must load, and watches it and dir/share.{crt,key}.
func NewCertPicker(def TLSConfig, dir string) (*CertPicker, error) {
	p := &CertPicker{
		def:   watchedPair{certPath: def.CertFile, keyPath: def.KeyFile, sticky: true},
		share: watchedPair{certPath: filepath.Join(dir, ShareCertFile), keyPath: filepath.Join(dir, ShareKeyFile)},
	}
	if err := p.def.read(); err != nil {
		return nil, err
	}

	return p, nil
}

// GetCertificate is the share certificate when it exists and covers the server
// name of the hello, else the default one. It never fails: a share pair that
// cannot be read must not take the dashboard down with it.
func (p *CertPicker) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	_ = p.share.read()
	_ = p.def.read() // sticky: a failure keeps the pair loaded at start or since

	if p.share.cert != nil && hello.ServerName != "" && p.share.leaf.VerifyHostname(hello.ServerName) == nil {
		return p.share.cert, nil
	}

	return p.def.cert, nil
}

// Config is the TLS configuration of a listener that picks by name.
func (p *CertPicker) Config() *tls.Config {
	return &tls.Config{GetCertificate: p.GetCertificate, MinVersion: tls.VersionTLS12}
}
