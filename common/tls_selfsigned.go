package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// A certificate of the gateway's own.
//
// The administrator can supply a certificate (TLSConfig above), and most do not:
// a LAN appliance has no public name to get one for. Without one, the dashboard
// went over plain HTTP, readable on the wire, and the browser refused it the
// APIs that need a secure context, the clipboard first among them. So the
// gateway makes a certificate for itself, once, and serves HTTPS with it on a
// second port beside the plain one. Self-signed, so the browser warns the first
// time; that warning is a person's to accept, and the plain port is still there.

// DefaultHTTPSPort is where the self-signed HTTPS listens when the
// configuration does not say.
const DefaultHTTPSPort = "443"

// SelfSigned returns the key pair kept in dir, making it on the first call.
// Ten years, this box's hostname, localhost and the loopback addresses.
func SelfSigned(dir string) (TLSConfig, error) {
	pair := TLSConfig{
		CertFile: filepath.Join(dir, "gateway.crt"),
		KeyFile:  filepath.Join(dir, "gateway.key"),
	}

	if pair.Validate() == nil && pair.Enabled() && exists(pair.CertFile) && exists(pair.KeyFile) {
		return pair, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return TLSConfig{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return TLSConfig{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return TLSConfig{}, err
	}

	hostname, _ := os.Hostname()
	names := []string{"localhost"}
	if hostname != "" && hostname != "localhost" {
		names = append(names, hostname)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "CasaOS", Organization: []string{"ReCasaOS"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return TLSConfig{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return TLSConfig{}, err
	}

	if err := os.WriteFile(pair.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return TLSConfig{}, err
	}
	if err := os.WriteFile(pair.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return TLSConfig{}, err
	}

	if err := pair.Validate(); err != nil {
		return TLSConfig{}, errors.Join(errors.New("the certificate just made does not load"), err)
	}

	return pair, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
