package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Each writePair gets an mtime a second later than the previous one, so the
// picker sees a change without the tests sleeping.
var pairClock = time.Now().Add(-time.Hour)

func makePair(t *testing.T, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "share"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func touch(t *testing.T, paths ...string) {
	t.Helper()

	pairClock = pairClock.Add(time.Second)
	for _, p := range paths {
		if err := os.Chtimes(p, pairClock, pairClock); err != nil {
			t.Fatal(err)
		}
	}
}

func writePair(t *testing.T, dir string, names ...string) {
	t.Helper()

	certPEM, keyPEM := makePair(t, names...)
	crt, key := filepath.Join(dir, ShareCertFile), filepath.Join(dir, ShareKeyFile)
	if err := os.WriteFile(crt, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	touch(t, crt, key)
}

func newPicker(t *testing.T, dir string) *CertPicker {
	t.Helper()

	def, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewCertPicker(def, dir)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func pick(t *testing.T, p *CertPicker, name string) []string {
	t.Helper()

	cert, err := p.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	return leaf.DNSNames
}

func isDefault(names []string) bool { return len(names) > 0 && names[0] == "localhost" }

func TestPicksTheShareCertificateBySNI(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "*.mybox.box.example.org")
	p := newPicker(t, dir)

	got := pick(t, p, "jellyfin.mybox.box.example.org")
	if len(got) != 1 || got[0] != "*.mybox.box.example.org" {
		t.Fatalf("the wildcard must be served for its subdomain: %v", got)
	}
	// A wildcard covers one label only, and the bare name is not under it.
	for _, name := range []string{"mybox.box.example.org", "casaos.local", ""} {
		if got := pick(t, p, name); !isDefault(got) {
			t.Fatalf("%q must get the default certificate: %v", name, got)
		}
	}
}

func TestReloadsTheSharePairWhenItChanges(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "*.mybox.box.example.org")
	p := newPicker(t, dir)

	if got := pick(t, p, "a.mybox.box.example.org"); isDefault(got) {
		t.Fatal("the first share pair must be served")
	}

	writePair(t, dir, "*.other.box.example.org")
	got := pick(t, p, "x.other.box.example.org")
	if len(got) != 1 || got[0] != "*.other.box.example.org" {
		t.Fatalf("the new pair must be served without a new picker: %v", got)
	}
}

func TestBrokenSharePairKeepsThePrevious(t *testing.T) {
	dir := t.TempDir()
	writePair(t, dir, "*.mybox.box.example.org")
	p := newPicker(t, dir)
	name := "a.mybox.box.example.org"

	if isDefault(pick(t, p, name)) {
		t.Fatal("the first share pair must be served")
	}

	// A certificate whose key is not share.key, as when the two files are caught mid-write.
	otherCert, _ := makePair(t, "*.broken.box.example.org")
	crt := filepath.Join(dir, ShareCertFile)
	if err := os.WriteFile(crt, otherCert, 0o600); err != nil {
		t.Fatal(err)
	}
	touch(t, crt)

	if got := pick(t, p, name); len(got) != 1 || got[0] != "*.mybox.box.example.org" {
		t.Fatalf("a broken pair must keep the previous one: %v", got)
	}

	writePair(t, dir, "*.fixed.box.example.org")
	if got := pick(t, p, "a.fixed.box.example.org"); len(got) != 1 || got[0] != "*.fixed.box.example.org" {
		t.Fatalf("the fixed pair must be served: %v", got)
	}
}

func TestNoShareFilesMeansTheDefault(t *testing.T) {
	dir := t.TempDir()
	p := newPicker(t, dir)

	if got := pick(t, p, "a.mybox.box.example.org"); !isDefault(got) {
		t.Fatalf("no share files: default expected: %v", got)
	}

	writePair(t, dir, "*.mybox.box.example.org")
	if isDefault(pick(t, p, "a.mybox.box.example.org")) {
		t.Fatal("the share pair must be served once written")
	}

	_ = os.Remove(filepath.Join(dir, ShareCertFile))
	_ = os.Remove(filepath.Join(dir, ShareKeyFile))
	if got := pick(t, p, "a.mybox.box.example.org"); !isDefault(got) {
		t.Fatalf("a removed share pair must be forgotten: %v", got)
	}
}

func TestDefaultPairMustLoad(t *testing.T) {
	if _, err := NewCertPicker(TLSConfig{CertFile: "nope", KeyFile: "nope"}, t.TempDir()); err == nil {
		t.Fatal("a default pair that does not load must fail the picker")
	}
}
