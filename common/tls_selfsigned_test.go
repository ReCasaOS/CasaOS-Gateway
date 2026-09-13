package common

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

func TestTheGatewayMakesItselfACertificateOnceAndKeepsIt(t *testing.T) {
	dir := t.TempDir()

	pair, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !pair.Enabled() || pair.Scheme() != "https" {
		t.Fatalf("the pair must serve HTTPS: %+v", pair)
	}

	loaded, err := tls.LoadX509KeyPair(pair.CertFile, pair.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(loaded.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "CasaOS" || len(cert.IPAddresses) != 2 || cert.DNSNames[0] != "localhost" {
		t.Fatalf("names: %v %v %v", cert.Subject.CommonName, cert.DNSNames, cert.IPAddresses)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	first, _ := os.ReadFile(pair.CertFile)
	again, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(again.CertFile)
	if string(first) != string(second) {
		t.Fatal("a second start must keep the certificate a browser was told to trust")
	}
}

func TestABrokenPairIsMadeAgain(t *testing.T) {
	dir := t.TempDir()
	if _, err := SelfSigned(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/gateway.key", []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	pair, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(pair.CertFile, pair.KeyFile); err != nil {
		t.Fatal(err)
	}
}
