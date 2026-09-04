package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeKeyPair drops a throwaway self-signed certificate in dir and returns the
// certificate and key paths.
func writeKeyPair(t *testing.T, dir string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "casaos.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling key: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "EC PRIVATE KEY", keyDER)

	return certPath, keyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()

	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func TestTLSConfigEnabledAndScheme(t *testing.T) {
	cases := []struct {
		name       string
		config     TLSConfig
		wantOn     bool
		wantScheme string
	}{
		{"unset serves plain HTTP", TLSConfig{}, false, "http"},
		{"a complete pair serves HTTPS", TLSConfig{CertFile: "c.pem", KeyFile: "k.pem"}, true, "https"},
		// Half a configuration is a mistake, and falling back to HTTP is the
		// behaviour that keeps a box reachable rather than bricking its UI.
		{"a certificate without a key falls back to HTTP", TLSConfig{CertFile: "c.pem"}, false, "http"},
		{"a key without a certificate falls back to HTTP", TLSConfig{KeyFile: "k.pem"}, false, "http"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.Enabled(); got != tc.wantOn {
				t.Fatalf("Enabled() = %v, want %v", got, tc.wantOn)
			}

			if got := tc.config.Scheme(); got != tc.wantScheme {
				t.Fatalf("Scheme() = %q, want %q", got, tc.wantScheme)
			}
		})
	}
}

func TestTLSConfigValidate(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyPair(t, dir)

	t.Run("an unset config is valid and means plain HTTP", func(t *testing.T) {
		if err := (TLSConfig{}).Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("a real key pair is accepted", func(t *testing.T) {
		config := TLSConfig{CertFile: certPath, KeyFile: keyPath}
		if err := config.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("a missing certificate file is rejected", func(t *testing.T) {
		config := TLSConfig{CertFile: filepath.Join(dir, "absent.pem"), KeyFile: keyPath}
		if err := config.Validate(); err == nil {
			t.Fatal("Validate() = nil, want an error")
		}
	})

	t.Run("a file that is not a certificate is rejected", func(t *testing.T) {
		junk := filepath.Join(dir, "junk.pem")
		if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("writing junk: %v", err)
		}

		config := TLSConfig{CertFile: junk, KeyFile: keyPath}
		if err := config.Validate(); err == nil {
			t.Fatal("Validate() = nil, want an error")
		}
	})
}
