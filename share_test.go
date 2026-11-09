package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"

	"github.com/ReCasaOS/CasaOS-Gateway/common"
	"github.com/ReCasaOS/CasaOS-Gateway/pkg/proxyproto"
	"github.com/ReCasaOS/CasaOS-Gateway/route"
	"github.com/ReCasaOS/CasaOS-Gateway/service"
)

const shareHost = "jellyfin.mybox.box.example.org"

var (
	visitor = &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4444}
	relay   = &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 443}
)

// writeSharePair writes dir/share.{crt,key} for names (copied from common's test helper).
func writeSharePair(t *testing.T, dir string, names ...string) {
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
	if err := os.WriteFile(filepath.Join(dir, common.ShareCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, common.ShareKeyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newShareManagement(t *testing.T, dir string) *service.Management {
	t.Helper()

	logger.LogInitConsoleOnly()
	state := service.NewState()
	if err := state.SetRuntimePath(dir); err != nil {
		t.Fatal(err)
	}
	return service.NewManagementService(state)
}

// request writes req on c and returns everything the server sends back until it closes.
func request(t *testing.T, c net.Conn, req string) string {
	t.Helper()

	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(resp)
}

func dialShare(t *testing.T, addr, serverName string) *tls.Conn {
	t.Helper()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := proxyproto.WriteV2(raw, visitor, relay); err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc
}

func TestShareListenerServesAVisitorThroughPROXYAndTLS(t *testing.T) {
	dir := t.TempDir()
	def, err := common.SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeSharePair(t, dir, "*.mybox.box.example.org")
	picker, err := common.NewCertPicker(def, dir)
	if err != nil {
		t.Fatal(err)
	}

	type seen struct{ host, xff string }
	got := make(chan seen, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Host, r.Header.Get("X-Forwarded-For")}
	}))
	defer backend.Close()

	mgmt := newShareManagement(t, dir)
	if err := mgmt.SetHost(service.HostRoute{Host: shareHost, Target: backend.URL}); err != nil {
		t.Fatal(err)
	}

	srv, err := serveShare(dir, picker.Config(), route.NewGatewayRoute(mgmt).GetShareRoute())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	b, err := os.ReadFile(filepath.Join(dir, common.ShareAddrFilename))
	if err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimSpace(string(b))

	// A visitor of a shared app: the share certificate, the backend sees the visitor's address.
	tc := dialShare(t, addr, shareHost)
	if names := tc.ConnectionState().PeerCertificates[0].DNSNames; len(names) != 1 || names[0] != "*.mybox.box.example.org" {
		t.Fatalf("certificate names = %v, want the share certificate", names)
	}
	resp := request(t, tc, "GET /x HTTP/1.1\r\nHost: "+shareHost+"\r\nX-Forwarded-For: 1.1.1.1\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("response = %q, want 200", resp)
	}
	if s := <-got; s.host != shareHost || s.xff != "203.0.113.9" {
		t.Fatalf("backend saw Host %q, X-Forwarded-For %q", s.host, s.xff)
	}

	// A host nobody shared: 404.
	other := "other.mybox.box.example.org"
	resp = request(t, dialShare(t, addr, other), "GET / HTTP/1.1\r\nHost: "+other+"\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 404") {
		t.Fatalf("response = %q, want 404", resp)
	}

	// No PROXY header: the listener drops the connection, the handshake fails.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	err = tls.Client(raw, &tls.Config{ServerName: shareHost, InsecureSkipVerify: true}).Handshake()
	if err == nil {
		t.Fatal("handshake without a PROXY header succeeded")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("handshake without a PROXY header hung until the deadline: %v", err)
	}
}

func TestPublicListenerIgnoresPROXY(t *testing.T) {
	srv := httptest.NewServer(route.NewGatewayRoute(newShareManagement(t, t.TempDir())).GetRoute())
	defer srv.Close()

	raw, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := proxyproto.WriteV2(raw, visitor, relay); err != nil {
		t.Fatal(err)
	}
	resp := request(t, raw, "GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 400") {
		t.Fatalf("response = %q, want 400: the public port must not parse PROXY", resp)
	}
}
