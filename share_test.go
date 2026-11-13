package main

import (
	"bufio"
	"context"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/utils/logger"

	"github.com/ReCasaOS/CasaOS-Gateway/common"
	"github.com/ReCasaOS/CasaOS-Gateway/pkg/guard"
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

func dialShare(t *testing.T, addr, serverName string, protos ...string) *tls.Conn {
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
	tc := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: protos})
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

	type seen struct{ host, xff, realIP string }
	got := make(chan seen, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP")}
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
	resp := request(t, tc, "GET /x HTTP/1.1\r\nHost: "+shareHost+"\r\nX-Forwarded-For: 1.1.1.1\r\nX-Real-IP: 127.0.0.1\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 200") {
		t.Fatalf("response = %q, want 200", resp)
	}
	if s := <-got; s.host != shareHost || s.xff != "203.0.113.9" || s.realIP != "" {
		t.Fatalf("backend saw Host %q, X-Forwarded-For %q, X-Real-IP %q", s.host, s.xff, s.realIP)
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

func TestShareListenerRefusesABlockedVisitor(t *testing.T) {
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
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer backend.Close()

	mgmt := newShareManagement(t, dir)
	if err := mgmt.SetHost(service.HostRoute{Host: shareHost, Target: backend.URL}); err != nil {
		t.Fatal(err)
	}
	if mgmt.Guard, err = guard.New(dir, dir, "", time.Now); err != nil {
		t.Fatal(err)
	}
	ban := guard.BanRules{WAFHits: 10, WAFWindowS: 600, Scan404: 100, ScanWindowS: 60, RateStrikes: 3, RateWindowS: 600, CodeFails: 5, CodeWindowS: 600}
	if err := mgmt.Guard.SetConfig(guard.Config{Protection: true, Apps: map[string]guard.AppConfig{shareHost: {
		App: "jellyfin", Access: "open",
		Policy: guard.Policy{WAF: "off", Block: []string{visitor.IP.String()}, Countries: guard.Countries{Mode: "none"}, RatePerMin: 600, Ban: ban},
	}}}); err != nil {
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

	resp := request(t, dialShare(t, strings.TrimSpace(string(b)), shareHost), "GET /x HTTP/1.1\r\nHost: "+shareHost+"\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 403") {
		t.Fatalf("response = %q, want 403", resp)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("backend saw %d requests, want none", n)
	}
	if ev := mgmt.Guard.Events("jellyfin", "blocklist", 0); len(ev) != 1 || ev[0].IP != visitor.IP.String() {
		t.Fatalf("events = %+v, want one blocklist event for the visitor", ev)
	}
}

func TestShareWebSocketWithAccessCookie(t *testing.T) {
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
	cookies := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies <- r.Header.Get("Cookie")
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		brw.Flush()
	}))
	defer backend.Close()

	mgmt := newShareManagement(t, dir)
	if err := mgmt.SetHost(service.HostRoute{Host: shareHost, Target: backend.URL}); err != nil {
		t.Fatal(err)
	}
	if mgmt.Guard, err = guard.New(dir, dir, "", time.Now); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	ban := guard.BanRules{WAFHits: 10, WAFWindowS: 600, Scan404: 100, ScanWindowS: 60, RateStrikes: 3, RateWindowS: 600, CodeFails: 5, CodeWindowS: 600}
	if err := mgmt.Guard.SetConfig(guard.Config{
		Secret: secret, Protection: true,
		Apps: map[string]guard.AppConfig{shareHost: {App: "jellyfin", Access: "code",
			Policy: guard.Policy{WAF: "off", Countries: guard.Countries{Mode: "none"}, RatePerMin: 600, Ban: ban}}},
		People: []guard.Person{{ID: "p1", Gen: 1, CodeHash: guard.CodeHash(secret, "ABCD-EFGH-JKMN"), Apps: []string{"jellyfin"}}},
	}); err != nil {
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

	upgrade := "GET /socket HTTP/1.1\r\nHost: " + shareHost + "\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	resp := request(t, dialShare(t, addr, shareHost, "http/1.1"), upgrade+"\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 401") {
		t.Fatalf("without a cookie: response = %q, want 401", resp)
	}

	token := guard.SignSession(secret, "p1", 1, time.Now())
	resp = request(t, dialShare(t, addr, shareHost, "http/1.1"), upgrade+"Cookie: a=b; recasaos_access="+token+"\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 101") {
		t.Fatalf("with a cookie: response = %q, want 101", resp)
	}
	if got := <-cookies; got != "a=b" {
		t.Fatalf("backend saw Cookie %q, want a=b", got)
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
	// One write: the server reads it all before answering 400 and closing, so no unread bytes turn the close into a reset.
	var hdr strings.Builder
	if err := proxyproto.WriteV2(&hdr, visitor, relay); err != nil {
		t.Fatal(err)
	}
	resp := request(t, raw, hdr.String()+"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 400") {
		t.Fatalf("response = %q, want 400: the public port must not parse PROXY", resp)
	}
}

func TestShareListenerSpeaksHTTP2(t *testing.T) {
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
	xff := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xff <- r.Header.Get("X-Forwarded-For")
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

	// A client that offers only HTTP/1.1 (a WebSocket, an old client) still gets it.
	if p := dialShare(t, addr, shareHost, "http/1.1").ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("HTTP/1.1-only client negotiated %q", p)
	}

	// A browser gets h2, and the request still reaches the app with the visitor's address.
	client := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return dialShare(t, addr, shareHost, "h2", "http/1.1"), nil
		},
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + shareHost + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		t.Fatalf("got %s %d, want HTTP/2.0 200", resp.Proto, resp.StatusCode)
	}
	if got := <-xff; got != "203.0.113.9" {
		t.Fatalf("backend saw X-Forwarded-For %q, want the visitor", got)
	}
}

// Over HTTP/2 a protected app answers a visitor without a session itself, and with one the app never
// sees the access cookie. A head past 32 KiB is refused by the listener.
func TestShareHTTP2AccessGate(t *testing.T) {
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
	var hits atomic.Int32
	cookies := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		cookies <- r.Header.Get("Cookie")
	}))
	defer backend.Close()

	mgmt := newShareManagement(t, dir)
	if err := mgmt.SetHost(service.HostRoute{Host: shareHost, Target: backend.URL}); err != nil {
		t.Fatal(err)
	}
	if mgmt.Guard, err = guard.New(dir, dir, "", time.Now); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	ban := guard.BanRules{WAFHits: 10, WAFWindowS: 600, Scan404: 100, ScanWindowS: 60, RateStrikes: 3, RateWindowS: 600, CodeFails: 5, CodeWindowS: 600}
	if err := mgmt.Guard.SetConfig(guard.Config{
		Secret: secret, Protection: true,
		Apps: map[string]guard.AppConfig{shareHost: {App: "jellyfin", Access: "code",
			Policy: guard.Policy{WAF: "off", Countries: guard.Countries{Mode: "none"}, RatePerMin: 600, Ban: ban}}},
		People: []guard.Person{{ID: "p1", Gen: 1, CodeHash: guard.CodeHash(secret, "ABCD-EFGH-JKMN"), Apps: []string{"jellyfin"}}},
	}); err != nil {
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

	client := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return dialShare(t, addr, shareHost, "h2"), nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	get := func(hdr ...string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+shareHost+"/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("got %s, want HTTP/2.0", resp.Proto)
		}
		return resp
	}

	if resp := get(); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d, want 401", resp.StatusCode)
	}
	if resp := get("Accept", "text/html"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), guard.EntryPath) {
		t.Fatalf("a browser without a session: %d to %q, want 302 to the entry page", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("backend saw %d requests without a session, want none", n)
	}
	token := guard.SignSession(secret, "p1", 1, time.Now())
	if resp := get("Cookie", "a=b; recasaos_access="+token); resp.StatusCode != http.StatusOK {
		t.Fatalf("with a session: %d, want 200", resp.StatusCode)
	}
	if got := <-cookies; got != "a=b" {
		t.Fatalf("backend saw Cookie %q, want a=b", got)
	}

	// The status line is all that is read: the listener stops reading the head at its limit.
	c := dialShare(t, addr, shareHost, "http/1.1")
	if _, err := io.WriteString(c, "GET /x HTTP/1.1\r\nHost: "+shareHost+"\r\nX-Pad: "+strings.Repeat("a", 40<<10)+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 431") {
		t.Fatalf("a 40 KiB head: %q (%v), want 431", line, err)
	}
}
