package service

import (
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gotest.tools/assert"
)

func newHostTestManagement(t *testing.T) (*Management, *State) {
	t.Helper()
	dir, err := os.MkdirTemp("", "casaos-gateway-host-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	state := NewState()
	if err := state.SetRuntimePath(dir); err != nil {
		t.Fatal(err)
	}
	return NewManagementService(state), state
}

func TestHostLookupNormalizes(t *testing.T) {
	m, _ := newHostTestManagement(t)

	if err := m.SetHost(HostRoute{Host: "Jellyfin.MyBox.box.example.org", Target: "http://127.0.0.1:8096"}); err != nil {
		t.Fatal(err)
	}

	for _, h := range []string{
		"jellyfin.mybox.box.example.org:443",
		"JELLYFIN.mybox.box.example.org",
		"jellyfin.mybox.box.example.org.",
	} {
		assert.Assert(t, m.GetHostProxy(h) != nil, h)
	}
	assert.Assert(t, m.GetHostProxy("other.mybox.box.example.org") == nil)
}

func TestHostValidation(t *testing.T) {
	m, _ := newHostTestManagement(t)

	for _, h := range []string{"", "mybox", "-a.b", "a-.b", "a..b", "a.b/c", "http://a.b", strings.Repeat("a.", 127) + "b"} {
		err := m.SetHost(HostRoute{Host: h, Target: "http://127.0.0.1:8096"})
		assert.Assert(t, errors.Is(err, ErrBadHost), "host %q: %v", h, err)
	}

	for _, target := range []string{"", "127.0.0.1:8096", "ftp://127.0.0.1", "http://", "http://127.0.0.1:8096/path", "http://127.0.0.1:8096?x=1", "http://u:p@127.0.0.1", "http://192.168.1.10:8096", "http://169.254.169.254", "http://casaos.local:80"} {
		err := m.SetHost(HostRoute{Host: "a.example.org", Target: target})
		assert.Assert(t, errors.Is(err, ErrBadTarget), "target %q: %v", target, err)
	}

	for _, target := range []string{"http://127.0.0.1:8096", "https://127.0.0.1:8443", "http://127.0.0.1:8096/", "http://localhost:8096", "https://[::1]:8443"} {
		assert.NilError(t, m.SetHost(HostRoute{Host: "a.example.org", Target: target}))
	}
}

func TestHostsPersistence(t *testing.T) {
	m, state := newHostTestManagement(t)

	assert.NilError(t, m.SetHost(HostRoute{Host: "a.example.org", Target: "http://127.0.0.1:1"}))
	assert.NilError(t, m.SetHost(HostRoute{Host: "b.example.org", Target: "http://127.0.0.1:2"}))
	assert.NilError(t, m.DeleteHost("a.example.org"))
	assert.NilError(t, m.DeleteHost("a.example.org")) // idempotent

	m2 := NewManagementService(state)
	hosts := m2.GetHosts()
	assert.Equal(t, 1, len(hosts))
	assert.Equal(t, "b.example.org", hosts[0].Host)
	assert.Equal(t, "http://127.0.0.1:2", hosts[0].Target)
	assert.Assert(t, m2.GetHostProxy("b.example.org") != nil)

	if runtime.GOOS != "windows" { // Windows has no unix permission bits
		info, err := os.Stat(filepath.Join(state.GetRuntimePath(), HostsFile))
		assert.NilError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestGetHostsEmptyIsNonNilAndSorted(t *testing.T) {
	m, _ := newHostTestManagement(t)
	hosts := m.GetHosts()
	assert.Assert(t, hosts != nil)
	assert.Equal(t, 0, len(hosts))

	assert.NilError(t, m.SetHost(HostRoute{Host: "z.example.org", Target: "http://127.0.0.1:1"}))
	assert.NilError(t, m.SetHost(HostRoute{Host: "a.example.org", Target: "http://127.0.0.1:2"}))
	hosts = m.GetHosts()
	assert.Equal(t, "a.example.org", hosts[0].Host)
	assert.Equal(t, "z.example.org", hosts[1].Host)
}

func TestHostProxySetsForwardedHeaders(t *testing.T) {
	const host = "jellyfin.mybox.box.example.org"

	var seenHost, xff, xfh, xfp, realIP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost, xff = r.Host, r.Header.Get("X-Forwarded-For")
		xfh, xfp = r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Forwarded-Proto")
		realIP = r.Header.Get("X-Real-IP")
	}))
	defer backend.Close()

	m, _ := newHostTestManagement(t)
	assert.NilError(t, m.SetHost(HostRoute{Host: host, Target: backend.URL}))

	serve := func(withTLS bool) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		req.RemoteAddr = "203.0.113.9:4444"
		req.Header.Set("X-Forwarded-For", "1.1.1.1") // spoof
		req.Header.Set("X-Real-IP", "127.0.0.1")     // spoof
		if withTLS {
			req.TLS = &tls.ConnectionState{}
		}
		m.GetHostProxy(host).ServeHTTP(httptest.NewRecorder(), req)
	}

	serve(false)
	assert.Equal(t, host, seenHost)
	assert.Equal(t, "203.0.113.9", xff)
	assert.Equal(t, host, xfh)
	assert.Equal(t, "http", xfp)
	assert.Equal(t, "", realIP)

	serve(true)
	assert.Equal(t, "https", xfp)
}

func TestHTTPSTargetIsNotVerified(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	defer backend.Close()

	const host = "app.mybox.box.example.org"
	m, _ := newHostTestManagement(t)
	assert.NilError(t, m.SetHost(HostRoute{Host: host, Target: backend.URL}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = host
	rec := httptest.NewRecorder()
	m.GetHostProxy(host).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "hello", rec.Body.String())
}
