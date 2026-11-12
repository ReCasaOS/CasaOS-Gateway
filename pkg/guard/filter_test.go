package guard

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

const (
	jf = "jellyfin.example.org"
	nc = "nextcloud.example.org"
)

func protectedConfig(mut func(*Policy)) Config {
	pol := Policy{
		WAF: "off", Countries: Countries{Mode: "none"}, RatePerMin: 600,
		Ban: BanRules{WAFHits: 10, WAFWindowS: 600, Scan404: 100, ScanWindowS: 60, RateStrikes: 3, RateWindowS: 600, CodeFails: 5, CodeWindowS: 600},
	}
	if mut != nil {
		mut(&pol)
	}
	return Config{Protection: true, Apps: map[string]AppConfig{
		jf: {App: "jellyfin", Access: "open", Policy: pol},
		nc: {App: "nextcloud", Access: "open", Policy: pol},
	}}
}

type fakeApp struct {
	status int
	hits   int
	seen   *http.Request
	w      http.ResponseWriter
}

func (a *fakeApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.hits++
	a.seen, a.w = r, w
	if a.status != 0 {
		w.WriteHeader(a.status)
	}
}

func get(h http.Handler, host, ip, path string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	r.RemoteAddr = net.JoinHostPort(ip, "4444")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func do(h http.Handler, host, ip string) *httptest.ResponseRecorder { return get(h, host, ip, "/x?q=1") }

func setup(t *testing.T, cfg *Config) (*Guard, *clock, *fakeApp, http.Handler) {
	t.Helper()
	c := startClock()
	g := newTestGuard(t, t.TempDir(), c)
	if cfg != nil {
		assert.NilError(t, g.SetConfig(*cfg))
	}
	a := &fakeApp{}
	return g, c, a, g.Handler(a)
}

func TestNoConfigPassesUntouched(t *testing.T) {
	g, _, a, h := setup(t, nil)

	r := httptest.NewRequest(http.MethodGet, "http://"+jf+"/x", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	r.Header.Set("Cookie", "a=b")
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	want := r.Header.Clone()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, a.hits, 1)
	assert.DeepEqual(t, a.seen.Header, want)
	assert.Equal(t, a.w, http.ResponseWriter(w)) // not wrapped
	assert.Equal(t, len(g.Events("", "", 0)), 0)
}

func TestProtectionOffSkipsFilters(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) { p.Block = []string{"203.0.113.9"}; p.RatePerMin = 1 })
	cfg.Protection = false
	g, _, a, h := setup(t, &cfg)

	for i := 0; i < 3; i++ {
		assert.Equal(t, do(h, jf, "203.0.113.9").Code, http.StatusOK)
	}
	assert.Equal(t, a.hits, 3)
	assert.Equal(t, len(g.Events("", "", 0)), 0)
}

func TestHostNotInAppsIsUntouched(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) { p.Block = []string{"203.0.113.9"} })
	g, _, a, h := setup(t, &cfg)

	assert.Equal(t, do(h, "other.example.org", "203.0.113.9").Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	assert.Equal(t, len(g.Events("", "", 0)), 0)
	// the host matches whatever its case, port or trailing dot
	assert.Equal(t, do(h, "JellyFin.Example.org.:443", "203.0.113.9").Code, http.StatusForbidden)
}

func TestBrokenAnswers503UntilSetConfig(t *testing.T) {
	c := startClock()
	rt := t.TempDir()
	assert.NilError(t, os.WriteFile(filepath.Join(rt, FileName), []byte("{"), 0o600))
	g, err := New(rt, t.TempDir(), c.now)
	assert.NilError(t, err)
	assert.Assert(t, g.Broken())
	a := &fakeApp{}
	h := g.Handler(a)

	w := do(h, "any.example.org", "203.0.113.9")
	assert.Equal(t, w.Code, http.StatusServiceUnavailable)
	assert.Equal(t, w.Body.String(), "This app is not available right now.\n")
	w = get(h, jf, "203.0.113.9", "/", "Accept-Language", "fr-FR,fr;q=0.9")
	assert.Equal(t, w.Body.String(), "Cette app n'est pas disponible pour le moment.\n")
	assert.Equal(t, a.hits, 0)

	assert.NilError(t, g.SetConfig(protectedConfig(nil)))
	assert.Equal(t, do(h, jf, "203.0.113.9").Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
}

func TestBlocklistAndAllowlist(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) {
		p.Block = []string{"203.0.113.9", "198.51.100.0/24"}
		p.Allow = []string{"198.51.100.7"}
	})
	g, _, a, h := setup(t, &cfg)

	w := do(h, jf, "203.0.113.9")
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.Equal(t, w.Body.String(), "Access denied.\n")
	ev := g.Events("", "blocklist", 0)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "blocked")
	assert.Equal(t, ev[0].App, "jellyfin")
	assert.Equal(t, ev[0].Path, "/x") // no query

	w = get(h, jf, "198.51.100.20", "/"+strings.Repeat("a", 300), "Accept-Language", "fr")
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.Equal(t, w.Body.String(), "Accès refusé.\n")
	assert.Equal(t, len(g.Events("", "blocklist", 0)[0].Path), 200)

	for i := 0; i < 601; i++ {
		assert.Equal(t, do(h, jf, "198.51.100.7").Code, http.StatusOK, "request %d", i+1)
	}
	assert.Equal(t, a.hits, 601)
}

func TestRateLimitThenBan(t *testing.T) {
	cfg := protectedConfig(nil)
	g, c, _, h := setup(t, &cfg)
	ip := "203.0.113.9"

	for minute := 0; minute < 3; minute++ {
		for i := 0; i < 600; i++ {
			assert.Equal(t, do(h, jf, ip).Code, http.StatusOK)
		}
		if minute == 0 {
			c.add(20500 * time.Millisecond)
		}
		w := do(h, jf, ip)
		assert.Equal(t, w.Code, http.StatusTooManyRequests)
		assert.Equal(t, w.Body.String(), "Too many requests. Try again later.\n")
		if minute == 0 {
			assert.Equal(t, w.Header().Get("Retry-After"), "40")
			// more refusals in the same window are not more strikes
			assert.Equal(t, do(h, jf, ip).Code, http.StatusTooManyRequests)
			assert.Equal(t, do(h, jf, ip).Code, http.StatusTooManyRequests)
		}
		_, banned := g.Banned(ip)
		assert.Equal(t, banned, minute == 2, "minute %d", minute)
		c.add(61 * time.Second)
	}

	b, _ := g.Banned(ip)
	assert.Equal(t, b.Reason, "rate")
	assert.Equal(t, b.App, "jellyfin")
	assert.Equal(t, len(g.Events("", "rate", 0)), 3)
	assert.Equal(t, g.Events("", "rate", 0)[0].Action, "banned")

	assert.Equal(t, do(h, jf, ip).Code, http.StatusForbidden)
	ev := g.Events("", "banned", 0)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "blocked")
}

func TestRateIsPerSlash64(t *testing.T) {
	cfg := protectedConfig(nil)
	_, _, _, h := setup(t, &cfg)

	for i := 0; i < 300; i++ {
		assert.Equal(t, do(h, jf, "2001:db8::1").Code, http.StatusOK)
		assert.Equal(t, do(h, jf, "2001:db8::2").Code, http.StatusOK)
	}
	assert.Equal(t, do(h, jf, "2001:db8::3").Code, http.StatusTooManyRequests)
	assert.Equal(t, do(h, jf, "2001:db8:0:1::1").Code, http.StatusOK)
	// per app as well
	assert.Equal(t, do(h, nc, "2001:db8::3").Code, http.StatusOK)
}

func TestScanBan(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) { p.Allow = []string{"192.0.2.0/24"} })
	g, c, a, h := setup(t, &cfg)
	a.status = http.StatusNotFound
	ip := "203.0.113.9"

	for i := 0; i < 99; i++ {
		assert.Equal(t, do(h, jf, ip).Code, http.StatusNotFound)
	}
	_, banned := g.Banned(ip)
	assert.Assert(t, !banned)

	// sliding window: the first 99 are out of it now
	c.add(61 * time.Second)
	for i := 0; i < 99; i++ {
		do(h, jf, ip)
	}
	_, banned = g.Banned(ip)
	assert.Assert(t, !banned)
	do(h, jf, ip)
	b, banned := g.Banned(ip)
	assert.Assert(t, banned)
	assert.Equal(t, b.Reason, "scan")
	ev := g.Events("", "scan", 0)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "banned")

	for i := 0; i < 200; i++ {
		do(h, jf, "192.0.2.5")
	}
	_, banned = g.Banned("192.0.2.5")
	assert.Assert(t, !banned)
}

func TestBanIsBoxWide(t *testing.T) {
	cfg := protectedConfig(nil)
	g, _, a, h := setup(t, &cfg)
	g.BanKey("203.0.113.9", "203.0.113.9", "jellyfin", "scan")

	assert.Equal(t, do(h, nc, "203.0.113.9").Code, http.StatusForbidden)
	assert.Equal(t, a.hits, 0)
	ev := g.Events("nextcloud", "banned", 0)
	assert.Equal(t, len(ev), 1)
}

func TestBannedEventsAreThrottled(t *testing.T) {
	cfg := protectedConfig(nil)
	g, c, _, h := setup(t, &cfg)
	g.BanKey("203.0.113.9", "203.0.113.9", "jellyfin", "scan")

	for i := 0; i < 50; i++ {
		assert.Equal(t, do(h, jf, "203.0.113.9").Code, http.StatusForbidden)
		c.add(time.Second)
	}
	ev := g.Events("", "banned", 0)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Count, 50)
}

func TestHooksRunInOrder(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) { p.Allow = []string{"192.0.2.5"} })
	g, _, a, h := setup(t, &cfg)
	var calls []string
	stop := ""
	hook := func(name string) hook {
		return func(w http.ResponseWriter, r *http.Request, app AppConfig) bool {
			calls = append(calls, name+":"+app.App)
			if name == stop {
				w.WriteHeader(http.StatusTeapot)
				return true
			}
			return false
		}
	}
	g.country, g.waf, g.gate = hook("country"), hook("waf"), hook("gate")

	do(h, jf, "203.0.113.9")
	assert.DeepEqual(t, calls, []string{"country:jellyfin", "waf:jellyfin", "gate:jellyfin"})

	calls = nil
	do(h, jf, "192.0.2.5") // allowed: the gate only
	assert.DeepEqual(t, calls, []string{"gate:jellyfin"})

	calls, stop = nil, "country"
	assert.Equal(t, do(h, jf, "203.0.113.9").Code, http.StatusTeapot)
	assert.DeepEqual(t, calls, []string{"country:jellyfin"})
	assert.Equal(t, a.hits, 2)

	cfg.Protection = false
	assert.NilError(t, g.SetConfig(cfg))
	calls, stop = nil, ""
	do(h, jf, "203.0.113.9")
	assert.DeepEqual(t, calls, []string{"gate:jellyfin"})
}

func TestCountersAreBounded(t *testing.T) {
	cfg := protectedConfig(func(p *Policy) { p.RatePerMin = 1 })
	g, c, a, h := setup(t, &cfg)
	a.status = http.StatusNotFound

	for i := 0; i < 10000; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		assert.Equal(t, do(h, jf, ip).Code, http.StatusNotFound)        // a scan count
		assert.Equal(t, do(h, jf, ip).Code, http.StatusTooManyRequests) // a rate strike
	}
	assert.Equal(t, len(g.rates), 10000)
	assert.Equal(t, len(g.scans), 10000)
	assert.Equal(t, len(g.rateStrikes), 10000)

	c.add(601 * time.Second)
	a.status = http.StatusOK
	do(h, jf, "203.0.113.9")
	assert.Equal(t, len(g.rates), 1) // the newcomer
	assert.Equal(t, len(g.scans), 0)
	assert.Equal(t, len(g.rateStrikes), 0)
}

// A WebSocket-style upgrade through httputil.ReverseProxy behind the guard: the wrapper must keep Hijacker.
func TestUpgradeThroughTheGuard(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		brw.Flush()
		io.Copy(conn, brw)
	}))
	defer backend.Close()
	u, err := url.Parse(backend.URL)
	assert.NilError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(u)

	cfg := protectedConfig(nil)
	cfg.Apps["127.0.0.1"] = cfg.Apps[jf]
	g, _, _, _ := setup(t, &cfg)
	type ifaces struct{ hijack, readFrom, flush bool }
	got := make(chan ifaces, 1)
	front := httptest.NewServer(g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hj := w.(http.Hijacker)
		_, rf := w.(io.ReaderFrom)
		_, fl := w.(http.Flusher)
		got <- ifaces{hj, rf, fl}
		proxy.ServeHTTP(w, r)
	})))
	defer front.Close()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	assert.NilError(t, err)
	defer conn.Close()
	assert.NilError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+front.Listener.Addr().String()+"\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	assert.NilError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	assert.NilError(t, err)
	assert.Equal(t, resp.StatusCode, http.StatusSwitchingProtocols)
	assert.Equal(t, <-got, ifaces{true, true, true})

	_, err = io.WriteString(conn, "ping")
	assert.NilError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(br, buf)
	assert.NilError(t, err)
	assert.Equal(t, string(buf), "ping")
}
