package guard

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

const sqli = "/?id=1'%20OR%20'1'='1"

func wafConfig(mode string, mut func(*Policy)) Config {
	return protectedConfig(func(p *Policy) {
		p.WAF = mode
		if mut != nil {
			mut(p)
		}
	})
}

func send(h http.Handler, method, host, path, ctype string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, body)
	r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	if r.ContentLength > 0 { // as net/http leaves it on a server request
		r.Header.Set("Content-Length", strconv.FormatInt(r.ContentLength, 10))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func wafEvents(g *Guard) []Event { return g.Events("", "waf", 0) }

func TestNoWAFWhenAllOff(t *testing.T) {
	w, err := buildWAF(protectedConfig(nil).Apps)
	assert.NilError(t, err)
	assert.Assert(t, w == nil)
}

// The WAF is rebuilt from guard.json at start, and not built at all with protection off.
func TestWAFBuiltAtLoadAndOnlyWithProtection(t *testing.T) {
	rt := t.TempDir()
	c := startClock()
	g, err := New(rt, t.TempDir(), "", c.now)
	assert.NilError(t, err)
	assert.NilError(t, g.SetConfig(wafConfig("block", nil)))

	g, err = New(rt, t.TempDir(), "", c.now)
	assert.NilError(t, err)
	assert.Assert(t, !g.Broken())
	assert.Equal(t, get(g.Handler(&fakeApp{}), jf, visitorIP, sqli).Code, http.StatusForbidden)

	cfg := wafConfig("block", nil)
	cfg.Protection = false
	assert.NilError(t, g.SetConfig(cfg))
	assert.Assert(t, g.crs == nil)
}

func TestBlockSQLi(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, a, h := setup(t, &cfg)

	w := get(h, jf, visitorIP, sqli)
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.Equal(t, w.Body.String(), "Access denied.\n")
	assert.Equal(t, a.hits, 0)
	ev := wafEvents(g)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "blocked")
	assert.Equal(t, ev[0].App, "jellyfin")
	assert.Equal(t, ev[0].Path, "/")
	assert.Assert(t, ev[0].Rule/1000 == 942, "rule %d", ev[0].Rule)
	assert.Assert(t, ev[0].Detail != "")
	assert.Assert(t, !strings.Contains(ev[0].Detail, "'1'"), ev[0].Detail)
}

func TestObserveLetsThrough(t *testing.T) {
	cfg := wafConfig("observe", nil)
	g, _, a, h := setup(t, &cfg)

	assert.Equal(t, get(h, jf, visitorIP, sqli).Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	ev := wafEvents(g)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "observed")
	assert.Equal(t, ev[0].Count, 1) // one event per request, not one per matched rule
	assert.Assert(t, ev[0].Rule/1000 == 942, "rule %d", ev[0].Rule)
}

// A match that alone stays under the anomaly threshold is no event, in either mode.
func TestLowScoreMatchIsNoEvent(t *testing.T) {
	for _, mode := range []string{"observe", "block"} {
		cfg := wafConfig(mode, nil)
		g, _, a, h := setup(t, &cfg)
		w := get(h, jf, visitorIP, "/x", "Range", "bytes=10-5") // 920190, a warning
		assert.Equal(t, w.Code, http.StatusOK, mode)
		assert.Equal(t, a.hits, 1, mode)
		assert.Equal(t, len(wafEvents(g)), 0, mode)
	}
}

func TestRuleOffPerHost(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, _, h := setup(t, &cfg)
	assert.Equal(t, get(h, jf, visitorIP, sqli).Code, http.StatusForbidden)
	rule := wafEvents(g)[0].Rule

	cfg = wafConfig("block", nil)
	app := cfg.Apps[jf]
	app.Policy.RulesOff = []int{rule}
	cfg.Apps[jf] = app
	g, _, a, h := setup(t, &cfg)

	// the host matches whatever its case, port or trailing dot, like the app lookup
	assert.Equal(t, get(h, "JellyFin.Example.org.:443", visitorIP, sqli).Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	assert.Equal(t, get(h, nc, visitorIP, sqli).Code, http.StatusForbidden)
	assert.Equal(t, a.hits, 1)
	assert.Equal(t, len(wafEvents(g)), 1)
}

func TestWebDAVMethodsAllowed(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, a, h := setup(t, &cfg)

	const propfind = `<?xml version="1.0" encoding="UTF-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:getcontentlength/></d:prop></d:propfind>`
	w := send(h, "PROPFIND", nc, "/remote.php/dav/files/u/", "application/xml; charset=utf-8", strings.NewReader(propfind))
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	body, err := io.ReadAll(a.seen.Body)
	assert.NilError(t, err)
	assert.Equal(t, string(body), propfind) // the app gets the body the WAF read

	for i, m := range []string{"PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "PUT", "DELETE", "PATCH"} {
		assert.Equal(t, send(h, m, nc, "/remote.php/dav/files/u/a", "", nil).Code, http.StatusOK, m)
		assert.Equal(t, a.hits, i+2, m)
	}
	assert.Equal(t, len(wafEvents(g)), 0)
}

// Any upload type reaches the app whole under block (920420 is off; such bodies are not parsed).
func TestUploadTypesAllowed(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, a, h := setup(t, &cfg)
	bin, _ := io.ReadAll(io.LimitReader(rand.NewChaCha8([32]byte{3}), 256<<10))
	for _, c := range []struct{ ctype, body string }{
		{"image/jpeg", string(bin)},
		{"text/plain", strings.Repeat("hello world, notes from the trip. ", 8<<10)},
	} {
		w := send(h, http.MethodPut, nc, "/remote.php/dav/files/u/f", c.ctype, strings.NewReader(c.body))
		assert.Equal(t, w.Code, http.StatusOK, c.ctype)
		got, err := io.ReadAll(a.seen.Body)
		assert.NilError(t, err)
		assert.Assert(t, string(got) == c.body, c.ctype)
	}
	assert.Equal(t, len(wafEvents(g)), 0)
}

// An attack inside the inspected first 64 KiB of a 2 MiB body is caught, whatever the parser.
func TestCutBodyStillInspected(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, _, h := setup(t, &cfg)
	pad := strings.Repeat(`{"name":"photo","size":12345},`, (2<<20)/30)
	for _, c := range []struct{ ctype, body string }{
		{"application/json", `{"q":"1' OR '1'='1","items":[` + pad + `{}]}`},
		{"application/xml", `<a><q>1' OR '1'='1</q>` + strings.Repeat("<i>photo</i>", (2<<20)/12) + `</a>`},
		{"application/x-www-form-urlencoded", "q=1'%20OR%20'1'='1&p=" + strings.Repeat("x", 2<<20)},
	} {
		assert.Equal(t, send(h, http.MethodPost, jf, "/api", c.ctype, strings.NewReader(c.body)).Code, http.StatusForbidden, c.ctype)
		assert.Assert(t, wafEvents(g)[0].Rule/1000 == 942, "%s: rule %d", c.ctype, wafEvents(g)[0].Rule)
	}
}

// sink is an app that hashes what it receives and notes the heap at the end of the body.
type sink struct {
	n    int64
	sum  []byte
	heap uint64
}

func (s *sink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hs := sha256.New()
	s.n, _ = io.Copy(hs, r.Body)
	s.sum = hs.Sum(nil)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.heap = m.HeapInuse
}

func TestLargeUploadStreams(t *testing.T) {
	const size = 64 << 20
	cfg := wafConfig("block", nil)
	g := newTestGuard(t, t.TempDir(), startClock())
	assert.NilError(t, g.SetConfig(cfg))
	app := &sink{}
	h := g.Handler(app)

	sent := sha256.New()
	body := io.TeeReader(io.LimitReader(rand.NewChaCha8([32]byte{1}), size), sent)
	r := httptest.NewRequest(http.MethodPut, "http://"+nc+"/remote.php/dav/files/u/big.bin", body)
	r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
	r.ContentLength = size
	r.Header.Set("Content-Length", strconv.Itoa(size))
	r.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	h.ServeHTTP(w, r)

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, app.n, int64(size))
	assert.DeepEqual(t, app.sum, sent.Sum(nil))
	grew := int64(app.heap) - int64(before.HeapInuse)
	t.Logf("heap in use grew by %d KiB during the request", grew>>10)
	assert.Assert(t, grew < 16<<20, "heap grew by %d bytes", grew)
}

// A valid body cut at the inspection limit is not a malformed body; a malformed one is still refused.
func TestLargeJSONPasses(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, a, h := setup(t, &cfg)

	var b bytes.Buffer
	b.WriteString(`{"items":[`)
	for b.Len() < 3<<20 {
		b.WriteString(`{"name":"photo","size":12345},`)
	}
	b.WriteString(`{"name":"last"}]}`)
	want := b.String()
	w := send(h, http.MethodPost, jf, "/api/items", "application/json", strings.NewReader(want))
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	got, err := io.ReadAll(a.seen.Body)
	assert.NilError(t, err)
	assert.Equal(t, len(got), len(want))
	assert.Assert(t, string(got) == want)
	assert.Equal(t, len(wafEvents(g)), 0)

	assert.Equal(t, send(h, http.MethodPost, jf, "/api/items", "application/json", strings.NewReader(`{"items":[`)).Code, http.StatusForbidden)
	assert.Equal(t, wafEvents(g)[0].Rule, 9100001)
}

func TestWAFHitsBan(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, c, _, h := setup(t, &cfg)

	for i := 0; i < 9; i++ {
		assert.Equal(t, get(h, jf, visitorIP, sqli).Code, http.StatusForbidden)
		c.add(time.Minute)
	}
	_, banned := g.Banned(visitorIP)
	assert.Assert(t, !banned)
	assert.Equal(t, get(h, jf, visitorIP, sqli).Code, http.StatusForbidden) // 10th within 10 min
	b, banned := g.Banned(visitorIP)
	assert.Assert(t, banned)
	assert.Equal(t, b.Reason, "waf")
	ev := wafEvents(g)
	assert.Equal(t, ev[0].Action, "banned")
	assert.Equal(t, ev[1].Action, "blocked")
	assert.Equal(t, ev[1].Count+ev[0].Count+len(ev)-2, 10)
}

// Observed matches never count toward a ban.
func TestObservedNeverBans(t *testing.T) {
	cfg := wafConfig("observe", nil)
	g, _, a, h := setup(t, &cfg)
	for i := 0; i < 12; i++ {
		assert.Equal(t, get(h, jf, visitorIP, sqli).Code, http.StatusOK)
	}
	assert.Equal(t, a.hits, 12)
	_, banned := g.Banned(visitorIP)
	assert.Assert(t, !banned)
}

// The WAF ignores the session cookie and the entry form of a code app, but inspects that path on an open app.
func TestWAFSkipsSessionCookieAndEntryForm(t *testing.T) {
	cfg := codeConfig(true)
	for host, app := range cfg.Apps {
		app.Policy.WAF = "block"
		cfg.Apps[host] = app
	}
	g, _, a, h := setup(t, &cfg)

	w := get(h, gh, visitorIP, "/x", "Cookie", CookieName+"=1' OR '1'='1 --; theme=dark")
	assert.Equal(t, w.Code, http.StatusUnauthorized) // the gate's answer, not the WAF's

	form := url.Values{"code": {"1' OR '1'='1 --"}, "next": {"/"}}.Encode()
	w = send(h, http.MethodPost, gh, EntryPath, "application/x-www-form-urlencoded", strings.NewReader(form))
	assert.Equal(t, w.Code, http.StatusUnauthorized) // wrong code
	assert.Equal(t, len(wafEvents(g)), 0)

	assert.Equal(t, get(h, ghOpen, visitorIP, EntryPath+sqli[1:]).Code, http.StatusForbidden)
	assert.Equal(t, a.hits, 0)
	assert.Equal(t, len(wafEvents(g)), 1)
}

func TestRuleMsgHasNoRequestData(t *testing.T) {
	assert.Equal(t, ruleMsg(`SecRule REQUEST_HEADERS_NAMES "@rx x" "id:920450,phase:1,block,msg:'HTTP header is restricted by policy (%{MATCHED_VAR})',logdata:'%{MATCHED_VAR}'"`),
		"HTTP header is restricted by policy")
	assert.Equal(t, ruleMsg(`SecRule ARGS "@rx x" "id:1,msg:'SQL Injection Attack Detected via libinjection',logdata:'Matched Data: %{TX.0}'"`),
		"SQL Injection Attack Detected via libinjection")
	assert.Equal(t, ruleMsg(`SecAction "id:2,pass"`), "")
	assert.Equal(t, len(ruleMsg(`SecAction "id:3,msg:'`+strings.Repeat("a", 300)+`'"`)), 200)
}

func TestHostileHostRefused(t *testing.T) {
	cfg := wafConfig("block", func(p *Policy) { p.RulesOff = []int{942100} })
	cfg.Apps[`evil" "id:1,phase:1,pass,ctl:ruleengine=off`] = cfg.Apps[jf]
	_, err := buildWAF(cfg.Apps)
	assert.Assert(t, errors.Is(err, ErrInvalid), "%v", err)
}

// slowGuard is a guard on block whose body inspections wait, inside their slot, until let is closed
// or written to; each one announces itself on in.
func slowGuard(t *testing.T) (g *Guard, h http.Handler, hits *atomic.Int32, in chan struct{}, let chan struct{}) {
	t.Helper()
	g = newTestGuard(t, t.TempDir(), startClock())
	assert.NilError(t, g.SetConfig(wafConfig("block", nil)))
	in, let, hits = make(chan struct{}, 8), make(chan struct{}), &atomic.Int32{}
	g.inspecting = func() { in <- struct{}{}; <-let }
	h = g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	return
}

func postForm(h http.Handler, ip string) int {
	r := httptest.NewRequest(http.MethodPost, "http://"+jf+"/login", strings.NewReader("user=bob&remember=1"))
	r.RemoteAddr = net.JoinHostPort(ip, "4444")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Content-Length", "19")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// entered waits briefly for an inspection to start; false when none does.
func entered(in chan struct{}) bool {
	select {
	case <-in:
		return true
	case <-time.After(150 * time.Millisecond):
		return false
	}
}

func TestBodyInspectionsCappedPerBox(t *testing.T) {
	g, h, hits, in, let := slowGuard(t)
	codes := make(chan int, 3)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		go func() { codes <- postForm(h, ip) }()
	}
	assert.Assert(t, entered(in))
	assert.Assert(t, entered(in))
	assert.Assert(t, !entered(in)) // the third waits for a slot

	// a request without a parsed body never waits for one
	assert.Equal(t, get(h, jf, "203.0.113.4", "/x").Code, http.StatusOK)
	assert.Equal(t, send(h, http.MethodPut, jf, "/f.bin", "application/octet-stream", strings.NewReader("raw bytes")).Code, http.StatusOK)

	let <- struct{}{}
	assert.Assert(t, entered(in)) // a slot freed: the third is inspected
	close(let)
	for i := 0; i < 3; i++ {
		assert.Equal(t, <-codes, http.StatusOK)
	}
	assert.Equal(t, hits.Load(), int32(5))
	assert.Equal(t, len(wafEvents(g)), 0)
}

func TestBodyInspectionsCappedPerKey(t *testing.T) {
	_, h, hits, in, let := slowGuard(t)
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { codes <- postForm(h, "2001:db8::1") }()
	}
	assert.Assert(t, entered(in))
	assert.Assert(t, !entered(in)) // same /64 key: the second waits though the box has a slot
	let <- struct{}{}
	assert.Assert(t, entered(in))
	close(let)
	assert.Equal(t, <-codes, http.StatusOK)
	assert.Equal(t, <-codes, http.StatusOK)
	assert.Equal(t, hits.Load(), int32(2))
}

func TestBodyInspectionBusyIs503(t *testing.T) {
	g, h, hits, in, let := slowGuard(t)
	g.inspectWait = 100 * time.Millisecond // stands for the 2 s
	first := make(chan int, 1)
	go func() { first <- postForm(h, visitorIP) }()
	assert.Assert(t, entered(in))

	r := httptest.NewRequest(http.MethodPost, "http://"+jf+"/login", strings.NewReader("user=bob&remember=1"))
	r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, w.Code, http.StatusServiceUnavailable)
	assert.Equal(t, w.Body.String(), "This app is not available right now.\n")
	assert.Equal(t, hits.Load(), int32(0)) // not passed uninspected
	ev := wafEvents(g)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "blocked")
	assert.Equal(t, ev[0].Detail, "inspection busy")
	assert.Equal(t, ev[0].Rule, 0)

	close(let)
	assert.Equal(t, <-first, http.StatusOK)
	assert.Equal(t, hits.Load(), int32(1))
	g.cm.Lock()
	assert.Equal(t, len(g.wafHits), 0) // no ban count
	g.cm.Unlock()
}
