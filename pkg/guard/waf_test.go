package guard

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3/types"
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
	rules, err := wafRules(protectedConfig(nil).Apps)
	assert.NilError(t, err)
	assert.Equal(t, rules, "")
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

// multipartFile wraps body as the single file part of a multipart/form-data upload.
func multipartFile(body io.Reader) (ctype string, r io.Reader, extra int) {
	const head = "--b0undary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
	const tail = "\r\n--b0undary--\r\n"
	return "multipart/form-data; boundary=b0undary", io.MultiReader(strings.NewReader(head), body, strings.NewReader(tail)), len(head) + len(tail)
}

// A 64 MiB upload streams to the app whole, unparsed (PUT) or parsed (multipart POST).
func TestLargeUploadStreams(t *testing.T) {
	const size = 64 << 20
	for _, multi := range []bool{false, true} {
		g := newTestGuard(t, t.TempDir(), startClock())
		assert.NilError(t, g.SetConfig(wafConfig("block", nil)))
		app := &sink{}
		h := g.Handler(app)

		var body io.Reader = io.LimitReader(rand.NewChaCha8([32]byte{1}), size)
		method, ctype, total := http.MethodPut, "application/octet-stream", size
		if multi {
			var extra int
			method = http.MethodPost
			ctype, body, extra = multipartFile(body)
			total += extra
		}
		sent := sha256.New()
		r := httptest.NewRequest(method, "http://"+nc+"/upload", io.TeeReader(body, sent))
		r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
		r.ContentLength = int64(total)
		r.Header.Set("Content-Length", strconv.Itoa(total))
		r.Header.Set("Content-Type", ctype)
		w := httptest.NewRecorder()

		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		h.ServeHTTP(w, r)

		assert.Equal(t, w.Code, http.StatusOK, ctype)
		assert.Equal(t, app.n, int64(total), ctype)
		assert.DeepEqual(t, app.sum, sent.Sum(nil))
		grew := int64(app.heap) - int64(before.HeapInuse)
		t.Logf("%s: heap in use grew by %d KiB during the request", ctype, grew>>10)
		assert.Assert(t, grew < 16<<20, "heap grew by %d bytes", grew)
		assert.Equal(t, len(wafEvents(g)), 0, ctype)
	}
}

// A multipart upload past the inspection limit is not refused as malformed (200003, 9100001).
func TestMultipartUploadPasses(t *testing.T) {
	cfg := wafConfig("block", nil)
	g, _, a, h := setup(t, &cfg)
	file, _ := io.ReadAll(io.LimitReader(rand.NewChaCha8([32]byte{4}), 300<<10))
	ctype, body, _ := multipartFile(bytes.NewReader(file))
	want, _ := io.ReadAll(body)

	w := send(h, http.MethodPost, jf, "/upload", ctype, bytes.NewReader(want))
	assert.Equal(t, w.Code, http.StatusOK)
	got, err := io.ReadAll(a.seen.Body)
	assert.NilError(t, err)
	assert.Assert(t, bytes.Equal(got, want))
	assert.Equal(t, len(wafEvents(g)), 0)
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
	_, err := wafRules(cfg.Apps)
	assert.Assert(t, errors.Is(err, ErrInvalid), "%v", err)
}

// slowGuard is a guard on mode whose body inspections wait, inside their slot, for let; each one
// announces itself on in, and each request that starts waiting for a slot on queued.
func slowGuard(t *testing.T, mode string) (g *Guard, h http.Handler, hits *atomic.Int32, in, queued, let chan struct{}) {
	t.Helper()
	g = newTestGuard(t, t.TempDir(), startClock())
	assert.NilError(t, g.SetConfig(wafConfig(mode, nil)))
	in, queued, let, hits = make(chan struct{}, 8), make(chan struct{}, 8), make(chan struct{}), &atomic.Int32{}
	g.inspecting = func() { in <- struct{}{}; <-let }
	g.slots.queued = func() { queued <- struct{}{} }
	h = g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	return
}

func postForm(h http.Handler, ip string) int {
	return postBody(h, ip, strings.NewReader("user=bob&remember=1"))
}

func postBody(h http.Handler, ip string, body io.Reader) int {
	r := httptest.NewRequest(http.MethodPost, "http://"+jf+"/login", body)
	r.RemoteAddr = net.JoinHostPort(ip, "4444")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// notIn fails when an inspection has started.
func notIn(t *testing.T, in chan struct{}) {
	t.Helper()
	select {
	case <-in:
		t.Fatal("an inspection started without a slot")
	default:
	}
}

func TestBodyInspectionsCappedPerBox(t *testing.T) {
	g, h, hits, in, queued, let := slowGuard(t, "block")
	codes := make(chan int, 3)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		go func() { codes <- postForm(h, ip) }()
	}
	<-in
	<-in
	<-queued
	<-queued
	<-queued
	notIn(t, in) // both box slots are held: the third waits

	// a request without a parsed body never waits for one
	assert.Equal(t, get(h, jf, "203.0.113.4", "/x").Code, http.StatusOK)
	assert.Equal(t, send(h, http.MethodPut, jf, "/f.bin", "application/octet-stream", strings.NewReader("raw bytes")).Code, http.StatusOK)

	let <- struct{}{}
	<-in // a slot freed: the third is inspected
	close(let)
	for i := 0; i < 3; i++ {
		assert.Equal(t, <-codes, http.StatusOK)
	}
	assert.Equal(t, hits.Load(), int32(5))
	assert.Equal(t, len(wafEvents(g)), 0)
}

func TestBodyInspectionsCappedPerKey(t *testing.T) {
	_, h, hits, in, queued, let := slowGuard(t, "block")
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() { codes <- postForm(h, "2001:db8::1") }()
	}
	<-in
	<-queued
	<-queued
	notIn(t, in) // same /64 key: the second waits though the box has a slot
	let <- struct{}{}
	<-in
	close(let)
	assert.Equal(t, <-codes, http.StatusOK)
	assert.Equal(t, <-codes, http.StatusOK)
	assert.Equal(t, hits.Load(), int32(2))
}

// No slot within the wait: "block" answers 503, "observe" lets the request pass uninspected; one event, no ban count.
func TestBodyInspectionBusy(t *testing.T) {
	for _, c := range []struct {
		mode, action string
		code         int
		hits         int32
	}{{"block", "blocked", http.StatusServiceUnavailable, 0}, {"observe", "observed", http.StatusOK, 1}} {
		g, h, hits, in, _, let := slowGuard(t, c.mode)
		g.inspectWait = 100 * time.Millisecond // stands for the 2 s
		first := make(chan int, 1)
		go func() { first <- postForm(h, visitorIP) }()
		<-in

		r := httptest.NewRequest(http.MethodPost, "http://"+jf+"/login", strings.NewReader("user=bob&remember=1"))
		r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(t, w.Code, c.code, c.mode)
		if c.mode == "block" {
			assert.Equal(t, w.Body.String(), "This app is not available right now.\n")
		}
		assert.Equal(t, hits.Load(), c.hits, c.mode)
		ev := wafEvents(g)
		assert.Equal(t, len(ev), 1, c.mode)
		assert.Equal(t, ev[0].Action, c.action)
		assert.Equal(t, ev[0].Detail, "inspection busy")
		assert.Equal(t, ev[0].Rule, 0)

		close(let)
		assert.Equal(t, <-first, http.StatusOK)
		g.cm.Lock()
		assert.Equal(t, len(g.wafHits), 0, c.mode) // no ban count
		g.cm.Unlock()
	}
}

// A panic during an inspection gives its slots back.
func TestPanicReleasesSlots(t *testing.T) {
	g, h, _, _, _, _ := slowGuard(t, "block")
	g.inspecting = func() { panic("boom") }
	for i := 0; i < 2; i++ {
		func() {
			defer func() { assert.Assert(t, recover() != nil) }()
			postForm(h, visitorIP)
		}()
	}
	g.inspecting = nil
	g.inspectWait = 100 * time.Millisecond
	assert.Equal(t, postForm(h, visitorIP), http.StatusOK)
}

type brokenBody struct{ n int }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.n > 0 {
		return 0, io.ErrUnexpectedEOF
	}
	b.n = copy(p, "user=bob")
	return b.n, nil
}

// A body the WAF cannot read is refused on "block", and passes with an event on "observe"; no ban count.
func TestInspectionErrorNotPassedOnBlock(t *testing.T) {
	for _, c := range []struct {
		mode, action string
		code         int
	}{{"block", "blocked", http.StatusForbidden}, {"observe", "observed", http.StatusOK}} {
		g, h, hits, _, _, _ := slowGuard(t, c.mode)
		g.inspecting = nil
		assert.Equal(t, postBody(h, visitorIP, &brokenBody{}), c.code, c.mode)
		assert.Equal(t, hits.Load() == 1, c.mode == "observe")
		ev := wafEvents(g)
		assert.Equal(t, len(ev), 1)
		assert.Equal(t, ev[0].Action, c.action)
		assert.Equal(t, ev[0].Detail, "inspection error")
		assert.Equal(t, len(g.wafHits), 0)
	}
}

// A client "host" header (kept beside :authority under HTTP/2) cannot borrow another app's rules_off.
func TestHostHeaderCannotBorrowRulesOff(t *testing.T) {
	cfg := wafConfig("block", nil)
	app := cfg.Apps[jf]
	app.Policy.RulesOff = []int{942100}
	cfg.Apps[jf] = app
	_, _, a, h := setup(t, &cfg)
	r := httptest.NewRequest(http.MethodGet, "http://"+nc+sqli, nil)
	r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
	r.Header["Host"] = []string{jf}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.Equal(t, a.hits, 0)
}

type fakeMeta struct {
	types.RuleMetadata
	id  int
	sev types.RuleSeverity
}

func (m fakeMeta) ID() int                      { return m.id }
func (m fakeMeta) Severity() types.RuleSeverity { return m.sev }
func (m fakeMeta) Raw() string {
	return fmt.Sprintf(`SecRule X "@rx y" "id:%d,msg:'rule %d'"`, m.id, m.id)
}

type fakeMatch struct {
	types.MatchedRule
	md fakeMeta
}

func (m fakeMatch) Rule() types.RuleMetadata { return m.md }

func TestDecidingRuleIsMostSevere(t *testing.T) {
	ms := func(rules ...fakeMeta) []types.MatchedRule {
		out := []types.MatchedRule{}
		for _, r := range rules {
			out = append(out, fakeMatch{md: r})
		}
		return out
	}
	warning, critical, critical2, total := fakeMeta{id: 920190, sev: 4}, fakeMeta{id: 942100, sev: 2}, fakeMeta{id: 932100, sev: 2}, fakeMeta{id: 949110, sev: 2}
	unset := fakeMeta{id: 901001, sev: types.RuleSeverityUnset}

	id, msg := decidingRule(ms(unset, warning, critical, critical2, total), 949110)
	assert.Equal(t, id, 942100) // most severe, first among equals
	assert.Equal(t, msg, "rule 942100")
	id, _ = decidingRule(ms(unset, total), 949110)
	assert.Equal(t, id, 949110) // nothing else with a severity
	id, _ = decidingRule(ms(critical, fakeMeta{id: 9100001, sev: 2}), 9100001)
	assert.Equal(t, id, 9100001) // a direct deny reports the rule that denied
}

// Requests keep being answered while SetConfig swaps the WAF.
func TestSetConfigDuringRequests(t *testing.T) {
	g := newTestGuard(t, t.TempDir(), startClock())
	assert.NilError(t, g.SetConfig(wafConfig("block", nil)))
	h := g.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				ip := fmt.Sprintf("198.51.100.%d", 1+(i*50+n)%200)
				var code int
				if n%2 == 0 {
					code = get(h, jf, ip, sqli).Code
				} else {
					code = postBody(h, ip, strings.NewReader("user=bob"))
				}
				if code != http.StatusOK && code != http.StatusForbidden {
					t.Errorf("code %d", code)
				}
			}
		}()
	}
	for _, mode := range []string{"observe", "off", "block", "observe"} {
		assert.NilError(t, g.SetConfig(wafConfig(mode, nil)))
	}
	close(stop)
	wg.Wait()
}

// A head too large to inspect is refused at once under block, with one event and no ban count.
func TestHeadTooLargeRefused(t *testing.T) {
	pairs := func(n int, sep string) string {
		p := make([]string, n)
		for i := range p {
			p[i] = fmt.Sprintf("c%d=1", i)
		}
		return strings.Join(p, sep)
	}
	for _, c := range []struct {
		name, path string
		hdr        []string
	}{
		{"256 KiB cookie", "/x", []string{"Cookie", "big=" + strings.Repeat("a", 256<<10)}},
		{"101 cookies", "/x", []string{"Cookie", pairs(101, "; ")}},
		{"101 query args", "/x?" + pairs(101, "&"), nil},
	} {
		cfg := wafConfig("block", nil)
		g, _, a, h := setup(t, &cfg)
		start := time.Now()
		w := get(h, jf, visitorIP, c.path, c.hdr...)
		took := time.Since(start)
		assert.Equal(t, w.Code, http.StatusRequestHeaderFieldsTooLarge, c.name)
		assert.Equal(t, w.Body.String(), "Request too large.\n", c.name)
		assert.Assert(t, took < time.Second, "%s: took %v", c.name, took)
		assert.Equal(t, a.hits, 0, c.name)
		ev := wafEvents(g)
		assert.Equal(t, len(ev), 1, c.name)
		assert.Equal(t, ev[0].Action, "blocked", c.name)
		assert.Equal(t, ev[0].Detail, "request too large to inspect", c.name)
		assert.Equal(t, len(g.wafHits), 0, c.name)
	}

	// at the limits: inspected as usual
	cfg := wafConfig("block", nil)
	g, _, a, h := setup(t, &cfg)
	assert.Equal(t, get(h, jf, visitorIP, "/x?"+pairs(100, "&"), "Cookie", pairs(100, "; ")).Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	assert.Equal(t, len(wafEvents(g)), 0)
}

// Under observe a head too large to inspect passes, with one event.
func TestHeadTooLargeObserved(t *testing.T) {
	cfg := wafConfig("observe", nil)
	g, _, a, h := setup(t, &cfg)
	assert.Equal(t, get(h, jf, visitorIP, "/x", "X-Pad", strings.Repeat("a", 20<<10)).Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	ev := wafEvents(g)
	assert.Equal(t, len(ev), 1)
	assert.Equal(t, ev[0].Action, "observed")
	assert.Equal(t, ev[0].Detail, "request too large to inspect")
}

// A head over 4 KiB is inspected in a slot, like a body, and gives it back before its own body takes one.
func TestBigHeadTakesASlot(t *testing.T) {
	g, h, hits, in, queued, let := slowGuard(t, "block")
	codes := make(chan int, 2)
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		go func() { codes <- postForm(h, ip) }()
	}
	<-in
	<-in
	<-queued
	<-queued

	pad := strings.Repeat("a", 5<<10)
	done := make(chan int, 1)
	go func() { done <- get(h, jf, "203.0.113.3", "/x", "X-Pad", pad).Code }()
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("a 5 KiB head did not wait for a slot")
	}
	select {
	case code := <-done:
		t.Fatalf("answered %d while both slots were held", code)
	default:
	}
	close(let)
	assert.Equal(t, <-done, http.StatusOK)
	assert.Equal(t, <-codes, http.StatusOK)
	assert.Equal(t, <-codes, http.StatusOK)

	g.inspecting, g.inspectWait = nil, 100*time.Millisecond
	r := httptest.NewRequest(http.MethodPost, "http://"+jf+"/login", strings.NewReader("user=bob&remember=1"))
	r.RemoteAddr = net.JoinHostPort(visitorIP, "4444")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Pad", pad)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, hits.Load(), int32(4))
	assert.Equal(t, len(wafEvents(g)), 0)
}

// A chunked multipart upload (no Content-Length) past the inspection limit reaches the app whole under block.
func TestChunkedMultipartUploadPasses(t *testing.T) {
	g := newTestGuard(t, t.TempDir(), startClock())
	assert.NilError(t, g.SetConfig(wafConfig("block", nil)))
	app := &sink{}
	srv := httptest.NewServer(g.Handler(app))
	defer srv.Close()

	file, _ := io.ReadAll(io.LimitReader(rand.NewChaCha8([32]byte{5}), 300<<10))
	ctype, body, _ := multipartFile(bytes.NewReader(file))
	want, _ := io.ReadAll(body)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/upload", io.MultiReader(bytes.NewReader(want))) // unknown length: sent chunked
	assert.NilError(t, err)
	req.Host = jf
	req.Header.Set("Content-Type", ctype)
	resp, err := srv.Client().Do(req)
	assert.NilError(t, err)
	resp.Body.Close()
	assert.Equal(t, resp.StatusCode, http.StatusOK)
	assert.Equal(t, app.n, int64(len(want)))
	sum := sha256.Sum256(want)
	assert.DeepEqual(t, app.sum, sum[:])
	assert.Equal(t, len(wafEvents(g)), 0)
}

// A push that changes only people, or only the mode, keeps the compiled WAF; a rule change rebuilds it.
func TestWAFReusedWhenRulesUnchanged(t *testing.T) {
	g := newTestGuard(t, t.TempDir(), startClock())
	cfg := wafConfig("block", nil)
	assert.NilError(t, g.SetConfig(cfg))
	first := g.crs
	assert.Assert(t, first != nil)

	cfg.Secret = testSecret
	cfg.People = []Person{{ID: "p9", Gen: 1, CodeHash: CodeHash(testSecret, goodCode), Apps: []string{"jellyfin"}}}
	assert.NilError(t, g.SetConfig(cfg))
	assert.Assert(t, g.crs == first)
	assert.NilError(t, g.SetConfig(wafConfig("observe", nil)))
	assert.Assert(t, g.crs == first)

	assert.NilError(t, g.SetConfig(wafConfig("block", func(p *Policy) { p.RulesOff = []int{942100} })))
	assert.Assert(t, g.crs != first)
	assert.Assert(t, g.crs != nil)
}

// A SetConfig that starts while another is between its build and its swap ends last: its config is held and written.
func TestSetConfigSerialised(t *testing.T) {
	rt := t.TempDir()
	g, err := New(rt, t.TempDir(), "", startClock().now)
	assert.NilError(t, err)
	first := wafConfig("block", nil)
	second := wafConfig("block", nil)
	second.Protection = false

	paused, resume := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	g.built = func() {
		if calls.Add(1) == 1 {
			close(paused)
			<-resume
		}
	}
	errs := make(chan error, 2)
	go func() { errs <- g.SetConfig(first) }()
	<-paused
	go func() { errs <- g.SetConfig(second) }()
	left := 2
	select {
	case err := <-errs: // the second finished while the first was paused
		assert.NilError(t, err)
		left--
	case <-time.After(200 * time.Millisecond):
	}
	close(resume)
	for ; left > 0; left-- {
		assert.NilError(t, <-errs)
	}

	assert.Equal(t, g.Config().Protection, false)
	assert.Assert(t, g.crs == nil)
	disk, err := load(filepath.Join(rt, FileName))
	assert.NilError(t, err)
	assert.Equal(t, disk.Protection, false)
}
