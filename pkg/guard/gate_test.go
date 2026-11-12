package guard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
)

const (
	gh        = "jellyfin.mybox.box.example.org"
	ghOther   = "nextcloud.mybox.box.example.org"
	ghOpen    = "photos.mybox.box.example.org"
	visitorIP = "203.0.113.9"
	goodCode  = "ABCD-EFGH-JKMN"
	otherCode = "2345-6789-ABCD" // p2's, opens nextcloud only
)

var testSecret = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

func codeConfig(protection bool) Config {
	pol := protectedConfig(nil).Apps[jf].Policy
	return Config{
		Secret: testSecret, Protection: protection,
		Apps: map[string]AppConfig{
			gh:      {App: "jellyfin", Access: "code", Policy: pol},
			ghOther: {App: "nextcloud", Access: "code", Policy: pol},
			ghOpen:  {App: "photos", Access: "open", Policy: pol},
		},
		People: []Person{
			{ID: "p1", Gen: 1, CodeHash: CodeHash(testSecret, goodCode), Apps: []string{"jellyfin"}},
			{ID: "p2", Gen: 1, CodeHash: CodeHash(testSecret, otherCode), Apps: []string{"nextcloud"}},
		},
	}
}

func sessionCookie(id string, gen int, issued time.Time) string {
	return CookieName + "=" + SignSession(testSecret, id, gen, issued)
}

func postCode(h http.Handler, host, ip string, form url.Values, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://"+host+EntryPath, strings.NewReader(form.Encode()))
	r.RemoteAddr = net.JoinHostPort(ip, "4444")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestGatePageForBrowser(t *testing.T) {
	cfg := codeConfig(true)
	_, _, a, h := setup(t, &cfg)

	w := get(h, gh, visitorIP, "/", "Accept", "text/html,application/xhtml+xml")
	assert.Equal(t, w.Code, http.StatusFound)
	assert.Equal(t, w.Header().Get("Location"), "/.recasaos/acces?next=%2F")
	assert.Equal(t, w.Header().Get("Cache-Control"), "no-store")
	w = get(h, gh, visitorIP, "/web/?a=1", "Accept", "text/html")
	assert.Equal(t, w.Header().Get("Location"), "/.recasaos/acces?next=%2Fweb%2F%3Fa%3D1")

	w = get(h, gh, visitorIP, EntryPath+"?next=%2Fweb%2F", "Accept", "text/html")
	assert.Equal(t, w.Code, http.StatusOK)
	body := w.Body.String()
	assert.Assert(t, strings.Contains(body, "jellyfin"), body)
	assert.Assert(t, strings.Contains(body, `name="code"`), body)
	assert.Assert(t, strings.Contains(body, `name="next" value="/web/"`), body)
	assert.Assert(t, strings.Contains(body, "Access code"), body)
	assert.Equal(t, w.Header().Get("Content-Type"), "text/html; charset=utf-8")
	assert.Equal(t, w.Header().Get("Cache-Control"), "no-store")
	assert.Equal(t, w.Header().Get("Referrer-Policy"), "no-referrer")
	assert.Equal(t, w.Header().Get("Content-Security-Policy"), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")

	w = get(h, gh, visitorIP, EntryPath+"?next=//evil", "Accept-Language", "fr-FR")
	body = w.Body.String()
	assert.Assert(t, strings.Contains(body, "Ouvrir"), body)
	assert.Assert(t, strings.Contains(body, `lang="fr"`), body)
	assert.Assert(t, strings.Contains(body, `name="next" value="/"`), body)
	assert.Equal(t, a.hits, 0)

	// a long next is dropped, so the form posted back stays under 4 KiB
	long := "/?" + strings.Repeat("a=b&", 500)
	body = get(h, gh, visitorIP, EntryPath+"?next="+url.QueryEscape(long)).Body.String()
	assert.Assert(t, strings.Contains(body, `name="next" value="/"`), body)
	w = postCode(h, gh, visitorIP, url.Values{"code": {goodCode}, "next": {"/?" + strings.Repeat("a=b&", 255)}})
	assert.Equal(t, w.Code, http.StatusSeeOther)

	// the app name is escaped
	cfg.Apps[gh] = AppConfig{App: "<b>x", Access: "code", Policy: cfg.Apps[gh].Policy}
	_, _, _, h = setup(t, &cfg)
	body = get(h, gh, visitorIP, EntryPath).Body.String()
	assert.Assert(t, !strings.Contains(body, "<b>x") && strings.Contains(body, "&lt;b&gt;x"), body)
}

func TestGate401ForNonPage(t *testing.T) {
	cfg := codeConfig(true)
	_, _, a, h := setup(t, &cfg)

	w := get(h, gh, visitorIP, "/api", "Accept", "application/json")
	assert.Equal(t, w.Code, http.StatusUnauthorized)
	assert.Equal(t, w.Body.String(), "Access code required.\n")
	assert.Equal(t, w.Header().Get("Cache-Control"), "no-store")
	w = get(h, gh, visitorIP, "/socket", "Accept", "text/html", "Upgrade", "websocket", "Connection", "Upgrade", "Accept-Language", "fr")
	assert.Equal(t, w.Code, http.StatusUnauthorized)
	assert.Equal(t, w.Body.String(), "Code d'accès requis.\n")

	r := httptest.NewRequest(http.MethodPost, "http://"+gh+"/form", nil)
	r.Header.Set("Accept", "text/html")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, w.Code, http.StatusUnauthorized)
	assert.Equal(t, a.hits, 0)
}

func TestGoodCodeSetsCookieAndRedirects(t *testing.T) {
	cfg := codeConfig(true)
	g, c, a, h := setup(t, &cfg)

	w := postCode(h, gh, visitorIP, url.Values{"code": {"abcd efgh jkmn"}, "next": {"/web/"}})
	assert.Equal(t, w.Code, http.StatusSeeOther)
	assert.Equal(t, w.Header().Get("Location"), "/web/")
	assert.Equal(t, w.Header().Get("Cache-Control"), "no-store")
	cookies := w.Result().Cookies()
	assert.Equal(t, len(cookies), 1)
	ck := cookies[0]
	assert.Equal(t, ck.Name, "recasaos_access")
	assert.Equal(t, ck.Domain, "mybox.box.example.org")
	assert.Equal(t, ck.Path, "/")
	assert.Equal(t, ck.MaxAge, 2592000)
	assert.Assert(t, ck.Secure && ck.HttpOnly)
	assert.Equal(t, ck.SameSite, http.SameSiteLaxMode)
	id, gen, issued, ok := ParseSession(testSecret, ck.Value)
	assert.Assert(t, ok)
	assert.Equal(t, id, "p1")
	assert.Equal(t, gen, 1)
	assert.Assert(t, issued.Equal(c.now()))
	assert.Assert(t, g.Status().PeopleLastUsed["p1"].Equal(c.now()))
	assert.Equal(t, a.hits, 0)

	// the session opens the app
	w = get(h, gh, visitorIP, "/web/", "Accept", "text/html", "Cookie", ck.Name+"="+ck.Value)
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, a.hits, 1)
	assert.Equal(t, w.Header().Get("Set-Cookie"), "")

	// a code in the query string is not read
	r := httptest.NewRequest(http.MethodPost, "http://"+gh+EntryPath+"?code="+goodCode, nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	assert.Equal(t, w.Code, http.StatusUnauthorized)

	// a body over 4 KiB is a wrong code
	w = postCode(h, gh, visitorIP, url.Values{"code": {goodCode}, "pad": {strings.Repeat("x", 5000)}})
	assert.Equal(t, w.Code, http.StatusUnauthorized)
}

func TestNextMustBeLocal(t *testing.T) {
	cfg := codeConfig(true)
	_, _, _, h := setup(t, &cfg)

	for next, want := range map[string]string{
		"https://evil.example/":     "/",
		"//evil":                    "/",
		`/\evil`:                    "/",
		"/\t/evil":                  "/",
		"javascript:alert(1)":       "/",
		"web/":                      "/",
		"":                          "/",
		EntryPath:                   "/",
		"/a/../.recasaos/acces?x=1": "/",
		"/web/?a=1#b":               "/web/?a=1#b",
	} {
		w := postCode(h, gh, visitorIP, url.Values{"code": {goodCode}, "next": {next}})
		assert.Equal(t, w.Code, http.StatusSeeOther, next)
		assert.Equal(t, w.Header().Get("Location"), want, next)
	}
}

func TestCodeForOtherApp(t *testing.T) {
	cfg := codeConfig(true)
	g, c, a, h := setup(t, &cfg)

	w := postCode(h, gh, visitorIP, url.Values{"code": {otherCode}, "next": {"/"}})
	assert.Equal(t, w.Code, http.StatusForbidden)
	assert.Assert(t, strings.Contains(w.Body.String(), "This code does not open this app"), w.Body.String())
	assert.Equal(t, w.Header().Get("Set-Cookie"), "")
	w = postCode(h, gh, visitorIP, url.Values{"code": {otherCode}}, "Accept-Language", "fr")
	assert.Assert(t, strings.Contains(w.Body.String(), "Ce code n&#39;ouvre pas cette app"), w.Body.String())
	assert.Equal(t, len(g.Events("", "code", 0)), 0)
	assert.Equal(t, len(g.Status().PeopleLastUsed), 0)
	assert.Equal(t, a.hits, 0)

	// p1's session does not open nextcloud either, though the cookie reaches it
	w = get(h, ghOther, visitorIP, "/", "Accept", "text/html", "Cookie", sessionCookie("p1", 1, c.now()))
	assert.Equal(t, w.Code, http.StatusFound)
	assert.Equal(t, a.hits, 0)
}

func TestCodeFailsBan(t *testing.T) {
	cfg := codeConfig(true)
	pol := cfg.Apps[gh].Policy
	pol.Allow = []string{"192.0.2.5"}
	cfg.Apps[gh] = AppConfig{App: "jellyfin", Access: "code", Policy: pol}
	g, c, _, h := setup(t, &cfg)
	wrong := url.Values{"code": {"WXYZ-WXYZ-WXYZ"}}

	for i := 0; i < 4; i++ {
		w := postCode(h, gh, visitorIP, wrong)
		assert.Equal(t, w.Code, http.StatusUnauthorized)
		assert.Assert(t, strings.Contains(w.Body.String(), "Wrong code"), w.Body.String())
		c.add(10 * time.Second)
	}
	_, banned := g.Banned(visitorIP)
	assert.Assert(t, !banned)
	// a good code is not a fail
	assert.Equal(t, postCode(h, gh, visitorIP, url.Values{"code": {goodCode}}).Code, http.StatusSeeOther)
	_, banned = g.Banned(visitorIP)
	assert.Assert(t, !banned)

	w := postCode(h, gh, visitorIP, wrong, "Accept-Language", "fr")
	assert.Assert(t, strings.Contains(w.Body.String(), "Code incorrect"), w.Body.String())
	b, banned := g.Banned(visitorIP)
	assert.Assert(t, banned)
	assert.Equal(t, b.Reason, "code")
	assert.Equal(t, b.App, "jellyfin")
	assert.Equal(t, b.Until.Sub(b.Since), time.Hour)
	ev := g.Events("", "code", 0)
	assert.Equal(t, len(ev), 2)
	assert.Equal(t, ev[0].Action, "banned")
	assert.Equal(t, ev[1].Action, "blocked")
	assert.Equal(t, ev[1].Count, 4)
	assert.Equal(t, ev[1].Path, EntryPath)
	assert.Equal(t, postCode(h, gh, visitorIP, url.Values{"code": {goodCode}}).Code, http.StatusForbidden)

	// sliding window: 4 fails, 10 minutes, 4 more is still no ban
	other := "198.51.100.3"
	for i := 0; i < 4; i++ {
		postCode(h, gh, other, wrong)
	}
	c.add(10 * time.Minute)
	for i := 0; i < 4; i++ {
		postCode(h, gh, other, wrong)
	}
	_, banned = g.Banned(other)
	assert.Assert(t, !banned)

	// an allowed address is never counted
	for i := 0; i < 10; i++ {
		assert.Equal(t, postCode(h, gh, "192.0.2.5", wrong).Code, http.StatusUnauthorized)
	}
	_, banned = g.Banned("192.0.2.5")
	assert.Assert(t, !banned)
	assert.Equal(t, len(g.codes), 1) // the other address only

	// bounded: the counters of past windows go at the next sweep
	c.add(601 * time.Second)
	postCode(h, gh, "198.51.100.4", wrong)
	assert.Equal(t, len(g.codes), 1) // the newcomer
}

func TestRevokedGenRejected(t *testing.T) {
	cfg := codeConfig(true)
	cfg.People[0].Gen = 2
	g, c, a, h := setup(t, &cfg)

	assert.Equal(t, get(h, gh, visitorIP, "/api", "Cookie", sessionCookie("p1", 1, c.now())).Code, http.StatusUnauthorized)
	assert.Equal(t, get(h, gh, visitorIP, "/api", "Cookie", sessionCookie("p1", 2, c.now())).Code, http.StatusOK)
	cfg.People = cfg.People[1:]
	assert.NilError(t, g.SetConfig(cfg))
	assert.Equal(t, get(h, gh, visitorIP, "/api", "Cookie", sessionCookie("p1", 2, c.now())).Code, http.StatusUnauthorized)
	assert.Equal(t, a.hits, 1)
}

func TestCookieStrippedBeforeApp(t *testing.T) {
	cfg := codeConfig(true)
	_, c, a, h := setup(t, &cfg)

	get(h, gh, visitorIP, "/", "Cookie", sessionCookie("p1", 1, c.now())+"; a=b")
	assert.Equal(t, a.hits, 1)
	assert.DeepEqual(t, a.seen.Header.Values("Cookie"), []string{"a=b"})

	// an open app: an invalid cookie is stripped too, the rest left as it was
	get(h, ghOpen, visitorIP, "/", "Cookie", "a=b;recasaos_access=junk; c=d")
	assert.DeepEqual(t, a.seen.Header.Values("Cookie"), []string{"a=b; c=d"})
	get(h, ghOpen, visitorIP, "/", "Cookie", "recasaos_access=junk")
	assert.Equal(t, len(a.seen.Header.Values("Cookie")), 0)
	get(h, ghOpen, visitorIP, "/", "Cookie", "a=b;c=d")
	assert.DeepEqual(t, a.seen.Header.Values("Cookie"), []string{"a=b;c=d"})

	// several Cookie lines (HTTP/2), a stale cookie planted beside the good one
	r := httptest.NewRequest(http.MethodGet, "http://"+gh+"/", nil)
	r.Header.Add("Cookie", "recasaos_access=junk; a=b")
	r.Header.Add("Cookie", sessionCookie("p1", 1, c.now()))
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, a.hits, 5)
	assert.DeepEqual(t, a.seen.Header.Values("Cookie"), []string{"a=b"})

	// the entry path is an ordinary path on an open app
	get(h, ghOpen, visitorIP, EntryPath)
	assert.Equal(t, a.hits, 6)
}

func TestSessionRefreshedAfter24h(t *testing.T) {
	cfg := codeConfig(true)
	g, c, _, h := setup(t, &cfg)

	w := get(h, gh, visitorIP, "/", "Cookie", sessionCookie("p1", 1, c.now().Add(-23*time.Hour)))
	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Set-Cookie"), "")
	assert.Equal(t, len(g.Status().PeopleLastUsed), 0)

	w = get(h, gh, visitorIP, "/", "Cookie", sessionCookie("p1", 1, c.now().Add(-25*time.Hour)))
	assert.Equal(t, w.Code, http.StatusOK)
	cookies := w.Result().Cookies()
	assert.Equal(t, len(cookies), 1)
	_, _, issued, ok := ParseSession(testSecret, cookies[0].Value)
	assert.Assert(t, ok)
	assert.Assert(t, issued.Equal(c.now()))
	assert.Equal(t, cookies[0].Domain, "mybox.box.example.org")
	assert.Assert(t, g.Status().PeopleLastUsed["p1"].Equal(c.now()))
}

func TestNoSecret503(t *testing.T) {
	cfg := codeConfig(true)
	cfg.Secret = nil
	_, c, a, h := setup(t, &cfg)

	for _, path := range []string{"/", EntryPath} {
		w := get(h, gh, visitorIP, path, "Accept", "text/html", "Cookie", sessionCookie("p1", 1, c.now()))
		assert.Equal(t, w.Code, http.StatusServiceUnavailable)
		assert.Equal(t, w.Body.String(), "This app is not available right now.\n")
	}
	assert.Equal(t, postCode(h, gh, visitorIP, url.Values{"code": {goodCode}}).Code, http.StatusServiceUnavailable)
	assert.Equal(t, a.hits, 0)
	// an open app still works
	assert.Equal(t, get(h, ghOpen, visitorIP, "/").Code, http.StatusOK)
}

func TestGateWorksWithProtectionOff(t *testing.T) {
	cfg := codeConfig(false)
	g, _, a, h := setup(t, &cfg)

	assert.Equal(t, get(h, gh, visitorIP, "/", "Accept", "text/html").Code, http.StatusFound)
	assert.Equal(t, get(h, gh, visitorIP, "/api").Code, http.StatusUnauthorized)
	for i := 0; i < 10; i++ {
		assert.Equal(t, postCode(h, gh, visitorIP, url.Values{"code": {"WXYZ"}}).Code, http.StatusUnauthorized)
	}
	_, banned := g.Banned(visitorIP)
	assert.Assert(t, !banned)
	assert.Equal(t, len(g.Events("", "", 0)), 0) // nothing is counted with protection off
	assert.Equal(t, postCode(h, gh, visitorIP, url.Values{"code": {goodCode}}).Code, http.StatusSeeOther)
	assert.Equal(t, a.hits, 0)
}
