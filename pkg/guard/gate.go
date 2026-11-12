package guard

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"
)

const (
	EntryPath  = "/.recasaos/acces"
	CookieName = "recasaos_access"

	sessionLife    = 30 * 24 * time.Hour
	sessionRefresh = 24 * time.Hour
	formMax        = 4 << 10
	nextMax        = 1 << 10
)

// accessGate is the gate hook (step 7), run for every host in Apps. It always takes the session
// cookie out of the request; on an app with access "code" it lets through only a valid session
// for this app, and answers everything else: the entry page, a redirect to it, 401, or 503.
func (g *Guard) accessGate(w http.ResponseWriter, r *http.Request, app AppConfig) bool {
	tokens := takeCookie(r)
	if app.Access != "code" {
		return false
	}
	cfg := g.Config()
	if len(cfg.Secret) == 0 { // cannot verify: fail closed
		deny(w, r, http.StatusServiceUnavailable)
		return true
	}
	if r.URL.Path == EntryPath {
		g.entry(w, r, app, cfg)
		return true
	}
	if p, issued, ok := g.session(cfg, tokens, app); ok {
		if g.now().Sub(issued) > sessionRefresh {
			g.startSession(w, r, cfg.Secret, p)
		}
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") && r.Header.Get("Upgrade") == "" {
		w.Header().Set("Location", EntryPath+"?next="+url.QueryEscape(r.URL.RequestURI()))
		w.WriteHeader(http.StatusFound)
		return true
	}
	deny(w, r, http.StatusUnauthorized)
	return true
}

// takeCookie removes every recasaos_access pair from the Cookie header lines and returns their
// values. Without one, the header is left exactly as it came.
func takeCookie(r *http.Request) (tokens []string) {
	lines := r.Header["Cookie"]
	var kept []string
	found := false
	for _, line := range lines {
		for _, pair := range strings.Split(line, ";") {
			pair = strings.TrimSpace(pair)
			name, value, _ := strings.Cut(pair, "=")
			if strings.TrimSpace(name) == CookieName {
				found = true
				tokens = append(tokens, strings.Trim(strings.TrimSpace(value), `"`))
			} else if pair != "" {
				kept = append(kept, pair)
			}
		}
	}
	if !found {
		return nil
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
	} else {
		r.Header["Cookie"] = []string{strings.Join(kept, "; ")}
	}
	return tokens
}

// session returns the person of the first token that is signed, under 30 days old, of the
// person's current generation, and for a person whose code opens app. Any token may be the good
// one: a sibling app on the box domain can plant a stale cookie beside it.
func (g *Guard) session(cfg Config, tokens []string, app AppConfig) (Person, time.Time, bool) {
	now := g.now()
	for _, t := range tokens {
		id, gen, issued, ok := ParseSession(cfg.Secret, t)
		if !ok || now.Sub(issued) >= sessionLife {
			continue
		}
		for _, p := range cfg.People {
			if p.ID == id && p.Gen == gen && slices.Contains(p.Apps, app.App) {
				return p, issued, true
			}
		}
	}
	return Person{}, time.Time{}, false
}

// startSession sets a new session cookie for p on the box domain (the host without its first label).
func (g *Guard) startSession(w http.ResponseWriter, r *http.Request, secret []byte, p Person) {
	_, domain, _ := strings.Cut(NormalizeHost(r.Host), ".")
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: SignSession(secret, p.ID, p.Gen, g.now()),
		Domain: domain, Path: "/", MaxAge: int(sessionLife / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	g.NoteUse(p.ID)
}

// entry serves the entry page; a POST checks the code it carries.
func (g *Guard) entry(w http.ResponseWriter, r *http.Request, app AppConfig, cfg Config) {
	if r.Method != http.MethodPost {
		showPage(w, r, app, localNext(r.URL.Query().Get("next")), msgNone, http.StatusOK)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, formMax)
	_ = r.ParseForm() // a body that is too big or malformed leaves the code empty: a wrong code
	next := localNext(r.PostForm.Get("next"))

	sum := []byte(CodeHash(cfg.Secret, r.PostForm.Get("code")))
	var match *Person
	for i := range cfg.People { // no early exit: the time does not tell which person matched
		if subtle.ConstantTimeCompare(sum, []byte(cfg.People[i].CodeHash)) == 1 {
			match = &cfg.People[i]
		}
	}
	switch {
	case match == nil:
		g.codeFailed(r, app, cfg.Protection)
		showPage(w, r, app, next, msgWrong, http.StatusUnauthorized)
	case !slices.Contains(match.Apps, app.App):
		showPage(w, r, app, next, msgOtherApp, http.StatusForbidden)
	default:
		g.startSession(w, r, cfg.Secret, *match)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", next)
		w.WriteHeader(http.StatusSeeOther)
	}
}

// codeFailed journals a wrong code and bans the key at code_fails within code_window_s. Like every
// other count, skipped with protection off and for an allowed address.
func (g *Guard) codeFailed(r *http.Request, app AppConfig, protection bool) {
	pol := app.Policy
	if !protection || listed(pol.Allow, remoteAddr(r)) {
		return
	}
	key, ip := Key(r.RemoteAddr)
	ck := counterKey{key, app.App}
	g.cm.Lock()
	now := g.now()
	g.sweep(now)
	ban := g.note(g.codes, ck, now, pol.Ban.CodeWindowS) >= pol.Ban.CodeFails
	if ban {
		delete(g.codes, ck)
	}
	g.cm.Unlock()
	action := "blocked"
	if ban {
		g.BanKey(key, ip, app.App, "code")
		action = "banned"
	}
	g.Record(Event{IP: ip, Key: key, App: app.App, Path: EntryPath, Reason: "code", Action: action})
}

// localNext keeps next only when it is a path on this host, and not the entry page itself. At most
// 1 KiB: encoded (×3 at worst) it must still fit, with the code, in the 4 KiB form posted back.
func localNext(next string) string {
	if len(next) > nextMax || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, `\`) ||
		strings.ContainsFunc(next, func(c rune) bool { return c < 0x20 || c == 0x7f }) { // browsers drop tabs and newlines: "/\t/x" is "//x"
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || path.Clean(u.Path) == EntryPath {
		return "/"
	}
	return next
}
