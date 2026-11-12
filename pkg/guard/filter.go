package guard

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	rateWindow = time.Minute
	sweepEvery = time.Minute
	pathMax    = 200
)

// hook is a filter step filled by a later part (country, WAF, access gate): it answers and returns
// true, or returns false to let the request go on. nil passes.
type hook func(w http.ResponseWriter, r *http.Request, app AppConfig) (handled bool)

type counterKey struct{ key, app string }

type rateWin struct {
	start  time.Time
	n      int
	struck bool // this window has counted its rate strike
}

// hits is a sliding window of events, oldest first.
type hits struct {
	at  []time.Time
	win time.Duration
}

func (h *hits) live(now time.Time) []time.Time {
	i := 0
	for i < len(h.at) && now.Sub(h.at[i]) >= h.win {
		i++
	}
	return h.at[i:]
}

// counters are the per key and app counts behind rate limits and bans; in memory only.
type counters struct {
	cm          sync.Mutex
	rates       map[counterKey]*rateWin
	rateStrikes map[counterKey]*hits
	scans       map[counterKey]*hits
	codes       map[counterKey]*hits
	wafHits     map[counterKey]*hits
	swept       time.Time
}

// note adds now to m[k] and returns how many events the window holds. Called with cm held.
func (c *counters) note(m map[counterKey]*hits, k counterKey, now time.Time, winS int) int {
	h := m[k]
	if h == nil {
		h = &hits{}
		m[k] = h
	}
	h.win = time.Duration(winS) * time.Second
	h.at = append(h.live(now), now)
	return len(h.at)
}

// sweep drops the counters whose window has passed, at most once a minute. Called with cm held.
func (c *counters) sweep(now time.Time) {
	if now.Sub(c.swept) < sweepEvery {
		return
	}
	c.swept = now
	for k, w := range c.rates {
		if now.Sub(w.start) >= rateWindow {
			delete(c.rates, k)
		}
	}
	for _, m := range []map[counterKey]*hits{c.rateStrikes, c.scans, c.codes, c.wafHits} {
		for k, h := range m {
			if len(h.live(now)) == 0 {
				delete(m, k)
			}
		}
	}
}

var visitorCopy = map[int][2]string{ // English, French
	http.StatusUnauthorized:       {"Access code required.", "Code d'accès requis."},
	http.StatusForbidden:          {"Access denied.", "Accès refusé."},
	http.StatusTooManyRequests:    {"Too many requests. Try again later.", "Trop de requêtes. Réessayez plus tard."},
	http.StatusServiceUnavailable: {"This app is not available right now.", "Cette app n'est pas disponible pour le moment."},
}

// lang is the visitor's language: 1 (French) when Accept-Language starts with fr, else 0 (English).
func lang(r *http.Request) int {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language"))), "fr") {
		return 1
	}
	return 0
}

// deny answers code with a short text in the visitor's language.
func deny(w http.ResponseWriter, r *http.Request, code int) {
	http.Error(w, visitorCopy[code][lang(r)], code)
}

// remoteAddr is the visitor's address, IPv4-mapped IPv6 as IPv4.
func remoteAddr(r *http.Request) netip.Addr {
	ap, _ := netip.ParseAddrPort(r.RemoteAddr)
	return ap.Addr().Unmap().WithZone("")
}

// NormalizeHost lowercases h, strips a port and a trailing dot. "" stays "". service.NormalizeHost uses it.
func NormalizeHost(h string) string {
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// eventPath is the request path for the journal: no query, at most 200 bytes.
func eventPath(r *http.Request) string {
	if p := r.URL.Path; len(p) > pathMax {
		return p[:pathMax]
	}
	return r.URL.Path
}

// shortcut: lists are parsed on every request (tens of ns an entry); parse them in SetConfig if lists reach thousands.
func listed(list []string, a netip.Addr) bool {
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			if p.Contains(a) {
				return true
			}
		} else if b, err := netip.ParseAddr(s); err == nil && b.Unmap().WithZone("") == a {
			return true
		}
	}
	return false
}

// Handler filters the requests of the shared hosts in the config, in the contract's order. An
// address on the allow list passes every filter but the access gate (spec: the allow list keeps
// the owner from being banned, it does not open a protected app), so it is checked first.
func (g *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.RLock()
		broken, cfg := g.broken, g.cfg
		g.mu.RUnlock()
		if broken {
			deny(w, r, http.StatusServiceUnavailable)
			return
		}
		app, ok := cfg.Apps[NormalizeHost(r.Host)]
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		pol := app.Policy
		addr := remoteAddr(r)
		if !cfg.Protection || listed(pol.Allow, addr) {
			if g.gate == nil || !g.gate(w, r, app) {
				next.ServeHTTP(w, r)
			}
			return
		}

		key, ip := Key(r.RemoteAddr)
		path := eventPath(r)
		record := func(reason, action string) {
			g.Record(Event{IP: ip, Key: key, App: app.App, Path: path, Reason: reason, Action: action})
		}

		if _, banned := g.Banned(key); banned {
			record("banned", "blocked")
			deny(w, r, http.StatusForbidden)
			return
		}
		if listed(pol.Block, addr) {
			record("blocklist", "blocked")
			deny(w, r, http.StatusForbidden)
			return
		}
		if g.country != nil && g.country(w, r, app) {
			return
		}

		ck := counterKey{key, app.App}
		now := g.now()
		g.cm.Lock()
		g.sweep(now)
		rw := g.rates[ck]
		if rw == nil || now.Sub(rw.start) >= rateWindow {
			rw = &rateWin{start: now}
			g.rates[ck] = rw
		}
		rw.n++
		over := rw.n > pol.RatePerMin
		ban := false
		if over && !rw.struck {
			rw.struck = true
			ban = g.note(g.rateStrikes, ck, now, pol.Ban.RateWindowS) >= pol.Ban.RateStrikes
		}
		if ban {
			delete(g.rateStrikes, ck)
		}
		left := rw.start.Add(rateWindow).Sub(now)
		g.cm.Unlock()
		if over {
			action := "blocked"
			if ban {
				g.BanKey(key, ip, app.App, "rate")
				action = "banned"
			}
			record("rate", action)
			w.Header().Set("Retry-After", strconv.Itoa(int((left+time.Second-1)/time.Second)))
			deny(w, r, http.StatusTooManyRequests)
			return
		}

		if g.waf != nil && g.waf(w, r, app) {
			return
		}
		if g.gate != nil && g.gate(w, r, app) {
			return
		}

		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status != http.StatusNotFound || sw.notByApp {
			return
		}
		g.cm.Lock()
		ban = g.note(g.scans, ck, g.now(), pol.Ban.ScanWindowS) >= pol.Ban.Scan404
		if ban {
			delete(g.scans, ck)
		}
		g.cm.Unlock()
		if ban {
			g.BanKey(key, ip, app.App, "scan")
			record("scan", "banned")
		}
	})
}

// statusWriter notes the app's final status for the scan count. It keeps Flush, Hijack (WebSockets
// through httputil.ReverseProxy) and ReadFrom; Hijack fails with http.ErrNotSupported where the
// underlying writer cannot (HTTP/2).
type statusWriter struct {
	http.ResponseWriter
	status   int
	notByApp bool
}

// NotFromApp marks the answer on w as the Gateway's own (a host it does not serve), so its 404 is
// not counted toward a scan ban.
func NotFromApp(w http.ResponseWriter) {
	if s, ok := w.(*statusWriter); ok {
		s.notByApp = true
	}
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 { // 1xx are not the answer
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(struct{ io.Writer }{s.ResponseWriter}, src)
}

func (s *statusWriter) Flush() { _ = http.NewResponseController(s.ResponseWriter).Flush() }

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(s.ResponseWriter).Hijack()
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
