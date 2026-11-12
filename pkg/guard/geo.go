package guard

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	countryFile = "dbip-country-lite.mmdb"
	asnFile     = "dbip-asn-lite.mmdb"
	geoCheck    = time.Minute
)

// mmdb is one database file and the mtime it was opened at.
type mmdb struct {
	name string
	r    *maxminddb.Reader
	mod  time.Time
}

// Geo answers country and network questions from the DB-IP Lite files in a directory. Missing or
// unreadable files mean unknown; the files are looked at again (by mtime) at most once a minute.
type Geo struct {
	dir string
	now func() time.Time

	mu      sync.RWMutex // lookups hold it shared, so a reader is closed only when none is in use
	country mmdb
	asn     mmdb
	checked time.Time
}

// OpenGeo never fails: what cannot be opened is unknown until it can.
func OpenGeo(dir string) *Geo { return openGeo(dir, time.Now) }

func openGeo(dir string, now func() time.Time) *Geo {
	g := &Geo{dir: dir, now: now, country: mmdb{name: countryFile}, asn: mmdb{name: asnFile}}
	g.mu.Lock()
	g.reload()
	g.mu.Unlock()
	return g
}

// reload reopens the files whose mtime changed; a file that cannot be opened keeps its previous reader. Called with mu held.
func (g *Geo) reload() {
	g.checked = g.now()
	for _, d := range []*mmdb{&g.country, &g.asn} {
		path := filepath.Join(g.dir, d.name)
		fi, err := os.Stat(path)
		if err != nil || (d.r != nil && fi.ModTime().Equal(d.mod)) {
			continue
		}
		r, err := maxminddb.Open(path)
		if err != nil {
			continue
		}
		if d.r != nil {
			d.r.Close()
		}
		d.r, d.mod = r, fi.ModTime()
	}
}

// refresh reloads when the minute is up, and returns with mu held shared.
func (g *Geo) refresh() {
	g.mu.RLock()
	due := g.now().Sub(g.checked) >= geoCheck
	g.mu.RUnlock()
	if due {
		g.mu.Lock()
		if g.now().Sub(g.checked) >= geoCheck {
			g.reload()
		}
		g.mu.Unlock()
	}
	g.mu.RLock()
}

// Loaded reports which files are readable.
func (g *Geo) Loaded() (country, asn bool) {
	g.refresh()
	defer g.mu.RUnlock()
	return g.country.r != nil, g.asn.r != nil
}

// Lookup returns the ISO country, the AS number and the AS organisation of ip; zero values when unknown.
func (g *Geo) Lookup(ip net.IP) (country string, asn uint, org string) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}
	a = a.Unmap()
	g.refresh()
	defer g.mu.RUnlock()
	if g.country.r != nil {
		var rec struct {
			Country struct {
				ISO string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if g.country.r.Lookup(a).Decode(&rec) == nil {
			country = rec.Country.ISO
		}
	}
	if g.asn.r != nil {
		var rec struct {
			N   uint   `maxminddb:"autonomous_system_number"`
			Org string `maxminddb:"autonomous_system_organization"`
		}
		if g.asn.r.Lookup(a).Decode(&rec) == nil {
			asn, org = rec.N, rec.Org
		}
	}
	return
}

// lookupIP is Lookup for an address in text form.
func (g *Geo) lookupIP(ip string) (string, int, string) {
	c, n, o := g.Lookup(net.ParseIP(ip))
	return c, int(n), o
}

// countryFilter is the country hook: the policy's list blocks ("block") or admits ("allow"); an
// address whose country is unknown passes, and a country refusal counts toward no ban.
func (g *Guard) countryFilter(w http.ResponseWriter, r *http.Request, app AppConfig) bool {
	cs := app.Policy.Countries
	if cs.Mode != "block" && cs.Mode != "allow" {
		return false
	}
	key, ip := Key(r.RemoteAddr)
	cc, _, _ := g.geo.lookupIP(ip)
	if cc == "" {
		return false
	}
	in := false
	for _, c := range cs.List {
		in = in || c == cc
	}
	if in != (cs.Mode == "block") {
		return false
	}
	g.Record(Event{IP: ip, Key: key, App: app.App, Path: eventPath(r), Reason: "country", Action: "blocked"})
	deny(w, r, http.StatusForbidden)
	return true
}
